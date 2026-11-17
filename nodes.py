# -*- coding: utf-8 -*-
"""
nodes.py — node latency measurement and best-node selection.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Tuple
from checks import tcping, url_test
from logger import logger
from state import is_node_blacklisted
from utils import fmt_ms
from checks import tcping, url_test
from data import MAX_WORKERS


def _check_one_server(srv: Dict[str, Any]) -> Dict[str, Any]:
    """
    Checks a single server (tcping + url_test). Returns a dictionary
    with fields latency / latency_source / ok.

    Latency priority:
        1. url_test — if it succeeds;
        2. tcping   — only if url_test fails.
    """
    address, port = srv["address"], srv["port"]
    logger.debug("%s: checking %s:%s", srv.get("id"), address, port)

    tcp_ok, tcp_lat = tcping(address, port)
    url_ok, url_lat = url_test(address, port)

    logger.debug(
        "%s: tcping=%s/%s, url_test=%s/%s",
        srv.get("id"), tcp_ok, fmt_ms(tcp_lat), url_ok, fmt_ms(url_lat),
    )

    if url_ok and url_lat is not None:
        latency, source, ok = url_lat, "url_test", True
    elif tcp_ok and tcp_lat is not None:
        latency, source, ok = tcp_lat, "tcping", True
    else:
        latency, source, ok = None, None, False

    result = dict(srv)
    result.update({
        "tcping_ok": tcp_ok,
        "tcping_latency": tcp_lat,
        "url_ok": url_ok,
        "url_latency": url_lat,
        "latency": latency,
        "latency_source": source,
        "ok": ok,
    })
    return result


def measure_servers_latency(
    servers: Dict[str, Dict[str, Any]],
    max_workers: int = MAX_WORKERS,
) -> Dict[str, Dict[str, Any]]:
    """
    Step 5: parallel latency measurement across all nodes.
    Total time ≈ time of the slowest node.
    """
    if not servers:
        return {}

    logger.info("Measuring latency: %d nodes, in parallel (workers=%d)",
                len(servers), max_workers)
    results: Dict[str, Dict[str, Any]] = {}

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(_check_one_server, srv): sid
                   for sid, srv in servers.items()}
        for fut in as_completed(futures):
            sid = futures[fut]
            try:
                results[sid] = fut.result()
            except Exception as exc:  # noqa: BLE001
                logger.exception("Error checking node %s: %s", sid, exc)
                bad = dict(servers[sid])
                bad.update({"ok": False, "latency": None,
                            "tcping_ok": False, "url_ok": False})
                results[sid] = bad

    for sid, srv in results.items():
        logger.info(
            "  %s ('%s') %s:%s → tcping=%s(%s), url_test=%s(%s) → latency=%s (src=%s)",
            sid, srv["remarks"], srv["address"], srv["port"],
            "OK" if srv.get("tcping_ok") else "FAIL",
            fmt_ms(srv.get("tcping_latency")),
            "OK" if srv.get("url_ok") else "FAIL",
            fmt_ms(srv.get("url_latency")),
            fmt_ms(srv.get("latency")),
            srv.get("latency_source") or "n/a",
        )
    return results


def select_best_server(
    servers: Dict[str, Dict[str, Any]],
    state: Dict[str, Any],
) -> Optional[Dict[str, Any]]:
    """
    Selects the node with the minimum latency among those available.

    Excluded:
        * nodes that failed the current measurement (ok=False);
        * nodes in the static blacklist;
        * nodes in the dynamic blacklist (state.node_stats).
    """
    available: List[Dict[str, Any]] = []
    skipped: List[Tuple[str, str, str]] = []

    for srv in servers.values():
        if not srv.get("ok") or srv.get("latency") is None:
            continue
        banned, reason = is_node_blacklisted(srv["address"], state)
        if banned:
            skipped.append((srv["id"], srv["address"], reason or ""))
            continue
        available.append(srv)

    for sid, addr, reason in skipped:
        logger.info("Skipping node %s (%s): %s", sid, addr, reason)

    if not available:
        logger.error("No available nodes after filtering")
        return None

    logger.debug(
        "Available candidates (id, latency_ms): %s",
        [(s["id"], round(s["latency"], 1)) for s in available],
    )

    available.sort(key=lambda s: s["latency"])
    best = available[0]
    logger.info(
        "Best node: id=%s, remarks='%s', %s:%s, latency=%s (src=%s)",
        best["id"], best["remarks"], best["address"], best["port"],
        fmt_ms(best["latency"]), best.get("latency_source") or "n/a",
    )
    return best
