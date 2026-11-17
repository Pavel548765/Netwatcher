#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
netwatcher.py — entry point.

The actual work is delegated to the modules:
    config, utils, logger, uci, state, checks, passwall, nodes.
"""

import os
import sys

from config import UCI_BIN, CURL_BIN, LUA_BIN, TCPING_BIN, validate_config
from logger import logger
from utils import which
from state import load_state, save_state, append_history
from checks import check_external_resources
from passwall import (
    parse_passwall2_nodes,
    vpn_set_default_node,
    vpn_switch_to_direct,
    vpn_update_subscriptions,
)
from nodes import measure_servers_latency, select_best_server
from utils import fmt_ms


def _log_banner(title: str) -> None:
    """A prominent log header."""
    line = "─" * 60
    logger.info(line)
    logger.info(title)
    logger.info(line)


def _finish_with_error(state, reason, extra=None) -> int:
    """
    Standardized error exit: writes state and history, then returns 1.
    """
    logger.error("Finishing with error: %s", reason)
    state["last_result"] = "fail"
    entry = {"result": "fail", "reason": reason}
    if extra:
        entry.update(extra)
    append_history(state, entry)
    save_state(state)
    return 1


def main() -> int:
    """Entry point. Returns the process exit code."""
    _log_banner("netwatcher: startup")
    validate_config()
    logger.info("PID=%s, euid=%s", os.getpid(), os.geteuid())

    for tool in (UCI_BIN, CURL_BIN, LUA_BIN, TCPING_BIN):
        path = which(tool)
        if path:
            logger.info("Utility '%s' found: %s", tool, path)
        else:
            logger.warning("Utility '%s' not found in PATH", tool)

    # ── Load state ────────────────────────────────────────────────────────
    logger.debug("Step 0: loading state")
    state = load_state()
    logger.debug(
        "Loaded state: keys=%s, last_run=%s",
        list(state.keys()), state.get("last_run"),
    )
    logger.info(
        "Previous state: last_result=%s, consecutive_fails=%s, nodes in stats=%d",
        state.get("last_result"),
        state.get("consecutive_fails"),
        len(state.get("node_stats") or {}),
    )

    # ── Step 1: connectivity check ─────────────────────────────────────────
    logger.debug("Step 1: external connectivity check")
    ok, details = check_external_resources()
    state["last_checks"] = details

    if ok:
        logger.info("Connectivity is fine — exiting")
        state["last_result"] = "ok"
        state["consecutive_fails"] = 0
        append_history(state, {"result": "ok", "checks": details})
        save_state(state)
        return 0

    prev_result = state.get("last_result")
    if prev_result != "fail":
        logger.warning(
            "There is no connectivity, but the previous result was '%s' — waiting for confirmation",
            prev_result,
        )
        state["last_result"] = "fail"
        state["consecutive_fails"] = int(state.get("consecutive_fails") or 0) + 1
        append_history(state, {"result": "fail",
                               "reason": "first failure in streak",
                               "checks": details})
        save_state(state)
        return 0

    logger.warning("Confirmed connectivity failure (2 runs in a row) — starting failover")
    state["consecutive_fails"] = int(state.get("consecutive_fails") or 0) + 1

    # ── Step 2: disable VPN ─────────────────────────────────────────────────
    logger.debug("Step 2: switching PassWall2 to _direct")
    if not vpn_switch_to_direct():
        return _finish_with_error(state, "failed to switch PassWall2 to _direct")

    # ── Step 3: update subscriptions ───────────────────────────────────────
    logger.debug("Step 3: updating subscriptions")
    if not vpn_update_subscriptions():
        return _finish_with_error(state, "subscription update failed")

    # ── Step 4: parse nodes ─────────────────────────────────────────────────
    logger.debug("Step 4: parsing PassWall2 nodes")
    servers = parse_passwall2_nodes()
    if not servers:
        return _finish_with_error(state, "node list is empty")
    logger.debug("Parsed %d nodes", len(servers))

    # ── Step 5: measure latency ────────────────────────────────────────────
    logger.debug("Step 5: measuring latency")
    servers = measure_servers_latency(servers)

    # Update stats BEFORE selection so the dynamic blacklist is considered in this run.
    logger.debug("Updating per-node stats")
    from state import update_node_stats
    update_node_stats(state, servers)

    # ── Step 6: choose and set ──────────────────────────────────────────────
    logger.debug("Step 6: selecting best server")
    best = select_best_server(servers, state)
    if not best:
        summary = {
            sid: {
                "remarks": s.get("remarks"),
                "address": s.get("address"),
                "latency": s.get("latency"),
                "ok": s.get("ok"),
            }
            for sid, s in servers.items()
        }
        return _finish_with_error(
            state,
            "no node passed validation / all are blacklisted",
            extra={"servers": summary},
        )

    logger.debug("Setting default node %s", best["id"])
    if not vpn_set_default_node(best["id"]):
        return _finish_with_error(
            state,
            f"failed to set default node {best['id']}",
        )

    # Success.
    state["last_result"] = "switched"
    state["selected_server"] = {
        "id": best["id"],
        "remarks": best["remarks"],
        "address": best["address"],
        "port": best["port"],
        "latency": best["latency"],
        "latency_source": best.get("latency_source"),
    }
    summary = {
        sid: {
            "remarks": s.get("remarks"),
            "address": s.get("address"),
            "latency": s.get("latency"),
            "latency_source": s.get("latency_source"),
            "ok": s.get("ok"),
        }
        for sid, s in servers.items()
    }
    append_history(state, {
        "result": "switched",
        "selected": state["selected_server"],
        "servers": summary,
    })
    save_state(state)

    _log_banner(
        f"netwatcher: switched to {best['id']} ('{best['remarks']}', "
        f"{best['address']}:{best['port']}) latency={fmt_ms(best['latency'])}"
    )
    return 0


# ─────────────────────────────────────────────────────────────────────────────
# Startup
# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        logger.warning("Interrupted by user (Ctrl+C)")
        sys.exit(130)
    except Exception as exc:  # noqa: BLE001
        logger.exception("Unexpected error: %s", exc)
        sys.exit(1)
