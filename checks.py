# -*- coding: utf-8 -*-
"""
checks.py — network checks: TCP, HTTPS, external resources.
"""

from __future__ import annotations

import logging
import re
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Tuple
from logger import logger
from utils import extract_host_port, fmt_ms, run_command
from data import (
    CHECK_URLS,
    CURL_BIN,
    CURL_TIMEOUT,
    MAX_WORKERS,
    TCPING_BIN,
    TCPING_TIMEOUT,
    VALID_REDIRECT_CODES,
)



# ─────────────────────────────────────────────────────────────────────────────
# Basic checks
# ─────────────────────────────────────────────────────────────────────────────
def tcping(
    host: str, port: int, timeout: int = TCPING_TIMEOUT
) -> Tuple[bool, Optional[float]]:
    """
    TCP check via the `tcping` utility.

    Syntax: tcping -c 1 -t <timeout> -p <port> <host>

    IMPORTANT: on failure we return latency=None — protection against a bug where
    tcping prints 'time=0.00ms' even on a failed attempt, and a zero latency
    gets treated as the best result.

    :return: (success, latency_ms_or_None).
    """
    if not host or not port:
        return False, None

    cmd = [
        TCPING_BIN,
        "-c", "1",
        "-t", str(timeout),
        "-p", str(port),
        host,
    ]

    try:
        res = run_command(cmd, timeout=timeout + 3)
    except RuntimeError:
        return False, None

    output = f"{res.stdout or ''}\n{res.stderr or ''}"
    success = res.returncode == 0 or "successful" in output.lower()

    if not success:
        return False, None

    latency: Optional[float] = None
    m = re.search(r"time[=\s]+([\d.]+)\s*ms", output, re.IGNORECASE)
    if not m:
        m = re.search(r"([\d.]+)\s*ms", output)
    if m:
        try:
            latency = float(m.group(1))
        except ValueError:
            latency = None

    if latency is None:
        return False, None
    return True, latency


def curl_https_check(url: str, timeout: int = CURL_TIMEOUT) -> Tuple[bool, Optional[int]]:
    """
    HTTPS GET check via curl.

    Returns (got_response, http_code). If the connection is not established
    or times out — (False, None). Code 0 (curl "000") is normalized to None.

    :param url:     URL to check;
    :param timeout: timeout in seconds.
    :return:        (got_response, http_code_or_None).
    """
    cmd = [
        CURL_BIN,
        "-s", "-o", "/dev/null",
        "-w", "%{http_code}",
        "--max-time", str(timeout),
        "-L",
        "--insecure",
        url,
    ]
    try:
        res = run_command(cmd, timeout=timeout + 3)
    except RuntimeError:
        return False, None

    code_str = (res.stdout or "").strip()
    try:
        code = int(code_str)
    except ValueError:
        return False, None

    if code == 0:
        return False, None

    return True, code


def url_test(
    host: str, port: int, timeout: int = TCPING_TIMEOUT
) -> Tuple[bool, Optional[float]]:
    """
    A node's `url-test` — an independent check over a plain Python socket.

    This serves as the second, independent latency measurement point from tcping.
    By spec, the url-test result takes priority over tcping when choosing latency.

    :return: (success, latency_ms_or_None).
    """
    if not host or not port:
        return False, None

    start = time.monotonic()
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True, (time.monotonic() - start) * 1000.0
    except (OSError, ValueError) as exc:
        logger.debug("url_test %s:%s failed: %s", host, port, exc)
        return False, None


# ─────────────────────────────────────────────────────────────────────────────
# HTTP code helpers
# ─────────────────────────────────────────────────────────────────────────────
def _is_http_code_ok(code: Optional[int]) -> bool:
    """True for 2xx, 301, 302, 307, 308. Everything else is a failure."""
    if not code:
        return False
    if 200 <= code < 300:
        return True
    return code in VALID_REDIRECT_CODES


def _is_http_code_5xx(code: Optional[int]) -> bool:
    """True for 5xx."""
    if not code:
        return False
    return 500 <= code < 600


def _format_http_code(code: Optional[int]) -> str:
    """Formats an HTTP status code for log output. None and 0 → 'timeout'."""
    if code is None or code == 0:
        return "timeout"
    return str(code)


def evaluate_resource(tcp_ok: bool, http_code: Optional[int]) -> Tuple[bool, str]:
    """
    Evaluates the availability of a single resource based on the results of two checks.

    Priority:
        1. HTTPS check — primary criterion.
        2. If the HTTP code is valid (2xx / 301 / 302 / 307 / 308) — resource OK.
        3. If the HTTP code is 5xx — priority falls back to tcping: tcping OK →
           resource OK (server is down, but the network works), tcping FAIL → FAIL.
        4. Everything else (4xx, 0, timeout) — resource NOT available.

    :return: (is_available, short_reason).
    """
    if not http_code:
        return False, "https timeout"

    if _is_http_code_ok(http_code):
        return True, f"http {http_code}"

    if _is_http_code_5xx(http_code):
        if tcp_ok:
            return True, f"http {http_code} (fallback to tcping OK)"
        return False, f"http {http_code} (tcping FAIL)"

    return False, f"http {http_code}"


# ─────────────────────────────────────────────────────────────────────────────
# External resources
# ─────────────────────────────────────────────────────────────────────────────
def _check_single_url(url: str) -> Tuple[str, Dict[str, Any]]:
    """
    Checks a single external URL (tcping + curl). For ThreadPool.

    :return: (url, info). info contains:
                host, port, tcping_ok, tcping_latency_ms,
                https_ok, http_code, resource_ok, reason.
    """
    host, port = extract_host_port(url)
    logger.debug("Checking %s (%s:%s)", url, host, port)

    tcp_ok, tcp_lat = tcping(host, port)
    got_response, http_code = curl_https_check(url)

    # https_ok — a valid HTTP code, not just any response.
    https_ok = got_response and _is_http_code_ok(http_code)

    resource_ok, reason = evaluate_resource(tcp_ok, http_code)

    logger.debug(
        "  %s → tcping=%s/%s, https=%s/%s",
        url, tcp_ok, fmt_ms(tcp_lat), got_response, http_code,
    )

    return url, {
        "host": host,
        "port": port,
        "tcping_ok": tcp_ok,
        "tcping_latency_ms": tcp_lat,
        "https_ok": https_ok,
        "http_code": http_code,
        "resource_ok": resource_ok,
        "reason": reason,
    }


def check_external_resources() -> Tuple[bool, Dict[str, Any]]:
    """
    Step 1: parallel connectivity check against external resources.

    Success conditions:
        * no more than one resource may fail (for N >= 2);
        * for N = 1 — the single resource must be available.

    Logging:
        * unavailable resource → CRITICAL;
        * overall FAIL → CRITICAL;
        * available resource → INFO.

    :return: (overall_success, details for each URL).
    """
    total = len(CHECK_URLS)
    logger.info("Checking external resources (%d items, in parallel)", total)

    details: Dict[str, Any] = {}
    workers = min(MAX_WORKERS, max(1, total))

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_check_single_url, u): u for u in CHECK_URLS}
        for fut in as_completed(futures):
            url = futures[fut]
            try:
                _, info = fut.result()
                details[url] = info
            except Exception as exc:  # noqa: BLE001
                logger.exception("Error checking resource %s: %s", url, exc)
                details[url] = {
                    "resource_ok": False,
                    "reason": f"exception: {exc}",
                }

    # Summary and failure count.
    failed_urls: List[str] = []
    for url in CHECK_URLS:
        info = details.get(url)
        if info is None:
            continue

        if "reason" in info and info["reason"].startswith("exception:"):
            logger.critical("  %s → ERROR: %s", url, info["reason"])
            failed_urls.append(url)
            continue

        level = logging.INFO if info.get("resource_ok") else logging.CRITICAL
        logger.log(
            level,
            "  %s (%s:%s) → tcping=%s(%s), https=%s(%s) → %s [%s]",
            url, info["host"], info["port"],
            "OK" if info["tcping_ok"] else "FAIL",
            fmt_ms(info["tcping_latency_ms"]),
            "OK" if info["https_ok"] else "FAIL",
            _format_http_code(info["http_code"]),
            "OK" if info["resource_ok"] else "FAIL",
            info["reason"],
        )
        if not info["resource_ok"]:
            failed_urls.append(url)

    # Final decision: no more than 1 failure for N >= 2.
    allowed_fails = 1 if total >= 2 else 0
    overall_ok = len(failed_urls) <= allowed_fails

    if overall_ok:
        logger.info(
            "External checks summary: OK (available %d of %d, failed: %s)",
            total - len(failed_urls), total,
            ", ".join(failed_urls) if failed_urls else "none",
        )
    else:
        logger.critical(
            "External checks summary: FAIL (failed %d of %d: %s)",
            len(failed_urls), total, ", ".join(failed_urls),
        )

    return overall_ok, details
