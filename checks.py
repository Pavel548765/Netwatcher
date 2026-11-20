# -*- coding: utf-8 -*-
"""
checks.py — network checks: TCP, ICMP, HTTPS, socket, DNS, external resources.
"""

from __future__ import annotations

import logging
import re
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Tuple

from data import (
    CHECK_URLS,
    CURL_BIN,
    CURL_TIMEOUT,
    DIG_BIN,
    DNS_CHECK_DNSSEC,
    INTERNET_PING_HOST,
    INTERNET_PING_TIMEOUT,
    INTERNET_TCPING_TARGETS,
    INTERNET_TCPING_TIMEOUT,
    MAX_WORKERS,
    PING_BIN,
    TCPING_BIN,
    TCPING_TIMEOUT,
    VALID_REDIRECT_CODES,
)
from logger import logger
from utils import extract_host_port, fmt_ms, run_command, which


# ─────────────────────────────────────────────────────────────────────────────
# Basic checks
# ─────────────────────────────────────────────────────────────────────────────
def tcping(
    host: str, port: int, timeout: int = TCPING_TIMEOUT
) -> Tuple[bool, Optional[float]]:
    """
    TCP check via the `tcping` utility.

    Syntax: tcping -c 1 -t <timeout> -p <port> <host>

    IMPORTANT: on failure we return latency=None — protection against a bug
    where tcping prints 'time=0.00ms' even on a failed attempt, and a zero
    latency gets treated as the best result.

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


def _ping_ok(host: str, timeout: int = 1) -> bool:
    """
    ICMP ping check: `ping -c 1 -W <timeout> <host>`.

    :return: True if the host replied, False otherwise (or binary missing).
    """
    if not host:
        return False
    if not which(PING_BIN):
        logger.debug("_ping_ok: '%s' not in PATH, skipping ICMP check", PING_BIN)
        return False

    cmd = [PING_BIN, "-c", "1", "-W", str(timeout), host]
    try:
        res = run_command(cmd, timeout=timeout + 3)
    except RuntimeError:
        return False
    return res.returncode == 0


def _parse_host_port(target: str, default_port: int = 443) -> Tuple[str, int]:
    """Parses 'host:port' or 'host' → (host, port)."""
    if ":" in target:
        host, port_s = target.rsplit(":", 1)
        try:
            return host, int(port_s)
        except ValueError:
            return host, default_port
    return target, default_port


def direct_internet_ok() -> bool:
    """
    Preflight: verifies that the internet works at all, BEFORE the tunnel
    is checked. This is deliberately done on raw IPs, so it doesn't depend
    on DNS.

    OR logic: any single successful check = internet is up.
        1. ICMP ping to `INTERNET_PING_HOST`.
        2. tcping to any target in `INTERNET_TCPING_TARGETS`.

    If everything fails — logs FATAL and returns False. The caller must
    abort without touching state or PassWall2.
    """
    # 1. ICMP ping
    if _ping_ok(INTERNET_PING_HOST, INTERNET_PING_TIMEOUT):
        logger.info("Direct internet: OK (ping %s)", INTERNET_PING_HOST)
        return True
    logger.debug("Direct internet: ping %s failed", INTERNET_PING_HOST)

    # 2. tcping targets
    for target in INTERNET_TCPING_TARGETS:
        host, port = _parse_host_port(target, 443)
        logger.debug("Direct internet: tcping %s:%d", host, port)
        ok, lat = tcping(host, port, timeout=INTERNET_TCPING_TIMEOUT)
        if ok:
            logger.info(
                "Direct internet: OK (tcping %s:%d, %s)",
                host, port, fmt_ms(lat),
            )
            return True

    logger.fatal(
        "Direct internet: FAIL (ping %s + %d tcping targets all failed)",
        INTERNET_PING_HOST, len(INTERNET_TCPING_TARGETS),
    )
    return False


def _dns_resolve_check(dns_ip: str, domain: str, timeout: int = 5) -> bool:
    """
    Resolves `domain` via the given DNS server and returns True if any
    answer was received.

    Empty output is treated as failure (DNS dead / NXDOMAIN / timeout).

    :param dns_ip:  IP of the DNS server (no port; dig defaults to 53);
    :param domain:  domain to resolve;
    :param timeout: per-query timeout in seconds.
    """
    if not dns_ip or not domain:
        return False

    cmd = [DIG_BIN, f"@{dns_ip}", "+udp", "+short", f"+time={timeout}"]
    if DNS_CHECK_DNSSEC:
        cmd.insert(2, "+dnssec")
    cmd.append(domain)

    try:
        res = run_command(cmd, timeout=timeout + 3)
    except RuntimeError:
        return False
    if res.returncode != 0:
        return False
    return bool((res.stdout or "").strip())


def curl_https_check(url: str, timeout: int = CURL_TIMEOUT) -> Tuple[bool, Optional[int]]:
    """ ... unchanged ... """
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
    """ ... unchanged ... """
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
# HTTP code helpers + external resources
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
