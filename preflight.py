# -*- coding: utf-8 -*-
"""
preflight.py — pre-flight checks that run BEFORE any state change.

Order:
    1. PassWall2 is installed and the shunt node is configured.
    2. Direct internet works (ping / tcping, OR logic).
    3. A working DNS server is configured as direct_dns.

On failure of any check — logs FATAL and returns False. Caller must exit
WITHOUT touching state, config, or PassWall2.
"""

from typing import List

from checks import _dns_resolve_check, direct_internet_ok
from data import (
    DNS_CHECK_DOMAIN,
    DNS_CHECK_TIMEOUT,
    DNS_FALLBACKS,
    PASSWALL2_GLOBAL,
)
from logger import logger
from passwall import check_passwall2_ready, restart_passwall2
from uci import uci_commit, uci_get, uci_set


def ensure_working_dns() -> bool:
    """
    Ensures that at least one working DNS server is configured as
    `passwall2.@global[0].direct_dns`.

    Strategy:
        1. Read the current value (comma-separated list supported).
        2. Test each of them.
        3. If none works, try each fallback from config in order.
        4. On first success — set direct_dns, commit, restart PassWall2.
        5. If none works — FATAL, return False (no internet / DNS at all).

    Nothing is modified in UCI unless a working DNS is actually found.
    """
    raw = uci_get(f"{PASSWALL2_GLOBAL}.direct_dns") or ""
    current_servers: List[str] = [s.strip() for s in raw.split(",") if s.strip()]

    # Step 1: test the currently configured DNS servers
    for dns in current_servers:
        logger.debug("DNS check: testing current '%s' for %s", dns, DNS_CHECK_DOMAIN)
        if _dns_resolve_check(dns, DNS_CHECK_DOMAIN, DNS_CHECK_TIMEOUT):
            logger.info("DNS check: current DNS '%s' works", dns)
            return True
    if current_servers:
        logger.warning("DNS check: current DNS %s is NOT working", current_servers)
    else:
        logger.warning("DNS check: no direct_dns configured")

    # Step 2: try fallbacks
    for dns in DNS_FALLBACKS:
        if dns in current_servers:
            continue  # already tested above and known broken
        logger.debug("DNS check: testing fallback '%s' for %s", dns, DNS_CHECK_DOMAIN)
        if not _dns_resolve_check(dns, DNS_CHECK_DOMAIN, DNS_CHECK_TIMEOUT):
            continue

        logger.info("DNS check: fallback '%s' works, switching", dns)
        if not uci_set(f"{PASSWALL2_GLOBAL}.direct_dns", dns):
            logger.error("DNS check: failed to write direct_dns=%s", dns)
            continue
        if not uci_commit():
            logger.error("DNS check: failed to commit UCI after DNS change")
            continue
        if not restart_passwall2():
            # Config is committed; the change will be picked up on next restart.
            logger.error("DNS check: PassWall2 restart failed after DNS change")
        return True

    logger.fatal(
        "DNS check: no working DNS server (tested current %s + fallbacks %s)",
        current_servers or ["<none>"],
        DNS_FALLBACKS,
    )
    return False


def run_preflight_checks() -> bool:
    """
    Runs all startup checks. Returns True if the program can proceed.

    Order matters:
        1. PassWall2 readiness (config check — no network needed).
        2. Direct internet (network check — no DNS needed).
        3. DNS (network check — needs internet).

    If any check fails — returns False. Caller must exit without touching
    state (the specific FATAL is already logged inside).
    """
    logger.debug("Preflight: PassWall2 readiness")
    if not check_passwall2_ready():
        return False

    logger.debug("Preflight: direct internet")
    if not direct_internet_ok():
        return False

    logger.debug("Preflight: DNS")
    if not ensure_working_dns():
        return False

    logger.info("Preflight checks: all OK")
    return True
  
