# -*- coding: utf-8 -*-
"""
uci.py — thin wrapper around the OpenWrt `uci` utility.
"""

from __future__ import annotations

from typing import Optional
from utils import run_command
from data import NET_CMD_TIMEOUT, PASSWALL2_PACKAGE, UCI_BIN
from logger import logger
from utils import run_command


def uci_get(path: str) -> Optional[str]:
    """Reads a UCI parameter, None if missing or on error."""
    logger.debug("uci get %s", path)
    try:
        res = run_command([UCI_BIN, "-q", "get", path], timeout=10)
    except RuntimeError:
        return None
    if res.returncode != 0:
        logger.debug("uci get %s → exit %d", path, res.returncode)
        return None
    value = (res.stdout or "").strip() or None
    logger.debug("uci get %s → %r", path, value)
    return value


def uci_set(path: str, value: str) -> bool:
    """Sets a UCI parameter. True on success."""
    try:
        res = run_command([UCI_BIN, "set", f"{path}={value}"], timeout=10)
    except RuntimeError:
        return False
    if res.returncode != 0:
        logger.error("uci set %s=%s failed: %s",
                     path, value, (res.stderr or "").strip())
        return False
    logger.info("UCI: set %s=%s", path, value)
    return True


def uci_commit(package: str = PASSWALL2_PACKAGE) -> bool:
    """Commits UCI changes for a package."""
    try:
        res = run_command([UCI_BIN, "commit", package], timeout=10)
    except RuntimeError:
        return False
    if res.returncode != 0:
        logger.error("uci commit %s failed: %s",
                     package, (res.stderr or "").strip())
        return False
    logger.info("UCI: changes for '%s' committed", package)
    return True


def uci_show(package: str = PASSWALL2_PACKAGE) -> str:
    """Full dump of `uci show <package>`."""
    logger.debug("uci show %s", package)
    try:
        res = run_command([UCI_BIN, "show", package], timeout=NET_CMD_TIMEOUT)
    except RuntimeError:
        return ""
    if res.returncode != 0:
        logger.error("uci show %s failed", package)
        return ""
    dump = res.stdout or ""
    logger.debug("uci show %s → %d bytes", package, len(dump))
    return dump
