# -*- coding: utf-8 -*-
"""
data.py — configuration loader and all global constants.

Reads /etc/netwatcher/config.toml (path can be overridden via the
NETWATCHER_CONFIG_DIR env var) and exposes all values as module-level
constants.

Also holds the hard-coded program constants (PassWall2 package name,
direct node alias, valid HTTP redirect codes) — these are part of the
program's contract with PassWall2 and are not user-tunable.
"""

import os
import sys

try:
    import tomllib  # Python 3.11+
except ImportError:
    print(
        "FATAL: Python 3.11+ is required (tomllib not available).",
        file=sys.stderr,
    )
    sys.exit(2)


# ─────────────────────────────────────────────────────────────────────────────
# Locate and parse config.toml
# ─────────────────────────────────────────────────────────────────────────────
CONFIG_DIR  = os.environ.get("NETWATCHER_CONFIG_DIR", "/etc/netwatcher")
CONFIG_FILE = os.path.join(CONFIG_DIR, "config.toml")


def _load_toml() -> dict:
    """Loads config.toml. Exits with code 2 on any error."""
    try:
        with open(CONFIG_FILE, "rb") as fh:
            return tomllib.load(fh)
    except FileNotFoundError:
        print(f"FATAL: config file not found: {CONFIG_FILE}", file=sys.stderr)
        sys.exit(2)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        print(f"FATAL: cannot parse {CONFIG_FILE}: {exc}", file=sys.stderr)
        sys.exit(2)


_CFG = _load_toml()


def _get(section: str, key: str, default=None):
    """Reads a value from a TOML section with a default fallback."""
    return _CFG.get(section, {}).get(key, default)


def _int(section: str, key: str, default: int) -> int:
    """Reads an int, coercing strings safely."""
    value = _get(section, key, default)
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _bool(section: str, key: str, default: bool) -> bool:
    """
    Reads a bool. Accepts native bool, plus string forms '1/true/yes/on'
    so that `file_color = "false"` doesn't accidentally become `True`.
    """
    value = _get(section, key, default)
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in ("1", "true", "yes", "on")
    if isinstance(value, (int, float)):
        return bool(value)
    return default


# ─────────────────────────────────────────────────────────────────────────────
# Paths
# ─────────────────────────────────────────────────────────────────────────────
LOG_DIR    = _get("paths", "log_dir",    "/var/log/netwatcher")
LOG_FILE   = _get("paths", "log_file",   os.path.join(LOG_DIR, "netwatcher.log"))
STATE_FILE = _get("paths", "state_file", os.path.join(LOG_DIR, "state.json"))


# ─────────────────────────────────────────────────────────────────────────────
# External checks — tunnel
# ─────────────────────────────────────────────────────────────────────────────
CHECK_URLS      = _get("checks", "urls", [])
URL_TEST_TARGET = _get("checks", "url_test_target", CHECK_URLS[0] if CHECK_URLS else "")


# ─────────────────────────────────────────────────────────────────────────────
# External checks — direct internet (runs BEFORE the tunnel check)
# ─────────────────────────────────────────────────────────────────────────────
INTERNET_PING_HOST     = _get("checks", "direct_ping_host", "178.219.36.49")
INTERNET_PING_TIMEOUT  = _int("checks", "direct_ping_timeout", 1)
INTERNET_TCPING_TARGETS = _get("checks", "direct_tcping_targets", [])
INTERNET_TCPING_TIMEOUT = _int("checks", "direct_tcping_timeout", 2)


# ─────────────────────────────────────────────────────────────────────────────
# External checks — DNS (runs AFTER internet, BEFORE the tunnel check)
# ─────────────────────────────────────────────────────────────────────────────
DNS_CHECK_DOMAIN  = _get("checks", "dns_check_domain", "ya.ru")
DNS_CHECK_TIMEOUT = _int("checks", "dns_check_timeout", 5)
DNS_CHECK_DNSSEC  = _bool("checks", "dns_check_dnssec", True)
DNS_FALLBACKS     = _get("checks", "dns_fallbacks", [])


# ─────────────────────────────────────────────────────────────────────────────
# External utilities
# ─────────────────────────────────────────────────────────────────────────────
TCPING_BIN = _get("utilities", "tcping", "tcping")
CURL_BIN   = _get("utilities", "curl",   "curl")
UCI_BIN    = _get("utilities", "uci",    "uci")
LUA_BIN    = _get("utilities", "lua",    "lua")
PING_BIN   = _get("utilities", "ping",   "ping")
DIG_BIN    = _get("utilities", "dig",    "dig")


# ─────────────────────────────────────────────────────────────────────────────
# Timeouts (sec)
# ─────────────────────────────────────────────────────────────────────────────
TCPING_TIMEOUT    = _int("timeouts", "tcping",    5)
CURL_TIMEOUT      = _int("timeouts", "curl",      10)
NET_CMD_TIMEOUT   = _int("timeouts", "net_cmd",   30)
SUBSCRIBE_WAIT    = _int("timeouts", "subscribe", 45)
INIT_RESTART_WAIT = _int("timeouts", "restart",   8)


# ─────────────────────────────────────────────────────────────────────────────
# PassWall2 — hard-coded (program contract)
# ─────────────────────────────────────────────────────────────────────────────
PASSWALL2_PACKAGE = "passwall2"
PASSWALL2_GLOBAL  = "passwall2.@global[0]"
DIRECT_NODE       = "_direct"


# ─────────────────────────────────────────────────────────────────────────────
# PassWall2 — paths (user-tunable)
# ─────────────────────────────────────────────────────────────────────────────
PASSWALL2_INIT = _get("passwall2", "init",          "/etc/init.d/passwall2")
SUBSCRIBE_LUA  = _get("passwall2", "subscribe_lua", "/usr/share/passwall2/subscribe.lua")


# ─────────────────────────────────────────────────────────────────────────────
# Parallelism
# ─────────────────────────────────────────────────────────────────────────────
MAX_WORKERS = _int("parallelism", "max_workers", 8)


# ─────────────────────────────────────────────────────────────────────────────
# Blacklist
# ─────────────────────────────────────────────────────────────────────────────
SERVER_BLACKLIST_ADDRESSES = _get("blacklist", "static_addresses", [])
BLACKLIST_THRESHOLD        = _int("blacklist", "threshold",    3)
BLACKLIST_DURATION_MIN     = _int("blacklist", "duration_min", 30)


# ─────────────────────────────────────────────────────────────────────────────
# State
# ─────────────────────────────────────────────────────────────────────────────
HISTORY_LIMIT = _int("state", "history_limit", 100)


# ─────────────────────────────────────────────────────────────────────────────
# Logging
# ─────────────────────────────────────────────────────────────────────────────
LOG_LEVEL      = _int("logging", "level",      1)
LOG_FILE_COLOR = _bool("logging", "file_color", True)


# ─────────────────────────────────────────────────────────────────────────────
# Hard-coded constants
# ─────────────────────────────────────────────────────────────────────────────
VALID_REDIRECT_CODES = (301, 302, 307, 308)


# ─────────────────────────────────────────────────────────────────────────────
# Validation
# ─────────────────────────────────────────────────────────────────────────────
def validate_config() -> None:
    """
    Validates critical runtime parameters. If checks.urls is empty,
    the program exits with code 2.
    """
    from logger import logger

    if not CHECK_URLS:
        logger.error("checks.urls in config.toml is empty — nothing to check")
        sys.exit(2)
    if not SERVER_BLACKLIST_ADDRESSES:
        logger.info("blacklist.static_addresses is empty — static blacklist disabled")
    if not INTERNET_TCPING_TARGETS and not INTERNET_PING_HOST:
        logger.warning(
            "checks.direct_tcping_targets and checks.direct_ping_host are both empty — "
            "direct internet check will be skipped"
        )
    logger.info(
        "Parameters: MAX_WORKERS=%d, BLACKLIST_THRESHOLD=%d, BLACKLIST_DURATION_MIN=%d",
        MAX_WORKERS, BLACKLIST_THRESHOLD, BLACKLIST_DURATION_MIN,
    )
