#!/usr/bin/env python3

import json
import logging
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse


# ─────────────────────────────────────────────────────────────────────────────
# Loading the user configuration from /etc/netwatcher/data.py
# ─────────────────────────────────────────────────────────────────────────────
CONFIG_DIR = os.environ.get("NETWATCHER_CONFIG_DIR", "/etc/netwatcher")
if CONFIG_DIR not in sys.path:
    sys.path.insert(0, CONFIG_DIR)

try:
    import data as CONFIG  # type: ignore
except ImportError as exc:
    print(
        f"FATAL: failed to load configuration from {CONFIG_DIR}/data.py: {exc}",
        file=sys.stderr,
    )
    sys.exit(2)


# ─────────────────────────────────────────────────────────────────────────────
# Constants from data.py
# ─────────────────────────────────────────────────────────────────────────────
LOG_DIR    = getattr(CONFIG, "LOG_DIR",    "/var/log/netwatcher")
LOG_FILE   = getattr(CONFIG, "LOG_FILE",   os.path.join(LOG_DIR, "netwatcher.log"))
STATE_FILE = getattr(CONFIG, "STATE_FILE", os.path.join(LOG_DIR, "state.json"))

CHECK_URLS: List[str]  = getattr(CONFIG, "CHECK_URLS", [])
URL_TEST_TARGET: str   = getattr(CONFIG, "URL_TEST_TARGET", CHECK_URLS[0] if CHECK_URLS else "")

TCPING_BIN: str = getattr(CONFIG, "TCPING_BIN", "tcping")
CURL_BIN: str   = getattr(CONFIG, "CURL_BIN",   "curl")
UCI_BIN: str    = getattr(CONFIG, "UCI_BIN",    "uci")
LUA_BIN: str    = getattr(CONFIG, "LUA_BIN",    "lua")

TCPING_TIMEOUT:    int = getattr(CONFIG, "TCPING_TIMEOUT",    5)
CURL_TIMEOUT:      int = getattr(CONFIG, "CURL_TIMEOUT",      10)
NET_CMD_TIMEOUT:   int = getattr(CONFIG, "NET_CMD_TIMEOUT",   30)
SUBSCRIBE_WAIT:    int = getattr(CONFIG, "SUBSCRIBE_WAIT",    45)
INIT_RESTART_WAIT: int = getattr(CONFIG, "INIT_RESTART_WAIT", 8)

PASSWALL2_INIT:    str = getattr(CONFIG, "PASSWALL2_INIT",    "/etc/init.d/passwall2")
SUBSCRIBE_LUA:     str = getattr(CONFIG, "SUBSCRIBE_LUA",     "/usr/share/passwall2/subscribe.lua")
PASSWALL2_PACKAGE: str = getattr(CONFIG, "PASSWALL2_PACKAGE", "passwall2")
PASSWALL2_GLOBAL:  str = getattr(CONFIG, "PASSWALL2_GLOBAL",  "passwall2.@global[0]")
DIRECT_NODE:       str = getattr(CONFIG, "DIRECT_NODE",       "_direct")

MAX_WORKERS: int = getattr(CONFIG, "MAX_WORKERS", 8)

SERVER_BLACKLIST_ADDRESSES: List[str] = getattr(CONFIG, "SERVER_BLACKLIST_ADDRESSES", [])
BLACKLIST_THRESHOLD:    int = getattr(CONFIG, "BLACKLIST_THRESHOLD",    3)
BLACKLIST_DURATION_MIN: int = getattr(CONFIG, "BLACKLIST_DURATION_MIN", 30)

HISTORY_LIMIT: int = getattr(CONFIG, "HISTORY_LIMIT", 100)

# Valid HTTP codes for a resource that responded correctly.
VALID_REDIRECT_CODES = (301, 302, 307, 308)


# ─────────────────────────────────────────────────────────────────────────────
# Logging
# ─────────────────────────────────────────────────────────────────────────────
def setup_logging() -> logging.Logger:
    """
    Configures the script's root logger. The level is always INFO.
    Records go to the file /var/log/netwatcher/netwatcher.log and to stdout.
    """
    os.makedirs(LOG_DIR, exist_ok=True)

    logger = logging.getLogger("netwatcher")
    logger.setLevel(logging.INFO)
    logger.propagate = False

    if logger.handlers:
        return logger

    fmt = logging.Formatter(
        fmt="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    fh = logging.FileHandler(LOG_FILE, encoding="utf-8")
    fh.setFormatter(fmt)
    fh.setLevel(logging.INFO)
    logger.addHandler(fh)

    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(fmt)
    sh.setLevel(logging.INFO)
    logger.addHandler(sh)

    return logger


logger = setup_logging()


# ─────────────────────────────────────────────────────────────────────────────
# General-purpose utilities
# ─────────────────────────────────────────────────────────────────────────────
def _fmt_ms(value: Optional[float]) -> str:
    """Formatting milliseconds for logs: 'n/a' or 'X.Xms'."""
    return f"{value:.1f}ms" if value is not None else "n/a"


def _extract_host_port(url: str) -> Tuple[str, int]:
    """
    Returns (host, port) from a URL. Defaults to 443 for https and 80 for http.
    """
    parsed = urlparse(url)
    host = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return host, port


def run_command(
    cmd: List[str],
    timeout: Optional[int] = NET_CMD_TIMEOUT,
    check: bool = False,
    capture: bool = True,
) -> subprocess.CompletedProcess:
    """
    Universal wrapper around subprocess.run for invoking external utilities.

    :param cmd:     list of arguments;
    :param timeout: timeout in seconds;
    :param check:   if True — raise on non-zero exit code;
    :param capture: capture stdout/stderr;
    :return:        CompletedProcess.
    """
    pretty = " ".join(cmd)
    logger.debug("run_command: %s", pretty)
    try:
        return subprocess.run(cmd, capture_output=capture, text=True,
                              timeout=timeout, check=check)
    except FileNotFoundError as exc:
        logger.error("Command not found: %s (%s)", pretty, exc)
        raise RuntimeError(f"binary not found: {cmd[0]}") from exc
    except subprocess.TimeoutExpired as exc:
        logger.error("Command timed out (%ss): %s", timeout, pretty)
        raise RuntimeError(f"command timeout: {pretty}") from exc


def which(binary: str) -> Optional[str]:
    """Absolute path to the binary or None."""
    return shutil.which(binary)


def validate_config() -> None:
    """
    Validates critical runtime parameters. If CHECK_URLS is missing,
    the script exits with code 2.
    """
    if not CHECK_URLS:
        logger.error("CHECK_URLS in data.py is empty — nothing to check")
        sys.exit(2)
    if not SERVER_BLACKLIST_ADDRESSES:
        logger.info("SERVER_BLACKLIST_ADDRESSES is empty — static blacklist disabled")
    logger.info(
        "Parameters: MAX_WORKERS=%d, BLACKLIST_THRESHOLD=%d, BLACKLIST_DURATION_MIN=%d",
        MAX_WORKERS, BLACKLIST_THRESHOLD, BLACKLIST_DURATION_MIN,
    )


# ─────────────────────────────────────────────────────────────────────────────
# UCI
# ─────────────────────────────────────────────────────────────────────────────
def uci_get(path: str) -> Optional[str]:
    """Reads a UCI parameter, None if missing or on error."""
    try:
        res = run_command([UCI_BIN, "-q", "get", path], timeout=10)
    except RuntimeError:
        return None
    if res.returncode != 0:
        return None
    return (res.stdout or "").strip() or None


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
    try:
        res = run_command([UCI_BIN, "show", package], timeout=NET_CMD_TIMEOUT)
    except RuntimeError:
        return ""
    if res.returncode != 0:
        logger.error("uci show %s failed", package)
        return ""
    return res.stdout or ""


# ─────────────────────────────────────────────────────────────────────────────
# State: state.json
# ─────────────────────────────────────────────────────────────────────────────
def _default_state() -> Dict[str, Any]:
    """Empty state."""
    return {
        "last_run": None,
        "last_result": None,
        "last_checks": None,
        "consecutive_fails": 0,
        "selected_server": None,
        "history": [],
        "node_stats": {},
    }


def load_state() -> Dict[str, Any]:
    """
    Loads state.json. If it is missing or corrupted, the state resets to the
    default. Invalid field types are restored.
    """
    if not os.path.exists(STATE_FILE):
        logger.info("state.json not found — starting from scratch")
        return _default_state()

    try:
        with open(STATE_FILE, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("Unable to read state.json (%s) — resetting", exc)
        return _default_state()

    if not isinstance(data, dict):
        logger.warning("state.json is not an object — resetting")
        return _default_state()

    default = _default_state()
    for k, v in default.items():
        data.setdefault(k, v)
    if not isinstance(data.get("history"), list):
        data["history"] = []
    if not isinstance(data.get("node_stats"), dict):
        data["node_stats"] = {}
    return data


def save_state(state: Dict[str, Any]) -> None:
    """Atomically write state.json (tmp + os.replace)."""
    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
    state["last_run"] = datetime.now().isoformat(timespec="seconds")

    tmp_fd, tmp_path = tempfile.mkstemp(
        prefix="state-", suffix=".json", dir=os.path.dirname(STATE_FILE)
    )
    try:
        with os.fdopen(tmp_fd, "w", encoding="utf-8") as fh:
            json.dump(state, fh, ensure_ascii=False, indent=2, sort_keys=True)
        os.replace(tmp_path, STATE_FILE)
        logger.info("State saved to %s", STATE_FILE)
    except OSError as exc:
        logger.error("Error writing state.json: %s", exc)
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


def append_history(state: Dict[str, Any], entry: Dict[str, Any]) -> None:
    """Adds a run history entry and truncates it to HISTORY_LIMIT."""
    entry.setdefault("timestamp", datetime.now().isoformat(timespec="seconds"))
    hist = state.setdefault("history", [])
    hist.append(entry)
    if len(hist) > HISTORY_LIMIT:
        del hist[:-HISTORY_LIMIT]


# ─────────────────────────────────────────────────────────────────────────────
# Node blacklist
# ─────────────────────────────────────────────────────────────────────────────
def _is_static_blacklisted(address: str) -> bool:
    """Checks against the static address list from data.py."""
    return address in SERVER_BLACKLIST_ADDRESSES


def _is_dynamic_blacklisted(address: str, state: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
    """
    Checks the dynamic blacklist.
    :return: (is_blacklisted, until_iso_or_None).
    """
    ns = (state.get("node_stats") or {}).get(address)
    if not ns:
        return False, None
    until_iso = ns.get("blacklisted_until")
    if not until_iso:
        return False, None
    try:
        until_dt = datetime.fromisoformat(until_iso)
    except ValueError:
        return False, None
    if datetime.now() < until_dt:
        return True, until_iso
    return False, None


def is_node_blacklisted(address: str, state: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
    """
    Combined check: static + dynamic blacklist.
    :return: (is_forbidden, reason).
    """
    if _is_static_blacklisted(address):
        return True, "static"
    banned, until = _is_dynamic_blacklisted(address, state)
    if banned:
        return True, f"dynamic until {until}"
    return False, None


def update_node_stats(state: Dict[str, Any], servers: Dict[str, Dict[str, Any]]) -> None:
    """
    Updates cumulative node statistics. The key is `address`
    (PassWall2 node IDs change when the subscription is refreshed, but the address stays stable).

    When BLACKLIST_THRESHOLD consecutive failures is reached, the node is added to the dynamic
    blacklist for BLACKLIST_DURATION_MIN minutes. The first success removes the blacklist.
    """
    now = datetime.now()
    stats = state.setdefault("node_stats", {})

    for srv in servers.values():
        addr = srv["address"]
        ns = stats.setdefault(addr, {
            "node_id": None,
            "remarks": None,
            "consecutive_fails": 0,
            "consecutive_oks": 0,
            "last_seen": None,
            "blacklisted_until": None,
        })

        ns["node_id"] = srv["id"]
        ns["remarks"] = srv["remarks"]
        ns["last_seen"] = now.isoformat(timespec="seconds")

        if srv.get("ok"):
            ns["consecutive_fails"] = 0
            ns["consecutive_oks"] = int(ns.get("consecutive_oks") or 0) + 1
            if ns.get("blacklisted_until"):
                logger.info("Node %s ('%s') recovered — removing from blacklist",
                            addr, srv["remarks"])
            ns["blacklisted_until"] = None
        else:
            ns["consecutive_fails"] = int(ns.get("consecutive_fails") or 0) + 1
            ns["consecutive_oks"] = 0
            if ns["consecutive_fails"] >= BLACKLIST_THRESHOLD:
                until = now + timedelta(minutes=BLACKLIST_DURATION_MIN)
                ns["blacklisted_until"] = until.isoformat(timespec="seconds")
                logger.warning(
                    "Node %s ('%s') failed %d checks in a row — "
                    "blacklisted until %s",
                    addr, srv["remarks"], ns["consecutive_fails"],
                    ns["blacklisted_until"],
                )


# ─────────────────────────────────────────────────────────────────────────────
# Network checks: basic
# ─────────────────────────────────────────────────────────────────────────────
def tcping(host: str, port: int, timeout: int = TCPING_TIMEOUT) -> Tuple[bool, Optional[float]]:
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


def url_test(host: str, port: int, timeout: int = TCPING_TIMEOUT) -> Tuple[bool, Optional[float]]:
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
# External checks: evaluation and aggregation
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


def _check_single_url(url: str) -> Tuple[str, Dict[str, Any]]:
    """
    Checks a single external URL (tcping + curl). For ThreadPool.

    :return: (url, info). info contains:
                host, port, tcping_ok, tcping_latency_ms,
                https_ok, http_code, resource_ok, reason.
    """
    host, port = _extract_host_port(url)
    tcp_ok, tcp_lat = tcping(host, port)
    got_response, http_code = curl_https_check(url)

    # https_ok — a valid HTTP code, not just any response.
    https_ok = got_response and _is_http_code_ok(http_code)

    resource_ok, reason = evaluate_resource(tcp_ok, http_code)

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
            _fmt_ms(info["tcping_latency_ms"]),
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


# ─────────────────────────────────────────────────────────────────────────────
# PassWall2: management
# ─────────────────────────────────────────────────────────────────────────────
def _current_passwall_node_section() -> Optional[str]:
    """ID of the current PassWall2 node section from passwall2.@global[0].node."""
    return uci_get(f"{PASSWALL2_GLOBAL}.node")


def restart_passwall2() -> bool:
    """Restart PassWall2 via the init script."""
    if not os.path.exists(PASSWALL2_INIT):
        logger.error("PassWall2 init script not found: %s", PASSWALL2_INIT)
        return False
    logger.info("Restarting PassWall2 (%s restart)", PASSWALL2_INIT)
    try:
        res = run_command([PASSWALL2_INIT, "restart"], timeout=NET_CMD_TIMEOUT)
    except RuntimeError as exc:
        logger.error("PassWall2 restart failed: %s", exc)
        return False
    if res.returncode != 0:
        logger.error("PassWall2 restart returned code %s", res.returncode)
        return False
    logger.info("Waiting %ss after the PassWall2 restart", INIT_RESTART_WAIT)
    time.sleep(INIT_RESTART_WAIT)
    return True


def vpn_switch_to_direct() -> bool:
    """Step 2: switch the current PassWall2 node to the _direct mode."""
    anchor = _current_passwall_node_section()
    if not anchor:
        logger.error("Failed to get the PassWall2 anchor")
        return False

    logger.info("Disabling VPN: node '%s' → '%s'", anchor, DIRECT_NODE)
    if not uci_set(f"{PASSWALL2_PACKAGE}.{anchor}.default_node", DIRECT_NODE):
        return False
    if not uci_commit():
        return False
    return restart_passwall2()


def vpn_update_subscriptions() -> bool:
    """Step 3: update subscriptions via the PassWall2 Lua script."""
    if not os.path.exists(SUBSCRIBE_LUA):
        logger.error("Subscription script not found: %s", SUBSCRIBE_LUA)
        return False

    logger.info("Updating PassWall2 subscriptions via %s", SUBSCRIBE_LUA)
    cmd = [LUA_BIN, SUBSCRIBE_LUA, "start", "all", "manual"]
    try:
        res = run_command(cmd, timeout=SUBSCRIBE_WAIT)
    except RuntimeError as exc:
        logger.error("Subscription update interrupted: %s", exc)
        return False

    if res.returncode != 0:
        logger.error(
            "Subscription update ended with code %s, stderr: %s",
            res.returncode, (res.stderr or "").strip(),
        )
        return False
    logger.info("Subscriptions updated successfully")
    return True


def vpn_set_default_node(node_id: str) -> bool:
    """Step 6: set the default node and restart."""
    if not node_id:
        logger.error("vpn_set_default_node: empty node_id")
        return False

    anchor = _current_passwall_node_section()
    if not anchor:
        logger.error("Failed to get the PassWall2 anchor")
        return False

    logger.info("Setting default node: anchor=%s, node_id=%s",
                anchor, node_id)
    if not uci_set(f"{PASSWALL2_PACKAGE}.{anchor}.default_node", node_id):
        return False
    if not uci_commit():
        return False
    return restart_passwall2()


# ─────────────────────────────────────────────────────────────────────────────
# Parsing servers from UCI
# ─────────────────────────────────────────────────────────────────────────────
def _parse_nodes_ids(uci_dump: str) -> List[str]:
    """Extracts node section IDs from `uci show passwall2` output (…=nodes)."""
    ids: List[str] = []
    pattern = re.compile(rf"^{re.escape(PASSWALL2_PACKAGE)}\.([A-Za-z0-9_]+)=nodes\s*$")
    for line in uci_dump.splitlines():
        m = pattern.match(line.strip())
        if m:
            ids.append(m.group(1))
    return ids


def _extract_value_from_dump(uci_dump: str, section_id: str, key: str) -> Optional[str]:
    """Extracts a section parameter value from the `uci show` dump."""
    prefix = f"{PASSWALL2_PACKAGE}.{section_id}.{key}="
    for line in uci_dump.splitlines():
        line = line.strip()
        if not line.startswith(prefix):
            continue
        raw = line[len(prefix):]
        if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in ("'", '"'):
            raw = raw[1:-1]
        return raw
    return None


def parse_passwall2_nodes() -> Dict[str, Dict[str, Any]]:
    """
    Step 4: builds a dictionary of nodes from the UCI configuration.
    Format:
        {"<id>": {"id","remarks","address","port","latency":None,"ok":None}, ...}
    """
    dump = uci_show(PASSWALL2_PACKAGE)
    if not dump:
        logger.error("Empty UCI dump for %s", PASSWALL2_PACKAGE)
        return {}

    ids = _parse_nodes_ids(dump)
    logger.info("Found PassWall2 node sections: %d", len(ids))

    servers: Dict[str, Dict[str, Any]] = {}
    for sid in ids:
        remarks = _extract_value_from_dump(dump, sid, "remarks") or sid
        address = _extract_value_from_dump(dump, sid, "address")
        port_s  = _extract_value_from_dump(dump, sid, "port")

        if not address:
            logger.warning("Skipping node %s ('%s'): address is not set", sid, remarks)
            continue
        try:
            port = int(port_s) if port_s else None
        except ValueError:
            logger.warning("Skipping node %s ('%s'): invalid port=%r",
                           sid, remarks, port_s)
            continue
        if port is None:
            logger.warning("Skipping node %s ('%s'): port is not set", sid, remarks)
            continue

        servers[sid] = {
            "id": sid,
            "remarks": remarks,
            "address": address,
            "port": port,
            "latency": None,
            "ok": None,
        }
        logger.info("  Node: id=%s, remarks='%s', address=%s, port=%s",
                    sid, remarks, address, port)

    logger.info("Total usable nodes: %d", len(servers))
    return servers


# ─────────────────────────────────────────────────────────────────────────────
# Latency checks (parallel)
# ─────────────────────────────────────────────────────────────────────────────
def _check_one_server(srv: Dict[str, Any]) -> Dict[str, Any]:
    """
    Checks a single server (tcping + url_test). Returns a dictionary
    with fields latency / latency_source / ok.

    Latency priority:
        1. url_test — if it succeeds;
        2. tcping   — only if url_test fails.
    """
    address, port = srv["address"], srv["port"]

    tcp_ok, tcp_lat = tcping(address, port)
    url_ok, url_lat = url_test(address, port)

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
            _fmt_ms(srv.get("tcping_latency")),
            "OK" if srv.get("url_ok") else "FAIL",
            _fmt_ms(srv.get("url_latency")),
            _fmt_ms(srv.get("latency")),
            srv.get("latency_source") or "n/a",
        )
    return results


# ─────────────────────────────────────────────────────────────────────────────
# Step 6: choosing the best server
# ─────────────────────────────────────────────────────────────────────────────
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

    available.sort(key=lambda s: s["latency"])
    best = available[0]
    logger.info(
        "Best node: id=%s, remarks='%s', %s:%s, latency=%s (src=%s)",
        best["id"], best["remarks"], best["address"], best["port"],
        _fmt_ms(best["latency"]), best.get("latency_source") or "n/a",
    )
    return best


# ─────────────────────────────────────────────────────────────────────────────
# Main scenario
# ─────────────────────────────────────────────────────────────────────────────
def _log_banner(title: str) -> None:
    """A prominent log header."""
    line = "─" * 60
    logger.info(line)
    logger.info(title)
    logger.info(line)


def _finish_with_error(
    state: Dict[str, Any],
    reason: str,
    extra: Optional[Dict[str, Any]] = None,
) -> int:
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
    state = load_state()
    logger.info(
        "Previous state: last_result=%s, consecutive_fails=%s, nodes in stats=%d",
        state.get("last_result"),
        state.get("consecutive_fails"),
        len(state.get("node_stats") or {}),
    )

    # ── Step 1: connectivity check ─────────────────────────────────────────
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
    if not vpn_switch_to_direct():
        return _finish_with_error(state, "failed to switch PassWall2 to _direct")

    # ── Step 3: update subscriptions ───────────────────────────────────────
    if not vpn_update_subscriptions():
        return _finish_with_error(state, "subscription update failed")

    # ── Step 4: parse nodes ─────────────────────────────────────────────────
    servers = parse_passwall2_nodes()
    if not servers:
        return _finish_with_error(state, "node list is empty")

    # ── Step 5: measure latency ────────────────────────────────────────────
    servers = measure_servers_latency(servers)

    # Update stats BEFORE selection so the dynamic blacklist is considered in this run.
    update_node_stats(state, servers)

    # ── Step 6: choose and set ──────────────────────────────────────────────
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
        f"{best['address']}:{best['port']}) latency={_fmt_ms(best['latency'])}"
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
