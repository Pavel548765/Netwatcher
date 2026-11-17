# -*- coding: utf-8 -*-
"""
state.py — persistent state (state.json), blacklist, cumulative node stats.
"""

from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timedelta
from typing import Any, Dict, Optional, Tuple
from logger import logger
from data import (
    BLACKLIST_DURATION_MIN,
    BLACKLIST_THRESHOLD,
    HISTORY_LIMIT,
    SERVER_BLACKLIST_ADDRESSES,
    STATE_FILE,
)


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
# Blacklist
# ─────────────────────────────────────────────────────────────────────────────
def _is_static_blacklisted(address: str) -> bool:
    """Checks against the static address list from data.py."""
    return address in SERVER_BLACKLIST_ADDRESSES


def _is_dynamic_blacklisted(
    address: str, state: Dict[str, Any]
) -> Tuple[bool, Optional[str]]:
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


def is_node_blacklisted(
    address: str, state: Dict[str, Any]
) -> Tuple[bool, Optional[str]]:
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


# ─────────────────────────────────────────────────────────────────────────────
# Cumulative node stats
# ─────────────────────────────────────────────────────────────────────────────
def update_node_stats(
    state: Dict[str, Any], servers: Dict[str, Dict[str, Any]]
) -> None:
    """
    Updates cumulative node statistics. The key is `address`
    (PassWall2 node IDs change when the subscription is refreshed, but the
    address stays stable).

    When BLACKLIST_THRESHOLD consecutive failures is reached, the node is
    added to the dynamic blacklist for BLACKLIST_DURATION_MIN minutes.
    The first success removes the blacklist.
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
