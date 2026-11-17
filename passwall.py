# -*- coding: utf-8 -*-
"""
passwall.py — PassWall2 integration: restart, switch to _direct,
subscription update, set default node, parse nodes from UCI.
"""

from __future__ import annotations

import os
import re
import time
from typing import Any, Dict, List, Optional
from data import *

from config import (
    DIRECT_NODE,
    INIT_RESTART_WAIT,
    LUA_BIN,
    NET_CMD_TIMEOUT,
    PASSWALL2_GLOBAL,
    PASSWALL2_INIT,
    PASSWALL2_PACKAGE,
    SUBSCRIBE_LUA,
    SUBSCRIBE_WAIT,
)
from logger import logger
from uci import uci_commit, uci_get, uci_set, uci_show
from utils import run_command


# ─────────────────────────────────────────────────────────────────────────────
# Management
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
    logger.debug("vpn_switch_to_direct: begin")
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
    logger.debug("vpn_update_subscriptions: begin")
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
    logger.debug("vpn_set_default_node: node_id=%s", node_id)
    if not node_id:
        logger.error("vpn_set_default_node: empty node_id")
        return False

    anchor = _current_passwall_node_section()
    if not anchor:
        logger.error("Failed to get the PassWall2 anchor")
        return False

    logger.info("Setting default node: anchor=%s, node_id=%s", anchor, node_id)
    if not uci_set(f"{PASSWALL2_PACKAGE}.{anchor}.default_node", node_id):
        return False
    if not uci_commit():
        return False
    return restart_passwall2()


# ─────────────────────────────────────────────────────────────────────────────
# Parsing nodes from UCI
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

        logger.debug(
            "Raw node %s: remarks=%r, address=%r, port=%r",
            sid, remarks, address, port_s,
        )

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
