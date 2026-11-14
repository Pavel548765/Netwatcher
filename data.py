# -*- coding: utf-8 -*-
"""
data.py — configuration for netwatcher.py.

The file is kept separate from the code and may contain secrets.
Permissions: 600, owner: root.
"""

# ─────────────────────────────────────────────────────────────────────────────
# Paths
# ─────────────────────────────────────────────────────────────────────────────
LOG_DIR    = "/var/log/netwatcher"
LOG_FILE   = "/var/log/netwatcher/netwatcher.log"
STATE_FILE = "/var/log/netwatcher/state.json"

# ─────────────────────────────────────────────────────────────────────────────
# External resources for connectivity checks (step 1 of the algorithm)
# ─────────────────────────────────────────────────────────────────────────────
CHECK_URLS = [
    "https://copilot.microsoft.com/",
    "https://t.me/",
    "https://youtube.com/",
]

# Target for url-test nodes. For now, it is used in the script as an informational
# variable — a direct proxy request through a specific node from outside is not possible.
URL_TEST_TARGET = "https://www.google.com/generate_204"

# ─────────────────────────────────────────────────────────────────────────────
# External utilities
# ─────────────────────────────────────────────────────────────────────────────
TCPING_BIN = "tcping"
CURL_BIN   = "curl"
UCI_BIN    = "uci"
LUA_BIN    = "lua"

# ─────────────────────────────────────────────────────────────────────────────
# Timeouts (sec)
# ─────────────────────────────────────────────────────────────────────────────
TCPING_TIMEOUT    = 5
CURL_TIMEOUT      = 10
NET_CMD_TIMEOUT   = 30
SUBSCRIBE_WAIT    = 45
INIT_RESTART_WAIT = 8

# ─────────────────────────────────────────────────────────────────────────────
# PassWall2
# ─────────────────────────────────────────────────────────────────────────────
PASSWALL2_PACKAGE = "passwall2"
PASSWALL2_GLOBAL  = "passwall2.@global[0]"
PASSWALL2_INIT    = "/etc/init.d/passwall2"
SUBSCRIBE_LUA     = "/usr/share/passwall2/subscribe.lua"
DIRECT_NODE       = "_direct"

# ─────────────────────────────────────────────────────────────────────────────
# Parallelism
# ─────────────────────────────────────────────────────────────────────────────
# How many nodes we check simultaneously. For routers with 128 MB of RAM, 8 is normal;
# with a large number of nodes it can be increased to 16-32.
MAX_WORKERS = 8

# ─────────────────────────────────────────────────────────────────────────────
# Server blacklist
# ─────────────────────────────────────────────────────────────────────────────
# Static blacklist — addresses that should NEVER be selected.
# Format: list of strings, exact match against the `address` from UCI.
SERVER_BLACKLIST_ADDRESSES = [
    # Example:
    # "example.com",
    # "1.2.3.4",
]

# Dynamic blacklist: a node that fails N checks in a row,
# is excluded from selection for BLACKLIST_DURATION_MIN minutes.
BLACKLIST_THRESHOLD    = 3      # how many consecutive failures → blacklist
BLACKLIST_DURATION_MIN = 30     # for how many minutes

# ─────────────────────────────────────────────────────────────────────────────
# State
# ─────────────────────────────────────────────────────────────────────────────
HISTORY_LIMIT = 100   # how many recent run records to keep

# ─────────────────────────────────────────────────────────────────────────────
# Secrets (if needed, store them here)
# ─────────────────────────────────────────────────────────────────────────────
# SUBSCRIPTION_KEY = "..."
