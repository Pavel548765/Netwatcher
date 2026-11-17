# Netwatcher

Python program for automatic replacement of a non-working VPN server and
renewal of the provider's subscription in PassWall2.

# Description and structure

## Project files

Program files (all in the same directory):

- `/usr/share/netwatcher/netwatcher.py` — entry point (`main()` only).
- `/usr/share/netwatcher/config.py`     — loads `data.py`, exposes all constants, validates config.
- `/usr/share/netwatcher/logger.py`     — colored logging module (self-contained).
- `/usr/share/netwatcher/utils.py`      — `run_command`, `which`, `fmt_ms`, `extract_host_port`.
- `/usr/share/netwatcher/uci.py`        — `uci get/set/commit/show` wrappers.
- `/usr/share/netwatcher/state.py`      — `state.json`: load/save/history, blacklist, node stats.
- `/usr/share/netwatcher/checks.py`     — network checks: `tcping`, `curl`, `url_test`, HTTP eval, external resources.
- `/usr/share/netwatcher/passwall.py`   — PassWall2: restart, switch to `_direct`, subscription update, set default node, parse nodes.
- `/usr/share/netwatcher/nodes.py`      — node latency measurement + best-node selection.

Config (separate, contains secrets):

- `/etc/netwatcher/data.py`             — configuration and secrets. Permissions 600, owner root.

Runtime files (created automatically):

- `/var/log/netwatcher/state.json`      — state between runs.
- `/var/log/netwatcher/netwatcher.log`  — log file.

## Module responsibilities

| Module         | Responsibility                                              |
|----------------|-------------------------------------------------------------|
| `config.py`    | Single import point for all config values + `validate_config()`. |
| `logger.py`    | Colored logging (levels, file + stdout, `LOG_LEVEL` control). |
| `utils.py`     | Generic helpers (subprocess wrapper, formatting, path lookup). |
| `uci.py`       | Thin wrapper around the `uci` binary.                       |
| `state.py`     | Persistence of `state.json`, blacklist, cumulative node stats. |
| `checks.py`    | Low-level network checks (TCP / HTTPS / socket) + external resource aggregation. |
| `passwall.py`  | All PassWall2 operations + parsing of `uci show passwall2`. |
| `nodes.py`     | Node-level latency measurement + best-node selection.       |
| `netwatcher.py`| Orchestrator: `main()` + startup block.                     |

## Algorithm (steps)

1. Checks the availability of the external resources from `CHECK_URLS` (in `data.py`).
   If successful — exits with `"result": "ok"` in state.
2. On an unsuccessful check (more than one failure), switches the current
   PassWall2 node to `_direct`.
3. Updates all subscription links.
4. Selects the best node by `tcping` + socket `url_test` results, honoring the
   static and dynamic blacklists.
5. Sets the chosen node as the default and restarts PassWall2.


## Installation

Make sure the required utilities are installed:

tcping, curl, uci, lua, python3
Copy all *.py files from this repository (except data.py) into the same
directory, e.g. /usr/share/netwatcher/. Place data.py into
/etc/netwatcher/ with permissions 600 and owner root.

To run the program on a schedule, use cron:

__*/2 * * * * flock -n /tmp/netwatcher.lock /usr/bin/python3.13 /usr/share/netwatcher/netwatcher.py >> /dev/null 2>&1__

(runs every two minutes, flock prevents parallel execution)
