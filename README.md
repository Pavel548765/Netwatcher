# Netwatcher

Python program for automatic replacement of a non-working VPN server and
renewal of the provider's subscription in PassWall2.

# Description and structure

## Project files

Program files (all in the same directory):

- `/usr/share/netwatcher/netwatcher.py` — entry point (`main()` only).
- `/usr/share/netwatcher/data.py`       — parses `config.toml`, exposes all constants, validates config.
- `/usr/share/netwatcher/logger.py`     — colored logging module (self-contained).
- `/usr/share/netwatcher/utils.py`      — `run_command`, `which`, `fmt_ms`, `extract_host_port`.
- `/usr/share/netwatcher/uci.py`        — `uci get/set/commit/show` wrappers.
- `/usr/share/netwatcher/state.py`      — `state.json`: load/save/history, blacklist, node stats.
- `/usr/share/netwatcher/checks.py`     — network checks: `tcping`, `curl`, `url_test`, HTTP eval, external resources.
- `/usr/share/netwatcher/passwall.py`   — PassWall2: restart, switch to `_direct`, subscription update, set default node, parse nodes.
- `/usr/share/netwatcher/nodes.py`      — node latency measurement + best-node selection.

Config (contains secrets, permissions `600`, owner `root`):

- `/etc/netwatcher/config.toml`         — user-tunable parameters.

Runtime files (created automatically):

- `/var/log/netwatcher/state.json`      — state between runs.
- `/var/log/netwatcher/netwatcher.log`  — log file.

## Module responsibilities

| Module         | Responsibility                                                       |
|----------------|----------------------------------------------------------------------|
| `data.py`      | Parses `config.toml`, exposes all constants, `validate_config()`.    |
| `logger.py`    | Colored logging (levels, file + stdout, `logging.level` control).    |
| `utils.py`     | Generic helpers (subprocess wrapper, formatting, path lookup).       |
| `uci.py`       | Thin wrapper around the `uci` binary.                                |
| `state.py`     | Persistence of `state.json`, blacklist, cumulative node stats.       |
| `checks.py`    | Low-level network checks (TCP / HTTPS / socket) + external aggregation. |
| `passwall.py`  | All PassWall2 operations + parsing of `uci show passwall2`.          |
| `nodes.py`     | Node-level latency measurement + best-node selection.                |
| `netwatcher.py`| Orchestrator: `main()` + startup block.                              |

## Algorithm

**Preflight checks** run on every start, BEFORE the main algorithm:

1. PassWall2 is installed and a shunt node is configured.
2. Direct internet works — ping to `checks.direct_ping_host`, OR tcping to
   any of `checks.direct_tcping_targets`. If everything fails, FATAL + exit.
3. A working DNS is configured as `passwall2.@global[0].direct_dns`. If the
   current DNS doesn't resolve `checks.dns_check_domain`, fallbacks from
   `checks.dns_fallbacks` are tried and the first working one is set.

If any preflight check fails, the program exits with FATAL and **makes no
changes** — no state update, no PassWall2 restart, no node shuffling. This
avoids polluting node statistics when the underlying problem is not VPN.

**Main algorithm** (runs only after preflight succeeds):

1. Checks the availability of the external resources from `checks.urls`.
   If successful — exits with `"result": "ok"` in state.
2. On an unsuccessful check (more than one failure) — switches the current
   PassWall2 node to `_direct`.
3. Updates all subscription links.
4. Selects the best node by `tcping` + socket `url_test` results, honoring
   the static and dynamic blacklists.
5. Sets the chosen node as the default and restarts PassWall2.

## Configuration

All user-tunable parameters live in `/etc/netwatcher/config.toml`.

What goes there:

- **`[paths]`** — log/state file locations.
- **`[checks]`** — URLs for external connectivity checks.
- **`[utilities]`** — binary names/paths (`tcping`, `curl`, `uci`, `lua`).
- **`[timeouts]`** — all timeout values (seconds).
- **`[passwall2]`** — init script and subscribe.lua paths.
- **`[parallelism]`** — worker count for parallel checks.
- **`[blacklist]`** — static addresses, thresholds.
- **`[state]`** — history limit.
- **`[logging]`** — log level (`0/1/2/3`), whether to colorize the log file.

What is **hard-coded** in `data.py` (not user-tunable):

- `PASSWALL2_PACKAGE = "passwall2"`
- `PASSWALL2_GLOBAL  = "passwall2.@global[0]"`
- `DIRECT_NODE       = "_direct"`
- `VALID_REDIRECT_CODES = (301, 302, 307, 308)`

These are part of the program's contract with PassWall2 and don't
normally need to change.

## Logging

Controlled by the `[logging]` section in `config.toml`:

```toml
[logging]
level = 1          # 0=DEBUG, 1=INFO (default), 2=WARNING, 3=CRITICAL
file_color = true  # colorize the log file too (false for plain text)
Environment overrides:

NETWATCHER_LOG_LEVEL=DEBUG — one-off level override (doesn't touch config.toml).

NETWATCHER_COLOR=1 — force ANSI colors even when piping (less -R).

NETWATCHER_CONFIG_DIR=/path — alternative config directory (default /etc/netwatcher).
```
To read a colored log file: less -R /var/log/netwatcher/netwatcher.log.

If you plan to grep or process the log file with external tools, set
file_color = false in config.toml — otherwise ANSI sequences will
break pattern matching.

Algorithm (steps)
Checks the availability of the external resources from checks.urls.
If successful — exits with "result": "ok" in state.

On an unsuccessful check (more than one failure), switches the current
PassWall2 node to _direct.

Updates all subscription links.

Selects the best node by tcping + socket url_test results, honoring
the static and dynamic blacklists.

Sets the chosen node as the default and restarts PassWall2.

## Installation
Make sure the required utilities are installed:


tcping, curl, uci, lua, python3 (3.11+)
Copy all *.py files from this repository (except data.py) into
/usr/share/netwatcher/. Then copy data.py there as well. Place
config.toml into /etc/netwatcher/ with permissions 600, owner root.

To run the program on a schedule, use cron:

__*/2 * * * * flock -n /tmp/netwatcher.lock /usr/bin/python3.13 /usr/share/netwatcher/netwatcher.py >> /dev/null 2>&1__

(runs every two minutes, flock prevents parallel execution)

## Notes
- **`[checks]`** also holds the preflight targets:
  `direct_ping_host`, `direct_tcping_targets`, `dns_check_domain`,
  `dns_fallbacks`. These are used BEFORE the tunnel check to distinguish
  "no internet" from "VPN down". Adjust them to hosts reachable from your
  provider without a VPN.
