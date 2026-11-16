# -*- coding: utf-8 -*-
"""
logger.py — logging module for netwatcher.

Provides:
    * ColoredFormatter  — ANSI coloring for terminals.
    * PlainFormatter    — plain format for the log file.
    * NetwatcherLogger  — wrapper around logging.Logger exposing all levels
                          (debug/info/warning/error/critical/fatal/exception).
    * Module-level instance `logger`, configured from data.py.
"""

from __future__ import annotations

import logging
import os
import sys
from datetime import datetime
from typing import Any


# ─────────────────────────────────────────────────────────────────────────────
# Custom FATAL level (above CRITICAL)
# ─────────────────────────────────────────────────────────────────────────────
FATAL_LEVEL = 60
logging.addLevelName(FATAL_LEVEL, "FATAL")


# ─────────────────────────────────────────────────────────────────────────────
# Paths from data.py (with fallback defaults)
# ─────────────────────────────────────────────────────────────────────────────
_CONFIG_DIR = os.environ.get("NETWATCHER_CONFIG_DIR", "/etc/netwatcher")
if _CONFIG_DIR not in sys.path:
    sys.path.insert(0, _CONFIG_DIR)

try:
    import data as _CONFIG  # type: ignore

    _DEFAULT_LOG_DIR: str = getattr(_CONFIG, "LOG_DIR", "/var/log/netwatcher")
    _DEFAULT_LOG_FILE: str = getattr(
        _CONFIG, "LOG_FILE", os.path.join(_DEFAULT_LOG_DIR, "netwatcher.log")
    )
except ImportError:
    _DEFAULT_LOG_DIR = "/var/log/netwatcher"
    _DEFAULT_LOG_FILE = os.path.join(_DEFAULT_LOG_DIR, "netwatcher.log")


# ─────────────────────────────────────────────────────────────────────────────
# Helper: does the stream support ANSI colors
# ─────────────────────────────────────────────────────────────────────────────
def _stdout_supports_color(stream: Any) -> bool:
    """
    Returns True if ANSI escapes can be written into the stream.
    NETWATCHER_COLOR=1 forces colors on (useful, e.g., when piping
    through `less -R`).
    """
    if os.environ.get("NETWATCHER_COLOR", "").lower() in ("1", "true", "yes"):
        return True
    try:
        return bool(stream is not None and stream.isatty())
    except (AttributeError, ValueError):
        return False


# ─────────────────────────────────────────────────────────────────────────────
# Colored formatter
# ─────────────────────────────────────────────────────────────────────────────
class ColoredFormatter(logging.Formatter):
    """
    Formatter for terminals.

    * The whole level tag is colored, including brackets: `[INFO]`.
    * Date is contrast-heavy (bold cyan); time parts `H:M:S` get a soft
      gradient of three blue shades.
    * Exceptions (exc_info) are appended as-is.
    """

    RESET = "\033[0m"

    # Timestamp: date is brighter/bolder; time is a soft gradient.
    DATE_COLOR      = "\033[1;38;5;51m"    # bold bright cyan
    TIME_HOUR_COLOR = "\033[38;5;117m"     # light blue
    TIME_MIN_COLOR  = "\033[38;5;111m"     # medium blue
    TIME_SEC_COLOR  = "\033[38;5;105m"     # darker blue

    # Level palette.
    LEVEL_COLORS = {
        "DEBUG":    "\033[38;5;244m",        # gray
        "INFO":     "\033[38;5;40m",         # green
        "WARNING":  "\033[38;5;214m",        # orange
        "ERROR":    "\033[38;5;196m",        # red
        "CRITICAL": "\033[1;38;5;196m",      # bold red
        "FATAL":    "\033[1;37;48;5;160m",   # white on red background
    }

    def format(self, record: logging.LogRecord) -> str:
        dt = datetime.fromtimestamp(record.created)

        # Date and time
        date_str = dt.strftime("%Y-%m-%d")
        h, m, s = dt.strftime("%H:%M:%S").split(":")

        timestamp = (
            f"{self.DATE_COLOR}{date_str}{self.RESET} "
            f"{self.TIME_HOUR_COLOR}{h}{self.RESET}:"
            f"{self.TIME_MIN_COLOR}{m}{self.RESET}:"
            f"{self.TIME_SEC_COLOR}{s}{self.RESET}"
        )

        # Level — color the whole `[LEVEL]`
        level_name = record.levelname
        level_color = self.LEVEL_COLORS.get(level_name, "")
        level_display = f"{level_color}[{level_name}]{self.RESET}"

        # Message
        message = record.getMessage()
        line = f"{timestamp} {level_display} {message}"

        # Exception (if any)
        if record.exc_info:
            if not record.exc_text:
                record.exc_text = self.formatException(record.exc_info)
            if record.exc_text:
                line = line + "\n" + record.exc_text

        return line


# ─────────────────────────────────────────────────────────────────────────────
# Plain formatter for the log file
# ─────────────────────────────────────────────────────────────────────────────
class PlainFormatter(logging.Formatter):
    """Formatter without ANSI codes — used for the log file."""

    def __init__(self) -> None:
        super().__init__(
            fmt="%(asctime)s [%(levelname)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )


# ─────────────────────────────────────────────────────────────────────────────
# NetwatcherLogger
# ─────────────────────────────────────────────────────────────────────────────
class NetwatcherLogger:
    """
    Wrapper around logging.Logger.

    Levels: debug / info / warning / error / critical / fatal / exception / log.
    """

    def __init__(self, name: str = "netwatcher") -> None:
        self._logger = logging.getLogger(name)
        self._configured = False

    # ── Setup ──────────────────────────────────────────────────────────
    def setup(self, log_dir: str, log_file: str) -> "NetwatcherLogger":
        """
        Configures the file and stdout handlers. Idempotent.
        The level comes from NETWATCHER_LOG_LEVEL (default INFO).
        """
        if self._configured:
            return self

        os.makedirs(log_dir, exist_ok=True)

        # Logging level
        level_name = os.environ.get("NETWATCHER_LOG_LEVEL", "INFO").upper()
        if level_name == "FATAL":
            level: int = FATAL_LEVEL
        else:
            level = getattr(logging, level_name, logging.INFO)

        self._logger.setLevel(level)
        self._logger.propagate = False

        # Drop any existing handlers (in case setup runs twice)
        for h in list(self._logger.handlers):
            self._logger.removeHandler(h)

        # File — no color
        fh = logging.FileHandler(log_file, encoding="utf-8")
        fh.setLevel(level)
        fh.setFormatter(PlainFormatter())
        self._logger.addHandler(fh)

        # Stdout — with color only if it's a TTY
        sh = logging.StreamHandler(sys.stdout)
        sh.setLevel(level)
        if _stdout_supports_color(sys.stdout):
            sh.setFormatter(ColoredFormatter())
        else:
            sh.setFormatter(PlainFormatter())
        self._logger.addHandler(sh)

        self._configured = True
        return self

    # ── Level methods ──────────────────────────────────────────────────
    def debug(self, msg: str, *args: Any, **kwargs: Any) -> None:
        self._logger.debug(msg, *args, **kwargs)

    def info(self, msg: str, *args: Any, **kwargs: Any) -> None:
        self._logger.info(msg, *args, **kwargs)

    def warning(self, msg: str, *args: Any, **kwargs: Any) -> None:
        self._logger.warning(msg, *args, **kwargs)

    def error(self, msg: str, *args: Any, **kwargs: Any) -> None:
        self._logger.error(msg, *args, **kwargs)

    def critical(self, msg: str, *args: Any, **kwargs: Any) -> None:
        self._logger.critical(msg, *args, **kwargs)

    def fatal(self, msg: str, *args: Any, **kwargs: Any) -> None:
        """FATAL — custom level 60, above CRITICAL."""
        self._logger.log(FATAL_LEVEL, msg, *args, **kwargs)

    def exception(self, msg: str, *args: Any, **kwargs: Any) -> None:
        self._logger.exception(msg, *args, **kwargs)

    def log(self, level: int, msg: str, *args: Any, **kwargs: Any) -> None:
        self._logger.log(level, msg, *args, **kwargs)

    # ── Access to the underlying logger ────────────────────────────────
    @property
    def logger(self) -> logging.Logger:
        return self._logger


# ─────────────────────────────────────────────────────────────────────────────
# Module-level instance
# ─────────────────────────────────────────────────────────────────────────────
logger = NetwatcherLogger().setup(_DEFAULT_LOG_DIR, _DEFAULT_LOG_FILE)
