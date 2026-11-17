# -*- coding: utf-8 -*-
"""
utils.py — general-purpose helpers used across the project.
"""

from __future__ import annotations

import shutil
import subprocess
from typing import List, Optional, Tuple
from urllib.parse import urlparse

from config import NET_CMD_TIMEOUT
from logger import logger
from data import *

def fmt_ms(value: Optional[float]) -> str:
    """Formatting milliseconds for logs: 'n/a' or 'X.Xms'."""
    return f"{value:.1f}ms" if value is not None else "n/a"


def extract_host_port(url: str) -> Tuple[str, int]:
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
