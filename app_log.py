"""
app_log.py — App-wide timestamped event/error log for LocalPatch.

Background threads (GUI scan/deploy workers) and unattended scheduled runs
(main.py --auto) have no console a human is watching -- an uncaught
exception there just dies silently or prints to a terminal window nobody
sees. Anything logged here goes to a rotating file on disk instead, so the
GUI's Status Log viewer (and anyone reading localpatch.log directly) can
see exactly what happened and when.
"""

import logging
import logging.handlers
from pathlib import Path

LOG_PATH = Path(__file__).parent / "localpatch.log"

_logger = logging.getLogger("localpatch")
_logger.setLevel(logging.DEBUG)

if not _logger.handlers:
    _handler = logging.handlers.RotatingFileHandler(
        LOG_PATH, maxBytes=1_000_000, backupCount=3, encoding="utf-8"
    )
    _handler.setFormatter(logging.Formatter(
        fmt="%(asctime)s [%(levelname)s] %(message)s", datefmt="%Y-%m-%dT%H:%M:%S"
    ))
    _logger.addHandler(_handler)


def info(message):
    _logger.info(message)


def warning(message):
    _logger.warning(message)


def error(message):
    _logger.error(message)


def get_recent_lines(max_lines=1000):
    """Reads the log file back for display. Already chronological (oldest first)."""
    if not LOG_PATH.exists():
        return []
    lines = LOG_PATH.read_text(encoding="utf-8", errors="replace").splitlines()
    return lines[-max_lines:]
