"""
state.py — Persistent storage for LocalPatch.

Tracks every installed app LocalPatch knows about, including when a newer
version was first observed (used to enforce the deployment delay window)
and any CVEs associated with the installed version.
"""

import sqlite3
import json
import time
from pathlib import Path
from contextlib import contextmanager

DB_PATH = Path(__file__).parent / "localpatch.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS apps (
    package_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    source TEXT,
    installed_version TEXT NOT NULL,
    available_version TEXT,
    first_seen_available TEXT,   -- ISO timestamp: when available_version first appeared
    cves TEXT DEFAULT '[]',      -- JSON list of {id, severity, url}
    last_scanned TEXT,
    last_deployed_version TEXT,
    last_deployed_at TEXT,
    deploy_status TEXT DEFAULT 'idle'  -- idle | deployed | failed
);
"""


@contextmanager
def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db():
    with get_conn() as conn:
        conn.execute(SCHEMA)


def upsert_app(package_id, name, source, installed_version, available_version):
    """
    Insert or update an app record. If available_version has changed since
    the last scan, reset first_seen_available so the delay timer restarts —
    this is standard "N-day patching" behavior: every new release gets its
    own burn-in period rather than inheriting an old timestamp.
    """
    now = time.strftime("%Y-%m-%dT%H:%M:%S")
    with get_conn() as conn:
        row = conn.execute(
            "SELECT available_version, first_seen_available FROM apps WHERE package_id = ?",
            (package_id,),
        ).fetchone()

        if row is None:
            first_seen = now if available_version else None
            conn.execute(
                """INSERT INTO apps
                   (package_id, name, source, installed_version, available_version,
                    first_seen_available, last_scanned)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (package_id, name, source, installed_version, available_version, first_seen, now),
            )
        else:
            prev_available, prev_first_seen = row["available_version"], row["first_seen_available"]
            if available_version and available_version != prev_available:
                first_seen = now  # new version released — restart the burn-in clock
            else:
                first_seen = prev_first_seen
            conn.execute(
                """UPDATE apps SET name=?, source=?, installed_version=?, available_version=?,
                   first_seen_available=?, last_scanned=? WHERE package_id=?""",
                (name, source, installed_version, available_version, first_seen, now, package_id),
            )


def set_cves(package_id, cve_list):
    with get_conn() as conn:
        conn.execute(
            "UPDATE apps SET cves = ? WHERE package_id = ?",
            (json.dumps(cve_list), package_id),
        )


def mark_deployed(package_id, version, success=True):
    now = time.strftime("%Y-%m-%dT%H:%M:%S")
    with get_conn() as conn:
        conn.execute(
            """UPDATE apps SET last_deployed_version=?, last_deployed_at=?,
               deploy_status=? WHERE package_id=?""",
            (version, now, "deployed" if success else "failed", package_id),
        )


def get_all_apps():
    with get_conn() as conn:
        rows = conn.execute("SELECT * FROM apps ORDER BY name COLLATE NOCASE").fetchall()
        return [dict(r) for r in rows]


def get_eligible_for_autodeploy(delay_days):
    """Apps with a pending available_version whose burn-in period has elapsed."""
    cutoff = time.time() - delay_days * 86400
    eligible = []
    for app in get_all_apps():
        if not app["available_version"] or app["available_version"] == app["installed_version"]:
            continue
        if app["available_version"] == app["last_deployed_version"]:
            continue  # already deployed this exact version
        if not app["first_seen_available"]:
            continue
        first_seen_ts = time.mktime(time.strptime(app["first_seen_available"], "%Y-%m-%dT%H:%M:%S"))
        if first_seen_ts <= cutoff:
            eligible.append(app)
    return eligible
