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
    first_seen_available TEXT,   -- ISO timestamp: when THIS MACHINE first noticed available_version
    release_date TEXT,           -- YYYY-MM-DD winget reports for available_version, if it has one
    cves TEXT DEFAULT '[]',      -- JSON list of {id, severity, url}
    last_scanned TEXT,
    last_deployed_version TEXT,
    last_deployed_at TEXT,
    deploy_status TEXT DEFAULT 'idle'  -- idle | deployed | failed
);

CREATE TABLE IF NOT EXISTS patch_cache (
    package_id TEXT,
    version TEXT,
    file_path TEXT,
    expected_sha256 TEXT,
    actual_sha256 TEXT,
    hash_match INTEGER,
    signature_status TEXT,      -- e.g. 'Valid', 'NotSigned', 'HashMismatch', 'NotTrusted'
    signer_subject TEXT,
    signature_message TEXT,     -- PowerShell's own explanation of signature_status
    verification_mode TEXT,     -- 'full' | 'manifest-only'
    verified INTEGER,           -- 1 if all applicable checks passed
    reason TEXT,                -- human-readable summary of why verified/blocked
    downloaded_at TEXT,
    PRIMARY KEY (package_id, version)
);
"""

# Columns added after each table's initial release. CREATE TABLE IF NOT
# EXISTS above only applies to brand-new databases -- an existing
# localpatch.db from before these columns existed needs them added via
# ALTER TABLE, or every read/write of them will fail.
_PATCH_CACHE_MIGRATIONS = [
    ("signature_message", "TEXT"),
    ("reason", "TEXT"),
]
_APPS_MIGRATIONS = [
    ("release_date", "TEXT"),
]


def _ensure_schema(conn):
    conn.executescript(SCHEMA)
    for table, migrations in (("patch_cache", _PATCH_CACHE_MIGRATIONS), ("apps", _APPS_MIGRATIONS)):
        existing_cols = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}
        for col, coltype in migrations:
            if col not in existing_cols:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} {coltype}")


@contextmanager
def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        # Self-healing: if localpatch.db is missing, gets deleted out from
        # under a running process, or is a fresh empty file, sqlite3.connect
        # silently creates/opens an empty database with no tables -- every
        # connection re-applies the (idempotent, CREATE TABLE IF NOT EXISTS)
        # schema rather than assuming init_db() ran once at startup and
        # nothing has touched the file since.
        _ensure_schema(conn)
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db():
    with get_conn():
        pass  # get_conn() ensures the schema on every connection now


def upsert_app(package_id, name, source, installed_version, available_version, release_date=None):
    """
    Insert or update an app record. If available_version has changed since
    the last scan, reset first_seen_available so the delay timer restarts —
    this is standard "N-day patching" behavior: every new release gets its
    own burn-in period rather than inheriting an old timestamp.

    `release_date` is whatever winget's manifest reports for
    `available_version` (see scanner.get_release_date), used to anchor the
    delay window to when the patch actually shipped rather than
    first_seen_available (when this machine happened to notice it) --
    see get_eligible_for_autodeploy(). A version's release date doesn't
    change, so this is written unconditionally rather than only on
    version-change like first_seen_available.
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
                    first_seen_available, release_date, last_scanned)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (package_id, name, source, installed_version, available_version,
                 first_seen, release_date, now),
            )
        else:
            prev_available, prev_first_seen = row["available_version"], row["first_seen_available"]
            if available_version and available_version != prev_available:
                first_seen = now  # new version released — restart the burn-in clock
            else:
                first_seen = prev_first_seen
            conn.execute(
                """UPDATE apps SET name=?, source=?, installed_version=?, available_version=?,
                   first_seen_available=?, release_date=?, last_scanned=? WHERE package_id=?""",
                (name, source, installed_version, available_version,
                 first_seen, release_date, now, package_id),
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


def record_patch_download(package_id, version, file_path, expected_sha256, actual_sha256,
                           signature_status, signer_subject, verification_mode, verified,
                           reason=None, signature_message=None):
    now = time.strftime("%Y-%m-%dT%H:%M:%S")
    hash_match = 1 if expected_sha256 and actual_sha256 and expected_sha256.lower() == actual_sha256.lower() else 0
    with get_conn() as conn:
        conn.execute(
            """INSERT INTO patch_cache
               (package_id, version, file_path, expected_sha256, actual_sha256, hash_match,
                signature_status, signer_subject, signature_message, verification_mode,
                verified, reason, downloaded_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(package_id, version) DO UPDATE SET
                 file_path=excluded.file_path, expected_sha256=excluded.expected_sha256,
                 actual_sha256=excluded.actual_sha256, hash_match=excluded.hash_match,
                 signature_status=excluded.signature_status, signer_subject=excluded.signer_subject,
                 signature_message=excluded.signature_message,
                 verification_mode=excluded.verification_mode, verified=excluded.verified,
                 reason=excluded.reason, downloaded_at=excluded.downloaded_at""",
            (package_id, version, file_path, expected_sha256, actual_sha256, hash_match,
             signature_status, signer_subject, signature_message, verification_mode,
             1 if verified else 0, reason, now),
        )


def is_patch_verified(package_id, version):
    with get_conn() as conn:
        row = conn.execute(
            "SELECT verified FROM patch_cache WHERE package_id = ? AND version = ?",
            (package_id, version),
        ).fetchone()
        return bool(row and row["verified"])


def get_patch_cache_entries():
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM patch_cache ORDER BY downloaded_at DESC"
        ).fetchall()
        return [dict(r) for r in rows]


def delete_patch_cache_entry(package_id, version):
    with get_conn() as conn:
        conn.execute(
            "DELETE FROM patch_cache WHERE package_id = ? AND version = ?",
            (package_id, version),
        )


def parse_anchor_timestamp(value):
    """
    Parses either an ISO datetime (first_seen_available, "%Y-%m-%dT%H:%M:%S")
    or a bare date (release_date, "%Y-%m-%d", as winget reports it) into a
    Unix timestamp. Returns None for anything unparseable rather than
    raising, so a malformed/unexpected value degrades to "skip this app"
    instead of crashing the whole eligibility check or table render.
    """
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            return time.mktime(time.strptime(value, fmt))
        except ValueError:
            continue
    return None


def get_eligible_for_autodeploy(delay_days):
    """
    Apps with a pending available_version whose burn-in period has elapsed.

    Anchored to release_date (when the patch actually shipped, per winget's
    manifest) when available, so the delay reflects real-world burn-in time
    rather than how promptly this machine happened to scan. Falls back to
    first_seen_available (local detection time) for packages winget doesn't
    report a release date for.
    """
    cutoff = time.time() - delay_days * 86400
    eligible = []
    for app in get_all_apps():
        if not app["available_version"] or app["available_version"] == app["installed_version"]:
            continue
        if app["available_version"] == app["last_deployed_version"]:
            continue  # already deployed this exact version
        anchor = app["release_date"] or app["first_seen_available"]
        if not anchor:
            continue
        anchor_ts = parse_anchor_timestamp(anchor)
        if anchor_ts is not None and anchor_ts <= cutoff:
            eligible.append(app)
    return eligible
