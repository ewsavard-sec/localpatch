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

-- Caches product-name -> CPE resolution only (cve_matcher._find_cpe).
-- NEVER cache CVE lookup results themselves here or anywhere else --
-- new CVEs get disclosed against unchanged software constantly, so
-- caching CVE results would silently hide newly-disclosed vulnerabilities
-- on software that hasn't changed. Only the name->CPE identity mapping is
-- stable enough to cache; see cve_matcher.CveMatcher._find_cpe.
CREATE TABLE IF NOT EXISTS cpe_cache (
    product_name TEXT PRIMARY KEY,
    cpe_name TEXT,          -- NULL caches a genuine "no CPE found" result
    resolved_at TEXT
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


# Tracks the DB_PATH (if any) whose schema DDL has actually been run in
# this process, so _ensure_schema can skip re-running it on every single
# connection. Measured overhead of the schema check on every connection:
# ~0.79ms/call vs ~0.42ms/call without -- real but modest, and a live scan
# opens on the order of 400+ connections, so it's free to fix.
#
# Deliberately keyed by PATH rather than a plain bool: DB_PATH is a module
# attribute, not a constant -- tests monkeypatch it to a fresh file per
# test (see tests/test_state.py's isolated_env fixture), and production
# code could in principle do the same. A bare "have we ever run schema
# setup in this process" bool would wrongly skip DDL for a second,
# different, table-less db file just because some OTHER path was already
# verified earlier in the same process -- keying by path avoids that.
_schema_verified_path = None


def _ensure_schema(conn):
    global _schema_verified_path
    if _schema_verified_path == DB_PATH:
        return
    conn.executescript(SCHEMA)
    for table, migrations in (("patch_cache", _PATCH_CACHE_MIGRATIONS), ("apps", _APPS_MIGRATIONS)):
        existing_cols = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}
        for col, coltype in migrations:
            if col not in existing_cols:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} {coltype}")
    _schema_verified_path = DB_PATH


@contextmanager
def get_conn():
    global _schema_verified_path
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        # Self-healing: if localpatch.db is missing, gets deleted out from
        # under a running process, or is a fresh empty file, sqlite3.connect
        # silently creates/opens an empty database with no tables. Rather
        # than re-run the (idempotent, CREATE TABLE IF NOT EXISTS) schema
        # setup on every single connection -- expensive, see
        # _schema_verified_path above -- _ensure_schema only actually runs
        # its DDL once per (process, DB_PATH) pair. If the db file gets
        # deleted/recreated externally after that, a query below will fail
        # with "no such table": catch that specific case, clear
        # _schema_verified_path so the NEXT connection to this same path
        # re-runs schema setup, then re-raise so the CALLER's query (which
        # really did fail this one time, against the now-empty db) still
        # surfaces the error rather than being silently swallowed.
        _ensure_schema(conn)
        try:
            yield conn
        except sqlite3.OperationalError as e:
            if "no such table" in str(e):
                _schema_verified_path = None
            raise
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
    change once known, so on a version-unchanged call that passes
    release_date=None (a transient lookup failure -- get_release_date()
    returning None doesn't mean "this version has no release date", it
    can just as easily mean "the winget/network call failed this one
    time"), the previously stored non-null value is preserved rather than
    overwritten with None. CONFIRMED bug this fixes: an app with a real
    release_date 30 days old (eligible under a 7-day delay) would get
    silently reverted to ineligible by a single transient None from a
    later scan, because release_date used to be written unconditionally
    on every call. When available_version actually changes, release_date
    IS written as given (including None) -- a genuinely new version might
    legitimately have no release date yet (e.g. just published), and NULL
    is the correct value in that case.
    """
    now = time.strftime("%Y-%m-%dT%H:%M:%S")
    with get_conn() as conn:
        row = conn.execute(
            "SELECT available_version, first_seen_available, release_date FROM apps WHERE package_id = ?",
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
            prev_available, prev_first_seen, prev_release_date = (
                row["available_version"], row["first_seen_available"], row["release_date"],
            )
            version_changed = bool(available_version) and available_version != prev_available
            if version_changed:
                first_seen = now  # new version released — restart the burn-in clock
            else:
                first_seen = prev_first_seen

            if release_date is None and not version_changed and prev_release_date:
                # Transient lookup failure on an otherwise-unchanged version:
                # keep the known-good anchor instead of wiping it to NULL.
                release_date = prev_release_date

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


def mark_deploying(package_id):
    """
    Sets deploy_status='deploying' -- an intermediate state shown as "In
    Progress" in the GUI while an app is being verified/installed, distinct
    from the terminal 'deployed'/'failed' states mark_deployed() sets.
    Doesn't touch last_deployed_version/last_deployed_at, which should only
    change on a terminal outcome.
    """
    with get_conn() as conn:
        conn.execute("UPDATE apps SET deploy_status='deploying' WHERE package_id=?", (package_id,))


def reconcile_stuck_deploys():
    """
    Resets any app stuck at deploy_status='deploying' back to 'failed'.
    This state should never persist across a process restart -- it only
    exists mid-deploy-worker-loop within a single running session, so
    finding it at startup means the previous process was killed/crashed
    mid-deploy, not that a deploy is genuinely still in progress.
    Returns the number of rows reconciled.
    """
    with get_conn() as conn:
        cursor = conn.execute("UPDATE apps SET deploy_status='failed' WHERE deploy_status='deploying'")
        return cursor.rowcount


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


def get_cached_cpe(product_name):
    """
    Looks up a cached product-name -> CPE resolution (see cve_matcher's
    module docstring: CPE resolution is stable, CVE results are not --
    only this mapping is ever cached).

    Returns (found: bool, cpe_name: str | None). `found` distinguishes
    "never looked up" (False, None) from "looked up and confirmed no CPE
    exists" (True, None) -- a plain `-> str | None` return couldn't tell
    those apart, and a cache miss must trigger a fresh network lookup
    while a cached negative result must NOT.
    """
    with get_conn() as conn:
        row = conn.execute(
            "SELECT cpe_name FROM cpe_cache WHERE product_name = ?",
            (product_name,),
        ).fetchone()
        if row is None:
            return False, None
        return True, row["cpe_name"]


def set_cached_cpe(product_name, cpe_name):
    """Upserts the product-name -> CPE resolution. cpe_name may be None
    to cache a confirmed "no CPE found" result."""
    now = time.strftime("%Y-%m-%dT%H:%M:%S")
    with get_conn() as conn:
        conn.execute(
            """INSERT INTO cpe_cache (product_name, cpe_name, resolved_at)
               VALUES (?, ?, ?)
               ON CONFLICT(product_name) DO UPDATE SET
                 cpe_name=excluded.cpe_name, resolved_at=excluded.resolved_at""",
            (product_name, cpe_name, now),
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
