"""
tests/test_state.py — delay-window logic (state.py), patch_store's
hash-mismatch verification path, and purge_expired().

Every test runs against an isolated SQLite DB and patch_cache directory via
the `isolated_env` fixture, so nothing here touches the real localpatch.db
or patch_cache/ next to the source files. Nothing in this file makes a real
winget or PowerShell call -- patch_store's own subprocess calls are mocked
so this suite runs the same on a bare CI runner as it does locally.
"""

import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

import state
import patch_store


@pytest.fixture
def isolated_env(tmp_path, monkeypatch):
    monkeypatch.setattr(state, "DB_PATH", tmp_path / "test.db")
    monkeypatch.setattr(patch_store, "CACHE_ROOT", tmp_path / "patch_cache")
    state.init_db()
    yield


def _iso(days_ago):
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(time.time() - days_ago * 86400))


def _date_only(days_ago):
    """Bare YYYY-MM-DD, matching the format winget reports for release_date."""
    return time.strftime("%Y-%m-%d", time.localtime(time.time() - days_ago * 86400))


# ---------- delay window (get_eligible_for_autodeploy) ----------

def test_delay_window_eligible_after_delay(isolated_env):
    state.upsert_app("pkg.a", "Pkg A", "winget", "1.0", "2.0")
    with state.get_conn() as conn:
        conn.execute("UPDATE apps SET first_seen_available = ? WHERE package_id = ?", (_iso(10), "pkg.a"))

    eligible = state.get_eligible_for_autodeploy(delay_days=7)
    assert [a["package_id"] for a in eligible] == ["pkg.a"]


def test_delay_window_not_yet_eligible(isolated_env):
    state.upsert_app("pkg.b", "Pkg B", "winget", "1.0", "2.0")
    with state.get_conn() as conn:
        conn.execute("UPDATE apps SET first_seen_available = ? WHERE package_id = ?", (_iso(2), "pkg.b"))

    assert state.get_eligible_for_autodeploy(delay_days=7) == []


def test_mark_deploying_sets_intermediate_status(isolated_env):
    state.upsert_app("pkg.g", "Pkg G", "winget", "1.0", "2.0")
    state.mark_deploying("pkg.g")

    row = state.get_all_apps()[0]
    assert row["deploy_status"] == "deploying"
    assert row["last_deployed_version"] is None  # not touched by mark_deploying


def test_mark_deploying_then_mark_deployed_reaches_terminal_state(isolated_env):
    state.upsert_app("pkg.h", "Pkg H", "winget", "1.0", "2.0")
    state.mark_deploying("pkg.h")
    state.mark_deployed("pkg.h", "2.0", success=True)

    row = state.get_all_apps()[0]
    assert row["deploy_status"] == "deployed"
    assert row["last_deployed_version"] == "2.0"


def test_delay_window_skips_already_deployed_version(isolated_env):
    state.upsert_app("pkg.c", "Pkg C", "winget", "1.0", "2.0")
    with state.get_conn() as conn:
        conn.execute("UPDATE apps SET first_seen_available = ? WHERE package_id = ?", (_iso(10), "pkg.c"))
    state.mark_deployed("pkg.c", "2.0", success=True)

    assert state.get_eligible_for_autodeploy(delay_days=7) == []


def test_delay_window_prefers_release_date_when_present(isolated_env):
    # Released 10 days ago (per winget), but this machine only scanned it
    # moments ago -- first_seen_available alone would say "not eligible yet"
    # (0 days old), but release_date should govern and make it eligible.
    state.upsert_app("pkg.d", "Pkg D", "winget", "1.0", "2.0", release_date=_date_only(10))

    eligible = state.get_eligible_for_autodeploy(delay_days=7)
    assert [a["package_id"] for a in eligible] == ["pkg.d"]


def test_delay_window_release_date_can_be_stricter_than_first_seen(isolated_env):
    # release_date says released 2 days ago (not yet eligible) even though
    # first_seen_available (backdated here to simulate a stale prior scan)
    # would say 10 days -- release_date must override, not just OR with it.
    state.upsert_app("pkg.e", "Pkg E", "winget", "1.0", "2.0", release_date=_date_only(2))
    with state.get_conn() as conn:
        conn.execute("UPDATE apps SET first_seen_available = ? WHERE package_id = ?", (_iso(10), "pkg.e"))

    assert state.get_eligible_for_autodeploy(delay_days=7) == []


def test_delay_window_falls_back_to_first_seen_without_release_date(isolated_env):
    # No release_date at all (winget didn't report one) -- falls back to
    # local detection time, the pre-existing behavior.
    state.upsert_app("pkg.f", "Pkg F", "winget", "1.0", "2.0")
    with state.get_conn() as conn:
        conn.execute("UPDATE apps SET first_seen_available = ? WHERE package_id = ?", (_iso(10), "pkg.f"))

    eligible = state.get_eligible_for_autodeploy(delay_days=7)
    assert [a["package_id"] for a in eligible] == ["pkg.f"]


def test_parse_anchor_timestamp():
    assert state.parse_anchor_timestamp("2026-01-15") is not None
    assert state.parse_anchor_timestamp("2026-01-15T09:30:00") is not None
    assert state.parse_anchor_timestamp("not a date") is None
    assert state.parse_anchor_timestamp("") is None


# ---------- patch_store verification (mocked winget calls) ----------

def test_patch_store_hash_mismatch_blocks(isolated_env, monkeypatch):
    def fake_download(package_id, version, target_dir):
        target_dir.mkdir(parents=True, exist_ok=True)
        (target_dir / "installer.exe").write_bytes(b"totally not the real installer")
        # Note: an all-digit hash string like "000...0" gets parsed by PyYAML
        # as an integer (0, falsy), not a string -- use a realistic hex value
        # with letters so this fixture actually exercises the string path a
        # real winget manifest would produce.
        (target_dir / "manifest.yaml").write_text(
            "Installers:\n"
            "- Architecture: x64\n"
            "  InstallerSha256: deadbeef00112233445566778899aabbccddeeff00112233445566778899aabb\n"
        )
        return True, "ok"

    monkeypatch.setattr(patch_store, "_run_winget_download", fake_download)
    result = patch_store.download_and_verify("fake.pkg", "1.0", config={})

    assert result.hash_match is False
    assert result.verified is False
    assert "hash mismatch" in result.reason


def test_patch_store_unsigned_blocked_by_default(isolated_env, monkeypatch):
    def fake_download(package_id, version, target_dir):
        target_dir.mkdir(parents=True, exist_ok=True)
        installer = target_dir / "installer.exe"
        installer.write_bytes(b"a real-enough installer body")
        actual_hash = patch_store._sha256_file(installer)
        (target_dir / "manifest.yaml").write_text(
            f"Installers:\n- Architecture: x64\n  InstallerSha256: {actual_hash}\n"
        )
        return True, "ok"

    monkeypatch.setattr(patch_store, "_run_winget_download", fake_download)
    monkeypatch.setattr(patch_store, "_check_signature", lambda *a, **k: ("NotSigned", None, "The file is not digitally signed."))

    result = patch_store.download_and_verify("fake.pkg", "1.0", config={"require_valid_signature": True})

    assert result.hash_match is True
    assert result.verified is False
    assert "signature" in result.reason


def test_patch_store_advisory_signature_when_not_required(isolated_env, monkeypatch):
    def fake_download(package_id, version, target_dir):
        target_dir.mkdir(parents=True, exist_ok=True)
        installer = target_dir / "installer.exe"
        installer.write_bytes(b"a real-enough installer body")
        actual_hash = patch_store._sha256_file(installer)
        (target_dir / "manifest.yaml").write_text(
            f"Installers:\n- Architecture: x64\n  InstallerSha256: {actual_hash}\n"
        )
        return True, "ok"

    monkeypatch.setattr(patch_store, "_run_winget_download", fake_download)
    monkeypatch.setattr(patch_store, "_check_signature", lambda *a, **k: ("NotSigned", None, "The file is not digitally signed."))

    result = patch_store.download_and_verify("fake.pkg", "1.0", config={"require_valid_signature": False})

    assert result.verified is True


# ---------- purge_expired ----------

def _seed_cache_entry(package_id, age_days):
    cache_dir = patch_store.CACHE_ROOT / package_id / "1.0"
    cache_dir.mkdir(parents=True, exist_ok=True)
    installer = cache_dir / "installer.exe"
    installer.write_bytes(b"x" * 100)

    state.record_patch_download(
        package_id=package_id, version="1.0", file_path=str(installer),
        expected_sha256="a", actual_sha256="a", signature_status="Valid",
        signer_subject=None, verification_mode="full", verified=True,
    )
    with state.get_conn() as conn:
        conn.execute("UPDATE patch_cache SET downloaded_at = ? WHERE package_id = ?",
                     (_iso(age_days), package_id))
    return installer, cache_dir


def test_purge_expired_removes_old_row_and_file(isolated_env):
    installer, cache_dir = _seed_cache_entry("old.pkg", age_days=200)

    summary = patch_store.purge_expired(max_age_days=180)

    assert summary["count"] == 1
    assert not installer.exists()
    assert not cache_dir.exists()
    assert state.get_patch_cache_entries() == []


def test_purge_expired_keeps_recent_row(isolated_env):
    installer, _ = _seed_cache_entry("recent.pkg", age_days=100)

    summary = patch_store.purge_expired(max_age_days=180)

    assert summary["count"] == 0
    assert installer.exists()
    assert len(state.get_patch_cache_entries()) == 1


def test_purge_expired_empty_cache_no_error(isolated_env):
    summary = patch_store.purge_expired(max_age_days=180)
    assert summary == {"count": 0, "bytes_freed": 0, "purged": []}
