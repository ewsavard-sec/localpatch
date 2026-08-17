"""
tests/test_patch_store.py — cache-path traversal guards
(patch_store._validate_cache_components / _is_under_cache_root) and the
allow_manifest_only_verification gate on _fallback_manifest_only().

Same isolation approach as test_state.py: an isolated SQLite DB and
patch_cache directory per test via the `isolated_env` fixture, and
patch_store's own subprocess calls (winget download/show) are mocked so
this suite makes no real winget or PowerShell calls.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

import gui
import patch_store
import state


@pytest.fixture
def isolated_env(tmp_path, monkeypatch):
    monkeypatch.setattr(state, "DB_PATH", tmp_path / "test.db")
    monkeypatch.setattr(patch_store, "CACHE_ROOT", tmp_path / "patch_cache")
    state.init_db()
    yield


# ---------- Fix 3: path traversal in cache paths ----------

def test_validate_cache_components_accepts_realistic_ids():
    # Real-world examples called out in the fix requirements -- the
    # allowlist must not start rejecting normal winget IDs/versions.
    assert patch_store._validate_cache_components("7zip.7zip", "26.02") is None
    assert patch_store._validate_cache_components("Microsoft.VisualStudioCode", "1.2.3-beta") is None


def test_validate_cache_components_rejects_dotdot_in_package_id():
    result = patch_store._validate_cache_components("..\\..\\evil", "1.0")
    assert result is not None
    assert result.verified is False
    assert "package_id" in result.reason


def test_validate_cache_components_rejects_dotdot_in_version():
    result = patch_store._validate_cache_components("some.pkg", "..\\..\\evil")
    assert result is not None
    assert result.verified is False
    assert "version" in result.reason


def test_validate_cache_components_rejects_empty_values():
    assert patch_store._validate_cache_components("", "1.0") is not None
    assert patch_store._validate_cache_components("some.pkg", "") is not None


def test_is_under_cache_root_true_for_normal_subpath(isolated_env):
    target = patch_store.CACHE_ROOT / "some.pkg" / "1.0"
    assert patch_store._is_under_cache_root(target) is True


def test_is_under_cache_root_false_for_traversal(isolated_env):
    target = patch_store.CACHE_ROOT / "some.pkg" / ".." / ".." / "escaped"
    assert patch_store._is_under_cache_root(target) is False


def test_download_and_verify_rejects_traversal_before_any_winget_call(isolated_env, monkeypatch):
    """
    The malicious package_id/version must be caught before target_dir is
    even created or winget is invoked -- proves the check is a real gate,
    not just cosmetic.
    """
    called = []

    def spy_download(package_id, version, target_dir):
        called.append((package_id, version))
        return True, "should never run"

    monkeypatch.setattr(patch_store, "_run_winget_download", spy_download)

    result = patch_store.download_and_verify("..\\..\\escape", "1.0", config={})

    assert result.verified is False
    assert "rejected" in result.reason
    assert called == []
    # The escaped directory must not have been created either.
    assert not (patch_store.CACHE_ROOT.parent / "escape").exists()


def test_download_and_verify_rejects_traversal_in_version(isolated_env, monkeypatch):
    called = []
    monkeypatch.setattr(patch_store, "_run_winget_download",
                         lambda package_id, version, target_dir: called.append(1) or (True, "x"))

    result = patch_store.download_and_verify("some.pkg", "../../escape", config={})

    assert result.verified is False
    assert "rejected" in result.reason
    assert called == []


# ---------- Fix 5: manifest-only mode must not silently claim full verification ----------

def test_manifest_only_disabled_by_default_blocks_deploy(isolated_env, monkeypatch):
    monkeypatch.setattr(patch_store, "_run_winget_download",
                         lambda package_id, version, target_dir: (False, "winget download not supported here"))

    # config={} -- allow_manifest_only_verification not set, so the
    # documented default (False) must apply.
    result = patch_store.download_and_verify("some.pkg", "1.0", config={})

    assert result.verified is False
    assert result.verification_mode == "manifest-only"
    assert "allow_manifest_only_verification" in result.reason


def test_manifest_only_explicitly_disabled_blocks_deploy(isolated_env, monkeypatch):
    monkeypatch.setattr(patch_store, "_run_winget_download",
                         lambda package_id, version, target_dir: (False, "winget download not supported here"))

    result = patch_store.download_and_verify(
        "some.pkg", "1.0", config={"allow_manifest_only_verification": False},
    )

    assert result.verified is False
    assert result.verification_mode == "manifest-only"


def test_manifest_only_enabled_verifies_but_does_not_claim_hash_match(isolated_env, monkeypatch):
    monkeypatch.setattr(patch_store, "_run_winget_download",
                         lambda package_id, version, target_dir: (False, "winget download not supported here"))
    monkeypatch.setattr(
        patch_store, "_run_winget_show",
        lambda package_id, version: (True, "InstallerSha256: deadbeef00112233445566778899aabbccddeeff00112233445566778899aabb"),
    )

    result = patch_store.download_and_verify(
        "some.pkg", "1.0", config={"allow_manifest_only_verification": True},
    )

    assert result.verified is True
    assert result.verification_mode == "manifest-only"
    # This is the actual regression this fix closes: verified=True must
    # never come bundled with a hardcoded, untrue hash_match=True -- no
    # file was ever downloaded or hashed in this mode.
    assert result.hash_match is False
    assert result.expected_sha256 is not None


def test_manifest_only_enabled_but_winget_show_also_fails(isolated_env, monkeypatch):
    monkeypatch.setattr(patch_store, "_run_winget_download",
                         lambda package_id, version, target_dir: (False, "download unsupported"))
    monkeypatch.setattr(patch_store, "_run_winget_show",
                         lambda package_id, version: (False, "show also failed"))

    result = patch_store.download_and_verify(
        "some.pkg", "1.0", config={"allow_manifest_only_verification": True},
    )

    assert result.verified is False
    assert result.verification_mode == "manifest-only"


# ---------- gui.py's distinct label for manifest-only passes (Fix 5) ----------

def test_verification_label_distinguishes_manifest_only_pass():
    full_entry = {"verified": True, "verification_mode": "full", "hash_match": True}
    manifest_only_entry = {"verified": True, "verification_mode": "manifest-only", "hash_match": False}

    full_label, full_failed = gui.LocalPatchApp._verification_label(full_entry)
    manifest_label, manifest_failed = gui.LocalPatchApp._verification_label(manifest_only_entry)

    assert full_label == "Verified"
    assert manifest_label == "Verified (manifest only)"
    assert manifest_label != full_label
    assert full_failed is False
    assert manifest_failed is False


def test_verification_label_not_checked_and_failed_unchanged():
    assert gui.LocalPatchApp._verification_label(None) == ("Not checked yet", False)
    failed_entry = {"verified": False, "verification_mode": "full", "hash_match": False}
    # Prefixed with a warning glyph as of the UI contrast fix (U1): a
    # verify-failed row no longer tints its whole row an under-contrast red
    # (#EF4444 measured below WCAG AA on the critical/high row backgrounds),
    # so the failure signal has to live in the cell text itself instead.
    assert gui.LocalPatchApp._verification_label(failed_entry) == ("⚠ Failed — hash mismatch", True)


# ---------- P2: verify_and_record() skips re-download for an already-verified,
# still-present local file, but still fully re-verifies the local bytes ----------

def _seed_verified_download(package_id, version, monkeypatch):
    """
    Runs a real (mocked-winget) download_and_verify() once so package_id+
    version ends up recorded in patch_cache as verified=True with a
    file_path pointing at an actual file on disk -- the precondition the
    P2 fast path checks for.
    """
    def fake_download(pkg_id, ver, target_dir):
        target_dir.mkdir(parents=True, exist_ok=True)
        installer = target_dir / "installer.exe"
        installer.write_bytes(b"a real-enough installer body")
        actual_hash = patch_store._sha256_file(installer)
        (target_dir / "manifest.yaml").write_text(
            f"Installers:\n- Architecture: x64\n  InstallerSha256: {actual_hash}\n"
        )
        return True, "ok"

    monkeypatch.setattr(patch_store, "_run_winget_download", fake_download)
    monkeypatch.setattr(patch_store, "_check_signature", lambda *a, **k: ("Valid", "CN=Test Publisher", None))

    result = patch_store.verify_and_record(package_id, version, config={})
    assert result.verified is True
    return result


def test_verify_and_record_skips_redownload_when_already_verified(isolated_env, monkeypatch):
    _seed_verified_download("cached.pkg", "1.0", monkeypatch)

    download_calls = []
    monkeypatch.setattr(
        patch_store, "_run_winget_download",
        lambda pkg_id, ver, target_dir: download_calls.append(1) or (True, "should not run"),
    )

    result = patch_store.verify_and_record("cached.pkg", "1.0", config={})

    assert result.verified is True
    assert result.hash_match is True
    # The core assertion: a second verify_and_record() for the SAME
    # already-verified package+version must not re-invoke winget download.
    assert download_calls == []


def test_verify_and_record_fast_path_still_catches_local_tampering(isolated_env, monkeypatch):
    """
    Security regression guard: the fast path must independently re-hash and
    re-check the signature of the local file every time, not just trust the
    previously recorded verified=True flag. If the cached file is tampered
    with on disk after the original verification, a second
    verify_and_record() call must catch it.
    """
    seeded = _seed_verified_download("tampered.pkg", "1.0", monkeypatch)

    # Tamper with the cached file after it was verified.
    Path(seeded.file_path).write_bytes(b"malicious replacement content")

    monkeypatch.setattr(
        patch_store, "_run_winget_download",
        lambda pkg_id, ver, target_dir: (True, "should not run -- fast path must be used"),
    )

    result = patch_store.verify_and_record("tampered.pkg", "1.0", config={})

    assert result.verified is False
    assert result.hash_match is False
    assert "hash mismatch" in result.reason


def test_verify_and_record_falls_through_to_download_when_cached_file_missing(isolated_env, monkeypatch):
    seeded = _seed_verified_download("purged.pkg", "1.0", monkeypatch)

    # Simulate the retention-policy purge deleting the cached file (but the
    # patch_cache row still says verified=True from the earlier run).
    Path(seeded.file_path).unlink()

    download_calls = []

    def fake_redownload(pkg_id, ver, target_dir):
        download_calls.append(1)
        target_dir.mkdir(parents=True, exist_ok=True)
        installer = target_dir / "installer.exe"
        installer.write_bytes(b"a freshly re-downloaded installer body")
        actual_hash = patch_store._sha256_file(installer)
        (target_dir / "manifest.yaml").write_text(
            f"Installers:\n- Architecture: x64\n  InstallerSha256: {actual_hash}\n"
        )
        return True, "ok"

    monkeypatch.setattr(patch_store, "_run_winget_download", fake_redownload)
    monkeypatch.setattr(patch_store, "_check_signature", lambda *a, **k: ("Valid", "CN=Test Publisher", None))

    result = patch_store.verify_and_record("purged.pkg", "1.0", config={})

    # Missing cached file -> must fall through to a fresh download rather
    # than failing silently.
    assert download_calls == [1]
    assert result.verified is True
