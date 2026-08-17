"""
patch_store.py — Downloads and independently verifies installers before
they're allowed anywhere near deployer.py's `winget upgrade` call.

Verification has two modes, recorded per-download as `verification_mode`:

  "full"           — the installer was downloaded via `winget download`,
                      then re-hashed and signature-checked independently of
                      winget's own internal checks.
  "manifest-only"  — `winget download` wasn't usable, so we only recorded
                      the hash `winget show` reports and are trusting
                      winget's own verification rather than an independent
                      re-check. See download_and_verify().

Real-winget note: the manifest YAML `winget download` writes alongside the
installer does NOT have a flat top-level `InstallerSha256` field the way an
earlier draft of this spec assumed — the hash lives in an `Installers:`
list (one entry per architecture/installer-type). Rather than guess which
list entry corresponds to the file that was actually downloaded, we search
the whole list for an entry whose declared hash matches the file we
computed — that's both simpler and a stronger check (it confirms the file's
hash is *some* hash the manifest vouches for, not just a hash that happens
to be in a field we assumed was authoritative).

Also: `Get-AuthenticodeSignature`'s `Status` is a PowerShell enum — through
ConvertTo-Json it serializes as an int (e.g. `2`) unless explicitly stringified,
so the PowerShell call below does `$_.Status.ToString()`.
"""

import hashlib
import json
import os
import re
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

import yaml

import state

CACHE_ROOT = Path(__file__).parent / "patch_cache"


@dataclass
class VerificationResult:
    verified: bool
    reason: str
    file_path: str | None = None
    expected_sha256: str | None = None
    actual_sha256: str | None = None
    hash_match: bool = False
    signature_status: str = "NotChecked"
    signer_subject: str | None = None
    signature_message: str | None = None
    verification_mode: str = "full"
    extra: dict = field(default_factory=dict)


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _run_winget_download(package_id, version, target_dir: Path):
    """Returns (success: bool, stdout+stderr: str)."""
    result = subprocess.run(
        ["winget", "download", "--id", package_id, "--version", version,
         "-d", str(target_dir), "--accept-source-agreements", "--accept-package-agreements"],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
    )
    return result.returncode == 0, result.stdout + result.stderr


def _run_winget_show(package_id, version):
    result = subprocess.run(
        ["winget", "show", "--id", package_id, "--version", version, "--accept-source-agreements"],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
    )
    return result.returncode == 0, result.stdout


def _find_download_files(target_dir: Path):
    """Returns (installer_path, manifest_path) or (None, None) if not found."""
    yaml_files = list(target_dir.glob("*.yaml")) + list(target_dir.glob("*.yml"))
    if not yaml_files:
        return None, None
    manifest_path = yaml_files[0]
    installers = [p for p in target_dir.iterdir() if p != manifest_path and p.is_file()]
    if not installers:
        return None, manifest_path
    return installers[0], manifest_path


def _expected_hash_from_manifest(manifest_path: Path, actual_sha256: str):
    """
    Search the manifest's Installers list for an entry whose declared hash
    matches the file we actually downloaded. Returns (expected_sha256, matched)
    where expected_sha256 is None if the manifest couldn't be parsed at all,
    or an unmatched hash (from the sole entry) if there's exactly one
    installer listed but its hash doesn't match — that's a real mismatch,
    not a parsing failure, and should still block deployment.
    """
    try:
        manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    except yaml.YAMLError:
        return None, False

    installers = (manifest or {}).get("Installers") or []
    hashes = [i.get("InstallerSha256", "").lower() for i in installers if i.get("InstallerSha256")]

    if actual_sha256.lower() in hashes:
        return actual_sha256, True
    if len(hashes) == 1:
        return hashes[0], False
    return None, False


_CHECK_SIGNATURE_SCRIPT = (
    "Get-AuthenticodeSignature -FilePath $env:LP_SIG_PATH | "
    "Select-Object @{N='Status';E={$_.Status.ToString()}}, StatusMessage, "
    "@{N='SignerSubject';E={$_.SignerCertificate.Subject}} | "
    "ConvertTo-Json -Compress"
)


def _check_signature(file_path: Path, trusted_publishers=None):
    """
    Runs Get-AuthenticodeSignature and returns (status, signer_subject,
    status_message). `status_message` is PowerShell's own human-readable
    explanation (e.g. "The file ... is not digitally signed.") -- this is
    the closest thing Get-AuthenticodeSignature offers to an "error code":
    the Status enum value IS the classification (NotSigned, HashMismatch,
    NotTrusted, etc.), and StatusMessage is its explanation.

    SECURITY (2026-08-17 finding, fixed here): file_path ends up in the
    installer filename winget derives from the manifest's InstallerUrl --
    not something this process controls. A single quote is a legal Windows
    filename character, so the earlier version of this function, which did
    f"Get-AuthenticodeSignature -FilePath '{file_path}' | ...", could have
    a crafted filename break out of the quoted string and inject arbitrary
    PowerShell. Fixed the same way as notifier.py's toast injection: the
    path is never spliced into script text at all -- it crosses the
    process boundary as the LP_SIG_PATH environment variable and the
    static script reads it via $env:LP_SIG_PATH, which PowerShell treats
    as an opaque string value, not code to parse.
    """
    env = {**os.environ, "LP_SIG_PATH": str(file_path)}
    result = subprocess.run(
        ["powershell", "-Command", _CHECK_SIGNATURE_SCRIPT],
        capture_output=True, text=True, encoding="utf-8", errors="replace", env=env,
    )
    try:
        data = json.loads(result.stdout.strip())
    except (ValueError, json.JSONDecodeError):
        detail = (result.stderr or result.stdout or "").strip()[-300:]
        message = f"powershell call failed: {detail}" if detail else "powershell call produced no parseable output"
        return "UnknownError", None, message

    status = data.get("Status", "UnknownError")
    signer_subject = data.get("SignerSubject")
    status_message = data.get("StatusMessage")

    if status == "Valid" and trusted_publishers:
        if not signer_subject or not any(pub in signer_subject for pub in trusted_publishers):
            return "NotTrusted", signer_subject, (
                f"signer '{signer_subject or '(none)'}' is not in the configured trusted_publishers list"
            )

    return status, signer_subject, status_message


# Real winget PackageIdentifiers and versions only ever use letters,
# digits, and a small set of separator punctuation -- examples actually
# seen from `winget list`/`winget show`: "7zip.7zip",
# "Microsoft.VisualStudioCode", "26.02", "1.2.3-beta". This is an
# allowlist (not a "reject '..'" blocklist) deliberately: enumerating bad
# substrings is easy to get wrong (encoded/alternate separators, etc.),
# while "must look like a real winget identifier" is easy to get right and
# still accepts everything real.
_SAFE_CACHE_COMPONENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]*$")


def _validate_cache_components(package_id, version):
    """
    package_id and version both become path components under CACHE_ROOT
    (CACHE_ROOT / package_id / version) in download_and_verify() below.
    Neither is trustworthy input: package_id/version are whatever the
    caller passed through (ultimately sourced from winget/NVD data), and
    purge_expired() later os.unlink()s files by the path recorded from a
    run like this -- so a package_id or version containing "..\\" or
    "../" could escape CACHE_ROOT entirely and cause this tool to write
    into, or delete, an arbitrary path outside its own cache directory.

    Returns None if both components are safe to use as path segments, or
    a VerificationResult(verified=False, ...) explaining the rejection if
    either is not. Returning a result rather than raising keeps this
    consistent with every other failure path in this module -- a
    hostile/malformed package_id should surface as "verification failed"
    to the caller, not crash the whole scan/deploy run.
    """
    for label, value in (("package_id", package_id), ("version", version)):
        if not value or not _SAFE_CACHE_COMPONENT_RE.match(value):
            return VerificationResult(
                verified=False,
                reason=(f"rejected: {label} {value!r} does not match the allowed pattern "
                        f"({_SAFE_CACHE_COMPONENT_RE.pattern}) -- refusing to use it as a cache path"),
            )
    return None


def _is_under_cache_root(target_dir: Path) -> bool:
    """
    Defense in depth on top of _validate_cache_components(): even if the
    allowlist regex above has a gap, refuse to touch a resolved path that
    isn't actually inside CACHE_ROOT.
    """
    try:
        target_dir.resolve().relative_to(CACHE_ROOT.resolve())
        return True
    except ValueError:
        return False


def _verify_local_file(installer_path: Path, expected_sha256, config, package_id) -> VerificationResult:
    """
    Shared post-download verification: re-hashes `installer_path` and
    checks its signature, then applies the same hash_match / signature_ok /
    require_valid_signature decision logic download_and_verify() has always
    used. Factored out so verify_and_record()'s "already verified, local
    file still present" fast path (see P2 below) can independently re-check
    the SAME local bytes every time -- skipping only the network fetch, not
    any of the actual verification -- without duplicating this logic.

    `expected_sha256` here is the previously-recorded manifest hash from
    patch_cache, not a freshly re-fetched manifest -- the whole point of
    the fast path is avoiding a network round-trip, so re-fetching the
    manifest would defeat it. The local file is still independently
    re-hashed and re-signature-checked, which is what actually matters for
    security (a locally-tampered file is caught exactly the same way it
    would be after a fresh download).
    """
    config = config or {}
    require_valid_signature = config.get("require_valid_signature", True)
    trusted_publishers = (config.get("trusted_publishers") or {}).get(package_id) or None

    actual_sha256 = _sha256_file(installer_path)
    hash_match = bool(expected_sha256) and actual_sha256.lower() == expected_sha256.lower()

    signature_status, signer_subject, signature_message = _check_signature(installer_path, trusted_publishers)
    signature_ok = signature_status == "Valid"

    if not hash_match:
        reason = (f"hash mismatch: expected {expected_sha256}, "
                   f"got {actual_sha256} -- downloaded file does not match winget's manifest")
        verified = False
    elif not signature_ok and require_valid_signature:
        detail = f" -- {signature_message}" if signature_message else ""
        reason = f"signature check failed ({signature_status}){detail}"
        verified = False
    else:
        if not signature_ok:
            detail = f" ({signature_message})" if signature_message else ""
            reason = f"verified (signature advisory-only, status={signature_status}{detail} -- require_valid_signature is false)"
        else:
            reason = "verified"
        verified = True

    return VerificationResult(
        verified=verified, reason=reason, file_path=str(installer_path),
        expected_sha256=expected_sha256, actual_sha256=actual_sha256,
        hash_match=hash_match, signature_status=signature_status,
        signer_subject=signer_subject, signature_message=signature_message,
        verification_mode="full",
    )


def download_and_verify(package_id, version, config=None) -> VerificationResult:
    """
    Downloads `package_id`==`version` via `winget download`, then verifies
    it against its own manifest (hash) and Get-AuthenticodeSignature
    (signature). Falls back to manifest-only mode if `winget download`
    fails outright (e.g. unsupported on this winget version/source).

    `config` is the loaded config.json dict; relevant keys:
      require_valid_signature (default True)
      trusted_publishers: {package_id: [substrings]}
    """
    config = config or {}

    invalid = _validate_cache_components(package_id, version)
    if invalid is not None:
        return invalid

    target_dir = CACHE_ROOT / package_id / version
    if not _is_under_cache_root(target_dir):
        return VerificationResult(
            verified=False,
            reason=f"rejected: resolved cache path {target_dir} is not under CACHE_ROOT",
        )
    target_dir.mkdir(parents=True, exist_ok=True)

    ok, log = _run_winget_download(package_id, version, target_dir)
    if not ok:
        return _fallback_manifest_only(package_id, version, config, reason=f"winget download failed: {log.strip()[-500:]}")

    installer_path, manifest_path = _find_download_files(target_dir)
    if installer_path is None:
        return _fallback_manifest_only(package_id, version, config, reason="winget download reported success but no installer file was found")

    actual_sha256 = _sha256_file(installer_path)

    expected_sha256, hash_match = (None, False)
    if manifest_path is not None:
        expected_sha256, hash_match = _expected_hash_from_manifest(manifest_path, actual_sha256)
    if expected_sha256 is None:
        # No manifest, or manifest had multiple installers we couldn't match by hash.
        return VerificationResult(
            verified=False, reason="could not determine expected hash from manifest",
            file_path=str(installer_path), actual_sha256=actual_sha256,
            hash_match=False, verification_mode="full",
        )

    return _verify_local_file(installer_path, expected_sha256, config, package_id)


def _fast_path_from_cache(package_id, version, config) -> VerificationResult | None:
    """
    If package_id+version was already verified in a prior run and its
    cached installer file is still on disk, re-verify that SAME local file
    (fresh hash + fresh signature check, no shortcuts on either) instead of
    re-downloading. Returns None if there's nothing to reuse (not
    previously verified, or the cached file has since been purged/moved),
    in which case the caller falls through to a normal fresh download.

    CONFIRMED empirically: `winget download` was run twice in a row for
    the same already-present package+version and re-fetched the installer
    both times (7.5s then 4.7s) -- winget itself has no skip-if-present
    behavior. For a "Deploy All Eligible" batch of apps that were already
    verified in an earlier run, that's pure waste: re-hashing the LOCAL
    file catches tampering exactly as well as a fresh download would,
    since the file's bytes are what actually get installed either way.
    Only the network fetch is skipped here -- the hash and signature are
    still independently re-checked against the local bytes every time.
    """
    if not state.is_patch_verified(package_id, version):
        return None

    entries = [
        e for e in state.get_patch_cache_entries()
        if e["package_id"] == package_id and e["version"] == version
    ]
    if not entries:
        return None

    cached_file_path = entries[0].get("file_path")
    cached_expected_sha256 = entries[0].get("expected_sha256")
    if not cached_file_path:
        return None

    installer_path = Path(cached_file_path)
    if not installer_path.exists():
        return None  # purged by retention policy or otherwise missing -- fall through

    return _verify_local_file(installer_path, cached_expected_sha256, config, package_id)


def verify_and_record(package_id, version, config=None) -> VerificationResult:
    """
    download_and_verify(), then unconditionally records the result to the
    patch_cache table (pass or fail) so there's an audit trail of every
    attempted download. This is the entry point deploy flows should call.

    Before downloading, checks whether this exact package_id+version was
    already verified in a prior run and its cached file is still present
    on disk -- see _fast_path_from_cache(). If so, skips the network
    fetch and re-verifies the local file directly, which is materially
    faster (a `winget download` re-fetch costs several seconds to tens of
    seconds depending on installer size, confirmed empirically at 7.5s and
    4.7s for repeat downloads of the same file) with no reduction in
    security guarantees, since the local bytes are independently re-hashed
    and re-signature-checked either way.
    """
    cached_result = _fast_path_from_cache(package_id, version, config)
    result = cached_result if cached_result is not None else download_and_verify(package_id, version, config)
    state.record_patch_download(
        package_id=package_id, version=version, file_path=result.file_path,
        expected_sha256=result.expected_sha256, actual_sha256=result.actual_sha256,
        signature_status=result.signature_status, signer_subject=result.signer_subject,
        verification_mode=result.verification_mode, verified=result.verified,
        reason=result.reason, signature_message=result.signature_message,
    )
    return result


def _fallback_manifest_only(package_id, version, config, reason) -> VerificationResult:
    """
    winget download didn't work — the only fallback left is to trust
    winget's own internal hash check (the same one `winget upgrade`
    performs) instead of independently downloading and re-hashing a file
    ourselves. This is a materially weaker guarantee than "full" mode: no
    file is downloaded here, no hash is independently computed, and no
    signature is checked -- this function only greps text out of
    `winget show`. It is clearly labeled as such via verification_mode.

    SECURITY (2026-08-17 finding, fixed here): this used to
    unconditionally return verified=True (with a hardcoded, and simply
    false, hash_match=True -- nothing was ever compared) whenever
    `winget show` merely reported *a* hash string. Callers only checked
    `result.verified`, so a source that couldn't be independently
    verified at all looked identical, from the caller's perspective, to
    one that had passed a full hash+signature check. Fixed two ways:

    1. Gated behind config["allow_manifest_only_verification"], which
       DEFAULTS TO FALSE. With the default, a failed `winget download`
       now blocks deployment outright (verified=False) rather than
       silently downgrading to a weaker check the operator never opted
       into.
    2. Even when explicitly enabled, hash_match is no longer hardcoded
       True -- it's False, because no actual downloaded file was ever
       hashed and compared here. verification_mode stays "manifest-only"
       so gui.py can (and does, see _verification_label) show this
       distinctly from a real "Verified".
    """
    config = config or {}
    if not config.get("allow_manifest_only_verification", False):
        return VerificationResult(
            verified=False,
            reason=(f"{reason}; manifest-only verification is disabled "
                    f"(allow_manifest_only_verification=false) -- blocking rather than "
                    f"falling back to a weaker, unverified-download check"),
            verification_mode="manifest-only",
        )

    ok, show_output = _run_winget_show(package_id, version)
    if not ok:
        return VerificationResult(
            verified=False,
            reason=f"{reason}; winget show also failed, cannot verify at all",
            verification_mode="manifest-only",
        )

    sha_match = None
    for line in show_output.splitlines():
        if "installersha256" in line.lower():
            sha_match = line.split(":", 1)[-1].strip()
            break

    if not sha_match:
        return VerificationResult(
            verified=False,
            reason=f"{reason}; winget show did not report an installer hash",
            verification_mode="manifest-only",
        )

    return VerificationResult(
        verified=True,
        reason=(f"{reason}; allow_manifest_only_verification is true -- trusting winget's own "
                f"manifest-reported hash, not independently re-verified (no file was downloaded "
                f"or hashed by this process)"),
        expected_sha256=sha_match, hash_match=False,
        signature_status="NotChecked", verification_mode="manifest-only",
    )


def purge_expired(max_age_days=180):
    """
    Deletes cached installer files (and their patch_cache rows) older than
    `max_age_days`. Does NOT touch the `apps` table's version history --
    only the cached installer files, which is what actually costs disk
    space.

    A per-file/per-row failure (locked file, already-missing path) is
    logged and skipped rather than aborting the whole purge run.

    Returns {"count": int, "bytes_freed": int, "purged": [{"package_id",
    "version", "age_days"}, ...]}.
    """
    cutoff = time.time() - max_age_days * 86400
    purged = []
    bytes_freed = 0

    for entry in state.get_patch_cache_entries():
        downloaded_at = entry.get("downloaded_at")
        if not downloaded_at:
            continue
        try:
            downloaded_ts = time.mktime(time.strptime(downloaded_at, "%Y-%m-%dT%H:%M:%S"))
        except ValueError:
            continue
        if downloaded_ts > cutoff:
            continue

        age_days = (time.time() - downloaded_ts) / 86400
        freed = 0
        file_path = entry.get("file_path")
        if file_path:
            p = Path(file_path)
            try:
                if p.exists():
                    freed = p.stat().st_size
                    p.unlink()
                if p.parent.exists() and not any(p.parent.iterdir()):
                    p.parent.rmdir()
            except OSError as e:
                print(f"patch_store.purge_expired: couldn't remove {file_path}: {e}")

        state.delete_patch_cache_entry(entry["package_id"], entry["version"])
        bytes_freed += freed
        purged.append({
            "package_id": entry["package_id"], "version": entry["version"],
            "age_days": round(age_days, 1),
        })
        print(f"Purged {entry['package_id']} {entry['version']} "
              f"(age {age_days:.1f} days, freed {freed} bytes)")

    return {"count": len(purged), "bytes_freed": bytes_freed, "purged": purged}
