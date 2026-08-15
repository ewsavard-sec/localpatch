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
import subprocess
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


def _check_signature(file_path: Path, trusted_publishers=None):
    """Runs Get-AuthenticodeSignature and returns (status, signer_subject)."""
    ps_cmd = (
        f"Get-AuthenticodeSignature -FilePath '{file_path}' | "
        "Select-Object @{N='Status';E={$_.Status.ToString()}}, "
        "@{N='SignerSubject';E={$_.SignerCertificate.Subject}} | "
        "ConvertTo-Json -Compress"
    )
    result = subprocess.run(
        ["powershell", "-Command", ps_cmd],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
    )
    try:
        data = json.loads(result.stdout.strip())
    except (ValueError, json.JSONDecodeError):
        return "UnknownError", None

    status = data.get("Status", "UnknownError")
    signer_subject = data.get("SignerSubject")

    if status == "Valid" and trusted_publishers:
        if not signer_subject or not any(pub in signer_subject for pub in trusted_publishers):
            return "NotTrusted", signer_subject

    return status, signer_subject


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
    require_valid_signature = config.get("require_valid_signature", True)
    trusted_publishers = (config.get("trusted_publishers") or {}).get(package_id) or None

    target_dir = CACHE_ROOT / package_id / version
    target_dir.mkdir(parents=True, exist_ok=True)

    ok, log = _run_winget_download(package_id, version, target_dir)
    if not ok:
        return _fallback_manifest_only(package_id, version, reason=f"winget download failed: {log.strip()[-500:]}")

    installer_path, manifest_path = _find_download_files(target_dir)
    if installer_path is None:
        return _fallback_manifest_only(package_id, version, reason="winget download reported success but no installer file was found")

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

    signature_status, signer_subject = _check_signature(installer_path, trusted_publishers)
    signature_ok = signature_status == "Valid"

    if not hash_match:
        reason = "hash mismatch"
        verified = False
    elif not signature_ok and require_valid_signature:
        reason = f"signature check failed ({signature_status})"
        verified = False
    else:
        if not signature_ok:
            reason = f"verified (signature advisory-only, status={signature_status})"
        else:
            reason = "verified"
        verified = True

    return VerificationResult(
        verified=verified, reason=reason, file_path=str(installer_path),
        expected_sha256=expected_sha256, actual_sha256=actual_sha256,
        hash_match=hash_match, signature_status=signature_status,
        signer_subject=signer_subject, verification_mode="full",
    )


def verify_and_record(package_id, version, config=None) -> VerificationResult:
    """
    download_and_verify(), then unconditionally records the result to the
    patch_cache table (pass or fail) so there's an audit trail of every
    attempted download. This is the entry point deploy flows should call.
    """
    result = download_and_verify(package_id, version, config)
    state.record_patch_download(
        package_id=package_id, version=version, file_path=result.file_path,
        expected_sha256=result.expected_sha256, actual_sha256=result.actual_sha256,
        signature_status=result.signature_status, signer_subject=result.signer_subject,
        verification_mode=result.verification_mode, verified=result.verified,
    )
    return result


def _fallback_manifest_only(package_id, version, reason) -> VerificationResult:
    """
    winget download didn't work — trust winget's own internal hash check
    (which `winget upgrade` also performs) instead of independently
    re-downloading and re-hashing. Weaker guarantee; clearly labeled as
    such via verification_mode so it's never misrepresented as a full
    independent verification.
    """
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
        reason=f"{reason}; trusting winget's own manifest-reported hash (not independently re-verified)",
        expected_sha256=sha_match, hash_match=True,
        signature_status="NotChecked", verification_mode="manifest-only",
    )
