"""
deployer.py — Executes the actual patch installation via winget.
"""

import subprocess


def deploy(package_id, version):
    """
    Silently upgrades a single package to a specific, already-verified
    version. Returns (success: bool, log: str).

    SECURITY (2026-08-17 finding, fixed here): this used to call
    `winget upgrade --id <id>` with no --version. patch_store verifies one
    specific version (hash + signature), but plain `winget upgrade`
    independently resolves and installs whatever winget considers current
    at install time -- if a new version got published in the gap between
    verify_and_record() and this call, winget would silently install that
    unverified version instead of the one that was actually checked. The
    verification gate was therefore only deciding *whether* to run
    winget, not *what* winget would install. Passing --version pins
    deploy() to install exactly the version that was verified, so a
    version race can no longer bypass verification.

    Residual limitation (explicitly out of scope for this fix): winget
    still independently re-downloads and re-checks the installer for
    --version rather than installing the exact local file
    verify_and_record() already downloaded and hashed to
    patch_cache/<package_id>/<version>/. That means this closes
    version-drift (installing a *different* version than what was
    verified) but does not achieve full byte-for-byte pinning (installing
    the literal bytes that were verified). Doing that would require
    driving the installer directly instead of going through
    `winget upgrade`, which is a larger design change.
    """
    result = subprocess.run(
        ["winget", "upgrade", "--id", package_id, "--version", version, "--silent",
         "--accept-package-agreements", "--accept-source-agreements"],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
    )
    success = result.returncode == 0
    log = result.stdout + result.stderr
    return success, log
