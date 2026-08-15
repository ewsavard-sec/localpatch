"""
deployer.py — Executes the actual patch installation via winget.
"""

import subprocess


def deploy(package_id):
    """
    Silently upgrades a single package. Returns (success: bool, log: str).
    """
    result = subprocess.run(
        ["winget", "upgrade", "--id", package_id, "--silent",
         "--accept-package-agreements", "--accept-source-agreements"],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
    )
    success = result.returncode == 0
    log = result.stdout + result.stderr
    return success, log
