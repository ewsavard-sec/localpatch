"""
scanner.py — Inventories installed software and checks for newer versions
using winget. Winget's plain-text tables are parsed by column offset, which
is more robust than splitting on whitespace since app names contain spaces.
"""

import subprocess
import re


def _run_winget(args):
    result = subprocess.run(
        ["winget", *args, "--accept-source-agreements"],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
    )
    return result.stdout


def _parse_table(output):
    """
    Parses winget's fixed-width table output into a list of dicts.
    Works for both `winget list` and `winget upgrade` since they share a
    header layout: Name  Id  Version  [Available]  Source
    """
    lines = [l for l in output.splitlines() if l.strip()]
    header_idx = next(
        (i for i, l in enumerate(lines) if re.search(r"\bName\b", l) and re.search(r"\bId\b", l)),
        None,
    )
    if header_idx is None:
        return []

    header = lines[header_idx]
    col_names = ["Name", "Id", "Version", "Available", "Source"]
    starts = {}
    for col in col_names:
        m = re.search(rf"\b{col}\b", header)
        if m:
            starts[col] = m.start()

    ordered_cols = sorted(starts.items(), key=lambda kv: kv[1])

    rows = []
    for line in lines[header_idx + 1:]:
        if set(line.strip()) <= {"-"}:
            continue  # separator line
        entry = {}
        for i, (col, start) in enumerate(ordered_cols):
            end = ordered_cols[i + 1][1] if i + 1 < len(ordered_cols) else len(line)
            entry[col] = line[start:end].strip()
        if entry.get("Name") and entry.get("Id"):
            rows.append(entry)
    return rows


def scan_installed():
    """Full inventory of installed apps winget knows about."""
    output = _run_winget(["list"])
    return _parse_table(output)


def scan_upgrades():
    """Apps with a newer version available, per winget's configured sources."""
    output = _run_winget(["upgrade", "--include-unknown"])
    return _parse_table(output)


def get_release_date(package_id, version):
    """
    Returns the release date winget's manifest reports for a specific
    package+version (as the raw string winget prints, typically
    YYYY-MM-DD), or None if winget doesn't report one for this package
    or the lookup fails. Used to anchor the auto-deploy delay window to
    when a patch actually shipped rather than when this machine happened
    to notice it.

    Confirmed via `winget show --id <id> --version <version>`: the field
    appears as `Release Date: <date>` indented under the `Installer:`
    section of the human-readable output -- there's no structured/JSON
    output mode for `winget show`, so this is line parsing, same as the
    rest of this module. If a package lists multiple installers (e.g.
    different architectures) with different release dates, this returns
    whichever appears first in the output.
    """
    output = _run_winget(["show", "--id", package_id, "--version", version])
    for line in output.splitlines():
        stripped = line.strip()
        if stripped.lower().startswith("release date:"):
            return stripped.split(":", 1)[-1].strip()
    return None
