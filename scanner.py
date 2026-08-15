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
