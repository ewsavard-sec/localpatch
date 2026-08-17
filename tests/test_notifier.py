"""
tests/test_notifier.py — diff_new_cves() logic only. Nothing here invokes
PowerShell or fires a real toast -- that path was verified manually on the
target machine (see the 2026-08-17 Iteration Log), and isn't something CI
can meaningfully check anyway (a headless runner has no desktop to show a
toast on).
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import notifier


def test_diff_new_cves_all_new_when_nothing_known_before():
    new = [{"id": "CVE-1", "severity": "HIGH", "url": "x"}]
    assert notifier.diff_new_cves([], new) == new


def test_diff_new_cves_excludes_already_known():
    prev = [{"id": "CVE-1", "severity": "HIGH", "url": "x"}]
    new = [{"id": "CVE-1", "severity": "HIGH", "url": "x"}]
    assert notifier.diff_new_cves(prev, new) == []


def test_diff_new_cves_returns_only_the_new_ones():
    prev = [{"id": "CVE-1", "severity": "HIGH", "url": "x"}]
    new = [
        {"id": "CVE-1", "severity": "HIGH", "url": "x"},
        {"id": "CVE-2", "severity": "CRITICAL", "url": "y"},
    ]
    result = notifier.diff_new_cves(prev, new)
    assert result == [{"id": "CVE-2", "severity": "CRITICAL", "url": "y"}]


def test_diff_new_cves_empty_new_list():
    prev = [{"id": "CVE-1", "severity": "HIGH", "url": "x"}]
    assert notifier.diff_new_cves(prev, []) == []


def test_worst_severity_prefers_critical():
    cves = [{"severity": "LOW"}, {"severity": "CRITICAL"}, {"severity": "HIGH"}]
    assert notifier._worst_severity(cves) == "CRITICAL"


def test_worst_severity_none_when_empty():
    assert notifier._worst_severity([]) is None
