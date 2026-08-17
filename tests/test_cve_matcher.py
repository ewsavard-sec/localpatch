"""
tests/test_cve_matcher.py — the persistent product-name -> CPE cache in
CveMatcher._find_cpe() (state.get_cached_cpe / state.set_cached_cpe).

Same isolation approach as test_state.py: an isolated SQLite DB per test
via the `isolated_env` fixture, so nothing here touches the real
localpatch.db. No real network call is made -- requests.get is monkeypatched
throughout, and call counts are asserted to prove the cache is actually
short-circuiting the network path, not just present but unused.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

import state
import cve_matcher


@pytest.fixture
def isolated_env(tmp_path, monkeypatch):
    monkeypatch.setattr(state, "DB_PATH", tmp_path / "test.db")
    state.init_db()
    yield


class _FakeResponse:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        pass

    def json(self):
        return self._payload


def _cpe_payload(cpe_name):
    return {"products": [{"cpe": {"cpeName": cpe_name}}]}


def test_find_cpe_caches_result_and_matches_mocked_response(isolated_env, monkeypatch):
    calls = []

    def fake_get(url, params=None, headers=None, timeout=None):
        calls.append((url, params))
        return _FakeResponse(_cpe_payload("cpe:2.3:a:mozilla:firefox:*:*:*:*:*:*:*:*"))

    monkeypatch.setattr(cve_matcher.requests, "get", fake_get)

    matcher = cve_matcher.CveMatcher()
    matcher.min_interval = 0  # don't actually sleep in tests
    result = matcher._find_cpe("Firefox")

    assert result == "cpe:2.3:a:mozilla:firefox:*:*:*:*:*:*:*:*"
    assert len(calls) == 1

    found, cached = state.get_cached_cpe("Firefox")
    assert found is True
    assert cached == "cpe:2.3:a:mozilla:firefox:*:*:*:*:*:*:*:*"


def test_find_cpe_second_call_uses_cache_not_network(isolated_env, monkeypatch):
    calls = []

    def fake_get(url, params=None, headers=None, timeout=None):
        calls.append((url, params))
        return _FakeResponse(_cpe_payload("cpe:2.3:a:mozilla:firefox:*:*:*:*:*:*:*:*"))

    monkeypatch.setattr(cve_matcher.requests, "get", fake_get)

    matcher = cve_matcher.CveMatcher()
    matcher.min_interval = 0

    first = matcher._find_cpe("Firefox")
    second = matcher._find_cpe("Firefox")

    assert first == second == "cpe:2.3:a:mozilla:firefox:*:*:*:*:*:*:*:*"
    # The whole point of the cache: the second lookup for the same product
    # name must not hit the network again.
    assert len(calls) == 1


def test_find_cpe_caches_negative_result(isolated_env, monkeypatch):
    calls = []

    def fake_get(url, params=None, headers=None, timeout=None):
        calls.append((url, params))
        return _FakeResponse({"products": []})

    monkeypatch.setattr(cve_matcher.requests, "get", fake_get)

    matcher = cve_matcher.CveMatcher()
    matcher.min_interval = 0

    first = matcher._find_cpe("SomeObscurePackage")
    second = matcher._find_cpe("SomeObscurePackage")

    assert first is None
    assert second is None
    # A confirmed "no CPE found" result must also be cached -- a package
    # that never resolves shouldn't get re-queried against NVD every scan.
    assert len(calls) == 1

    found, cached = state.get_cached_cpe("SomeObscurePackage")
    assert found is True
    assert cached is None


def test_find_cpe_network_failure_is_not_cached(isolated_env, monkeypatch):
    calls = []

    def fake_get(url, params=None, headers=None, timeout=None):
        calls.append((url, params))
        raise cve_matcher.requests.RequestException("boom")

    monkeypatch.setattr(cve_matcher.requests, "get", fake_get)

    matcher = cve_matcher.CveMatcher()
    matcher.min_interval = 0

    first = matcher._find_cpe("FlakyPackage")
    assert first is None

    # A transient failure is NOT a confirmed negative result -- it must not
    # be cached, so the next scan gets a real chance to resolve it.
    found, _ = state.get_cached_cpe("FlakyPackage")
    assert found is False

    second = matcher._find_cpe("FlakyPackage")
    assert second is None
    assert len(calls) == 2
