"""
cve_matcher.py — Best-effort CVE lookup against the NVD (National
Vulnerability Database) API 2.0.

This is a heuristic matcher: it resolves a product name to a likely CPE
(Common Platform Enumeration) entry and pulls CVEs associated with that
CPE at the installed version. It is NOT a substitute for a proper CPE
dictionary lookup — treat results as leads to verify, not ground truth.
Product-name-to-CPE resolution is a hard problem in general; this uses
NVD's keyword search and takes the shortest/most-generic match, which
works reasonably well for well-known software (browsers, Java, Adobe
Reader, etc.) and less well for obscure or oddly-named packages.

Get a free API key at https://nvd.nist.gov/developers/request-an-api-key
to raise the rate limit from 5 req/30s to 50 req/30s — recommended once
you're scanning more than a handful of apps.
"""

import time
import requests

import state

NVD_CPE_URL = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class CveMatcher:
    def __init__(self, api_key=None, min_request_interval=None):
        self.api_key = api_key
        # Without a key: 5 requests / 30s -> stay under that.
        # With a key: 50 requests / 30s.
        self.min_interval = min_request_interval or (0.7 if api_key else 6.5)
        self._last_request = 0

    def _headers(self):
        return {"apiKey": self.api_key} if self.api_key else {}

    def _throttle(self):
        elapsed = time.time() - self._last_request
        if elapsed < self.min_interval:
            time.sleep(self.min_interval - elapsed)
        self._last_request = time.time()

    def _find_cpe(self, product_name):
        """
        Resolves product_name -> CPE, backed by a persistent cache
        (state.get_cached_cpe / state.set_cached_cpe).

        IMPORTANT: this cache is for the product-name -> CPE mapping ONLY.
        That mapping is genuinely stable (a product's CPE identity doesn't
        change), which is why the module docstring calls it the
        expensive/heuristic-but-stable part of a lookup. Do NOT extend this
        caching approach to CVE results themselves (see lookup() below) --
        new CVEs get disclosed against unchanged software constantly, so
        caching CVE results would silently hide newly-disclosed
        vulnerabilities on software nobody touched. Only identity
        resolution is safe to cache; vulnerability data is not.
        """
        found, cached_cpe = state.get_cached_cpe(product_name)
        if found:
            return cached_cpe

        self._throttle()
        try:
            resp = requests.get(
                NVD_CPE_URL,
                params={"keywordSearch": product_name, "resultsPerPage": 5},
                headers=self._headers(),
                timeout=15,
            )
            resp.raise_for_status()
            products = resp.json().get("products", [])
            if not products:
                state.set_cached_cpe(product_name, None)  # cache the negative result too
                return None
            # Naive best match: shortest cpeName is usually the base product entry
            # rather than a specific edition/language variant.
            best = min(products, key=lambda p: len(p["cpe"]["cpeName"]))
            cpe_name = best["cpe"]["cpeName"]
            state.set_cached_cpe(product_name, cpe_name)
            return cpe_name
        except (requests.RequestException, KeyError, ValueError):
            # Deliberately NOT cached: this is a lookup failure (network,
            # rate limit, malformed response), not a confirmed "no CPE
            # exists" result -- caching it would permanently blind this
            # product to future CVE lookups over a transient hiccup.
            return None

    def lookup(self, product_name, version):
        """
        Returns a list of {id, severity, url} for CVEs plausibly affecting
        `product_name` at `version`. Returns [] on no match or lookup
        failure — network errors are swallowed so a CVE lookup failure
        never blocks the rest of a scan.
        """
        base_cpe = self._find_cpe(product_name)
        if not base_cpe:
            return []

        # CPE 2.3 format: cpe:2.3:a:vendor:product:version:update:edition:...
        # Swap in the installed version (field index 5).
        parts = base_cpe.split(":")
        if len(parts) > 5:
            parts[5] = version
        target_cpe = ":".join(parts)

        self._throttle()
        try:
            resp = requests.get(
                NVD_CVE_URL,
                params={"cpeName": target_cpe, "resultsPerPage": 20},
                headers=self._headers(),
                timeout=15,
            )
            resp.raise_for_status()
            vulns = resp.json().get("vulnerabilities", [])
        except (requests.RequestException, KeyError, ValueError):
            return []

        results = []
        for v in vulns:
            cve = v.get("cve", {})
            cve_id = cve.get("id")
            metrics = cve.get("metrics", {})
            severity = "UNKNOWN"
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if metrics.get(key):
                    severity = metrics[key][0]["cvssData"].get("baseSeverity", "UNKNOWN")
                    break
            results.append({
                "id": cve_id,
                "severity": severity,
                "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            })
        return results
