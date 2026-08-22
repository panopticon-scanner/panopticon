from unittest import mock
import json
import os
import tempfile
import unittest

import scripts.citations as cit


class TestCatalog(unittest.TestCase):
    def test_loads_and_has_core_entries(self):
        cat = cit.load_cwe_catalog()
        self.assertEqual(
            cat["cwe"]["CWE-89"],
            "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
        )
        self.assertEqual(cat["cwe_owasp"]["CWE-89"], "A03:2021-Injection")
        self.assertIn("A01:2021-Broken Access Control", cat["owasp_top10"])

    def test_missing_catalog_degrades_gracefully(self):
        # CD-002 regression: a missing/corrupt catalog must not abort the run.
        import contextlib, io

        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            cat = cit.load_cwe_catalog(path="/no/such/catalog.json")
        self.assertEqual(cat["cwe"], {})
        self.assertEqual(cat["cwe_owasp"], {})
        self.assertEqual(cat["owasp_top10"], [])
        self.assertIn("catalog unavailable", stderr.getvalue())
        # enrichment still runs against the empty catalog without raising
        cit.enrich_citations([{"citations": {"cwe": ["CWE-89"]}}], cat)

    def test_corrupt_catalog_degrades_gracefully(self):
        import contextlib, io, tempfile
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "corrupt.json")
            with open(p, "w") as f:
                f.write("{invalid json")
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                cat = cit.load_cwe_catalog(path=p)
            self.assertEqual(cat["cwe"], {})
            self.assertIn("catalog unavailable", stderr.getvalue())


class TestCweOwasp(unittest.TestCase):
    def setUp(self):
        self.cat = cit.load_cwe_catalog()

    def test_validate_known_cwe(self):
        v = cit.validate_cwe("CWE-89", self.cat)
        self.assertEqual(v["id"], "CWE-89")
        self.assertTrue(v["verified"])
        self.assertIn("SQL", v["name"])

    def test_validate_unlisted_cwe_agent(self):
        v = cit.validate_cwe("CWE-99999", self.cat)
        self.assertEqual(v["id"], "CWE-99999")
        self.assertIsNone(v["name"])
        self.assertFalse(v["verified"])

    def test_validate_unlisted_cwe_tool_is_verified(self):
        v = cit.validate_cwe("CWE-99999", self.cat, tool_sourced=True)
        self.assertTrue(v["verified"])

    def test_validate_malformed_cwe(self):
        self.assertIsNone(cit.validate_cwe("SQLi", self.cat))

    def test_derive_owasp_from_cwe_and_asserted(self):
        out = cit.derive_owasp(["CWE-89"], ["A01:2021-Broken Access Control", "bogus"], self.cat)
        self.assertIn("A03:2021-Injection", out)
        self.assertIn("A01:2021-Broken Access Control", out)
        self.assertNotIn("bogus", out)

    def test_cwe_regex_case_insensitive(self):
        cat = cit.load_cwe_catalog()
        v = cit.validate_cwe("cwe-89", cat)
        self.assertIsNotNone(v)
        self.assertEqual(v["id"], "CWE-89")  # canonical upper-case output

    def test_cve_regex_case_insensitive(self):
        v = cit.CVE_RE.match("cve-2023-1234")
        self.assertIsNotNone(v)

    def test_cwe_95_in_catalog(self):
        cat = cit.load_cwe_catalog()
        self.assertIn("CWE-95", cat["cwe"])
        self.assertIn("CWE-95", cat["cwe_owasp"])


class TestSsvc(unittest.TestCase):
    def test_act_high_end(self):
        self.assertEqual(cit.ssvc_decide("active", "open", "very_high"), "Act")

    def test_act_active_high_impact_shortcut(self):
        self.assertEqual(cit.ssvc_decide("active", "small", "high"), "Act")

    def test_track_low_end(self):
        self.assertEqual(cit.ssvc_decide("none", "small", "low"), "Track")

    def test_attend_middle(self):
        self.assertEqual(cit.ssvc_decide("poc", "controlled", "medium"), "Attend")

    def test_case_insensitive(self):
        self.assertEqual(cit.ssvc_decide("NONE", "Small", "LOW"), "Track")

    def test_invalid_returns_none(self):
        self.assertIsNone(cit.ssvc_decide("nope", "open", "high"))
        self.assertIsNone(cit.ssvc_decide("active", None, "high"))

    def test_none_exploitation_returns_none(self):
        self.assertIsNone(cit.ssvc_decide(None, "open", "high"))

    def test_none_impact_returns_none(self):
        self.assertIsNone(cit.ssvc_decide("active", "open", None))


class _FakeResp:
    def __init__(self, payload):
        self._b = json.dumps(payload).encode()
        self.last_read_size = None

    def read(self, amt=None):
        self.last_read_size = amt
        return self._b

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class TestEpss(unittest.TestCase):
    def test_lookup_success_and_cache(self):
        calls = {"n": 0}

        def opener(url, timeout=0):
            calls["n"] += 1
            return _FakeResp(
                {
                    "data": [
                        {
                            "cve": "CVE-2023-1234",
                            "epss": "0.42",
                            "percentile": "0.97",
                            "date": "2026-07-20",
                        }
                    ]
                }
            )

        with tempfile.TemporaryDirectory() as d:
            cache = os.path.join(d, "epss-cache.json")
            out = cit.epss_lookup(["CVE-2023-1234"], cache, opener=opener)
            self.assertAlmostEqual(out["CVE-2023-1234"]["score"], 0.42)
            self.assertEqual(out["CVE-2023-1234"]["source"], "FIRST.org")
            # second call served from cache (opener not called again)
            out2 = cit.epss_lookup(["CVE-2023-1234"], cache, opener=opener)
            self.assertEqual(calls["n"], 1)
            self.assertIn("CVE-2023-1234", out2)

    @mock.patch("logging.warning")
    def test_network_error_omits_cve(self, mock_warn):
        def opener(url, timeout=0):
            raise OSError("offline")

        with tempfile.TemporaryDirectory() as d:
            out = cit.epss_lookup(["CVE-2023-1234"], os.path.join(d, "c.json"), opener=opener)
            self.assertEqual(out, {})
            mock_warn.assert_called_with(
                "EPSS network failure or error for %s: %s", "CVE-2023-1234", mock.ANY
            )

    def test_malformed_cve_skipped(self):
        def opener(url, timeout=0):
            raise AssertionError("should not be called")

        with tempfile.TemporaryDirectory() as d:
            out = cit.epss_lookup(["not-a-cve"], os.path.join(d, "c.json"), opener=opener)
            self.assertEqual(out, {})

    def test_lookup_accepts_lowercase_cve(self):
        def opener(req, timeout=0):
            return _FakeResp(
                {
                    "data": [
                        {
                            "cve": "CVE-2023-1234",
                            "epss": "0.42",
                            "percentile": "0.97",
                            "date": "2026-07-20",
                        }
                    ]
                }
            )

        with tempfile.TemporaryDirectory() as d:
            out = cit.epss_lookup(["cve-2023-1234"], os.path.join(d, "c.json"), opener=opener)
            self.assertIn("CVE-2023-1234", out)  # canonical upper-case key

    def test_request_capped_read_and_user_agent(self):
        holder = {}

        def opener(req, timeout=0):
            holder["req"] = req
            resp = _FakeResp(
                {
                    "data": [
                        {
                            "cve": "CVE-2023-1234",
                            "epss": "0.1",
                            "percentile": "0.5",
                            "date": "2026-07-20",
                        }
                    ]
                }
            )
            holder["resp"] = resp
            return resp

        with tempfile.TemporaryDirectory() as d:
            cit.epss_lookup(["CVE-2023-1234"], os.path.join(d, "c.json"), opener=opener)
        from _version import __version__

        self.assertEqual(holder["req"].get_header("User-agent"), "panopticon/%s" % __version__)
        self.assertEqual(holder["resp"].last_read_size, 1000000)


class TestCitationQuality(unittest.TestCase):
    def setUp(self):
        self.catalog = cit.load_cwe_catalog()

    def test_full_quality(self):
        f = {
            "citations": {
                "cwe": [{"id": "CWE-89"}],
                "owasp": ["A03:2021"],
                "cve": ["CVE-2023-1234"],
            }
        }
        cit.enrich_citations([f], self.catalog)
        self.assertEqual(f["citation_quality"], "full")

    def test_partial_quality(self):
        f = {"citations": {"cwe": [{"id": "CWE-89"}]}}
        cit.enrich_citations([f], self.catalog)
        self.assertEqual(f["citation_quality"], "partial")

    def test_unverified_cwe_scores_minimal(self):
        f = {"citations": {"cwe": ["CWE-99999"]}}
        cit.enrich_citations([f], self.catalog)
        self.assertEqual(f["citation_quality"], "minimal")
        self.assertFalse(f["citations"]["cwe"][0]["verified"])

    def test_verified_real_cwe_scores_partial(self):
        f = {"citations": {"cwe": ["CWE-89"]}}
        cit.enrich_citations([f], self.catalog)
        self.assertEqual(f["citation_quality"], "partial")
        self.assertTrue(f["citations"]["cwe"][0]["verified"])
        self.assertFalse(f["citations"]["cwe"][0].get("derived"))

    def test_none_quality(self):
        f = {"citations": {}}
        cit.enrich_citations([f], self.catalog)
        self.assertEqual(f["citation_quality"], "none")

    def test_category_mapping(self):
        f = {"category": "injection", "citations": {}}
        cit.enrich_citations([f], self.catalog)
        self.assertEqual(f["citation_quality"], "minimal")
        self.assertIn("CWE-89", [c["id"] for c in f["citations"]["cwe"]])
        self.assertTrue(all(c.get("derived") for c in f["citations"]["cwe"]))
        self.assertTrue(all(c.get("verified") is False for c in f["citations"]["cwe"]))

    def test_real_cwe_is_partial_not_minimal(self):
        f = {"citations": {"cwe": ["CWE-89"]}}
        cit.enrich_citations([f], self.catalog)
        self.assertEqual(f["citation_quality"], "partial")
        self.assertTrue(all(not c.get("derived") for c in f["citations"]["cwe"]))

    def test_top_level_cvss_counts_for_full_quality(self):
        f = {
            "citations": {"cwe": [{"id": "CWE-89"}]},
            "cvss": {"score": 8.1, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
        }
        cit.enrich_citations([f], self.catalog)
        self.assertEqual(f["citation_quality"], "full")

    def test_category_derived_cwe_with_top_level_cvss_is_minimal(self):
        f = {
            "category": "sql_injection",
            "citations": {},
            "cvss": {"score": 8.1, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
        }
        cit.enrich_citations([f], self.catalog)
        self.assertEqual(f["citation_quality"], "minimal")
        self.assertIn("CWE-89", [c["id"] for c in f["citations"]["cwe"]])


class TestEnrich(unittest.TestCase):
    def setUp(self):
        self.cat = cit.load_cwe_catalog()

    def test_enrich_full_finding(self):
        f = {
            "source": "agent:security-reviewer",
            "citations": {
                "cwe": ["CWE-89", "bogus"],
                "ssvc": {
                    "inputs": {"exploitation": "active", "exposure": "open", "impact": "high"}
                },
            },
        }
        cit.enrich_citations([f], self.cat)
        c = f["citations"]
        self.assertEqual([e["id"] for e in c["cwe"]], ["CWE-89"])  # malformed dropped
        self.assertIn("A03:2021-Injection", c["owasp"])  # derived
        self.assertEqual(c["ssvc"]["decision"], "Act")
        self.assertEqual(c["ssvc"]["model"], "deployer-reduced")

    def test_enrich_removes_empty_citations(self):
        f = {"source": "agent:code-reviewer", "citations": {"cwe": ["nope"]}}
        cit.enrich_citations([f], self.cat)
        self.assertNotIn("citations", f)

    def test_enrich_tool_cwe_verified(self):
        f = {"source": "tool:semgrep", "citations": {"cwe": [{"id": "CWE-99999"}]}}
        cit.enrich_citations([f], self.cat)
        self.assertTrue(f["citations"]["cwe"][0]["verified"])

    def test_enrich_epss_disabled_no_lookup(self):
        f = {"source": "tool:trivy", "citations": {"cve": ["CVE-2023-1234"]}}
        cit.enrich_citations([f], self.cat, epss_enabled=False)
        self.assertIn("CVE-2023-1234", f["citations"]["cve"])
        self.assertNotIn("epss", f["citations"])

    def test_enrich_epss_enabled_end_to_end_adds_epss_citation(self):
        def opener(req, timeout=0):
            return _FakeResp(
                {
                    "data": [
                        {
                            "cve": "CVE-2023-1234",
                            "epss": "0.42",
                            "percentile": "0.97",
                            "date": "2026-07-20",
                        }
                    ]
                }
            )

        f = {"source": "tool:trivy", "citations": {"cve": ["CVE-2023-1234"]}}
        with tempfile.TemporaryDirectory() as d:
            cit.enrich_citations(
                [f],
                self.cat,
                epss_enabled=True,
                cache_path=os.path.join(d, "epss-cache.json"),
                opener=opener,
            )
        self.assertIn("epss", f["citations"])
        self.assertEqual(f["citations"]["epss"][0]["cve"], "CVE-2023-1234")
        self.assertAlmostEqual(f["citations"]["epss"][0]["score"], 0.42)

    def test_enrich_epss_enabled_cve_not_scored_omits_epss(self):
        def opener(req, timeout=0):
            return _FakeResp({"data": []})  # FIRST.org: CVE not scored

        f = {"source": "tool:trivy", "citations": {"cve": ["CVE-2023-1234"]}}
        with tempfile.TemporaryDirectory() as d:
            cit.enrich_citations(
                [f],
                self.cat,
                epss_enabled=True,
                cache_path=os.path.join(d, "epss-cache.json"),
                opener=opener,
            )
        self.assertIn("CVE-2023-1234", f["citations"]["cve"])
        self.assertNotIn("epss", f["citations"])

    def test_enrich_preserves_existing_epss(self):
        f = {
            "source": "agent:security-reviewer",
            "citations": {
                "cwe": ["CWE-89"],
                "epss": [{"cve": "CVE-2023-1234", "score": 0.42, "percentile": 0.97}],
            },
        }
        cit.enrich_citations([f], self.cat, epss_enabled=False)
        self.assertIn("epss", f["citations"])
        self.assertEqual(f["citations"]["epss"][0]["cve"], "CVE-2023-1234")
        self.assertAlmostEqual(f["citations"]["epss"][0]["score"], 0.42)

    def test_enrich_tolerant_of_malformed_subfields(self):
        findings = [
            {"source": "agent:x", "citations": {"ssvc": "active"}},  # ssvc as string
            {"source": "agent:x", "citations": {"cwe": 89}},  # cwe as int
            {"source": "agent:x", "citations": {"cve": 5, "owasp": 1}},
            {"source": "agent:x", "citations": {"cwe": ["CWE-89"]}},  # valid alongside
        ]
        cit.enrich_citations(findings, cit.load_cwe_catalog())  # must not raise
        self.assertNotIn("citations", findings[0])
        self.assertNotIn("citations", findings[1])
        self.assertEqual([c["id"] for c in findings[3]["citations"]["cwe"]], ["CWE-89"])

    def test_epss_response_size_cap_behavioral(self):
        # Behavioral test for SEC-G3B: return a payload larger than 1MB

        class HugeResp:
            def __init__(self):
                # 2MB of spaces before a valid JSON, which will get truncated
                self.data = b" " * 1500000 + b'{"data": [{"cve": "CVE-2023-1234", "epss": "0.1", "percentile": "0.5", "date": "2026-07-20"}]}'
            def read(self, size=-1):
                return self.data[:size] if size > 0 else self.data
            def __enter__(self): return self
            def __exit__(self, *args): pass

        def opener(req, timeout=0):
            return HugeResp()

        with tempfile.TemporaryDirectory() as d:
            out = cit.epss_lookup(["CVE-2023-1234"], os.path.join(d, "c.json"), opener=opener)
            # Should be empty because the json was truncated and failed to parse
            self.assertEqual(out, {})
