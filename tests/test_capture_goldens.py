"""Tests for the generator of the normalization-contract goldens (#1525).

`capture_goldens.py` is the sole producer of `tests/goldens/tool-raw/`, and had
zero tests: a regression in `trim()` that dropped a payload's only
vulnerability-bearing entries would produce a golden that parses to nothing, and
nothing pinned that at the source. The downstream consumer
(`tests/tools/test_normalization_contract.py`) only fires after a human has
regenerated and committed a golden.

The module's own `sys.path.insert(0, "/opt/panopticon")` is a no-op off the
image; `trim` and `_trim_xml` are pure bytes->bytes functions.
"""
import contextlib
import io
import json
import os
import tempfile
import unittest
import unittest.mock
import xml.etree.ElementTree as ET

import scripts.capture_goldens as cg


class TestTrimJson(unittest.TestCase):
    def test_a_top_level_list_keeps_the_first_few(self):
        out = json.loads(cg.trim(json.dumps(list(range(10))).encode()))
        self.assertEqual(out, list(range(cg.KEEP)))

    def test_sarif_keeps_one_run_and_caps_results_and_rules(self):
        sarif = {"runs": [{"results": [{"i": i} for i in range(10)],
                           "tool": {"driver": {"rules": [{"id": str(i)}
                                                         for i in range(50)]}}},
                          {"results": []}]}
        out = json.loads(cg.trim(json.dumps(sarif).encode()))
        self.assertEqual(len(out["runs"]), 1)
        self.assertEqual(len(out["runs"][0]["results"]), cg.KEEP)
        self.assertEqual(len(out["runs"][0]["tool"]["driver"]["rules"]), 10)

    def test_osv_trims_the_nested_packages_level(self):
        # results[].packages[] nests two deep; trimming `results` alone left
        # every package behind it.
        payload = {"results": [{"packages": [{"name": "clean-%d" % i}
                                             for i in range(5)]
                                + [{"name": "bad", "vulnerabilities": [{"id": "V"}]}]},
                               {"packages": []}]}
        out = json.loads(cg.trim(json.dumps(payload).encode()))
        self.assertEqual(len(out["results"]), 1)
        packages = out["results"][0]["packages"]
        self.assertEqual([p["name"] for p in packages], ["bad"])

    def test_osv_falls_back_to_clean_packages_when_none_have_vulns(self):
        payload = {"results": [{"packages": [{"name": "c%d" % i} for i in range(9)]}]}
        out = json.loads(cg.trim(json.dumps(payload).encode()))
        self.assertEqual(len(out["results"][0]["packages"]), cg.KEEP)

    def test_a_trim_never_drops_the_only_findings_bearing_entries(self):
        # The invariant _has_vulns exists for: dependency-check lists every
        # dependency it saw and most are clean, so keeping the FIRST few
        # produced a golden that parsed to ZERO findings.
        payload = {"dependencies": [{"fileName": "clean-%d" % i} for i in range(8)]
                   + [{"fileName": "vulnerable", "vulnerabilities": [{"name": "CVE-1"}]}]}
        out = json.loads(cg.trim(json.dumps(payload).encode()))
        self.assertEqual([d["fileName"] for d in out["dependencies"]], ["vulnerable"])

    def test_all_clean_entries_still_yield_a_trimmed_list(self):
        payload = {"dependencies": [{"fileName": "c%d" % i} for i in range(8)]}
        out = json.loads(cg.trim(json.dumps(payload).encode()))
        self.assertEqual(len(out["dependencies"]), cg.KEEP)

    def test_every_list_key_is_trimmed(self):
        payload = {k: [{"n": i} for i in range(9)] for k in cg.LIST_KEYS}
        out = json.loads(cg.trim(json.dumps(payload).encode()))
        for key in cg.LIST_KEYS:
            self.assertEqual(len(out[key]), cg.KEEP, key)

    def test_a_dict_valued_list_key_is_capped_too(self):
        payload = {"vulnerabilities": {str(i): {"n": i} for i in range(9)}}
        out = json.loads(cg.trim(json.dumps(payload).encode()))
        self.assertEqual(len(out["vulnerabilities"]), cg.KEEP)

    def test_a_scalar_payload_is_returned_unchanged(self):
        self.assertEqual(cg.trim(b"5"), b"5")


class TestTrimXml(unittest.TestCase):
    def test_xml_is_trimmed_structurally_and_stays_well_formed(self):
        # Slicing XML at a byte offset produced an unclosed element that no
        # longer parsed. A golden that cannot be parsed is worse than a big one.
        doc = b"<BugCollection>" + b"".join(
            b"<BugInstance i='%d'><Class/></BugInstance>" % i for i in range(9)
        ) + b"<Errors/></BugCollection>"
        out = cg.trim(doc)
        root = ET.fromstring(out.decode("utf-8"))          # must still parse
        self.assertEqual(len(root.findall("BugInstance")), cg.KEEP)
        self.assertIsNotNone(root.find("Errors"))          # envelope preserved

    def test_unparseable_bytes_are_returned_unchanged(self):
        self.assertEqual(cg.trim(b"<not xml"), b"<not xml")

    def test_non_finding_children_are_never_dropped(self):
        doc = b"<r>" + b"".join(b"<other/>" for _ in range(9)) + b"</r>"
        root = ET.fromstring(cg.trim(doc).decode("utf-8"))
        self.assertEqual(len(root.findall("other")), 9)


class _Adapter:
    """Stand-in for a tool adapter, each hook independently riggable."""

    def __init__(self, applicable=True, raw=b'{"results": []}', parsed=None,
                 fail=None):
        self._applicable, self._raw = applicable, raw
        self._parsed = [{"id": "X-001"}] if parsed is None else parsed
        self._fail = fail

    def is_applicable(self, target):
        if self._fail == "is_applicable":
            raise RuntimeError("boom")
        return self._applicable

    def invoke(self, target):
        if self._fail == "invoke":
            raise RuntimeError("boom")
        return self._raw, 0

    def parse(self, raw, group):
        if self._fail == "parse":
            raise RuntimeError("boom")
        if self._fail == "reparse" and raw != self._raw:
            raise RuntimeError("trim broke it")
        return self._parsed


class TestMainStatusClassification(unittest.TestCase):
    """main()'s seven-way classification is how an operator learns WHY a golden
    is missing. A capture that silently reported 'ok' for a tool it never ran
    would leave a stale golden in place."""

    def _run(self, adapters, targets, argv_extra=()):
        with tempfile.TemporaryDirectory() as out_dir:
            argv = ["capture_goldens.py", out_dir] + list(argv_extra)
            out = io.StringIO()
            with unittest.mock.patch.object(cg, "ADAPTERS", adapters), \
                 unittest.mock.patch.object(cg, "TARGETS", targets), \
                 unittest.mock.patch.object(cg.sys, "argv", argv), \
                 contextlib.redirect_stdout(out):
                cg.main()
            return json.loads(out.getvalue()), sorted(os.listdir(out_dir))

    def _with_target(self, **kw):
        d = tempfile.mkdtemp()
        self.addCleanup(lambda: os.rmdir(d) if os.path.isdir(d) else None)
        return d, _Adapter(**kw)

    def test_missing_target_directory_is_no_target(self):
        report, written = self._run({"t": _Adapter()}, {"t": "/nonexistent/dir"})
        self.assertEqual(report["t"]["status"], "no-target")
        self.assertEqual(written, [])

    def test_unregistered_adapter_is_no_target(self):
        report, _ = self._run({}, {"t": "/tmp"}, argv_extra=["t"])
        self.assertEqual(report["t"]["status"], "no-target")

    def test_not_applicable_is_reported_not_captured(self):
        d, adapter = self._with_target(applicable=False)
        report, written = self._run({"t": adapter}, {"t": d})
        self.assertEqual(report["t"]["status"], "not-applicable")
        self.assertEqual(written, [])

    def test_each_hook_failure_gets_its_own_status(self):
        for fail, status in (("is_applicable", "is_applicable-error"),
                             ("invoke", "invoke-error"),
                             ("parse", "parse-error")):
            d, adapter = self._with_target(fail=fail)
            report, written = self._run({"t": adapter}, {"t": d})
            self.assertEqual(report["t"]["status"], status, fail)
            self.assertEqual(written, [], fail)

    def test_a_trim_that_breaks_parsing_writes_no_golden(self):
        # The guard that keeps an unusable golden out of the corpus.
        d, adapter = self._with_target(
            raw=json.dumps({"results": [{"i": i} for i in range(9)]}).encode(),
            fail="reparse")
        report, written = self._run({"t": adapter}, {"t": d})
        self.assertEqual(report["t"]["status"], "trim-broke-parse")
        self.assertEqual(written, [])

    def test_a_successful_capture_writes_the_golden_and_counts_both_sides(self):
        d, adapter = self._with_target(
            raw=json.dumps({"results": [{"i": i} for i in range(9)]}).encode())
        report, written = self._run({"t": adapter}, {"t": d})
        self.assertEqual(report["t"]["status"], "ok")
        self.assertEqual(written, ["t.raw"])
        self.assertLess(report["t"]["golden_bytes"], report["t"]["raw_bytes"])
        self.assertEqual(report["t"]["golden_findings"], 1)


if __name__ == "__main__":
    unittest.main()
