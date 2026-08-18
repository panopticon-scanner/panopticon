import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir, "skill"))
import scripts.security_gate as gate


def _sarif(level=None):
    results = []
    if level:
        results.append({
            "ruleId": "test.rule",
            "level": level,
            "message": {"text": "test finding"},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": "/src/app.py"},
                "region": {"startLine": 1}}}],
        })
    return {"version": "2.1.0", "runs": [{
        "tool": {"driver": {"name": "semgrep", "rules": []}},
        "results": results,
    }]}


class TestSecurityGate(unittest.TestCase):
    def _write(self, root, manifest, sarif=None):
        tools = os.path.join(root, "tools")
        os.makedirs(tools)
        if sarif is not None:
            with open(os.path.join(tools, "semgrep.sarif"), "w") as fh:
                json.dump(sarif, fh)
        manifest_path = os.path.join(root, "manifest.json")
        with open(manifest_path, "w") as fh:
            json.dump(manifest, fh)
        return tools, manifest_path

    def test_complete_clean_scan_passes(self):
        with tempfile.TemporaryDirectory() as root:
            tools, manifest = self._write(
                root, {"selected": ["semgrep"], "produced": ["semgrep"],
                       "missing": []}, _sarif())
            findings, dispositions, failures, high = gate.evaluate(tools, manifest)
        self.assertEqual(findings, [])
        self.assertEqual(dispositions["semgrep"]["status"], "empty")
        self.assertEqual(failures, [])
        self.assertEqual(high, [])

    def test_missing_selected_scanner_fails_coverage(self):
        with tempfile.TemporaryDirectory() as root:
            tools, manifest = self._write(
                root, {"selected": ["semgrep"], "produced": [],
                       "missing": ["semgrep"]})
            _, _, failures, _ = gate.evaluate(tools, manifest)
        self.assertEqual(failures, ["semgrep: no output"])

    def test_high_finding_fails_gate(self):
        with tempfile.TemporaryDirectory() as root:
            tools, manifest = self._write(
                root, {"selected": ["semgrep"], "produced": ["semgrep"],
                       "missing": []}, _sarif("error"))
            _, _, failures, high = gate.evaluate(tools, manifest)
        self.assertEqual(failures, [])
        self.assertEqual(len(high), 1)
        self.assertEqual(high[0]["severity"], "HIGH")

    def test_empty_selection_is_invalid(self):
        with tempfile.TemporaryDirectory() as root:
            tools, manifest = self._write(
                root, {"selected": [], "produced": [], "missing": []})
            with self.assertRaisesRegex(ValueError, "selected no tools"):
                gate.evaluate(tools, manifest)

    def test_excluded_scope_scanner_does_not_fail_coverage(self):
        # An adapter demoted to excluded_scope is NOT in selected/missing, so a
        # clean scan passes even though the adapter produced no output.
        with tempfile.TemporaryDirectory() as root:
            tools, manifest = self._write(
                root, {"selected": ["semgrep"], "produced": ["semgrep"],
                       "missing": [], "excluded_scope": ["eslint-security"]},
                _sarif())
            _, _, failures, high = gate.evaluate(tools, manifest, ["tests/fixtures/*"])
        self.assertEqual(failures, [])
        self.assertEqual(high, [])

    def test_excluded_scope_backward_compatible_absent(self):
        # A manifest without the excluded_scope key still loads (older producer).
        with tempfile.TemporaryDirectory() as root:
            tools, manifest = self._write(
                root, {"selected": ["semgrep"], "produced": ["semgrep"],
                       "missing": []}, _sarif())
            data = gate.load_manifest(manifest)
        self.assertEqual(data["excluded_scope"], [])

    def test_excluded_scope_overlapping_selected_is_invalid(self):
        with tempfile.TemporaryDirectory() as root:
            tools, manifest = self._write(
                root, {"selected": ["semgrep"], "produced": ["semgrep"],
                       "missing": [], "excluded_scope": ["semgrep"]})
            with self.assertRaisesRegex(ValueError, "excluded_scope overlaps"):
                gate.evaluate(tools, manifest)

    def test_large_sarif_file_loading(self):
        # Generate a large SARIF file with many findings to verify performance and scaling
        results = [
            {
                "ruleId": f"rule.{i}",
                "level": "warning" if i % 10 != 0 else "error",
                "message": {"text": f"Finding description {i}"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": f"/src/module_{i % 50}.py"},
                        "region": {"startLine": (i * 3) % 1000 + 1},
                    }
                }],
            }
            for i in range(1000)
        ]
        large_sarif = {
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {"name": "semgrep", "rules": []}},
                "results": results,
            }],
        }
        with tempfile.TemporaryDirectory() as root:
            tools, manifest = self._write(
                root, {"selected": ["semgrep"], "produced": ["semgrep"], "missing": []},
                large_sarif,
            )
            findings, dispositions, failures, high = gate.evaluate(tools, manifest)
        self.assertEqual(len(findings), 1000)
        self.assertEqual(dispositions["semgrep"]["status"], "ok")
        self.assertEqual(dispositions["semgrep"]["findings"], 1000)
        self.assertEqual(failures, [])
        self.assertEqual(len(high), 100)  # 1000 / 10 = 100 error/high findings


if __name__ == "__main__":
    unittest.main()
