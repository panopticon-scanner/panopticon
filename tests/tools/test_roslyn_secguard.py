import json
import os
import tempfile
import unittest

import scripts.tools.base as tools_base
import scripts.tools.roslyn_secguard as rs

ROSLYN_SAMPLE = json.dumps({
    "runs": [{
        "results": [{
            "ruleId": "SCS0026",
            "message": {"text": "Potential XSS"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": "Program.cs"},
                    "region": {"startLine": 15},
                }
            }],
        }]
    }]
}).encode()

ROSLYN_SAMPLE_V1 = json.dumps({
    "version": "1.0.0",
    "runs": [{
        "tool": {"name": "csc"},
        "results": [{
            "ruleId": "SCS0001",
            "level": "warning",
            "message": {"text": "Potential command injection"},
            "locations": [{
                "resultFile": {
                    "uri": "file:///tmp/Apps/Controllers/HomeController.cs",
                    "region": {"startLine": 42},
                }
            }],
        }]
    }]
}).encode()

# SecurityCodeScan can emit ``message`` as a plain string rather than a dict.
ROSLYN_SAMPLE_STRING_MESSAGE = json.dumps({
    "runs": [{
        "results": [{
            "ruleId": "SCS0018",
            "message": "Potential path traversal",
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": "Controllers/HomeController.cs"},
                    "region": {"startLine": 7},
                }
            }],
        }]
    }]
}).encode()

ROSLYN_SAMPLE_LEVELS = json.dumps({
    "runs": [{
        "results": [
            {"ruleId": "SCS0002", "level": "error", "message": {"text": "SQL injection"},
             "locations": [{"physicalLocation": {
                 "artifactLocation": {"uri": "a.cs"}, "region": {"startLine": 3}}}]},
            {"ruleId": "SCS0026", "level": "warning", "message": {"text": "XSS"},
             "locations": [{"physicalLocation": {
                 "artifactLocation": {"uri": "b.cs"}, "region": {"startLine": 5}}}]},
            {"ruleId": "SCS0018", "level": "note", "message": {"text": "Path traversal"},
             "locations": [{"physicalLocation": {
                 "artifactLocation": {"uri": "c.cs"}, "region": {"startLine": 7}}}]},
        ]
    }]
}).encode()

ROSLYN_SAMPLE_EMPTY_LOCATIONS = json.dumps({
    "runs": [{"results": [
        {"ruleId": "SCS0002", "message": {"text": "SQL injection"},
         "locations": [{"physicalLocation": {
             "artifactLocation": {"uri": "a.cs"}, "region": {"startLine": 3}}}]},
        {"ruleId": "SCS0026", "message": {"text": "location-less diagnostic"},
         "locations": []},
    ]}]
}).encode()

ROSLYN_SAMPLE_NULL_LOCATIONS = json.dumps({
    "runs": [{"results": [
        {"ruleId": "SCS0002", "message": {"text": "SQL injection"},
         "locations": [{"physicalLocation": {
             "artifactLocation": {"uri": "a.cs"}, "region": {"startLine": 3}}}]},
        {"ruleId": "SCS0026", "message": {"text": "location-less diagnostic"},
         "locations": None},
    ]}]
}).encode()

ROSLYN_SAMPLE_MISSING_LOCATIONS_KEY = json.dumps({
    "runs": [{"results": [
        {"ruleId": "SCS0002", "message": {"text": "SQL injection"}},
    ]}]
}).encode()

MIXED_SARIF = json.dumps({
    "runs": [{"results": [
        {"ruleId": "SCS0002",
         "message": {"text": "SQL injection"},
         "locations": [{"physicalLocation": {
             "artifactLocation": {"uri": "a.cs"},
             "region": {"startLine": 3}}}]},
        {"ruleId": "CS0246",
         "message": {"text": "type not found: leaked /etc/passwd content"},
         "locations": [{"physicalLocation": {
             "artifactLocation": {"uri": "b.cs"},
             "region": {"startLine": 1}}}]},
    ]}]
}).encode()


class TestRoslynSecGuardAdapter(unittest.TestCase):
    def test_parse_produces_finding(self):
        findings = rs.RoslynSecGuardAdapter().parse(ROSLYN_SAMPLE, "g1")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["source"], "tool:roslyn-secguard")
        self.assertEqual(findings[0]["location"]["file"], "Program.cs")
        self.assertEqual(findings[0]["location"]["line_start"], 15)
        self.assertIn("CWE-79", findings[0]["citations"]["cwe"])

    def test_parse_v1_result_file(self):
        findings = rs.RoslynSecGuardAdapter().parse(ROSLYN_SAMPLE_V1, "g1")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["location"]["file"], "/tmp/Apps/Controllers/HomeController.cs")
        self.assertEqual(findings[0]["location"]["line_start"], 42)
        self.assertIn("CWE-78", findings[0]["citations"]["cwe"])
        self.assertEqual(findings[0]["severity"], "MEDIUM")  # ROSLYN_SAMPLE_V1 carries level="warning"

    def test_parse_maps_sarif_level_to_severity(self):
        findings = rs.RoslynSecGuardAdapter().parse(ROSLYN_SAMPLE_LEVELS, "g1")
        self.assertEqual(len(findings), 3)
        by_rule = {f["tool_evidence"]["rule_id"]: f["severity"] for f in findings}
        self.assertEqual(by_rule["SCS0002"], "HIGH")
        self.assertEqual(by_rule["SCS0026"], "MEDIUM")
        self.assertEqual(by_rule["SCS0018"], "LOW")

    def test_parse_defaults_missing_level_to_warning_severity(self):
        # ROSLYN_SAMPLE has no "level" key at all; SARIF's own default for an
        # unspecified level is "warning".
        findings = rs.RoslynSecGuardAdapter().parse(ROSLYN_SAMPLE, "g1")
        self.assertEqual(findings[0]["severity"], "MEDIUM")

    def test_parse_survives_empty_locations_array(self):
        findings = rs.RoslynSecGuardAdapter().parse(ROSLYN_SAMPLE_EMPTY_LOCATIONS, "g1")
        # The well-formed SCS0002 result survives; the location-less SCS0026
        # result is skipped rather than crashing the whole parse.
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["tool_evidence"]["rule_id"], "SCS0002")

    def test_parse_survives_null_locations(self):
        findings = rs.RoslynSecGuardAdapter().parse(ROSLYN_SAMPLE_NULL_LOCATIONS, "g1")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["tool_evidence"]["rule_id"], "SCS0002")

    def test_parse_missing_locations_key_drops_like_empty(self):
        # #476: an OMITTED locations key is the same location-less case as an
        # empty/null one -- both drop. Previously the omitted form emitted a
        # placeholder {"file": "", "line_start": 1} finding while the empty
        # form was dropped, an asymmetry with no basis in SARIF semantics.
        findings = rs.RoslynSecGuardAdapter().parse(ROSLYN_SAMPLE_MISSING_LOCATIONS_KEY, "g1")
        self.assertEqual(findings, [])

    def test_parse_survives_non_dict_run_entry(self):
        # A non-dict entry in the SARIF "runs" array must not crash the whole
        # parse — mirror sarif_to_findings' run-level isinstance guard (#253).
        for bad in (
            b'{"runs": ["not-a-dict"]}',
            b'{"runs": [null]}',
            b'{"runs": null}',
            b'{"runs": [{"results": null}]}',
        ):
            self.assertEqual(rs.RoslynSecGuardAdapter().parse(bad, "g1"), [])

    def test_parse_string_message(self):
        findings = rs.RoslynSecGuardAdapter().parse(ROSLYN_SAMPLE_STRING_MESSAGE, "g1")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["title"], "Potential path traversal")
        self.assertEqual(findings[0]["description"], "Potential path traversal")
        self.assertEqual(findings[0]["location"]["file"], "Controllers/HomeController.cs")
        self.assertIn("CWE-22", findings[0]["citations"]["cwe"])

    def test_parse_includes_provenance(self):
        findings = rs.RoslynSecGuardAdapter().parse(ROSLYN_SAMPLE, "g1")
        self.assertTrue(findings)
        self.assertEqual(findings[0]["provenance"]["discovered_by"], "tool:roslyn-secguard")
        self.assertEqual(findings[0]["provenance"]["confirmation_status"], "TOOL")

    def test_build_target_prefers_solution(self):
        adapter = rs.RoslynSecGuardAdapter()
        with tempfile.TemporaryDirectory() as d:
            csproj = os.path.join(d, "a.csproj")
            sln = os.path.join(d, "b.sln")
            open(csproj, "w").close()
            open(sln, "w").close()
            self.assertEqual(adapter._build_target(d), sln)

    def test_invoke_builds_in_temp_copy(self):
        adapter = rs.RoslynSecGuardAdapter()
        calls = []
        copied_src = []
        copied_dst = []

        class Result:
            returncode = 0
            stdout = b""
            stderr = b""

        old_run = tools_base.subprocess.run
        old_safe_copytree = rs._safe_copytree
        try:
            def fake_safe_copytree(src, dst):
                copied_src.append(src)
                copied_dst.append(dst)
                open(os.path.join(dst, "x.csproj"), "w").close()
                return 0

            def fake_run(cmd, **kwargs):
                calls.append((cmd, kwargs))
                return Result()

            rs._safe_copytree = fake_safe_copytree
            tools_base.subprocess.run = fake_run
            with tempfile.TemporaryDirectory() as d:
                open(os.path.join(d, "x.csproj"), "w").close()
                raw, rc = adapter.invoke(d)
                self.assertEqual(raw, b"{}")
                self.assertEqual(rc, 0)
                self.assertEqual(copied_src, [d])
        finally:
            tools_base.subprocess.run = old_run
            rs._safe_copytree = old_safe_copytree

        cmd = calls[0][0]
        kwargs = calls[0][1]
        self.assertEqual(cmd[0], "dotnet")
        self.assertEqual(cmd[1], "build")
        self.assertTrue(cmd[2].startswith(copied_dst[0]))
        self.assertTrue(any(arg.startswith("-p:ErrorLog=") for arg in cmd))
        self.assertEqual(kwargs.get("timeout"), 600)
        self.assertTrue(kwargs.get("capture_output"))


class TestSafeCopytree(unittest.TestCase):
    def _tree(self, d):
        os.makedirs(os.path.join(d, "src", "sub"))
        with open(os.path.join(d, "src", "app.csproj"), "w") as fh:
            fh.write("<Project/>")
        with open(os.path.join(d, "outside.txt"), "w") as fh:
            fh.write("SECRET")
        return os.path.join(d, "src")

    def test_out_of_tree_symlink_is_skipped_and_counted(self):
        with tempfile.TemporaryDirectory() as d:
            src = self._tree(d)
            os.symlink(os.path.join(d, "outside.txt"),
                       os.path.join(src, "leak.cs"))
            dst = os.path.join(d, "dst")
            skipped = rs._safe_copytree(src, dst)
            self.assertEqual(skipped, 1)
            self.assertFalse(os.path.lexists(os.path.join(dst, "leak.cs")))
            self.assertTrue(os.path.exists(os.path.join(dst, "app.csproj")))

    def test_in_tree_symlink_copied_as_link(self):
        with tempfile.TemporaryDirectory() as d:
            src = self._tree(d)
            os.symlink("app.csproj", os.path.join(src, "alias.csproj"))
            dst = os.path.join(d, "dst")
            self.assertEqual(rs._safe_copytree(src, dst), 0)
            self.assertTrue(os.path.islink(os.path.join(dst, "alias.csproj")))

    def test_dangling_symlink_does_not_abort(self):
        with tempfile.TemporaryDirectory() as d:
            src = self._tree(d)
            os.symlink(os.path.join(d, "gone.txt"),
                       os.path.join(src, "dangling.cs"))
            dst = os.path.join(d, "dst")
            skipped = rs._safe_copytree(src, dst)   # must not raise
            self.assertEqual(skipped, 1)

    def test_symlink_loop_terminates(self):
        with tempfile.TemporaryDirectory() as d:
            src = self._tree(d)
            os.symlink(src, os.path.join(src, "sub", "loop"))
            dst = os.path.join(d, "dst")
            rs._safe_copytree(src, dst)             # must return, not recurse
            self.assertTrue(os.path.exists(os.path.join(dst, "sub")))

    def test_sibling_prefix_dir_is_out_of_tree(self):
        with tempfile.TemporaryDirectory() as d:
            src = self._tree(d)                      # <d>/src
            evil = os.path.join(d, "src-evil")
            os.makedirs(evil)
            with open(os.path.join(evil, "secret.txt"), "w") as fh:
                fh.write("SECRET")
            os.symlink(os.path.join(evil, "secret.txt"),
                       os.path.join(src, "leak.cs"))
            dst = os.path.join(d, "dst")
            skipped = rs._safe_copytree(src, dst)
            self.assertEqual(skipped, 1)
            self.assertFalse(os.path.lexists(os.path.join(dst, "leak.cs")))


class TestScsOnlyFilter(unittest.TestCase):
    def test_non_scs_results_are_dropped(self):
        found = rs.RoslynSecGuardAdapter().parse(MIXED_SARIF, "g")
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["tool_evidence"]["rule_id"], "SCS0002")
