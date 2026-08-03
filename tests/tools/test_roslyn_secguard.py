import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir, os.pardir, "skill"))
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

        old_run = rs.subprocess.run
        old_copytree = rs.shutil.copytree
        try:
            def fake_copytree(src, dst, dirs_exist_ok=False):
                copied_src.append(src)
                copied_dst.append(dst)
                open(os.path.join(dst, "x.csproj"), "w").close()

            def fake_run(cmd, **kwargs):
                calls.append((cmd, kwargs))
                return Result()

            rs.shutil.copytree = fake_copytree
            rs.subprocess.run = fake_run
            with tempfile.TemporaryDirectory() as d:
                open(os.path.join(d, "x.csproj"), "w").close()
                raw, rc = adapter.invoke(d)
                self.assertEqual(raw, b"{}")
                self.assertEqual(rc, 0)
                self.assertEqual(copied_src, [d])
        finally:
            rs.subprocess.run = old_run
            rs.shutil.copytree = old_copytree

        cmd = calls[0][0]
        self.assertEqual(cmd[0], "dotnet")
        self.assertEqual(cmd[1], "build")
        self.assertTrue(cmd[2].startswith(copied_dst[0]))
        self.assertTrue(any(arg.startswith("-p:ErrorLog=") for arg in cmd))
