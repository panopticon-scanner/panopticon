import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir, os.pardir))
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


class TestRoslynSecGuardAdapter(unittest.TestCase):
    def test_parse_produces_finding(self):
        findings = rs.RoslynSecGuardAdapter().parse(ROSLYN_SAMPLE, "g1")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["source"], "tool:roslyn-secguard")
        self.assertEqual(findings[0]["location"]["file"], "Program.cs")

    def test_build_target_prefers_solution(self):
        adapter = rs.RoslynSecGuardAdapter()
        with tempfile.TemporaryDirectory() as d:
            csproj = os.path.join(d, "a.csproj")
            sln = os.path.join(d, "b.sln")
            open(csproj, "w").close()
            open(sln, "w").close()
            self.assertEqual(adapter._build_target(d), sln)

    def test_invoke_uses_temp_output_paths(self):
        adapter = rs.RoslynSecGuardAdapter()
        calls = []

        class Result:
            returncode = 0

        old_run = rs.subprocess.run
        try:
            def fake_run(cmd, **kwargs):
                calls.append((cmd, kwargs))
                return Result()

            rs.subprocess.run = fake_run
            with tempfile.TemporaryDirectory() as d:
                open(os.path.join(d, "x.csproj"), "w").close()
                raw, rc = adapter.invoke(d)
                self.assertEqual(raw, b"{}")
                self.assertEqual(rc, 0)
        finally:
            rs.subprocess.run = old_run

        cmd = calls[0][0]
        self.assertTrue(any(arg.startswith("-p:BaseIntermediateOutputPath=") for arg in cmd))
        self.assertTrue(any(arg.startswith("-p:BaseOutputPath=") for arg in cmd))
