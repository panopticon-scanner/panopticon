import contextvars
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import scripts.ingest_tools as it
import scripts.tools.pip_audit as pip_audit_module
from scripts.tools import ADAPTERS

# #run7 QAL-D1B: the raw pip-audit fixture output, previously duplicated verbatim.
_PIP_AUDIT_OUTPUT = b'{"dependencies": [{"name": "requests", "version": "2.20.0", "vulns": [{"id": "CVE-2018-18074", "aliases": ["CVE-2018-18074"], "fix_versions": ["2.20.1"], "description": "vuln"}]}]}'


class TestPhase1Integration(unittest.TestCase):
    def test_pip_audit_parses_literal_report(self):
        adapter = ADAPTERS["pip-audit"]
        token = pip_audit_module._manifest_path_cv.set(None)
        try:
            findings = adapter.parse(_PIP_AUDIT_OUTPUT, "g1")
        finally:
            pip_audit_module._manifest_path_cv.reset(token)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["id"], "PA-001")
        self.assertEqual(findings[0]["source"], "tool:pip-audit")
        self.assertEqual(findings[0]["severity"], "MEDIUM")
        self.assertEqual(findings[0]["citations"]["cve"], ["CVE-2018-18074"])
        self.assertEqual(findings[0]["location"]["file"], "requirements.txt")
        self.assertEqual(findings[0]["tool_evidence"]["package_name"], "requests")

    def test_npm_audit_parses_literal_report(self):
        adapter = ADAPTERS["npm-audit"]
        mock_output = json.dumps({"advisories": {"123": {"title": "Command Injection in lodash", "module_name": "lodash", "vulnerable_versions": "<4.17.21", "patched_versions": ">=4.17.21", "severity": "high", "cves": ["CVE-2021-23337"]}}}).encode()
        findings = adapter.parse(mock_output, "g1")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["source"], "tool:npm-audit")
        self.assertEqual(findings[0]["severity"], "HIGH")
        self.assertEqual(findings[0]["citations"]["cve"], ["CVE-2021-23337"])
        self.assertEqual(findings[0]["location"]["file"], "package-lock.json")
        self.assertEqual(findings[0]["title"], "lodash <4.17.21: Command Injection in lodash")

    def test_osv_scanner_parses_raw_output(self):
        adapter = ADAPTERS["osv-scanner"]
        raw = json.dumps(
            {
                "results": [
                    {
                        "source": {"path": "/src/package-lock.json", "type": "lockfile"},
                        "packages": [
                            {
                                "package": {
                                    "name": "lodash",
                                    "version": "4.17.20",
                                    "ecosystem": "npm",
                                },
                                "vulnerabilities": [
                                    {
                                        "id": "GHSA-35jh-r3h4-6jhm",
                                        "aliases": ["CVE-2021-23337"],
                                        "severity": [
                                            {
                                                "type": "CVSS_V3",
                                                "score": (
                                    "CVSS:3.1/AV:N/AC:L/PR:N/"
                                    "UI:N/S:U/C:H/I:H/A:H"
                                ),
                                            }
                                        ],
                                        "summary": "Command Injection in lodash",
                                    }
                                ],
                                "groups": [
                                    {
                                        "ids": ["GHSA-35jh-r3h4-6jhm"],
                                        "aliases": ["CVE-2021-23337"],
                                        "max_severity": "7.2",
                                    }
                                ],
                            }
                        ],
                    }
                ]
            }
        ).encode()
        findings = adapter.parse(raw, "g1")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["source"], "tool:osv-scanner")
        self.assertEqual(findings[0]["citations"]["cve"], ["CVE-2021-23337"])

    def test_ingest_dir_routes_osv_scanner_output(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "osv-scanner.json"), "wb") as fh:
                fh.write(json.dumps({"results": []}).encode())
            findings = it.ingest_dir(d, "g1")
            self.assertEqual(findings, [])

    def test_eslint_security_parses_literal_report(self):
        adapter = ADAPTERS["eslint-security"]
        mock_output = json.dumps([{"filePath": "app.js", "messages": [{"ruleId": "security/detect-eval-with-expression", "severity": 2, "message": "eval can be harmful", "line": 5, "column": 1}]}]).encode()
        findings = adapter.parse(mock_output, "g1")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["source"], "tool:eslint-security")
        self.assertEqual(findings[0]["severity"], "HIGH")
        self.assertEqual(findings[0]["category"], "code_security")
        self.assertEqual(findings[0]["location"]["file"], "app.js")
        self.assertEqual(findings[0]["location"]["line_start"], 5)
        self.assertEqual(findings[0]["citations"]["cwe"], ["CWE-95"])

    def test_ingest_dir_routes_adapter_output(self):
        raw = _PIP_AUDIT_OUTPUT
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "pip-audit.json"), "wb") as fh:
                fh.write(raw)
            # Literal report ingestion is separate from the controlled invoke seam.
            findings = it.ingest_dir(d, "g1", include_fixtures=True)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["source"], "tool:pip-audit")
            self.assertEqual(findings[0]["citations"]["cve"], ["CVE-2018-18074"])
            self.assertEqual(findings[0]["severity"], "MEDIUM")

    def test_offline_adapters_invoke_controlled_children_and_parse(self):
        fixtures = Path(__file__).parent / "fixtures"
        cases = (
            ("pip-audit", fixtures / "vulnerable-python", "requirements.txt",
             "requests==2.25.1", _PIP_AUDIT_OUTPUT, "CVE-2018-18074"),
            ("npm-audit", fixtures / "vulnerable-node", "package.json",
             '"lodash": "4.17.20"', json.dumps({"advisories": {"123": {
                 "title": "Command Injection in lodash", "module_name": "lodash",
                 "vulnerable_versions": "<4.17.21", "patched_versions": ">=4.17.21",
                 "severity": "high", "cves": ["CVE-2021-23337"]}}}).encode(),
             "CVE-2021-23337"),
            ("eslint-security", fixtures / "insecure-js", "app.js", "eval(userInput)",
             json.dumps([{"filePath": "app.js", "messages": [{
                 "ruleId": "security/detect-eval-with-expression", "severity": 2,
                 "message": "eval can be harmful", "line": 2, "column": 1}]}]).encode(),
             "CWE-95"),
        )
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            bin_dir = root / "bin"
            bin_dir.mkdir()
            empty_target = root / "empty-target"
            empty_target.mkdir()
            for name, target, manifest, needle, report, citation in cases:
                self.assertTrue(ADAPTERS[name].is_applicable(str(target)))
                self.assertFalse(ADAPTERS[name].is_applicable(str(empty_target)))
                self.assertIn(needle, (target / manifest).read_text())
                marker = root / (name + ".invoked")
                # A real child process validates the argv and fixture bytes before
                # returning planted scanner output. No scanner or network starts.
                script = """#!/usr/bin/env python3
import pathlib, sys
args = sys.argv[1:]
target = pathlib.Path({target!r})
pathlib.Path({marker!r}).write_text(repr(args))
if {name!r} == 'pip-audit':
    assert '--requirement' in args and str(target) not in args
    assert '--format=json' in args and '--desc=on' in args
    assert {needle!r} in pathlib.Path(args[args.index('--requirement') + 1]).read_text()
elif {name!r} == 'npm-audit':
    assert args == ['audit', '--json', '--prefix', str(target)]
    assert {needle!r} in (target / {manifest!r}).read_text()
else:
    assert '--no-config-lookup' in args and '--format' in args
    assert args[-1] == str(target.resolve())
    assert {needle!r} in (target / {manifest!r}).read_text()
pathlib.Path({marker!r}).write_text('called')
sys.stdout.buffer.write({report!r})
sys.exit(1)
""".format(target=str(target), name=name,
               needle=needle, manifest=manifest, marker=str(marker), report=report)
                executable = bin_dir / {"pip-audit": "pip-audit", "npm-audit": "npm",
                                        "eslint-security": "eslint"}[name]
                executable.write_text(script)
                executable.chmod(0o755)
            with mock.patch.dict(os.environ, {"PATH": str(bin_dir) + os.pathsep + os.environ["PATH"],
                                               "TMPDIR": d}), mock.patch.object(tempfile, "tempdir", d):
                for name, target, _, _, _, citation in cases:
                    def exercise_adapter():
                        adapter = ADAPTERS[name]
                        raw, rc = adapter.invoke(str(target))
                        self.assertEqual(rc, 1, name)
                        self.assertEqual((root / (name + ".invoked")).read_text(),
                                         "called", name)
                        findings = adapter.parse(raw, "g1")
                        self.assertEqual(len(findings), 1, name)
                        cited = findings[0]["citations"]
                        self.assertIn(citation, cited.get("cve", []) + cited.get("cwe", []))
                        self.assertEqual(findings[0]["source"], "tool:" + name)

                    # invoke stores the scanned manifest in ContextVars shared
                    # by the singleton adapters. Keep those writes inside this
                    # call so later tests see their own caller context.
                    original_manifest = pip_audit_module._manifest_path_cv.get()
                    contextvars.copy_context().run(exercise_adapter)
                    self.assertEqual(pip_audit_module._manifest_path_cv.get(),
                                     original_manifest)


if __name__ == "__main__":
    unittest.main()
