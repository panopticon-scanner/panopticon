import contextlib
import contextvars
import io
import json
import os
import shutil
import tempfile
import unittest
from unittest import mock

import pytest

from _test_helpers import FakePopen, first, only
import scripts.tools.pip_audit as pa


@pytest.fixture(autouse=True)
def _reset_pip_audit_manifest_path_cv():
    """Reset the per-invocation manifest path ContextVar around each test."""
    token = pa._manifest_path_cv.set(None)
    try:
        yield
    finally:
        pa._manifest_path_cv.reset(token)

PIP_AUDIT_SAMPLE = json.dumps({
    "dependencies": [
        {
            "name": "requests",
            "version": "2.25.1",
            "vulns": [
                {
                    "id": "PYSEC-2023-1",
                    "fix_versions": ["2.31.0"],
                    "description": "Unintended leak of proxy credentials",
                    "aliases": ["CVE-2023-32681"],
                }
            ]
        }
    ]
}).encode()


class TestPipAuditAdapter(unittest.TestCase):
    def test_parse_produces_finding(self):
        adapter = pa.PipAuditAdapter()
        findings = adapter.parse(PIP_AUDIT_SAMPLE, "g1")
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f["source"], "tool:pip-audit")
        self.assertEqual(f["severity"], "MEDIUM")
        self.assertEqual(f["citations"]["cve"], ["CVE-2023-32681"])
        self.assertEqual(f["tool_evidence"]["package_name"], "requests")
        self.assertEqual(f["tool_evidence"]["fixed_version"], "2.31.0")

    def test_parse_survives_empty_fix_versions_list(self):
        # pip-audit emits "fix_versions": [] when no fixed release exists; the
        # .get default only covers a MISSING key, so [..][0] used to IndexError
        # and ingest marked the whole pip-audit document failed (PR #945 scan,
        # finding CORR-001).
        sample = json.dumps({
            "dependencies": [
                {"name": "leftpad", "version": "0.1", "vulns": [
                    {"id": "PYSEC-2024-9", "fix_versions": [],
                     "description": "d", "aliases": []}]}
            ]
        }).encode()
        findings = pa.PipAuditAdapter().parse(sample, "g1")
        self.assertEqual(len(findings), 1)
        self.assertNotIn("fixed_version", findings[0]["tool_evidence"])

    def test_parse_uses_actual_manifest_path(self):
        adapter = pa.PipAuditAdapter()
        token = pa._manifest_path_cv.set("/tmp/fake/pyproject.toml")
        try:
            findings = adapter.parse(PIP_AUDIT_SAMPLE, "g1")
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["location"]["file"], "/tmp/fake/pyproject.toml")
        finally:
            pa._manifest_path_cv.reset(token)

    def test_parse_defaults_location_file_when_no_manifest(self):
        adapter = pa.PipAuditAdapter()
        findings = adapter.parse(PIP_AUDIT_SAMPLE, "g1")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["location"]["file"], "requirements.txt")

    def test_manifest_path_is_per_invocation_not_singleton_state(self):
        # Regression: _manifest_path used to be stored on the singleton
        # instance, so a second invoke could overwrite the value before the
        # first invoke's output was parsed. To catch that, invoke both targets
        # before parsing either result. Each target's invoke/parse pair runs in
        # its own copied execution context so the ContextVar set by invoke is
        # still the right one when parse is finally called.
        adapter = pa.PipAuditAdapter()

        def fake_find_requirement(target: str) -> str:
            return os.path.join(target, "requirements.txt")

        with mock.patch.object(adapter, "_find_requirement", side_effect=fake_find_requirement):
            with mock.patch.object(pa, "run_tool", return_value=(PIP_AUDIT_SAMPLE, 0)):
                ctx1 = contextvars.copy_context()
                ctx2 = contextvars.copy_context()
                raw1, _ = ctx1.run(adapter.invoke, "/tmp/fake1")
                raw2, _ = ctx2.run(adapter.invoke, "/tmp/fake2")
                findings1 = ctx1.run(adapter.parse, raw1, "g1")
                findings2 = ctx2.run(adapter.parse, raw2, "g2")

        self.assertEqual(first(findings1)["location"]["file"], "/tmp/fake1/requirements.txt")
        self.assertEqual(first(findings2)["location"]["file"], "/tmp/fake2/requirements.txt")

    def test_parse_omits_none_tool_evidence_fields(self):
        sample = json.dumps({
            "dependencies": [
                {
                    "name": "requests",
                    "version": "2.25.1",
                    "vulns": [
                        {
                            "id": "PYSEC-2023-1",
                            "description": "Missing fixed version",
                        }
                    ]
                }
            ]
        }).encode()
        findings = pa.PipAuditAdapter().parse(sample, "g1")
        self.assertEqual(len(findings), 1)
        evidence = findings[0]["tool_evidence"]
        self.assertNotIn("fixed_version", evidence)
        self.assertEqual(evidence["package_name"], "requests")

    def test_is_applicable_when_requirements_present(self):
        with mock.patch("os.path.exists", side_effect=lambda p: p.endswith("requirements.txt")):
            self.assertTrue(pa.PipAuditAdapter().is_applicable("/tmp/fake"))

    def test_is_applicable_when_requirements_dev_present(self):
        with mock.patch("scripts.tools.pip_audit.glob.glob", return_value=["/tmp/fake/requirements-dev.txt"]):
            with mock.patch("os.path.exists", return_value=False):
                self.assertTrue(pa.PipAuditAdapter().is_applicable("/tmp/fake"))

    def test_is_applicable_when_pyproject_present(self):
        with mock.patch("os.path.exists", side_effect=lambda p: p.endswith("pyproject.toml")):
            with mock.patch("scripts.tools.pip_audit.glob.glob", return_value=[]):
                self.assertTrue(pa.PipAuditAdapter().is_applicable("/tmp/fake"))

    def test_is_applicable_false_for_setup_py(self):
        with mock.patch("os.path.exists", side_effect=lambda p: p.endswith("setup.py")):
            with mock.patch("scripts.tools.pip_audit.glob.glob", return_value=[]):
                self.assertFalse(pa.PipAuditAdapter().is_applicable("/tmp/fake"))

    def test_is_applicable_false_for_setup_cfg(self):
        with mock.patch("os.path.exists", side_effect=lambda p: p.endswith("setup.cfg")):
            with mock.patch("scripts.tools.pip_audit.glob.glob", return_value=[]):
                self.assertFalse(pa.PipAuditAdapter().is_applicable("/tmp/fake"))

    def test_is_applicable_false_when_no_manifest(self):
        with mock.patch("os.path.exists", return_value=False):
            with mock.patch("scripts.tools.pip_audit.glob.glob", return_value=[]):
                self.assertFalse(pa.PipAuditAdapter().is_applicable("/tmp/fake"))

    def test_find_requirement_prefers_canonical_over_dev_sibling(self):
        # #707: requirements-dev.txt sorts before requirements.txt ('-' < '.'),
        # so the old lexicographic-first pick silently audited the dev manifest
        # and skipped the primary one. The canonical file must always win.
        with tempfile.TemporaryDirectory() as d:
            for name in ("requirements.txt", "requirements-dev.txt",
                         "requirements-test.txt"):
                open(os.path.join(d, name), "w").close()
            self.assertEqual(pa.PipAuditAdapter()._find_requirement(d),
                             os.path.join(d, "requirements.txt"))

    def test_find_requirement_falls_back_to_glob_without_canonical(self):
        with tempfile.TemporaryDirectory() as d:
            open(os.path.join(d, "requirements-dev.txt"), "w").close()
            self.assertEqual(pa.PipAuditAdapter()._find_requirement(d),
                             os.path.join(d, "requirements-dev.txt"))

    def test_find_requirement_none_when_absent(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertIsNone(pa.PipAuditAdapter()._find_requirement(d))

    def test_parse_includes_provenance(self):
        findings = pa.PipAuditAdapter().parse(PIP_AUDIT_SAMPLE, "g1")
        self.assertTrue(findings)
        self.assertEqual(first(findings)["provenance"]["discovered_by"], "tool:pip-audit")
        self.assertEqual(first(findings)["provenance"]["confirmation_status"], "TOOL")

    def test_invoke_uses_a_generated_file_not_the_found_requirements_txt(self):
        # #1646: this test used to PIN the defect -- it asserted the argv
        # carried `/tmp/fake/requirements.txt`, the repo's own file. The
        # adapter now always names a generated temp file; the repo path it
        # found survives only in the argv's ABSENCE of it.
        adapter = pa.PipAuditAdapter()
        fake_run = FakePopen(stdout=b"[]", stderr=b"", returncode=0)
        with mock.patch("scripts.tools.base.subprocess.Popen",
                        return_value=fake_run) as popen_mock:
            with mock.patch("scripts.tools.pip_audit.glob.glob", return_value=["/tmp/fake/requirements.txt"]):
                stdout, rc = adapter.invoke("/tmp/fake")
        self.assertEqual(stdout, b"[]")
        self.assertEqual(rc, 0)
        argv = popen_mock.call_args[0][0]
        self.assertEqual(argv[:5], ["pip-audit", "--format=json", "--desc=on",
                                    "--progress-spinner=off", "--requirement"])
        self.assertNotIn("/tmp/fake/requirements.txt", argv)
        self.assertFalse(argv[5].startswith("/tmp/fake/"))

    def test_invoke_falls_back_to_pyproject_toml(self):
        adapter = pa.PipAuditAdapter()
        fake_run = FakePopen(stdout=b"[]", stderr=b"", returncode=0)
        with mock.patch("scripts.tools.base.subprocess.Popen",
                        return_value=fake_run) as popen_mock:
            with mock.patch("scripts.tools.pip_audit.glob.glob", return_value=[]):
                with mock.patch("scripts.tools.pip_audit._deps_from_pyproject",
                               return_value=["requests==2.25.1"]):
                    stdout, rc = adapter.invoke("/tmp/fake")
        self.assertEqual(stdout, b"[]")
        self.assertEqual(rc, 0)
        # Verify that --requirement is used with a temp file, not a positional arg
        call_args = popen_mock.call_args[0][0]
        self.assertIn("--requirement", call_args)
        self.assertNotIn("/tmp/fake", call_args)


PYPROJECT_STATIC = b"""
[project]
name = "x"
dependencies = ["requests==2.25.1", "urllib3>=1.26"]
[project.optional-dependencies]
dev = ["pytest"]
"""

PYPROJECT_DYNAMIC = b"""
[project]
name = "x"
dynamic = ["dependencies"]
"""


class TestStaticPyproject(unittest.TestCase):
    def _target(self, content):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        with open(os.path.join(d, "pyproject.toml"), "wb") as fh:
            fh.write(content)
        return d

    def test_static_deps_extracted(self):
        deps = pa._deps_from_pyproject(self._target(PYPROJECT_STATIC))
        self.assertEqual(deps,
                         ["requests==2.25.1", "urllib3>=1.26", "pytest"])

    def test_dynamic_deps_return_none(self):
        self.assertIsNone(
            pa._deps_from_pyproject(self._target(PYPROJECT_DYNAMIC)))

    def test_invoke_uses_requirement_file_not_positional(self):
        target = self._target(PYPROJECT_STATIC)
        captured = {}
        def fake_run_tool(cmd, timeout=0):
            captured["cmd"] = list(cmd)
            # Guard the index so a command-shape change fails with a clear
            # message, not an opaque ValueError/IndexError (#587).
            self.assertIn("--requirement", cmd)
            req_idx = cmd.index("--requirement")
            self.assertLess(req_idx + 1, len(cmd),
                            "--requirement is the last argument with no value")
            with open(cmd[req_idx + 1]) as fh:
                captured["reqs"] = fh.read()
            return b"{}", 0
        with mock.patch.object(pa, "run_tool", fake_run_tool):
            pa.PipAuditAdapter().invoke(target)
        self.assertNotIn(target, captured["cmd"])
        self.assertIn("requests==2.25.1", captured["reqs"])

    def test_invoke_reports_nonzero_exit(self):
        import contextlib, io
        adapter = pa.PipAuditAdapter()
        fake_run = FakePopen(stdout=b"audit output", stderr=b"pip-audit failed",
                             returncode=2)
        buf = io.StringIO()
        with mock.patch("scripts.tools.base.subprocess.Popen", return_value=fake_run), \
             mock.patch("scripts.tools.pip_audit.glob.glob", return_value=["/tmp/fake/requirements.txt"]), \
             contextlib.redirect_stderr(buf):
            stdout, rc = adapter.invoke("/tmp/fake")
        self.assertEqual(stdout, b"audit output")
        self.assertEqual(rc, 2)
        self.assertIn("tool pip-audit exited 2", buf.getvalue())
        self.assertIn("pip-audit failed", buf.getvalue())

    def test_invoke_dynamic_pyproject_returns_empty_without_running(self):
        target = self._target(PYPROJECT_DYNAMIC)
        buf = io.StringIO()
        with mock.patch.object(pa, "run_tool") as rt_mock, \
             contextlib.redirect_stderr(buf):
            raw, rc = pa.PipAuditAdapter().invoke(target)
        rt_mock.assert_not_called()
        self.assertEqual((json.loads(raw), rc),
                         ({"dependencies": [], "fixes": []}, 0))
        self.assertIn("no static [project.dependencies]", buf.getvalue())

    def test_non_utf8_pyproject_returns_none(self):
        deps = pa._deps_from_pyproject(
            self._target(b'\xff\xfe[project]\nname = "x"\n'))
        self.assertIsNone(deps)


# #1646 (SEC-E3A): the adapter used to hand pip-audit the REPOSITORY'S OWN
# requirements file. Requirements syntax admits `-e .`, `./local/path`,
# `git+https://...`, `https://.../x.tar.gz` and `--index-url`; resolving the
# first four invokes the reviewed repo's PEP 517 build backend, so a hostile
# target ran code under the scanner account, online. Owner ruling D5 is
# sanitize-and-disclose: pip-audit is always handed a GENERATED file holding
# only bare PEP 508 requirement lines, and every dropped line is recorded.
HOSTILE_REQUIREMENTS = (
    "# a comment\n"
    "\n"
    "-e .\n"
    "./vendor/pkg\n"
    "git+https://x/y.git#egg=z\n"
    "https://x/z.tar.gz\n"
    "--index-url https://evil\n"
    "pkg==1.0 --hash=sha256:abc\n"
    'good>=1,<2 ; python_version<"3.13"\n'
    "--extra\\\n"
    "-index-url https://evil2\n"
)

SAFE_LINES = ["pkg==1.0", 'good>=1,<2 ; python_version<"3.13"']


class TestSanitizeRequirements(unittest.TestCase):
    """The grammar: a kept line is a bare PEP 508 requirement and nothing else."""

    def test_the_hostile_fixture_keeps_only_the_two_safe_lines(self):
        kept, dropped = pa.sanitize_requirements(HOSTILE_REQUIREMENTS)
        self.assertEqual(kept, SAFE_LINES)
        self.assertEqual(
            dropped,
            [{"line": "-e .", "reason": "editable"},
             {"line": "./vendor/pkg", "reason": "local path"},
             {"line": "git+https://x/y.git#egg=z", "reason": "vcs url"},
             {"line": "https://x/z.tar.gz", "reason": "direct url"},
             {"line": "--index-url https://evil", "reason": "option line"},
             {"line": "--extra-index-url https://evil2", "reason": "option line"}])

    def test_comments_and_blanks_are_skipped_not_dropped(self):
        kept, dropped = pa.sanitize_requirements("\n# note\n\n  \nreq==1\n")
        self.assertEqual(kept, ["req==1"])
        self.assertEqual(dropped, [])

    def test_version_grammar_passes_through_byte_for_byte(self):
        text = ('name==1.2.3\n'
                'name>=1,<2\n'
                'name[extra]~=1.4 ; python_version < "3.12"\n')
        kept, dropped = pa.sanitize_requirements(text)
        self.assertEqual(kept, text.splitlines())
        self.assertEqual(dropped, [])

    def test_direct_url_reference_is_dropped_not_kept(self):
        kept, dropped = pa.sanitize_requirements("name @ https://x/y.whl\n")
        self.assertEqual(kept, [])
        self.assertEqual(dropped, [{"line": "name @ https://x/y.whl",
                                    "reason": "direct url"}])

    def test_vcs_direct_reference_is_dropped_as_vcs(self):
        kept, dropped = pa.sanitize_requirements("name @ git+ssh://x/y.git\n")
        self.assertEqual(kept, [])
        self.assertEqual(dropped, [{"line": "name @ git+ssh://x/y.git",
                                    "reason": "vcs url"}])

    def test_unparseable_line_is_dropped_with_that_reason(self):
        kept, dropped = pa.sanitize_requirements("not a requirement!!\n")
        self.assertEqual(kept, [])
        self.assertEqual(dropped, [{"line": "not a requirement!!",
                                    "reason": "unparseable"}])

    def test_include_lines_are_dropped_by_the_pure_grammar(self):
        # The pure function never reads the filesystem: it classifies -r/-c as
        # `include` and the include-following wrapper decides what to do.
        kept, dropped = pa.sanitize_requirements("-r base.txt\n-c pins.txt\n")
        self.assertEqual(kept, [])
        self.assertEqual([d["reason"] for d in dropped], ["include", "include"])

    def test_a_dropped_line_never_carries_url_credentials(self):
        # tools-manifest.json is an artifact operators copy into CI; a dropped
        # option line is target-authored text and can carry a private-index
        # password. Mask it at the producer, not at the sink.
        _kept, dropped = pa.sanitize_requirements(
            "--index-url https://bob:hunter2@pypi.internal/simple\n")
        entry = only(dropped)
        self.assertEqual(entry["reason"], "option line")
        self.assertNotIn("hunter2", entry["line"])

    def test_hashes_are_stripped_from_a_kept_line(self):
        kept, dropped = pa.sanitize_requirements(
            "pkg==1.0 --hash=sha256:abc --hash=sha256:def\n")
        self.assertEqual(kept, ["pkg==1.0"])
        self.assertEqual(dropped, [])


class TestSanitizeRequirementsFile(unittest.TestCase):
    """Includes: followed ONE level, confined to the target root."""

    def _target(self, files):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        for name, text in files.items():
            path = os.path.join(d, name)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(text)
        return d

    def test_include_is_followed_once_and_sanitized(self):
        d = self._target({"requirements.txt": "-r base.txt\ntop==1\n",
                          "base.txt": "-e .\nbase==2\n"})
        kept, dropped, hashes = pa.sanitize_requirements_file(
            os.path.join(d, "requirements.txt"), d)
        self.assertEqual(kept, ["base==2", "top==1"])
        self.assertEqual(dropped, [{"line": "-e .", "reason": "editable"}])
        self.assertFalse(hashes)

    def test_include_outside_the_target_is_dropped(self):
        d = self._target({"requirements.txt": "-r ../outside.txt\nok==1\n"})
        kept, dropped, _h = pa.sanitize_requirements_file(
            os.path.join(d, "requirements.txt"), d)
        self.assertEqual(kept, ["ok==1"])
        self.assertEqual(dropped, [{"line": "-r ../outside.txt",
                                    "reason": "include outside target"}])

    def test_include_cycle_is_dropped_as_nested_include(self):
        d = self._target({"requirements.txt": "-r self.txt\n",
                          "self.txt": "-r self.txt\nok==1\n"})
        kept, dropped, _h = pa.sanitize_requirements_file(
            os.path.join(d, "requirements.txt"), d)
        self.assertEqual(kept, ["ok==1"])
        self.assertEqual(dropped, [{"line": "-r self.txt",
                                    "reason": "nested include"}])

    def test_second_level_include_is_dropped_as_nested_include(self):
        d = self._target({"requirements.txt": "-r a.txt\n",
                          "a.txt": "-r b.txt\na==1\n",
                          "b.txt": "b==2\n"})
        kept, dropped, _h = pa.sanitize_requirements_file(
            os.path.join(d, "requirements.txt"), d)
        self.assertEqual(kept, ["a==1"])
        self.assertEqual(dropped, [{"line": "-r b.txt",
                                    "reason": "nested include"}])

    def test_unreadable_include_is_disclosed(self):
        d = self._target({"requirements.txt": "-r gone.txt\nok==1\n"})
        kept, dropped, _h = pa.sanitize_requirements_file(
            os.path.join(d, "requirements.txt"), d)
        self.assertEqual(kept, ["ok==1"])
        self.assertEqual(dropped, [{"line": "-r gone.txt",
                                    "reason": "include unreadable"}])

    def test_hashes_stripped_is_reported_once_for_the_whole_tree(self):
        d = self._target({"requirements.txt": "pkg==1 --hash=sha256:abc\n"})
        kept, dropped, hashes = pa.sanitize_requirements_file(
            os.path.join(d, "requirements.txt"), d)
        self.assertEqual((kept, dropped, hashes), (["pkg==1"], [], True))


class TestInvokeNeverPassesTheRepoFile(unittest.TestCase):
    """Ruling 1: the repo's own requirements file is never an argv value."""

    def _target(self, text=HOSTILE_REQUIREMENTS):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        with open(os.path.join(d, "requirements.txt"), "w", encoding="utf-8") as fh:
            fh.write(text)
        return d

    def _invoke(self, target):
        seen = {}

        def fake_run_tool(cmd, timeout=0):
            seen["cmd"] = list(cmd)
            idx = cmd.index("--requirement")
            seen["req"] = cmd[idx + 1]
            with open(cmd[idx + 1], encoding="utf-8") as fh:
                seen["content"] = fh.read()
            return b"{}", 0

        with mock.patch.object(pa, "run_tool", fake_run_tool):
            pa.PipAuditAdapter().invoke(target)
        return seen

    def test_requirement_names_a_temp_file_not_the_repo_path(self):
        target = self._target()
        seen = self._invoke(target)
        self.assertNotIn(os.path.join(target, "requirements.txt"), seen["cmd"])
        self.assertFalse(seen["req"].startswith(target),
                         "pip-audit was handed a path inside the reviewed repo: %s"
                         % seen["req"])

    def test_the_generated_file_holds_exactly_the_safe_lines(self):
        seen = self._invoke(self._target())
        self.assertEqual(seen["content"].splitlines(), SAFE_LINES)

    def test_the_generated_file_is_deleted_after_the_run(self):
        seen = self._invoke(self._target())
        self.assertFalse(os.path.exists(seen["req"]),
                         "the generated requirements file outlived the run")

    def test_location_still_points_at_the_repo_manifest(self):
        target = self._target()
        with mock.patch.object(pa, "run_tool",
                               return_value=(PIP_AUDIT_SAMPLE, 0)):
            ctx = contextvars.copy_context()
            raw, _rc = ctx.run(pa.PipAuditAdapter().invoke, target)
            findings = ctx.run(pa.PipAuditAdapter().parse, raw, "g1")
        self.assertEqual(first(findings)["location"]["file"],
                         os.path.join(target, "requirements.txt"))

    def test_pyproject_branch_is_sanitized_too_and_its_temp_file_removed(self):
        # `_deps_from_pyproject` is a STATIC read, but PEP 621 dependencies may
        # themselves carry `name @ git+https://...` -- the same build-backend
        # door through a second file. The generated file is the control on both
        # branches (ruling 1).
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        with open(os.path.join(d, "pyproject.toml"), "w", encoding="utf-8") as fh:
            fh.write('[project]\nname = "x"\n'
                     'dependencies = ["requests==2.25.1", "evil @ git+https://x/y.git"]\n')
        seen = self._invoke(d)
        self.assertEqual(seen["content"].splitlines(), ["requests==2.25.1"])
        self.assertFalse(os.path.exists(seen["req"]))


class TestSanitizationReport(unittest.TestCase):
    """The DISCLOSE half of ruling D5: the adapter->manifest channel.

    Shaped exactly like `excluded_scope`: the runner queries the adapter
    IN-PROCESS, on the host, and hands the answer to `write_manifest`. The
    method is pure (it reads files, launches nothing), so asking it is safe on
    the docker-absent path too.
    """

    def _target(self, files):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        for name, text in files.items():
            with open(os.path.join(d, name), "w", encoding="utf-8") as fh:
                fh.write(text)
        return d

    def test_report_names_the_source_the_count_and_every_dropped_line(self):
        d = self._target({"requirements.txt": HOSTILE_REQUIREMENTS})
        report = pa.PipAuditAdapter().sanitization_report(d)
        self.assertEqual(report["source"], "requirements.txt")
        self.assertEqual(report["kept"], 2)
        self.assertEqual([x["reason"] for x in report["dropped"]],
                         ["editable", "local path", "vcs url", "direct url",
                          "option line", "option line"])
        self.assertTrue(report["hashes_stripped"])

    def test_source_is_repo_relative_never_an_absolute_host_path(self):
        d = self._target({"requirements.txt": "ok==1\n"})
        report = pa.PipAuditAdapter().sanitization_report(d)
        self.assertEqual(report["source"], "requirements.txt")
        self.assertNotIn(d, json.dumps(report))

    def test_report_covers_the_pyproject_branch_too(self):
        d = self._target({"pyproject.toml": '[project]\nname = "x"\n'
                                            'dependencies = ["a==1", "b @ https://x/y.whl"]\n'})
        report = pa.PipAuditAdapter().sanitization_report(d)
        self.assertEqual(report["source"], "pyproject.toml")
        self.assertEqual(report["kept"], 1)
        self.assertEqual(only(report["dropped"]),
                         {"line": "b @ https://x/y.whl", "reason": "direct url"})

    def test_no_report_when_the_adapter_is_not_applicable(self):
        self.assertIsNone(pa.PipAuditAdapter().sanitization_report(self._target({})))

    def test_report_is_pure_and_launches_nothing(self):
        d = self._target({"requirements.txt": HOSTILE_REQUIREMENTS})
        with mock.patch.object(pa, "run_tool") as rt_mock:
            pa.PipAuditAdapter().sanitization_report(d)
        rt_mock.assert_not_called()


if __name__ == "__main__":
    unittest.main()
