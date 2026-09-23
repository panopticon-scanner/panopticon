import ast
import contextlib
import contextvars
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import pytest

from _test_helpers import FakePopen, fake_aws_key, first, only
import scripts.ingest_tools as ingest_tools
import scripts.run_tools as run_tools
import scripts.tools.pip_audit as pa

try:
    from packaging.requirements import Requirement
except ImportError:                                  # pragma: no cover
    Requirement = None


def _assert_every_kept_line_parses(kept):
    """Every KEPT line must parse as a real, URL-free PEP 508 requirement.

    pip-audit resolves the generated file through `pip install --dry-run`,
    which parses every line, so ONE line this module keeps but pip cannot parse
    aborts the WHOLE dependency audit: pip-audit produces nothing, the coverage
    manifest lands it in `missing`, and the gate reads a target-side typo as a
    scanner failure. The kept grammar therefore has to be at least as strict as
    pip-audit's own parser -- which is what this asserts, with the real parser.

    `packaging` is not a declared runtime dependency (see pyproject.toml) and
    `scripts/tools/pip_audit.py` deliberately does not import it, so this is a
    TEST-ONLY cross-check and is a no-op where it is unavailable. It runs on
    this workstation and on the 3.11 leg.
    """
    if Requirement is None:                          # pragma: no cover
        return
    for line in kept:
        req = Requirement(line)                      # raises InvalidRequirement
        assert req.url is None, "a kept line carries a URL: %r" % (line,)


def sanitize(text):
    """The ONLY way this module calls `sanitize_requirements`.

    Every call is cross-checked inline, so "the corpus is complete" is
    structural rather than a comment somebody has to remember to honour --
    `TestEverySanitizerCallGoesThroughTheHelper` is what keeps it that way.
    """
    kept, dropped = pa.sanitize_requirements(text)
    _assert_every_kept_line_parses(kept)
    return kept, dropped


def sanitize_file(path, root):
    """The ONLY way this module calls `sanitize_requirements_file`."""
    report = pa.sanitize_requirements_file(path, root)
    _assert_every_kept_line_parses(report["kept"])
    return report


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

    def test_parse_defaults_location_file_when_nothing_names_a_tree(self):
        # Last resort only -- see the ingest tests below for the route a real
        # scan takes (#1649).
        adapter = pa.PipAuditAdapter()
        findings = adapter.parse(PIP_AUDIT_SAMPLE, "g1")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["location"]["file"], pa.DEFAULT_MANIFEST)

    # ---- the route a real scan actually takes (#1649) -----------------------
    #
    # `invoke` runs inside the tools container and `parse` on the host, so the
    # manifest ContextVar `invoke` sets is gone by parse time and every
    # production finding used to be located at a flat "requirements.txt" -- a
    # file a pyproject-only or requirements-dev-only project does not have.

    def _target(self, *names):
        d = tempfile.mkdtemp()
        self.addCleanup(lambda: shutil.rmtree(d, ignore_errors=True))
        for name in names:
            with open(os.path.join(d, name), "w", encoding="utf-8") as fh:
                fh.write("")
        return d

    def _ingested(self, target):
        """The host half, through the real ingest: the container's bytes on
        disk, `ingest_dir_detailed` over them, the target root named."""
        tools_dir = tempfile.mkdtemp()
        self.addCleanup(lambda: shutil.rmtree(tools_dir, ignore_errors=True))
        with open(os.path.join(tools_dir, "pip-audit.json"), "wb") as fh:
            fh.write(PIP_AUDIT_SAMPLE)
        findings, _dispositions = ingest_tools.ingest_dir_detailed(
            tools_dir, "g1", target_root=target)
        return only(findings)["location"]["file"]

    def test_a_host_side_ingest_locates_the_finding_at_the_manifest_in_the_tree(self):
        # The glob fallback is what pip-audit would have audited here; the
        # canonical requirements.txt is not in this tree at all.
        target = self._target("requirements-dev.txt")
        located = self._ingested(target)
        self.assertEqual("requirements-dev.txt", located)
        self.assertTrue(os.path.isfile(os.path.join(target, located)))

    def test_a_pyproject_only_tree_is_located_at_its_pyproject(self):
        target = self._target("pyproject.toml")
        self.assertEqual("pyproject.toml", self._ingested(target))

    def test_the_canonical_requirements_file_still_wins_when_present(self):
        target = self._target("requirements.txt", "requirements-dev.txt")
        self.assertEqual("requirements.txt", self._ingested(target))

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
        # carried the target's own `requirements.txt`. The adapter now always
        # names a generated temp file; the repo path it found survives only in
        # the argv's ABSENCE of it. A REAL file on disk, not a mocked glob:
        # fix round 2 F5 made every candidate `isfile`-checked, and a fixture
        # naming a path that does not exist would stop exercising this branch.
        target = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, target, ignore_errors=True)
        with open(os.path.join(target, "requirements.txt"), "w", encoding="utf-8") as fh:
            fh.write("ok==1\n")
        fake_run = FakePopen(stdout=b"[]", stderr=b"", returncode=0)
        with mock.patch("scripts.tools.base.subprocess.Popen",
                        return_value=fake_run) as popen_mock:
            stdout, rc = pa.PipAuditAdapter().invoke(target)
        self.assertEqual(stdout, b"[]")
        self.assertEqual(rc, 0)
        argv = popen_mock.call_args[0][0]
        self.assertEqual(argv[:5], ["pip-audit", "--format=json", "--desc=on",
                                    "--progress-spinner=off", "--requirement"])
        self.assertNotIn(os.path.join(target, "requirements.txt"), argv)
        self.assertFalse(argv[5].startswith(target + os.sep))

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
        def fake_run_tool(cmd, timeout=0, **kw):
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
        target = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, target, ignore_errors=True)
        with open(os.path.join(target, "requirements.txt"), "w", encoding="utf-8") as fh:
            fh.write("ok==1\n")
        adapter = pa.PipAuditAdapter()
        fake_run = FakePopen(stdout=b"audit output", stderr=b"pip-audit failed",
                             returncode=2)
        buf = io.StringIO()
        with mock.patch("scripts.tools.base.subprocess.Popen", return_value=fake_run), \
             contextlib.redirect_stderr(buf):
            stdout, rc = adapter.invoke(target)
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


class TestPyprojectReadBoundary(unittest.TestCase):
    def _target(self, content=None):
        target = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, target, ignore_errors=True)
        path = os.path.join(target, "pyproject.toml")
        if content is not None:
            with open(path, "wb") as fh:
                fh.write(content)
        return target, path

    def _assert_refused(self, target, reason, truncated):
        stderr = io.StringIO()
        with mock.patch.object(pa, "run_tool") as launch, \
             contextlib.redirect_stderr(stderr):
            raw, status = pa.PipAuditAdapter().invoke(target)
            report = pa.PipAuditAdapter().sanitization_report(target)
        launch.assert_not_called()
        self.assertNotEqual(status, 0)
        self.assertNotEqual(raw, b'{"dependencies": [], "fixes": []}')
        self.assertIn(reason, stderr.getvalue())
        self.assertLess(len(stderr.getvalue()), 200)
        self.assertNotIn(target, stderr.getvalue())
        self.assertEqual(report["source"], "pyproject.toml")
        self.assertEqual(report["kept"], 0)
        self.assertEqual(report["dropped"],
                         [{"line": "pyproject.toml", "reason": reason}])
        self.assertEqual(report["truncated"], truncated)
        self.assertEqual(report["dropped_truncated"], 0)
        self.assertLess(len(json.dumps(report)), 1000)
        self.assertEqual(run_tools.collect_sanitization(
            {"pip-audit": pa.PipAuditAdapter()}, target), {"pip-audit": report})

    def test_exact_read_limit_keeps_static_dependencies(self):
        content = PYPROJECT_STATIC + b"#" + b"x" * (
            pa._MAX_READ_BYTES - len(PYPROJECT_STATIC) - 1)
        self.assertEqual(len(content), pa._MAX_READ_BYTES)
        target, _ = self._target(content)
        self.assertEqual(pa._deps_from_pyproject(target),
                         ["requests==2.25.1", "urllib3>=1.26", "pytest"])
        seen = {}

        def fake_run(cmd, **_kwargs):
            with open(cmd[cmd.index("--requirement") + 1], encoding="utf-8") as fh:
                seen["lines"] = fh.read().splitlines()
            return b"{}", 0

        with mock.patch.object(pa, "run_tool", side_effect=fake_run):
            self.assertEqual(pa.PipAuditAdapter().invoke(target), (b"{}", 0))
        report = pa.PipAuditAdapter().sanitization_report(target)
        self.assertEqual(seen["lines"],
                         ["requests==2.25.1", "urllib3>=1.26", "pytest"])
        self.assertEqual((report["kept"], report["truncated"]), (3, False))

    def test_limit_plus_one_is_refused_before_toml_parse(self):
        content = PYPROJECT_STATIC + b"#" + b"x" * (
            pa._MAX_READ_BYTES - len(PYPROJECT_STATIC))
        self.assertEqual(len(content), pa._MAX_READ_BYTES + 1)
        target, _ = self._target(content)
        with mock.patch.object(pa.tomllib, "loads") as parse:
            self._assert_refused(target, "pyproject.toml exceeds the 1 MiB read limit", True)
        parse.assert_not_called()

    def test_giant_single_comment_line_is_refused(self):
        target, _ = self._target(PYPROJECT_STATIC + b"#" + b"x" * pa._MAX_READ_BYTES)
        self._assert_refused(target, "pyproject.toml exceeds the 1 MiB read limit", True)

    def test_sparse_oversized_file_is_refused_before_toml_parse(self):
        target, path = self._target(PYPROJECT_STATIC)
        os.truncate(path, 8 * pa._MAX_READ_BYTES)
        with mock.patch.object(pa.tomllib, "loads") as parse:
            self._assert_refused(target, "pyproject.toml exceeds the 1 MiB read limit", True)
        parse.assert_not_called()

    def test_excessive_toml_nesting_is_refused(self):
        nested = b"[project]\nname = " + b"[" * 1200 + b"1" + b"]" * 1200
        target, _ = self._target(nested)
        self._assert_refused(target, "pyproject.toml exceeds the TOML nesting limit", False)

    def test_symlink_to_regular_file_is_refused(self):
        target, path = self._target()
        with open(os.path.join(target, "real.toml"), "wb") as fh:
            fh.write(PYPROJECT_STATIC)
        os.symlink("real.toml", path)
        self._assert_refused(target, "pyproject.toml is a symbolic link", False)

    def test_directory_is_refused_as_non_regular_file(self):
        target, path = self._target()
        os.mkdir(path)
        self._assert_refused(target, "pyproject.toml is not a regular file", False)

    def test_fifo_refusal_cannot_hang_reader(self):
        target, path = self._target()
        os.mkfifo(path)
        # A child and a hard deadline keep the RED run safe: the old open()
        # blocks forever on this path without a writer.
        code = ("import json, sys; sys.path.insert(0, sys.argv[1]); "
                "import scripts.tools.pip_audit as pa; "
                "a = pa.PipAuditAdapter(); raw, rc = a.invoke(sys.argv[2]); "
                "print(json.dumps({'rc': rc, 'raw': raw.decode(), "
                "'report': a.sanitization_report(sys.argv[2])}))")
        skill_root = os.path.dirname(os.path.dirname(os.path.dirname(pa.__file__)))
        result = subprocess.run([sys.executable, "-c", code, skill_root, target],
                                capture_output=True, text=True, timeout=2, check=True)
        observed = json.loads(result.stdout)
        self.assertNotEqual(observed["rc"], 0)
        self.assertEqual(observed["report"]["dropped"],
                         [{"line": "pyproject.toml",
                           "reason": "pyproject.toml is not a regular file"}])


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
        kept, dropped = sanitize(HOSTILE_REQUIREMENTS)
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
        kept, dropped = sanitize("\n# note\n\n  \nreq==1\n")
        self.assertEqual(kept, ["req==1"])
        self.assertEqual(dropped, [])

    def test_version_grammar_passes_through_byte_for_byte(self):
        text = ('name==1.2.3\n'
                'name>=1,<2\n'
                'name[extra]~=1.4 ; python_version < "3.12"\n')
        kept, dropped = sanitize(text)
        self.assertEqual(kept, text.splitlines())
        self.assertEqual(dropped, [])

    def test_direct_url_reference_is_dropped_not_kept(self):
        kept, dropped = sanitize("name @ https://x/y.whl\n")
        self.assertEqual(kept, [])
        self.assertEqual(dropped, [{"line": "name @ https://x/y.whl",
                                    "reason": "direct url"}])

    def test_vcs_direct_reference_is_dropped_as_vcs(self):
        kept, dropped = sanitize("name @ git+ssh://x/y.git\n")
        self.assertEqual(kept, [])
        self.assertEqual(dropped, [{"line": "name @ git+ssh://x/y.git",
                                    "reason": "vcs url"}])

    def test_unparseable_line_is_dropped_with_that_reason(self):
        kept, dropped = sanitize("not a requirement!!\n")
        self.assertEqual(kept, [])
        self.assertEqual(dropped, [{"line": "not a requirement!!",
                                    "reason": "unparseable"}])

    def test_include_lines_are_dropped_by_the_pure_grammar(self):
        # The pure function never reads the filesystem: it classifies -r/-c as
        # `include` and the include-following wrapper decides what to do.
        kept, dropped = sanitize("-r base.txt\n-c pins.txt\n")
        self.assertEqual(kept, [])
        self.assertEqual([d["reason"] for d in dropped], ["include", "include"])

    def test_a_dropped_line_never_carries_url_credentials(self):
        # tools-manifest.json is an artifact operators copy into CI; a dropped
        # option line is target-authored text and can carry a private-index
        # password. Mask it at the producer, not at the sink.
        _kept, dropped = sanitize(
            "--index-url https://bob:hunter2@pypi.internal/simple\n")
        entry = only(dropped)
        self.assertEqual(entry["reason"], "option line")
        self.assertNotIn("hunter2", entry["line"])

    def test_hashes_are_stripped_from_a_kept_line(self):
        kept, dropped = sanitize(
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
        report = sanitize_file(
            os.path.join(d, "requirements.txt"), d)
        self.assertEqual(report["kept"], ["base==2", "top==1"])
        self.assertEqual(report["dropped"],
                         [{"line": "-e .", "reason": "editable"}])
        self.assertFalse(report["hashes_stripped"])

    def test_include_outside_the_target_is_dropped(self):
        d = self._target({"requirements.txt": "-r ../outside.txt\nok==1\n"})
        report = sanitize_file(
            os.path.join(d, "requirements.txt"), d)
        self.assertEqual(report["kept"], ["ok==1"])
        self.assertEqual(report["dropped"], [{"line": "-r ../outside.txt",
                                              "reason": "include outside target"}])

    def test_include_cycle_is_dropped_as_nested_include(self):
        d = self._target({"requirements.txt": "-r self.txt\n",
                          "self.txt": "-r self.txt\nok==1\n"})
        report = sanitize_file(
            os.path.join(d, "requirements.txt"), d)
        self.assertEqual(report["kept"], ["ok==1"])
        self.assertEqual(report["dropped"], [{"line": "-r self.txt",
                                              "reason": "nested include"}])

    def test_second_level_include_is_dropped_as_nested_include(self):
        d = self._target({"requirements.txt": "-r a.txt\n",
                          "a.txt": "-r b.txt\na==1\n",
                          "b.txt": "b==2\n"})
        report = sanitize_file(
            os.path.join(d, "requirements.txt"), d)
        self.assertEqual(report["kept"], ["a==1"])
        self.assertEqual(report["dropped"], [{"line": "-r b.txt",
                                              "reason": "nested include"}])

    def test_unreadable_include_is_disclosed(self):
        d = self._target({"requirements.txt": "-r gone.txt\nok==1\n"})
        report = sanitize_file(
            os.path.join(d, "requirements.txt"), d)
        self.assertEqual(report["kept"], ["ok==1"])
        self.assertEqual(report["dropped"], [{"line": "-r gone.txt",
                                              "reason": "include unreadable"}])

    def test_hashes_stripped_is_reported_once_for_the_whole_tree(self):
        d = self._target({"requirements.txt": "pkg==1 --hash=sha256:abc\n"})
        report = sanitize_file(
            os.path.join(d, "requirements.txt"), d)
        self.assertEqual((report["kept"], report["dropped"],
                          report["hashes_stripped"]), (["pkg==1"], [], True))


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

        def fake_run_tool(cmd, timeout=0, **kw):
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


# #1646 fix round 1, C1: pip decides a requirement is a PATH before it decides
# it looks like one. `pip._internal.req.constructors._get_url_from_path` tests
# `is_archive_file(name)` -- a pure suffix match against
# `pip._internal.utils.filetypes.ARCHIVE_EXTENSIONS` -- ahead of any
# `_looks_like_path` consideration, so a bare name with no separator and no
# leading dot still resolves to `file://<cwd>/<name>`. Verified by the reviewer
# against real pip 26.2.1:
#     _looks_like_path('evil.tar.gz') -> False
#     is_archive_file('evil.tar.gz')  -> True
#     install_req_from_line('evil.tar.gz') -> link=file:///.../src/evil.tar.gz
# An sdist resolved that way has its PEP 517 build backend invoked -- the exact
# #1646 chain. No cross-check against real pip here: pip is not a test-time
# dependency, so the extension list is pinned by NAME and version in a comment
# on `_ARCHIVE_EXTENSIONS` and by the named inputs below.
ARCHIVE_NAMES = [
    "evil.tar.gz", "evil.zip", "evil.tgz", "evil.tar", "evil.tar.bz2",
    "evil.tbz", "evil.tar.xz", "evil.txz", "evil.tlz", "evil.tar.lz",
    "evil.tar.lzma", "foo-1.0-py3-none-any.whl", "x.whl",
    "evil.tar.gz==1.0", "evil.tar.gz ; python_version>'3'",
]


class TestArchiveSuffixedNames(unittest.TestCase):
    def test_every_archive_suffixed_name_is_dropped(self):
        for line in ARCHIVE_NAMES:
            with self.subTest(line=line):
                kept, dropped = sanitize(line + "\n")
                self.assertEqual(kept, [])
                self.assertEqual(only(dropped),
                                 {"line": line, "reason": "archive name"})

    def test_the_suffix_match_is_case_insensitive(self):
        for line in ("Evil.TAR.GZ", "X.WhL", "evil.ZIP"):
            with self.subTest(line=line):
                kept, _dropped = sanitize(line + "\n")
                self.assertEqual(kept, [])

    def test_archive_suffixed_name_with_extras_is_dropped(self):
        kept, dropped = sanitize("evil.tar.gz[x]>=1\n")
        self.assertEqual(kept, [])
        self.assertEqual(only(dropped)["reason"], "archive name")

    def test_an_ordinary_dotted_name_is_still_kept(self):
        # `x.y` is not an archive suffix; pip treats it as a name, and dropping
        # it would be coverage loss, not safety.
        kept, dropped = sanitize("x.y\nzope.interface>=5\n")
        self.assertEqual(kept, ["x.y", "zope.interface>=5"])
        self.assertEqual(dropped, [])

    def test_the_generated_file_never_carries_an_archive_name(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        with open(os.path.join(d, "requirements.txt"), "w", encoding="utf-8") as fh:
            fh.write("evil.tar.gz\nok==1\n")
        seen = {}

        def fake_run_tool(cmd, timeout=0, **kw):
            with open(cmd[cmd.index("--requirement") + 1], encoding="utf-8") as fh:
                seen["content"] = fh.read()
            return b"{}", 0
        with mock.patch.object(pa, "run_tool", fake_run_tool):
            pa.PipAuditAdapter().invoke(d)
        self.assertEqual(seen["content"].splitlines(), ["ok==1"])


class TestPipAuditRunsInAnEmptyWorkingDirectory(unittest.TestCase):
    """C1(b), belt and braces: even if a future grammar gap lets a bare name
    through, cwd-relative resolution must have nothing to find. The container's
    WORKDIR is `/src` -- the target mount -- so without this the scanner's pip
    subprocess resolves relative names INSIDE the reviewed repository."""

    def _invoke(self, target):
        seen = {}

        def fake_run_tool(cmd, timeout=0, **kw):
            seen["cwd"] = kw.get("cwd")
            seen["cwd_entries"] = (sorted(os.listdir(kw["cwd"]))
                                   if kw.get("cwd") else None)
            return b"{}", 0
        with mock.patch.object(pa, "run_tool", fake_run_tool):
            pa.PipAuditAdapter().invoke(target)
        return seen

    def _target(self, name):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        with open(os.path.join(d, name), "w", encoding="utf-8") as fh:
            fh.write('[project]\nname = "x"\ndependencies = ["ok==1"]\n'
                     if name == "pyproject.toml" else "ok==1\n")
        return d

    def test_the_requirements_branch_runs_in_an_empty_scratch_dir(self):
        target = self._target("requirements.txt")
        seen = self._invoke(target)
        self.assertIsNotNone(seen["cwd"], "run_tool was given no cwd")
        self.assertEqual(seen["cwd_entries"], [], "the scratch cwd was not empty")
        self.assertFalse(os.path.realpath(seen["cwd"]).startswith(
            os.path.realpath(target) + os.sep))

    def test_the_pyproject_branch_runs_in_an_empty_scratch_dir(self):
        seen = self._invoke(self._target("pyproject.toml"))
        self.assertEqual(seen["cwd_entries"], [])

    def test_the_scratch_dir_is_removed_after_the_run(self):
        seen = self._invoke(self._target("requirements.txt"))
        self.assertFalse(os.path.exists(seen["cwd"]),
                         "the scratch cwd outlived the run")


class TestPipJoinAndEncodingParity(unittest.TestCase):
    """M4/M5/M6: three ways a VALID pin was silently lost or a broken one kept."""

    def test_a_comment_after_a_continuation_does_not_eat_the_pin(self):
        # pip's `join_lines` prepends a space to a comment line before joining,
        # precisely so the comment is still recognisable afterwards. Appending
        # it raw produced `pkg==1.0# comment`, which `_COMMENT` (which needs
        # `^` or whitespace before the `#`) cannot strip -- so a correctly
        # pinned dependency was dropped as `unparseable`.
        kept, dropped = sanitize(
            "pkg==1.0\\\n# comment\ngood==2.0\n")
        self.assertEqual(kept, ["pkg==1.0", "good==2.0"])
        self.assertEqual(dropped, [])

    def test_a_utf8_bom_does_not_cost_the_first_dependency(self):
        # pip strips the BOM (`auto_decode`); a requirements.txt saved by a
        # Windows editor otherwise loses its first entry with no signal beyond
        # one `unparseable` row.
        kept, dropped = sanitize("\ufeffpkg==1.0\ngood==2\n")
        self.assertEqual(kept, ["pkg==1.0", "good==2"])
        self.assertEqual(dropped, [])

    def test_an_empty_marker_is_dropped_rather_than_kept_and_fatal(self):
        # `packaging.requirements.Requirement("pkg==1.0;")` raises, and
        # pip-audit parses every line of the generated file -- so keeping this
        # would trade one bad target line for the entire audit.
        for line in ("pkg==1.0;", "pkg==1.0; ", "pkg==1.0 ;"):
            with self.subTest(line=line):
                kept, dropped = sanitize(line + "\n")
                self.assertEqual(kept, [])
                self.assertEqual(only(dropped)["reason"], "unparseable")

    # Fix round 2, F1: the `\S` M6 used to force a NON-EMPTY marker also let one
    # ARBITRARY character through -- the regex read "marker charset, then any
    # one character, then marker charset". Every one of these raises
    # InvalidRequirement in packaging, so each is one line away from aborting
    # the whole audit: verbatim the class M6 exists to close, reopened by its
    # own fix. The first is a REGRESSION -- round 0 dropped it.
    SMUGGLED_MARKERS = [
        'pkg==1.0; python_version<"3" or "a" @ "b"',
        "pkg==1.0;@",
        "pkg==1.0; @",
        "pkg==1.0;a#b",
        "pkg==1.0;a:b",
        "pkg==1.0;\x00",
        'pkg==1.0; extra == "x" @',
    ]

    def test_one_arbitrary_character_cannot_ride_into_the_marker(self):
        for line in self.SMUGGLED_MARKERS:
            with self.subTest(line=line):
                kept, dropped = sanitize(line + "\n")
                self.assertEqual(kept, [])
                self.assertEqual(only(dropped)["reason"], "unparseable")

    def test_the_marker_charset_invariant_holds(self):
        # The comment on `_MARKER_CHARS` promises `@`, `/`, `\`, `:` and `#`
        # cannot appear in a marker. Assert the promise, not just the examples.
        for ch in "@/\\:#$`|&":
            with self.subTest(ch=ch):
                self.assertIsNone(pa._MARKER_OK.match('a == "x" ' + ch))

    def test_a_real_marker_is_still_kept(self):
        kept, _dropped = sanitize(
            'pkg==1.0 ; python_version < "3.12"\n')
        self.assertEqual(kept, ['pkg==1.0 ; python_version < "3.12"'])


class TestIncludeResolutionUsesTheRawLine(unittest.TestCase):
    """M7: include resolution must not depend on the redactor's pattern set.

    `dropped[].line` is MASKED before publication. Re-parsing that masked copy
    to find the include target keys path resolution off a lossy string -- the
    failure mode is closed today (a mangled path becomes `include unreadable`),
    but it makes the redactor's patterns load-bearing for confinement, which
    they must never be.
    """

    def test_an_include_whose_path_the_redactor_rewrites_is_still_followed(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        # A filename carrying a shape `redact.redact` masks (a bare UUID).
        name = "reqs-123e4567-e89b-12d3-a456-426614174000.txt"
        with open(os.path.join(d, name), "w", encoding="utf-8") as fh:
            fh.write("base==2\n")
        with open(os.path.join(d, "requirements.txt"), "w", encoding="utf-8") as fh:
            fh.write("-r %s\ntop==1\n" % name)
        report = sanitize_file(
            os.path.join(d, "requirements.txt"), d)
        self.assertEqual(report["kept"], ["base==2", "top==1"])
        self.assertEqual(report["dropped"], [])

    def test_what_is_published_is_still_masked(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        with open(os.path.join(d, "requirements.txt"), "w", encoding="utf-8") as fh:
            fh.write("-r /etc/hosts-123e4567-e89b-12d3-a456-426614174000.txt\n")
        report = sanitize_file(
            os.path.join(d, "requirements.txt"), d)
        entry = only(report["dropped"])
        self.assertEqual(entry["reason"], "include outside target")
        self.assertNotIn("123e4567-e89b-12d3-a456-426614174000", entry["line"])


class TestTheRootFileIsConfinedToo(unittest.TestCase):
    """C2(a): `_within` guarded every `-r`/`-c` include but not the file the
    follower STARTS from.

    `os.path.isfile` follows symlinks, so a repo whose `requirements.txt` is a
    symlink to an arbitrary host path was opened and read -- and on this branch
    every line that does not parse is copied into `dropped[]`, which reaches
    `tools-manifest.json` and `report.json`. Line-by-line publication also
    defeats the one redaction rule that would have caught a private key: the
    multiline PEM pattern never fires on one base64 line at a time. That is a
    host-file exfiltration channel into an artifact operators copy into CI, and
    it runs ON THE HOST, outside the container, because `sanitization_report`
    is called in-process so the disclosure survives the docker-absent path.
    """

    def _repo_with_symlinked_requirements(self, host_contents):
        outside = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, outside, ignore_errors=True)
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        host_file = os.path.join(outside, "credentials")
        with open(host_file, "w", encoding="utf-8") as fh:
            fh.write(host_contents)
        os.symlink(host_file, os.path.join(d, "requirements.txt"))
        return d

    def test_a_symlinked_root_manifest_is_treated_as_absent(self):
        d = self._repo_with_symlinked_requirements("host-only-marker = 1\n")
        self.assertIsNone(pa.PipAuditAdapter()._find_requirement(d))

    def test_its_contents_are_never_published(self):
        d = self._repo_with_symlinked_requirements(
            "aws_secret_access_key = wJalrXUtnFEMIsecretvalue\nhostname=internal.corp\n")
        report = pa.PipAuditAdapter().sanitization_report(d)
        blob = json.dumps(report)
        self.assertNotIn("wJalrXUtnFEMIsecretvalue", blob)
        self.assertNotIn("internal.corp", blob)

    def test_the_source_says_why_the_pyproject_branch_ran(self):
        d = self._repo_with_symlinked_requirements("junk\n")
        with open(os.path.join(d, "pyproject.toml"), "w", encoding="utf-8") as fh:
            fh.write('[project]\nname = "x"\ndependencies = ["ok==1"]\n')
        report = pa.PipAuditAdapter().sanitization_report(d)
        self.assertIn("pyproject.toml", report["source"])
        self.assertIn("outside target", report["source"])
        self.assertEqual(report["kept"], 1)

    def test_the_rejection_is_disclosed_even_with_no_fallback(self):
        d = self._repo_with_symlinked_requirements("junk\n")
        report = pa.PipAuditAdapter().sanitization_report(d)
        self.assertIn("outside target", report["source"])
        self.assertEqual(report["kept"], 0)

    def test_a_confined_sibling_is_audited_when_the_canonical_one_escapes(self):
        d = self._repo_with_symlinked_requirements("junk\n")
        with open(os.path.join(d, "requirements-dev.txt"), "w", encoding="utf-8") as fh:
            fh.write("dev==1\n")
        self.assertEqual(pa.PipAuditAdapter()._find_requirement(d),
                         os.path.join(d, "requirements-dev.txt"))

    def test_invoke_never_reads_the_escaping_file(self):
        d = self._repo_with_symlinked_requirements("secretline\n")
        with open(os.path.join(d, "pyproject.toml"), "w", encoding="utf-8") as fh:
            fh.write('[project]\nname = "x"\ndependencies = ["ok==1"]\n')
        seen = {}

        def fake_run_tool(cmd, timeout=0, **kw):
            with open(cmd[cmd.index("--requirement") + 1], encoding="utf-8") as fh:
                seen["content"] = fh.read()
            return b"{}", 0
        with mock.patch.object(pa, "run_tool", fake_run_tool), \
                contextlib.redirect_stderr(io.StringIO()):
            pa.PipAuditAdapter().invoke(d)
        self.assertEqual(seen["content"], "ok==1\n")
        self.assertNotIn("secretline", seen["content"])


class TestPublishedLinesAreBounded(unittest.TestCase):
    """C2(b)/(c) and I1: `dropped` is target-authored text on its way into two
    published artifacts, and every sibling path in this module is bounded
    (`MAX_TOOL_OUTPUT_BYTES`, the PEM 16 KiB bound). This one was not."""

    def _target(self, text):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        with open(os.path.join(d, "requirements.txt"), "w", encoding="utf-8") as fh:
            fh.write(text)
        return d

    def test_a_secret_on_a_dropped_line_is_published_redacted(self):
        _kept, dropped = sanitize(
            "--index-url https://%s@evil\n" % fake_aws_key())
        entry = only(dropped)
        self.assertNotIn(fake_aws_key(), entry["line"])
        self.assertIn("[REDACTED_AWS_KEY]", entry["line"])

    def test_a_long_dropped_line_is_truncated_with_a_marker(self):
        _kept, dropped = sanitize("!" * 5000 + "\n")
        line = only(dropped)["line"]
        self.assertEqual(len(line), pa._MAX_PUBLISHED_CHARS + 1)
        self.assertTrue(line.endswith("\u2026"))

    def test_a_short_dropped_line_is_untouched(self):
        _kept, dropped = sanitize("-e .\n")
        self.assertEqual(only(dropped)["line"], "-e .")

    def test_dropped_rows_are_capped_and_the_remainder_counted(self):
        report = pa.PipAuditAdapter().sanitization_report(
            self._target("".join("junk line %d !!\n" % n for n in range(500))))
        self.assertEqual(len(report["dropped"]), pa._MAX_DROPPED_ROWS)
        self.assertEqual(report["dropped_truncated"],
                         500 - pa._MAX_DROPPED_ROWS)

    def test_an_uncapped_file_reports_no_remainder(self):
        report = pa.PipAuditAdapter().sanitization_report(self._target("-e .\n"))
        self.assertEqual(report["dropped_truncated"], 0)
        self.assertFalse(report["truncated"])

    def test_a_ten_megabyte_single_line_is_truncated_not_read_whole(self):
        report = pa.PipAuditAdapter().sanitization_report(
            self._target("x" * (10 * 1024 * 1024)))
        self.assertTrue(report["truncated"])
        self.assertLessEqual(
            sum(len(r["line"]) for r in report["dropped"]),
            pa._MAX_DROPPED_ROWS * (pa._MAX_PUBLISHED_CHARS + 1))

    def test_a_file_with_too_many_lines_is_truncated(self):
        report = pa.PipAuditAdapter().sanitization_report(
            self._target("ok==1\n" * (pa._MAX_READ_LINES + 10)))
        self.assertTrue(report["truncated"])
        self.assertLessEqual(report["kept"], pa._MAX_READ_LINES)


class TestEverySanitizerCallGoesThroughTheHelper(unittest.TestCase):
    """The drift guard for the cross-check itself (fix round 2, F4).

    The `packaging` re-parse is only as good as the set of lines it sees, and a
    hand-assembled corpus has no mechanism to stay complete: round 1's corpus
    comment claimed "every requirements document any test in this file feeds
    the sanitizer" and the one line the grammar comment explicitly promised to
    reject (`… or "a" @ "b"`) appeared nowhere in the module, so the check ran
    green over a corpus that did not contain the very input that would have
    failed it.

    Routing every call through `sanitize`/`sanitize_file` makes the claim
    STRUCTURAL: a new hostile literal is cross-checked because there is no
    other way to call the sanitizer from here. This test is what keeps that
    true. AST, not grep -- a text scan cannot tell a call from a mention in a
    docstring, and cannot see which function body a call sits in.
    """

    _SANITIZERS = ("sanitize_requirements", "sanitize_requirements_file")
    _HELPERS = ("sanitize", "sanitize_file")
    _MODULE = "pip_audit"

    @staticmethod
    def _dotted(node):
        """`pa` / `scripts.tools.pip_audit` for a Name/Attribute chain, else ''."""
        parts = []
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        if not isinstance(node, ast.Name):
            return ""
        parts.append(node.id)
        return ".".join(reversed(parts))

    def _bindings(self, tree):
        """`(receivers, bare)` DERIVED from the module's own import statements.

        Hard-coding the receiver name is what made round 2's guard recognise
        one of five spellings (F7). `import … pip_audit as pa` binds a
        receiver; `from …pip_audit import sanitize_requirements [as s]` binds a
        bare name; `from scripts.tools import pip_audit` binds a receiver too.
        A plain `import scripts.tools.pip_audit` binds `scripts`, and the call
        is then a dotted chain -- handled by `_dotted` at the call site rather
        than by a binding.
        """
        receivers, bare = set(), set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.rpartition(".")[2] == self._MODULE and alias.asname:
                        receivers.add(alias.asname)
            elif isinstance(node, ast.ImportFrom):
                where = (node.module or "").rpartition(".")[2]
                for alias in node.names:
                    if where == self._MODULE and alias.name in self._SANITIZERS:
                        bare.add(alias.asname or alias.name)
                    elif alias.name == self._MODULE:
                        receivers.add(alias.asname or alias.name)
        # A local bind of a sanitizer to a bare name (`f = pa.sanitize_…`) is
        # another spelling; resolve to a fixed point so a chain of them counts.
        changed = True
        while changed:
            changed = False
            for node in ast.walk(tree):
                if not isinstance(node, ast.Assign) or len(node.targets) != 1:
                    continue
                (target,) = node.targets          # unpack; never index a node
                if not isinstance(target, ast.Name) or target.id in bare:
                    continue
                name, value = target.id, node.value
                if (self._is_sanitizer_attr(value, receivers)
                        or (isinstance(value, ast.Name) and value.id in bare)):
                    bare.add(name)
                    changed = True
        return receivers, bare

    def _is_sanitizer_attr(self, node, receivers):
        """`<module>.sanitize_requirements[_file]`, by any spelling of <module>."""
        if not (isinstance(node, ast.Attribute) and node.attr in self._SANITIZERS):
            return False
        owner = self._dotted(node.value)
        return owner in receivers or owner.rpartition(".")[2] == self._MODULE

    def _offenders(self, source=None, path=None):
        path = path or __file__
        if source is None:
            with open(path, encoding="utf-8") as fh:
                source = fh.read()
        tree = ast.parse(source, path)
        receivers, bare = self._bindings(tree)
        allowed = set()
        for node in tree.body:
            if isinstance(node, ast.FunctionDef) and node.name in self._HELPERS:
                allowed.update(range(node.lineno, (node.end_lineno or node.lineno) + 1))
        out = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            direct = (self._is_sanitizer_attr(func, receivers)
                      or (isinstance(func, ast.Name) and func.id in bare))
            if not direct or node.lineno in allowed:
                continue
            out.append("%s:%d %s" % (os.path.basename(path), node.lineno,
                                     ast.unparse(node)))
        return out

    def test_no_test_calls_the_sanitizer_directly(self):
        self.assertEqual(
            self._offenders(), [],
            "call sanitize()/sanitize_file() instead: a direct call skips the "
            "packaging cross-check, and the kept grammar must be at least as "
            "strict as pip-audit's own parser or one target line aborts the "
            "whole audit:\n  " + "\n  ".join(self._offenders()))

    def test_the_guard_can_actually_fail(self):
        # MUTATION: with no helper recognised, the two calls INSIDE the helpers
        # must be reported -- proof the walk can see a `pa.sanitize_*` call at
        # all, so the green above means "none outside", not "matched nothing".
        with mock.patch.object(type(self), "_HELPERS", ()):
            found = self._offenders()
        self.assertEqual(len(found), 2, found)
        blob = "\n".join(found)
        for name in self._SANITIZERS:
            self.assertIn("pa.%s(" % name, blob)

    # Fix round 3, F7: the guard hard-coded the receiver name `pa`, so it
    # recognised ONE of the five ways this module could call the sanitizer --
    # a completeness claim whose mechanism does not cover the case that
    # matters, which is the round-1 F4 defect reproduced one level up. Each
    # spelling is mutation-proved here rather than assumed.
    _SPELLINGS = {
        "module alias":
            "import scripts.tools.pip_audit as pa\n"
            "pa.sanitize_requirements('x')\n",
        "a different module alias":
            "import scripts.tools.pip_audit as pip_audit\n"
            "pip_audit.sanitize_requirements('x')\n",
        "from-import":
            "from scripts.tools.pip_audit import sanitize_requirements\n"
            "sanitize_requirements('x')\n",
        "renamed from-import":
            "from scripts.tools.pip_audit import sanitize_requirements as s\n"
            "s('x')\n",
        "bound alias":
            "import scripts.tools.pip_audit as pa\n"
            "f = pa.sanitize_requirements\n"
            "f('x')\n",
        "dotted module path":
            "import scripts.tools.pip_audit\n"
            "scripts.tools.pip_audit.sanitize_requirements_file('x', 'y')\n",
        "from-import of the module":
            "from scripts.tools import pip_audit\n"
            "pip_audit.sanitize_requirements_file('x', 'y')\n",
    }

    def test_every_spelling_of_a_direct_call_is_caught(self):
        for label, source in sorted(self._SPELLINGS.items()):
            with self.subTest(spelling=label):
                self.assertTrue(self._offenders(source, "<%s>" % label),
                                "this spelling walks past the guard:\n" + source)

    def test_an_unrelated_call_is_not_flagged(self):
        # The receiver set is DERIVED from the module's own imports, so an
        # unrelated object that happens to expose the same method name is not
        # an offender -- the guard must not become noise nobody can satisfy.
        self.assertEqual(
            self._offenders("import other\nother.sanitize_requirements('x')\n",
                            "<unrelated>"), [])


@unittest.skipUnless(Requirement is not None, "packaging is not importable")
class TestTheParserCrossCheckIsLive(unittest.TestCase):
    """Vacuity guard: the helper's assertion must be able to FAIL."""

    def test_a_line_packaging_rejects_would_fail_the_helper(self):
        with self.assertRaises(Exception):
            _assert_every_kept_line_parses(["pkg==1.0;"])

    def test_a_line_carrying_a_url_would_fail_the_helper(self):
        with self.assertRaises(AssertionError):
            _assert_every_kept_line_parses(["pkg @ https://x/y.whl"])

    def test_ordinary_kept_lines_pass(self):
        _assert_every_kept_line_parses(['pkg==1.0 ; python_version < "3.12"'])


class TestOnlyRealFilesAreCandidates(unittest.TestCase):
    """F5: only the canonical name was `isfile`-checked.

    A directory named `requirements-x.txt` became the chosen candidate; `walk`
    swallowed the `IsADirectoryError` and the manifest said `kept: 0,
    dropped: [], truncated: false` -- which reads as "audited, nothing to
    disclose" rather than "could not read". The confinement loop is the natural
    place for the check.
    """

    def test_a_directory_named_like_a_manifest_is_not_a_candidate(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        os.mkdir(os.path.join(d, "requirements-x.txt"))
        self.assertIsNone(pa.PipAuditAdapter()._find_requirement(d))

    def test_a_dangling_symlink_out_of_the_tree_still_says_outside_target(self):
        # F8: `isfile` ran BEFORE the confinement loop, and `isfile` is false
        # for a symlink whose target does not exist -- so a repo whose
        # `requirements.txt` points at a non-existent host path read as having
        # NO manifest, which is precisely the reading C2(a) promised to make
        # impossible. Nothing to read and nothing to publish, so no security
        # consequence; it is a hole in the disclosure.
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        os.symlink("/nonexistent/outside/credentials",
                   os.path.join(d, "requirements.txt"))
        report = pa.PipAuditAdapter().sanitization_report(d)
        self.assertIsNotNone(report, "the escaping manifest was not disclosed")
        self.assertIn("outside target", report["source"])

    def test_a_dangling_symlink_inside_the_tree_is_just_absent(self):
        # Confined and broken is not an escape: nothing to disclose.
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        os.symlink(os.path.join(d, "gone.txt"), os.path.join(d, "requirements.txt"))
        self.assertIsNone(pa.PipAuditAdapter().sanitization_report(d))

    def test_a_real_sibling_beside_it_still_wins(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        os.mkdir(os.path.join(d, "requirements-a.txt"))
        with open(os.path.join(d, "requirements-b.txt"), "w", encoding="utf-8") as fh:
            fh.write("ok==1\n")
        self.assertEqual(pa.PipAuditAdapter()._find_requirement(d),
                         os.path.join(d, "requirements-b.txt"))


class TestBothBranchesShareOneBound(unittest.TestCase):
    """F2: I1's cap was applied to the requirements branch only.

    `invoke`'s pyproject arm had no bound at all and `sanitization_report`'s
    had a DIFFERENT one -- a character slice with no newline rollback -- plus a
    hard-coded `truncated: False`. Measured on 120,000 dependencies: `invoke`
    wrote all 120,000 into the generated file while the manifest claimed
    `kept: 65536, truncated: false`. Three failures in one place: the "read is
    capped FIRST" guarantee did not hold, `kept` measured nothing, and a
    published field asserted the opposite of what had just happened.
    """

    _N = pa._MAX_READ_LINES + 10000

    def _target(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        deps = ",\n  ".join('"dep%d==1.0"' % n for n in range(self._N))
        with open(os.path.join(d, "pyproject.toml"), "w", encoding="utf-8") as fh:
            fh.write('[project]\nname = "x"\ndependencies = [\n  %s\n]\n' % deps)
        return d

    def test_invoke_writes_at_most_the_bound(self):
        seen = {}

        def fake_run_tool(cmd, timeout=0, **kw):
            with open(cmd[cmd.index("--requirement") + 1], encoding="utf-8") as fh:
                seen["lines"] = fh.read().splitlines()
            return b"{}", 0
        with mock.patch.object(pa, "run_tool", fake_run_tool):
            pa.PipAuditAdapter().invoke(self._target())
        self.assertEqual(len(seen["lines"]), pa._MAX_READ_LINES)

    def test_the_manifest_reports_the_true_kept_and_truncated(self):
        report = pa.PipAuditAdapter().sanitization_report(self._target())
        self.assertEqual(report["kept"], pa._MAX_READ_LINES)
        self.assertTrue(report["truncated"])

    def test_the_two_call_sites_cannot_disagree(self):
        # The generated file and the disclosure are built from ONE bounding
        # helper, so what pip-audit was handed is what the manifest counts.
        target = self._target()
        seen = {}

        def fake_run_tool(cmd, timeout=0, **kw):
            with open(cmd[cmd.index("--requirement") + 1], encoding="utf-8") as fh:
                seen["lines"] = fh.read().splitlines()
            return b"{}", 0
        with mock.patch.object(pa, "run_tool", fake_run_tool):
            pa.PipAuditAdapter().invoke(target)
        self.assertEqual(len(seen["lines"]),
                         pa.PipAuditAdapter().sanitization_report(target)["kept"])

    def test_a_small_pyproject_is_not_reported_as_truncated(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        with open(os.path.join(d, "pyproject.toml"), "w", encoding="utf-8") as fh:
            fh.write('[project]\nname = "x"\ndependencies = ["ok==1"]\n')
        report = pa.PipAuditAdapter().sanitization_report(d)
        self.assertEqual((report["kept"], report["truncated"]), (1, False))

    def test_a_leading_newline_does_not_keep_a_megabyte_of_partial_line(self):
        # F9: the rollback guarded on `cut > 0` to avoid emptying the buffer,
        # so a document whose only newline is byte 0 kept its whole 1 MiB
        # partial tail -- exactly the noise row the rollback exists to prevent,
        # in the one case it declined to handle. Same for no newline at all:
        # neither holds a COMPLETE line, and a partial line is not a
        # requirement.
        for data in (b"\n" + b"z" * (2 * 1024 * 1024), b"z" * (2 * 1024 * 1024)):
            with self.subTest(leading_newline=data.startswith(b"\n")):
                text, truncated = pa._bounded(data)
                self.assertTrue(truncated)
                self.assertEqual(text, "")

    def test_the_byte_bound_rolls_back_to_a_line_break(self):
        # A character slice can cut a dependency mid-string and manufacture a
        # bogus `unparseable` row; `_read_bounded` already rolled back for the
        # requirements branch and both must behave the same.
        text, truncated = pa._bounded("ok==1\n" * 400000)
        self.assertTrue(truncated)
        self.assertFalse(text.endswith("ok=="))
        self.assertEqual(set(text.splitlines()), {"ok==1"})


class TestTheScratchCwdIsRemovedEvenIfSomethingWroteThere(unittest.TestCase):
    """F3: `os.rmdir` in `finally` turned a SUCCESSFUL audit into a lost tool.

    The scratch directory exists precisely to be where stray writes land -- a
    build backend's temp file, pip's legacy in-cwd artifacts -- so "something
    wrote there" is the expected case. `os.rmdir` raised `OSError: Directory
    not empty`, `_run_adapter.main` caught it and returned FAIL_RC, and
    pip-audit landed in the manifest's `missing`: the coverage gate degraded on
    a run whose audit had actually succeeded.
    """

    def test_a_file_written_into_the_scratch_cwd_does_not_fail_the_audit(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        with open(os.path.join(d, "requirements.txt"), "w", encoding="utf-8") as fh:
            fh.write("ok==1\n")
        scratch = {}

        def fake_run_tool(cmd, timeout=0, **kw):
            scratch["path"] = kw["cwd"]
            with open(os.path.join(kw["cwd"], "pip-build-junk"), "w") as fh:
                fh.write("x")
            return b'{"dependencies": []}', 0
        with mock.patch.object(pa, "run_tool", fake_run_tool):
            raw, rc = pa.PipAuditAdapter().invoke(d)
        self.assertEqual(rc, 0)
        self.assertEqual(json.loads(raw), {"dependencies": []})
        self.assertFalse(os.path.exists(scratch["path"]))


if __name__ == "__main__":
    unittest.main()
