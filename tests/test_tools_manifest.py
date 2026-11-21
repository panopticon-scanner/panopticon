"""Behavior tests for the scanner coverage manifest and its published rows."""
import contextlib
import io
import json
import os
import tempfile
import unittest
from unittest import mock

import scripts.run_tools as rt
import scripts.scanner_config as sc
import scripts.tool_capture as tc
import scripts.tools_manifest as tm

from tests.run_tools_test_helpers import _FakeResult


class TestTheOutputReceipt(unittest.TestCase):
    """#2070: only exact captures written by this invocation may be ingested."""

    def test_the_writer_records_exact_basenames_bound_to_the_run(self):
        with tempfile.TemporaryDirectory() as d:
            captures = [os.path.join(d, "semgrep.sarif"),
                        os.path.join(d, "pip-audit.json")]
            for path in captures:
                open(path, "w").close()
            payload = tm.write_manifest(
                os.path.join(d, "manifest.json"), ["semgrep", "pip-audit"],
                captures, run_id="RID")
        self.assertEqual(payload["outputs"], ["pip-audit.json", "semgrep.sarif"])
        self.assertEqual(
            tm.output_receipt(payload, expected_run_id="RID", required=True),
            ("pip-audit.json", "semgrep.sarif"))

    def test_a_same_stem_alternate_suffix_is_not_the_written_capture(self):
        manifest = {"run_id": "RID", "selected": ["semgrep"],
                    "produced": ["semgrep"], "missing": [],
                    "outputs": ["semgrep.json"]}
        with self.assertRaisesRegex(ValueError, "canonical output"):
            tm.output_receipt(manifest, expected_run_id="RID", required=True)

    def test_a_driver_run_requires_the_receipt_and_its_run_id(self):
        base = {"run_id": "RID", "selected": ["semgrep"],
                "produced": ["semgrep"], "missing": []}
        with self.assertRaisesRegex(ValueError, "output receipt"):
            tm.output_receipt(base, expected_run_id="RID", required=True)
        with self.assertRaisesRegex(ValueError, "run_id"):
            tm.output_receipt({**base, "outputs": ["semgrep.sarif"]},
                              expected_run_id="OTHER", required=True)


class TestTheDependencyAuditReceipt(unittest.TestCase):
    """#3269 SCA: applicability, selection and output are three facts."""

    def test_dependency_surfaces_are_reported_by_ecosystem(self):
        with tempfile.TemporaryDirectory() as d:
            for name in ("pyproject.toml", "Cargo.toml", "go.sum", "build.gradle",
                         "package.json", "Gemfile"):
                open(os.path.join(d, name), "w").close()
            self.assertEqual(
                tm.dependency_audit_applicable(d),
                ["go", "java", "javascript", "python", "ruby", "rust"],
            )

    def test_variant_requirements_file_is_still_a_python_surface(self):
        with tempfile.TemporaryDirectory() as d:
            open(os.path.join(d, "requirements-dev.txt"), "w").close()
            self.assertEqual(tm.dependency_audit_applicable(d), ["python"])

    def test_variant_requirements_under_a_glob_metacharacter_path_is_found(self):
        with tempfile.TemporaryDirectory() as root:
            target = os.path.join(root, "repo[a]")
            os.mkdir(target)
            open(os.path.join(target, "requirements-dev.txt"), "w").close()
            self.assertEqual(tm.dependency_audit_applicable(target), ["python"])

    def test_markers_removed_from_osv_still_make_their_ecosystem_applicable(self):
        markers = {
            "pyproject.toml": "python",
            "Cargo.toml": "rust",
            "go.sum": "go",
            "build.gradle": "java",
            "npm-shrinkwrap.json": "javascript",
        }
        for marker, ecosystem in markers.items():
            with self.subTest(marker=marker), tempfile.TemporaryDirectory() as d:
                open(os.path.join(d, marker), "w").close()
                self.assertEqual(tm.dependency_audit_applicable(d), [ecosystem])

    def test_writer_records_only_dedicated_dependency_adapters(self):
        with tempfile.TemporaryDirectory() as d:
            captures = [os.path.join(d, "trivy.sarif"),
                        os.path.join(d, "osv-scanner.json")]
            for path in captures:
                open(path, "w").close()
            payload = tm.write_manifest(
                os.path.join(d, "manifest.json"),
                ["trivy", "osv-scanner", "pip-audit"], captures,
                dependency_applicable=["python"],
            )
        self.assertEqual(payload["dependency_audit"], {
            "applicable": ["python"],
            "selected": ["osv-scanner", "pip-audit"],
            "produced": ["osv-scanner"],
        })
        self.assertNotIn("trivy", payload["dependency_audit"]["selected"])
        self.assertNotIn("trivy", payload["dependency_audit"]["produced"])

    def test_writer_drops_non_producer_ecosystem_values(self):
        with tempfile.TemporaryDirectory() as d:
            payload = tm.write_manifest(
                os.path.join(d, "manifest.json"), ["semgrep"], [],
                dependency_applicable=["python", "unknown", "forged"],
            )
        self.assertEqual(payload["dependency_audit"]["applicable"], ["python"])
        # A caller that measured no reasons writes none: the three-key receipt.
        self.assertEqual({"applicable", "selected", "produced"},
                         set(payload["dependency_audit"]))


def _tree(d, *names):
    for name in names:
        os.makedirs(os.path.dirname(os.path.join(d, name)), exist_ok=True)
        open(os.path.join(d, name), "w").close()
    return d


class TestWhyAnEcosystemWentUnaudited(unittest.TestCase):
    """#3648. A JavaScript tree with `package.json` and no lockfile is applicable and
    no auditor reads it. The report said only "no SCA tool produced output", which
    does not say why; beside an audited `requirements.txt` it said nothing at all."""

    JS = ("javascript not audited: no npm-shrinkwrap.json, package-lock.json, yarn.lock or "
          "pnpm-lock.yaml; npm-audit and osv-scanner need one")

    def _unaudited(self, names, selected=(), online=False):
        with tempfile.TemporaryDirectory() as d:
            return tm.dependency_audit_unaudited(_tree(d, *names), list(selected), online)

    def test_no_file_any_auditor_reads(self):
        for names, ecosystem in ((["package.json"], "javascript"), (["Cargo.toml"], "rust"),
                                 (["Gemfile"], "ruby"), (["go.sum"], "go"),
                                 (["Pipfile"], "python")):
            for online in (False, True):
                with self.subTest(names=names, online=online):
                    self.assertEqual({ecosystem: "no_auditable_file"},
                                     self._unaudited(names, online=online))

    def test_a_selected_auditor_that_reads_it_leaves_no_reason(self):
        for names, selected in ((["package.json", "yarn.lock"], ["osv-scanner"]),
                                (["package.json", "npm-shrinkwrap.json"], ["npm-audit"]),
                                (["Cargo.toml", "Cargo.lock"], ["cargo-audit"]),
                                (["requirements-dev.txt"], ["pip-audit"]),
                                (["go.mod"], ["osv-scanner"])):
            with self.subTest(names=names):
                self.assertEqual({}, self._unaudited(names, selected, online=True))

    def test_a_selected_auditor_reads_only_the_ecosystems_whose_files_are_there(self):
        self.assertEqual({"javascript": "no_auditable_file"},
                         self._unaudited(["requirements.txt", "package.json"], ["osv-scanner"]))
        # npm-audit selected, and its lockfile absent: it is not reading this tree.
        self.assertEqual({"javascript": "not_run"},
                         self._unaudited(["package.json", "yarn.lock"], ["npm-audit"],
                                         online=True))

    def test_an_auditor_that_runs_only_online(self):
        self.assertEqual({"python": "needs_online"}, self._unaudited(["pyproject.toml"]))
        self.assertEqual({"python": "needs_online"}, self._unaudited(["requirements-dev.txt"]))
        # #3699 L2: only when EVERY reader is online-only. osv-scanner reads a
        # requirements.txt offline, so its absence is not for want of --online.
        self.assertEqual({"python": "not_run"}, self._unaudited(["requirements.txt"]))
        self.assertEqual({"javascript": "not_run"},
                         self._unaudited(["package.json", "package-lock.json"]))
        # Online and still not selected: that is not for want of --online.
        self.assertEqual({"python": "not_run"},
                         self._unaudited(["pyproject.toml"], online=True))
        # npm-audit's lockfile is not osv-scanner's: only --online audits a shrinkwrap.
        self.assertEqual({"javascript": "needs_online"},
                         self._unaudited(["package.json", "npm-shrinkwrap.json"]))

    def test_a_file_is_there_and_no_auditor_was_selected_for_it(self):
        # osv-scanner reads package-lock.json offline and was left out of the selection.
        self.assertEqual({"javascript": "not_run"},
                         self._unaudited(["package.json", "package-lock.json"], online=True))
        # dependency-check reads build.gradle, and declines a tree with no resolved jars.
        self.assertEqual({"java": "not_run"}, self._unaudited(["build.gradle"]))

    def test_a_tree_with_no_dependency_surface_has_no_reasons(self):
        self.assertEqual({}, self._unaudited(["app.py"]))

    def test_a_directory_with_a_lockfiles_name_is_no_lockfile(self):
        # #3699 L1. npm-audit and osv-scanner ask for a regular file, so neither would
        # be selected for this tree, online or not: "npm-audit needs --online" would be
        # wrong advice. The reason uses each adapter's own test.
        for online in (False, True):
            with self.subTest(online=online), tempfile.TemporaryDirectory() as d:
                _tree(d, "package.json")
                os.mkdir(os.path.join(d, "package-lock.json"))
                os.mkdir(os.path.join(d, "npm-shrinkwrap.json"))
                self.assertEqual({"javascript": "no_auditable_file"},
                                 tm.dependency_audit_unaudited(d, [], online))
        # cargo-audit's own test is "the path exists", and it is asked the same way.
        with tempfile.TemporaryDirectory() as d:
            _tree(d, "Cargo.toml")
            os.mkdir(os.path.join(d, "Cargo.lock"))
            self.assertEqual({"rust": "not_run"}, tm.dependency_audit_unaudited(d, [], True))
            self.assertEqual({}, tm.dependency_audit_unaudited(d, ["cargo-audit"], True))

    def test_the_file_test_asked_is_the_adapters_own(self):
        from scripts.tools import ADAPTERS
        asked = []

        def never(target, name):
            asked.append(name)
            return False

        with tempfile.TemporaryDirectory() as d, mock.patch.object(
                type(ADAPTERS["npm-audit"]), "has_audit_file", staticmethod(never)):
            _tree(d, "package.json", "npm-shrinkwrap.json")
            self.assertEqual({"javascript": "no_auditable_file"},
                             tm.dependency_audit_unaudited(d, [], False))
        self.assertEqual(["npm-shrinkwrap.json", "package-lock.json"], asked)

    def test_the_auditors_and_their_files_come_from_the_adapters(self):
        from scripts.tools import ADAPTERS
        self.assertEqual({"npm-audit": ("npm-shrinkwrap.json", "package-lock.json"),
                          "osv-scanner": ("package-lock.json", "yarn.lock", "pnpm-lock.yaml")},
                         tm.dependency_auditors("javascript"))
        self.assertEqual({}, tm.dependency_auditors("unknown"))
        for ecosystem in sorted(tm.DEPENDENCY_AUDIT_ECOSYSTEMS - {"unknown"}):
            readers = tm.dependency_auditors(ecosystem)
            self.assertTrue(readers, ecosystem)
            for tool, files in readers.items():
                with self.subTest(ecosystem=ecosystem, tool=tool):
                    self.assertIn(tool, tm.DEPENDENCY_AUDIT_TOOLS)
                    self.assertIs(ADAPTERS[tool].audit_files[ecosystem], files)
        # Every dedicated auditor exports its list, and reads at least one ecosystem.
        for tool in sorted(tm.DEPENDENCY_AUDIT_TOOLS):
            self.assertTrue(ADAPTERS[tool].audit_files, tool)
        # Only a dedicated auditor counts: a pattern scanner that grew a list would
        # not make a `package.json` audited.
        before = tm.dependency_auditors("javascript")
        with mock.patch.object(type(ADAPTERS["semgrep"]), "audit_files",
                               {"javascript": ("package.json",)}, create=True):
            self.assertEqual(before, tm.dependency_auditors("javascript"))

    def test_the_sentences(self):
        sentence = tm.unaudited_sentence
        self.assertEqual(self.JS, sentence("javascript", "no_auditable_file"))
        self.assertEqual("go not audited: no go.mod; osv-scanner needs one",
                         sentence("go", "no_auditable_file"))
        self.assertEqual("python not audited: pip-audit needs --online",
                         sentence("python", "needs_online"))
        self.assertEqual("javascript not audited: npm-audit needs --online",
                         sentence("javascript", "needs_online"))
        self.assertEqual("java not audited: no dependency auditor ran on it",
                         sentence("java", "not_run"))
        # No online-only auditor reads Go: the pair is still named, in the plain words.
        self.assertEqual("go not audited: no dependency auditor ran on it",
                         sentence("go", "needs_online"))
        for ecosystem, reason in (("unknown", "not_run"), ("javascript", "because"),
                                  ("<b>", "not_run"), ("javascript", None), (None, "not_run")):
            with self.subTest(ecosystem=ecosystem, reason=reason):
                self.assertIsNone(sentence(ecosystem, reason))
        self.assertEqual(("no_auditable_file", "needs_online", "not_run"), tm.UNAUDITED_REASONS)

    def test_the_writer_records_reasons_for_listed_ecosystems_in_closed_enums(self):
        with tempfile.TemporaryDirectory() as d:
            payload = tm.write_manifest(
                os.path.join(d, "manifest.json"), ["osv-scanner"], [],
                dependency_applicable=["python", "javascript"],
                dependency_unaudited={"javascript": "no_auditable_file", "rust": "not_run",
                                      "python": "<script>", "unknown": "not_run"})
            self.assertEqual({"applicable": ["javascript", "python"],
                              "selected": ["osv-scanner"], "produced": [],
                              "unaudited": {"javascript": "no_auditable_file"}},
                             payload["dependency_audit"])
            payload = tm.write_manifest(
                os.path.join(d, "manifest.json"), ["osv-scanner"], [],
                dependency_applicable=["python"], dependency_unaudited={})
            self.assertEqual({}, payload["dependency_audit"]["unaudited"])
            # No applicability measured: no receipt, so no reasons either.
            payload = tm.write_manifest(
                os.path.join(d, "manifest.json"), ["osv-scanner"], [],
                dependency_unaudited={"javascript": "not_run"})
            self.assertNotIn("dependency_audit", payload)


class TestTheManifestPublishesItsScopeRows(unittest.TestCase):
    """Six rows the manifest states on EVERY manifest -- the excluded scope, the
    pruned virtualenv rows with their depth bound, the exclude globs and the
    sanitizer disclosure -- each also at its empty value, because absence must
    not be readable as "nobody measured"; they came out of
    `tests/test_run_tools_core.py` with the writer, names and bodies unchanged."""

    def test_manifest_records_excluded_scope(self):
        with tempfile.TemporaryDirectory() as d:
            payload = tm.write_manifest(
                os.path.join(d, "m.json"), ["semgrep"], [],
                excluded_scope=["eslint-security"])
            self.assertEqual(payload["excluded_scope"], ["eslint-security"])
            self.assertNotIn("eslint-security", payload["selected"])

    def test_manifest_records_excluded_dirs_with_reasons(self):
        with tempfile.TemporaryDirectory() as d:
            payload = tm.write_manifest(
                os.path.join(d, "m.json"), ["semgrep"], [],
                excluded_dirs=[{"path": ".venv", "reason": "pyvenv.cfg"},
                               {"path": "venv", "reason": "name"}])
            # #1740: `skipped` defaults to True, the pre-#1740 meaning of
            # this list, for a caller handing `find_virtualenvs` output in.
            self.assertEqual(payload["excluded_dirs"],
                             [{"path": ".venv", "reason": "pyvenv.cfg",
                               "skipped": True},
                              {"path": "venv", "reason": "name",
                               "skipped": True}])
            # F2: the list is what the SCAN was told to skip, found by a
            # depth-bounded walk -- ingest prunes a superset, at any depth.
            self.assertEqual(payload["depth_bound"], tm.VENV_MAX_DEPTH)
            with open(os.path.join(d, "m.json"), encoding="utf-8") as fh:
                self.assertEqual(json.load(fh), payload)

    def test_manifest_records_the_exclude_globs_it_was_given(self):
        # #1740 fix round 1: the committed `exclude_paths:` policy now reaches
        # the scan, so the manifest says which globs this run was handed --
        # beside `excluded_scope` (the adapters those globs disqualified) and
        # `excluded_dirs` (the virtualenvs). Stated on every manifest, `[]`
        # included: absence must not read as "nobody measured".
        with tempfile.TemporaryDirectory() as d:
            payload = tm.write_manifest(os.path.join(d, "m.json"), ["semgrep"], [],
                                        exclude_globs=["tests/fixtures/**"])
            self.assertEqual(payload["exclude_globs"], ["tests/fixtures/**"])
            bare = tm.write_manifest(os.path.join(d, "b.json"), ["semgrep"], [])
            self.assertEqual(bare["exclude_globs"], [])

    def test_manifest_records_what_the_sanitizer_dropped(self):
        # #1646 ruling 3: the audit was PARTIAL and the manifest says so.
        block = {"pip-audit": {"source": "requirements.txt", "kept": 2,
                               "dropped": [{"line": "-e .", "reason": "editable"}],
                               "hashes_stripped": True}}
        with tempfile.TemporaryDirectory() as d:
            payload = tm.write_manifest(os.path.join(d, "m.json"), ["pip-audit"],
                                        [], sanitized=block)
            self.assertEqual(payload["sanitized"], block)
            with open(os.path.join(d, "m.json"), encoding="utf-8") as fh:
                self.assertEqual(json.load(fh)["sanitized"], block)

    def test_manifest_sanitized_defaults_to_empty(self):
        # Stated on every manifest, `{}` included: absence must not be readable
        # as "nobody measured" -- the same rule `excluded_dirs` follows.
        with tempfile.TemporaryDirectory() as d:
            payload = tm.write_manifest(os.path.join(d, "m.json"), ["semgrep"], [])
            self.assertEqual(payload["sanitized"], {})

    def test_manifest_excluded_dirs_defaults_to_empty(self):
        with tempfile.TemporaryDirectory() as d:
            payload = tm.write_manifest(os.path.join(d, "m.json"), ["semgrep"], [])
            self.assertEqual(payload["excluded_dirs"], [])
            self.assertEqual(payload["depth_bound"], tm.VENV_MAX_DEPTH)


class TestTheManifestReportsTheRedactionPass(unittest.TestCase):
    """#1639 P11 fix round 1 (F5): `tools-ran.json`'s `redacted` claim used to
    be a literal in the phase module asserting another module's behaviour. The
    runner reports what it actually did -- `tool_capture._redact_capture`
    records each capture it passes, `write_manifest` publishes it, and the phase
    copies the answer instead of restating it."""

    TOKEN = "ghp_" + "MANIFEST" + "M" * 28

    def _run(self, d, patch_identity=False):
        payload = json.dumps({"runs": [{"results": [
            {"ruleId": "r", "message": {"text": self.TOKEN}}]}]}).encode()

        def runner(cmd, **kw):
            return _FakeResult(returncode=0, stdout=payload)

        out_dir = os.path.join(d, "tools")
        ctx = (mock.patch.object(tc, "_redact_capture", lambda tool, data: data)
               if patch_identity else contextlib.nullcontext())
        with contextlib.redirect_stderr(io.StringIO()), ctx:
            written = rt.run_tools(d, ["gitleaks", "semgrep"], out_dir, runner=runner)
        return tm.write_manifest(os.path.join(d, "tools-manifest.json"),
                                 ["gitleaks", "semgrep"], written)

    def test_a_run_through_the_choke_point_claims_the_pass(self):
        with tempfile.TemporaryDirectory() as d:
            payload = self._run(d)
        self.assertEqual(payload["produced"], ["gitleaks", "semgrep"])
        self.assertIs(payload["redacted"], True)

    def test_bypassing_the_choke_point_makes_the_claim_go_false(self):
        """The coupling: with the redactor replaced by identity the captures are
        written unmasked, and the artifact says so rather than repeating a
        literal `true` nobody checked."""
        with tempfile.TemporaryDirectory() as d:
            payload = self._run(d, patch_identity=True)
            with open(os.path.join(d, "tools", "gitleaks.sarif"), "rb") as fh:
                self.assertIn(self.TOKEN.encode(), fh.read())   # non-vacuous
        self.assertEqual(payload["produced"], ["gitleaks", "semgrep"])
        self.assertIs(payload["redacted"], False)

    def test_no_capture_written_makes_no_claim(self):
        # The docker-absent manifest (produced=[]): nothing was written, so
        # there is nothing to vouch for.
        with tempfile.TemporaryDirectory() as d:
            payload = tm.write_manifest(os.path.join(d, "m.json"),
                                        ["gitleaks"], [])
        self.assertIs(payload["redacted"], False)


class TestTheManifestPublishesTheSuppressionPosture(unittest.TestCase):
    """#1839 (run-14 SEC-284952751): under `standard` an inline suppression
    comment in the target's own source is HONOURED -- an operator's reviewed,
    in-diff decision about their own repository -- and that is a coverage fact a
    reader of the artifacts is entitled to. So it is honoured DISCLOSED, not
    silently: `tools-manifest.json` carries one row per assessed tool.

    Like `network` and `redacted`, the claim is an OBSERVATION of what decided
    it: the argv the runner built for a flag-lever tool (bandit, gitleaks), so
    it cannot outlive the flag; the run's mode for an ingest-lever tool
    (semgrep, `SUPPRESSION_INGEST_LEVER`), where no flag decides and the mode
    is the fact.
    """

    TOOLS = ["semgrep", "bandit", "trivy", "gitleaks", "gosec"]

    def _manifest(self, d, tools=None, **kwargs):
        def runner(cmd, **kw):
            return _FakeResult(returncode=0, stdout=b'{"runs":[]}')
        tools = list(self.TOOLS if tools is None else tools)
        with contextlib.redirect_stderr(io.StringIO()):
            written = rt.run_tools(d, tools, os.path.join(d, "tools"),
                                   runner=runner, venv_dirs=[], **kwargs)
        return tm.write_manifest(os.path.join(d, "tools-manifest.json"),
                                 tools, written)

    def test_standard_says_the_comments_stood(self):
        with tempfile.TemporaryDirectory() as d:
            payload = self._manifest(d, security_mode="standard")
        self.assertEqual(payload["suppression_comments"],
                         {"semgrep": "honoured", "bandit": "honoured",
                          "gitleaks": "honoured", "gosec": "honoured",
                          "trivy": "n/a"})

    def test_redteam_says_they_were_ignored(self):
        with tempfile.TemporaryDirectory() as d:
            payload = self._manifest(d, security_mode="redteam")
        self.assertEqual(payload["suppression_comments"],
                         {"semgrep": "ignored", "bandit": "ignored",
                          "gitleaks": "ignored",
                          # No knob verified at the pin: the residual is
                          # disclosed in BOTH modes rather than invented.
                          "gosec": "honoured",
                          "trivy": "n/a"})

    def test_an_unassessed_tool_gets_no_row(self):
        # Absent is not `n/a`: "nobody looked" and "there is nothing to look
        # at" are different claims, and the tool axis has been burned by
        # reading one as the other (#1839's own `excluded_dirs` note).
        with tempfile.TemporaryDirectory() as d:
            payload = self._manifest(d, tools=["brakeman"])
        self.assertNotIn("brakeman", payload["suppression_comments"])
        self.assertNotIn("brakeman", sc.SUPPRESSION_COMMENTS)

    def test_the_claim_follows_the_argv_and_not_the_intent(self):
        # The coupling, the same way the redaction claim is coupled -- for a
        # tool whose ARGV is the lever. With bandit's knob taken out of the
        # table the redteam argv carries no `--ignore-nosec`, bandit really does
        # honour a `# nosec`, and the manifest says `honoured` instead of
        # repeating the mode back.
        table = dict(sc.SUPPRESSION_COMMENTS)
        table["bandit"] = ("# nosec", None)
        with tempfile.TemporaryDirectory() as d, \
                mock.patch.object(sc, "SUPPRESSION_COMMENTS", table):
            payload = self._manifest(d, tools=["bandit"],
                                     security_mode="redteam")
        self.assertEqual(payload["suppression_comments"],
                         {"bandit": "honoured"})

    def test_an_ingest_lever_tools_row_follows_the_mode_not_the_flag(self):
        # Re-review finding 3. semgrep's `--disable-nosem` is BELT at the pin:
        # the scanner marks and reports a `# nosemgrep`'d result either way, and
        # `sarif_utils.sarif_to_findings` is what honours the comment (under
        # `standard`) or ignores it (under `redteam`). So reading semgrep's row
        # off the argv publishes a FALSE COVERAGE CLAIM the moment the belt comes
        # off: `honoured` on a redteam run whose ingest ignores every such
        # comment. The row follows what actually governs -- the mode.
        table = dict(sc.SUPPRESSION_COMMENTS)
        table["semgrep"] = ("# nosemgrep", None)   # the belt taken off
        for mode, expected in (("redteam", "ignored"), ("standard", "honoured")):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as d, \
                    mock.patch.object(sc, "SUPPRESSION_COMMENTS", table):
                payload = self._manifest(d, tools=["semgrep"],
                                         security_mode=mode)
            self.assertEqual(payload["suppression_comments"],
                             {"semgrep": expected})

    def test_the_belt_is_still_on_the_real_redteam_argv(self):
        # The test above patches the flag away, so this one pins that the
        # unpatched redteam launch still carries it -- the belt is documented,
        # and a later semgrep may act on it.
        calls = []

        def runner(cmd, **kw):
            calls.append(list(cmd))
            return _FakeResult(returncode=0, stdout=b'{"runs":[]}')
        with tempfile.TemporaryDirectory() as d, \
                contextlib.redirect_stderr(io.StringIO()):
            rt.run_tools(d, ["semgrep"], os.path.join(d, "tools"),
                         runner=runner, venv_dirs=[], security_mode="redteam")
        self.assertIn("--disable-nosem", calls[0])

    def test_the_ledger_is_this_runs_and_not_the_last_one(self):
        with tempfile.TemporaryDirectory() as d:
            self._manifest(d, tools=["semgrep"], security_mode="redteam")
            payload = self._manifest(d, tools=["bandit"],
                                     security_mode="standard")
        self.assertEqual(payload["suppression_comments"],
                         {"bandit": "honoured"})

    def test_a_scan_that_never_ran_claims_nothing(self):
        # The docker-absent manifest: no tool was launched, so there is no
        # observation to publish.
        with tempfile.TemporaryDirectory() as d:
            payload = tm.write_manifest(os.path.join(d, "m.json"),
                                        ["semgrep"], [],
                                        suppression_comments={})
        self.assertEqual(payload["suppression_comments"], {})

    def test_explicit_ignore_file_observation_is_filtered_to_produced_gitleaks(self):
        with tempfile.TemporaryDirectory() as d:
            capture = os.path.join(d, "gitleaks.sarif")
            with open(capture, "wb") as fh:
                fh.write(b'{"runs":[]}')
            payload = tm.write_manifest(os.path.join(d, "m.json"),
                                        ["gitleaks", "semgrep"], [capture],
                                        ignore_files={"gitleaks": "neutralised",
                                                      "semgrep": "honoured"})
            missing = tm.write_manifest(os.path.join(d, "n.json"),
                                        ["gitleaks"], [],
                                        ignore_files={"gitleaks": "neutralised"})
        self.assertEqual(payload["ignore_files"], {"gitleaks": "neutralised"})
        self.assertEqual(missing["ignore_files"], {})

    def test_unknown_ignore_file_observation_cannot_invalidate_manifest(self):
        with tempfile.TemporaryDirectory() as d:
            capture = os.path.join(d, "gitleaks.sarif")
            with open(capture, "wb") as fh:
                fh.write(b'{"runs":[]}')
            for value in (None, 3, [], {}, "unexpected"):
                with self.subTest(value=value):
                    payload = tm.write_manifest(os.path.join(d, "m.json"),
                                                ["gitleaks"], [capture],
                                                ignore_files={"gitleaks": value})
                    self.assertEqual(payload["ignore_files"], {})


class TestContainerCleanupManifest(unittest.TestCase):
    def test_a_capture_cleanup_failure_is_structured_in_the_manifest(self):
        failure = {
            "semgrep": {
                "kind": "kill_failed",
                "detail": "docker kill exited 125 — daemon unavailable",
            }
        }
        with tempfile.TemporaryDirectory() as d, \
                mock.patch.dict(tc._CONTAINER_CLEANUP_FAILURES, failure, clear=True):
            payload = tm.write_manifest(
                os.path.join(d, "tools-manifest.json"), ["semgrep"], [])
            with open(os.path.join(d, "tools-manifest.json"),
                      encoding="utf-8") as stream:
                written = json.load(stream)
        self.assertEqual(payload["cleanup_failures"], failure)
        self.assertEqual(written["cleanup_failures"], failure)

    def test_no_cleanup_failure_adds_no_legacy_manifest_claim(self):
        with tempfile.TemporaryDirectory() as d, \
                mock.patch.dict(tc._CONTAINER_CLEANUP_FAILURES, {}, clear=True):
            payload = tm.write_manifest(
                os.path.join(d, "tools-manifest.json"), ["semgrep"], [])
        self.assertNotIn("cleanup_failures", payload)


class TestLanguageDetectionSkipManifest(unittest.TestCase):
    REASON = "present only under pruned directories"
    PYTHON = {"language": "python", "tool": "bandit", "reason": REASON}

    def test_legacy_absence_and_measured_clean_remain_distinct(self):
        with tempfile.TemporaryDirectory() as d:
            absent = tm.write_manifest(os.path.join(d, "absent.json"), [], [])
            clean = tm.write_manifest(os.path.join(d, "clean.json"), [], [],
                                      language_detection_skips=[])
        self.assertNotIn("language_detection_skips", absent)
        self.assertEqual(clean["language_detection_skips"], [])

    def test_the_writer_asserts_the_controlled_rows_and_runtime_cap(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(AssertionError):
                tm.write_manifest(
                    os.path.join(d, "pair.json"), [], [],
                    language_detection_skips=[{
                        "language": "python", "tool": "gosec",
                        "reason": self.REASON,
                    }])
            with self.assertRaises(AssertionError):
                tm.write_manifest(
                    os.path.join(d, "cap.json"), [], [],
                    language_detection_skips=[self.PYTHON] *
                    (tm.LANGUAGE_DETECTION_SKIPS_MAX + 1))


class TestTheEslintCoverageReadIsDepthBounded(unittest.TestCase):
    def test_a_too_deep_eslint_capture_measures_no_file_coverage(self):
        """#2959: the coverage read kept a RecursionError out of nothing; past the bound it is the
        unreadable capture it already tolerated (ingestion owns the failure)."""
        with tempfile.TemporaryDirectory() as root:
            capture = os.path.join(root, "eslint-security.json")
            with open(capture, "w") as stream:
                stream.write("[" * 100_000 + "]" * 100_000)
            path = os.path.join(root, "tools-manifest.json")
            tm.write_manifest(path, ["eslint-security"], [capture])
            with open(path, encoding="utf-8") as stream:
                self.assertNotIn("eslint-security", json.load(stream)["file_coverage"])


if __name__ == "__main__":
    unittest.main()
