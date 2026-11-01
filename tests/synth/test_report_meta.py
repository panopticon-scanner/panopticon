"""#3368: each report field says what it claims, read from a ledger the real `Ledger` wrote and from
findings the real loader read, and filling a category in moves nothing that reads one."""
import contextlib
import copy
import hashlib
import io
import json
import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock

import scripts.citations as citations
import scripts.evidence as evidence_mod
import scripts.file_issues as file_issues
import scripts.ledger as ledger_mod
import scripts.ocrdb as ocrdb
import scripts.phases.review as review_phase
import scripts.phases.verify as verify_phase
import scripts.phases.verify_tools as verify_tools
import scripts.reconcile as reconcile
import scripts.runners.base as runners_base
import scripts.synth.cost as cost_mod
import scripts.synth.findings as findings_mod
import scripts.synth.report as report_mod
import scripts.synthesize as syn
from tests.synth.helpers import DEFAULT_TIMESTAMP, _chdir

CODED = "SEC-A3A"                 # the catalog's `sql-injection`, which also names a CWE to derive


def _agent_finding(**extra):
    return dict({"domain": "SEC", "code": CODED, "severity": "HIGH", "title": "Query built by hand",
                 "description": "d", "source_role": "domain_panel",
                 "location": {"file": "a.py", "line_start": 1}}, **extra)


class _Case(unittest.TestCase):
    def setUp(self):
        self.dir = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir, True)
        # These tests run from a temporary cwd (tests/synth's autouse fixture), and `file_issues`
        # caches the repo root it detects from the cwd. Detected here, that cache told every later
        # test in the worker the checkout was a temp dir, so it is put back after each test.
        sanitize = sys.modules[file_issues.repo_root.__module__]
        patch = mock.patch.object(sanitize, "_REPO_ROOT_CACHE", sanitize._REPO_ROOT_CACHE)
        patch.start()
        self.addCleanup(patch.stop)

    def _load(self, *findings):
        """Through the real loader and its strip list, as an agent's file reaches a report."""
        path = os.path.join(self.dir, "findings-app-SEC.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({"findings": list(findings)}, fh)
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            loaded = findings_mod.load_findings([path])
        self.stderr = err.getvalue()
        return loaded

    def _report(self, findings, cost=None):
        return report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="t", fail_on="high", timestamp=DEFAULT_TIMESTAMP),
            findings=findings_mod.FindingSet(findings=copy.deepcopy(findings)),
            cost=cost or cost_mod.CostInputs()))

    def _ledger(self, *rows):
        ledger = ledger_mod.Ledger(self.dir)
        for entry_id, checkpoint, model in rows:
            ledger.record({"id": entry_id}, checkpoint, runners_base.RunResult(
                entry_id=entry_id, ok=True, text="", usage={}, cost_usd=None, model=model,
                session_id=None, denials=[], error=None), "headless", "claude")

    def _cost(self, driver_cost=None):
        loaded = cost_mod.CostInputs.load(self.dir, self.dir, 0)
        return cost_mod.CostInputs(driver_cost=driver_cost or loaded.driver_cost,
                                   run_usage=loaded.run_usage, ledger_models=loaded.ledger_models)


class ModelsFromTheLedgerTest(_Case):
    DRIVER = {"review_cells": 1, "verify_primary": 1, "verify_backup": 1, "verify_tools": 1,
              "tool_scan": 1}

    def _rows(self, report):
        return {row["role"]: row["model"] for row in report["meta"]["cost"]["dispatches"]}

    def test_every_role_reports_the_model_its_entries_ran(self):
        self._ledger(("scout-my-group", "scout", "s"), ("review-my-group-SEC", "review", "r"),
                     ("verify-my-group-SEC-primary", "verify", "p"),
                     ("verify-my-group-SEC-backup-part2", "verify", "b"),
                     ("verify-tool-abc", "verify", "t"))
        report = self._report(self._load(_agent_finding()), self._cost(self.DRIVER))
        self.assertEqual({"scout": "s", "domain_panel": "r", "domain_advisor": "p",
                          "domain_advisor_backup": "b", "tool_advisor": "t", "scan": None},
                         self._rows(report))
        self.assertEqual([{"model": "s", "role": "scout"}, {"model": "r", "role": "domain_panel"},
                          {"model": "p", "role": "domain_advisor"},
                          {"model": "b", "role": "domain_advisor_backup"},
                          {"model": "t", "role": "tool_advisor"}], report["meta"]["models_used"])

    def test_the_role_reader_agrees_with_the_id_builders(self):
        self.assertEqual("verify-tool-", verify_tools.TOOL_ENTRY_PREFIX)
        for source in (review_phase, verify_phase):
            with open(source.__file__, encoding="utf-8") as fh:
                self.assertRegex(fh.read(), r'entry_id = "(review|verify)-%s-%s')

    def test_a_role_that_ran_two_models_is_null_and_models_used_names_both(self):
        self._ledger(("review-g-SEC", "review", "one"), ("review-g-COD", "review", "two"),
                     ("review-g-DAT", "review", "one"))
        report = self._report([], self._cost(self.DRIVER))
        self.assertIsNone(self._rows(report)["domain_panel"])
        self.assertEqual([{"model": "one", "role": "domain_panel"},
                          {"model": "two", "role": "domain_panel"}], report["meta"]["models_used"])

    def test_a_row_with_no_model_says_nothing(self):
        self._ledger(("review-g-SEC", "review", None))
        report = self._report([], self._cost(self.DRIVER))
        self.assertIsNone(self._rows(report)["domain_panel"])
        self.assertEqual([], report["meta"]["models_used"])

    def test_an_id_naming_no_role_is_published_as_unknown_and_fills_no_row(self):
        self._ledger(("mystery-primary", "review", "m"))
        report = self._report([], self._cost(self.DRIVER))
        self.assertEqual([{"model": "m", "role": cost_mod.UNKNOWN_ROLE}],
                         report["meta"]["models_used"])
        self.assertEqual({None}, set(self._rows(report).values()))

    def test_lines_that_cannot_be_read_are_skipped_and_good_ones_kept(self):
        with open(os.path.join(self.dir, runners_base.LEDGER_FILE), "wb") as fh:
            fh.write(b'not json\n[1]\n{"entry_id": "review-g-SEC", "model": 7}\n\xff\xfe\n'
                     + b"[" * 100000 + b"\n"
                     + b'{"entry_id": "review-g-SEC", "model": "real"}\n')
        self.assertEqual((("domain_panel", "real"),), cost_mod.load_ledger_models(self.dir))

    def test_a_model_name_is_made_inert_and_bounded(self):
        self._ledger(("review-g-SEC", "review", "evil\x1b[2Jname" + "x" * 500))
        ((role, name),) = cost_mod.load_ledger_models(self.dir)
        self.assertEqual("domain_panel", role)
        self.assertNotIn("\x1b", name)
        self.assertLess(len(name), 210)         # the cap, and the mark that says it was cut

    def test_an_unreadable_ledger_is_said_and_reads_as_none(self):
        os.mkdir(os.path.join(self.dir, runners_base.LEDGER_FILE))
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual((), cost_mod.load_ledger_models(self.dir))
        self.assertIn("could not be read", err.getvalue())

    def test_a_symlinked_ledger_is_not_followed(self):
        real = os.path.join(self.dir, "elsewhere.jsonl")
        with open(real, "w", encoding="utf-8") as fh:
            fh.write('{"entry_id": "review-g-SEC", "model": "planted"}\n')
        os.symlink(real, os.path.join(self.dir, runners_base.LEDGER_FILE))
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual((), cost_mod.load_ledger_models(self.dir))

    def test_no_run_dir_reads_as_none(self):
        self.assertEqual((), cost_mod.load_ledger_models(None))


class SessionModeTest(_Case):
    """No ledger rows. What was REQUESTED is on the plan, and must not be what the report says ran."""

    def _plan_requesting_a_model(self):
        with open(os.path.join(self.dir, "dispatch-plan-driver.json"), "w", encoding="utf-8") as fh:
            json.dump([{"group": "g", "domain": "SEC", "model": "requested-only",
                        "out_file": "x.json"}], fh)

    def _usage(self, document):
        with open(os.path.join(self.dir, "usage.json"), "w", encoding="utf-8") as fh:
            json.dump(document, fh)

    def test_with_nothing_measured_both_fields_stay_empty(self):
        self._plan_requesting_a_model()
        report = self._report([], self._cost())
        self.assertEqual([], report["meta"]["models_used"])
        self.assertEqual({None}, {row["model"] for row in report["meta"]["cost"]["dispatches"]})
        self.assertNotIn("requested-only", json.dumps(report["meta"]["models_used"]))

    def test_names_a_host_measured_are_listed_with_no_role_and_fill_no_row(self):
        self._plan_requesting_a_model()
        self._usage({"total": 1, "by_model": {"b-model": 3, "a-model": 9}})
        report = self._report([], self._cost())
        self.assertEqual([{"model": "a-model", "role": cost_mod.UNKNOWN_ROLE},
                          {"model": "b-model", "role": cost_mod.UNKNOWN_ROLE}],
                         report["meta"]["models_used"])
        self.assertEqual({None}, {row["model"] for row in report["meta"]["cost"]["dispatches"]})

    def test_the_ledger_wins_over_usage_when_it_has_rows(self):
        self._usage({"total": 1, "by_model": {"from-usage": 3}})
        self._ledger(("review-g-SEC", "review", "from-ledger"))
        self.assertEqual([{"model": "from-ledger", "role": "domain_panel"}],
                         self._report([], self._cost())["meta"]["models_used"])

    def test_a_by_model_of_the_wrong_shape_lists_nothing(self):
        self._usage({"total": 1, "by_model": ["a"]})
        self.assertEqual([], self._report([], self._cost())["meta"]["models_used"])

    def test_a_usage_name_is_made_inert(self):
        self._usage({"total": 1, "by_model": {"evil\x1b[2J": 1}})
        (entry,) = self._report([], self._cost())["meta"]["models_used"]
        self.assertNotIn("\x1b", entry["model"])


class SelfAssertedModelTest(_Case):
    def test_a_name_an_agent_wrote_about_itself_reaches_no_part_of_the_report(self):
        loaded = self._load(_agent_finding(provenance={
            "model": "self-asserted", "model_version": "self-asserted", "discovered_by": "agent:x"}))
        self.assertIn("stripped self-asserted provenance.model ", self.stderr)
        self.assertIn("stripped self-asserted provenance.model_version ", self.stderr)
        self.assertEqual({"discovered_by": "agent:x"}, loaded[0]["provenance"])
        report = self._report(loaded)
        self.assertNotIn("self-asserted", json.dumps(report))
        self.assertEqual([], report["meta"]["models_used"])

    def test_models_used_does_not_read_a_finding_even_if_one_arrives_carrying_it(self):
        finding = self._load(_agent_finding())[0]
        finding["provenance"] = {"model": "self-asserted", "discovered_by": "agent:x"}
        self.assertEqual([], self._report([finding])["meta"]["models_used"])

    def test_a_filed_issue_does_not_print_one_from_an_older_report(self):
        body = file_issues.body_for(dict(self._report(self._load(_agent_finding()))["findings"][0],
                                            provenance={"model": "self-asserted",
                                                        "discovered_by": "agent:x"}))
        self.assertIn("**Found by:** agent:x", body)
        self.assertNotIn("self-asserted", body)


class TopIssuesTest(_Case):
    def test_the_display_is_bounded_and_the_stored_title_is_not(self):
        title = "T" * 400
        report = self._report(self._load(_agent_finding(title=title)))
        (shown,) = report["summary"]["top_issues"]
        self.assertLessEqual(len(shown), findings_mod.SHORT_TITLE_MAX)
        self.assertTrue(shown.endswith("…"))
        self.assertEqual(title, report["findings"][0]["title"])

    def test_a_short_title_is_shown_whole(self):
        report = self._report(self._load(_agent_finding()))
        self.assertEqual(["Query built by hand"], report["summary"]["top_issues"])

    def test_a_finding_with_no_short_form_still_shows_its_title(self):
        finding = self._load(_agent_finding())[0]
        finding.pop("short_title")
        self.assertEqual(["Query built by hand"], self._report([finding])["summary"]["top_issues"])


class CategoryFillTest(_Case):
    def test_a_coded_finding_reads_the_catalogs_category(self):
        (finding,) = self._report(self._load(_agent_finding()))["findings"]
        self.assertEqual("sql-injection", finding["category"])
        self.assertEqual("catalog", finding[evidence_mod.CATEGORY_SOURCE])

    def test_it_only_ever_replaces_general(self):
        cases = (("prompt-injection", CODED), ("logic", CODED), ("general", "SEC-X0X"),
                 ("general", "SEC-Z9Z"), ("general", None))
        for category, code in cases:
            with self.subTest(category=category, code=code):
                finding = self._load(_agent_finding(category=category, code=code))[0]
                (out,) = self._report([finding])["findings"]
                self.assertEqual(category, out["category"])
                self.assertNotIn(evidence_mod.CATEGORY_SOURCE, out)

    def test_the_catalog_answers_only_for_a_real_entry(self):
        bundle = ocrdb.load_bundle()
        self.assertEqual("command-execution", ocrdb.category_of(bundle, "SEC-A1A"))
        for bad in ("SEC-X0X", "SEC-Z9Z", "SEC-A1Z", "NOPE", "", None, 7, ["SEC-A1A"]):
            with self.subTest(code=bad):
                self.assertIsNone(ocrdb.category_of(bundle, bad))
        self.assertIsNone(ocrdb.category_of(None, "SEC-A1A"))

    def test_every_catalog_entry_names_a_category(self):
        bundle = ocrdb.load_bundle()
        codes = [code for dom in bundle["domains"].values() for code in dom["entries"]]
        self.assertGreater(len(codes), 100)
        self.assertEqual([], [code for code in codes if not ocrdb.category_of(bundle, code)])

    def test_a_bundle_of_the_wrong_shape_names_none(self):
        entry = {"domains": {"SEC": {"entries": {"SEC-A1A": {}}}}}
        self.assertIsNone(ocrdb.category_of(entry, "SEC-A1A"))
        entry["domains"]["SEC"]["areas"] = {"A": {"categories": {"1": 7}}}
        self.assertIsNone(ocrdb.category_of(entry, "SEC-A1A"))


class TheFillMovesNothingElseTest(_Case):
    """The claim the fill rests on: ids, counts, verdicts, grades and citations stay where they were."""

    def _pair(self):
        findings = self._load(_agent_finding(), _agent_finding(
            code="SEC-D2A", location={"file": "b.py", "line_start": 2}, title="Fetches any URL"),
            _agent_finding(category="logic", code="COD-A1A", title="Written category",
                           location={"file": "c.py", "line_start": 3}))
        filled = self._report(findings)
        with mock.patch.object(ocrdb, "category_of", return_value=None):
            unfilled = self._report(findings)
        return filled, unfilled

    def test_the_two_reports_differ_only_in_what_the_fill_writes(self):
        filled, unfilled = self._pair()
        self.assertEqual(["sql-injection", "ssrf", "logic"],
                         sorted((f["category"] for f in filled["findings"]),
                                key=["sql-injection", "ssrf", "logic"].index))
        for finding in filled["findings"]:
            if finding.pop(evidence_mod.CATEGORY_SOURCE, None):
                finding["category"] = "general"
        self.assertEqual(unfilled, filled)

    def test_no_cwe_is_derived_from_a_filled_category(self):
        # Both of these name a CWE through `citations.CATEGORY_CWE_OVERRIDES`: a fill that ran before
        # `enrich_citations` would write one, and the citation quality with it.
        catalog = citations.load_cwe_catalog()
        self.assertIsNotNone(citations._derive_cwe_from_category("sql-injection", catalog))
        filled, unfilled = self._pair()
        for finding, other in zip(filled["findings"], unfilled["findings"]):
            self.assertEqual(other.get("citations"), finding.get("citations"))
            self.assertEqual(other.get("citation_quality"), finding.get("citation_quality"))
            self.assertNotIn("cwe", finding.get("citations") or {})


class TheIdentityStaysTest(_Case):
    @staticmethod
    def _before_3368(finding, category):
        """`finding_fingerprint` as a pre-change report stored it, spelled out rather than called."""
        parts = [finding["panel"], category, finding["location"]["file"], finding["title"]]
        return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:16]

    def test_a_filled_finding_keeps_the_fingerprint_an_older_run_stored(self):
        (finding,) = self._report(self._load(_agent_finding()))["findings"]
        self.assertEqual("sql-injection", finding["category"])
        older = self._before_3368(finding, "general")
        self.assertEqual(older, finding["fingerprint"])
        self.assertEqual(older, evidence_mod.finding_fingerprint(finding))
        as_an_older_run_filed_it = dict(finding, category="general", fingerprint=older)
        as_an_older_run_filed_it.pop(evidence_mod.CATEGORY_SOURCE)
        self.assertEqual(file_issues.key_for(as_an_older_run_filed_it, False),
                         file_issues.key_for(finding, False))

    def test_an_agents_marker_is_lost_at_load_and_its_own_category_is_hashed(self):
        (finding,) = self._load(_agent_finding(category="logic", category_source="catalog"))
        self.assertNotIn(evidence_mod.CATEGORY_SOURCE, finding)
        self.assertIn("stripped self-asserted 'category_source'", self.stderr)
        self.assertEqual(self._before_3368(finding, "logic"),
                         evidence_mod.finding_fingerprint(finding))

    def test_an_agent_written_category_gets_no_marker_and_its_fingerprint_is_unchanged(self):
        (finding,) = self._report(self._load(_agent_finding(category="logic")))["findings"]
        self.assertNotIn(evidence_mod.CATEGORY_SOURCE, finding)
        self.assertEqual(self._before_3368(finding, "logic"), finding["fingerprint"])

    def test_a_report_reconciled_against_itself_agrees_on_every_finding(self):
        report = self._report(self._load(
            _agent_finding(),
            _agent_finding(code="SEC-D2A", title="Fetches any URL", location={"file": "b.py"}),
            _agent_finding(category="logic", title="Written", location={"file": "c.py"}),
            _agent_finding(code="SEC-X0X", title="Fallback", location={"file": "d.py"})))
        records = reconcile.iter_records(report)
        self.assertEqual(4, len(records))
        for record in records:
            self.assertEqual(record["stored_fingerprint"], record["fingerprint"], record["id"])
        self.assertEqual([], reconcile._degenerate(reconcile._group_by_fingerprint(records), "r"))


class ThroughBothPassesTest(unittest.TestCase):
    """The real two-pass synthesize: a verdict keyed on the queue pass 1 wrote still binds, on a
    finding pass 2 fills in, and a finding the advisor rejected is filled in too."""

    def setUp(self):
        self.dir = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir, True)

    def _run(self):
        run, verdicts, source = (os.path.join(self.dir, name) for name in ("run", "v", "src"))
        for path in (run, verdicts, source):
            os.mkdir(path)
        findings = os.path.join(source, "findings-app-SEC.json")
        with open(findings, "w", encoding="utf-8") as fh:
            json.dump({"findings": [
                _agent_finding(id="SEC-1", location={"file": "a.py", "line_start": 1}),
                _agent_finding(id="SEC-2", title="Rejected",
                               location={"file": "b.py", "line_start": 1}),
            ]}, fh)
        groups = os.path.join(run, "groups.json")
        with open(groups, "w", encoding="utf-8") as fh:
            json.dump({"mode": "repo", "groups": [{"name": "app", "files": ["a.py", "b.py"]}]}, fh)
        with open(os.path.join(run, runners_base.LEDGER_FILE), "w", encoding="utf-8") as fh:
            fh.write(json.dumps({"entry_id": "review-app-SEC", "model": "measured"}) + "\n")
        out = os.path.join(self.dir, "report.json")
        with _chdir(self.dir), contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(io.StringIO()):
            syn.main(["--target", "app", "--run-dir", run, "--groups", groups,
                      "--emit-verify-queue", findings])
            with open(os.path.join(run, "verify-queue.json"), encoding="utf-8") as fh:
                queue_run_id = json.load(fh)["run_id"]
            keep, reject = (f["id"] for f in findings_mod.load_findings([findings]))
            with open(os.path.join(verdicts, "verdicts-app-SEC.json"), "w", encoding="utf-8") as fh:
                json.dump({"verdicts": [
                    {"finding_id": keep, "verdict": "CONFIRMED", "reasoning": "reachable"},
                    {"finding_id": reject, "verdict": "REJECTED", "reasoning": "not reachable"},
                ], "_panopticon": {"run_id": queue_run_id, "role": "domain_advisor", "domain": "SEC",
                                   "group": "app", "stage": "primary"}}, fh)
            syn.main(["--target", "app", "--out", out, "--run-dir", run, "--groups", groups,
                      "--verdicts-dir", verdicts, findings])
        with open(out, encoding="utf-8") as fh:
            return json.load(fh)

    def test_a_filled_finding_keeps_its_verdict_and_a_rejected_one_is_filled_too(self):
        report = self._run()
        (kept,) = report["findings"]
        self.assertEqual("advisor_confirmed", kept["evidence"]["status"])
        self.assertEqual(("sql-injection", "catalog"), (kept["category"], kept["category_source"]))
        (rejected,) = report["discarded_claims"]
        self.assertEqual(("sql-injection", "catalog"),
                         (rejected["category"], rejected["category_source"]))
        self.assertEqual([{"model": "measured", "role": "domain_panel"}],
                         report["meta"]["models_used"])
        for record in reconcile.iter_records(report):
            self.assertEqual(record["stored_fingerprint"], record["fingerprint"])
