"""#3702: an advisor's verdict counts only for a claim that advisor was handed.

Bundle verdicts are matched to findings by id across the run. A backup advisor
handed one claim could say REJECTED about two that no primary had answered: both
were discarded and the run certified. A primary could do the same to another
cell's claims. The verify phase now records what each part of each cell and stage
is handed, and the bundle loader drops every verdict that record does not cover.
"""

import json
import os
import tempfile
import types
import unittest

import jsonschema

import scripts.evidence as evidence_mod
import scripts.html_report as html_report
import scripts.phases.verify as verify
import scripts.synth.backups as backups_mod
import scripts.synth.findings as findings_mod
import scripts.synth.grading as grading_mod
import scripts.synth.plan as plan_mod
import scripts.synth.render as render_mod
import scripts.synth.report as report_mod
import scripts.synth.verdict_scope as scope_mod
from tests.synth.helpers import _target_with_files

SCHEMA_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))), "skill", "reference", "report-schema.json")

RUN_ID = "run-1"


def record(group="g1", domain="SEC", stage="primary", claims=("SEC-001", "SEC-002", "SEC-003"),
           size=2, parts=None, count=1):
    """What `verify._scope_record` writes for one cell and stage, beside its charge."""
    key = "%s/%s/%s" % (group, domain, stage)
    return {key: count, key + "/claims": list(claims), key + "/part_size": size,
            key + "/parts": -(-len(claims) // size) if parts is None else parts}


def name_of(group="g1", domain="SEC", stage="primary", part=0):
    return os.path.basename(verify._verify_out_file("/r", group, domain, stage, part))


def stamp(group="g1", domain="SEC", stage="primary"):
    return {"group": group, "domain": domain, "stage": stage}


def verdict(finding_id, said="CONFIRMED"):
    return {"finding_id": finding_id, "verdict": said, "reasoning": "checked"}


class TestWhatAPartWasHanded(unittest.TestCase):
    def test_each_part_was_handed_its_own_slice_of_the_claims(self):
        scope = scope_mod.Scope(record())
        self.assertEqual({"SEC-001", "SEC-002"}, scope.handed(name_of(part=0), stamp()))
        self.assertEqual({"SEC-003"}, scope.handed(name_of(part=1), stamp()))

    def test_the_two_stages_of_one_cell_are_recorded_apart(self):
        scope = scope_mod.Scope({**record(), **record(stage="backup", claims=("SEC-002",))})
        self.assertEqual({"SEC-002"}, scope.handed(name_of(stage="backup"), stamp(stage="backup")))
        self.assertEqual({"SEC-001", "SEC-002"}, scope.handed(name_of(), stamp()))

    def test_a_file_that_is_not_a_recorded_part_of_its_cell_was_handed_nothing(self):
        scope = scope_mod.Scope({**record(), **record(stage="backup")})
        for label, name, stamped in (
                ("a part past the recorded count", name_of(part=2), stamp()),
                ("the backup's file, stamped primary", name_of(stage="backup"), stamp()),
                ("the primary's file, stamped backup", name_of(), stamp(stage="backup")),
                ("another cell's file", name_of(group="g2"), stamp()),
                ("a part number written another way", "verdicts-g1-SEC-part01.json", stamp()),
                ("part 0 written out", "verdicts-g1-SEC-part0.json", stamp()),
                ("no bundle name at all", "notes.json", stamp())):
            with self.subTest(label):
                self.assertEqual(frozenset(), scope.handed(name, stamped))

    def test_a_bundle_stamped_for_no_cell_was_handed_nothing(self):
        scope = scope_mod.Scope(record())
        for stamped in ({}, None, {"group": "g1"}, {"domain": "SEC"}, stamp(stage="tool"),
                        {"group": "", "domain": "SEC", "stage": "primary"},
                        {"group": ["g1"], "domain": "SEC", "stage": "primary"},
                        {"group": "g1", "domain": 7, "stage": "primary"}):
            with self.subTest(stamped=stamped):
                self.assertEqual(frozenset(), scope.handed(name_of(), stamped))

    def test_a_cell_the_record_does_not_cover_is_not_recorded(self):
        scope = scope_mod.Scope(record())
        self.assertIsNone(scope.handed(name_of(group="g2"), stamp(group="g2")))
        self.assertIsNone(scope.handed(name_of(stage="backup"), stamp(stage="backup")))

    def test_a_record_missing_any_of_its_three_keys_is_not_recorded(self):
        # One part and two: no key has a default that happens to fit either.
        for claims in (("SEC-001",), ("SEC-001", "SEC-002", "SEC-003")):
            for suffix in ("/claims", "/parts", "/part_size"):
                with self.subTest(claims=claims, missing=suffix):
                    body = record(claims=claims, size=2)
                    self.assertIsNotNone(scope_mod.Scope(body).handed(name_of(), stamp()))
                    del body["g1/SEC/primary" + suffix]
                    self.assertIsNone(scope_mod.Scope(body).handed(name_of(), stamp()))

    def test_a_charge_alone_is_not_a_scope(self):
        """A run charged before the scope was recorded: nothing shows what was handed."""
        self.assertIsNone(scope_mod.Scope({"g1/SEC/primary": 2}).handed(name_of(), stamp()))

    def test_a_value_that_is_not_what_verify_writes_is_not_recorded(self):
        for key, bad in (("/claims", []), ("/claims", "SEC-001"), ("/claims", ["SEC-001", ""]),
                         ("/claims", ["SEC-001", 2]), ("/claims", None), ("/claims", {"a": 1}),
                         ("/parts", 0), ("/parts", True), ("/parts", "2"), ("/parts", 2.0),
                         ("/part_size", 0), ("/part_size", -1), ("/part_size", True),
                         ("/part_size", "2"), ("/part_size", None)):
            for claims in (("SEC-001",), ("SEC-001", "SEC-002", "SEC-003")):
                with self.subTest(key=key, bad=bad, claims=claims):
                    body = dict(record(claims=claims), **{"g1/SEC/primary" + key: bad})
                    self.assertIsNone(scope_mod.Scope(body).handed(name_of(), stamp()))

    def test_a_part_count_the_claims_do_not_split_into_is_not_recorded(self):
        for parts in (1, 3):
            with self.subTest(parts=parts):
                scope = scope_mod.Scope(record(parts=parts))     # 3 claims by 2 is 2 parts
                self.assertIsNone(scope.handed(name_of(), stamp()))

    def test_no_charge_is_needed_for_the_scope_to_stand(self):
        """A paused checkpoint gives its charge back; what its cells were handed and
        answered before the pause still counts."""
        scope = scope_mod.Scope(record(count=0))
        self.assertEqual({"SEC-001", "SEC-002"}, scope.handed(name_of(), stamp()))

    def test_a_claim_recorded_twice_keeps_its_place_in_each_part(self):
        scope = scope_mod.Scope(record(claims=("A", "B", "A", "C"), size=2))
        self.assertEqual({"A", "B"}, scope.handed(name_of(part=0), stamp()))
        self.assertEqual({"A", "C"}, scope.handed(name_of(part=1), stamp()))


class TestReadingTheRecord(unittest.TestCase):
    def setUp(self):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        self.run_dir = d.name

    def write(self, text):
        with open(os.path.join(self.run_dir, backups_mod.ATTEMPTS_FILE), "w",
                  encoding="utf-8") as fh:
            fh.write(text)

    def test_the_record_is_read_from_the_run_folder(self):
        self.write(json.dumps(record()))
        self.assertEqual({"SEC-003"},
                         scope_mod.Scope.load(self.run_dir).handed(name_of(part=1), stamp()))

    def test_with_nothing_to_go_by_nothing_is_recorded(self):
        cases = (("no run folder", lambda: None), ("no record", lambda: self.run_dir),
                 ("not JSON", lambda: self.write("{not json") or self.run_dir),
                 ("not an object", lambda: self.write("[1, 2]") or self.run_dir),
                 ("null", lambda: self.write("null") or self.run_dir))
        for label, where in cases:
            with self.subTest(label):
                self.assertIsNone(scope_mod.Scope.load(where()).handed(name_of(), stamp()))

    def test_the_names_are_the_verify_phases_own(self):
        """Synth may not import phases, so it spells the record's names itself."""
        written = verify._scope_record("g1", "SEC", "primary", [{"id": "SEC-001"}])
        key = verify._verify_key("g1", "SEC", "primary")
        self.assertEqual({key + backups_mod.CLAIMS_SUFFIX, key + backups_mod.PARTS_SUFFIX,
                          key + scope_mod.PART_SIZE_SUFFIX}, set(written))
        self.assertEqual(verify._part_size_key("g1", "SEC", "primary"),
                         key + scope_mod.PART_SIZE_SUFFIX)
        self.assertEqual(verify._VERIFY_ATTEMPTS_FILE, backups_mod.ATTEMPTS_FILE)
        for stage in scope_mod.STAGES:
            for part in (0, 1, 12):
                self.assertEqual(
                    os.path.basename(verify._verify_out_file("/r", "g-1", "SEC", stage, part)),
                    scope_mod._bundle_name("g-1", "SEC", stage, part))

    def test_what_verify_records_is_what_synth_reads_back(self):
        cell = [{"id": "SEC-%03d" % n} for n in range(verify._CELL_CLAIMS_CAP + 3)]
        scope = scope_mod.Scope(verify._scope_record("g1", "SEC", "backup", cell))
        for part, chunk in enumerate(verify._cell_chunks(cell)):
            self.assertEqual({f["id"] for f in chunk},
                             scope.handed(name_of(stage="backup", part=part),
                                          stamp(stage="backup")))
        self.assertEqual(frozenset(), scope.handed(name_of(stage="backup", part=2),
                                                   stamp(stage="backup")))


class _Verdicts(unittest.TestCase):
    def setUp(self):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        self.run_dir = d.name
        self.verdicts = os.path.join(d.name, "verdicts")
        os.makedirs(self.verdicts)

    def record(self, *bodies):
        merged = {}
        for body in bodies:
            merged.update(body)
        with open(os.path.join(self.run_dir, backups_mod.ATTEMPTS_FILE), "w",
                  encoding="utf-8") as fh:
            json.dump(merged, fh)

    def bundle(self, verdicts, group="g1", domain="SEC", stage="primary", part=0, name=None):
        name = name or name_of(group, domain, stage, part)
        with open(os.path.join(self.verdicts, name), "w", encoding="utf-8") as fh:
            json.dump({"verdicts": verdicts, "_panopticon": {
                "run_id": RUN_ID, "group": group, "domain": domain, "stage": stage}}, fh)
        return name

    def load(self, scoped=True):
        accepted = {}
        scope = scope_mod.Scope.load(self.run_dir).handed if scoped else None
        by_fid, unloadable = evidence_mod.load_verdict_bundles(
            self.verdicts, accepted=accepted, scope=scope)
        return by_fid, accepted, unloadable


class TestTheLoaderCountsOnlyWhatWasHanded(_Verdicts):
    def test_a_verdict_for_a_handed_claim_counts(self):
        self.record(record())
        name = self.bundle([verdict("SEC-001"), verdict("SEC-002")])
        by_fid, accepted, _ = self.load()
        self.assertEqual({"SEC-001", "SEC-002"}, set(by_fid))
        self.assertEqual((2, ["SEC-001", "SEC-002"], 0, 0), tuple(accepted[name][key] for key in (
            "kept", "finding_ids", "out_of_scope", "scope_not_recorded")))

    def test_a_verdict_for_any_other_claim_is_dropped_and_counted(self):
        self.record(record(), record(group="g2", claims=("SEC-900",), size=25))
        name = self.bundle([verdict("SEC-001"), verdict("SEC-002"),
                            verdict("SEC-003", "REJECTED"),      # the cell's other part's
                            verdict("SEC-900", "REJECTED"),      # another cell's
                            verdict("SEC-000", "REJECTED")])     # nothing's
        by_fid, accepted, unloadable = self.load()
        self.assertEqual({"SEC-001", "SEC-002"}, set(by_fid))
        self.assertEqual((2, ["SEC-001", "SEC-002"], 3, 0), tuple(accepted[name][key] for key in (
            "kept", "finding_ids", "out_of_scope", "scope_not_recorded")))
        self.assertEqual([], unloadable)

    def test_the_claims_own_verdict_is_the_one_left(self):
        """The first file by name used to win: `verdicts-g1-SEC.json` over g2's own."""
        self.record(record(claims=("SEC-001",)), record(group="g2", claims=("SEC-900",)))
        self.bundle([verdict("SEC-001"), verdict("SEC-900", "REJECTED")])
        self.bundle([verdict("SEC-900", "CONFIRMED")], group="g2")
        by_fid, _, _ = self.load()
        self.assertEqual(["CONFIRMED"], [v["verdict"] for v in by_fid["SEC-900"]])
        match = evidence_mod.match_verdict_by_id({"id": "SEC-900"}, by_fid)
        self.assertEqual("CONFIRMED", match["verdict"])

    def test_a_backup_counts_only_for_its_own_scope(self):
        """The issue's case: the backup was handed SEC-001 and says REJECTED about
        the two claims no primary answered."""
        self.record(record(size=25), record(stage="backup", claims=("SEC-001",), size=25))
        self.bundle([verdict("SEC-001")])
        name = self.bundle([verdict("SEC-001"), verdict("SEC-002", "REJECTED"),
                            verdict("SEC-003", "REJECTED")], stage="backup")
        by_fid, accepted, _ = self.load()
        self.assertEqual({"SEC-001"}, set(by_fid))
        self.assertEqual(["backup", "primary"], sorted(v["stage"] for v in by_fid["SEC-001"]))
        self.assertEqual((1, 2), (accepted[name]["kept"], accepted[name]["out_of_scope"]))

    def test_an_id_is_compared_as_text_and_whole(self):
        self.record(record(claims=("SEC-001", "7"), size=25))
        name = self.bundle([verdict("SEC-001"), verdict(7), verdict("SEC-0011"),
                            verdict("sec-001"), verdict(" SEC-001")])
        by_fid, accepted, _ = self.load()
        self.assertEqual({"SEC-001", "7"}, set(by_fid))
        self.assertEqual(3, accepted[name]["out_of_scope"])

    def test_with_no_scope_recorded_nothing_in_the_bundle_counts(self):
        cases = (("no record at all", None),
                 ("a charge and no scope", {"g1/SEC/primary": 1}),
                 ("another cell's scope", record(group="g2")))
        for label, body in cases:
            with self.subTest(label):
                path = os.path.join(self.run_dir, backups_mod.ATTEMPTS_FILE)
                if os.path.exists(path):
                    os.remove(path)
                if body is not None:
                    self.record(body)
                name = self.bundle([verdict("SEC-001"), verdict("SEC-002")])
                by_fid, accepted, unloadable = self.load()
                self.assertEqual({}, by_fid)
                self.assertEqual((0, [], 0, 2), tuple(accepted[name][key] for key in (
                    "kept", "finding_ids", "out_of_scope", "scope_not_recorded")))
                self.assertEqual([], unloadable)

    def test_an_entry_that_cannot_be_read_is_still_unloadable_and_not_out_of_scope(self):
        self.record(record())
        name = self.bundle([verdict("SEC-001"), {"verdict": "CONFIRMED"}, "text",
                            {"finding_id": "SEC-900", "verdict": "MAYBE"}])
        _, accepted, unloadable = self.load()
        self.assertEqual([1, 2, 3], [row["entry"] for row in unloadable])
        self.assertEqual((1, 0), (accepted[name]["kept"], accepted[name]["out_of_scope"]))

    def test_the_stamp_and_not_the_advisor_says_which_bundle_this_is(self):
        """An advisor's own `stage` is stripped; a bundle stamped for another cell
        than its file is named for was handed nothing."""
        self.record(record(claims=("SEC-001",)), record(group="g2", claims=("SEC-900",)))
        name = self.bundle([verdict("SEC-900", "REJECTED")], group="g2", name=name_of())
        by_fid, accepted, _ = self.load()
        self.assertEqual({}, by_fid)
        self.assertEqual(1, accepted[name]["out_of_scope"])

    def test_without_a_scope_the_loader_keeps_every_entry(self):
        """The loader's other callers are not deciding what a verdict binds to."""
        name = self.bundle([verdict("SEC-001"), verdict("SEC-900")])
        by_fid, accepted, _ = self.load(scoped=False)
        self.assertEqual({"SEC-001", "SEC-900"}, set(by_fid))
        self.assertEqual((2, 0, 0), tuple(accepted[name][key] for key in (
            "kept", "out_of_scope", "scope_not_recorded")))

    def test_synthesis_always_loads_through_the_record(self):
        """`FindingSet.load` is the one production caller: with no record in the
        run folder it gives the matcher nothing."""
        self.bundle([verdict("SEC-001")])
        args = types.SimpleNamespace(verdicts_dir=self.verdicts)
        for run_dir in (self.run_dir, None):
            with self.subTest(run_dir=run_dir):
                fs = findings_mod.FindingSet.load(args, [], False, RUN_ID,
                                                  prepared=([], None, {}), run_dir=run_dir)
                self.assertEqual({}, fs.verdict_bundles)
                self.assertEqual((0, 1), scope_mod.counts(fs.bundle_files))
        self.record(record())
        fs = findings_mod.FindingSet.load(args, [], False, RUN_ID, prepared=([], None, {}),
                                          run_dir=self.run_dir)
        self.assertEqual({"SEC-001"}, set(fs.verdict_bundles))
        self.assertEqual((0, 0), scope_mod.counts(fs.bundle_files))


class TestTheSharedRule(unittest.TestCase):
    def test_the_ids_said_that_were_not_handed_in_order_each_once(self):
        rule = evidence_mod.claims_out_of_scope
        self.assertEqual([], rule(["A", "B"], ["B", "A", "A"]))
        self.assertEqual(["Z", "C"], rule(["A", "B"], ["Z", "A", "C", "Z"]))
        self.assertEqual(["A"], rule([], ["A"]))
        self.assertEqual([], rule(["A"], []))
        self.assertEqual([], rule(["A"], [None]))
        self.assertEqual([], rule([7], ["7"]))
        self.assertEqual(["8"], rule(["7"], [8]))


class TestTheCountsAndTheirReasons(unittest.TestCase):
    def test_the_counts_are_summed_over_the_files(self):
        files = {"a.json": {"out_of_scope": 2, "scope_not_recorded": 0},
                 "b.json": {"out_of_scope": 1, "scope_not_recorded": 4},
                 "c.json": {"kept": 3}, "d.json": None,
                 "e.json": {"out_of_scope": True, "scope_not_recorded": "9"}}
        self.assertEqual((3, 4), scope_mod.counts(files))
        self.assertEqual((0, 0), scope_mod.counts(None))

    def test_each_count_is_a_reason_of_its_own(self):
        for stats, expected in (
                ({"out_of_scope": 0, "scope_not_recorded": 0}, []),
                ({}, []), (None, []),
                ({"out_of_scope": 1}, ["1 advisor verdict outside its handed scope"]),
                ({"out_of_scope": 2}, ["2 advisor verdicts outside their handed scope"]),
                ({"scope_not_recorded": 1},
                 ["verify scope not recorded: 1 advisor verdict not counted"]),
                ({"out_of_scope": 3, "scope_not_recorded": 12},
                 ["3 advisor verdicts outside their handed scope",
                  "verify scope not recorded: 12 advisor verdicts not counted"])):
            with self.subTest(stats=stats):
                self.assertEqual(expected, scope_mod.reasons(stats))

    def test_either_count_alone_is_a_grade_shortfall(self):
        for key in ("out_of_scope", "scope_not_recorded"):
            with self.subTest(key):
                resolved = types.SimpleNamespace(unanswered_gate=0, unanswered_tools=0,
                                                 verdict_stats={key: 1})
                self.assertEqual(scope_mod.reasons({key: 1}),
                                 grading_mod.grade_shortfalls(resolved))
        clean = types.SimpleNamespace(unanswered_gate=0, unanswered_tools=0,
                                      verdict_stats={"out_of_scope": 0, "scope_not_recorded": 0})
        self.assertEqual([], grading_mod.grade_shortfalls(clean))
        self.assertEqual([], grading_mod.grade_shortfalls(types.SimpleNamespace()))


GROUPS = [{"name": "g1", "files": ["a.py"]}, {"name": "g2", "files": ["b.py"]}]
OUTSIDE = "1 advisor verdict outside its handed scope"


class TestTheReport(_Verdicts):
    """Through the loader synthesis uses and `build_report`: two cells, one CRITICAL
    claim each. `A` is g1's and `B` is g2's."""

    def setUp(self):
        super().setUp()
        paths = []
        for group, file in (("g1", "a.py"), ("g2", "b.py")):
            paths.append(os.path.join(self.run_dir, "findings-%s-SEC.json" % group))
            with open(paths[-1], "w", encoding="utf-8") as fh:
                json.dump({"findings": [{
                    "domain": "SEC", "code": "SEC-A1A", "severity": "CRITICAL",
                    "title": "claim in %s" % file, "description": "x", "category": "authz",
                    "location": {"file": file, "line_start": 1}}]}, fh)
        self.paths = paths
        self.a, self.b = (f["id"] for f in findings_mod.load_findings(paths))

    def recorded(self):
        self.record(record(claims=(self.a,), size=25),
                    record(group="g2", claims=(self.b,), size=25))

    def report(self):
        fs = findings_mod.FindingSet.load(
            types.SimpleNamespace(verdicts_dir=self.verdicts), [], "standard", None,
            prepared=(findings_mod.load_findings(self.paths), None, None),
            run_dir=self.run_dir)
        with _target_with_files(GROUPS, lines=5000) as target:
            return report_mod.build_report(report_mod.ReportInputs(
                run=report_mod.RunConfig(target=target, fail_on="critical",
                                         timestamp="2026-01-01T00:00:00Z"),
                findings=fs, plan=plan_mod.PlanInputs(groups_meta=GROUPS)))

    def facts(self, report):
        summary = report["summary"]
        claims = {f["id"]: ("report", f["evidence"]["status"]) for f in report["findings"]}
        claims.update({f["id"]: ("discarded", f["evidence"]["status"])
                       for f in report["discarded_claims"]})
        counted = report["meta"]["coverage"]["verdicts"]
        return (claims, summary["grade_shortfalls"], summary["coverage_certified"],
                summary["overall_grade"], summary["provisional_grade"],
                (counted["out_of_scope"], counted["scope_not_recorded"]))

    def honest(self):
        self.bundle([verdict(self.a)])
        self.bundle([verdict(self.b)], group="g2")
        return self.report()

    def test_every_advisor_answering_its_own_claims_certifies(self):
        self.recorded()
        claims, shortfalls, certified, letter, provisional, counted = self.facts(self.honest())
        self.assertEqual({self.a: ("report", "advisor_confirmed"),
                          self.b: ("report", "advisor_confirmed")}, claims)
        self.assertEqual(([], True, None, (0, 0)), (shortfalls, certified, provisional, counted))
        self.assertIsNotNone(letter)

    def test_a_verdict_added_about_another_cells_claim_changes_nothing_but_certification(self):
        """The attack shape: g1's advisor answers its own claim and also rejects g2's,
        which g2's own advisor confirmed. `verdicts-g1-SEC.json` sorts first."""
        self.recorded()
        honest = self.facts(self.honest())
        self.bundle([verdict(self.a), verdict(self.b, "REJECTED")])
        report = self.report()
        claims, shortfalls, certified, letter, provisional, counted = self.facts(report)
        self.assertEqual(honest[0], claims)
        self.assertEqual(([OUTSIDE], False, None, honest[3], (1, 0)),
                         (shortfalls, certified, letter, provisional, counted))
        self.assertIn(OUTSIDE, report["summary"]["coverage_note"])
        text = render_mod.render_summary(report)
        self.assertIn("(provisional; %s" % OUTSIDE, text)
        self.assertIn("**Coverage:** NOT CERTIFIED — %s" % OUTSIDE, text)
        page = html_report.render(report)
        self.assertIn("NOT CERTIFIED &mdash; %s" % OUTSIDE, page)

    def test_a_rejection_of_a_claim_whose_own_advisor_never_answered_dismisses_nothing(self):
        """The false certification: B used to be discarded and the run certified."""
        self.recorded()
        self.bundle([verdict(self.a)])
        silent = self.facts(self.report())
        self.assertEqual(("report", "unverified"), silent[0][self.b])
        self.assertEqual(["1 finding unanswered by its verify advisor"], silent[1])
        self.bundle([verdict(self.a), verdict(self.b, "REJECTED")])
        claims, shortfalls, certified, letter, _provisional, counted = self.facts(self.report())
        self.assertEqual(silent[0], claims)
        self.assertEqual((silent[1] + [OUTSIDE], False, None, (1, 0)),
                         (shortfalls, certified, letter, counted))

    def test_a_confirmation_of_a_claim_its_own_advisor_rejected_brings_nothing_back(self):
        self.recorded()
        self.bundle([verdict(self.a)])
        self.bundle([verdict(self.b, "REJECTED")], group="g2")
        honest = self.facts(self.report())
        self.assertEqual(("discarded", "rejected"), honest[0][self.b])
        self.bundle([verdict(self.a), verdict(self.b, "CONFIRMED")])
        claims, shortfalls, certified, _letter, _provisional, _counted = self.facts(self.report())
        self.assertEqual(honest[0], claims)
        self.assertEqual(([OUTSIDE], False), (shortfalls, certified))

    def test_a_bundle_verdict_cannot_speak_for_a_tool_finding(self):
        """A tool finding is answered by its own advisor, in a file named for it. It is
        in no cell's scope, so a bundle that names its id decides nothing about it. It
        used to bind whenever the tool advisor had not answered."""
        self.recorded()
        tool = findings_mod.normalize_finding({
            "id": "SG-001", "title": "tool hit", "severity": "CRITICAL", "panel": "security",
            "confidence": "LIKELY", "category": "injection", "source": "tool:semgrep",
            "location": {"file": "a.py", "line_start": 40},
            "provenance": {"discovered_by": "tool:semgrep", "confirmation_status": "UNVERIFIED",
                           "tool_evidence": {"rule_id": "r1"}}})
        self.bundle([verdict(self.a), verdict(tool["id"], "REJECTED")])
        self.bundle([verdict(self.b)], group="g2")
        fs = findings_mod.FindingSet.load(
            types.SimpleNamespace(verdicts_dir=self.verdicts), [], "standard", None,
            prepared=(findings_mod.load_findings(self.paths) + [tool], None, None),
            run_dir=self.run_dir)
        self.assertNotIn(tool["id"], fs.verdict_bundles)
        with _target_with_files(GROUPS, lines=5000) as target:
            report = report_mod.build_report(report_mod.ReportInputs(
                run=report_mod.RunConfig(target=target, fail_on="critical",
                                         timestamp="2026-01-01T00:00:00Z"),
                findings=fs, plan=plan_mod.PlanInputs(groups_meta=GROUPS)))
        self.assertEqual(["tool_reported"], [f["evidence"]["status"] for f in report["findings"]
                                             if f["id"] == tool["id"]])
        self.assertEqual([], report["discarded_claims"])
        self.assertEqual(["1 tool finding unanswered by its advisor", OUTSIDE],
                         report["summary"]["grade_shortfalls"])

    def test_a_run_with_no_recorded_scope_counts_no_verdict_and_says_why(self):
        """A run verified before the scope was recorded, or a hand call with no record."""
        reason = "verify scope not recorded: 2 advisor verdicts not counted"
        for label, body in (("no record", None),
                            ("charges and no scope", {"g1/SEC/primary": 1, "g2/SEC/primary": 1})):
            with self.subTest(label):
                if body is not None:
                    self.record(body)
                report = self.honest()
                claims, shortfalls, certified, letter, _provisional, counted = self.facts(report)
                self.assertEqual({self.a: ("report", "unverified"),
                                  self.b: ("report", "unverified")}, claims)
                self.assertEqual((["2 findings unanswered by their verify advisors", reason],
                                  False, None, (0, 2)), (shortfalls, certified, letter, counted))
                self.assertIn(reason, report["summary"]["coverage_note"])
                self.assertIn(reason, render_mod.render_summary(report))
                self.assertIn(reason, html_report.render(report))

    def test_the_counts_are_in_the_report_schema(self):
        self.recorded()
        self.bundle([verdict(self.a), verdict(self.b, "REJECTED")])
        report = self.report()
        with open(SCHEMA_PATH, encoding="utf-8") as fh:
            validator = jsonschema.Draft7Validator(json.load(fh))
        self.assertEqual([], [e.message for e in validator.iter_errors(report)])
        for key in ("out_of_scope", "scope_not_recorded"):
            with self.subTest(key):
                report["meta"]["coverage"]["verdicts"][key] = "1"
                self.assertNotEqual([], list(validator.iter_errors(report)))
                report["meta"]["coverage"]["verdicts"][key] = 0


if __name__ == "__main__":
    unittest.main()
