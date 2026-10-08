import json
import contextlib
import io
import os
import unittest

import jsonschema

from tests._test_helpers import only
import scripts.evidence as evidence
import scripts.x0x_report as x0x


def _schema():
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "skill", "reference", "x0x-report-schema.json")
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _f(code, domain, sev, title, file, line=1, fid=None, desc="d", refs=None):
    return {"code": code, "domain": domain, "severity": sev,
            "short_title": title, "title": title, "description": desc,
            "id": fid or f"{domain}-{title}", "references": refs or [],
            "location": {"file": file, "line_start": line, "line_end": line + 2}}


_CONTROL_AND_BIDI_CODE_POINTS = tuple(
    point
    for first, last in (
        (0x0000, 0x0008),
        (0x000B, 0x001F),
        (0x007F, 0x009F),
        (0x061C, 0x061C),
        (0x200E, 0x200F),
        (0x202A, 0x202E),
        (0x2066, 0x2069),
    )
    for point in range(first, last + 1)
)

_IDENTIFIER_PATTERN = (
    r"^[^\u0000-\u0008\u000B-\u001F\u007F-\u009F\u061C"
    r"\u200E-\u200F\u202A-\u202E\u2066-\u2069]*$"
)

_ALLOWED_BOUNDARY_CODE_POINTS = (
    0x0009, 0x000A, 0x0020, 0x007E, 0x00A0, 0x061B, 0x061D,
    0x200D, 0x2010, 0x2029, 0x202F, 0x2065, 0x206A,
)


class TestX0XReport(unittest.TestCase):
    def test_only_fallback_findings_become_candidates(self):
        findings = [
            _f("COD-X0X", "COD", "LOW", "dup dead block", "a.py"),
            _f("SEC-A1A", "SEC", "HIGH", "sql injection", "b.py"),  # real code -> ignored
        ]
        cands = x0x.build_candidates(findings)
        self.assertEqual(len(cands), 1)
        self.assertEqual(cands[0]["fallback_code"], "COD-X0X")
        self.assertEqual(cands[0]["domain"], "COD")

    def test_clusters_same_pattern_keeps_distinct_separate(self):
        findings = [
            _f("SEC-X0X", "SEC", "HIGH", "hardcoded id", "page.tsx", 1, "f1"),
            _f("SEC-X0X", "SEC", "CRITICAL", "hardcoded id", "other.tsx", 5, "f2"),
            _f("DAT-X0X", "DAT", "MEDIUM", "no volume", "compose.yml", 1, "f3"),
        ]
        cands = x0x.build_candidates(findings)
        self.assertEqual(len(cands), 2)
        sec = next(c for c in cands if c["domain"] == "SEC")
        self.assertEqual(sec["recurrence"], 2)
        self.assertEqual({o["finding_id"] for o in sec["occurrences"]}, {"f1", "f2"})
        self.assertEqual(sec["severity"], "CRITICAL")   # the most severe finding leads

    def test_domain_case_folded_so_variants_cluster_together(self):
        # #run7 COD-C2D: the domain flows in verbatim (no case-fold upstream)
        # while the title half of the cluster key is lowercased. "SEC" vs "sec"
        # must cluster into ONE candidate, not split -- and the emitted domain
        # must be the canonical upper form.
        findings = [
            _f("SEC-X0X", "SEC", "HIGH", "hardcoded id", "a.tsx", 1, "f1"),
            _f("sec-X0X", "sec", "LOW", "hardcoded id", "b.tsx", 2, "f2"),
        ]
        cands = x0x.build_candidates(findings)
        self.assertEqual(len(cands), 1)
        self.assertEqual(cands[0]["domain"], "SEC")
        self.assertEqual(cands[0]["recurrence"], 2)
        self.assertEqual({o["finding_id"] for o in cands[0]["occurrences"]},
                         {"f1", "f2"})

    def test_candidate_fields_and_slug_and_cwe_scrape(self):
        f = _f("ARC-X0X", "ARC", "MEDIUM", "Ungated Fixture Provisioning", "x.py",
               3, "f1", desc="runs on every start", refs=["see CWE-400 and CWE-522"])
        c = only(x0x.build_candidates([f]), "candidate")
        self.assertEqual(c["proposed_name"], "ungated-fixture-provisioning")
        self.assertEqual(c["summary"], "Ungated Fixture Provisioning")
        self.assertEqual(c["description"], "runs on every start")
        self.assertEqual(c["cwe"], ["CWE-400", "CWE-522"])   # scraped from free text
        self.assertEqual(only(c["occurrences"], "occurrence"),
                         {"file": "x.py", "line_start": 3, "line_end": 5, "finding_id": "f1"})

    def test_the_zzz_line_is_one_bounded_inert_line_for_a_hostile_finding(self):
        # Re-review of #1807: the pre-existing "not an OCRDb domain" line
        # rendered the agent-authored id raw and the code prefix unbounded --
        # one hostile finding could repaint the terminal. Same treatment as
        # the drop line: squeezed, bounded, %r-escaped, one physical line.
        f = {"code": ("\x1b[2J" + "Q" * 300) + "-X0X", "severity": "MEDIUM",
             "short_title": "t", "id": "\x1b[31mID\nx0x: forged: nothing",
             "location": {"file": "a.py"}}
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            x0x.build_candidates([f])
        out = err.getvalue()
        self.assertEqual(len(out.splitlines()), 1)
        self.assertNotIn("\x1b", out)
        self.assertIn("\\x1b[31mID", out)
        self.assertLess(len(out), 6 * (120 + 40) + 200)

    def test_a_locus_free_cluster_is_dropped_and_announced(self):
        # #1807 DAT-2501524861: a finding with no location is the CANONICAL shape
        # for a repo-wide catalog gap (`synth/findings.py` pops the empty location
        # deliberately), so this drop lands on exactly the gaps this emitter
        # exists to carry. No occurrence can be invented -- the schema requires a
        # file on every one -- so the cluster is announced instead of vanishing.
        # The title is agent-authored, so the line renders it through `%r`: the
        # whitespace squeeze alone would leave an ESC raw and a hostile title
        # could repaint the operator's terminal (#1807 review N3).
        f = _f("COD-X0X", "COD", "LOW", "dup dead\tblock\x1b[31m", None)
        f["location"] = {}   # no file -> no valid occurrence -> candidate dropped
        dropped = []
        with contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertEqual(x0x.build_candidates([f], dropped), [])
        self.assertEqual(err.getvalue(),
                         "x0x: COD: dropping a catalog-gap cluster with no file "
                         "location: 'dup dead block\\x1b[31m' (1 finding(s))\n")
        # the out-list `build_report` tallies from, pinned (review N4): the record
        # carries the squeezed text itself -- escaping belongs at the render.
        self.assertEqual(dropped, [{"domain": "COD",
                                    "summary": "dup dead block\x1b[31m",
                                    "finding_count": 1}])

    def test_an_untitled_cluster_is_named_by_its_finding_id(self):
        # Review N1: the cluster KEY already falls back to the id and `_domain`'s
        # line names the id, so the diagnostic was the one place that named
        # nothing identifiable. A whitespace-only title is empty once squeezed.
        f = {"code": "SEC-X0X", "domain": "SEC", "severity": "LOW", "id": "gap-77",
             "short_title": "   "}
        with contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertEqual(x0x.build_candidates([f]), [])
        self.assertEqual(err.getvalue(),
                         "x0x: SEC: dropping a catalog-gap cluster with no file "
                         "location: 'gap-77' (1 finding(s))\n")

    def test_a_long_title_is_cut_with_the_cut_marked(self):
        # Review N2: the house rule (`phases/review.py::_hit_text`) is that a cut
        # is MARKED, so a truncated value cannot read as a complete one.
        f = _f("SEC-X0X", "SEC", "LOW", "g" * 200, None)
        f["location"] = {}
        with contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertEqual(x0x.build_candidates([f]), [])
        self.assertIn("'" + "g" * 119 + "\u2026'", err.getvalue())

    def test_the_envelope_counts_the_locus_free_clusters_it_dropped(self):
        # The count `synthesize` prints comes off `candidates`; without this the
        # artifact is quietly short and nothing on the line says so.
        gap = {"code": "SEC-X0X", "domain": "SEC", "severity": "HIGH", "id": "gap-1",
               "short_title": "no code covers repo-wide dependency pinning",
               "description": "whole-repo gap"}
        with contextlib.redirect_stderr(io.StringIO()):
            report = x0x.build_report([gap], {}, run_id="run-1")
        self.assertEqual(report["candidates"], [])
        self.assertEqual(report["candidates_dropped_locus_free"], 1)
        # the envelope is a published contract: the new key must validate AND be
        # declared, or a downstream ingester has no documented field to read
        # (review I2).
        self.assertIsNone(jsonschema.validate(report, _schema()))
        self.assertIn("candidates_dropped_locus_free", _schema()["properties"])

    def test_a_mixed_cluster_survives_and_reports_nothing_dropped(self):
        # One located finding is enough to carry the cluster, so nothing was
        # dropped -- only the locus-free occurrence is missing, and `recurrence`
        # counts occurrences, as it always has.
        located = _f("SEC-X0X", "SEC", "LOW", "hardcoded id", "a.py", 1, "f1")
        locus_free = _f("SEC-X0X", "SEC", "HIGH", "hardcoded id", None, 1, "f2")
        with contextlib.redirect_stderr(io.StringIO()) as err:
            report = x0x.build_report([located, locus_free], {}, run_id="run-1")
        candidate = only(report["candidates"], "candidate")
        self.assertEqual(candidate["recurrence"], 1)
        self.assertEqual(only(candidate["occurrences"], "occurrence")["finding_id"], "f1")
        self.assertNotIn("candidates_dropped_locus_free", report)
        self.assertEqual(err.getvalue(), "")

    def test_domainless_zzz_sentinel(self):
        f = {"code": "ZZZ-X0X", "severity": "MEDIUM", "short_title": "t",
             "id": "z1", "location": {"file": "a.py"}}
        self.assertEqual(
            only(x0x.build_candidates([f]), "candidate")["domain"], "ZZZ")

    def test_off_roster_code_prefix_is_clamped_and_reported(self):
        f = _f("BOG-X0X", None, "LOW", "missing rule", "a.py", fid="gap-1")
        with contextlib.redirect_stderr(io.StringIO()) as err:
            candidate = only(x0x.build_candidates([f]), "candidate")
        self.assertEqual(candidate["domain"], "ZZZ")
        self.assertEqual(err.getvalue(),
                         "x0x: 'gap-1': domain 'BOG' is not an OCRDb domain; "
                         "filing the candidate under ZZZ\n")

    def test_valid_roster_domain_is_retained_without_diagnostic(self):
        f = _f("SEC-X0X", "sec", "LOW", "missing rule", "a.py", fid="gap-2")
        with contextlib.redirect_stderr(io.StringIO()) as err:
            candidate = only(x0x.build_candidates([f]), "candidate")
        self.assertEqual(candidate["domain"], "SEC")
        self.assertEqual(err.getvalue(), "")

    def test_build_report_shape_and_required_fields(self):
        meta = {"version": "5.0.1", "ocrdb_version": "0.3.1",
                "target": "/repo", "timestamp": "2026-08-18T00:00:00Z"}
        r = x0x.build_report([_f("COD-X0X", "COD", "LOW", "t", "a.py")], meta,
                             run_id="abc123")
        for k in ("schema_version", "generated_by", "ocrdb_version", "candidates"):
            self.assertIn(k, r)
        self.assertEqual(r["generated_by"],
                         {"panopticon_version": "5.0.1", "run_id": "abc123"})
        self.assertEqual(r["ocrdb_version"], "0.3.1")
        self.assertEqual(r["target"], {"name": "/repo"})
        self.assertEqual(r["generated_at"], "2026-08-18T00:00:00Z")
        for c in r["candidates"]:
            for k in ("domain", "summary", "severity", "occurrences"):
                self.assertIn(k, c)
            self.assertTrue(c["occurrences"] and all("file" in o for o in c["occurrences"]))

    def test_empty_when_no_gaps(self):
        r = x0x.build_report([_f("SEC-A1A", "SEC", "HIGH", "t", "a.py")], {}, run_id="r")
        self.assertEqual(r["candidates"], [])
        self.assertEqual(r["generated_by"]["run_id"], "r")
        self.assertEqual(r["ocrdb_version"], "unknown")   # meta lacked it

    def test_run_id_none_falls_back_to_unknown(self):
        self.assertEqual(
            x0x.build_report([], {}, run_id=None)["generated_by"]["run_id"], "unknown")

    def test_conforms_to_schema(self):
        schema = _schema()
        meta = {"version": "5.0.1", "ocrdb_version": "0.3.1", "target": "/r",
                "timestamp": "t"}
        findings = [_f("COD-X0X", "COD", "LOW", "dup block", "a.py", 1, "f1"),
                    _f("SEC-X0X", "SEC", "HIGH", "hardcoded id", "b.tsx", 5, "f2",
                       refs=["CWE-639"])]
        self.assertIsNone(jsonschema.validate(x0x.build_report(findings, meta, run_id="run-xyz"), schema))

    def test_schema_rejects_the_exact_control_and_bidi_set_in_identifiers(self):
        schema = _schema()
        validator = jsonschema.Draft7Validator(schema)

        def document():
            report = x0x.build_report(
                [_f("SEC-X0X", "SEC", "MEDIUM", "honest candidate",
                    "src/package/widget.py")], {}, run_id="run-1")
            candidate = only(report["candidates"], "candidate")
            candidate["area"] = "runtime"
            return report, candidate

        fields = {
            "occurrence.file": (
                lambda candidate, value: only(
                    candidate["occurrences"], "occurrence").__setitem__("file", value),
                ["candidates", 0, "occurrences", 0, "file"],
            ),
            "candidate.area": (
                lambda candidate, value: candidate.__setitem__("area", value),
                ["candidates", 0, "area"],
            ),
            "candidate.proposed_name": (
                lambda candidate, value: candidate.__setitem__("proposed_name", value),
                ["candidates", 0, "proposed_name"],
            ),
        }
        for field, (set_value, expected_path) in fields.items():
            for point in _CONTROL_AND_BIDI_CODE_POINTS:
                with self.subTest(field=field, code_point="U+%04X" % point):
                    report, candidate = document()
                    set_value(candidate, "safe" + chr(point) + "value")
                    errors = list(validator.iter_errors(report))
                    self.assertEqual(len(errors), 1)
                    self.assertEqual(list(errors[0].path), expected_path)
                    self.assertEqual(errors[0].validator, "pattern")
                    self.assertEqual(errors[0].validator_value,
                                     _IDENTIFIER_PATTERN)

    def test_schema_accepts_every_control_and_bidi_range_neighbour(self):
        schema = _schema()
        validator = jsonschema.Draft7Validator(schema)

        def document():
            report = x0x.build_report(
                [_f("SEC-X0X", "SEC", "MEDIUM", "honest candidate",
                    "src/package/widget.py")], {}, run_id="run-1")
            candidate = only(report["candidates"], "candidate")
            candidate["area"] = "runtime"
            return report, candidate

        setters = {
            "occurrence.file": lambda candidate, value: only(
                candidate["occurrences"], "occurrence").__setitem__("file", value),
            "candidate.area": lambda candidate, value: candidate.__setitem__("area", value),
            "candidate.proposed_name": lambda candidate, value: candidate.__setitem__(
                "proposed_name", value),
        }
        for field, set_value in setters.items():
            for point in _ALLOWED_BOUNDARY_CODE_POINTS:
                with self.subTest(field=field, code_point="U+%04X" % point):
                    report, candidate = document()
                    set_value(candidate, "safe" + chr(point) + "value")
                    self.assertEqual(list(validator.iter_errors(report)), [])

    def test_schema_accepts_empty_identifier_strings(self):
        # #2712 governs which code points may occur. Preserve the schema's
        # existing compatibility choice that a present identifier may be empty;
        # producer-specific shape rules can be stricter (as #2713 will be).
        schema = _schema()
        validator = jsonschema.Draft7Validator(schema)
        setters = {
            "occurrence.file": lambda candidate: only(
                candidate["occurrences"], "occurrence").__setitem__("file", ""),
            "candidate.area": lambda candidate: candidate.__setitem__("area", ""),
            "candidate.proposed_name": lambda candidate: candidate.__setitem__(
                "proposed_name", ""),
        }
        for field, set_value in setters.items():
            with self.subTest(field=field):
                report = x0x.build_report(
                    [_f("SEC-X0X", "SEC", "MEDIUM", "honest candidate",
                        "src/package/widget.py")], {}, run_id="run-1")
                candidate = only(report["candidates"], "candidate")
                set_value(candidate)
                self.assertEqual(list(validator.iter_errors(report)), [])

    def test_schema_keeps_honest_identifiers_and_emitter_output_valid(self):
        schema = _schema()
        validator = jsonschema.Draft7Validator(schema)
        report = x0x.build_report(
            [_f("ARC-X0X", "ARC", "LOW", "bounded retry loop",
                "packages/worker/retry.py")], {}, run_id="run-1")
        candidate = only(report["candidates"], "candidate")
        candidate["area"] = "worker-runtime"
        validator.validate(report)
        self.assertEqual(candidate["proposed_name"], "bounded-retry-loop")

        # #2712 excludes neither horizontal tab nor line feed. #2713 may later
        # layer a kebab-only rule onto proposed_name; paths and areas retain this
        # exact control-character boundary.
        for field, set_value in (
                ("occurrence.file", lambda candidate, value: only(
                    candidate["occurrences"], "occurrence").__setitem__("file", value)),
                ("candidate.area", lambda candidate, value: candidate.__setitem__(
                    "area", value))):
            with self.subTest(field=field):
                report = x0x.build_report(
                    [_f("ARC-X0X", "ARC", "LOW", "bounded retry loop",
                        "packages/worker/retry.py")], {}, run_id="run-1")
                candidate = only(report["candidates"], "candidate")
                candidate["area"] = "worker-runtime"
                set_value(candidate, "segment\tline\nnext")
                validator.validate(report)

    def test_proposed_name_is_bounded_kebab_case_and_the_emitter_conforms(self):
        schema = _schema()
        validator = jsonschema.Draft7Validator(schema)

        def document(name):
            report = x0x.build_report(
                [_f("ARC-X0X", "ARC", "LOW", "ordinary gap", "src/gap.py")],
                {}, run_id="run-1")
            only(report["candidates"], "candidate")["proposed_name"] = name
            return report

        for name in ("", "-leading", "trailing-", "two--hyphens", "Upper-case",
                     "under_score", "white space", "line\n", "tab\tname", "a" * 61):
            with self.subTest(rejected=name):
                self.assertTrue(list(validator.iter_errors(document(name))))
        for name in ("a", "cwe-400", "a" * 60, "bounded-retry-loop"):
            with self.subTest(accepted=name):
                validator.validate(document(name))

        emitted = x0x.build_report(
            [_f("ARC-X0X", "ARC", "LOW", "A" * 70 + " tail", "src/gap.py")],
            {}, run_id="run-1")
        proposed = only(emitted["candidates"], "candidate")["proposed_name"]
        self.assertEqual(proposed, "a" * 60)
        validator.validate(emitted)

    def test_candidate_array_is_total_sorted_and_input_order_independent(self):
        findings = [
            _f("SEC-X0X", "SEC", "HIGH", "Shared Gap", "z.py", 9, "s-z",
               desc="from z", refs=["CWE-522"]),
            _f("ARC-X0X", "ARC", "LOW", "Beta gap", "beta.py", 4, "arc"),
            _f("COD-X0X", "COD", "HIGH", "Cache/read gap", "slash.py", 3,
               "cod-slash"),
            _f("DAT-X0X", "DAT", "CRITICAL", "Critical gap", "critical.py", 1,
               "dat"),
            _f("SEC-X0X", "SEC", "HIGH", "shared gap", "a.py", 2, "s-a",
               desc="from a", refs=["CWE-400"]),
            _f("COD-X0X", "COD", "HIGH", "Cache read gap", "space.py", 5,
               "cod-space"),
        ]
        orders = (
            findings,
            list(reversed(findings)),
            findings[2:] + findings[:2],
            sorted(findings, key=lambda finding: finding["id"]),
        )
        emitted = [x0x.build_candidates(order) for order in orders]
        for candidate_array in emitted[1:]:
            self.assertEqual(candidate_array, emitted[0])

        self.assertEqual(
            [(candidate["domain"], candidate.get("proposed_name"))
             for candidate in emitted[0]],
            [("DAT", "critical-gap"),
             ("COD", "cache-read-gap"),
             ("COD", "cache-read-gap"),
             ("SEC", "shared-gap"),
             ("ARC", "beta-gap")])
        shared = next(candidate for candidate in emitted[0]
                      if candidate["domain"] == "SEC")
        expected_lead = max(
            (finding for finding in findings if finding["domain"] == "SEC"),
            key=evidence.finding_fingerprint)
        self.assertEqual(shared["description"], expected_lead["description"])
        self.assertEqual(shared["cwe"], ["CWE-400", "CWE-522"])
        self.assertEqual([occurrence["file"] for occurrence in shared["occurrences"]],
                         ["a.py", "z.py"])

    def test_generated_at_stays_optional(self):
        schema = _schema()
        report = x0x.build_report([], {}, run_id="run-1")
        self.assertNotIn("generated_at", schema["required"])
        self.assertNotIn("generated_at", report)
        self.assertIsNone(jsonschema.validate(report, schema))
