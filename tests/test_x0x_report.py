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

    def test_cwe_is_omitted_when_the_scrape_is_empty(self):
        candidate = only(
            x0x.build_candidates([
                _f("ARC-X0X", "ARC", "LOW", "uncatalogued pattern", "x.py")
            ]),
            "candidate",
        )
        self.assertNotIn("cwe", candidate)

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

    def test_a_locus_free_finding_is_discarded_into_a_redacted_inert_log(self):
        # #2713 revised owner ruling: keep the X0X, omit the unrepresentable
        # occurrence, and preserve a loud machine-readable record beside it.
        secret = "sk-" + "A" * 20
        f = _f("COD-X0X", "COD", "LOW",
               "dup dead\tblock\x1b[31m " + secret, None, fid="gap-77")
        f["location"] = {}

        report, failure_log = x0x.build_emission([f], {}, run_id="run-1")

        self.assertEqual(report["candidates"], [])
        record = only(failure_log["discarded_findings"], "discarded finding")
        self.assertEqual(record["finding_id"], "gap-77")
        self.assertEqual(record["reason"], "no file locus")
        diagnostic = record["diagnostic"]
        self.assertEqual(len(diagnostic.splitlines()), 1)
        self.assertNotIn("\x1b", diagnostic)
        self.assertNotIn(secret, diagnostic)
        self.assertIn("[REDACTED_KEY]", diagnostic)
        self.assertIn("'gap-77'", diagnostic)
        self.assertIn("\\x1b[31m", diagnostic)
        self.assertLess(len(diagnostic), 2 * 120 + 100)

    def test_an_untitled_cluster_is_named_by_its_finding_id(self):
        # A whitespace-only title is empty once squeezed, so the id remains the
        # identifying value in the failure log.
        f = {"code": "SEC-X0X", "domain": "SEC", "severity": "LOW", "id": "gap-77",
             "short_title": "   "}
        _report, failure_log = x0x.build_emission([f], {}, run_id="run-1")
        self.assertEqual(
            only(failure_log["discarded_findings"], "discarded finding")["diagnostic"],
            "catalog-gap finding 'gap-77' ('?') has no location.file",
        )

    def test_a_long_title_is_cut_with_the_cut_marked(self):
        # Review N2: the house rule (`phases/review.py::_hit_text`) is that a cut
        # is MARKED, so a truncated value cannot read as a complete one.
        f = _f("SEC-X0X", "SEC", "LOW", "g" * 200, None)
        f["location"] = {}
        _report, failure_log = x0x.build_emission([f], {}, run_id="run-1")
        diagnostic = only(
            failure_log["discarded_findings"], "discarded finding")["diagnostic"]
        self.assertIn("'" + "g" * 119 + "\u2026'", diagnostic)

    def test_failure_log_redacts_before_cutting_a_diagnostic_field(self):
        # Cutting first can turn a recognizable credential into an unrecognized
        # partial credential at the 120-character boundary.
        secret = "sk-" + "B" * 20
        f = _f("SEC-X0X", "SEC", "LOW", "p" * 105 + " " + secret, None,
               fid="gap-1")
        _report, failure_log = x0x.build_emission([f], {}, run_id="run-1")
        diagnostic = only(
            failure_log["discarded_findings"], "discarded finding")["diagnostic"]
        self.assertNotIn(secret, diagnostic)
        self.assertNotIn("sk-", diagnostic)
        self.assertIn("[REDACTED_KEY]", diagnostic)

    def test_an_all_locus_free_run_emits_an_empty_x0x_and_a_separate_log(self):
        gap = {"code": "SEC-X0X", "domain": "SEC", "severity": "HIGH", "id": "gap-1",
               "short_title": "no code covers repo-wide dependency pinning",
               "description": "whole-repo gap"}
        report, failure_log = x0x.build_emission([gap], {}, run_id="run-1")
        self.assertEqual(report["candidates"], [])
        self.assertEqual(len(failure_log["discarded_findings"]), 1)
        self.assertNotIn("candidates_dropped_locus_free", _schema()["properties"])

    def test_a_mixed_cluster_discards_only_its_locus_free_finding(self):
        # A located sibling remains a complete one-occurrence candidate; the
        # omitted sibling is visible in the separate log and nowhere else.
        located = _f("SEC-X0X", "SEC", "LOW", "hardcoded id", "a.py", 1, "f1")
        locus_free = _f("SEC-X0X", "SEC", "HIGH", "hardcoded id", None, 1, "f2")
        for order in ([located, locus_free], [locus_free, located]):
            with self.subTest(order=[finding["id"] for finding in order]):
                report, failure_log = x0x.build_emission(order, {}, run_id="run-1")
                candidate = only(report["candidates"], "candidate")
                self.assertEqual(candidate["recurrence"], 1)
                self.assertEqual(
                    only(candidate["occurrences"], "occurrence")["finding_id"], "f1")
                self.assertEqual(
                    only(failure_log["discarded_findings"], "discarded finding")
                    ["finding_id"], "f2")

    def test_discard_order_and_x0x_bytes_are_input_independent(self):
        located = _f("SEC-X0X", "SEC", "HIGH", "hardcoded id", "a.py", 1, "f1")
        missing_z = _f("COD-X0X", "COD", "LOW", "missing z", None, fid="z")
        missing_a = _f("ARC-X0X", "ARC", "LOW", "missing a", None, fid="a")
        baseline, _baseline_log = x0x.build_emission([located], {}, run_id="run-1")
        emissions = [
            x0x.build_emission(order, {}, run_id="run-1")
            for order in (
                [located, missing_z, missing_a],
                [missing_a, located, missing_z],
                [missing_z, missing_a, located],
            )
        ]
        for report, _failure_log in emissions:
            self.assertEqual(
                json.dumps(report, indent=2, sort_keys=True),
                json.dumps(baseline, indent=2, sort_keys=True),
            )
        logs = [failure_log for _report, failure_log in emissions]
        first_log, *other_logs = logs
        self.assertTrue(all(log == first_log for log in other_logs))
        discarded = first_log["discarded_findings"]
        self.assertEqual(
            [row["finding_id"] for row in discarded],
            ["a", "z"],
        )

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

    def test_schema_identifier_pattern_rejects_the_exact_control_and_bidi_set(self):
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
                    identifier_errors = [
                        error for error in errors
                        if error.validator == "pattern"
                        and error.validator_value == _IDENTIFIER_PATTERN
                    ]
                    self.assertEqual(len(identifier_errors), 1)
                    self.assertEqual(list(identifier_errors[0].path), expected_path)

    def test_every_identifier_pattern_accepts_control_and_bidi_range_neighbours(self):
        schema = _schema()
        candidate = schema["properties"]["candidates"]["items"]["properties"]
        patterns = {
            "occurrence.file": candidate["occurrences"]["items"]["properties"]["file"][
                "pattern"],
            "candidate.area": candidate["area"]["pattern"],
            "candidate.proposed_name": candidate["proposed_name"]["pattern"],
        }
        for field, pattern in patterns.items():
            self.assertEqual(pattern, _IDENTIFIER_PATTERN)
            validator = jsonschema.Draft7Validator({"type": "string", "pattern": pattern})
            for point in _ALLOWED_BOUNDARY_CODE_POINTS:
                with self.subTest(field=field, code_point="U+%04X" % point):
                    self.assertEqual(
                        list(validator.iter_errors("safe" + chr(point) + "value")),
                        [],
                    )

    def test_empty_paths_and_areas_remain_valid_but_a_proposed_name_is_kebab(self):
        # #2712 governs which code points may occur. Preserve the schema's
        # existing compatibility choice for paths and areas. #2713 layers a
        # non-empty kebab shape onto proposed_name.
        schema = _schema()
        validator = jsonschema.Draft7Validator(schema)
        setters = {
            "occurrence.file": lambda candidate: only(
                candidate["occurrences"], "occurrence").__setitem__("file", ""),
            "candidate.area": lambda candidate: candidate.__setitem__("area", ""),
        }
        for field, set_value in setters.items():
            with self.subTest(field=field):
                report = x0x.build_report(
                    [_f("SEC-X0X", "SEC", "MEDIUM", "honest candidate",
                        "src/package/widget.py")], {}, run_id="run-1")
                candidate = only(report["candidates"], "candidate")
                set_value(candidate)
                self.assertEqual(list(validator.iter_errors(report)), [])

        report = x0x.build_report(
            [_f("SEC-X0X", "SEC", "MEDIUM", "honest candidate",
                "src/package/widget.py")], {}, run_id="run-1")
        only(report["candidates"], "candidate")["proposed_name"] = ""
        self.assertTrue(list(validator.iter_errors(report)))

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
        baseline, *permuted = emitted
        for candidate_array in permuted:
            self.assertEqual(candidate_array, baseline)

        self.assertEqual(
            [(candidate["domain"], candidate.get("proposed_name"))
             for candidate in baseline],
            [("DAT", "critical-gap"),
             ("COD", "cache-read-gap"),
             ("COD", "cache-read-gap"),
             ("SEC", "shared-gap"),
             ("ARC", "beta-gap")])
        shared = next(candidate for candidate in baseline
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

    def test_extension_objects_stay_open_without_declaring_evidence_status(self):
        schema = _schema()
        candidate_schema = schema["properties"]["candidates"]["items"]
        occurrence_schema = candidate_schema["properties"]["occurrences"]["items"]
        self.assertNotIn("evidence_status", candidate_schema["properties"])
        self.assertNotIn("cwe", candidate_schema["required"])

        report = x0x.build_report(
            [_f("ARC-X0X", "ARC", "LOW", "open contract", "src/gap.py")],
            {"target": "repo"}, run_id="run-1")
        candidate = only(report["candidates"], "candidate")
        occurrence = only(candidate["occurrences"], "occurrence")
        report["extension"] = True
        report["generated_by"]["extension"] = True
        report["target"]["extension"] = True
        candidate["extension"] = True
        occurrence["extension"] = True
        self.assertIsNone(jsonschema.validate(report, schema))
        for node in (
                schema,
                schema["properties"]["generated_by"],
                schema["properties"]["target"],
                candidate_schema,
                occurrence_schema):
            self.assertNotEqual(node.get("additionalProperties"), False)
