"""Tests for scripts.synth.render: report writing, redaction, summary and compare rendering.
"""
import contextlib
import copy
import io
import os
import json
import tempfile
import unittest
from unittest import mock

import scripts.synth.corroborate as corroborate_mod
import scripts.synth.findings as findings_mod
import scripts.synth.render as render_mod
from scripts import host_disclosure, hosts

# Sentinel distinguishing "meta.host_capabilities key omitted entirely" from
# an explicit None value -- both are shapes render_summary must survive.
_OMIT = object()


class TestUncertifiedCoverageLine(unittest.TestCase):
    """#1644: what the terminal prints when there is no divergence to print."""

    def _summary(self, **summary):
        base = {"overall_grade": "B", "risk_level": "MEDIUM", "gate": "PASS",
                "coverage_certified": False, "evidence_stats": {},
                "stats": {}, "gate_severities": None}
        base.update(summary)
        return {"meta": {"target": "t", "coverage": {}, "integrity": {}},
                "summary": base, "findings": [], "groups": []}

    def test_the_reason_replaces_the_bare_word_incomplete(self):
        text = render_mod.render_summary(self._summary(
            coverage_note="tools manifest unreadable — tool coverage could not "
                          "be computed: tools-manifest.json is unreadable: x"))
        self.assertIn("NOT CERTIFIED", text)
        self.assertIn("tools manifest unreadable", text)
        self.assertNotIn("NOT CERTIFIED — incomplete", text)

    def test_a_note_and_a_divergence_are_both_printed(self):
        """#2013 review M5: the note is a peer of the divergence parts, not a
        fallback -- a delta-scope caveat must not vanish behind a panel gap."""
        rep = self._summary(coverage_note="delta scope inflated by suppressed git drivers")
        rep["meta"]["coverage"]["divergence"] = {
            "panels": {"security": {"executed": 1, "planned": 2}}}
        text = render_mod.render_summary(rep)
        self.assertIn("panels security 1/2", text)
        self.assertIn("delta scope inflated by suppressed git drivers", text)

    def test_with_no_note_and_no_divergence_it_still_says_something(self):
        text = render_mod.render_summary(self._summary(coverage_note=None))
        self.assertIn("NOT CERTIFIED — incomplete", text)


class TestCompareParts(unittest.TestCase):
    def test_read_json_report_merges_meta_parts(self):
        # #run7 ARC-D1A: --compare must merge split-report continuation parts, not
        # silently drop every part2+ finding.
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "r_part2.json"), "w") as fh:
                json.dump({"findings": [{"id": "F2"}],
                           "discarded_claims": [{"id": "D2"}]}, fh)
            main = os.path.join(d, "r.json")
            with open(main, "w") as fh:
                json.dump({"meta": {"parts": ["r_part2.json"]},
                           "summary": {"gate": "PASS"},
                           "findings": [{"id": "F1"}], "discarded_claims": []}, fh)
            rep = render_mod._read_json_report(main)
        self.assertEqual([f["id"] for f in rep["findings"]], ["F1", "F2"])
        self.assertEqual([x["id"] for x in rep["discarded_claims"]], ["D2"])
        self.assertEqual(rep["summary"]["gate"], "PASS")   # main meta/summary kept

    def test_read_json_report_missing_part_fails_loud(self):
        with tempfile.TemporaryDirectory() as d:
            main = os.path.join(d, "r.json")
            with open(main, "w") as fh:
                json.dump({"meta": {"parts": ["missing_part2.json"]},
                           "findings": []}, fh)
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                self.assertIsNone(render_mod._read_json_report(main))  # not a silent partial
            self.assertIn("incomplete", err.getvalue())

    def test_read_json_report_recovers_discarded_sibling_without_parts(self):
        # #run9 ARC-D1A: discarded_claims can spill to a <stem>-discarded.json
        # sibling INDEPENDENTLY of meta.parts, so --compare must follow that pointer
        # even when there are no parts -- else it drops every rejected claim.
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "r-discarded.json"), "w") as fh:
                json.dump({"discarded_claims": [{"id": "D1"}, {"id": "D2"}]}, fh)
            main = os.path.join(d, "r.json")
            with open(main, "w") as fh:
                json.dump({"meta": {"discarded_claims_file": "r-discarded.json"},
                           "summary": {"gate": "PASS"},
                           "findings": [{"id": "F1"}], "discarded_claims": []}, fh)
            rep = render_mod._read_json_report(main)
        self.assertEqual([f["id"] for f in rep["findings"]], ["F1"])
        self.assertEqual([x["id"] for x in rep["discarded_claims"]], ["D1", "D2"])

    def test_read_json_report_missing_discarded_sibling_fails_loud(self):
        with tempfile.TemporaryDirectory() as d:
            main = os.path.join(d, "r.json")
            with open(main, "w") as fh:
                json.dump({"meta": {"discarded_claims_file": "gone.json"},
                           "findings": []}, fh)
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                self.assertIsNone(render_mod._read_json_report(main))   # not a silent partial
            self.assertIn("incomplete", err.getvalue())

class TestGradeTextRendering(unittest.TestCase):
    def test_a_letter_renders_bare(self):
        self.assertEqual(render_mod._grade_text({"overall_grade": "B"}), "B")

    def test_a_held_letter_renders_provisional(self):
        self.assertEqual(render_mod._grade_text({"overall_grade": None,
                                          "provisional_grade": "C"}),
                         "C (provisional)")

    def test_no_letter_at_all_renders_n_a_not_the_word_none(self):
        # The old two-way format produced "None (provisional)" here, which reads
        # as a grade rather than as the absence of one.
        text = render_mod._grade_text({"overall_grade": None, "provisional_grade": None})
        self.assertNotIn("None", text)
        self.assertIn("n/a", text)

class TestRenderDelta(unittest.TestCase):
    """#449 Task 9: render_summary surfaces summary.delta -- on-diff counts,
    all-severity pre-existing counts, and a loud (advisory, non-gating)
    warning when pre-existing CRITICAL+HIGH > 0."""

    def _report(self, pre):
        return {
            "meta": {"target": "t"},
            "summary": {
                "overall_grade": "B",
                "risk_level": "MEDIUM",
                "gate": "PASS",
                "stats": {},
                "evidence_stats": {},
                "delta": {"on_diff": {"high": 1}, "pre_existing": pre},
            },
            "groups": [],
            "findings": [],
        }

    def test_warns_on_pre_existing_high(self):
        out = render_mod.render_summary(self._report({"critical": 0, "high": 2, "medium": 5, "low": 3}))
        self.assertIn("pre-existing", out.lower())
        self.assertEqual([line for line in out.splitlines() if line.startswith("**Pre-existing")],
                         ["**Pre-existing (files you touched, not gating):** HIGH 2, MEDIUM 5, LOW 3"])
        self.assertIn("⚠", out)  # loud warning glyph

    def test_no_warning_without_high(self):
        out = render_mod.render_summary(self._report({"critical": 0, "high": 0, "medium": 4, "low": 1}))
        self.assertNotIn("⚠", out)
        self.assertEqual([line for line in out.splitlines() if line.startswith("**Pre-existing")],
                         ["**Pre-existing (files you touched, not gating):** MEDIUM 4, LOW 1"])

    def test_counts_are_bound_to_the_pre_existing_severity(self):
        report = self._report({"high": 5, "medium": 2, "low": 4})
        report["meta"]["target"] = "unrelated digits 2 5 4"
        lines = render_mod.render_summary(report).splitlines()
        self.assertEqual([line for line in lines if line.startswith("**Pre-existing")],
                         ["**Pre-existing (files you touched, not gating):** HIGH 5, MEDIUM 2, LOW 4"])
        self.assertNotIn("**Pre-existing (files you touched, not gating):** HIGH 2, MEDIUM 5, LOW 3", lines)

    def test_delta_lines_placed_between_evidence_and_groups(self):
        r = self._report({"critical": 1, "high": 0, "medium": 0, "low": 0})
        out = render_mod.render_summary(r)
        lines = out.split("\n")
        ev_idx = next(i for i, ln in enumerate(lines) if ln.startswith("**Evidence:**"))
        groups_idx = next(i for i, ln in enumerate(lines) if ln == "## Groups")
        ondiff_idx = next(i for i, ln in enumerate(lines) if ln.startswith("**On-diff:**"))
        pre_idx = next(i for i, ln in enumerate(lines) if ln.startswith("**Pre-existing"))
        self.assertTrue(ev_idx < ondiff_idx < pre_idx < groups_idx)

    def test_no_delta_block_when_not_delta_mode(self):
        r = self._report({"critical": 0, "high": 0, "medium": 0, "low": 0})
        r["summary"]["delta"] = None
        out = render_mod.render_summary(r)
        self.assertNotIn("On-diff", out)
        self.assertNotIn("Pre-existing", out)

class TestHostCapabilitiesSurface(unittest.TestCase):
    """F3b Task 5, spec 5.1 surface 3: a person reading the report body must
    meet the host-capability limitation without opening JSON. Rendered
    through host_disclosure so this surface speaks with the same voice as
    the other three (driver stderr, meta.host_capabilities, X0X)."""

    def _report_with_posture(self, host_capabilities):
        meta = {"target": "t"}
        # Distinguish "key omitted entirely" from "key present but None" --
        # both are shapes render_summary must survive, and a bare
        # `meta["host_capabilities"] = host_capabilities` would collapse the
        # omitted case into an explicit None every time this helper is called
        # with None.
        if host_capabilities is not _OMIT:
            meta["host_capabilities"] = host_capabilities
        return {
            "meta": meta,
            "summary": {"overall_grade": "B", "risk_level": "MEDIUM", "gate": "PASS",
                       "stats": {}, "evidence_stats": {}},
            "groups": [],
            "findings": [],
        }

    def test_the_body_names_the_unproven_capabilities(self):
        # Genuinely mixed (plan Global Constraints): all five capabilities
        # named explicitly, spread across proven/refuted/unknown on
        # DIFFERENT capabilities, so this cannot pass by hard-coding one.
        md = render_mod.render_summary(self._report_with_posture({
            "host": "claude",
            "capabilities": {
                hosts.TOOL_POLICY_ENFORCED: {
                    "state": hosts.REFUTED, "by": "shadow-shell-scan",
                    "detail": "ships panopticon-scout.md"},
                hosts.ARTIFACT_WRITE_GUARD: {
                    "state": hosts.PROVEN, "by": "write-guard-armed",
                    "detail": "round-trip denied"},
                hosts.USAGE_LEDGER: {
                    "state": hosts.UNKNOWN, "by": None,
                    "detail": "no transcript directory"},
                hosts.READ_SCOPE_CONFINED: {
                    "state": hosts.UNKNOWN, "by": None,
                    "detail": "claude proves this since plan 5; other hosts do not claim it"},
                hosts.MODEL_BINDING: {
                    "state": hosts.UNKNOWN, "by": None,
                    "detail": "model=None until F4 binds them"},
            },
        }))
        self.assertIn("**Host capabilities:**", md)
        self.assertIn(hosts.TOOL_POLICY_ENFORCED, md)
        # "shadow-shell-scan" (the `by` probe id) only appears in the
        # per-capability GAP line, never in the headline -- this is what
        # discriminates "headline rendered, gap lines dropped" (M2) from a
        # correct render.
        self.assertIn("shadow-shell-scan", md)
        self.assertIn(hosts.USAGE_LEDGER, md)
        # the proven one is not listed as a gap
        gap_block = md.split("**Host capabilities:**")[1].split("\n\n")[0]
        self.assertNotIn(hosts.ARTIFACT_WRITE_GUARD, gap_block)

    def test_an_all_proven_report_states_it_rather_than_staying_silent(self):
        # The synthetic fixture pins the shape; claude proves read_scope_confined
        # since plan 5, other hosts do not claim it, and hosts.posture()'s
        # claim-mask forces an unclaimed capability to unknown no matter what
        # the evidence says. Patch in a synthetic host that claims all five,
        # same pattern as test_host_disclosure.py
        # / test_host_evidence_wiring.py, so this fixture genuinely reaches
        # zero gaps under the real posture().
        all_claims = hosts.HostSpec(name="proves-everything",
                                    claims=frozenset(hosts.CAPABILITIES))
        assert host_disclosure.hosts is hosts, (
            "host_disclosure's hosts import has drifted from the canonical "
            "scripts.hosts module -- patching hosts.HOSTS below would be a "
            "silent no-op")
        with mock.patch.dict(hosts.HOSTS, {"proves-everything": all_claims}):
            md = render_mod.render_summary(self._report_with_posture({
                "host": "proves-everything",
                "capabilities": {c: {"state": hosts.PROVEN, "by": "p", "detail": "d"}
                                 for c in hosts.CAPABILITIES},
            }))
        self.assertIn("**Host capabilities:**", md)
        # The literal constant, not the bare word "PROVEN": "NOT PROVEN"
        # contains "PROVEN" as a substring, so a report that is actually 1 of
        # 5 NOT PROVEN would satisfy assertIn("PROVEN", md) too and prove
        # nothing. The full ALL_PROVEN sentence is unique to the zero-gap
        # branch; assertNotIn("NOT PROVEN") closes the substring escape hatch
        # from the other side.
        self.assertIn(host_disclosure.ALL_PROVEN, md)
        self.assertNotIn("NOT PROVEN", md)

    def test_a_report_with_no_posture_says_nobody_looked(self):
        md = render_mod.render_summary(self._report_with_posture(None))
        self.assertIn(host_disclosure.NO_EVIDENCE, md)

    def test_an_omitted_host_capabilities_key_also_says_nobody_looked(self):
        # meta.host_capabilities being ABSENT (a report.json older than this
        # feature, or any hand-built summary) is a distinct shape from an
        # explicit None -- `.get("host_capabilities")` must survive both, not
        # just the one the brief spelled out.
        md = render_mod.render_summary(self._report_with_posture(_OMIT))
        self.assertIn(host_disclosure.NO_EVIDENCE, md)

    def test_a_malformed_host_capabilities_does_not_crash(self):
        # meta.host_capabilities is a FILE ON DISK's parsed JSON, reachable
        # from --compare on a foreign report -- it can be any JSON shape, not
        # only the dict report.py's own assemble() always produces. Must
        # render "nobody looked", never raise mid-render.
        for bad in ([1, 2, 3], "garbage", 5):
            with self.subTest(bad=bad):
                md = render_mod.render_summary(self._report_with_posture(bad))
                self.assertIn(host_disclosure.NO_EVIDENCE, md)


class TestReportSecretRedaction(unittest.TestCase):
    """#run7 SEC-B2C: secrets a reviewer quoted-but-didn't-redact must be masked
    before the report reaches any shareable artifact (report.json/html/x0x)."""

    def test_redacts_findings_and_discarded_claims(self):
        secret = "ghp_" + "Z" * 36
        report = {
            "findings": [{"id": "F1", "severity": "HIGH", "line_start": 3,
                          "description": "leaked %s here" % secret,
                          "references": ["see %s" % secret]}],
            "discarded_claims": [{"id": "D1", "reason": "quoted %s" % secret}],
        }
        render_mod.redact_report_secrets(report)
        blob = json.dumps(report)
        self.assertNotIn(secret, blob)
        self.assertIn("[REDACTED_TOKEN]", report["findings"][0]["description"])
        self.assertIn("[REDACTED_TOKEN]", report["findings"][0]["references"][0])
        self.assertIn("[REDACTED_TOKEN]", report["discarded_claims"][0]["reason"])
        # structured scalars survive
        self.assertEqual(report["findings"][0]["severity"], "HIGH")
        self.assertEqual(report["findings"][0]["line_start"], 3)

    def test_no_findings_or_discarded_is_safe(self):
        r = {"findings": []}
        render_mod.redact_report_secrets(r)
        self.assertEqual(r["findings"], [])

    def test_redacts_every_section_not_just_findings(self):
        """#1634: the backstop walks the WHOLE report. Two keys was a list a
        producer had to be remembered for -- summary.top_issues and
        groups[].key_findings were derived from finding titles and never
        revisited, and meta/cross_panel/delta were never covered at all."""
        secret = "ghp_" + "Z" * 36
        report = {
            "meta": {"coverage": {"adapters": {
                "gitleaks": {"status": "ok", "reason": "found %s" % secret}}}},
            "summary": {"top_issues": ["leak %s" % secret], "gate": "FAIL"},
            "groups": [{"name": "app", "key_findings": ["leak %s" % secret]}],
            "findings": [],
            "cross_panel": {"integration_findings": [
                {"severity": "HIGH", "note": "quoted %s" % secret}]},
            "delta": {"note": "on-diff %s" % secret},
        }
        render_mod.redact_report_secrets(report)
        self.assertNotIn(secret, json.dumps(report))
        self.assertEqual(report["summary"]["top_issues"],
                         ["leak [REDACTED_TOKEN]"])
        self.assertEqual(report["groups"][0]["key_findings"],
                         ["leak [REDACTED_TOKEN]"])
        self.assertIn("[REDACTED_TOKEN]",
                      report["meta"]["coverage"]["adapters"]["gitleaks"]["reason"])
        self.assertIn("[REDACTED_TOKEN]",
                      report["cross_panel"]["integration_findings"][0]["note"])
        self.assertIn("[REDACTED_TOKEN]", report["delta"]["note"])
        self.assertEqual(report["summary"]["gate"], "FAIL")

    def test_structured_sections_survive_the_walk(self):
        """The patterns mask well-formed secrets only, so walking meta changes
        nothing that is not one -- host_capabilities (copied verbatim off the
        probe artifact), integrity hashes and file paths come back identical."""
        report = {
            "schema_version": 1,
            "meta": {
                "target": "src", "timestamp": "2026-09-15T00:00:00Z",
                "integrity": {"out_file_hashes": {"findings-app-SEC.json":
                                                  "sha256:" + "a" * 64}},
                "host_capabilities": {
                    "host": "claude", "schema_version": 1,
                    "probed_at": "2026-09-15T00:00:00Z",
                    "capabilities": {"tool_policy_enforced": {
                        "state": "proven", "by": "probe:settings",
                        "detail": "deny rule at ~/.claude/settings.json",
                        "guid": "3f2504e0-4f89-11d3-9a0c-0305e82c3301"}}},
            },
            "groups": [{"name": "app", "files": ["app/x.py"]}],
            "findings": [],
        }
        before = copy.deepcopy(report)
        render_mod.redact_report_secrets(report)
        self.assertEqual(report, before)

    def test_mutates_in_place_and_keeps_key_order(self):
        """Callers read the SAME dict afterwards (write_report, the X0X and
        HTML producers, render_summary), and write_report dumps insertion
        order -- key order is part of the artifact."""
        report = {"schema_version": 1, "meta": {"target": "src"},
                  "summary": {"gate": "PASS"}, "groups": [], "findings": [],
                  "cross_panel": {}, "discarded_claims": []}
        original = report
        returned = render_mod.redact_report_secrets(report)
        self.assertIs(returned, original)
        self.assertEqual(list(report), ["schema_version", "meta", "summary",
                                        "groups", "findings", "cross_panel",
                                        "discarded_claims"])

class TestWriteReportDiscardedSplit(unittest.TestCase):
    """#15: a large discarded_claims set (unbounded in the REJECTED count, which
    grows when verification works well) must not floor chunk_limit into one finding
    per part (417 files on run-6). It's written to a sibling artifact instead."""

    def _report(self, n_findings, n_discarded):
        return {
            "meta": {"coverage": {}},
            "findings": [{"id": "F%d" % i, "severity": "LOW", "desc": "d" * 250}
                         for i in range(n_findings)],
            "discarded_claims": [{"id": "D%d" % i, "reason": "x" * 400}
                                 for i in range(n_discarded)],
        }

    def test_large_discarded_split_to_sibling_bounded_parts(self):
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "report.json")
            report = self._report(n_findings=60, n_discarded=200)   # ~80KB discarded
            with contextlib.redirect_stderr(io.StringIO()):
                written = render_mod.write_report(report, out, max_bytes=8000)
            disc = os.path.join(d, "report-discarded.json")
            self.assertIn(disc, written)
            self.assertTrue(os.path.isfile(disc))
            with open(out, encoding="utf-8") as fh:
                main = json.load(fh)
            self.assertEqual(main.get("discarded_claims"), [])
            self.assertEqual(main["meta"]["discarded_claims_count"], 200)
            self.assertEqual(main["meta"]["discarded_claims_file"], "report-discarded.json")
            with open(disc, encoding="utf-8") as fh:
                self.assertEqual(len(json.load(fh)["discarded_claims"]), 200)
            parts = [p for p in written if "_part" in p]
            self.assertGreater(len(parts), 0)     # findings still needed splitting
            self.assertLess(len(parts), 30)       # bounded — old bug: ~60 parts

    def test_sibling_replace_failure_leaves_no_dangling_main_report(self):
        # #run7 COD-F1A: the small-report branch used to commit the MAIN report
        # (with meta.discarded_claims_file set) before the sibling, so a failed
        # sibling write left the main report pointing at a file that never
        # existed. Committing the pointed-to sibling first means a sibling
        # failure aborts before the main is written -- no dangling pointer.
        real_replace = os.replace

        def flaky(src, dst):
            if "discarded" in os.path.basename(dst):
                raise OSError("boom writing sibling")
            return real_replace(src, dst)

        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "report.json")
            # 1 finding but a big discarded set -> sibling split + small branch.
            report = self._report(n_findings=1, n_discarded=200)
            with mock.patch("os.replace", side_effect=flaky):
                with self.assertRaises(OSError):
                    render_mod.write_report(report, out, max_bytes=2000)
            self.assertFalse(os.path.exists(out))            # main never committed
            self.assertFalse(os.path.exists(
                os.path.join(d, "report-discarded.json")))    # sibling not left
            self.assertEqual(os.listdir(d), [])               # no stray temps

    def test_base_over_max_is_loud_not_silent(self):
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "report.json")
            report = {"meta": {"bloat": "y" * 20000},
                      "findings": [{"id": "F%d" % i, "desc": "d" * 250} for i in range(5)]}
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                render_mod.write_report(report, out, max_bytes=8000)
            self.assertIn("report base is", err.getvalue())   # loud, not silent floor


class TestSuppressedToolFindingsAreRendered(unittest.TestCase):
    """#1578: what the vendored-path exclusion dropped is named in the markdown
    summary, not only in the JSON.

    An operator reading the summary had no way to tell a bundled jQuery from a
    payload parked under `app/vendor/` -- the only signal was an aggregate
    stderr line from a process that had already exited.
    """

    def _report(self, suppressed):
        return {"meta": {"target": "src", "coverage": {"tools_suppressed": suppressed}},
                "summary": {"grade": "B", "risk_level": "MEDIUM", "gate": "PASS",
                            "stats": {}, "evidence_stats": {"unverified": 1},
                            "coverage_certified": True},
                "groups": [], "findings": []}

    def test_the_segments_and_counts_are_named(self):
        out = render_mod.render_summary(self._report({"vendor": 592, "node_modules": 3}))
        self.assertIn("vendor: 592", out)
        self.assertIn("node_modules: 3", out)

    def test_a_run_that_suppressed_nothing_says_nothing(self):
        self.assertNotIn("suppressed", render_mod.render_summary(self._report({})))

    def test_a_malformed_block_renders_no_line_rather_than_a_traceback(self):
        for bad in ("nope", 7, ["vendor"], None):
            with self.subTest(value=repr(bad)):
                self.assertNotIn(
                    "suppressed", render_mod.render_summary(self._report(bad)))


class TestExcludedToolFindingsAreRendered(unittest.TestCase):
    def _report(self, excluded=_OMIT):
        coverage = {"tools_suppressed": {"vendor": 2}}
        if excluded is not _OMIT:
            coverage["tools_excluded"] = excluded
        return {"meta": {"target": "src", "coverage": coverage},
                "summary": {"overall_grade": "B", "risk_level": "MEDIUM",
                            "gate": "PASS", "stats": {}, "evidence_stats": {},
                            "coverage_certified": True},
                "groups": [], "findings": []}

    def test_count_and_every_glob_appear_beside_suppression(self):
        out = render_mod.render_summary(self._report(
            {"count": 3, "globs": ["vendor/**", "tests/fixtures/**"]}))
        self.assertIn("**Tool findings excluded by policy:** 3", out)
        self.assertIn("`\"vendor/**\"`", out)
        self.assertIn("`\"tests/fixtures/**\"`", out)
        self.assertIn("**Tool findings suppressed:** vendor: 2", out)

    def test_the_venv_tally_rows_say_what_they_rest_on(self):
        # #1839: this line is about findings dropped on a directory NAME, and
        # three of the rows it now carries are not that -- `pyvenv.cfg:<dir>`
        # counts findings dropped on a `pyvenv.cfg` the target WROTE, and the two
        # CLASS keys count virtualenv DIRECTORIES the scan never entered (review
        # round 1 I4 added the name-only half of that). Surfacing them here
        # without saying so would trade a silence for a misstatement.
        for key, shown in ((render_mod.MARKER_VENV_SEGMENT,
                            "virtualenv-by-marker: 1"),
                           (render_mod.NAME_VENV_SEGMENT,
                            "virtualenv-by-name: 1"),
                           (render_mod.MARKER_VENV_PREFIX + "app/venv",
                            "pyvenv.cfg:'app/venv': 1")):
            with self.subTest(key=key):
                report = self._report()
                report["meta"]["coverage"]["tools_suppressed"] = {
                    "vendor": 2, key: 1}
                out = render_mod.render_summary(report)
                self.assertIn(shown, out)
                self.assertIn("NAME A CLASS", out)
                self.assertIn("DIRECTORIES the SCAN was told to skip", out)
        # And not a word of it on a run with no such row.
        self.assertNotIn("NAME A CLASS", render_mod.render_summary(self._report()))

    def test_a_target_authored_tally_key_is_escaped_and_capped(self):
        # Review round 1 I3: the `<dir>` half of a `pyvenv.cfg:<dir>` key is a
        # path out of the reviewed tree. A newline in it forged a second line
        # that read like this one, and there is a row per virtualenv, so a
        # monorepo mints dozens -- the JSON keeps them all, this line does not.
        rows = {"pyvenv.cfg:v%02d" % i: 1 for i in range(15)}
        rows["pyvenv.cfg:hostile\x1b[2J\n**Tool findings suppressed:** none"] = 3
        report = self._report()
        report["meta"]["coverage"]["tools_suppressed"] = rows
        out = render_mod.render_summary(report)
        lines = [ln for ln in out.splitlines()
                 if "**Tool findings suppressed:**" in ln]
        self.assertEqual(len(lines), 1, out)
        self.assertNotIn("\x1b", out)
        self.assertIn("pyvenv.cfg:'hostile\\x1b[2J\\n", lines[0])
        self.assertIn("and 6 more (see meta.coverage.tools_suppressed)", lines[0])

    def test_measured_zero_with_or_without_policy_is_explicit(self):
        for globs in (["vendor/**"], []):
            with self.subTest(globs=globs):
                out = render_mod.render_summary(self._report(
                    {"count": 0, "globs": globs}))
                self.assertIn("**Tool findings excluded by policy:** 0", out)
                self.assertEqual('`"vendor/**"`' in out, bool(globs))

    def test_legacy_missing_and_malformed_optional_block_do_not_claim_zero(self):
        for excluded in (_OMIT, None, "bad", {"count": "many", "globs": []},
                         {"count": 1, "globs": "bad"}):
            with self.subTest(excluded=excluded):
                out = render_mod.render_summary(self._report(excluded))
                self.assertNotIn("Tool findings excluded by policy", out)
                self.assertIn("**Tool findings suppressed:** vendor: 2", out)

    def test_hostile_glob_cannot_inject_a_markdown_heading(self):
        glob = '<script>" & `x`\n## Forged section'
        out = render_mod.render_summary(self._report(
            {"count": 1, "globs": [glob]}))
        self.assertIn("**Tool findings excluded by policy:** 1", out)
        self.assertIn(r'\n## Forged section', out)
        self.assertNotIn("\n## Forged section", out)
        self.assertIn('<script>', out)
        self.assertIn('" &', out)


class TestTargetConfigLine(unittest.TestCase):
    """#1681 Plan 2: the summary says when a target's config was refused."""

    def _report(self, config):
        return {"schema_version": 1,
                "meta": {"target": "src", "coverage": {}, "integrity": {},
                         **({"config": config} if config is not None else {})},
                "summary": {"overall_grade": "B", "risk_level": "MEDIUM",
                            "gate": "PASS", "coverage_certified": True,
                            "evidence_stats": {}, "stats": {},
                            "gate_severities": None},
                "findings": [], "groups": []}

    def test_the_summary_names_a_refused_or_clamped_config(self):
        text = render_mod.render_summary(self._report({
            "requested": {"tools": False, "max_per_group": 5000},
            "effective": {"max_per_group": 48},
            "refused": [{"key": "tools", "value": False,
                         "reason": "loosens the built-in default `true`"}],
            "clamped": [{"key": "max_per_group", "requested": 5000, "effective": 48}],
            "disclosures": []}))
        self.assertIn("**Target config:**", text)
        self.assertIn("`tools: false` refused", text)
        self.assertIn("`max_per_group: 5000` clamped to 48", text)

    def test_a_long_key_is_bounded_the_same_way_the_value_is(self):
        # Final review M7: the line bounded the target-authored VALUE at 80
        # characters and interpolated the target-authored KEY raw -- bounded
        # only by `load_resolution`'s own 300, on a line a human reads.
        long_key = "k" * 300
        text = render_mod.render_summary(self._report({
            "requested": {}, "effective": {},
            "refused": [{"key": long_key, "value": 1, "reason": "unknown key"}],
            "clamped": [{"key": long_key, "requested": 5000, "effective": 48}],
            "disclosures": []}))
        self.assertIn("`" + "k" * render_mod._CFG_VALUE_MAX + "\u2026", text)
        self.assertNotIn("k" * (render_mod._CFG_VALUE_MAX + 1), text)

    def test_the_summary_is_silent_when_nothing_was_refused_or_clamped(self):
        text = render_mod.render_summary(self._report(
            {"requested": {"max_per_group": 20}, "effective": {"max_per_group": 20},
             "refused": [], "clamped": [], "disclosures": []}))
        self.assertNotIn("Target config", text)

    def test_a_report_without_meta_config_still_renders(self):
        # A pre-Plan-2 report.json re-rendered by a current synthesize.
        self.assertIn("**Grade:**", render_mod.render_summary(self._report(None)))


class TestTheSummaryPrintsNoLiveControlBytes(unittest.TestCase):
    r"""#1829 SEC-798292895: the terminal summary was built from raw target text.

    `render_summary`'s only caller is `print(render_summary(report))` -- a
    direct `synthesize.py` run's terminal -- and, on the driver path, a 400-char
    excerpt of it on failure. A hostile scanned repo could therefore make the
    Top-findings line clear the operator's screen and read `** clean **`:
    `\x1b[2J\x1b[H` erases it, `\r` overwrites the line, `\x07` rings the bell.

    The finding FIELDS are fixed at the normalization boundary (so every
    renderer inherits it); `meta.target`, `groups[].name` and the target's own
    config values are not normalization's to own, so they are neutralized here.
    """

    HOSTILE = "ok\x1b[2J\x1b[H** clean **\x07\x00"
    HAZARDS = frozenset(chr(o) for o in
                        list(range(0x00, 0x20)) + [0x7f]
                        + list(range(0x80, 0xa0)) + [0x2028, 0x2029])

    def _report(self):
        finding = findings_mod.normalize_finding({
            "id": "SG-001", "title": self.HOSTILE, "severity": "HIGH",
            "confidence": "CERTAIN", "panel": "security",
            "category": "r\x1b[31m1", "source": "tool:semgrep",
            "location": {"file": "a\x1b[2Kb.py", "line_start": 3},
            "impact": self.HOSTILE, "remediation": self.HOSTILE})
        return {"schema_version": 1,
                # The cross-domain Note prints an AGENT-authored domain, which
                # `synth/integrity` only isinstance-checks (fix round 1,
                # finding 2): a third field normalization does not own.
                "meta": {"target": "/t\x1b[2Karget", "coverage": {},
                         "integrity": {"cross_domain_findings": [
                             {"file": "f", "cell_domain": "ARC", "code": "TST-X0X",
                              "finding_domain": "TST\x1b[2J\rdriver: all clear\x07"}]},
                         "config": {"requested": {}, "effective": {},
                                    "refused": [{"key": "k\x1b[2J",
                                                 "value": "v\x07",
                                                 "reason": "unknown key"}],
                                    "clamped": [], "disclosures": []}},
                "summary": {"overall_grade": "D", "risk_level": "HIGH",
                            "gate": "OFF", "coverage_certified": True,
                            "evidence_stats": {"unverified": 1},
                            "stats": {"HIGH": 1}, "gate_severities": None},
                "findings": [finding],
                "groups": [{"name": "G\x1b[31mX",
                            "panel_grades": {p: "C" for p in findings_mod.PANEL_ORDER}}]}

    def _live_bytes(self, text):
        return sorted({"0x%02x" % ord(ch) for ch in text if ch in self.HAZARDS
                       and ch != "\n"})

    def test_no_line_of_the_markdown_carries_a_live_control_byte(self):
        out = render_mod.render_summary(self._report())
        self.assertEqual([], self._live_bytes(out),
                         "\n".join(repr(line) for line in out.splitlines()
                                   if self._live_bytes(line)))

    def test_every_neutralized_field_is_still_legible_as_evidence(self):
        out = render_mod.render_summary(self._report())
        for expected in (r"# panopticon — /t\x1b[2Karget",        # meta.target
                         r"- **G\x1b[31mX** — code C",            # groups[].name
                         r"**ok\x1b[2J\x1b[H** clean **\x07\x00**",  # finding title
                         r"a\x1b[2Kb.py:3",                       # location.file
                         r"`k\x1b[2J: v\x07` refused",            # target config
                         "ARC\u2192TST" + r"\x1b[2J\x0ddriver: all clear\x07"
                         + " \u00d71"):                            # cross-domain Note
            with self.subTest(line=expected):
                self.assertIn(expected, out)

    def test_the_target_path_is_kept_byte_for_byte(self):
        # Re-review nit: `meta.target` is a PATH, so it renders in path mode --
        # a real directory named with two spaces is escaped and bounded and
        # otherwise untouched, never renamed to one space.
        report = self._report()
        report["meta"]["target"] = "/t  arget\x1b[2K"
        out = render_mod.render_summary(report)
        self.assertIn(r"# panopticon — /t  arget\x1b[2K", out)

    def test_a_cross_panel_entry_inherits_the_boundary_rather_than_a_second_fix(self):
        # The cross-panel block prints `location.file` and `categories` -- both
        # COPIED from normalized findings by `corroborate`, which is why the
        # renderer does not neutralize them a second time. If that ever stops
        # being true, this fails and the belt-and-braces moves here.
        pair = [findings_mod.normalize_finding(
                    {"id": "SG-00%d" % n, "title": "t", "severity": "HIGH",
                     "confidence": "CERTAIN", "panel": panel,
                     "category": "x\x07y",
                     "location": {"file": "c\x1b[2Kd.py", "line_start": 2}})
                for n, panel in ((1, "security"), (2, "architecture"))]
        integration = corroborate_mod.cross_panel_corroboration(pair)
        self.assertEqual(1, len(integration), integration)
        report = self._report()
        report["cross_panel"] = {"integration_findings": integration}
        out = render_mod.render_summary(report)
        self.assertEqual([], self._live_bytes(out))
        # `evidence.norm_path` -- the clustering key every consumer agrees on --
        # rewrites a backslash as a slash, so the escape an inert path carries
        # reads as a directory here. Cosmetic, hostile-paths-only, and applied to
        # both sides of every comparison; pinned so a change to it is visible.
        self.assertIn("c/x1b[2Kd.py:2", out)
        self.assertIn(r"x\x07y", out)
