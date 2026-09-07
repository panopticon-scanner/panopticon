"""Tests for scripts.synth.findings: loading, normalizing, deduping and
reinforcing findings, the doc-tree severity policy, FindingSet.load.
"""
import contextlib
import io
import os
import json
import tempfile
import unittest
import scripts.phases.runio as runio

import scripts.synthesize as syn
import scripts.synth.findings as findings_mod
import scripts.synth.integrity as integrity_mod
import scripts.synth.report as report_mod
import scripts.evidence as evidence_mod

from tests.synth.helpers import DEFAULT_TIMESTAMP, _chdir, _make_finding, _cli_args


class TestNormalize(unittest.TestCase):
    def test_verdict_maps_to_confidence(self):
        f = findings_mod.normalize_finding({"severity": "high", "verdict": "CONFIRMED", "panel": "security"})
        self.assertEqual(f["severity"], "HIGH")
        self.assertEqual(f["confidence"], "CERTAIN")

    def test_plausible_maps_to_likely(self):
        f = findings_mod.normalize_finding({"verdict": "PLAUSIBLE"})
        self.assertEqual(f["confidence"], "LIKELY")

    def test_unlabeled_defaults_possible(self):
        f = findings_mod.normalize_finding({"severity": "MEDIUM"})
        self.assertEqual(f["confidence"], "POSSIBLE")

    def test_invalid_severity_becomes_info(self):
        f = findings_mod.normalize_finding({"severity": "sorta-bad"})
        self.assertEqual(f["severity"], "INFO")

    def test_normalize_accepts_new_panels(self):
        for panel in ["architecture", "database", "redteam"]:
            f = findings_mod.normalize_finding({"panel": panel, "title": "x", "description": "y"})
            self.assertEqual(f["panel"], panel)

    def test_normalize_defaults_unknown_panel_to_code(self):
        f = findings_mod.normalize_finding({"panel": "unknown", "title": "x"})
        self.assertEqual(f["panel"], "code")

    def test_normalize_omits_empty_lens(self):
        f = findings_mod.normalize_finding({"title": "x"})
        self.assertNotIn("lens", f)

    def test_normalize_preserves_nonempty_lens(self):
        f = findings_mod.normalize_finding({"title": "x", "lens": "injection"})
        self.assertEqual(f["lens"], "injection")

    def test_normalize_bridges_line_to_line_start(self):
        # #5.0-04: agents emit location {file, line}; the pipeline keys line_start.
        f = findings_mod.normalize_finding({"title": "x", "location": {"file": "a.py", "line": 7}})
        self.assertEqual(f["location"]["line_start"], 7)
        self.assertNotIn("line", f["location"])

    def test_normalize_does_not_override_explicit_line_start(self):
        f = findings_mod.normalize_finding(
            {"title": "x", "location": {"file": "a.py", "line": 7, "line_start": 3}}
        )
        self.assertEqual(f["location"]["line_start"], 3)

    def test_location_coerced(self):
        f = findings_mod.normalize_finding({"location": {"file": "a.py", "line_start": 10}})
        self.assertEqual(f["location"]["line_end"], 10)

class TestNormalizeCodeDomain(unittest.TestCase):
    def test_code_and_domain_pass_through(self):
        f = findings_mod.normalize_finding({"code": "SEC-A1A", "domain": "SEC", "panel": "security"})
        self.assertEqual(f["code"], "SEC-A1A")
        self.assertEqual(f["domain"], "SEC")

    def test_panel_backfilled_from_domain_when_absent(self):
        # a domain-scoped finding with no valid panel gets panel from the map
        f = findings_mod.normalize_finding({"code": "DAT-A1A", "domain": "DAT"})
        self.assertEqual(f["panel"], "database")

    def test_panel_backfilled_for_domain_without_legacy_panel(self):
        f = findings_mod.normalize_finding({"code": "OPS-A1A", "domain": "OPS"})
        self.assertEqual(f["panel"], "code")  # OPS has no legacy panel -> code

    def test_explicit_valid_panel_is_not_overridden(self):
        f = findings_mod.normalize_finding({"domain": "SEC", "panel": "database"})
        self.assertEqual(f["panel"], "database")  # caller's valid panel wins

    def test_no_domain_no_code_is_unchanged_behavior(self):
        f = findings_mod.normalize_finding({"title": "x"})
        self.assertEqual(f["panel"], "code")  # existing default
        self.assertNotIn("code", f)

class TestLoad(unittest.TestCase):
    def test_tolerant_json_with_fences(self):
        body = '```json\n{"findings": [{"severity": "LOW"}]}\n```'
        data = evidence_mod.load_json_tolerant(body)
        self.assertEqual(len(data["findings"]), 1)

    def test_load_findings_skips_missing(self):
        with tempfile.TemporaryDirectory() as d:
            good = os.path.join(d, "findings-x-code.json")
            with open(good, "w") as fh:
                json.dump({"findings": [{"severity": "HIGH", "panel": "code"}]}, fh)
            findings = findings_mod.load_findings([good, os.path.join(d, "missing.json")])
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["confidence"], "POSSIBLE")

    def test_load_findings_skips_non_dict_toplevel(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "findings-x-code.json")
            with open(p, "w") as fh:
                fh.write("[1, 2, 3]")
            self.assertEqual(findings_mod.load_findings([p]), [])

    def test_load_findings_skips_non_dict_finding_entries(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "findings-x-code.json")
            with open(p, "w") as fh:
                json.dump({"findings": ["oops", {"severity": "LOW", "panel": "code"}]}, fh)
            out = findings_mod.load_findings([p])
            self.assertEqual(len(out), 1)
            self.assertEqual(out[0]["severity"], "LOW")

    def test_tolerant_json_with_prose_around_object(self):
        # The regex fallback: panel output wrapped in prose (no code fence).
        body = 'Sure, here is the JSON:\n{"findings": [{"severity": "LOW"}]}\nHope that helps!'
        self.assertEqual(evidence_mod.load_json_tolerant(body), {"findings": [{"severity": "LOW"}]})

    def test_load_findings_skips_invalid_json_and_continues(self):

        with tempfile.TemporaryDirectory() as d:
            bad = os.path.join(d, "findings-g-code.json")
            good = os.path.join(d, "findings-g-test.json")
            with open(bad, "w") as fh:
                fh.write("{ not valid json ")
            with open(good, "w") as fh:
                json.dump(
                    {
                        "findings": [
                            {
                                "severity": "LOW",
                                "panel": "test",
                                "location": {"file": "a.py", "line_start": 1},
                            }
                        ]
                    },
                    fh,
                )
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                out = findings_mod.load_findings([bad, good])
            self.assertIn("PARSE ERROR", err.getvalue())
            self.assertEqual(len(out), 1)  # good file still processed

    def test_load_findings_skips_non_list_findings_key(self):

        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "findings-g-code.json")
            with open(p, "w") as fh:
                json.dump({"findings": "not-a-list"}, fh)
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                out = findings_mod.load_findings([p])
            self.assertIn("no findings list", err.getvalue())
            self.assertEqual(out, [])

    def test_load_findings_strips_forged_trust_fields(self):
        # #983: trust fields the pipeline derives must never come from an agent
        # payload. A forged `corroborated`/`corroborated_by` self-certifies
        # cross-panel verification (evidence status `corroborated` + a triage
        # queue-jump); `source`/`reinforced` are the pre-existing cases.
        # `evidence` (5.0 P5 Slice B, R1): evidence.status is ALWAYS derived by
        # derive_evidence from a real verdict bundle -- never self-asserted -- and
        # score_gate reads it straight off the finding, so a forged
        # `evidence: {"status": "rejected"}` (factor 0.0) would let a finding
        # duck the matrix's F_p/F_b verification gate entirely. All five are
        # stripped in load_findings, before any derivation runs.

        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "findings-g-code.json")
            with open(p, "w") as fh:
                json.dump(
                    {
                        "findings": [
                            {
                                "severity": "HIGH",
                                "panel": "code",
                                "location": {"file": "a.py", "line_start": 1},
                                "source": "tool:semgrep",
                                "reinforced": True,
                                "corroborated": True,
                                "corroborated_by": ["security", "test"],
                                "evidence": {"status": "rejected"},
                            }
                        ]
                    },
                    fh,
                )
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                out = findings_mod.load_findings([p])
            self.assertEqual(len(out), 1)
            for forged in ("source", "reinforced", "corroborated", "corroborated_by", "evidence"):
                self.assertNotIn(forged, out[0])
            self.assertIn("stripped self-asserted", err.getvalue())

class TestDedupe(unittest.TestCase):
    def test_merges_same_location_and_category(self):
        findings = [
            {
                "severity": "LOW",
                "confidence": "POSSIBLE",
                "category": "injection",
                "location": {"file": "a.rb", "line_start": 10},
            },
            {
                "severity": "HIGH",
                "confidence": "CERTAIN",
                "category": "injection",
                "location": {"file": "a.rb", "line_start": 10},
            },
        ]
        out = findings_mod.dedupe(findings)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["severity"], "HIGH")

    def test_same_source_distinct_categories_kept_separate(self):
        # Same source (no cross-source corroboration), different categories at
        # the same file+line: these are genuinely distinct findings and must
        # NOT be merged just because they share a locus.
        findings = [
            {
                "severity": "HIGH",
                "confidence": "CERTAIN",
                "category": "injection",
                "location": {"file": "a.rb", "line_start": 10},
            },
            {
                "severity": "HIGH",
                "confidence": "CERTAIN",
                "category": "structure",
                "location": {"file": "a.rb", "line_start": 10},
            },
        ]
        self.assertEqual(len(findings_mod.dedupe(findings)), 2)

    def test_two_agent_findings_same_line_both_kept(self):
        # Two agent-sourced findings (different panels/categories) at the same
        # file+line are NOT cross-source corroboration -> kept separate.
        findings = [
            {
                "severity": "HIGH",
                "confidence": "LIKELY",
                "panel": "code",
                "category": "structure",
                "source": "agent:code-reviewer",
                "location": {"file": "a.py", "line_start": 5},
            },
            {
                "severity": "HIGH",
                "confidence": "LIKELY",
                "panel": "security",
                "category": "sql-injection",
                "source": "agent:security-reviewer",
                "location": {"file": "a.py", "line_start": 5},
            },
        ]
        out = findings_mod.dedupe(findings)
        self.assertEqual(len(out), 2)
        self.assertFalse(any(f.get("reinforced") for f in out))

    def test_keeps_distinct_files(self):
        findings = [
            {
                "severity": "HIGH",
                "confidence": "CERTAIN",
                "category": "injection",
                "location": {"file": "a.rb", "line_start": 10},
            },
            {
                "severity": "HIGH",
                "confidence": "CERTAIN",
                "category": "injection",
                "location": {"file": "b.rb", "line_start": 10},
            },
        ]
        self.assertEqual(len(findings_mod.dedupe(findings)), 2)

    def test_no_file_findings_not_merged(self):
        findings = [
            {"severity": "LOW", "confidence": "NOTE", "category": "x", "location": {}},
            {"severity": "LOW", "confidence": "NOTE", "category": "x", "location": {}},
        ]
        self.assertEqual(len(findings_mod.dedupe(findings)), 2)

    def test_no_line_same_category_both_kept(self):
        # CD-001 regression: two distinct issues in the same file that both omit
        # line_start must NOT collapse on file+category alone. Without a concrete
        # line they can't be reliably clustered -> both pass through.
        findings = [
            {
                "severity": "MEDIUM",
                "confidence": "LIKELY",
                "category": "correctness",
                "source": "agent:code-reviewer",
                "location": {"file": "a.py"},
            },
            {
                "severity": "HIGH",
                "confidence": "CERTAIN",
                "category": "correctness",
                "source": "agent:code-reviewer",
                "location": {"file": "a.py"},
            },
        ]
        self.assertEqual(len(findings_mod.dedupe(findings)), 2)

    def test_reinforce_sourceless_agent_with_tool(self):
        # Production shape: real panel findings carry NO 'source' field; only
        # tool findings do. A tool+agent pair at the same locus must still
        # reinforce (regression for the dead-branch bug where the reinforce
        # condition required a literal 'agent' source token that never existed).
        findings = [
            {
                "id": "SG-1",
                "severity": "MEDIUM",
                "confidence": "CERTAIN",
                "panel": "security",
                "category": "sqli",
                "source": "tool:semgrep",
                "location": {"file": "db.py", "line_start": 10},
                "citations": {"cwe": [{"id": "CWE-89", "verified": True}]},
            },
            {
                "id": "SE-1",
                "severity": "HIGH",
                "confidence": "LIKELY",
                "panel": "security",
                "category": "novel",  # no 'source' key -> real agent shape
                "location": {"file": "db.py", "line_start": 10},
            },
        ]
        out = findings_mod.dedupe(findings)
        self.assertEqual(len(out), 1)
        self.assertTrue(out[0].get("reinforced"))
        # confidence is never mutated by the pipeline (amended spec) — the
        # survivor keeps its own original confidence.
        self.assertEqual(out[0].get("confidence"), "LIKELY")
        self.assertIn("citations", out[0])  # tool CWE carried to the survivor

    def test_reinforce_across_type_and_category_mismatch(self):
        findings = [
            {
                "id": "SE-001",
                "severity": "HIGH",
                "confidence": "LIKELY",
                "panel": "security",
                "category": "novel",
                "source": "agent:security-reviewer",
                "location": {"file": "webapp.py", "line_start": 151},
            },
            {
                "id": "SG-001",
                "severity": "MEDIUM",
                "confidence": "CERTAIN",
                "panel": "security",
                "category": "django-csrf",
                "source": "tool:semgrep",
                "location": {"file": "webapp.py", "line_start": "151"},
                "citations": {"cwe": [{"id": "CWE-352", "name": "CSRF", "verified": True}]},
            },
        ]
        out = findings_mod.dedupe(findings)
        self.assertEqual(len(out), 1)
        self.assertTrue(out[0].get("reinforced"))

    def test_three_findings_at_locus_keeps_unrelated(self):
        # tool + agent corroborate on sql-injection at the same line, plus an
        # UNRELATED agent 'structure' finding on that line -> the unrelated one survives.
        findings = [
            {
                "id": "TR-001",
                "severity": "HIGH",
                "confidence": "CERTAIN",
                "panel": "security",
                "category": "sql-injection",
                "source": "tool:semgrep",
                "location": {"file": "db.py", "line_start": 10},
            },
            {
                "id": "SE-001",
                "severity": "HIGH",
                "confidence": "LIKELY",
                "panel": "security",
                "category": "sql-injection",
                "source": "agent:security-reviewer",
                "location": {"file": "db.py", "line_start": 10},
            },
            {
                "id": "CD-001",
                "severity": "MEDIUM",
                "confidence": "POSSIBLE",
                "panel": "code",
                "category": "structure",
                "source": "agent:code-reviewer",
                "location": {"file": "db.py", "line_start": 10},
            },
        ]
        out = findings_mod.dedupe(findings)
        cats = sorted(f.get("category") for f in out)
        self.assertIn("structure", cats)  # unrelated finding NOT dropped
        self.assertEqual(len(out), 2)  # sql-injection (collapsed) + structure
        sql = [f for f in out if f.get("category") == "sql-injection"][0]
        self.assertTrue(sql.get("reinforced"))  # corroboration reinforces even in >2 clusters
        self.assertEqual(sql.get("confidence"), "CERTAIN")

class TestReinforceMerge(unittest.TestCase):
    def test_protects_tool_cvss_when_category_differs(self):
        # A same-LOCUS but DIFFERENT-category agent finding must not overwrite a
        # tool survivor's authoritative cvss/exploit_scenario (run-4 C20); a
        # MISSING field is still filled from the agent finding.
        tool_best = {
            "source": "tool:trivy",
            "category": "sqli",
            "cvss": {"score": 9.8, "vector": "TOOL"},
        }
        agent_other = {
            "source": "agent:panel",
            "category": "xss",
            "cvss": {"score": 1.0, "vector": "AGENT"},
            "exploit_scenario": "agent scenario",
        }
        findings_mod._reinforce_merge(tool_best, agent_other)
        self.assertEqual(tool_best["cvss"]["vector"], "TOOL")
        self.assertEqual(tool_best["exploit_scenario"], "agent scenario")

    def test_same_category_still_prefers_agent_cvss(self):
        # Same issue (category match): the richer agent cvss still wins --
        # preserved behavior (guards the deliberate dedupe contract).
        tool_best = {
            "source": "tool:semgrep",
            "category": "sqli",
            "cvss": {"score": 5.0, "vector": "TOOL"},
        }
        agent_other = {
            "source": "agent:panel",
            "category": "sqli",
            "cvss": {"score": 8.5, "vector": "AGENT"},
        }
        findings_mod._reinforce_merge(tool_best, agent_other)
        self.assertEqual(tool_best["cvss"]["vector"], "AGENT")

class TestReinforce(unittest.TestCase):
    def test_tool_and_agent_reinforce(self):
        findings = [
            {
                "id": "SE-001",
                "severity": "HIGH",
                "confidence": "LIKELY",
                "panel": "security",
                "category": "sql-injection",
                "source": "agent:security-reviewer",
                "location": {"file": "a.py", "line_start": 10},
            },
            {
                "id": "SG-001",
                "severity": "HIGH",
                "confidence": "CERTAIN",
                "panel": "security",
                "category": "sql-injection",
                "source": "tool:semgrep",
                "location": {"file": "a.py", "line_start": 10},
                "citations": {"cwe": [{"id": "CWE-89", "name": "SQLi", "verified": True}]},
            },
        ]
        out = findings_mod.dedupe(findings)
        self.assertEqual(len(out), 1)
        self.assertTrue(out[0].get("reinforced"))
        self.assertEqual(out[0]["confidence"], "CERTAIN")
        self.assertIn("citations", out[0])

    def test_tool_higher_confidence_keeps_agent_cvss_and_exploit(self):
        # PT-002 regression: a tool finding with higher confidence must not
        # discard the agent's cvss/exploit_scenario when it wins as survivor.
        findings = [
            {
                "id": "SG-001",
                "title": "SQL injection",
                "severity": "HIGH",
                "confidence": "CERTAIN",
                "panel": "security",
                "category": "sql-injection",
                "source": "tool:semgrep",
                "location": {"file": "a.py", "line_start": 10},
                "citations": {"cwe": [{"id": "CWE-89"}]},
            },
            {
                "id": "SE-001",
                "title": "SQL injection",
                "severity": "HIGH",
                "confidence": "LIKELY",
                "panel": "security",
                "category": "sql-injection",
                "location": {"file": "a.py", "line_start": 10},
                "cvss": {"score": 8.1, "vector": "CVSS:3.1/AV:N"},
                "exploit_scenario": "Attacker injects SQL via the search box.",
            },
        ]
        out = findings_mod.dedupe(findings)
        self.assertEqual(len(out), 1)
        self.assertTrue(out[0].get("reinforced"))
        self.assertEqual(out[0]["confidence"], "CERTAIN")
        self.assertEqual(out[0]["cvss"]["score"], 8.1)
        self.assertEqual(out[0]["exploit_scenario"], "Attacker injects SQL via the search box.")
        self.assertIn("cwe", out[0].get("citations", {}))

        report = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="src", fail_on=None, timestamp=DEFAULT_TIMESTAMP),
            findings=findings_mod.FindingSet(findings=out),
        ))
        errors, _ = report_mod.validate_report(report)
        self.assertEqual(errors, [])

    def test_agent_cvss_preferred_over_tool_cvss(self):
        findings = [
            {
                "id": "SG-001",
                "severity": "HIGH",
                "confidence": "CERTAIN",
                "panel": "security",
                "category": "sql-injection",
                "source": "tool:semgrep",
                "location": {"file": "a.py", "line_start": 10},
                "cvss": {"score": 5.0},
                "exploit_scenario": "tool scenario",
                "citations": {"cwe": [{"id": "CWE-89"}]},
            },
            {
                "id": "SE-001",
                "severity": "HIGH",
                "confidence": "LIKELY",
                "panel": "security",
                "category": "sql-injection",
                "location": {"file": "a.py", "line_start": 10},
                "cvss": {"score": 8.5},
                "exploit_scenario": "agent scenario",
            },
        ]
        out = findings_mod.dedupe(findings)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["cvss"]["score"], 8.5)
        self.assertEqual(out[0]["exploit_scenario"], "agent scenario")
        self.assertIn("cwe", out[0].get("citations", {}))

    def test_merge_preserves_missing_text_fields(self):
        findings = [
            {
                "id": "SG-001",
                "severity": "HIGH",
                "confidence": "CERTAIN",
                "panel": "security",
                "category": "sql-injection",
                "source": "tool:semgrep",
                "location": {"file": "a.py", "line_start": 10},
                "citations": {"cwe": [{"id": "CWE-89"}]},
                "impact": "Data exfiltration",
                "references": ["https://example.com"],
            },
            {
                "id": "SE-001",
                "severity": "HIGH",
                "confidence": "LIKELY",
                "panel": "security",
                "category": "sql-injection",
                "location": {"file": "a.py", "line_start": 10},
                "cvss": {"score": 8.1},
                "exploit_scenario": "x",
                "remediation": "Use parameterized queries",
            },
        ]
        out = findings_mod.dedupe(findings)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["impact"], "Data exfiltration")
        self.assertEqual(out[0]["references"], ["https://example.com"])
        self.assertEqual(out[0]["remediation"], "Use parameterized queries")
        self.assertEqual(out[0]["cvss"]["score"], 8.1)

class TestLoadFindingsProvenanceScrub(unittest.TestCase):
    def test_self_asserted_confirmation_status_is_stripped(self):
        # #run7 COD-X0X: an agent's self-reported provenance.confirmation_status
        # renders as an authoritative confirmed badge -- strip it at load (a real
        # verdict re-sets it via apply_verdict). Non-verification provenance stays.
        with tempfile.TemporaryDirectory() as d:
            fp = os.path.join(d, "findings-g-code.json")
            with open(fp, "w") as fh:
                json.dump({"findings": [{
                    "title": "x", "severity": "LOW", "panel": "code",
                    "category": "s", "location": {"file": "a.py", "line_start": 1},
                    "provenance": {"confirmation_status": "CONFIRMED",
                                   "confirmed_by": "agent:self", "model": "m"}}]}, fh)
            with contextlib.redirect_stderr(io.StringIO()):
                out = findings_mod.load_findings([fp])
        prov = out[0].get("provenance") or {}
        self.assertNotIn("confirmation_status", prov)
        self.assertNotIn("confirmed_by", prov)
        self.assertEqual(prov.get("model"), "m")   # non-verification provenance kept

class TestGroupReMatchesDispatchNames(unittest.TestCase):
    def test_matches_names_actually_produced_by_the_driver(self):
        # #run10: build_plan retired with the 4.x roles, so the producer of
        # findings filenames is now the driver's review-cell path. GROUP_RE must
        # still parse the group out of what the pipeline ACTUALLY writes -- that
        # is the invariant this guards, independent of which module emits it.

        for group, domain in (("changes_1", "SEC"), ("Auth", "COD"),
                              ("Ungrouped_1", "TST")):
            base = os.path.basename(
                runio._pano("/repo", "findings-%s-%s.json" % (group, domain)))
            m = findings_mod.GROUP_RE.match(base)
            self.assertIsNotNone(m, base)
            self.assertEqual(m.group(1), group, base)

    def test_still_matches_legacy_2x_names(self):
        m = findings_mod.GROUP_RE.match("findings-changes_1-security.json")
        self.assertIsNotNone(m)
        self.assertEqual(m.group(1), "changes_1")

    def test_matches_p4_domain_suffixed_names(self):
        # P4 review cells: findings-<group>-<domain>.json, domain from
        # groups_schema.DOMAINS (e.g. "SEC"), no further panel_review/lens_sweep
        # suffix. GROUP_RE's axis alternation must include the domain codes.
        m = findings_mod.GROUP_RE.match("findings-Auth-SEC.json")
        self.assertIsNotNone(m)
        self.assertEqual(m.group(1), "Auth")

    def test_mislabel_check_parses_what_the_driver_actually_writes(self):
        # The #937 mislabel control went silently inert because ITS filename
        # regex was never re-pointed when the review-cell spelling changed: it
        # returned "nothing wrong" for every file a 5.x run can produce, and
        # five green tests said otherwise. Pin it to the real producer, the same
        # way the GROUP_RE guard above does, so a future rename fails loudly
        # here instead of quietly disarming an integrity check.

        for group, domain in (("changes_1", "SEC"), ("Auth", "COD"),
                              ("My-Hyphenated-Group", "TST")):
            base = os.path.basename(
                runio._pano("/repo", "findings-%s-%s.json" % (group, domain)))
            self.assertEqual(integrity_mod._expected_from_filename(base), (group, domain), base)

class TestDedupeRuleIdDiscrimination(unittest.TestCase):
    """Calibration 2026-08-03: distinct advisories at the same manifest locus
    must not collapse to one-per-category (22 real osv findings survived as 3)."""

    def _dep(self, fid, rule, sev="MEDIUM"):
        return {
            "id": fid,
            "title": rule,
            "severity": sev,
            "confidence": "CERTAIN",
            "panel": "security",
            "category": "dependency_vulnerability",
            "source": "tool:osv-scanner",
            "location": {"file": "requirements.txt", "line_start": 1},
            "tool_evidence": {"rule_id": rule},
            "provenance": {"discovered_by": "tool:osv-scanner", "confirmation_status": "TOOL"},
        }

    def test_distinct_rule_ids_all_survive(self):
        findings = [
            self._dep("OS-001", "GHSA-aaaa"),
            self._dep("OS-002", "GHSA-bbbb"),
            self._dep("OS-003", "GHSA-cccc", sev="CRITICAL"),
        ]
        out = findings_mod.dedupe(findings)
        self.assertEqual(len(out), 3)
        self.assertEqual(
            {f["tool_evidence"]["rule_id"] for f in out}, {"GHSA-aaaa", "GHSA-bbbb", "GHSA-cccc"}
        )

    def test_same_rule_id_still_collapses_to_most_severe(self):
        findings = [
            self._dep("OS-001", "GHSA-aaaa", sev="MEDIUM"),
            self._dep("OS-002", "GHSA-aaaa", sev="HIGH"),
            self._dep("OS-003", "GHSA-bbbb"),
        ]
        out = findings_mod.dedupe(findings)
        self.assertEqual(len(out), 2)
        kept = {f["tool_evidence"]["rule_id"]: f["severity"] for f in out}
        self.assertEqual(kept["GHSA-aaaa"], "HIGH")

    def test_tool_agent_reinforce_survives_rule_bucketing(self):
        agent = {
            "id": "AG-001",
            "title": "vulnerable dep use",
            "severity": "HIGH",
            "confidence": "POSSIBLE",
            "panel": "security",
            "category": "dependency_vulnerability",
            "location": {"file": "requirements.txt", "line_start": 1},
            "provenance": {
                "discovered_by": "agent:panel_review",
                "confirmation_status": "UNVERIFIED",
            },
        }
        findings = [self._dep("OS-001", "GHSA-aaaa"), self._dep("OS-002", "GHSA-bbbb"), agent]
        out = findings_mod.dedupe(findings)
        self.assertEqual(len(out), 3)  # two rules + the agent bucket
        self.assertTrue(all(f.get("reinforced") for f in out))

class TestCalibrationFixmes(unittest.TestCase):
    def test_models_used_dedups_inconsistent_versions(self):
        # F-CAL-3: same model+role with three self-reported version spellings -> 1 entry
        fs = []
        for i, ver in enumerate(("claude-haiku-4-5-20251001", "4.5", "20251001")):
            fs.append(
                {
                    "id": "AG-%03d" % i,
                    "title": "t",
                    "severity": "LOW",
                    "confidence": "NOTE",
                    "panel": "code",
                    "category": "style",
                    "location": {"file": "a.py", "line_start": i + 1},
                    "provenance": {
                        "discovered_by": "agent:lens_sweep",
                        "model": "claude-haiku-4-5-20251001",
                        "model_version": ver,
                        "confirmation_status": "UNVERIFIED",
                    },
                }
            )
        entries = report_mod._collect_models_used(fs)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["model"], "claude-haiku-4-5-20251001")

    def test_id_re_accepts_real_agent_prefixes(self):
        # F-CAL-4: observed real ids like STRUCT-001 (6 letters) must validate
        for good in ("CD-001", "STRUCT-001", "ABCDEFGH-123"):
            self.assertIsNotNone(findings_mod.ID_RE.match(good), good)
        for bad in ("A-001", "ABCDEFGHI-001", "struct-001", "SEC-01"):
            self.assertIsNone(findings_mod.ID_RE.match(bad), bad)

class TestEvidenceIntegrity(unittest.TestCase):
    """SEC-102: trust must never derive from a field the finding payload sets."""

    def _agent_file(self, d, findings):
        p = os.path.join(d, "findings-g1-security-panel_review.json")
        with open(p, "w") as fh:
            json.dump({"findings": findings}, fh)
        return p

    def test_agent_cannot_forge_tool_source(self):
        forged = {
            "id": "AG-001",
            "title": "forged",
            "severity": "CRITICAL",
            "confidence": "CERTAIN",
            "panel": "security",
            "category": "injection",
            "source": "tool:bandit",
            "location": {"file": "a.py", "line_start": 1},
        }
        with tempfile.TemporaryDirectory() as d:
            loaded = findings_mod.load_findings([self._agent_file(d, [forged])])
        self.assertNotIn("source", loaded[0])
        self.assertFalse(evidence_mod.is_tool_sourced(loaded[0]))

    def test_agent_cannot_forge_reinforced(self):
        forged = {
            "id": "AG-002",
            "title": "forged",
            "severity": "HIGH",
            "confidence": "CERTAIN",
            "panel": "security",
            "category": "injection",
            "reinforced": True,
            "location": {"file": "a.py", "line_start": 2},
        }
        with tempfile.TemporaryDirectory() as d:
            loaded = findings_mod.load_findings([self._agent_file(d, [forged])])
        self.assertNotIn("reinforced", loaded[0])

    def test_forged_finding_still_reaches_the_verify_queue(self):
        forged = {
            "id": "AG-003",
            "title": "forged",
            "severity": "CRITICAL",
            "confidence": "CERTAIN",
            "panel": "security",
            "category": "injection",
            "source": "tool:bandit",
            "reinforced": True,
            "location": {"file": "a.py", "line_start": 3},
        }
        with tempfile.TemporaryDirectory() as d:
            loaded = findings_mod.load_findings([self._agent_file(d, [forged])])
        entries, _ = evidence_mod.build_verify_queue(loaded)
        # forged finding is still queued (not dropped) -- but its supplied id is
        # replaced with a content-derived one, so it can't bind a foreign verdict
        # (#1109).
        self.assertEqual(len(entries), 1)
        self.assertNotEqual(entries[0]["finding"]["id"], "AG-003")
        self.assertTrue(findings_mod.ID_RE.match(entries[0]["finding"]["id"]))

    def test_real_tool_findings_keep_their_source(self):
        # ingest_tools output is not agent-authored and must be untouched.
        tool = {
            "id": "TL-001",
            "title": "real",
            "severity": "HIGH",
            "confidence": "CERTAIN",
            "panel": "security",
            "category": "injection",
            "source": "tool:semgrep",
            "location": {"file": "a.py", "line_start": 4},
            "provenance": {"discovered_by": "tool:semgrep", "confirmation_status": "TOOL"},
        }
        f = findings_mod.normalize_finding(dict(tool))
        self.assertTrue(evidence_mod.is_tool_sourced(f))

class TestToolFindingAggregation(unittest.TestCase):
    """41 identical rule hits should be one issue with many loci, not 41 issues."""

    def _hit(self, fid, line, rule="ACTIONS-PIN"):
        return {
            "id": fid,
            "title": "mutable tag",
            "severity": "MEDIUM",
            "confidence": "CERTAIN",
            "panel": "security",
            "category": "known_vulns",
            "source": "tool:semgrep",
            "tool_evidence": {"rule_id": rule},
            "location": {"file": ".github/workflows/ci.yml", "line_start": line},
            "provenance": {"discovered_by": "tool:semgrep", "confirmation_status": "TOOL"},
        }

    def test_same_rule_same_file_collapses_with_loci(self):
        out = findings_mod.aggregate_tool_findings(
            [self._hit("A-001", 13), self._hit("A-002", 20), self._hit("A-003", 31)]
        )
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["location"]["line_start"], 13)
        self.assertEqual(len(out[0]["additional_loci"]), 2)
        self.assertEqual(out[0]["occurrences"], 3)

    def test_different_rules_stay_separate(self):
        out = findings_mod.aggregate_tool_findings(
            [self._hit("A-001", 13, "R1"), self._hit("A-002", 20, "R2")]
        )
        self.assertEqual(len(out), 2)

    def test_agent_findings_never_aggregated(self):
        a = {
            "id": "AG-001",
            "title": "x",
            "severity": "LOW",
            "confidence": "NOTE",
            "panel": "code",
            "category": "style",
            "location": {"file": "a.py", "line_start": 1},
        }
        b = dict(a, id="AG-002", location={"file": "a.py", "line_start": 2})
        self.assertEqual(len(findings_mod.aggregate_tool_findings([a, b])), 2)

    def _sarif_hit(
        self, fid, line, rule="B607", title="Starting a process with a partial executable path"
    ):
        """A SARIF-adapter finding: rule id lands in provenance, NOT tool_evidence."""
        return {
            "id": fid,
            "title": title,
            "severity": "LOW",
            "confidence": "CERTAIN",
            "panel": "security",
            "category": rule,
            "source": "tool:bandit",
            "location": {"file": "skill/scripts/orchestrator.py", "line_start": line},
            "provenance": {
                "discovered_by": "tool:bandit",
                "confirmed_by": "tool:bandit",
                "confirmation_status": "TOOL",
                "confirmation_reasoning": rule,
            },
        }

    def test_sarif_adapter_findings_aggregate_by_rule(self):
        # bandit/semgrep go through the SARIF path and emit no tool_evidence at
        # all; the rule id is in provenance.confirmation_reasoning. Keying only
        # on tool_evidence.rule_id silently skipped every SARIF finding, so one
        # rule firing 4x in one file stayed 4 issues instead of 1 with 4 loci.
        out = findings_mod.aggregate_tool_findings(
            [
                self._sarif_hit("BN-1", 129),
                self._sarif_hit("BN-2", 140),
                self._sarif_hit("BN-3", 149),
                self._sarif_hit("BN-4", 161),
            ]
        )
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["occurrences"], 4)
        self.assertEqual(out[0]["location"]["line_start"], 129)
        self.assertEqual(len(out[0]["additional_loci"]), 3)

    def test_sarif_fingerprint_survives_a_tool_message_rewording(self):
        # Identity must key on the rule, not the scanner's prose — otherwise a
        # tool upgrade that rewords its message orphans every existing issue.
        a = evidence_mod.finding_fingerprint(self._sarif_hit("BN-1", 129))
        b = evidence_mod.finding_fingerprint(
            self._sarif_hit("BN-1", 129, title="Partial executable path used")
        )
        self.assertEqual(a, b)

    def test_aggregation_preserves_a_tool_plus_agent_reinforcement(self):
        # Aggregation runs before dedupe, and dedupe reinforces on an EXACT
        # (file, line) match. Collapsing a multi-hit rule to its lowest line
        # would move the tool witness away from the line an agent independently
        # flagged, silently downgrading a tool_confirmed finding.
        agent = {
            "id": "AG-001",
            "title": "agent claim",
            "severity": "HIGH",
            "confidence": "LIKELY",
            "panel": "security",
            "category": "known_vulns",
            "location": {"file": ".github/workflows/ci.yml", "line_start": 20},
        }
        aggregated = findings_mod.aggregate_tool_findings(
            [self._hit("A-001", 13), self._hit("A-002", 20), self._hit("A-003", 31), agent]
        )
        tool_survivor = [f for f in aggregated if f.get("id", "").startswith("A-")]
        self.assertEqual(len(tool_survivor), 1)
        self.assertEqual(tool_survivor[0]["occurrences"], 3)
        # The survivor sits on the corroborated line, not the lowest one.
        self.assertEqual(tool_survivor[0]["location"]["line_start"], 20)
        deduped, _ = findings_mod.prepare_findings(aggregated)
        self.assertTrue(any(f.get("reinforced") for f in deduped))

class TestShortTitle(unittest.TestCase):
    def test_long_tool_message_gets_a_short_title(self):
        long = (
            "This Dependabot configuration does not set a cooldown period. "
            "Newly published packages can be malicious or unstable. " + "x" * 400
        )
        f = findings_mod.normalize_finding(
            {
                "id": "SG-001",
                "title": long,
                "severity": "LOW",
                "confidence": "CERTAIN",
                "panel": "security",
                "category": "x",
                "location": {"file": "a.yml", "line_start": 1},
            }
        )
        self.assertLessEqual(len(f["short_title"]), 100)
        self.assertEqual(f["title"], " ".join(long.split()))
        self.assertTrue(f["short_title"].endswith("…"))

    def test_short_title_passes_through_unchanged(self):
        f = findings_mod.normalize_finding(
            {
                "id": "SG-002",
                "title": "Short and sweet",
                "severity": "LOW",
                "confidence": "CERTAIN",
                "panel": "code",
                "category": "x",
                "location": {"file": "a.py", "line_start": 1},
            }
        )
        self.assertEqual(f["short_title"], "Short and sweet")

class TestDocSeverityPolicy(unittest.TestCase):
    """#487: path-scoped, mode-gated, severity-only soft downgrade with a
    secrets carve-out -- disclosed, never silent, never upward."""

    def _f(self, file, sev="MEDIUM", category="structure", title="x", source=None):
        f = {
            "id": "D-1",
            "severity": sev,
            "panel": "code",
            "category": category,
            "title": title,
            "location": {"file": file, "line_start": 1},
        }
        if source:
            f["source"] = source
        return f

    def test_code_finding_under_doc_tree_downgrades_to_info(self):
        f = self._f("docs/superpowers/plans/x.md")
        res = findings_mod.apply_doc_severity_policy([f], "standard")
        self.assertEqual(f["severity"], "INFO")
        self.assertEqual(f["doc_policy"], {"downgraded_from": "MEDIUM"})
        self.assertEqual(res["downgraded"], 1)
        self.assertEqual(res["examples"][0]["file"], "docs/superpowers/plans/x.md")

    def test_secret_finding_keeps_severity(self):
        f = self._f(
            "docs/plan.md",
            sev="CRITICAL",
            title="Hardcoded API key pasted into plan",
            category="secrets",
        )
        res = findings_mod.apply_doc_severity_policy([f], "standard")
        self.assertEqual(f["severity"], "CRITICAL")
        self.assertEqual(res["downgraded"], 0)

    def test_redteam_mode_is_a_full_bypass(self):
        f = self._f("docs/plan.md")
        res = findings_mod.apply_doc_severity_policy([f], "redteam")
        self.assertIsNone(res)
        self.assertEqual(f["severity"], "MEDIUM")

    def test_non_doc_path_untouched_and_info_never_touched(self):
        a = self._f("skill/scripts/synthesize.py")
        b = self._f("docs/x.md", sev="INFO")
        res = findings_mod.apply_doc_severity_policy([a, b], "standard")
        self.assertEqual(a["severity"], "MEDIUM")
        self.assertNotIn("doc_policy", b)
        self.assertEqual(res["downgraded"], 0)

    def test_main_wires_policy_and_discloses(self):

        with tempfile.TemporaryDirectory() as d, _chdir(d):
            fp = os.path.join(d, "findings-g1-code.json")
            with open(fp, "w") as fh:
                json.dump(
                    {
                        "findings": [
                            {
                                "id": "A-1",
                                "title": "hardcoded path",
                                "severity": "MEDIUM",
                                "confidence": "POSSIBLE",
                                "panel": "code",
                                "category": "structure",
                                "location": {"file": "docs/plans/roadmap.md", "line_start": 3},
                            }
                        ]
                    },
                    fh,
                )
            out = os.path.join(d, "r.json")
            err = io.StringIO()
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
                rc = syn.main(["--target", "src", "--out", out, fp])
            self.assertEqual(rc, 0)
            self.assertIn("soft-downgraded", err.getvalue())
            with open(out) as fh:
                report = json.load(fh)
            self.assertEqual(report["meta"]["coverage"]["doc_policy"]["downgraded"], 1)
            f = report["findings"][0]
            self.assertEqual(f["severity"], "INFO")
            self.assertEqual(f["doc_policy"]["downgraded_from"], "MEDIUM")

class TestPathVariantClustering(unittest.TestCase):
    """#977: dedupe/corroboration/aggregation key on evidence.norm_path, so
    cosmetic path dressing (a `./` prefix, backslashes) from one emitter never
    splits a cluster and silently costs a finding its reinforcement."""

    def _agent(self, fid, file, line, panel="security", category="sql-injection"):
        return {
            "id": fid,
            "title": fid,
            "severity": "HIGH",
            "confidence": "LIKELY",
            "panel": panel,
            "category": category,
            "source": "agent:security-reviewer",
            "location": {"file": file, "line_start": line},
        }

    def _tool(self, fid, file, line, rule="B608"):
        return {
            "id": fid,
            "title": fid,
            "severity": "HIGH",
            "confidence": "CERTAIN",
            "panel": "security",
            "category": "sql-injection",
            "source": "tool:semgrep",
            "tool_evidence": {"rule_id": rule},
            "location": {"file": file, "line_start": line},
        }

    def test_dedupe_merges_dot_slash_variant(self):
        out = findings_mod.dedupe(
            [self._agent("SE-001", "./src/auth.py", 10), self._tool("SG-001", "src/auth.py", 10)]
        )
        self.assertEqual(len(out), 1)
        self.assertTrue(out[0].get("reinforced"))

    def test_dedupe_merges_backslash_variant(self):
        out = findings_mod.dedupe(
            [self._agent("SE-001", "src/auth.py", 10), self._tool("SG-001", "src\\auth.py", 10)]
        )
        self.assertEqual(len(out), 1)
        self.assertTrue(out[0].get("reinforced"))

    def test_corroboration_across_path_variants(self):
        a = self._agent("SE-001", "./app/resolver.py", 42)
        b = self._agent("TS-001", "app/resolver.py", 43, panel="test", category="test-coverage")
        integration = findings_mod.cross_panel_corroboration([a, b])
        self.assertEqual(len(integration), 1)
        self.assertTrue(a.get("corroborated"))
        self.assertTrue(b.get("corroborated"))

    def test_aggregate_agent_locus_wins_across_variant(self):
        # The agent flagged ./f.py:10; the tool's rule hit f.py:5 and f.py:10.
        # The agent-corroborated locus must win primary, exactly as it does
        # when both spell the path identically.
        agent = self._agent("SE-001", "./f.py", 10)
        tools = [self._tool("SG-001", "f.py", 5), self._tool("SG-002", "f.py", 10)]
        out = findings_mod.aggregate_tool_findings([agent] + tools)
        merged = [f for f in out if evidence_mod.is_tool_sourced(f)]
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0]["location"]["line_start"], 10)

class FindingSetLoaderTest(unittest.TestCase):
    """WS-0 S3: FindingSet.load = files + tool findings + enrichment + policy +
    severity floor + verdicts, in main()'s original order."""

    def _write_findings(self, d, findings):
        p = os.path.join(d, "findings-g1-code-panel_review.json")
        with open(p, "w") as fh:
            json.dump({"findings": findings}, fh)
        return p

    def test_loads_files_and_normalizes_tool_findings(self):
        with tempfile.TemporaryDirectory() as d:
            p = self._write_findings(d, [_make_finding(severity="HIGH", id="CD-001")])
            tf = {"tool": "semgrep", "rule_id": "r.1", "severity": "MEDIUM",
                  "title": "tool hit", "location": {"file": "b.py", "line_start": 1},
                  "panel": "security", "category": "injection", "confidence": "LIKELY"}
            with contextlib.redirect_stdout(io.StringIO()):
                fs = findings_mod.FindingSet.load(_cli_args(files=[p]), [tf], "standard", None)
            self.assertEqual(len(fs.findings), 2)
            self.assertEqual(fs.findings[1]["title"], "tool hit")
            self.assertFalse(fs.verdicts_supplied)
            self.assertEqual(fs.verdicts, {})
            self.assertEqual(fs.verdict_unloadable, [])
            self.assertIsNone(fs.verdict_run_id)
            self.assertIsNotNone(fs.catalog)

    def test_severity_floor_and_run_id_are_applied(self):
        with tempfile.TemporaryDirectory() as d:
            p = self._write_findings(d, [_make_finding(severity="HIGH", id="CD-001"),
                                         _make_finding(severity="LOW", id="CD-002")])
            with contextlib.redirect_stdout(io.StringIO()):
                fs = findings_mod.FindingSet.load(_cli_args(files=[p], severity="high"),
                                                  [], "standard", "run-9")
            self.assertEqual([f["severity"] for f in fs.findings], ["HIGH"])
            self.assertEqual(fs.verdict_run_id, "run-9")

    def test_verdicts_dir_is_read_once_and_unloadable_deduped(self):
        with tempfile.TemporaryDirectory() as d:
            p = self._write_findings(d, [_make_finding(severity="HIGH", id="CD-001")])
            vd = os.path.join(d, "verdicts")
            os.makedirs(vd)
            with open(os.path.join(vd, "broken.json"), "w") as fh:
                fh.write("{broken")
            with contextlib.redirect_stdout(io.StringIO()), \
                    contextlib.redirect_stderr(io.StringIO()):
                fs = findings_mod.FindingSet.load(_cli_args(files=[p], verdicts_dir=vd),
                                                  [], "standard", None)
            self.assertTrue(fs.verdicts_supplied)
            # both loaders trip over the same file; it is reported once (#938)
            self.assertEqual([u["file"] for u in fs.verdict_unloadable], ["broken.json"])
