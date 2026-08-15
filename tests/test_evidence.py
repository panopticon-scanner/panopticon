import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), os.pardir, "skill"))
import scripts.evidence as evidence
import scripts.evidence as ev


def _finding(**kw):
    f = {"id": "SEC-001", "title": "t", "severity": "HIGH",
         "confidence": "POSSIBLE", "panel": "security", "category": "injection",
         "location": {"file": "app.py", "line_start": 10},
         "citation_quality": "partial"}
    f.update(kw)
    return f


class TestDeriveEvidence(unittest.TestCase):
    def test_tool_sourced_is_tool_reported(self):
        # P2/#446: no verdict means the tool's claim is reported, not verified.
        f = _finding(source="tool:semgrep",
                     provenance={"confirmation_reasoning": "Reported by semgrep"})
        ev = evidence.derive_evidence(f)
        self.assertEqual(ev["status"], "tool_reported")
        self.assertEqual(ev["verified_by"], "tool:semgrep")
        self.assertEqual(ev["reasoning"], "Reported by semgrep")
        self.assertEqual(ev["citation_quality"], "partial")

    def test_confirmed_verdict_is_advisor_confirmed(self):
        ev = evidence.derive_evidence(
            _finding(), {"verdict": "CONFIRMED", "reasoning": "sink verified"})
        self.assertEqual(ev["status"], "advisor_confirmed")
        self.assertEqual(ev["verified_by"], "agent:advisor")
        self.assertEqual(ev["reasoning"], "sink verified")

    def test_rejected_verdict_is_rejected(self):
        ev = evidence.derive_evidence(
            _finding(), {"verdict": "REJECTED", "reasoning": "no sink"})
        self.assertEqual(ev["status"], "rejected")

    def test_needs_more_info_verdict(self):
        ev = evidence.derive_evidence(
            _finding(), {"verdict": "NEEDS_MORE_INFO", "reasoning": "need config"})
        self.assertEqual(ev["status"], "needs_more_info")
        self.assertEqual(ev["reasoning"], "need config")

    def test_verdict_beats_corroboration(self):
        ev = evidence.derive_evidence(
            _finding(corroborated=True, corroborated_by=["security", "database"]),
            {"verdict": "REJECTED", "reasoning": "r"})
        self.assertEqual(ev["status"], "rejected")

    def test_verdict_beats_tool_source(self):
        # P2/#446: precedence inverted. An advisor verdict now outranks
        # tool-sourcing -- the whole point being that an advisor CAN refute a
        # scanner (e.g. Bandit B105 flagging a CSS-class-name string as a
        # "hardcoded password").
        ev = evidence.derive_evidence(
            _finding(source="tool:bandit"), {"verdict": "REJECTED"})
        self.assertEqual(ev["status"], "rejected")

    def test_cross_panel_corroborated(self):
        ev = evidence.derive_evidence(
            _finding(corroborated=True, corroborated_by=["security", "database"]))
        self.assertEqual(ev["status"], "corroborated")
        self.assertEqual(ev["verified_by"], ["security", "database"])

    def test_reinforced_is_tool_reported(self):
        # A tool+agent same-locus merge is tool-reported by construction
        # (never demoted to mere `corroborated`), but P2/#446 means that alone
        # no longer gates -- it still needs an advisor CONFIRMED verdict to
        # reach tool_confirmed.
        ev = evidence.derive_evidence(_finding(reinforced=True))
        self.assertEqual(ev["status"], "tool_reported")
        self.assertEqual(ev["verified_by"], "tool+agent")

    def test_default_is_unverified(self):
        ev = evidence.derive_evidence(_finding())
        self.assertEqual(ev["status"], "unverified")
        self.assertIsNone(ev["verified_by"])
        self.assertIsNone(ev["reasoning"])

    def test_never_mutates_severity_or_confidence(self):
        for verdict in (None, {"verdict": "CONFIRMED"}, {"verdict": "REJECTED"},
                        {"verdict": "NEEDS_MORE_INFO"}):
            f = _finding()
            evidence.derive_evidence(f, verdict)
            self.assertEqual(f["severity"], "HIGH")
            self.assertEqual(f["confidence"], "POSSIBLE")

    def test_missing_citation_quality_defaults_none(self):
        f = _finding()
        del f["citation_quality"]
        self.assertEqual(evidence.derive_evidence(f)["citation_quality"], "none")


class TestToolReported(unittest.TestCase):
    def _tool(self, **over):
        f = {"id": "T-1", "source": "tool:bandit", "severity": "HIGH",
             "panel": "security", "category": "secrets",
             "provenance": {"confirmation_reasoning": "B105"}}
        f.update(over)
        return f

    def test_unverified_tool_finding_is_tool_reported(self):
        ev_obj = ev.derive_evidence(self._tool())
        self.assertEqual(ev_obj["status"], "tool_reported")

    def test_tool_reported_is_not_gate_eligible(self):
        self.assertNotIn("tool_reported", ev.GATE_ELIGIBLE_DEFAULT)

    def test_confirmed_verdict_promotes_tool_finding(self):
        ev_obj = ev.derive_evidence(self._tool(),
                                    {"verdict": "CONFIRMED", "reasoning": "real"})
        self.assertEqual(ev_obj["status"], "tool_confirmed")
        self.assertIn("tool_confirmed", ev.GATE_ELIGIBLE_DEFAULT)

    def test_rejected_verdict_rejects_tool_finding(self):
        # The whole point of #446: an advisor CAN now refute a scanner.
        ev_obj = ev.derive_evidence(self._tool(),
                                    {"verdict": "REJECTED", "reasoning": "CSS class"})
        self.assertEqual(ev_obj["status"], "rejected")

    def test_needs_more_info_verdict_on_tool_finding(self):
        ev_obj = ev.derive_evidence(self._tool(), {"verdict": "NEEDS_MORE_INFO"})
        self.assertEqual(ev_obj["status"], "needs_more_info")

    def test_reinforced_unverified_is_tool_reported_keeping_corroboration(self):
        f = {"id": "R-1", "reinforced": True, "severity": "HIGH",
             "panel": "code", "category": "logic"}
        ev_obj = ev.derive_evidence(f)
        self.assertEqual(ev_obj["status"], "tool_reported")
        self.assertEqual(ev_obj["verified_by"], "tool+agent")

    def test_reinforced_confirmed_verdict_promotes_to_tool_confirmed(self):
        # A reinforced (tool+agent same-locus merge) finding is tool-like, so
        # a CONFIRMED verdict promotes it exactly like a plain tool finding --
        # and verified_by carries both the merge origin and the advisor.
        f = {"id": "R-2", "reinforced": True, "severity": "HIGH",
             "panel": "code", "category": "logic"}
        ev_obj = ev.derive_evidence(f, {"verdict": "CONFIRMED", "reasoning": "real"})
        self.assertEqual(ev_obj["status"], "tool_confirmed")
        self.assertEqual(ev_obj["verified_by"], ["tool+agent", "agent:advisor"])

    def test_reinforced_rejected_verdict_rejects(self):
        # Same as the plain-tool case: an advisor can refute a reinforced
        # (tool+agent) finding too, not just a lone tool one.
        f = {"id": "R-3", "reinforced": True, "severity": "HIGH",
             "panel": "code", "category": "logic"}
        ev_obj = ev.derive_evidence(f, {"verdict": "REJECTED", "reasoning": "false positive"})
        self.assertEqual(ev_obj["status"], "rejected")

    def test_agent_finding_unaffected(self):
        f = {"id": "A-1", "severity": "HIGH", "panel": "code",
             "category": "logic"}
        self.assertEqual(ev.derive_evidence(f)["status"], "unverified")
        self.assertEqual(
            ev.derive_evidence(f, {"verdict": "CONFIRMED"})["status"],
            "advisor_confirmed")

    def test_status_is_in_schema_enum(self):
        import json as _json
        # Anchor on __file__, not the cwd: a bare relative path assumes the
        # suite runs from the repo root and breaks from anywhere else.
        schema_path = os.path.join(os.path.dirname(__file__), os.pardir,
                                   "skill", "reference", "report-schema.json")
        with open(schema_path, encoding="utf-8") as fh:
            schema = _json.load(fh)
        text = _json.dumps(schema)
        self.assertIn("tool_reported", text)


class TestFingerprintMoved(unittest.TestCase):
    def _f(self, **over):
        f = {"id": "SEC-1", "panel": "security", "category": "injection",
             "title": "SQL injection", "location": {"file": "a.py",
                                                    "line_start": 3}}
        f.update(over)
        return f

    def test_fingerprint_is_stable_hex(self):
        fp = evidence.finding_fingerprint(self._f())
        self.assertEqual(len(fp), 16)
        self.assertTrue(all(c in "0123456789abcdef" for c in fp))

    def test_fingerprint_ignores_line_number(self):
        a = evidence.finding_fingerprint(self._f())
        b = evidence.finding_fingerprint(
            self._f(location={"file": "a.py", "line_start": 99}))
        self.assertEqual(a, b)

    def test_tool_rule_id_reads_both_adapter_families(self):
        self.assertEqual(
            evidence.tool_rule_id({"tool_evidence": {"rule_id": "B105"}}), "B105")
        self.assertEqual(
            evidence.tool_rule_id({"provenance": {"confirmation_reasoning": "SCS0005"}}),
            "SCS0005")
        self.assertIsNone(evidence.tool_rule_id({}))

    def test_synthesize_aliases_still_resolve(self):
        import scripts.synthesize as syn
        self.assertIs(syn.finding_fingerprint, evidence.finding_fingerprint)
        self.assertIs(syn.tool_rule_id, evidence.tool_rule_id)


class TestReconcileKey(unittest.TestCase):
    def _f(self, **kw):
        base = {"panel": "security", "category": "injection",
                "location": {"file": "app/db.py"}, "title": "SQLi", "source": "agent"}
        base.update(kw)
        return base

    def test_key_is_file_panel_category_tuple(self):
        self.assertEqual(evidence.reconcile_key(self._f()),
                         ("app/db.py", "security", "injection"))

    def test_drops_title__reworded_finding_shares_key(self):
        a = self._f(title="SQL injection in query")
        b = self._f(title="Unsanitized input reaches execute()")
        self.assertEqual(evidence.reconcile_key(a), evidence.reconcile_key(b))

    def test_file_normalized_like_fingerprint(self):
        self.assertEqual(evidence.reconcile_key(self._f(location={"file": "./a\\b.py"}))[0],
                         "a/b.py")

    def test_missing_fields_become_empty_strings(self):
        self.assertEqual(evidence.reconcile_key({}), ("", "", ""))


class TestReconcileKeyCode(unittest.TestCase):
    """5.0: reconcile_key prefers the OCRDb (file, code) identity when a
    finding carries a domain code; a code-less finding keeps the legacy
    (file, panel, category) tuple unchanged."""

    def test_code_preferred(self):
        k = evidence.reconcile_key({"code": "SEC-A1A", "location": {"file": "a.py"},
                                    "panel": "security", "category": "x"})
        self.assertEqual(k, ("a.py", "code", "SEC-A1A"))

    def test_falls_back_without_code(self):
        k = evidence.reconcile_key({"location": {"file": "a.py"},
                                    "panel": "security", "category": "x"})
        self.assertEqual(k, ("a.py", "security", "x"))


class TestNormPath(unittest.TestCase):
    """#977: the file normalization finding_fingerprint/reconcile_key shared
    inline is owned by norm_path, and clustering keys use the same function."""

    def test_strips_dot_slash_prefix_and_backslashes(self):
        self.assertEqual(ev.norm_path("./src/x.py"), "src/x.py")
        self.assertEqual(ev.norm_path("././src/x.py"), "src/x.py")
        self.assertEqual(ev.norm_path("src\\x.py"), "src/x.py")

    def test_dotfile_prefix_preserved(self):
        # lstrip-style stripping would collapse `.github/x` onto `github/x`.
        self.assertEqual(ev.norm_path(".github/workflows/ci.yml"),
                         ".github/workflows/ci.yml")

    def test_none_and_empty(self):
        self.assertEqual(ev.norm_path(None), "")
        self.assertEqual(ev.norm_path(""), "")

    def test_fingerprint_invariant_under_path_dressing(self):
        a = _finding(location={"file": "./src/x.py", "line_start": 10})
        b = _finding(location={"file": "src/x.py", "line_start": 10})
        self.assertEqual(ev.finding_fingerprint(a), ev.finding_fingerprint(b))
        self.assertEqual(ev.reconcile_key(a), ev.reconcile_key(b))

    def test_fingerprint_does_not_collapse_dotfiles(self):
        a = _finding(location={"file": ".github/x", "line_start": 1})
        b = _finding(location={"file": "github/x", "line_start": 1})
        self.assertNotEqual(ev.finding_fingerprint(a), ev.finding_fingerprint(b))


if __name__ == "__main__":
    unittest.main()
