import ast
import hashlib
import os
import json
import unittest

import scripts.evidence as evidence

ev = evidence


def _key_reads(tree, key):
    """The enclosing function names (module level -> "<module>") of every
    occurrence of `key` as a constant in `tree`, in ANY idiom -- `x[key]`,
    `x.get(key)`, `x.pop(key)`, `x.setdefault(key)`, `key in x`, a constant
    assigned to a name and read later -- except one: the slice of a Store-context
    subscript, which is a write (#2365). Naming the KEY rather than a list of
    read idioms is what makes the guard hold for idioms nobody has used yet.

    A function's decorators and default arguments are attributed to that function
    rather than to its enclosing scope, so the one shape this scan cannot see is
    a read hidden in the decorator list or the defaults OF THE READER ITSELF.
    """
    written = {id(node.slice) for node in ast.walk(tree)
               if isinstance(node, ast.Subscript) and isinstance(node.ctx, ast.Store)}
    found = set()

    def visit(node, scope):
        if (isinstance(node, ast.Constant) and node.value == key
                and id(node) not in written):
            found.add(scope)
        for child in ast.iter_child_nodes(node):
            visit(child, child.name if isinstance(
                child, (ast.FunctionDef, ast.AsyncFunctionDef)) else scope)

    visit(tree, "<module>")
    return found


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
        derived = ev.derive_evidence(f)
        self.assertEqual(derived["status"], "tool_reported")
        self.assertEqual(derived["verified_by"], "tool:semgrep")
        self.assertEqual(derived["reasoning"], "Reported by semgrep")
        self.assertEqual(derived["citation_quality"], "partial")

    def test_confirmed_verdict_is_advisor_confirmed(self):
        derived = ev.derive_evidence(
            _finding(), {"verdict": "CONFIRMED", "reasoning": "sink verified"})
        self.assertEqual(derived["status"], "advisor_confirmed")
        self.assertEqual(derived["verified_by"], "agent:advisor")
        self.assertEqual(derived["reasoning"], "sink verified")

    def test_rejected_verdict_is_rejected(self):
        derived = ev.derive_evidence(
            _finding(), {"verdict": "REJECTED", "reasoning": "no sink"})
        self.assertEqual(derived["status"], "rejected")

    def test_needs_more_info_verdict(self):
        derived = ev.derive_evidence(
            _finding(), {"verdict": "NEEDS_MORE_INFO", "reasoning": "need config"})
        self.assertEqual(derived["status"], "needs_more_info")
        self.assertEqual(derived["reasoning"], "need config")

    def test_verdict_beats_corroboration(self):
        derived = ev.derive_evidence(
            _finding(corroborated=True, corroborated_by=["security", "database"]),
            {"verdict": "REJECTED", "reasoning": "r"})
        self.assertEqual(derived["status"], "rejected")

    def test_verdict_beats_tool_source(self):
        # P2/#446: precedence inverted. An advisor verdict now outranks
        # tool-sourcing -- the whole point being that an advisor CAN refute a
        # scanner (e.g. Bandit B105 flagging a CSS-class-name string as a
        # "hardcoded password").
        derived = ev.derive_evidence(
            _finding(source="tool:bandit"), {"verdict": "REJECTED"})
        self.assertEqual(derived["status"], "rejected")

    def test_cross_panel_corroborated(self):
        derived = ev.derive_evidence(
            _finding(corroborated=True, corroborated_by=["security", "database"]))
        self.assertEqual(derived["status"], "corroborated")
        self.assertEqual(derived["verified_by"], ["security", "database"])

    def test_reinforced_is_tool_reported(self):
        # A tool+agent same-locus merge is tool-reported by construction
        # (never demoted to mere `corroborated`), but P2/#446 means that alone
        # no longer gates -- it still needs an advisor CONFIRMED verdict to
        # reach tool_confirmed.
        derived = ev.derive_evidence(_finding(reinforced=True))
        self.assertEqual(derived["status"], "tool_reported")
        self.assertEqual(derived["verified_by"], "tool+agent")

    def test_default_is_unverified(self):
        derived = ev.derive_evidence(_finding())
        self.assertEqual(derived["status"], "unverified")
        self.assertIsNone(derived["verified_by"])
        self.assertIsNone(derived["reasoning"])

    def test_never_mutates_severity_or_confidence(self):
        for verdict in (None, {"verdict": "CONFIRMED"}, {"verdict": "REJECTED"},
                        {"verdict": "NEEDS_MORE_INFO"}):
            f = _finding()
            ev.derive_evidence(f, verdict)
            self.assertEqual(f["severity"], "HIGH")
            self.assertEqual(f["confidence"], "POSSIBLE")

    def test_missing_citation_quality_defaults_none(self):
        f = _finding()
        del f["citation_quality"]
        self.assertEqual(ev.derive_evidence(f)["citation_quality"], "none")


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

    def test_status_schema_enum_matches_code(self):
        # Anchor on __file__, not the cwd: a bare relative path assumes the
        # suite runs from the repo root and breaks from anywhere else.
        schema_path = os.path.join(os.path.dirname(__file__), os.pardir,
                                   "skill", "reference", "report-schema.json")
        with open(schema_path, encoding="utf-8") as fh:
            schema = json.load(fh)
        status_enum = (
            schema["properties"]["findings"]["items"]["properties"]["evidence"]
            ["properties"]["status"]["enum"]
        )
        self.assertEqual(set(status_enum), set(ev.EVIDENCE_STATUSES))
        self.assertEqual(len(status_enum), len(ev.EVIDENCE_STATUSES))


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

    def test_synthesize_no_longer_re_exports_evidence(self):
        # WS-0 S1: a name lives in exactly one module -- the entry script
        # dropped its `X = evidence_mod.X` delegation aliases.
        import scripts.synthesize as syn
        for name in ("finding_fingerprint", "tool_rule_id", "load_json_tolerant"):
            self.assertFalse(hasattr(syn, name), name)


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


class TestReconcileKeyCollision(unittest.TestCase):
    """#1034: pin the narrow, acknowledged reconcile_key aliasing the docstring
    now describes honestly (it is NOT the impossibility earlier wording claimed)."""

    def test_code_arm_aliases_panel_code_category_codestring(self):
        a = ev.reconcile_key({"location": {"file": "a.py"}, "code": "COD-A1A"})
        b = ev.reconcile_key({"location": {"file": "a.py"},
                              "panel": "code", "category": "COD-A1A"})
        self.assertEqual(a, b)   # documented coarse match at the same file

    def test_ordinary_panel_does_not_alias_a_code(self):
        a = ev.reconcile_key({"location": {"file": "a.py"}, "code": "SEC-A1A"})
        b = ev.reconcile_key({"location": {"file": "a.py"},
                              "panel": "security", "category": "SEC-A1A"})
        self.assertNotEqual(a, b)   # only panel=="code" can collide


class TestArtifactTerm(unittest.TestCase):
    """#2352: `artifact_term` is the ONE reading of `tool_evidence.package_name`,
    and both identity functions carry it. The manifest proxy (#2225) puts every
    dependency-check finding at `pom.xml:1`, so the ARTIFACT is what tells two
    vulnerable jars sharing one advisory apart."""

    MISSING = object()

    def _f(self, pkg=MISSING, **over):
        f = {"id": "SEC-9", "panel": "security",
             "category": "vulnerable-dependency", "title": "CVE-2021-1",
             "source": "tool:dependency-check",
             "location": {"file": "pom.xml", "line_start": 1},
             "tool_evidence": {"rule_id": "CVE-2021-1"}}
        if pkg is not self.MISSING:
            f["tool_evidence"]["package_name"] = pkg
        f.update(over)
        return f

    def test_only_a_non_empty_string_names_an_artifact(self):
        self.assertEqual(ev.artifact_term(self._f("a.jar")), "a.jar")
        for absent in (self._f(), self._f(""), self._f(None), self._f(["a.jar"]),
                       self._f(0), {}, {"tool_evidence": None},
                       {"tool_evidence": "a.jar"}):
            with self.subTest(finding=absent):
                self.assertIsNone(ev.artifact_term(absent))

    def test_two_jars_at_one_locus_are_two_fingerprints(self):
        self.assertNotEqual(ev.finding_fingerprint(self._f("a.jar")),
                            ev.finding_fingerprint(self._f("b.jar")))

    def test_two_jars_are_two_reconcile_keys_in_both_arms(self):
        self.assertNotEqual(ev.reconcile_key(self._f("a.jar")),
                            ev.reconcile_key(self._f("b.jar")))
        self.assertNotEqual(ev.reconcile_key(self._f("a.jar", code="SEC-A1A")),
                            ev.reconcile_key(self._f("b.jar", code="SEC-A1A")))

    def test_a_finding_naming_no_artifact_keys_exactly_as_before(self):
        # absent-means-unchanged, pinned against the pre-#2352 payload spelled
        # out here rather than against the function that is being changed.
        expected = hashlib.sha256("|".join(
            ["security", "vulnerable-dependency", "pom.xml",
             "CVE-2021-1"]).encode("utf-8")).hexdigest()[:16]
        self.assertEqual(ev.finding_fingerprint(self._f()), expected)
        self.assertEqual(ev.reconcile_key(self._f()),
                         ("pom.xml", "security", "vulnerable-dependency"))

    def test_an_agent_finding_cannot_choose_its_own_artifact(self):
        # #914 guard: `tool_evidence` is not in AGENT_FORBIDDEN_FIELDS and the
        # report schema permits `package_name` on any finding regardless of
        # `source`, so an ungated read would let an agent-authored payload pick
        # part of its own fingerprint -- and with it its queue_id, the advisor
        # verdict it answers to, and the cross-run identity a filed issue is
        # keyed on. Only a tool-sourced finding names an artifact.
        forged = self._f("forged.jar", title="Missing role check")
        clean = self._f(title="Missing role check")
        del forged["source"], clean["source"]
        self.assertIsNone(ev.artifact_term(forged))
        self.assertEqual(ev.finding_fingerprint(forged),
                         ev.finding_fingerprint(clean))
        self.assertEqual(ev.reconcile_key(forged), ev.reconcile_key(clean))
        self.assertEqual(ev.reconcile_key(dict(forged, code="SEC-A1A")),
                         ev.reconcile_key(dict(clean, code="SEC-A1A")))

    def test_a_non_dict_tool_evidence_names_nothing_and_does_not_raise(self):
        # `reconcile.load_report` is a plain json.load with no schema check and
        # `iter_records` calls reconcile_key on every record of a PRIOR run's
        # report read off disk, so one malformed finding there must not abort
        # the reconcile with a traceback.
        agent = {"tool_evidence": "a.jar", "panel": "security",
                 "category": "authz", "title": "t",
                 "location": {"file": "auth.py"}}
        self.assertIsNone(ev.artifact_term(agent))
        self.assertEqual(len(ev.finding_fingerprint(agent)), 16)
        self.assertEqual(ev.reconcile_key(agent), ("auth.py", "security", "authz"))
        self.assertEqual(ev.reconcile_key(dict(agent, code="SEC-A1A")),
                         ("auth.py", "code", "SEC-A1A"))
        # On a TOOL finding the tool-sourcing gate does not short-circuit, so
        # the isinstance guard is the only thing standing between a malformed
        # `tool_evidence` and an AttributeError out of reconcile_key.
        tool = dict(agent, source="tool:dependency-check")
        self.assertIsNone(ev.artifact_term(tool))
        # ...and #2359: finding_fingerprint reads the rule id too, so the same
        # payload must survive that identity as well as this one.
        self.assertEqual(len(ev.finding_fingerprint(tool)), 16)
        self.assertEqual(ev.reconcile_key(tool), ("auth.py", "security", "authz"))
        self.assertEqual(ev.reconcile_key(dict(tool, code="SEC-A1A")),
                         ("auth.py", "code", "SEC-A1A"))

    def test_an_empty_package_name_keys_like_no_package_name_at_all(self):
        bare, empty = self._f(), self._f("")
        self.assertEqual(ev.finding_fingerprint(bare),
                         ev.finding_fingerprint(empty))
        self.assertEqual(ev.reconcile_key(bare), ev.reconcile_key(empty))


class TestMalformedToolEvidence(unittest.TestCase):
    """#2359: nothing validates a report read off disk -- `reconcile.load_report`
    is a plain json.load -- so a stored finding's `tool_evidence` or `provenance`
    can be a non-dict, and `iter_records` fingerprints EVERY record of a prior
    run. One guarded reader stands behind both reads, so a malformed finding
    names no rule instead of aborting the reconcile with an AttributeError."""

    def _f(self, **over):
        f = {"id": "SEC-1", "panel": "security", "category": "injection",
             "title": "t", "source": "tool:bandit",
             "location": {"file": "a.py"}}
        f.update(over)
        return f

    def test_a_non_dict_tool_evidence_still_falls_through_to_provenance(self):
        f = self._f(tool_evidence="x",
                    provenance={"confirmation_reasoning": "B105"})
        self.assertEqual(ev.tool_rule_id(f), "B105")
        fp = ev.finding_fingerprint(f)
        self.assertEqual(len(fp), 16)
        self.assertTrue(all(c in "0123456789abcdef" for c in fp))
        self.assertEqual(ev.reconcile_key(f), ("a.py", "security", "injection"))
        # the SARIF rule is the discriminator, exactly as on a well-formed payload
        self.assertEqual(fp, ev.finding_fingerprint(
            self._f(tool_evidence={"rule_id": "B105"})))

    def test_a_rule_id_nowhere_readable_is_no_rule_and_no_raise(self):
        for f in (self._f(tool_evidence="x", provenance="x"),
                  self._f(tool_evidence={}, provenance=["x"]),
                  self._f(tool_evidence={"package_name": "a.jar"})):
            with self.subTest(finding=f):
                self.assertIsNone(ev.tool_rule_id(f))
                self.assertEqual(len(ev.finding_fingerprint(f)), 16)

    def test_the_reader_passes_a_dict_through_and_maps_everything_else_to_empty(self):
        te = {"rule_id": "B105"}
        self.assertIs(ev._tool_evidence({"tool_evidence": te}), te)
        for bad in (None, "x", ["x"], 0):
            with self.subTest(value=bad):
                self.assertEqual(ev._tool_evidence({"tool_evidence": bad}), {})
        self.assertEqual(ev._tool_evidence({}), {})


class TestMalformedLocation(unittest.TestCase):
    """#2365: `load_report` is a plain `json.load`, so a stored finding's
    `location` can be any JSON value. A non-dict must key exactly like an absent
    one instead of aborting the caller on `.get`."""

    def test_the_reader_passes_a_dict_through_and_maps_everything_else_to_empty(self):
        loc = {"file": "a.py", "line_start": 3}
        self.assertIs(ev.location_of({"location": loc}), loc)
        for bad in (None, "a.py", ["a.py"], 7):
            with self.subTest(value=bad):
                self.assertEqual(ev.location_of({"location": bad}), {})
        self.assertEqual(ev.location_of({}), {})

    def test_a_string_location_keys_exactly_like_no_location_at_all(self):
        absent = _finding(source="tool:bandit")
        absent.pop("location")
        for fn in (ev.finding_fingerprint, ev.matrix_finding_id, ev.reconcile_key,
                   ev._queue_tiebreak):
            with self.subTest(function=fn.__name__):
                self.assertEqual(fn(_finding(source="tool:bandit", location="a.py")),
                                 fn(absent))


class TestOneReaderPerGuardedKey(unittest.TestCase):
    """#2365: `tool_evidence` and `location` are both read off an unvalidated
    stored report, and the unguarded idiom recurred four times for `location`
    after #2359 fixed it for `tool_evidence`. So each key has exactly ONE reader
    in `evidence.py`, and this guard fails on every occurrence of the key as a
    constant, in any idiom, except a subscript write.

    It covers `evidence.py` alone. `phases/review.py` and `security_gate.py` keep
    the idiom on adapter-constructed findings, whose `location` is always a dict
    an adapter built, so those are safe by construction; `scripts/file_issues.py`
    -- the other consumer of the same `reconcile.load_report` -- still carries it
    and is tracked as #2372. One layer up, a report whose top level is not an
    object or whose `meta.parts` is not a list still aborts in `load_report`
    itself (#2373)."""

    def _tree(self):
        with open(evidence.__file__, encoding="utf-8") as fh:
            return ast.parse(fh.read())

    def test_each_guarded_key_is_read_inside_its_reader_only(self):
        tree = self._tree()
        for key, reader in (("tool_evidence", "_tool_evidence"),
                            ("location", "location_of")):
            with self.subTest(key=key):
                self.assertEqual(_key_reads(tree, key), {reader})

    def test_the_walker_trips_on_every_read_idiom(self):
        # Must-trip controls: each idiom in its own tiny module, each reporting
        # its own function. A walker that missed one would make the assertion
        # above vacuous for exactly that idiom -- which is how `.pop`,
        # `.setdefault` and `in` went unmodelled in the first cut (#2365).
        for body in ('return x.get("location")', 'return x["location"]["file"]',
                     'return x.pop("location", {})',
                     'return x.setdefault("location", {})',
                     'return "location" in x'):
            with self.subTest(idiom=body):
                self.assertEqual(
                    _key_reads(ast.parse("def f(x):\n    " + body + "\n"),
                               "location"), {"f"})

    def test_a_write_is_not_a_read(self):
        self.assertEqual(
            _key_reads(ast.parse('def h(q, v):\n    q["location"] = v\n'),
                       "location"), set())


class TestReportSectionPartition(unittest.TestCase):
    """#1774 (ARC-3073755386): `evidence_sections` owns which statuses the report
    calls verified and which ones it collapses. Both sets are CLOSED and the
    three of them partition EVIDENCE_STATUSES, so a status added to that tuple
    cannot join either set (or the main list) by default."""

    def _sections(self):
        import scripts.evidence_sections as sections
        return sections

    def test_the_three_sets_partition_every_known_status(self):
        sections = self._sections()
        named = (list(sections.VERIFIED_STATUSES) + list(sections.UNVERIFIED_STATUSES)
                 + list(sections.MAIN_LIST_STATUSES))
        self.assertEqual(sorted(named), sorted(ev.EVIDENCE_STATUSES))

    def test_is_verified_is_the_headers_word_not_the_split(self):
        sections = self._sections()
        for status in ev.EVIDENCE_STATUSES:
            with self.subTest(status=status):
                self.assertEqual(sections.is_verified(status),
                                 status in sections.VERIFIED_STATUSES)
        # #1638 P16: a second opinion could not look, so the header's word does
        # not apply -- and the finding still belongs in the main list.
        self.assertFalse(sections.is_verified(ev.BACKUP_SCOPE_LIMITED))
        self.assertFalse(sections.is_unverified(ev.BACKUP_SCOPE_LIMITED))

    def test_is_unverified_fails_closed_outside_the_known_statuses(self):
        sections = self._sections()
        self.assertTrue(sections.is_unverified(None))
        self.assertTrue(sections.is_unverified("some_future_status"))
        self.assertFalse(sections.is_verified(None))
        self.assertFalse(sections.is_verified("some_future_status"))
        for status in ev.EVIDENCE_STATUSES:
            with self.subTest(status=status):
                self.assertEqual(sections.is_unverified(status),
                                 status in sections.UNVERIFIED_STATUSES)

    def test_gate_eligibility_is_a_third_question(self):
        # Not a re-spelling of GATE_ELIGIBLE_DEFAULT: a scope-limited finding
        # gates (the primary CONFIRMED stands) without being called verified.
        sections = self._sections()
        self.assertEqual(set(ev.GATE_ELIGIBLE_DEFAULT),
                         set(sections.VERIFIED_STATUSES) | {ev.BACKUP_SCOPE_LIMITED})


if __name__ == "__main__":
    unittest.main()
