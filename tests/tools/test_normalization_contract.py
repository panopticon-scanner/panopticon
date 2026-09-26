"""Every adapter's parse() must yield a NARF finding envelope.

NARF -- Normalized Analysis Result Format (`.narf.json`) -- is the shape a
finding takes once it is ours, whatever produced it. This file is the contract.

Per-adapter test files each assert their own slice of the envelope, which means
the assertions drift: a new adapter can ship with a thinner check than its
neighbours and nothing notices. This is the one place that holds EVERY adapter
to the same contract, driven off the registry rather than a hand-kept list, so
adding an adapter without a golden fails here instead of silently going
unverified.

The goldens are real, trimmed tool output captured from targets that actually
produce findings (see tests/goldens/tool-raw/README.md). Hand-written
approximations would defeat the purpose: the contract is that parse() handles
what the tools genuinely emit.

This proves the TRANSFORM. It does not prove the tool can read the target --
that is capability, and it lives in the fixture-image integration tests
(tests/tools/test_*_integration.py), because a scanner that reads nothing and
exits 0 still parses perfectly (#1457).
"""
import json
import os
import tempfile
import types
import unittest

from _test_helpers import only, skip_or_fail

import scripts.phases.evidence_scope as evidence_scope
import scripts.synth.findings as findings_mod
import scripts.synth.report as report_mod
import scripts.tools.base as base
import scripts.tools.sarif_utils as sarif_utils
from scripts.tools import ADAPTERS

_HERE = os.path.dirname(os.path.abspath(__file__))
GOLDEN_DIR = os.path.join(os.path.dirname(_HERE), "goldens", "tool-raw")
_SCHEMA = os.path.join(os.path.dirname(os.path.dirname(_HERE)),
                       "skill", "reference", "report-schema.json")


def _schema_enums():
    """Severity/confidence/panel enums, read from the report schema itself so
    this test cannot drift away from what the report will actually accept."""
    with open(_SCHEMA, encoding="utf-8") as fh:
        schema = json.load(fh)
    props = schema["properties"]["findings"]["items"]["properties"]
    return ({e for e in props["severity"]["enum"]},
            {e for e in props["confidence"]["enum"]},
            {e for e in props["panel"]["enum"]})


SEVERITIES, CONFIDENCES, PANELS = _schema_enums()

# There are deliberately TWO builders, and this is their intersection.
#
# make_finding() (the 10 dependency/SAST adapters) adds description, impact,
# remediation and references, because those tools report prose the adapter can
# map. sarif_to_findings() (bandit, gitleaks, gosec, semgrep, trivy) does not:
# a SARIF result's message IS the title, so there is no second body to carry,
# and inventing empty strings would be noise rather than data. The report schema
# requires neither, and every downstream reader uses .get().
#
# So this list is what BOTH produce and what downstream actually keys on. Do not
# "unify" the two envelopes by demanding prose the SARIF path cannot supply.
ENVELOPE_KEYS = ("id", "title", "severity", "confidence", "panel", "category",
                 "source", "location", "tool_evidence", "provenance", "_group")

# Present only on the make_finding() path; type-checked when they appear.
OPTIONAL_TEXT = ("description", "impact", "remediation")

# #1829 (SEC-4277410777, SEC-798292895, SEC-2200312865; #2069, the residual of
# #1752): every string in the envelope is built from text a TARGET or its
# scanner wrote, and the terminal summary prints several of them, so no field
# may carry a live control byte and none may be unbounded. Asserted here, over
# the registry, so one rule holds every present and future adapter.
#
# `\n` and `\t` stay legal in the prose fields -- they are the body's own
# structure, and `render_summary` collapses them where it renders a label.
HAZARDS = frozenset(chr(o) for o in
                    list(range(0x00, 0x20)) + [0x7f]
                    + list(range(0x80, 0xa0)) + [0x2028, 0x2029])
HOSTILE = "ok\x1b[2J\x1b[H** clean **\x07\x00\x7f\x9b\u2028 "


def _live_control_bytes(text, allow=""):
    return sorted({"0x%02x" % ord(ch) for ch in text
                   if ch in HAZARDS and ch not in allow})


def _strings(where, value):
    """Every string leaf under `value`, each with the path that reached it."""
    if isinstance(value, str):
        yield where, value
    elif isinstance(value, dict):
        for key in sorted(value, key=str):
            yield from _strings("%s.%s" % (where, key), value[key])
    elif isinstance(value, (list, tuple)):
        for index, val in enumerate(value):
            yield from _strings("%s[%d]" % (where, index), val)


def golden_path(name):
    return os.path.join(GOLDEN_DIR, "%s.raw" % name)


class TestGoldenCoverage(unittest.TestCase):
    def test_every_registered_adapter_has_a_golden(self):
        # The guard that keeps this suite honest as adapters are added.
        missing = sorted(n for n in ADAPTERS if not os.path.isfile(golden_path(n)))
        self.assertEqual(
            missing, [],
            "no captured tool output for %s -- add one with the capture script "
            "in tests/goldens/tool-raw/README.md so its parse() is covered "
            "like every other adapter's" % ", ".join(missing))

    def test_goldens_have_no_orphans(self):
        # A golden for an adapter that no longer exists is dead weight that
        # reads as coverage.
        if not os.path.isdir(GOLDEN_DIR):
            skip_or_fail(self, "golden corpus not present")
        orphans = sorted(f[:-4] for f in os.listdir(GOLDEN_DIR)
                         if f.endswith(".raw") and f[:-4] not in ADAPTERS)
        self.assertEqual(orphans, [], "goldens with no registered adapter: %s"
                         % ", ".join(orphans))


class TestNormalizationContract(unittest.TestCase):
    """One subtest per adapter, so a failure names the adapter that broke."""

    def test_every_adapter_normalizes_its_real_output(self):
        for name in sorted(ADAPTERS):
            adapter = ADAPTERS[name]
            path = golden_path(name)
            if not os.path.isfile(path):
                continue          # TestGoldenCoverage owns that failure
            with self.subTest(adapter=name):
                with open(path, "rb") as fh:
                    raw = fh.read()
                findings = adapter.parse(raw, "Probe")
                self.assertTrue(
                    findings,
                    "%s parsed real tool output into ZERO findings -- the "
                    "golden holds findings, so the transform dropped them" % name)
                for f in findings:
                    self._assert_normalized(name, adapter, f)

    def _assert_normalized(self, name, adapter, f):
        for key in ENVELOPE_KEYS:
            self.assertIn(key, f, "%s: finding is missing %r" % (name, key))

        self.assertIn(f["severity"], SEVERITIES,
                      "%s: severity %r is not in the report schema's enum"
                      % (name, f["severity"]))
        self.assertIn(f["confidence"], CONFIDENCES,
                      "%s: confidence %r is not in the report schema's enum"
                      % (name, f["confidence"]))
        self.assertIn(f["panel"], PANELS,
                      "%s: panel %r is not in the report schema's enum"
                      % (name, f["panel"]))

        # Provenance: a finding must say which tool produced it, in both the
        # human-facing field and the machine-facing one, and agree with itself.
        self.assertEqual(f["source"], "tool:%s" % adapter.name,
                         "%s: source does not name its own adapter" % name)
        self.assertTrue(str(f["id"]).startswith(adapter.prefix),
                        "%s: finding id %r does not carry the adapter's prefix %r"
                        % (name, f["id"], adapter.prefix))

        # Location is what routes a finding to a review group and a diff hunk;
        # a finding without it cannot be placed.
        loc = f["location"]
        self.assertIsInstance(loc, dict, "%s: location is not an object" % name)
        self.assertTrue(loc.get("file"), "%s: location.file is empty" % name)
        self.assertIsInstance(loc.get("line_start"), int,
                              "%s: location.line_start is not an int" % name)
        self.assertGreaterEqual(loc["line_start"], 0,
                                "%s: negative line_start" % name)

        # Text fields carry untrusted tool/target content and are sanitized on
        # the way in; they must at least be strings by the time they land.
        for key in ("title", "category"):
            self.assertIsInstance(f[key], str, "%s: %s is not a string" % (name, key))
        for key in OPTIONAL_TEXT:
            if key in f:
                self.assertIsInstance(f[key], str,
                                      "%s: %s is present but not a string" % (name, key))
        if "references" in f:
            self.assertIsInstance(f["references"], list,
                                  "%s: references is not a list" % name)
        self.assertIsInstance(f["tool_evidence"], dict,
                              "%s: tool_evidence is not an object" % name)
        # Provenance is what lets synthesize attribute a finding to its tool.
        self.assertIsInstance(f["provenance"], dict,
                              "%s: provenance is not an object" % name)
        self.assertEqual(f["provenance"].get("discovered_by"), "tool:%s" % adapter.name,
                         "%s: provenance does not name its own adapter" % name)
        # Citations are optional, but when present must be lists per scheme --
        # synthesize iterates them.
        for scheme, vals in (f.get("citations") or {}).items():
            self.assertIsInstance(vals, list,
                                  "%s: citations.%s is not a list" % (name, scheme))

        self._assert_inert(name, f)

    def _assert_inert(self, name, f):
        """No field of the envelope carries a live control byte, and the
        neutralized ones are bounded (#1829 / #2069)."""
        for key, value in sorted(f.items()):
            allow = "\n\t" if key in OPTIONAL_TEXT else ""
            bound = (base.INERT_BODY_MAX if key in OPTIONAL_TEXT
                     else base.INERT_TEXT_MAX) + len(base.INERT_CUT)
            for where, text in _strings(key, value):
                self.assertEqual(
                    [], _live_control_bytes(text, allow),
                    "%s: %s carries live control bytes %s -- tool and target "
                    "text must be inert before it reaches the summary or the "
                    "artifact" % (name, where, _live_control_bytes(text, allow)))
                if key in ("title", "category") or key in OPTIONAL_TEXT:
                    self.assertLessEqual(
                        len(text), bound,
                        "%s: %s is %d chars -- unbounded target text"
                        % (name, where, len(text)))


class TestHostileToolTextIsInert(unittest.TestCase):
    """#1829 SEC-4277410777 / #2069: the contract above rides on goldens, which
    are honest tool output. This is the same contract under a HOSTILE one.

    Driven at the two ENVELOPE BUILDERS rather than per adapter, because every
    adapter reaches the envelope through one of them -- which the contract above
    proves for each of them (the id prefix and the provenance block are the
    builders' own work, so a finding carrying them came through a builder). Pin
    the builders and every present and future adapter is pinned with them.
    """

    ADAPTER = types.SimpleNamespace(prefix="XX", name="demo")

    RULE = "r\x1b[31m1"

    def _hostile_sarif(self, rule_id=RULE, message=HOSTILE):
        """A one-result SARIF whose every target-authored string is hostile.
        Parameterized rather than reached into, so no test indexes the fixture
        it just built (TST-B3A's rule)."""
        result = {"message": {"text": message},
                  "locations": [{"physicalLocation": {
                      "artifactLocation": {"uri": "/src/a\x1b[2Kb.py"},
                      "region": {"startLine": 3}}}]}
        if rule_id is not None:
            result["ruleId"] = rule_id
        return {"runs": [{"tool": {"driver": {"name": "semgrep", "rules": [
            {"id": self.RULE, "defaultConfiguration": {"level": "error"}}]}},
            "results": [result]}]}

    def _assert_no_live_bytes(self, finding):
        for key, value in sorted(finding.items()):
            allow = "\n\t" if key in OPTIONAL_TEXT else ""
            for where, text in _strings(key, value):
                self.assertEqual([], _live_control_bytes(text, allow),
                                 "%s still carries %s" % (where, repr(text)))

    def test_the_sarif_builder_neutralizes_every_field_it_fills(self):
        f = only(sarif_utils.sarif_to_findings(
            self._hostile_sarif(), "semgrep", "G", "SEC"))
        self._assert_no_live_bytes(f)
        # Escaped, not deleted: the ESC is the evidence that someone tried.
        self.assertEqual(r"ok\x1b[2J\x1b[H** clean **\x07\x00\x7f\x9b\u2028",
                         f["title"])
        self.assertEqual(r"r\x1b[31m1", f["category"])
        self.assertEqual(r"a\x1b[2Kb.py", f["location"]["file"])
        self.assertEqual(r"r\x1b[31m1", f["tool_evidence"]["rule_id"])
        self.assertEqual(r"r\x1b[31m1", f["provenance"]["confirmation_reasoning"])

    def test_the_make_finding_builder_neutralizes_every_field_it_fills(self):
        f = base.make_finding(
            self.ADAPTER, 1, "G", title=HOSTILE, severity="HIGH",
            category="c\x1b[31m", location={"file": "a\x1b[2Kb.py", "line_start": 1},
            description=HOSTILE, impact=HOSTILE, remediation=HOSTILE,
            tool_evidence={"rule_id": "r\x1b[31m1"})
        self._assert_no_live_bytes(f)
        self.assertEqual(r"ok\x1b[2J\x1b[H** clean **\x07\x00\x7f\x9b\u2028",
                         f["title"])
        self.assertEqual(r"a\x1b[2Kb.py", f["location"]["file"])

    def test_both_builders_bound_an_unbounded_message(self):
        # A SARIF `message.text` is unbounded inside the 50 MiB ingest cap.
        huge = "A" * (base.INERT_TEXT_MAX * 3)
        for what, f in (("sarif", only(sarif_utils.sarif_to_findings(
                            self._hostile_sarif(message=huge),
                            "semgrep", "G", "SEC"))),
                        ("make_finding", base.make_finding(
                            self.ADAPTER, 1, "G", title=huge, severity="HIGH",
                            category="c", location={"file": "a", "line_start": 1},
                            description="d", impact="", remediation=""))):
            with self.subTest(builder=what):
                self.assertEqual(base.INERT_TEXT_MAX + len(base.INERT_CUT),
                                 len(f["title"]))
                self.assertTrue(f["title"].endswith(base.INERT_CUT),
                                "a truncated title must say that it was cut")

    def test_a_result_without_a_rule_id_keeps_a_null_rule_id(self):
        # `evidence.tool_rule_id` falls back to provenance.confirmation_reasoning,
        # so a neutralizer that turned None into the string "None" would forge a
        # rule id -- and with it the finding's fingerprint.
        f = only(sarif_utils.sarif_to_findings(
            self._hostile_sarif(rule_id=None), "semgrep", "G", "SEC"))
        self.assertIsNone(f["tool_evidence"]["rule_id"])
        self.assertEqual("Reported by static-analysis tool semgrep",
                         f["provenance"]["confirmation_reasoning"])
        self.assertEqual("tool", f["category"])


class TestLegitimatePathsSurviveByteForByte(unittest.TestCase):
    """Fix round 1, finding 1: neutralizing a path must not REWRITE it.

    The first cut sent `location.file` through the label form, whose
    `" ".join(text.split())` splits on every Unicode space -- so `src/a  b.py`,
    a macOS `Screen\u202fShot.png`, an NBSP or a U+3000 name came out renamed.
    Nothing hostile is needed to trigger it, and the consumers that resolve
    `location.file` on disk (`evidence_scope._usable`, the advisor's read
    grant) or by equality (`grading`'s group-file attribution, `plan`'s
    off-plan diagnostic) silently miss the file.
    """

    REAL_NAMES = ("src/a  b.py", "Screen\u202fShot.png", "doc/\xa0nbsp.py",
                  "a\u3000b.py")

    def _sarif(self, uri):
        return {"runs": [{"tool": {"driver": {"name": "semgrep", "rules": []}},
                          "results": [{"ruleId": "r1", "message": {"text": "m"},
                                       "locations": [{"physicalLocation": {
                                           "artifactLocation": {"uri": "/src/" + uri},
                                           "region": {"startLine": 1}}}]}]}]}

    def test_the_sarif_builder_keeps_the_path_it_was_given(self):
        for name in self.REAL_NAMES:
            with self.subTest(name=name):
                f = only(sarif_utils.sarif_to_findings(
                    self._sarif(name), "semgrep", "G", "SEC"))
                self.assertEqual(name, f["location"]["file"])

    def test_make_finding_keeps_the_path_it_was_given(self):
        adapter = types.SimpleNamespace(prefix="XX", name="demo")
        for name in self.REAL_NAMES:
            with self.subTest(name=name):
                f = base.make_finding(
                    adapter, 1, "G", title="t", severity="HIGH", category="c",
                    location={"file": name, "line_start": 1}, description="d",
                    impact="", remediation="")
                self.assertEqual(name, f["location"]["file"])

    def test_the_advisor_s_read_grant_still_resolves_the_file(self):
        # The consumer, not a proxy for it: `_usable` is what decides whether
        # the file a claim is about may be read.
        with tempfile.TemporaryDirectory() as root:
            for name in self.REAL_NAMES:
                with self.subTest(name=name):
                    full = os.path.join(root, *name.split("/"))
                    os.makedirs(os.path.dirname(full), exist_ok=True)
                    with open(full, "w", encoding="utf-8") as fh:
                        fh.write("x\n")
                    f = only(sarif_utils.sarif_to_findings(
                        self._sarif(name), "semgrep", "G", "SEC"))
                    self.assertEqual(
                        name, evidence_scope._usable(root, f["location"]["file"]),
                        "the advisor cannot read the file the finding is about")

    def test_a_control_char_in_a_path_is_still_neutralized(self):
        f = only(sarif_utils.sarif_to_findings(
            self._sarif("a\x1b[2Kb\tc.py"), "semgrep", "G", "SEC"))
        self.assertEqual(r"a\x1b[2Kb\x09c.py", f["location"]["file"])
        self.assertEqual([], _live_control_bytes(f["location"]["file"]))


class TestFindingsSurviveIntoAReport(unittest.TestCase):
    """The last link: normalized findings must produce a VALID report.

    The contract above checks each finding in isolation. This puts every
    adapter's output through the real report builder and the real validator
    together, which is the claim that actually matters -- that a scan mixing all
    fifteen tools yields an artifact the schema accepts, not fifteen shapes that
    each look fine alone.
    """

    def _all_findings(self):
        findings = []
        for name in sorted(ADAPTERS):
            path = golden_path(name)
            if os.path.isfile(path):
                with open(path, "rb") as fh:
                    findings.extend(ADAPTERS[name].parse(fh.read(), "Probe"))
        return findings

    def test_every_adapters_findings_validate_in_one_report(self):
        findings = self._all_findings()
        self.assertGreater(len(findings), 30,
                           "expected findings from every adapter's golden")
        report = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(
                target="probe-target",
                fail_on="high",
                timestamp="2026-01-01T00:00:00Z",
            ),
            findings=findings_mod.FindingSet(findings=findings),
        ))
        errors, _warnings = report_mod.validate_report(report)
        self.assertEqual(
            errors, [],
            "findings from real tool output failed the report schema: %s"
            % "; ".join(errors[:10]))

    def test_the_validator_would_have_caught_a_bad_finding(self):
        # Guards the test above: prove the validator is actually looking, so a
        # green result means "valid", not "unchecked".
        findings = self._all_findings()
        self.assertGreater(len(findings), 0, "no goldens parsed; nothing to corrupt")
        findings[0] = dict(findings[0], id="not-a-valid-id", title="")
        report = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(
                target="probe-target",
                fail_on="high",
                timestamp="2026-01-01T00:00:00Z",
            ),
            findings=findings_mod.FindingSet(findings=findings),
        ))
        errors, _warnings = report_mod.validate_report(report)
        self.assertTrue(errors, "validator accepted a malformed finding")


if __name__ == "__main__":
    unittest.main()
