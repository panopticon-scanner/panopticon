"""Every adapter's parse() must yield the normalized finding envelope.

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
import unittest

from scripts import synthesize as syn
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
            self.skipTest("golden corpus not present")
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
        report = syn.build_report(findings, [], "probe-target", "high",
                                  "2026-01-01T00:00:00Z")
        errors, _warnings = syn.validate_report(report)
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
        report = syn.build_report(findings, [], "probe-target", "high",
                                  "2026-01-01T00:00:00Z")
        errors, _warnings = syn.validate_report(report)
        self.assertTrue(errors, "validator accepted a malformed finding")


if __name__ == "__main__":
    unittest.main()
