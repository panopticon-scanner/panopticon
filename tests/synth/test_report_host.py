"""Host capability loading and report metadata contracts."""

import contextlib
import io
import os
import json
import tempfile
import unittest
import scripts.synthesize as syn
import scripts.synth.findings as findings_mod
import scripts.synth.report as report_mod
import scripts.hosts as hosts_mod
from tests.synth.helpers import _chdir


class TestSynthesizeLoadsHostCapabilities(unittest.TestCase):
    """synthesize.py's own artifact read: dirname(--groups)/host-capabilities.json,
    beside groups.json (F3a's write location) -- the part of Task 4 that lives
    outside report.py and so isn't exercised by TestHostCapabilitiesMeta at all.
    """

    def _run(self, d, groups_extra_files=(), out_name="report.json"):
        gj = os.path.join(d, "groups.json")
        with open(gj, "w") as fh:
            json.dump({"mode": "repo", "groups": [{"name": "g1", "files": ["a.py"]}]}, fh)
        fpath = os.path.join(d, "findings-g1-code.json")
        with open(fpath, "w") as fh:
            json.dump({"findings": []}, fh)
        for name, content in groups_extra_files:
            with open(os.path.join(d, name), "w") as fh:
                fh.write(content)
        out = os.path.join(d, out_name)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            syn.main(["--target", "src", "--groups", gj, "--out", out, fpath])
        with open(out) as fh:
            return json.load(fh)

    def test_reads_the_artifact_beside_groups_json(self):
        env = {"schema_version": 1, "host": "claude", "probed_at": "T",
              "capabilities": {hosts_mod.TOOL_POLICY_ENFORCED:
                               {"state": hosts_mod.REFUTED, "by": "shadow-shell-scan",
                                "detail": "ships panopticon-scout.md"},
                               hosts_mod.ARTIFACT_WRITE_GUARD:
                               {"state": hosts_mod.PROVEN, "by": "write-guard-armed",
                                "detail": "round-trip denied"}}}
        with tempfile.TemporaryDirectory() as d:
            report = self._run(d, [("host-capabilities.json", json.dumps(env))])
        hc = report["meta"]["host_capabilities"]
        self.assertEqual("claude", hc["host"])
        self.assertEqual(env["capabilities"], hc["capabilities"])

    def test_missing_artifact_reads_as_nobody_looked(self):
        with tempfile.TemporaryDirectory() as d:
            report = self._run(d)
        hc = report["meta"]["host_capabilities"]
        self.assertIsNone(hc["host"])
        self.assertEqual({}, hc["capabilities"])

    def test_corrupt_json_reads_as_nobody_looked_not_a_crash(self):
        # Truncated mid-write is the realistic corruption shape for an
        # artifact another process is writing concurrently.
        with tempfile.TemporaryDirectory() as d:
            report = self._run(d, [("host-capabilities.json", '{"host": "claude", "cap')])
        hc = report["meta"]["host_capabilities"]
        self.assertIsNone(hc["host"])
        self.assertEqual({}, hc["capabilities"])

    def test_a_json_array_artifact_reads_as_nobody_looked_not_a_crash(self):
        # json.load succeeds on any valid JSON document, not just objects --
        # the isinstance guard is what stops a bare array from propagating.
        with tempfile.TemporaryDirectory() as d:
            report = self._run(d, [("host-capabilities.json", "[1, 2, 3]")])
        hc = report["meta"]["host_capabilities"]
        self.assertIsNone(hc["host"])
        self.assertEqual({}, hc["capabilities"])


def _hc_envelope(host="claude"):
    """A MIXED host-capabilities.json body: one proven, one refuted, three
    unknown, each on a different capability (plan Global Constraints). An
    all-proven or all-unknown fixture would pass a loader that dropped a
    capability."""
    return {
        "schema_version": 1, "host": host, "probed_at": "T",
        "capabilities": {
            hosts_mod.TOOL_POLICY_ENFORCED: {
                "state": hosts_mod.REFUTED, "by": "shadow-shell-scan",
                "detail": "ships panopticon-scout.md"},
            hosts_mod.ARTIFACT_WRITE_GUARD: {
                "state": hosts_mod.PROVEN, "by": "write-guard-armed",
                "detail": "round-trip denied"},
            hosts_mod.USAGE_LEDGER: {
                "state": hosts_mod.UNKNOWN, "by": None,
                "detail": "no transcript directory"},
            hosts_mod.READ_SCOPE_CONFINED: {
                "state": hosts_mod.UNKNOWN, "by": None,
                "detail": "claude proves this since plan 5; other hosts do not claim it"},
            hosts_mod.MODEL_BINDING: {
                "state": hosts_mod.UNKNOWN, "by": None,
                "detail": "model=None until F4 binds them"},
        },
    }


class TestHostCapabilitiesResolvesUnderTheRunDir(unittest.TestCase):
    """`host-capabilities.json` is a RUN artifact and resolves under `run_dir`,
    like groups.json, the dispatch plans, the verify queue and the tools
    manifest.

    TestSynthesizeLoadsHostCapabilities above always passes `--groups`, and
    `--groups` is the single invocation shape in which `dirname(--groups)` and
    `run_dir` agree -- so its fixture cannot express this at all. These three
    exercise the shapes where they diverge: the auto-discovered groups path, an
    explicit `--run-dir`, and the directory ABOVE the cwd (which
    `dirname(abspath(args.groups or "."))` resolved to, and which for the
    synthesize child -- `cwd=review_root` -- is the parent of the reviewed
    tree).
    """

    def _seed_run(self, run_dir, envelope=None):
        os.makedirs(run_dir, exist_ok=True)
        with open(os.path.join(run_dir, "groups.json"), "w") as fh:
            json.dump({"mode": "repo", "groups": [{"name": "g1", "files": ["a.py"]}]}, fh)
        if envelope is not None:
            with open(os.path.join(run_dir, "host-capabilities.json"), "w") as fh:
                json.dump(envelope, fh)

    def _synth(self, argv):
        """Run synthesize in the CURRENT directory and return the report."""
        with open("findings-g1-code.json", "w") as fh:
            json.dump({"findings": []}, fh)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            syn.main(argv + ["findings-g1-code.json"])
        with open("report.json") as fh:
            return json.load(fh)

    def test_without_groups_it_reads_beside_the_discovered_groups_json(self):
        with tempfile.TemporaryDirectory() as parent:
            tree = os.path.join(parent, "tree")
            os.makedirs(tree)
            self._seed_run(os.path.join(tree, ".panopticon"), _hc_envelope())
            with _chdir(tree):
                report = self._synth(["--target", "src", "--out", "report.json"])
        hc = report["meta"]["host_capabilities"]
        self.assertEqual("claude", hc["host"])
        self.assertEqual(_hc_envelope()["capabilities"], hc["capabilities"])

    def test_run_dir_names_the_directory_the_artifact_comes_from(self):
        with tempfile.TemporaryDirectory() as parent:
            tree = os.path.join(parent, "tree")
            run = os.path.join(tree, ".panopticon", "runs", "claude-redteam-repo-x")
            self._seed_run(run, _hc_envelope())
            with _chdir(tree):
                report = self._synth(["--target", "src", "--run-dir", run,
                                      "--out", "report.json"])
        hc = report["meta"]["host_capabilities"]
        self.assertEqual("claude", hc["host"])
        self.assertEqual(_hc_envelope()["capabilities"], hc["capabilities"])

    def test_an_artifact_in_the_parent_of_the_cwd_is_never_read(self):
        # The reviewed tree's PARENT is not a run directory and nothing in it
        # is a run artifact. A file planted there is another project's, or an
        # attacker's -- either way reading it fabricates a posture for this run.
        forged = {"schema_version": 1, "host": "PLANTED-FROM-PARENT-DIR",
                  "probed_at": "T",
                  "capabilities": {hosts_mod.TOOL_POLICY_ENFORCED: {
                      "state": hosts_mod.PROVEN, "by": "forged",
                      "detail": "planted in the parent directory"}}}
        with tempfile.TemporaryDirectory() as parent:
            tree = os.path.join(parent, "tree")
            self._seed_run(os.path.join(tree, ".panopticon"))   # no artifact of its own
            with open(os.path.join(parent, "host-capabilities.json"), "w") as fh:
                json.dump(forged, fh)
            with _chdir(tree):
                report = self._synth(["--target", "src", "--out", "report.json"])
        hc = report["meta"]["host_capabilities"]
        self.assertIsNone(hc["host"])
        self.assertEqual({}, hc["capabilities"])


class TestHostCapabilitiesMeta(unittest.TestCase):
    """meta.host_capabilities: 5.1 surface 2 -- the artifact's `capabilities`
    map VERBATIM (state + by + detail), plus the host, so a consumer can diff
    posture across runs without re-deriving it.

    Test-helper note: the plan's brief called for a `self._build(host_capabilities=...)`
    helper that does not exist in this class. `TestEvidenceReport._report`
    (in test_report_evidence.py) is close but requires `findings` first and has no
    `host_capabilities` parameter; ~15 other tests already depend on its exact
    signature. Rather than retrofit a parameter only this class needs, this
    class gets its own minimal `_build`, matching the brief's call shape
    (`self._build(host_capabilities=env)`) with an empty findings set --
    meta.host_capabilities does not depend on the findings axis at all.
    """

    def _build(self, host_capabilities):
        return report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(
                target="target",
                fail_on="high",
                timestamp="2026-08-03T00:00:00Z",
                host_capabilities=host_capabilities,
            ),
            findings=findings_mod.FindingSet(findings=[]),
        ))

    def test_meta_carries_the_posture_verbatim(self):
        # Mixed on purpose (plan Global Constraints): a surface that
        # hard-codes one capability's shape passes an all-proven or
        # all-unknown fixture and fails to catch it. All five capabilities
        # present, spread across three different states -- proven, refuted,
        # unknown, each on a different capability.
        caps = {
            hosts_mod.TOOL_POLICY_ENFORCED: {"state": hosts_mod.REFUTED,
                                             "by": "shadow-shell-scan",
                                             "detail": "ships panopticon-scout.md"},
            hosts_mod.ARTIFACT_WRITE_GUARD: {"state": hosts_mod.PROVEN,
                                             "by": "write-guard-armed",
                                             "detail": "round-trip denied"},
            hosts_mod.USAGE_LEDGER: {"state": hosts_mod.UNKNOWN,
                                     "by": None,
                                     "detail": "no transcript directory"},
            hosts_mod.READ_SCOPE_CONFINED: {"state": hosts_mod.UNKNOWN,
                                            "by": None,
                                            "detail": "claude proves this since plan 5; other hosts do not claim it"},
            hosts_mod.MODEL_BINDING: {"state": hosts_mod.UNKNOWN,
                                      "by": None,
                                      "detail": "model=None until F4 binds them"},
        }
        env = {"schema_version": 1, "host": "claude",
               "probed_at": "2026-09-11T04:05:06Z", "capabilities": caps}
        report = self._build(host_capabilities=env)
        hc = report["meta"]["host_capabilities"]
        self.assertEqual("claude", hc["host"])
        # verbatim: the REASON survives, not just the verdict -- by/detail
        # included, nothing re-keyed, nothing summarised.
        self.assertEqual(env["capabilities"], hc["capabilities"])
        # ...and WHEN, and in which schema. 5.2 re-probes on every invocation
        # precisely because setup-time-only evidence is unbounded in age; a
        # consumer that cannot read the probe time cannot tell a posture
        # measured at this invocation from a stale one. `meta.timestamp` does
        # not answer it -- that is SYNTHESIS time, which on a resumed run is a
        # different moment from the probe.
        self.assertEqual("2026-09-11T04:05:06Z", hc["probed_at"])
        self.assertEqual(1, hc["schema_version"])

    def test_meta_says_nobody_looked_when_the_artifact_is_absent(self):
        # synthesize.py's own absent/corrupt-artifact branch normalises to
        # {} -- this is what a RunConfig sees when nobody looked.
        report = self._build(host_capabilities={})
        hc = report["meta"]["host_capabilities"]
        self.assertIsNone(hc["host"])
        self.assertEqual({}, hc["capabilities"])
        # None, not a fabricated "now": a probe time nobody recorded must not
        # read as a probe that happened.
        self.assertIsNone(hc["probed_at"])
        self.assertIsNone(hc["schema_version"])

    def test_meta_fails_closed_on_a_non_dict_artifact(self):
        # The artifact is a file on disk and therefore untrusted: a
        # truncated or tampered host-capabilities.json can deserialize to
        # any JSON shape, not just an object. This must render as "nobody
        # looked", never raise mid-synthesis and never fabricate a posture.
        for bad in ([1, 2, 3], "garbage", 5, None):
            with self.subTest(bad=bad):
                report = self._build(host_capabilities=bad)
                hc = report["meta"]["host_capabilities"]
                self.assertIsNone(hc["host"])
                self.assertEqual({}, hc["capabilities"])
                self.assertIsNone(hc["probed_at"])
                self.assertIsNone(hc["schema_version"])

    def test_meta_fails_closed_when_capabilities_key_is_not_a_dict(self):
        # Isolates the OTHER arm: `host` is a valid, readable string but
        # `capabilities` is garbage. host_disclosure.host_of() never looks at
        # `capabilities`, so the host name still survives verbatim here --
        # only the unusable capabilities value collapses to {}. Without this
        # test, a single shared guard could look correct while actually only
        # covering the host_of() arm.
        bad = {"host": "claude", "capabilities": "not-a-mapping"}
        report = self._build(host_capabilities=bad)
        hc = report["meta"]["host_capabilities"]
        self.assertEqual("claude", hc["host"])
        self.assertEqual({}, hc["capabilities"])
