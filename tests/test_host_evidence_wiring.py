import os
import tempfile
import unittest
from unittest import mock

from scripts import driver, host_probes, hosts, run_manifest
from scripts.phases import runio


class _Args:
    def __init__(self, **kw):
        self.__dict__.update(kw)


class TestThePostureIsEstablishedEveryInvocation(unittest.TestCase):
    """#1344 F3a, spec 5.2: probe on every invocation and compare rather than
    overwrite. Setup-time-only evidence is unbounded in age."""

    def _manifest(self, host="claude", session_dir=None):
        # session_dir is pinned rather than left None on purpose. With None the
        # write-guard probe resolves `.claude/settings.local.json` relative to
        # the CWD pytest happens to run in -- inside this repo it exists, in CI
        # it may not, and the probe's answer would swing with it. Point it at a
        # temp root and the tests measure the code, not the checkout.
        manifest = {"host": host, "run_id": "r1" * 4, "created": "2026-09-10",
                    "security_mode": "standard"}
        if session_dir:
            claude = os.path.join(session_dir, ".claude")
            os.makedirs(claude, exist_ok=True)
            with open(os.path.join(claude, "settings.local.json"), "w",
                      encoding="utf-8") as fh:
                fh.write("{}")
            manifest["session_dir"] = session_dir
        return manifest

    def test_the_first_invocation_writes_the_artifact(self):
        with tempfile.TemporaryDirectory() as review_root:
            manifest = self._manifest(session_dir=review_root)
            err = driver._establish_host_posture(
                review_root, manifest, _Args(target=review_root, session_dir=None))
            self.assertIsNone(err)
            self.assertTrue(runio.host_evidence(review_root))

    def test_a_second_invocation_with_the_same_posture_is_silent(self):
        # Not just "the second call returns None" -- that would also be true of
        # an `_establish_host_posture` that never compared anything. Wrap
        # run_probes so the mock still does the real work, and require it to
        # have been INVOKED again on the second call: a short-circuit that
        # skips re-probing once an artifact exists would leave call_count at 1
        # while still returning None and leaving the artifact unchanged.
        with tempfile.TemporaryDirectory() as review_root:
            manifest = self._manifest(session_dir=review_root)
            args = _Args(target=review_root, session_dir=None)
            with mock.patch.object(host_probes, "run_probes",
                                   wraps=host_probes.run_probes) as probed:
                driver._establish_host_posture(review_root, manifest, args)
                before = runio.host_evidence(review_root)
                self.assertIsNone(
                    driver._establish_host_posture(review_root, manifest, args))
                self.assertEqual(2, probed.call_count)
            self.assertEqual(before, runio.host_evidence(review_root))

    def test_a_posture_that_moved_refuses_and_names_the_capability(self):
        # The 5.2 rule, in the degrading direction: the run's earlier entries
        # were dispatched under a posture that no longer holds.
        with tempfile.TemporaryDirectory() as review_root:
            manifest = self._manifest(session_dir=review_root)
            args = _Args(target=review_root, session_dir=None)
            driver._establish_host_posture(review_root, manifest, args)
            drifted = host_probes.run_probes("claude", review_root)
            drifted["capabilities"][hosts.USAGE_LEDGER]["state"] = (
                hosts.PROVEN if drifted["capabilities"][hosts.USAGE_LEDGER][
                    "state"] != hosts.PROVEN else hosts.REFUTED)
            with mock.patch.object(host_probes, "run_probes",
                                   return_value=drifted):
                err = driver._establish_host_posture(review_root, manifest, args)
            self.assertIsNotNone(err)
            self.assertIn(hosts.USAGE_LEDGER, err)
            self.assertIn("--reset", err)

    def test_an_improving_posture_refuses_too(self):
        # Deliberately blunt in BOTH directions. The operator who registers the
        # missing shells mid-run still has entries already dispatched
        # unenforced; the honest answer is a fresh run, not a silent upgrade.
        #
        # Isolate a PURE improvement: a real `run_probes()` call against a
        # throwaway target incidentally moves usage_ledger from unknown to
        # refuted too (no transcript dir exists for a made-up project), which
        # is a genuine degradation riding along with the intended improvement
        # -- a mutant that refuses on degradation only would pass this test
        # for the wrong reason and never get caught. Copy every OTHER
        # capability's row forward unchanged so tool_policy_enforced's
        # unknown -> proven is the only real difference (artifact_write_guard
        # legitimately also moves unknown -> proven here, which is fine: it is
        # improvement too, not degradation).
        with tempfile.TemporaryDirectory() as review_root:
            manifest = self._manifest(session_dir=review_root)
            args = _Args(target=review_root, session_dir=None)
            first = host_probes.run_probes("claude", review_root)
            for row in first["capabilities"].values():
                row["state"] = hosts.UNKNOWN
                row["by"] = None
            runio._write_json(
                runio._pano(review_root, runio.HOST_CAPABILITIES), first)
            better = host_probes.run_probes("claude", review_root)
            for name, row in better["capabilities"].items():
                if name != hosts.TOOL_POLICY_ENFORCED:
                    row["state"], row["by"] = hosts.UNKNOWN, None
            better["capabilities"][hosts.TOOL_POLICY_ENFORCED]["state"] = hosts.PROVEN
            was = host_probes.capabilities_of(first)
            now = host_probes.capabilities_of(better)
            self.assertEqual(  # the fixture itself must be a PURE improvement
                {hosts.TOOL_POLICY_ENFORCED},
                {k for k in was if was[k] != now.get(k)})
            with mock.patch.object(host_probes, "run_probes",
                                   return_value=better):
                err = driver._establish_host_posture(review_root, manifest, args)
            self.assertIsNotNone(err)
            self.assertIn(hosts.TOOL_POLICY_ENFORCED, err)
            self.assertIn("--reset", err)

    def test_a_shadowed_target_refuses_the_run(self):
        # Spec 7.3, the owner's ruling: refuse, naming the offending path.
        with tempfile.TemporaryDirectory() as review_root:
            d = os.path.join(review_root, ".claude", "agents")
            os.makedirs(d)
            with open(os.path.join(d, "panopticon-scout.md"), "w",
                      encoding="utf-8") as fh:
                fh.write("x")
            err = driver._establish_host_posture(
                review_root, self._manifest(session_dir=review_root),
                _Args(target=review_root, session_dir=None))
            self.assertIsNotNone(err)
            self.assertIn("panopticon-scout.md", err)

    def test_allow_unenforced_downgrades_the_refusal(self):
        # It papers over nothing: the run proceeds with the capability REFUTED,
        # which is stronger than unknown -- the report says plainly it was not
        # enforced rather than quietly forgetting.
        with tempfile.TemporaryDirectory() as review_root:
            d = os.path.join(review_root, ".claude", "agents")
            os.makedirs(d)
            with open(os.path.join(d, "panopticon-scout.md"), "w",
                      encoding="utf-8") as fh:
                fh.write("x")
            manifest = self._manifest(session_dir=review_root)
            manifest["flags"] = {"allow_unenforced": True}
            err = driver._establish_host_posture(
                review_root, manifest, _Args(target=review_root, session_dir=None))
            self.assertIsNone(err)
            evidence = runio.host_evidence(review_root)
            self.assertEqual(
                hosts.REFUTED,
                evidence[hosts.TOOL_POLICY_ENFORCED]["state"])

    def test_the_artifact_lands_under_the_run_folder_not_flat(self):
        # ★ hazard from Task 6 verification: `_pano` falls back to a FLAT
        # `.panopticon/<name>` path when `_run_tag` can't resolve a manifest
        # from DISK. `_establish_host_posture` reads its `manifest` argument
        # from memory, but `_pano` (via `_run_tag`) re-reads
        # run-manifest.json off disk independently -- so this only holds if a
        # real manifest is written to disk before this step runs, exactly as
        # driver.run() does (write_manifest happens well before
        # capture_tree_baseline / this step). Prove it end to end with a real
        # written manifest rather than assuming the insertion point saves us.
        with tempfile.TemporaryDirectory() as review_root:
            manifest = run_manifest.build_manifest(
                target=review_root, review_root=review_root, host="claude",
                security_mode="standard", created="2026-09-10")
            manifest["session_dir"] = review_root
            claude = os.path.join(review_root, ".claude")
            os.makedirs(claude, exist_ok=True)
            with open(os.path.join(claude, "settings.local.json"), "w",
                      encoding="utf-8") as fh:
                fh.write("{}")
            run_manifest.write_manifest(review_root, manifest)
            err = driver._establish_host_posture(
                review_root, manifest, _Args(target=review_root, session_dir=None))
            self.assertIsNone(err)
            tag = run_manifest.run_tag(manifest)
            self.assertIsNotNone(tag)
            expected = os.path.join(review_root, ".panopticon", "runs", tag,
                                    runio.HOST_CAPABILITIES)
            self.assertTrue(os.path.isfile(expected),
                            "expected artifact at %s" % expected)
            flat = os.path.join(review_root, ".panopticon", runio.HOST_CAPABILITIES)
            self.assertFalse(os.path.isfile(flat),
                             "artifact leaked into the flat top-level path")


if __name__ == "__main__":
    unittest.main()
