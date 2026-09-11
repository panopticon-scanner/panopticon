import contextlib
import copy
import dataclasses
import os
import shutil
import tempfile
import unittest
from unittest import mock

from scripts import collect_usage, driver, host_probes, hosts, run_manifest
from scripts.phases import runio


@contextlib.contextmanager
def _in(path):
    """Run the block with `path` as the process cwd, always restoring it.

    Needed because `runio.session_dir` falls back to cwd when no --session-dir
    was passed, and the resume-without-the-flag scenario is only reproducible
    if that fallback is a directory the test controls.
    """
    previous = os.getcwd()
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(previous)


class _Args:
    def __init__(self, **kw):
        self.__dict__.update(kw)


def _pinned_registration(directory):
    """Patch the registry's `claude` row so `registration_dir` points at
    `directory` for the `with` block, regardless of what this machine's real
    ~/.claude/agents holds.

    Fix-round 1: these wiring tests passed on the author's machine only
    because it happens to have 3/3 driver-role shells registered. On a
    machine that has never run `driver setup` (any CI runner, any fresh
    checkout), registered-shell-tools ALSO refutes (no registration
    directory), and the pre-fix `_shadow_refusal` -- which decided from the
    artifact's `by` field rather than the shadow probe's own result -- named
    whichever probe `run_probes` recorded first, silently dropping the
    shadow finding. Pinning here removes the machine as a variable; the
    dedicated unregistered-machine test below pins it open on purpose.
    """
    return mock.patch.dict(
        hosts.HOSTS,
        {"claude": dataclasses.replace(hosts.HOSTS["claude"],
                                       registration_dir=directory)})


def _register_perfect_shells(directory):
    """Every driver-role shell, exactly matching its template, so
    registered-shell-tools PROVES -- isolating a REFUTED tool_policy_enforced
    to the shadow scan alone."""
    from scripts import dispatch
    os.makedirs(directory, exist_ok=True)
    for role in host_probes.DRIVER_ROLES:
        role_file = dispatch.ROLE_FILES[role]
        allowed = dispatch.load_template(role_file)[0]["tool_policy"]["allowed"]
        name = dispatch.registered_agent_filename("claude", role_file)
        with open(os.path.join(directory, name), "w", encoding="utf-8") as fh:
            fh.write("---\nname: %s\ndescription: probe fixture\ntools: %s\n"
                     "---\n\nbody\n" % (name[:-3], ", ".join(allowed)))


def _write_evidence(review_root, states):
    """A host-capabilities.json whose capabilities carry the given states."""
    capabilities = {name: {"state": states.get(name, hosts.UNKNOWN),
                           "by": "fixture", "detail": "fixture"}
                    for name in hosts.CAPABILITIES}
    return runio._write_json(
        runio._pano(review_root, runio.HOST_CAPABILITIES),
        {"schema_version": 1, "host": "claude", "probed_at": "2026-09-10T00:00:00Z",
         "capabilities": capabilities})


class TestThePostureIsEstablishedEveryInvocation(unittest.TestCase):
    """#1344 F3a, spec 5.2: probe on every invocation and compare rather than
    overwrite. Setup-time-only evidence is unbounded in age."""

    def _args(self, target=None):
        """CLI args whose `target` is a DIFFERENT directory from review_root.

        C1: `args.target` is the operator's own checkout; `review_root` is the
        tree actually under review (the --pr worktree, or the git toplevel from
        a subdirectory). They differ on every --pr run, and they differed on the
        run that produced C1. Every fixture here used to pass
        `_Args(target=review_root)`, which baked the conflation into the harness
        -- it is why five separate mutation checks failed to notice that the
        shadow scan was reading the wrong tree. Default to a fresh, EMPTY
        directory so anything that reads `target` for a tree question reads a
        tree with nothing in it.
        """
        if target is None:
            target = tempfile.mkdtemp(prefix="operator-checkout-")
            self.addCleanup(shutil.rmtree, target, ignore_errors=True)
        return _Args(target=target, session_dir=None)

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
                review_root, manifest, self._args())
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
            args = self._args()
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
            args = self._args()
            driver._establish_host_posture(review_root, manifest, args)
            # Derived from the STORED artifact, not from a second live probe:
            # a fresh `run_probes` with no session_root now defaults to cwd, so
            # usage_ledger's state there depends on whether the machine running
            # the suite happens to have a transcript directory for its own cwd.
            # Flipping relative to what was actually stored is deterministic.
            drifted = copy.deepcopy(runio._load_json(
                runio._pano(review_root, runio.HOST_CAPABILITIES)))
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
            args = self._args()
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
        # Shells are PERFECTLY registered here (pinned, not this machine's
        # real state) so the refusal is attributable to the shadow scan
        # alone, not to an incidental registration gap.
        with tempfile.TemporaryDirectory() as review_root, \
                tempfile.TemporaryDirectory() as registration:
            _register_perfect_shells(registration)
            d = os.path.join(review_root, ".claude", "agents")
            os.makedirs(d)
            with open(os.path.join(d, "panopticon-scout.md"), "w",
                      encoding="utf-8") as fh:
                fh.write("x")
            with _pinned_registration(registration):
                err = driver._establish_host_posture(
                    review_root, self._manifest(session_dir=review_root),
                    self._args())
            self.assertIsNotNone(err)
            self.assertIn("panopticon-scout.md", err)

    def test_a_shadowed_target_is_refused_even_when_shells_are_unregistered(self):
        # The machine-independence bug (fix round 1): both probes refute, the
        # tie-break in run_probes names registered-shell-tools (the first
        # recorded), and a _shadow_refusal that keyed off the artifact's `by`
        # field let the run proceed while dropping the shadow finding from
        # the artifact entirely. An unregistered machine is the COMMON case
        # for a first run -- any CI runner, any checkout that has never run
        # `driver setup` -- and a hostile target is exactly what it is most
        # likely to be pointed at. _shadow_refusal must decide from the
        # shadow probe's own result, never from which probe `run_probes`
        # happened to report first.
        with tempfile.TemporaryDirectory() as review_root, \
                tempfile.TemporaryDirectory() as registration:
            # `registration` exists but is EMPTY: registered-shell-tools also
            # REFUTES ("no shell at ..." for every driver role), tying with
            # shadow-shell-scan's own refutation.
            d = os.path.join(review_root, ".claude", "agents")
            os.makedirs(d)
            with open(os.path.join(d, "panopticon-scout.md"), "w",
                      encoding="utf-8") as fh:
                fh.write("x")
            with _pinned_registration(registration):
                err = driver._establish_host_posture(
                    review_root, self._manifest(session_dir=review_root),
                    self._args())
            self.assertIsNotNone(err)
            self.assertIn("panopticon-scout.md", err)

    def test_allow_unenforced_downgrades_the_refusal(self):
        # It papers over nothing: the run proceeds with the capability REFUTED,
        # which is stronger than unknown -- the report says plainly it was not
        # enforced rather than quietly forgetting. Shells pinned perfect, same
        # reasoning as test_a_shadowed_target_refuses_the_run.
        with tempfile.TemporaryDirectory() as review_root, \
                tempfile.TemporaryDirectory() as registration:
            _register_perfect_shells(registration)
            d = os.path.join(review_root, ".claude", "agents")
            os.makedirs(d)
            with open(os.path.join(d, "panopticon-scout.md"), "w",
                      encoding="utf-8") as fh:
                fh.write("x")
            manifest = self._manifest(session_dir=review_root)
            manifest["flags"] = {"allow_unenforced": True}
            with _pinned_registration(registration):
                err = driver._establish_host_posture(
                    review_root, manifest,
                    self._args())
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
                review_root, manifest, self._args())
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


class TestTheProbesReadTheRightTree(unittest.TestCase):
    """C1/C2: `run_probes` answers questions about THREE trees, and one
    `target` argument used to serve all of them. The reviewed tree, the host
    session, and the user's registration directory are different places on
    every run that is not a self-scan, which is why both Criticals hid behind
    ten green mutation checks."""

    def _manifest(self, session_dir=None):
        manifest = {"host": "claude", "run_id": "r1" * 4,
                    "created": "2026-09-10", "security_mode": "standard"}
        if session_dir:
            manifest["session_dir"] = session_dir
        return manifest

    def _settings(self, root):
        claude = os.path.join(root, ".claude")
        os.makedirs(claude, exist_ok=True)
        with open(os.path.join(claude, "settings.local.json"), "w",
                  encoding="utf-8") as fh:
            fh.write("{}")
        return root

    def _shadow(self, root):
        d = os.path.join(root, ".claude", "agents")
        os.makedirs(d, exist_ok=True)
        path = os.path.join(d, "panopticon-scout.md")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("x")
        return path

    def test_the_shadow_scan_reads_the_reviewed_tree_not_the_target(self):
        # C1, the regression test. Under --pr, `review_root` is the PR
        # WORKTREE and `args.target` is the operator's own checkout -- the one
        # tree guaranteed clean. A hostile PR that ships
        # `.claude/agents/panopticon-scout.md` lands in the worktree, so a
        # scan of args.target sees nothing, 7.3's refusal never fires, and
        # every dispatch entry is stamped enforced: true. Measured on the
        # pre-fix tree: reviewed -> refuted, args.target -> unknown.
        with tempfile.TemporaryDirectory() as review_root, \
                tempfile.TemporaryDirectory() as target, \
                tempfile.TemporaryDirectory() as registration:
            _register_perfect_shells(registration)   # isolate the refusal
            self._settings(review_root)
            planted = self._shadow(review_root)      # in the REVIEWED tree
            with _pinned_registration(registration):
                err = driver._establish_host_posture(
                    review_root, self._manifest(session_dir=review_root),
                    _Args(target=target, session_dir=None))
            self.assertIsNotNone(err)
            self.assertIn(os.path.basename(planted), err)

    def test_a_shadow_file_in_the_operators_checkout_is_not_scanned(self):
        # The converse, and it is what makes the test above non-vacuous: a
        # scan that reads BOTH trees would pass that one and fail this one.
        # `args.target` is not the tree under review, so a panopticon-* agent
        # sitting in the operator's own checkout -- where the operator's
        # REGISTERED shells legitimately live on a self-scan -- is not a
        # shadowing attack and must not refuse the run.
        with tempfile.TemporaryDirectory() as review_root, \
                tempfile.TemporaryDirectory() as target, \
                tempfile.TemporaryDirectory() as registration:
            _register_perfect_shells(registration)
            self._settings(review_root)
            self._shadow(target)                     # NOT the reviewed tree
            with _pinned_registration(registration):
                err = driver._establish_host_posture(
                    review_root, self._manifest(session_dir=review_root),
                    _Args(target=target, session_dir=None))
            self.assertIsNone(err)

    def test_the_shadow_scan_runs_exactly_once_per_invocation(self):
        # Minor 4: it ran twice on a first invocation -- once inside
        # `run_probes` for the artifact, once directly for the refusal --
        # which is duplicate tree-walking AND a window in which the two could
        # disagree about the same tree. The single result is threaded through.
        with tempfile.TemporaryDirectory() as review_root:
            self._settings(review_root)
            with mock.patch.object(host_probes, "probe_shadow_shells",
                                   wraps=host_probes.probe_shadow_shells) as scan:
                driver._establish_host_posture(
                    review_root, self._manifest(session_dir=review_root),
                    _Args(target=review_root, session_dir=None))
            self.assertEqual(1, scan.call_count)
            self.assertEqual(review_root, scan.call_args.args[1])

    def test_the_artifact_records_the_threaded_scan_result(self):
        # Threading must not mean the artifact stops recording the scan. Feed
        # `run_probes` a shadow result it could not have produced itself (the
        # tree is clean) and require it in the artifact: a `shadow=` argument
        # that were accepted and ignored would silently re-scan and report
        # UNKNOWN here.
        sentinel = (hosts.REFUTED, host_probes.SHADOW_SHELL_SCAN,
                    "threaded-scan-sentinel")
        with tempfile.TemporaryDirectory() as review_root:
            art = host_probes.run_probes("claude", review_root,
                                         session_root=review_root,
                                         shadow=sentinel)
            row = art["capabilities"][hosts.TOOL_POLICY_ENFORCED]
            self.assertEqual(hosts.REFUTED, row["state"])
            self.assertIn("threaded-scan-sentinel", row["detail"])

    def test_the_usage_probe_reads_the_session_transcript_not_the_target(self):
        # C2. `probe_transcript_dir` received `target`, so on the documented
        # external invocation (`driver run /tmp/fzf` from the panopticon
        # session) it resolved `~/.claude/projects/-tmp-fzf`, found nothing,
        # REFUTED -- and `_collect_host_usage`, which gates on that posture,
        # returned None. meta.cost.tokens went null on every calibration run,
        # reintroducing #calibration-2 one layer up. Self-scans hid it because
        # session dir == target there.
        with tempfile.TemporaryDirectory() as review_root, \
                tempfile.TemporaryDirectory() as session, \
                tempfile.TemporaryDirectory() as home:
            session_slug = collect_usage.project_slug(session)
            self.assertNotEqual(session_slug,
                                collect_usage.project_slug(review_root))
            # transcripts exist for the SESSION's slug and nothing else
            os.makedirs(os.path.join(home, ".claude", "projects", session_slug))
            art = host_probes.run_probes("claude", review_root,
                                         session_root=session, home=home)
            row = art["capabilities"][hosts.USAGE_LEDGER]
            self.assertEqual(hosts.PROVEN, row["state"])
            # Asserted against collect_usage.project_slug, the collector's own
            # definition, so probe and collector are pinned to one slug.
            self.assertIn(session_slug, row["detail"])

    def test_the_driver_hands_the_probe_the_collectors_session_dir(self):
        # The wiring half of C2: one expression, `runio.session_dir`, feeds
        # both the probe that GATES the ledger and the collector that BUILDS
        # it. Pinning the value the driver passes is what stops the two
        # drifting apart again.
        with tempfile.TemporaryDirectory() as review_root, \
                tempfile.TemporaryDirectory() as session, \
                tempfile.TemporaryDirectory() as target:
            self._settings(session)
            manifest = self._manifest(session_dir=session)
            self.assertNotEqual(runio.session_dir(manifest), target)
            self.assertNotEqual(runio.session_dir(manifest), review_root)
            with mock.patch.object(host_probes, "run_probes",
                                   wraps=host_probes.run_probes) as probed:
                driver._establish_host_posture(
                    review_root, manifest,
                    _Args(target=target, session_dir=None))
            self.assertEqual(review_root, probed.call_args.args[1])
            self.assertEqual(runio.session_dir(manifest),
                             probed.call_args.kwargs["session_root"])

    def test_an_absent_session_dir_defaults_to_the_collectors_fallback(self):
        # `runio.session_dir` is the fallback too, so the probe and the
        # collector agree even when the operator passed no flag at all.
        self.assertEqual(os.getcwd(), runio.session_dir({}))
        self.assertEqual(os.getcwd(), runio.session_dir(None))
        self.assertEqual(os.getcwd(), runio.session_dir({"session_dir": ""}))


class TestTheShadowRefusalIsEvaluatedOnEveryInvocation(unittest.TestCase):
    """I6 / spec 5.2: probe EVERY invocation. The refusal used to be evaluated
    only under `if stored is None:`, so it was a first-invocation check
    wearing an every-invocation docstring."""

    def _manifest(self, session_dir):
        return {"host": "claude", "run_id": "r1" * 4, "created": "2026-09-10",
                "security_mode": "standard", "session_dir": session_dir}

    def test_a_shadow_file_planted_mid_run_refuses_on_the_resume(self):
        # The capability MAP does not move here, deliberately: the
        # registration directory is empty, so tool_policy_enforced is already
        # REFUTED on the first invocation, and the shadow file makes it
        # refuted -> refuted. No mismatch, so the drift check says nothing,
        # and a refusal confined to the first invocation never looks again.
        with tempfile.TemporaryDirectory() as review_root, \
                tempfile.TemporaryDirectory() as registration:
            claude = os.path.join(review_root, ".claude")
            os.makedirs(claude, exist_ok=True)
            with open(os.path.join(claude, "settings.local.json"), "w",
                      encoding="utf-8") as fh:
                fh.write("{}")
            manifest = self._manifest(review_root)
            args = _Args(target=review_root, session_dir=None)
            with _pinned_registration(registration):
                self.assertIsNone(driver._establish_host_posture(
                    review_root, manifest, args))
                before = host_probes.capabilities_of(
                    runio._load_json(runio._pano(review_root,
                                                 runio.HOST_CAPABILITIES)))
                d = os.path.join(review_root, ".claude", "agents")
                os.makedirs(d, exist_ok=True)
                with open(os.path.join(d, "panopticon-scout.md"), "w",
                          encoding="utf-8") as fh:
                    fh.write("x")
                err = driver._establish_host_posture(
                    review_root, manifest, args)
                after = host_probes.capabilities_of(
                    host_probes.run_probes("claude", review_root,
                                           session_root=review_root))
            # The state map really is unchanged -- so the drift check cannot
            # be what caught this, and the refusal text proves which one did.
            self.assertEqual(before[hosts.TOOL_POLICY_ENFORCED],
                             after[hosts.TOOL_POLICY_ENFORCED])
            self.assertIsNotNone(err)
            self.assertIn("panopticon-scout.md", err)
            self.assertIn("--allow-unenforced", err)   # only _shadow_refusal
            self.assertNotIn("--reset", err)           # not the drift message


class TestTheDriftRefusalNamesTheRightRemedy(unittest.TestCase):
    """I2: `session_dir` is deliberately not a manifest field, so resuming
    without `--session-dir` re-resolves two capabilities against cwd. The
    operator was told to discard the run, and the message named neither the
    flag nor the option of simply passing it again."""

    _WAS = {name: hosts.PROVEN for name in hosts.CAPABILITIES}

    def test_a_session_derived_capability_names_session_dir_first(self):
        for capability in (hosts.ARTIFACT_WRITE_GUARD, hosts.USAGE_LEDGER):
            with self.subTest(capability=capability):
                now = dict(self._WAS, **{capability: hosts.REFUTED})
                err = driver._posture_drift(self._WAS, now, {"host": "claude"})
                self.assertIn("--session-dir", err)
                self.assertIn(capability, err)

    def test_a_capability_the_session_root_cannot_explain_does_not(self):
        # The other half, and the one that makes the first non-vacuous: a
        # message that named --session-dir unconditionally would pass the test
        # above while telling every operator the wrong thing. The shadow scan
        # and the shell registration read the REVIEWED tree and the USER's
        # registration directory; --session-dir moves neither.
        now = dict(self._WAS, **{hosts.TOOL_POLICY_ENFORCED: hosts.REFUTED})
        err = driver._posture_drift(self._WAS, now, {"host": "claude"})
        self.assertNotIn("--session-dir", err)
        self.assertIn("--reset", err)

    def test_a_run_that_passed_the_flag_is_not_told_to_pass_it_again(self):
        now = dict(self._WAS, **{hosts.ARTIFACT_WRITE_GUARD: hosts.REFUTED})
        err = driver._posture_drift(self._WAS, now,
                                    {"host": "claude", "session_dir": "/s"})
        self.assertNotIn("--session-dir", err)
        self.assertIn("--reset", err)

    def test_resuming_without_the_flag_is_told_to_pass_it_again(self):
        # End to end through `_establish_host_posture`, which is where the
        # operator actually meets this. First invocation with --session-dir
        # (a settings file exists there, so the write guard PROVES); resume
        # from a directory that has none, with the flag omitted.
        with tempfile.TemporaryDirectory() as review_root, \
                tempfile.TemporaryDirectory() as session, \
                tempfile.TemporaryDirectory() as elsewhere:
            claude = os.path.join(session, ".claude")
            os.makedirs(claude)
            with open(os.path.join(claude, "settings.local.json"), "w",
                      encoding="utf-8") as fh:
                fh.write("{}")
            args = _Args(target=review_root, session_dir=None)
            manifest = {"host": "claude", "run_id": "r1" * 4,
                        "created": "2026-09-10", "security_mode": "standard",
                        "session_dir": session}
            self.assertIsNone(driver._establish_host_posture(
                review_root, manifest, args))
            stored = runio.host_evidence(review_root)
            self.assertEqual(hosts.PROVEN,
                             stored[hosts.ARTIFACT_WRITE_GUARD]["state"])
            resumed = {k: v for k, v in manifest.items() if k != "session_dir"}
            with _in(elsewhere):
                err = driver._establish_host_posture(
                    review_root, resumed, args)
            self.assertIsNotNone(err)
            self.assertIn(hosts.ARTIFACT_WRITE_GUARD, err)
            self.assertIn("--session-dir", err)


class TestNothingIsEnforcedWithoutEvidence(unittest.TestCase):
    """Spec 9.2: with no host-capabilities.json every capability is unknown
    and every entry is enforced:false -- on CLAUDE, not only on an exotic
    host. This is the test that would have caught 7.1."""

    def test_claude_with_no_evidence_is_not_enforced(self):
        from scripts.phases import coverage
        with tempfile.TemporaryDirectory() as review_root:
            manifest = {"host": "claude", "run_id": "r" * 8,
                        "security_mode": "standard"}
            entry = coverage._scout_entry(review_root, manifest, "g", ["a.py"],
                                          "claude")
            self.assertFalse(entry["enforced"])
            self.assertIsNone(entry["agent"])

    def test_claude_with_proven_evidence_is_enforced(self):
        from scripts.phases import coverage
        with tempfile.TemporaryDirectory() as review_root:
            manifest = {"host": "claude", "run_id": "r" * 8,
                        "security_mode": "standard"}
            _write_evidence(review_root, {hosts.TOOL_POLICY_ENFORCED: hosts.PROVEN})
            entry = coverage._scout_entry(review_root, manifest, "g", ["a.py"],
                                          "claude")
            self.assertTrue(entry["enforced"])
            self.assertIsNotNone(entry["agent"])

    def test_a_claimed_but_unproven_capability_is_not_enforced(self):
        # Spec 9.3, "claiming is not evidence" -- the test that would have
        # caught P2. claude CLAIMS tool_policy_enforced; unknown evidence must
        # not let the claim through.
        from scripts.phases import coverage
        with tempfile.TemporaryDirectory() as review_root:
            manifest = {"host": "claude", "run_id": "r" * 8,
                        "security_mode": "standard"}
            _write_evidence(review_root, {hosts.TOOL_POLICY_ENFORCED: hosts.UNKNOWN})
            self.assertTrue(hosts.declares("claude", hosts.TOOL_POLICY_ENFORCED))
            entry = coverage._scout_entry(review_root, manifest, "g", ["a.py"],
                                          "claude")
            self.assertFalse(entry["enforced"])

    def test_a_refuted_capability_is_not_enforced(self):
        from scripts.phases import coverage
        with tempfile.TemporaryDirectory() as review_root:
            manifest = {"host": "claude", "run_id": "r" * 8,
                        "security_mode": "standard"}
            _write_evidence(review_root, {hosts.TOOL_POLICY_ENFORCED: hosts.REFUTED})
            entry = coverage._scout_entry(review_root, manifest, "g", ["a.py"],
                                          "claude")
            self.assertFalse(entry["enforced"])

    def test_the_hint_list_still_reads_claims_not_proof(self):
        # requests.py:201 asks which hosts CLAIM the guard, to build the
        # "or use one of: --host claude" hint. There is no evidence for a host
        # you are not running, so posture() would empty the hint.
        guarded = [n for n in hosts.driver_hosts()
                   if hosts.declares(n, hosts.ARTIFACT_WRITE_GUARD)]
        self.assertIn("claude", guarded)


class TestTheOtherFourSitesAlsoRequireEvidence(unittest.TestCase):
    """The brief's own class above exercises the pattern once, on
    `coverage._scout_entry`, because the docstring at requests.py:180 says all
    seven TOOL_POLICY_ENFORCED/ARTIFACT_WRITE_GUARD/USAGE_LEDGER sites are
    "written identically, so a future change is mechanical." Mechanically
    identical code is not mechanically identical TEST COVERAGE: reverting any
    one of `review._cell_entry`, `verify._verify_entry`,
    `verify._tool_verify_entry` or `requests._driver_plan_entries` back to
    `hosts.declares()` alone -- confirmed by hand during verification, then
    reverted -- left the full suite green, because
    `TestTheThreeCapabilitiesAreNotInterchangeable` (test_host_posture_wiring.py)
    always supplies PROVEN evidence in its fixture and no other test calls
    these four with none. These four close that gap the same way the class
    above closes it for the scout. (The write-guard and usage-ledger sites --
    requests.require_unenforced_ack and synthesize._collect_host_usage -- are
    NOT repeated here: TestTheThreeCapabilitiesAreNotInterchangeable's own
    no-evidence-by-default hosts already exercise those two live, via
    test_unenforced_ack.py and test_synthesize.py respectively.)"""

    def _manifest(self):
        return {"host": "claude", "run_id": "r" * 8, "security_mode": "standard"}

    def test_review_cell_entry_is_not_enforced_without_evidence(self):
        from scripts.phases import review
        import scripts.ocrdb as ocrdb
        with tempfile.TemporaryDirectory() as review_root:
            entry = review._cell_entry(review_root, self._manifest(), "g", "SEC",
                                       ["a.py"], [], "claude", ocrdb.load_bundle())
            self.assertFalse(entry["enforced"])
            self.assertIsNone(entry["agent"])

    def test_verify_entry_is_not_enforced_without_evidence(self):
        from scripts.phases import verify
        import scripts.ocrdb as ocrdb
        with tempfile.TemporaryDirectory() as review_root:
            entry = verify._verify_entry(review_root, self._manifest(), "g", "SEC",
                                         ["a.py"], [], "claude", ocrdb.load_bundle(),
                                         "primary")
            self.assertFalse(entry["enforced"])
            self.assertIsNone(entry["agent"])

    def test_tool_verify_entry_is_not_enforced_without_evidence(self):
        from scripts.phases import verify
        with tempfile.TemporaryDirectory() as review_root:
            entry = verify._tool_verify_entry(
                review_root, self._manifest(), "q1",
                {"id": "T-1", "severity": "HIGH"}, "claude")
            self.assertFalse(entry["enforced"])
            self.assertIsNone(entry["agent"])

    def test_driver_plan_entries_are_not_enforced_without_evidence(self):
        from scripts.phases import requests as requests_mod
        with tempfile.TemporaryDirectory() as review_root:
            runio._write_json(runio._pano(review_root, "groups.json"),
                              {"groups": [{"name": "g", "files": ["a.py"]}]})
            runio._write_json(runio._pano(review_root, "coverage-g.json"),
                              {"effective": ["SEC"]})
            entries = requests_mod._driver_plan_entries(review_root, self._manifest())
            self.assertTrue(entries)
            self.assertFalse(entries[0]["enforced"])


class TestTheWriteGuardAndUsageLedgerAlsoRequireEvidence(unittest.TestCase):
    """Closes the same gap as `TestTheOtherFourSitesAlsoRequireEvidence` above
    for the two remaining posture sites, `requests.require_unenforced_ack`
    (ARTIFACT_WRITE_GUARD) and `synthesize._collect_host_usage`
    (USAGE_LEDGER). Neither is caught by any existing test without these:
    `test_unenforced_ack.py::test_claude_is_enforced_and_writes_no_ack` and
    every `test_synthesize.py::TestHostUsageCollection` test supply PROVEN
    evidence (they exist to test what happens once posture holds, not
    whether it is required) -- confirmed by hand during verification,
    mutating each site back to `hosts.declares()` and watching the WHOLE
    suite of 2899 tests stay green, then reverted."""

    def test_write_guard_refuses_claude_with_no_evidence(self):
        from scripts.phases import requests as requests_mod
        entries = [{"group": "g", "domain": "SEC", "enforced": False,
                   "out_file": "/abs/findings-g-SEC.json"}]
        with tempfile.TemporaryDirectory() as review_root:
            with self.assertRaises(runio.DriverError):
                requests_mod.require_unenforced_ack(
                    review_root, {"host": "claude", "flags": {}}, entries)

    def test_usage_ledger_does_not_collect_for_claude_with_no_evidence(self):
        from scripts.phases import synthesize
        with tempfile.TemporaryDirectory() as review_root:
            with mock.patch("scripts.phases.runio._run_child") as run:
                result = synthesize._collect_host_usage(
                    review_root, {"host": "claude", "run_id": "r1",
                                 "created": "2026-09-10T00:00:00Z"})
        self.assertIsNone(result)
        run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
