"""Tests for scripts.phases.coverage: the scout checkpoint, chunk maps, attempts and
per-group domains.
"""
import contextlib
import io
import os
import tempfile
import unittest
from unittest import mock

from scripts import hosts
from conftest import write_host_evidence
import scripts.phases.runio as runio
import scripts.phases.requests as requests
import scripts.phases.coverage as coverage
import scripts.phases.review as review
import scripts.model_resolver as model_resolver


class TestCoveragePhase(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.root = os.path.realpath(self._t.name)
        os.makedirs(runio._pano(self.root))
        self.addCleanup(self._t.cleanup)
        self.manifest = {"run_id": "R", "security_mode": "standard", "host": "claude"}
        # #1344 F3: this suite exercises a "claude" host and expects the old
        # enforced/guarded answers; that now requires PROVEN evidence, not just
        # the claim. Prove every capability claude claims once, here, so every
        # test in this class keeps asserting what it always meant to assert.
        write_host_evidence(self.root, {c: hosts.PROVEN for c in hosts.CAPABILITIES})

    def _groups_json(self, groups):
        runio._write_json(runio._pano(self.root, "groups.json"), {"groups": groups})

    def _groups_yml(self, body):
        with open(runio._pano(self.root, "groups.yml"), "w") as fh:
            fh.write(body)

    def test_emits_scout_checkpoint_when_scout_absent(self):
        self._groups_json([{"name": "Auth", "files": ["a.py"]}])
        self._groups_yml("groups:\n  Auth:\n    match: ['a.py']\n    panels: [SEC]\n")
        with mock.patch("scripts.dispatch.render_prompt",
                        return_value="SCOUT-BODY"), \
             mock.patch("scripts.dispatch.registered_agent_name",
                        return_value="panopticon-scout"):
            result = coverage.coverage_execute(self.root, self.manifest)
        self.assertEqual(result.kind, "checkpoint")
        self.assertEqual(result.checkpoint, "scout")
        self.assertIsNone(result.group)                 # #1056: batched, not per-group
        req = runio._load_json(runio._pano(self.root, "dispatch-request.json"))
        self.assertEqual(req["checkpoint"], "scout")
        entry = req["entries"][0]
        self.assertTrue(entry["out_file"].endswith("scout-Auth.json"))
        self.assertEqual(entry["out_file"], os.path.abspath(entry["out_file"]))
        self.assertTrue(entry["enforced"])              # claude host
        self.assertNotIn("delivery", entry)             # host-agnostic

    def test_scout_entry_binds_the_resolved_model(self):
        # #1344 F4 (b). Sentinel, not a literal: a builder that hard-coded the
        # profile's value would pass a literal and still not be bound.
        self._groups_json([{"name": "Auth", "files": ["a.py"]}])
        self._groups_yml("groups:\n  Auth:\n    match: ['a.py']\n    panels: [SEC]\n")
        with mock.patch("scripts.dispatch.render_prompt", return_value="SCOUT-BODY"), \
             mock.patch("scripts.dispatch.registered_agent_name",
                        return_value="panopticon-scout"), \
             mock.patch.object(model_resolver, "resolve_model",
                               return_value={"model": "SENTINEL-SCOUT"}) as rm:
            coverage.coverage_execute(self.root, self.manifest)
        entry = runio._load_json(runio._pano(self.root, "dispatch-request.json"))["entries"][0]
        self.assertEqual("SENTINEL-SCOUT", entry["model"])
        rm.assert_any_call(self.manifest.get("host", "claude"), "scout")

    def test_batches_all_pending_scouts_into_one_checkpoint(self):
        # #1056: every group's scout goes in ONE checkpoint (they are
        # independent) so they dispatch concurrently, not 21 sequential
        # round-trips. A group whose scout already landed is not re-emitted.
        self._groups_json([{"name": "Auth", "files": ["a.py"]},
                           {"name": "Core", "files": ["b.py"]},
                           {"name": "UI", "files": ["c.py"]}])
        self._groups_yml("groups:\n  Auth:\n    match: ['a.py']\n"
                         "  Core:\n    match: ['b.py']\n  UI:\n    match: ['c.py']\n")
        # Core already has a scout output -> only Auth + UI should be emitted.
        runio._write_json(runio._pano(self.root, "scout-Core.json"),
                           {"group": "Core", "domains": ["COD"]})
        with mock.patch("scripts.dispatch.render_prompt", return_value="B"), \
             mock.patch("scripts.dispatch.registered_agent_name",
                        return_value="panopticon-scout"):
            result = coverage.coverage_execute(self.root, self.manifest)
        self.assertEqual(result.checkpoint, "scout")
        req = runio._load_json(runio._pano(self.root, "dispatch-request.json"))
        outs = sorted(os.path.basename(e["out_file"]) for e in req["entries"])
        self.assertEqual(outs, ["scout-Auth.json", "scout-UI.json"])   # Core omitted
    def test_scout_entry_injects_adapter_registry(self):
        # #1053: the scout prompt must carry the real scanner registry so it can
        # only recommend tools that exist -- deleting the requested_unavailable
        # noise class. The registry is appended by _scout_entry (not the mocked
        # body), so it appears in the dispatched prompt regardless of template.
        # run-9 E1: the registry is now GATED to the repo's languages + applicable
        # adapters, so a pure-Python repo offers bandit (python SAST) but NOT gosec
        # (go SAST) -- the cross-language over-request that made requested_unavailable
        # noise. A real a.py drives detection.
        self._groups_json([{"name": "Auth", "files": ["a.py"]}])
        self._groups_yml("groups:\n  Auth:\n    match: ['a.py']\n    panels: [SEC]\n")
        with open(os.path.join(self.root, "a.py"), "w") as fh:
            fh.write("import os\n")             # real Python surface -> python detected
        with mock.patch("scripts.dispatch.render_prompt",
                        return_value="SCOUT-BODY"), \
             mock.patch("scripts.dispatch.registered_agent_name",
                        return_value="panopticon-scout"):
            coverage.coverage_execute(self.root, self.manifest)
        prompt = runio._load_json(
            runio._pano(self.root, "dispatch-request.json"))["entries"][0]["prompt"]
        self.assertIn("Available scanners", prompt)
        self.assertIn("semgrep", prompt)       # always-on SARIF: survives gating
        self.assertIn("bandit", prompt)        # python SAST: gated IN by the .py
        self.assertNotIn("gosec", prompt)      # go SAST: gated OUT (no .go) -- the E1 fix
        self.assertNotIn("pytest", prompt)     # an invented tool never appears

    def test_generic_host_scout_entry_not_enforced(self):
        self._groups_json([{"name": "Auth", "files": ["a.py"]}])
        self._groups_yml("groups:\n  Auth:\n    match: ['a.py']\n")
        m = dict(self.manifest, host="generic")
        with mock.patch("scripts.dispatch.render_prompt", return_value="B"), \
             mock.patch("scripts.dispatch.registered_agent_name",
                        return_value="panopticon-scout"):
            coverage.coverage_execute(self.root, m)
        entry = runio._load_json(runio._pano(self.root, "dispatch-request.json"))["entries"][0]
        self.assertFalse(entry["enforced"])
        self.assertIsNone(entry["agent"])

    def test_computes_floor_coverage_after_scout_lands(self):
        self._groups_json([{"name": "Auth", "files": ["a.py"]}])
        self._groups_yml(
            "groups:\n  Auth:\n    match: ['a.py']\n    panels: [SEC, DAT]\n"
            "    exclude: [OPS]\n")
        runio._write_json(runio._pano(self.root, "scout-Auth.json"),
                           {"group": "Auth", "panels": ["code"]})
        result = coverage.coverage_execute(self.root, self.manifest)
        self.assertEqual(result.kind, "advanced")
        cov = runio._load_json(runio._pano(self.root, "coverage-Auth.json"))
        # #5.0-19: the universal floor (#5.0-11) is now surface-gated. This
        # group is a single, surfaceless file ('a.py', no db/test/arch signal
        # and a scout with no surfaces), so only COD (universal) is injected;
        # ARC/TST are suppressed. DAT is still present because it is the group's
        # COMMITTED vertical floor (panels: [SEC, DAT]) -- the gate only governs
        # the GLOBAL injection, never the declared floor.
        self.assertEqual(cov["floor"], ["COD", "DAT", "SEC"])
        self.assertEqual(cov["excluded"], ["OPS"])
        self.assertEqual(cov["effective"], ["COD", "DAT", "SEC"])
        self.assertEqual(cov["global_floor_suppressed"], ["ARC", "DAT", "TST"])
        self.assertEqual(cov["scout_added"], [])              # bridge deferred to P4
        self.assertTrue(cov["scout_file"].endswith("scout-Auth.json"))

    def test_dispatch_entries_carry_an_addressable_prompt_file(self):
        # #run10 B2: an entry carried its prompt ONLY inline (13.3 KB avg for
        # review cells), so a controller dispatching 120 cells had to echo ~1.6 MB
        # it had just read from disk. `prompt_file` is the addressable alternative;
        # `prompt` stays inline so no host is forced to migrate.
        self._groups_json([{"name": "Auth", "files": ["a.py"]}])
        self._groups_yml("groups:\n  Auth:\n    match: ['a.py']\n")
        with mock.patch("scripts.dispatch.render_prompt",
                        return_value="SCOUT-BODY-XYZ"), \
             mock.patch("scripts.dispatch.registered_agent_name",
                        return_value="panopticon-scout"):
            coverage.coverage_execute(self.root, self.manifest)
        entry = runio._load_json(
            runio._pano(self.root, "dispatch-request.json"))["entries"][0]
        self.assertIn("prompt_file", entry)
        self.assertEqual(entry["prompt_file"], os.path.abspath(entry["prompt_file"]))
        with open(entry["prompt_file"], encoding="utf-8") as fh:
            self.assertEqual(fh.read(), entry["prompt"])   # same text, addressable
        self.assertIn("SCOUT-BODY-XYZ", entry["prompt"])   # inline still intact

    def test_prompt_file_name_cannot_escape_the_prompts_dir(self):
        # An entry id embeds an operator-supplied group name; a `/` or `..` in it
        # must not steer the write out of _prompts/.
        prompts_dir = os.path.realpath(runio._pano(self.root, "_prompts"))
        for hostile in ("review-../../etc/passwd-SEC", "a/b/c", "../../../x",
                        "", "..", "/abs/path"):
            p = os.path.realpath(requests._prompt_file_path(self.root, hostile))
            # The invariant is containment, not the absence of dot characters:
            # separators are stripped, so a residual ".." is just a flat filename.
            self.assertEqual(os.path.dirname(p), prompts_dir, hostile)
            self.assertTrue(os.path.basename(p).endswith(".txt"), hostile)

    def test_unwritable_prompts_dir_does_not_block_dispatch(self):
        # Best-effort by design: this is an ergonomic affordance, never a
        # dispatch precondition. A failure keeps the inline prompt and proceeds.
        with mock.patch("scripts.phases.runio._open_w_nofollow",
                        side_effect=OSError("read-only fs")), \
             contextlib.redirect_stderr(io.StringIO()) as err:
            entries = requests._materialize_prompts(
                self.root, [{"id": "scout-Auth", "prompt": "BODY"}])
        self.assertNotIn("prompt_file", entries[0])
        self.assertEqual(entries[0]["prompt"], "BODY")
        self.assertIn("inline prompt still stands", err.getvalue())

    def test_fence_wrapped_scout_is_accepted_and_normalized(self):
        # run-9 A1: a scout is a RETURN-PERSIST file, and a model wraps its reply
        # in a ```json fence (0/25 clean in run-9). The old strict read counted
        # that as "no output" and re-dispatched forever. It must be unwrapped,
        # accepted, and normalized in place so the coverage read and synthesize's
        # raw scout scan both get clean bytes.
        self._groups_json([{"name": "Auth", "files": ["a.py"]}])
        self._groups_yml("groups:\n  Auth:\n    match: ['a.py']\n    panels: [SEC]\n")
        sp = runio._pano(self.root, "scout-Auth.json")
        with open(sp, "w", encoding="utf-8") as fh:
            fh.write('```json\n{"group": "Auth", "panels": ["code"]}\n```\n')
        result = coverage.coverage_execute(self.root, self.manifest)
        self.assertEqual(result.kind, "advanced")            # accepted, not re-dispatched
        self.assertTrue(runio._json_parses(
            runio._pano(self.root, "coverage-Auth.json")))
        # normalized in place: a STRICT reader now parses it (no fence left on disk)
        self.assertEqual(runio._load_json(sp)["group"], "Auth")

    def test_scout_with_non_string_domain_elements_is_rejected(self):
        # #run10 COD-B2A: the shape gate checked only that `domains` IS an array,
        # so a nested/object ELEMENT passed and then crashed coverage_execute with
        # an uncaught TypeError (unhashable list) mid-phase. It must be caught at
        # the accept boundary and re-dispatched instead.
        for bad in ([["COD"]], [{"x": 1}], ["COD", 7], [None]):
            errs = coverage._scout_shape_errors({"domains": bad})
            self.assertTrue(errs, "accepted a bad domains payload: %r" % (bad,))
            self.assertIn("only strings", " ".join(errs))
        self.assertEqual(coverage._scout_shape_errors({"domains": ["COD", "SEC"]}), [])
        self.assertEqual(coverage._scout_shape_errors({"domains": []}), [])
        self.assertEqual(coverage._scout_shape_errors({}), [])          # absent is fine

    def test_malformed_scout_domains_redispatches_instead_of_crashing(self):
        # End-to-end: the bad profile is DISCARDED and the scout re-emitted, not
        # carried into coverage where it would blow up.
        self._groups_json([{"name": "Auth", "files": ["a.py"]}])
        self._groups_yml("groups:\n  Auth:\n    match: ['a.py']\n")
        runio._write_json(runio._pano(self.root, "scout-Auth.json"),
                           {"group": "Auth", "domains": [["COD"]]})
        with mock.patch("scripts.dispatch.render_prompt", return_value="B"), \
             mock.patch("scripts.dispatch.registered_agent_name",
                        return_value="panopticon-scout"), \
             contextlib.redirect_stderr(io.StringIO()):
            result = coverage.coverage_execute(self.root, self.manifest)
        self.assertEqual(result.checkpoint, "scout")      # re-dispatched, no crash

    def test_prose_preamble_scout_is_recovered(self):
        # 3/25 run-9 scouts added a prose preamble BEFORE the fence; the tolerant
        # reader's balanced-brace scan recovers the object regardless.
        self._groups_json([{"name": "Auth", "files": ["a.py"]}])
        self._groups_yml("groups:\n  Auth:\n    match: ['a.py']\n    panels: [SEC]\n")
        sp = runio._pano(self.root, "scout-Auth.json")
        with open(sp, "w", encoding="utf-8") as fh:
            fh.write('Here is the ScopeProfile for Auth:\n\n'
                     '```json\n{"group": "Auth", "domains": ["COD"]}\n```\n')
        result = coverage.coverage_execute(self.root, self.manifest)
        self.assertEqual(result.kind, "advanced")
        self.assertTrue(runio._json_parses(
            runio._pano(self.root, "coverage-Auth.json")))

    def test_return_channel_tolerant_but_load_json_stays_strict(self):
        # The unwrap is scoped to the RETURN-PERSIST channel. Driver-internal reads
        # (_load_json) stay strict so a markdown fence -- which on a driver-written
        # file means tampering, not a chat wrapper -- can never be silently accepted.
        p = runio._pano(self.root, "x.json")
        with open(p, "w", encoding="utf-8") as fh:
            fh.write('```json\n{"a": 1}\n```')
        self.assertIsNone(runio._load_json(p))                   # strict: rejects the fence
        self.assertEqual(runio._load_return_json(p), {"a": 1})   # tolerant: unwraps
        self.assertTrue(runio._return_json_parses(p))

    def test_write_json_rejects_symlinked_intermediate_panopticon_dir(self):
        # #run9 SEC-X0X: artifact_root() vets only the top-level .panopticon and
        # _open_w_nofollow's O_NOFOLLOW only the final file, so a hostile target
        # could plant an INTERMEDIATE symlink (.panopticon/runs -> /elsewhere) and
        # the driver's own writes would escape. _confine_artifact_path blocks it,
        # and nothing lands in the outside dir.
        with tempfile.TemporaryDirectory() as root, \
             tempfile.TemporaryDirectory() as outside:
            os.makedirs(os.path.join(root, ".panopticon"))
            os.symlink(outside, os.path.join(root, ".panopticon", "runs"))   # planted
            escaping = os.path.join(root, ".panopticon", "runs", "tag", "x.json")
            with self.assertRaises(ValueError):
                runio._write_json(escaping, {"a": 1})
            self.assertEqual(os.listdir(outside), [])            # nothing escaped
            ok = os.path.join(root, ".panopticon", "runs2", "y.json")   # normal write works
            runio._write_json(ok, {"b": 2})
            self.assertEqual(runio._load_json(ok), {"b": 2})

    def test_confine_allows_the_intentional_latest_symlink(self):
        # The runs/latest -> <tag> link points WITHIN .panopticon, so a path
        # through it must NOT be falsely rejected (no regression on per-run folders).
        with tempfile.TemporaryDirectory() as root:
            runs = os.path.join(root, ".panopticon", "runs")
            os.makedirs(os.path.join(runs, "t1"))
            os.symlink("t1", os.path.join(runs, "latest"))
            runio._confine_artifact_path(os.path.join(runs, "latest", "z.json"))  # no raise

    def test_persists_and_warns_exclude_rejected_for_non_excludable(self):
        # #8c/#7: a committed `exclude` naming SEC (NON_EXCLUDABLE, #1084) is
        # OVERRIDDEN -- the SEC panel still runs wherever floor/scout put it. A
        # redteam scout profiling deliberately-vulnerable fixtures requests SEC,
        # so the fixture-sink's `exclude: [SEC]` is rejected and SEC reviews the
        # corpus anyway. The coverage-write used to DROP that override signal, so
        # run-6's 16 illusory HIGHs reached the gate unannounced. Persist it as
        # `exclude_rejected` AND warn loudly, steering the operator to top-level
        # `exclude_paths:` (which prunes before grouping so no domain reviews it).
        self._groups_json([{"name": "Fixtures", "files": ["tests/fixtures/x.py"]}])
        self._groups_yml("groups:\n  Fixtures:\n    match: ['tests/fixtures/**']\n"
                         "    exclude: [SEC]\n")
        runio._write_json(runio._pano(self.root, "scout-Fixtures.json"),
                           {"group": "Fixtures", "domains": ["SEC"]})
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            coverage.coverage_execute(self.root, self.manifest)
        cov = runio._load_json(runio._pano(self.root, "coverage-Fixtures.json"))
        self.assertEqual(cov["exclude_rejected"], ["SEC"])
        self.assertNotIn("SEC", cov["excluded"])    # override -> not a real exclusion
        self.assertIn("SEC", cov["effective"])       # SEC still RUNS -> the leak disclosed
        msg = err.getvalue()
        self.assertIn("exclude_paths", msg)          # steer to the right tool
        self.assertIn("Fixtures", msg)               # names the offending group

    def test_no_exclude_rejected_key_when_nothing_overridden(self):
        # Back-compat: an excludable domain (OPS) is honored, so no override
        # signal is emitted and the coverage doc keeps its prior shape.
        self._groups_json([{"name": "Auth", "files": ["a.py"]}])
        self._groups_yml("groups:\n  Auth:\n    match: ['a.py']\n    panels: [SEC]\n"
                         "    exclude: [OPS]\n")
        runio._write_json(runio._pano(self.root, "scout-Auth.json"),
                           {"group": "Auth", "panels": ["code"]})
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            coverage.coverage_execute(self.root, self.manifest)
        cov = runio._load_json(runio._pano(self.root, "coverage-Auth.json"))
        self.assertNotIn("exclude_rejected", cov)
        self.assertNotIn("exclude_paths", err.getvalue())
    def test_schema_invalid_scout_is_rediscpatched(self):
        # #3: a scout that parses as JSON but is structurally invalid must be
        # rejected at the return-persist accept boundary -- discard the garbage and
        # re-dispatch -- not consumed into coverage. (#run10 D3: this used to plant
        # a malformed `lenses` object; lenses left the contract with the retired
        # lens_sweep role, so the case is now carried by `domains`, the field that
        # actually routes work.)
        self._groups_json([{"name": "Auth", "files": ["a.py"]}])
        self._groups_yml("groups:\n  Auth:\n    match: ['a.py']\n    panels: [SEC]\n")
        runio._write_json(runio._pano(self.root, "scout-Auth.json"),
                           {"group": "Auth", "domains": [{"name": "SEC"}]})
        err = io.StringIO()
        with mock.patch("scripts.dispatch.render_prompt", return_value="B"), \
             mock.patch("scripts.dispatch.registered_agent_name",
                        return_value="panopticon-scout"), \
             contextlib.redirect_stderr(err):
            result = coverage.coverage_execute(self.root, self.manifest)
        self.assertEqual(result.kind, "checkpoint")
        self.assertEqual(result.checkpoint, "scout")
        self.assertFalse(os.path.exists(runio._pano(self.root, "scout-Auth.json")))
        self.assertFalse(os.path.exists(runio._pano(self.root, "coverage-Auth.json")))
        self.assertIn("domains", err.getvalue())

    def test_scout_carrying_legacy_fields_is_still_accepted(self):
        # #run10 D3: lenses/depth/risk left the contract, but a profile that still
        # emits them (an older host, a cached prompt) must not be rejected -- they
        # are simply never read. Forward compatibility, not a new failure mode.
        self._groups_json([{"name": "Auth", "files": ["a.py"]}])
        self._groups_yml("groups:\n  Auth:\n    match: ['a.py']\n    panels: [SEC]\n")
        runio._write_json(runio._pano(self.root, "scout-Auth.json"),
                           {"group": "Auth", "domains": ["SEC"], "risk": "high",
                            "depth": "deep", "languages": ["python"],
                            "lenses": {"code": [{"name": "x", "spawn": True}]}})
        result = coverage.coverage_execute(self.root, self.manifest)
        self.assertEqual(result.kind, "advanced")
        self.assertTrue(os.path.isfile(runio._pano(self.root, "coverage-Auth.json")))

    def test_repeated_invalid_scout_fails_loud_after_cap(self):
        # A deterministically-broken host that keeps returning garbage must fail
        # loud after the retry cap, never re-dispatch forever.
        self._groups_json([{"name": "Auth", "files": ["a.py"]}])
        self._groups_yml("groups:\n  Auth:\n    match: ['a.py']\n    panels: [SEC]\n")
        bad = {"group": "Auth", "domains": [["SEC"]]}   # #run10 D3: was a bad `lenses`
        with mock.patch("scripts.dispatch.render_prompt", return_value="B"), \
             mock.patch("scripts.dispatch.registered_agent_name",
                        return_value="panopticon-scout"), \
             contextlib.redirect_stderr(io.StringIO()):
            for _ in range(coverage._MAX_SCOUT_ATTEMPTS - 1):
                runio._write_json(runio._pano(self.root, "scout-Auth.json"), bad)
                self.assertEqual(
                    coverage.coverage_execute(self.root, self.manifest).kind,
                    "checkpoint")
            runio._write_json(runio._pano(self.root, "scout-Auth.json"), bad)
            with self.assertRaises(runio.DriverError):
                coverage.coverage_execute(self.root, self.manifest)
    def test_review_batches_all_pending_cells_across_groups(self):
        # #5: every pending (domain, group) cell across ALL groups goes out in ONE
        # review checkpoint (group=None), not one round trip per group (run-6: 26
        # groups = 26 sequential trips while the host runs ~20 agents at once).
        self._groups_json([{"name": "Auth", "files": ["a.py"]},
                           {"name": "Api", "files": ["b.py"]}])
        self._groups_yml("groups:\n"
                         "  Auth:\n    match: ['a.py']\n    panels: [SEC]\n"
                         "  Api:\n    match: ['b.py']\n    panels: [SEC]\n")
        for g in ("Auth", "Api"):
            runio._write_json(runio._pano(self.root, "scout-%s.json" % g),
                               {"group": g, "domains": ["SEC"]})
        # coverage computes one group per call (engine re-selects) -- drive it to
        # completion so BOTH groups have coverage before review runs.
        for _ in range(10):
            if coverage.coverage_done(self.root, self.manifest):
                break
            coverage.coverage_execute(self.root, self.manifest)
        self.assertTrue(coverage.coverage_done(self.root, self.manifest))
        with mock.patch("scripts.dispatch.render_prompt", return_value="B"), \
             mock.patch("scripts.dispatch.registered_agent_name",
                        return_value="panopticon-domain-panel"):
            r = review.review_execute(self.root, self.manifest)
        self.assertEqual(r.kind, "checkpoint")
        self.assertEqual(r.checkpoint, "review")
        self.assertIsNone(r.group)                        # batched, not per-group
        req = requests.load_dispatch_request(self.root)
        groups_in_batch = {e["id"][len("review-"):].rsplit("-", 1)[0]
                           for e in req["entries"]}
        self.assertEqual(groups_in_batch, {"Auth", "Api"})   # both groups, ONE checkpoint

    def test_surfaced_group_retains_full_global_floor(self):
        # #5.0-19: a group whose files/scout show db, tests, and cross-module
        # structure keeps the whole universal floor -- the gate drops cells only
        # where the surface is absent, never where it exists.
        self._groups_json([{"name": "Core", "files": [
            "src/db/schema.prisma", "src/api/route.ts", "tests/route.test.ts"]}])
        self._groups_yml("groups:\n  Core:\n    match: ['src/**']\n    panels: [SEC]\n")
        runio._write_json(runio._pano(self.root, "scout-Core.json"),
                           {"group": "Core", "surfaces": ["database", "architecture"]})
        coverage.coverage_execute(self.root, self.manifest)
        cov = runio._load_json(runio._pano(self.root, "coverage-Core.json"))
        self.assertEqual(cov["effective"], ["ARC", "COD", "DAT", "SEC", "TST"])
        self.assertEqual(cov["global_floor_suppressed"], [])

    def test_group_absent_from_matrix_gets_only_global_floor(self):
        # A group GENUINELY absent from groups.yml (not a <name>_<i> chunk of any
        # committed group) has no VERTICAL floor, but still rides the universal
        # global floor (#5.0-11). (A chunk instead inherits its parent's floor,
        # see TestCoverageBridge.test_chunk_inherits_parent_committed_floor —
        # #5.0-10.)
        self._groups_json([{"name": "Orphan", "files": ["a.py"]}])
        self._groups_yml("groups:\n  Auth:\n    match: ['a.py']\n    panels: [SEC]\n")
        runio._write_json(runio._pano(self.root, "scout-Orphan.json"), {"g": 1})
        coverage.coverage_execute(self.root, self.manifest)
        cov = runio._load_json(runio._pano(self.root, "coverage-Orphan.json"))
        # no vertical floor, and a single surfaceless file ('a.py') -> the
        # surface-gated global floor (#5.0-19) injects only universal COD.
        self.assertEqual(cov["effective"], ["COD"])

    def test_objective_security_surface_forces_sec_without_floor_or_scout(self):
        # #run8 SEC-G2A: a group whose committed panels: never lists SEC and
        # whose scout adds no SEC still gets a deterministic SEC review when its
        # FILES carry an objective security surface (here a dependency manifest +
        # an auth file). Without this a forgetful or adversarial groups.yml
        # silently exempts its own code from security review.
        self._groups_json([{"name": "Api", "files": [
            "requirements.txt", "src/auth/login.py"]}])
        self._groups_yml("groups:\n  Api:\n    match: ['**']\n    panels: [COD]\n")
        runio._write_json(runio._pano(self.root, "scout-Api.json"),
                           {"group": "Api", "domains": ["COD"]})   # no SEC from scout
        coverage.coverage_execute(self.root, self.manifest)
        cov = runio._load_json(runio._pano(self.root, "coverage-Api.json"))
        self.assertIn("SEC", cov["effective"])                 # forced by objective signal
        self.assertEqual(cov["sec_floor_applied"], ["SEC"])    # disclosed
        self.assertIn("SEC", cov["floor"])                     # forced-on, not scout_added

    def test_sec_objective_floor_survives_committed_exclude_sec(self):
        # SEC forced by the objective floor is NON_EXCLUDABLE: a groups.yml that
        # both omits SEC from panels: AND commits exclude: [SEC] cannot silence
        # it; the ignored attempt is disclosed and warned.
        self._groups_json([{"name": "Api", "files": ["Dockerfile", "src/api.py"]}])
        self._groups_yml("groups:\n  Api:\n    match: ['**']\n    panels: [COD]\n"
                         "    exclude: [SEC]\n")
        runio._write_json(runio._pano(self.root, "scout-Api.json"),
                           {"group": "Api", "domains": []})
        with contextlib.redirect_stderr(io.StringIO()):
            coverage.coverage_execute(self.root, self.manifest)
        cov = runio._load_json(runio._pano(self.root, "coverage-Api.json"))
        self.assertIn("SEC", cov["effective"])
        self.assertEqual(cov["exclude_rejected"], ["SEC"])

    def test_surfaceless_group_gets_no_sec_floor(self):
        # #5.0-19 stays honored end-to-end: a group with no objective security
        # surface spends no SEC cell (the floor widens, it does not blanket).
        self._groups_json([{"name": "Docs", "files": ["README.md", "docs/intro.md"]}])
        self._groups_yml("groups:\n  Docs:\n    match: ['**']\n    panels: [COD]\n")
        runio._write_json(runio._pano(self.root, "scout-Docs.json"),
                           {"group": "Docs", "domains": []})
        coverage.coverage_execute(self.root, self.manifest)
        cov = runio._load_json(runio._pano(self.root, "coverage-Docs.json"))
        self.assertNotIn("SEC", cov["effective"])
        self.assertEqual(cov["sec_floor_applied"], [])

    def test_coverage_done_only_when_all_groups_covered(self):
        self._groups_json([{"name": "A", "files": []}, {"name": "B", "files": []}])
        self._groups_yml("groups:\n  A:\n    match: ['*']\n  B:\n    match: ['*']\n")
        self.assertFalse(coverage.coverage_done(self.root, self.manifest))
        for g in ("A", "B"):
            runio._write_json(runio._pano(self.root, "coverage-%s.json" % g), {"g": g})
        self.assertTrue(coverage.coverage_done(self.root, self.manifest))

class TestCoverageBridge(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.root = os.path.realpath(self._t.name)
        os.makedirs(runio._pano(self.root))
        self.addCleanup(self._t.cleanup)
        self.manifest = {"run_id": "R", "security_mode": "standard", "host": "claude"}

    def _setup(self, floor_yaml, scout_domains):
        runio._write_json(runio._pano(self.root, "groups.json"),
                           {"groups": [{"name": "Auth", "files": ["a.py"]}]})
        with open(runio._pano(self.root, "groups.yml"), "w") as fh:
            fh.write(floor_yaml)
        runio._write_json(runio._pano(self.root, "scout-Auth.json"),
                           {"group": "Auth", "domains": scout_domains})

    def test_scout_widens_coverage(self):
        # OPS is a vertical domain (not in the global floor), so the scout genuinely
        # widens coverage with it; SEC is already the committed floor.
        self._setup("groups:\n  Auth:\n    match: ['a.py']\n    panels: [SEC]\n",
                    ["SEC", "OPS"])
        coverage.coverage_execute(self.root, self.manifest)
        cov = runio._load_json(runio._pano(self.root, "coverage-Auth.json"))
        self.assertEqual(cov["scout_added"], ["OPS"])          # SEC already floor
        # #5.0-19: 'a.py' is surfaceless, so the global floor injects only COD;
        # OPS still widens via scout_added, SEC is the committed floor.
        self.assertEqual(cov["effective"], ["COD", "OPS", "SEC"])

    def test_invalid_scout_domain_dropped_and_disclosed(self):
        self._setup("groups:\n  Auth:\n    match: ['a.py']\n    panels: [SEC]\n",
                    ["DAT", "BOGUS"])
        coverage.coverage_execute(self.root, self.manifest)
        cov = runio._load_json(runio._pano(self.root, "coverage-Auth.json"))
        self.assertEqual(cov["scout_added"], ["DAT"])
        self.assertEqual(cov["scout_invalid"], ["BOGUS"])

    def test_scout_cannot_override_exclude(self):
        self._setup("groups:\n  Auth:\n    match: ['a.py']\n    panels: [SEC]\n"
                    "    exclude: [DAT]\n", ["DAT"])
        coverage.coverage_execute(self.root, self.manifest)
        cov = runio._load_json(runio._pano(self.root, "coverage-Auth.json"))
        self.assertNotIn("DAT", cov["effective"])              # exclude wins

    def test_non_dict_scout_rediscpatched_then_fails_loud(self):
        # #5.0-12 + #3: a scout returning a JSON ARRAY (not an object) must never
        # crash `.get` with an uncaught AttributeError. It is now rejected at the
        # return-persist accept boundary and re-dispatched (uniformly with any
        # other shape error); a host that keeps returning a non-object fails loud
        # after the retry cap, never loops.
        runio._write_json(runio._pano(self.root, "groups.json"),
                           {"groups": [{"name": "Auth", "files": ["a.py"]}]})
        with open(runio._pano(self.root, "groups.yml"), "w") as fh:
            fh.write("groups:\n  Auth:\n    match: ['a.py']\n    panels: [SEC]\n")
        with mock.patch("scripts.dispatch.render_prompt", return_value="B"), \
             mock.patch("scripts.dispatch.registered_agent_name",
                        return_value="panopticon-scout"), \
             contextlib.redirect_stderr(io.StringIO()):
            for _ in range(coverage._MAX_SCOUT_ATTEMPTS - 1):
                with open(runio._pano(self.root, "scout-Auth.json"), "w") as fh:
                    fh.write('["SEC", "DAT"]')      # a list, not an object
                self.assertEqual(
                    coverage.coverage_execute(self.root, self.manifest).kind,
                    "checkpoint")
            with open(runio._pano(self.root, "scout-Auth.json"), "w") as fh:
                fh.write('["SEC", "DAT"]')
            with self.assertRaises(runio.DriverError):
                coverage.coverage_execute(self.root, self.manifest)

    def test_chunk_inherits_parent_committed_floor(self):
        # #5.0-10: a >15-file group split into Auth_1/Auth_2 chunks must inherit
        # the committed parent (Auth) floor, not fall back to an empty floor.
        runio._write_json(runio._pano(self.root, "groups.json"),
                           {"groups": [{"name": "Auth_1", "files": ["a.py"]}]})
        with open(runio._pano(self.root, "groups.yml"), "w") as fh:
            fh.write("groups:\n  Auth:\n    match: ['a.py']\n    panels: [SEC]\n")
        runio._write_json(runio._pano(self.root, "scout-Auth_1.json"),
                           {"group": "Auth_1", "domains": []})
        coverage.coverage_execute(self.root, self.manifest)
        cov = runio._load_json(runio._pano(self.root, "coverage-Auth_1.json"))
        # SEC is the parent's committed floor — only present if the chunk resolved
        # to Auth (without the fix the chunk misses the matrix -> no SEC).
        self.assertIn("SEC", cov["floor"])
        self.assertIn("SEC", cov["effective"])

    def test_chunk_parent_parsing(self):
        self.assertEqual(coverage._chunk_parent("Auth_1"), "Auth")
        self.assertEqual(coverage._chunk_parent("skill_1_2"), "skill_1")
        self.assertEqual(coverage._chunk_parent("._3"), ".")   # legacy leftover chunk
        self.assertEqual(coverage._chunk_parent("Ungrouped_3"), "Ungrouped")  # run-9 A5
        self.assertIsNone(coverage._chunk_parent("Auth"))
        self.assertIsNone(coverage._chunk_parent("Auth_x"))
