"""Tests for scripts.phases.requests: dispatch-request.json, the driver plan and the
prompt file lists every checkpoint emits.
"""
import hashlib
import json
import os
import tempfile
import unittest
from unittest import mock

from scripts import hosts
from conftest import write_host_evidence
import scripts.phases.runio as runio
import scripts.phases.persist as persist
import scripts.phases.requests as requests
import scripts.phases.coverage as coverage
import scripts.phases.setup as setup
import scripts.run_manifest as run_manifest
import scripts.phases.review as review
import scripts.phases.verify as verify

import scripts.ocrdb as ocrdb
import scripts.model_resolver as model_resolver


class TestWriteDispatchRequest(unittest.TestCase):
    def test_writes_host_agnostic_request(self):
        with tempfile.TemporaryDirectory() as root:
            entries = [{"id": "e1", "agent": "panopticon-scout", "enforced": True,
                        "model": None, "prompt": "…", "out_file": "/abs/scout-Auth.json"}]
            path = requests.write_dispatch_request(root, "RID", "scout", "Auth", entries)
            self.assertTrue(path.endswith(".panopticon/dispatch-request.json"))
            self.assertEqual(path, os.path.abspath(path))
            with open(path, encoding="utf-8") as fh:
                req = json.load(fh)
            self.assertEqual(req["checkpoint"], "scout")
            self.assertEqual(req["run_id"], "RID")
            self.assertEqual(req["group"], "Auth")
            self.assertEqual(req["entries"][0]["out_file"], "/abs/scout-Auth.json")
            # host-agnostic: no per-host delivery block
            self.assertNotIn("delivery", req["entries"][0])

    def test_unknown_checkpoint_kind_raises(self):
        with tempfile.TemporaryDirectory() as root:
            with self.assertRaises(ValueError):
                requests.write_dispatch_request(root, "RID", "bogus", "Auth", [])

class TestReviewerFileListsAreAbsolute(unittest.TestCase):
    """#975-class regression: the reviewer subagent inherits the HOST's cwd
    (the user's checkout), never the --pr worktree/review_root. A relative
    file list in the checkpoint prompt resolves against the wrong checkout —
    silent wrong-tree review. review_root here is deliberately NOT cwd (a
    dedicated tmp dir distinct from the test process's cwd), so a prompt that
    still carries a bare-relative entry would resolve to nothing/the wrong
    file under the old code, exactly like a real --pr run."""

    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.root = os.path.realpath(self._t.name)
        os.makedirs(runio._pano(self.root))
        self.addCleanup(self._t.cleanup)
        self.manifest = {"run_id": "R", "security_mode": "standard", "host": "claude"}
        # #1344 F4 (a): _cell_entry/_verify_entry now derive `delivery` from
        # the host's proven write guard -- this class is about the #975 file
        # list/repo-root pin, not the bridge, so prove it PROVEN and keep
        # exercising the enforced/self-write path these tests were written for.
        write_host_evidence(self.root, {c: hosts.PROVEN for c in hosts.CAPABILITIES})
        self.assertNotEqual(self.root, os.path.realpath(os.getcwd()))
        self.files = ["src/checkout/pay.py"]
        self.abs_file = os.path.abspath(os.path.join(self.root, self.files[0]))
        self.cell = [{"id": "F1", "code": "SEC-A1A", "severity": "HIGH", "title": "t",
                      "category": "SEC", "location": {"file": self.files[0], "line": 1},
                      "description": "d"}]

    def _make_verify_entry(self):
        return verify._verify_entry(self.root, self.manifest, "Auth", "SEC",
                                    self.files, self.cell, "claude",
                                    ocrdb.load_bundle(), "primary")

    def _assert_absolute_not_relative(self, prompt):
        self.assertIn("- %s" % self.abs_file, prompt)
        # no bare-relative remnant: "- src/checkout/pay.py" is not a substring
        # of "- /tmp/.../src/checkout/pay.py" (the dash-space precedes the
        # absolute root, not "src"), so this is a real, precise negative.
        self.assertNotIn("- %s" % self.files[0], prompt)

    def test_scout_entry_file_list_is_absolute(self):
        entry = coverage._scout_entry(self.root, self.manifest, "Auth", self.files, "claude")
        self._assert_absolute_not_relative(entry["prompt"])

    def test_cell_entry_file_list_is_absolute(self):
        entry = review._cell_entry(self.root, self.manifest, "Auth", "SEC",
                                    self.files, [], "claude", ocrdb.load_bundle())
        self._assert_absolute_not_relative(entry["prompt"])

    def test_verify_entry_file_list_is_absolute(self):
        self._assert_absolute_not_relative(self._make_verify_entry()["prompt"])

    def test_verify_entry_prompt_carries_repo_root_header(self):
        # The advisor also adjudicates the findings JSON's `location` fields,
        # which stay repo-relative on disk (Part A can't reach into that
        # payload) -- so the prompt itself must tell the advisor the absolute
        # root those relative locations resolve against (mirrors the retired
        # dispatch.render_advisor_prompts' #975 "Repo root:" prepend).
        expected_header = "Repo root: %s" % os.path.abspath(self.root)
        # startswith is strictly stronger than assertIn (present AND at pos 0).
        entry = self._make_verify_entry()
        self.assertTrue(entry["prompt"].startswith(requests.entry_marker(entry["id"]) + expected_header))


class TestBoundModel(unittest.TestCase):
    """#1344 F4 (b): the entry's model comes from model_resolver, not a literal.

    One helper so five builders cannot resolve five ways. The value is the
    STRING model id, not resolve_model's whole config dict: docs/PANOPTICON.md
    defines entry["model"] as "the model named by entry['model'] (omit when
    null)". Kimi's max_context_size/alias extras are that family's PR to carry.
    """

    def test_returns_the_resolved_model_string(self):
        with mock.patch.object(model_resolver, "resolve_model",
                               return_value={"model": "SENTINEL", "alias": "x"}) as rm:
            self.assertEqual("SENTINEL", requests.bound_model("claude", "domain_panel"))
        rm.assert_called_once_with("claude", "domain_panel")

    def test_a_host_with_no_model_policy_binds_none(self):
        # gemini/generic: registry row, no profile table, no fallback table.
        # None means "inherit the session's model" and is what those hosts
        # dispatch with today -- unchanged by this plan (R-F4-1).
        for host in ("gemini", "generic"):
            with self.subTest(host=host):
                self.assertIsNone(requests.bound_model(host, "domain_panel"))

    def test_claude_binds_the_profile_model_not_the_session_default(self):
        # Oracle is resolve_model itself, not a literal: model-profiles.yml is
        # the owner of the value and this test must not become a second copy.
        expected = model_resolver.resolve_model("claude", "domain_panel")["model"]
        self.assertIsNotNone(expected, "fixture precondition: claude has a profile")
        self.assertEqual(expected, requests.bound_model("claude", "domain_panel"))


class TestDelivery(unittest.TestCase):
    """#1344 F4 (a): delivery is DERIVED from the role's Write grant and the
    host's proven write guard, in one place. It used to be a literal set at
    exactly one builder (the tool-advisor) while the two write-capable
    builders never set it -- so a host with no write guard got unguarded
    self-write.
    """

    def _evidence(self, guard):
        # MIXED, and specifically tool_policy PROVEN with the guard varying:
        # an enforced shell with no write guard is the case the bridge is for.
        return {hosts.TOOL_POLICY_ENFORCED: {"state": hosts.PROVEN, "by": "x", "detail": "x"},
                hosts.ARTIFACT_WRITE_GUARD: {"state": guard, "by": "x", "detail": "x"},
                hosts.USAGE_LEDGER: {"state": hosts.UNKNOWN, "by": None, "detail": "x"}}

    def test_a_write_role_on_a_guarded_host_self_writes(self):
        mode, prefix = requests.delivery("claude", self._evidence(hosts.PROVEN),
                                         "domain-panel.md", "/abs/out.json")
        self.assertIsNone(mode)
        self.assertEqual("", prefix)

    def test_a_write_role_on_an_unguarded_host_is_bridged_with_the_preamble(self):
        for guard in (hosts.REFUTED, hosts.UNKNOWN):
            with self.subTest(guard=guard):
                mode, prefix = requests.delivery("claude", self._evidence(guard),
                                                 "domain-panel.md", "/abs/out.json")
                self.assertEqual("return_json", mode)
                self.assertEqual(requests.RETURN_PERSIST_PREAMBLE
                                 % {"out_file": "/abs/out.json"}, prefix)

    def test_a_read_only_role_is_return_persist_with_no_preamble(self):
        # advisor.md grants no Write: there is nothing to override, so the
        # template's own "return" instruction stands and no preamble is added
        # -- on a guarded host AND an unguarded one.
        for guard in (hosts.PROVEN, hosts.REFUTED):
            with self.subTest(guard=guard):
                mode, prefix = requests.delivery("claude", self._evidence(guard),
                                                 "advisor.md", "/abs/v.json")
                self.assertEqual(("return_json", ""), (mode, prefix))

    def test_a_host_that_claims_no_guard_is_bridged(self):
        # gemini/generic: the registry's two claim-nothing rows -- generic
        # selectable, gemini registered-only since #1621. R-F4-4.
        for host in ("gemini", "generic"):
            with self.subTest(host=host):
                mode, _prefix = requests.delivery(host, {}, "domain-advisor.md", "/abs/o")
                self.assertEqual("return_json", mode)

    def test_the_preamble_names_the_out_file_and_forbids_the_write(self):
        prefix = requests.RETURN_PERSIST_PREAMBLE % {"out_file": "/abs/out.json"}
        self.assertIn("/abs/out.json", prefix)
        self.assertIn("do NOT write", prefix)
        self.assertIn("final message", prefix)
        self.assertTrue(prefix.endswith("\n\n"), "preamble must separate from the body")


class TestDriverPlanEntries(unittest.TestCase):
    def test_the_declaration_plan_carries_no_scope(self):
        # Its docstring says so: "a declaration of which out_files must exist,
        # not a scope grant". Pinned so the plan and the entries do not drift
        # into looking alike -- reconcile reads one, a confinement primitive
        # will read the other.
        with tempfile.TemporaryDirectory() as root:
            manifest = {"run_id": "R", "security_mode": "standard", "host": "claude"}
            runio._write_json(runio._pano(root, "groups.json"),
                             {"groups": [{"name": "Auth", "files": ["a.py"]}]})
            runio._write_json(runio._pano(root, "coverage-Auth.json"),
                             {"effective": ["SEC"]})
            entries = list(requests._driver_plan_entries(root, manifest))
            self.assertTrue(entries)
            for entry in entries:
                self.assertNotIn("files", entry)
                self.assertNotIn("model", entry)

    def test_driver_plan_entries_carry_no_scope(self):
        # R-P5-6: a declaration of which out_files must exist, not a scope grant.
        with tempfile.TemporaryDirectory() as root:
            manifest = {"run_id": "R", "security_mode": "standard", "host": "claude"}
            runio._write_json(runio._pano(root, "groups.json"),
                             {"groups": [{"name": "Auth", "files": ["a.py"]}]})
            runio._write_json(runio._pano(root, "coverage-Auth.json"),
                             {"effective": ["SEC"]})
            entries = list(requests._driver_plan_entries(root, manifest))
            self.assertTrue(entries)
            for entry in entries:
                self.assertNotIn("scope", entry)
                self.assertNotIn("marker", entry)


class TestEntryMarkerAndScope(unittest.TestCase):
    def test_entry_marker_is_the_hooks_marker_line_plus_newline(self):
        from scripts import read_guard_hook
        self.assertEqual(read_guard_hook.marker_line("review-app-SEC") + "\n",
                         requests.entry_marker("review-app-SEC"))
        self.assertEqual("review-app-SEC",
                         read_guard_hook.marker_of(requests.entry_marker("review-app-SEC") + "body"))

    def test_scope_has_exactly_the_three_keys(self):
        from scripts import read_guard_hook
        self.assertEqual({"files": ["/a"], "dirs": [], "reads": []}, requests.scope(files=["/a"]))
        self.assertEqual(set(read_guard_hook.SCOPE_KEYS), set(requests.scope()))


class TestTheRetryPromptCarriesTheRefusal(unittest.TestCase):
    """D10 ruling 2: the next attempt is told why the last one was refused.

    The retry used to be the same prompt, verbatim: `driver.run` regenerates
    the dispatch request and `_materialize_prompts` writes it out, and nothing
    anywhere told the agent that its previous reply had been thrown away or
    what was wrong with it. Run-13 spent three launches of one cell that way.
    """

    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.root = os.path.realpath(self._t.name)
        self.addCleanup(self._t.cleanup)
        os.makedirs(runio._pano(self.root))
        self.out_file = runio._pano(self.root, "findings-app-SEC.json")
        # return-persist: D10 F4 gates the retry note on the delivery mode,
        # because the block's whole text is about the envelope the controller
        # will persist.
        self.entry = {"id": "review-app-SEC", "prompt": "review the app cell",
                      "delivery": "return_json",
                      "out_file": self.out_file, "run_id": "RID",
                      "group": "app", "domain": "SEC"}

    def _write(self, entry):
        path = requests.write_dispatch_request(self.root, "RID", "review", None, [entry])
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)["entries"][0]

    def _refuse(self, reason):
        return persist.retain_rejected(persist.run_dir(self.root), self.entry,
                                       '{"findings": []}', reason, kind=persist.REFUSAL)

    def test_an_entry_with_no_record_is_what_it_has_always_been(self):
        written = self._write(self.entry)
        self.assertEqual(written["prompt"], "review the app cell")
        self.assertNotIn("prior_rejection", written)

    def test_the_reason_reaches_both_the_prompt_and_the_prompt_file(self):
        self._refuse("reply carries no _panopticon stamp")
        written = self._write(self.entry)
        self.assertIn("reply carries no _panopticon stamp", written["prompt"])
        self.assertIn("attempt 1", written["prompt"])
        self.assertIn('"findings"', written["prompt"].split("review the app cell")[1])
        self.assertEqual({"attempt": 1, "reason": "reply carries no _panopticon stamp"},
                         written["prior_rejection"])
        with open(written["prompt_file"], encoding="utf-8") as fh:
            self.assertEqual(fh.read(), written["prompt"])

    def test_the_block_names_the_latest_refusal_only(self):
        self._refuse("first reason")
        self._refuse("second reason")
        written = self._write(self.entry)
        self.assertEqual(2, written["prior_rejection"]["attempt"])
        self.assertIn("second reason", written["prompt"])
        self.assertNotIn("first reason", written["prompt"])

    def test_the_envelope_shape_is_the_one_the_role_is_refused_against(self):
        self.assertIn('"verdicts"', persist.envelope_shape(
            {"out_file": "/r/.panopticon/verdicts/verdicts-app-SEC.json"}))
        self.assertIn('"findings"', persist.envelope_shape(self.entry))
        self.assertIn('"domains"', persist.envelope_shape(
            {"out_file": "/r/.panopticon/scout-app.json"}))


class TestOutputSchemaIsStampedOnTheEntry(unittest.TestCase):
    """D10 ruling 3: the entry names its role's published schema, so a runner
    whose CLI takes one can constrain the reply without knowing what a role
    is. Host-agnostic, exactly as `delivery` and `prompt_file` are."""

    ADVERTISED = {hosts.OUTPUT_SCHEMA: {"flag": "--json-schema", "advertised": True,
                                        "detail": "fixture"}}

    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.root = os.path.realpath(self._t.name)
        self.addCleanup(self._t.cleanup)
        os.makedirs(runio._pano(self.root))
        write_host_evidence(self.root, {}, cli_flags=self.ADVERTISED)

    def _written(self, entry):
        path = requests.write_dispatch_request(self.root, "RID", "review", None, [entry])
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)["entries"][0]

    def test_a_review_cell_entry_names_the_findings_envelope(self):
        written = self._written({"id": "review-app-SEC", "prompt": "p",
                                 "delivery": "return_json",
                                 "out_file": runio._pano(self.root, "findings-app-SEC.json")})
        self.assertEqual(os.path.basename(written["output_schema"]),
                         "findings-envelope-schema.json")
        self.assertEqual(written["output_schema"],
                         persist.role_schema({"out_file": "findings-app-SEC.json"}))

    def test_a_self_writing_entry_names_no_schema(self):
        # The schema describes what the CONTROLLER will persist from the reply.
        # A self-writing reviewer's final message is a one-line confirmation --
        # the findings went to its out_file under the write guard -- so
        # constraining that message to the findings envelope would demand the
        # agent return the very object the whole self-write path exists to
        # avoid moving through the loop.
        written = self._written({"id": "review-app-SEC", "prompt": "p",
                                 "out_file": runio._pano(self.root, "findings-app-SEC.json")})
        self.assertNotIn("output_schema", written)
        returned = self._written({"id": "review-app-SEC", "prompt": "p",
                                  "delivery": "return_json",
                                  "out_file": runio._pano(self.root, "findings-app-SEC.json")})
        self.assertIn("output_schema", returned)

    def test_nothing_is_stamped_until_the_cli_says_it_takes_one(self):
        # D10 F1, the fail-safe: a machine whose `claude` predates
        # `--json-schema` exits non-zero on the unknown option and prints no
        # envelope, so EVERY return-persist entry would fail its three
        # launches and the run would die naming an entry, not the flag.
        # Absent evidence and a refuted flag are the same answer -- omit --
        # which is byte-identical to the behaviour before ruling 3.
        cell = {"id": "review-app-SEC", "prompt": "p", "delivery": "return_json",
                "out_file": runio._pano(self.root, "findings-app-SEC.json")}
        for flags in ({}, {hosts.OUTPUT_SCHEMA: {"flag": "--json-schema", "advertised": False,
                                                 "detail": "fixture"}},
                      {hosts.OUTPUT_SCHEMA: {"flag": "--json-schema", "advertised": None,
                                             "detail": "fixture"}}):
            with self.subTest(flags=flags):
                write_host_evidence(self.root, {}, cli_flags=flags)
                self.assertNotIn("output_schema", self._written(cell))
        write_host_evidence(self.root, {}, cli_flags=self.ADVERTISED)
        self.assertIn("output_schema", self._written(cell))

    def test_a_scout_entry_names_no_schema_at_all(self):
        written = self._written({"id": "scout-app", "prompt": "p",
                                 "delivery": "return_json",
                                 "out_file": runio._pano(self.root, "scout-app.json")})
        self.assertNotIn("output_schema", written)


class RequestIntegrityCase(unittest.TestCase):
    """#1727: `.panopticon/dispatch-request.json` lives INSIDE the reviewed
    tree, and several readers trust every field on it. Its integrity is
    anchored in the run (or setup) manifest -- a sha256 over the exact bytes
    the driver wrote, recorded as it writes them. That manifest is inside the
    tree too; what it is, is better defended (no dispatched agent may write
    it; `_foreign_manifest` discards a planted one), and forging it as well is
    a second write the loop's in-memory hash still catches.
    """

    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.root = os.path.realpath(self._t.name)
        self.addCleanup(self._t.cleanup)
        os.makedirs(runio._pano(self.root))

    def _run_manifest(self):
        run_manifest.write_manifest(self.root, {
            "schema_version": 1, "run_id": "0123456789abcdef", "host": "claude",
            "security_mode": "standard", "created": "2026-09-20T00:00:00Z",
            "review_root": self.root, "target": self.root})
        return run_manifest.load_manifest(self.root)

    def _setup_manifest(self):
        runio._write_json(setup._setup_manifest_path(self.root),
                          {"schema_version": 1, "run_id": "RID", "host": "claude",
                           "review_root": self.root, "target": self.root})

    def _entries(self):
        return [{"id": "scout-app", "agent": "panopticon-scout", "enforced": True,
                 "model": None, "prompt": "p",
                 "out_file": os.path.join(self.root, ".panopticon", "scout-app.json")}]

    def _write(self, checkpoint="scout", namespace=None):
        return requests.write_dispatch_request_bound(
            self.root, "RID", checkpoint, None, self._entries(), namespace=namespace)

    def _tamper(self, path):
        with open(path, "r+b") as fh:
            body = fh.read().replace(b'"scout-app"', b'"scout-evil"', 1)
            fh.seek(0)
            fh.write(body)
            fh.truncate()


class TestTheWriterRecordsTheHash(RequestIntegrityCase):
    def test_the_recorded_hash_is_the_sha256_of_the_file_bytes(self):
        self._run_manifest()
        path, digest = self._write()
        with open(path, "rb") as fh:
            self.assertEqual(hashlib.sha256(fh.read()).hexdigest(), digest)
        record = run_manifest.load_manifest(self.root)["dispatch_request"]
        self.assertEqual(record["sha256"], digest)
        self.assertEqual(record["checkpoint"], "scout")
        self.assertTrue(record["at"])

    def test_the_old_name_still_returns_only_the_path(self):
        self._run_manifest()
        path = requests.write_dispatch_request(self.root, "RID", "scout", None,
                                               self._entries())
        self.assertEqual(path, os.path.abspath(path))
        self.assertTrue(os.path.isfile(path))
        self.assertEqual(run_manifest.load_manifest(self.root)["dispatch_request"]["sha256"],
                         hashlib.sha256(open(path, "rb").read()).hexdigest())

    def test_the_setup_namespace_records_into_the_setup_manifest(self):
        self._setup_manifest()
        path, digest = self._write(checkpoint="scan", namespace="setup")
        self.assertTrue(path.endswith("setup-dispatch-request.json"), path)
        record = setup.load_setup_manifest(self.root)["dispatch_request"]
        self.assertEqual((record["sha256"], record["checkpoint"]), (digest, "scan"))
        # ...and never into the review namespace's manifest
        self.assertIsNone(run_manifest.load_manifest(self.root))

    def test_every_write_overwrites_the_record(self):
        # The request is ROLLING -- regenerated every iteration -- so the
        # record is not an anti-drift key: it says what the driver last wrote.
        self._run_manifest()
        _p1, first = self._write()
        _p2, second = self._write(checkpoint="review")
        self.assertNotEqual(first, second)
        self.assertEqual(run_manifest.load_manifest(self.root)["dispatch_request"],
                         {"checkpoint": "review", "sha256": second,
                          "at": run_manifest.load_manifest(self.root)
                          ["dispatch_request"]["at"]})

    def test_a_tree_with_no_manifest_records_nothing_and_still_writes(self):
        # Unit callers (and the pre-manifest window) have no manifest to
        # anchor to; the writer must not raise, and the reader then refuses.
        path, digest = self._write()
        self.assertTrue(os.path.isfile(path))
        self.assertTrue(digest)


class TestLoadBoundRequest(RequestIntegrityCase):
    """Fail-closed, every case: a reader that cannot prove the file is the one
    this run wrote gets `(None, <refusal>)` and never an entry."""

    def test_a_clean_file_loads_with_no_refusal(self):
        self._run_manifest()
        _path, digest = self._write()
        req, refusal = requests.load_bound_request(self.root)
        self.assertIsNone(refusal)
        self.assertEqual(req["checkpoint"], "scout")
        self.assertEqual([e["id"] for e in req["entries"]], ["scout-app"])
        # the in-memory hash the loop carries must agree too
        req2, refusal2 = requests.load_bound_request(self.root, expected_sha256=digest)
        self.assertIsNone(refusal2)
        self.assertEqual(req2["run_id"], req["run_id"])

    def test_a_fresh_tree_with_no_file_and_no_record_is_not_a_refusal(self):
        # The `driver loop` re-entry read: before `_first_run` there may be no
        # previous request at all, which is "no previous entries", not an error.
        self._run_manifest()
        self.assertEqual((None, None), requests.load_bound_request(self.root))

    def test_a_tampered_byte_is_refused_with_both_hashes(self):
        self._run_manifest()
        path, digest = self._write()
        self._tamper(path)
        req, refusal = requests.load_bound_request(self.root)
        self.assertIsNone(req)
        self.assertIn("dispatch-request.json does not match the request this run wrote",
                      refusal)
        self.assertIn(digest[:12], refusal)
        self.assertIn("re-run", refusal)
        # never the file's contents, only hashes
        self.assertNotIn("scout-evil", refusal)

    def test_a_request_with_no_recorded_hash_is_refused(self):
        # A request on disk that this run's manifest does not vouch for: a
        # planted file, or one left by a manifest that was reset under it.
        self._run_manifest()
        self._write()
        manifest = run_manifest.load_manifest(self.root)
        manifest.pop("dispatch_request")
        run_manifest._rewrite(self.root, manifest)
        req, refusal = requests.load_bound_request(self.root)
        self.assertIsNone(req)
        self.assertIn("no recorded hash in run-manifest.json", refusal)

    def test_a_missing_file_with_a_record_is_refused(self):
        self._run_manifest()
        path, _digest = self._write()
        os.remove(path)
        req, refusal = requests.load_bound_request(self.root)
        self.assertIsNone(req)
        self.assertIn("dispatch request missing", refusal)
        self.assertIn(path, refusal)

    def test_a_record_altered_after_the_write_is_refused_by_the_in_memory_hash(self):
        # Assume the manifest was reached too (it is inside the tree, only
        # better defended): the loop also carries the hash the phase returned
        # IN MEMORY, which no on-disk edit can reach.
        self._run_manifest()
        path, digest = self._write()
        forged = hashlib.sha256(b"forged").hexdigest()
        with open(path, "wb") as fh:
            fh.write(b"forged")
        manifest = run_manifest.load_manifest(self.root)
        manifest["dispatch_request"]["sha256"] = forged
        run_manifest._rewrite(self.root, manifest)
        # the file now matches the RECORD, and only the in-memory hash knows better
        req, refusal = requests.load_bound_request(self.root, expected_sha256=digest)
        self.assertIsNone(req)
        self.assertIn("run-manifest.json's recorded dispatch request hash was altered",
                      refusal)
        self.assertIn(digest[:12], refusal)
        self.assertIn(forged[:12], refusal)

    def test_the_setup_namespace_reads_its_own_manifest(self):
        self._setup_manifest()
        path, digest = self._write(checkpoint="scan", namespace="setup")
        req, refusal = requests.load_bound_request(self.root, "setup",
                                                   expected_sha256=digest)
        self.assertIsNone(refusal)
        self.assertEqual(req["checkpoint"], "scan")
        self._tamper(path)
        req, refusal = requests.load_bound_request(self.root, "setup")
        self.assertIsNone(req)
        self.assertIn("does not match the request this run wrote", refusal)

    def test_a_setup_record_altered_names_the_setup_manifest(self):
        self._setup_manifest()
        _path, digest = self._write(checkpoint="scan", namespace="setup")
        manifest = setup.load_setup_manifest(self.root)
        manifest["dispatch_request"]["sha256"] = hashlib.sha256(b"x").hexdigest()
        runio._write_json(setup._setup_manifest_path(self.root), manifest)
        req, refusal = requests.load_bound_request(self.root, "setup",
                                                   expected_sha256=digest)
        self.assertIsNone(req)
        self.assertIn("setup-manifest.json's recorded dispatch request hash", refusal)

    def test_unparseable_json_that_matches_its_record_is_still_refused(self):
        self._run_manifest()
        path, _digest = self._write()
        with open(path, "wb") as fh:
            fh.write(b"{not json")
        run_manifest.record_dispatch_request(
            self.root, None, "scout", hashlib.sha256(b"{not json").hexdigest())
        req, refusal = requests.load_bound_request(self.root)
        self.assertIsNone(req)
        self.assertIn("is not a readable dispatch request", refusal)
