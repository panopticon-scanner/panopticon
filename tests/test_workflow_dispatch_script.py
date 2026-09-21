"""#1736: automated coverage for skill/workflows/dispatch.js, the Claude
Code Workflow script that runs one Panopticon session-mode checkpoint.

No test loaded it: it is Workflow-tool source, not an importable module --
`export const meta = {...}` then top-level code closing over the Workflow
globals `args`, `agent`, `parallel`, `phase`, `log`, ending in a top-level
`return`. `tests/test_skill_md.py` only checks that it parses as JavaScript
and names a few literal tokens; nothing had ever RUN it. A flipped `enforced`
condition (`e.enforced && e.agent` -> `||`) would launch a reviewer outside
its registered shell, and a swapped read-guard marker or reply-routing branch
would deny every read or misfile findings -- with nothing failing (#1736,
TST-A1A).

These pins run the real script through `tests/workflows/dispatch_harness.mjs`,
a small Node harness (no npm packages) that evaluates it with `vm` -- never
as an ES module import, since the script has no import target for the
Workflow globals it closes over -- and answers `agent()` calls from a JSON
scenario. Shells out to `node`; guarded through `_test_helpers.skip_or_fail`
so `PANOPTICON_REQUIRE_INTEGRATION=1` turns a missing node into a failure
rather than a silent green, the same as every other live-tool gate in this
suite (#1422).
"""
import json
import os
import shutil
import subprocess
import unittest

from conftest import REPO_ROOT
from _test_helpers import skip_or_fail

HARNESS = os.path.join(REPO_ROOT, "tests", "workflows", "dispatch_harness.mjs")
DISPATCH_JS = os.path.join(REPO_ROOT, "skill", "workflows", "dispatch.js")


def _entry(entry_id, **overrides):
    """A minimally-valid dispatch entry for `entry_id`; override any field."""
    entry = {
        "id": entry_id,
        "marker": "panopticon-entry: " + entry_id,
        "prompt_file": entry_id + ".md",
    }
    entry.update(overrides)
    return entry


class DispatchScriptTestCase(unittest.TestCase):
    def setUp(self):
        self.node = shutil.which("node")
        if not self.node:
            skip_or_fail(self, "node is not installed here; CI's runners "
                         "have it, and PANOPTICON_REQUIRE_INTEGRATION=1 is "
                         "how a runner that is MEANT to have it fails loud")

    def run_harness(self, scenario, script=None):
        """The harness's `{meta, calls, result, error}` document for `scenario`
        run against `script` (default: the real dispatch.js)."""
        proc = subprocess.run(
            [self.node, HARNESS, script or DISPATCH_JS],
            input=json.dumps(scenario), capture_output=True, text=True,
            timeout=30)
        self.assertEqual(
            0, proc.returncode,
            "harness process failed (not the wrapped script -- it always "
            "exits 0 and reports the wrapped script's own throw in `error`):"
            "\n%s" % proc.stderr)
        return json.loads(proc.stdout)


class TestEmptyEntries(DispatchScriptTestCase):
    """(a) empty `entries` -> an error naming `args.entries`."""

    def test_empty_list_errors_naming_args_entries(self):
        out = self.run_harness({"args": {"entries": []}})
        self.assertIsNotNone(out["error"])
        self.assertIn("args.entries", out["error"])
        self.assertEqual([], out["calls"], "no agent should be dispatched")

    def test_missing_entries_key_errors_the_same_way(self):
        out = self.run_harness({"args": {}})
        self.assertIsNotNone(out["error"])
        self.assertIn("args.entries", out["error"])


class TestMarkerGuard(DispatchScriptTestCase):
    """(b) missing/wrong marker -> an error naming the read guard, exact-match
    on 'panopticon-entry: ' + id (a marker for a DIFFERENT id is rejected)."""

    def test_missing_marker_names_the_read_guard(self):
        out = self.run_harness({"args": {"entries": [
            {"id": "e1", "prompt_file": "e1.md"}]}})
        self.assertIsNotNone(out["error"])
        self.assertIn("read guard", out["error"])
        self.assertIn("e1", out["error"])

    def test_marker_for_a_different_id_is_rejected(self):
        entry = _entry("e1", marker="panopticon-entry: e2")
        out = self.run_harness({"args": {"entries": [entry]}})
        self.assertIsNotNone(out["error"])
        self.assertIn("read guard", out["error"])
        self.assertIn("e1", out["error"])

    def test_a_marker_whose_id_extends_the_entrys_own_id_is_rejected(self):
        # A guard loosened from `===` to `startsWith` would accept the marker
        # for `e10` on entry `e1`; the `e2` case above shares no prefix and
        # cannot tell the two guards apart.
        entry = _entry("e1", marker="panopticon-entry: e10")
        out = self.run_harness({"args": {"entries": [entry]}})
        self.assertIsNotNone(out["error"])
        self.assertIn("read guard", out["error"])

    def test_a_marker_with_trailing_text_after_the_id_is_rejected(self):
        # Same loosening, other direction: a marker line that continues past
        # the id is not the exact marker the read guard armed.
        entry = _entry("e1", marker="panopticon-entry: e1 extra")
        out = self.run_harness({"args": {"entries": [entry]}})
        self.assertIsNotNone(out["error"])
        self.assertIn("read guard", out["error"])

    def test_the_exact_marker_passes(self):
        out = self.run_harness({"args": {"entries": [_entry("e1")]},
                                "replies": {"e1": "ok"}})
        self.assertIsNone(out["error"])


class TestPromptFileGuard(DispatchScriptTestCase):
    """(c) missing `prompt_file` -> an error."""

    def test_absent_prompt_file_errors(self):
        out = self.run_harness({"args": {"entries": [
            {"id": "e1", "marker": "panopticon-entry: e1"}]}})
        self.assertIsNotNone(out["error"])
        self.assertIn("prompt_file", out["error"])
        self.assertIn("e1", out["error"])

    def test_empty_prompt_file_errors(self):
        out = self.run_harness({"args": {"entries": [
            _entry("e1", prompt_file="")]}})
        self.assertIsNotNone(out["error"])
        self.assertIn("prompt_file", out["error"])


class TestAgentTypeVsModel(DispatchScriptTestCase):
    """(d) enforced + agent -> opts.agentType == agent, NO opts.model.
    enforced without agent -> falls to model. unenforced with agent ->
    opts.model, NO agentType -- the #1720 contract: an unenforced entry
    never names a shell."""

    def test_enforced_with_agent_sets_agent_type_never_model(self):
        entries = [_entry("e1", agent="panopticon-scout", enforced=True,
                          model="opus")]
        out = self.run_harness({"args": {"entries": entries},
                                "replies": {"e1": "ok"}})
        opts = out["calls"][0]["opts"]
        self.assertEqual("panopticon-scout", opts["agentType"])
        self.assertNotIn("model", opts)

    def test_enforced_without_agent_falls_to_model(self):
        entries = [_entry("e1", enforced=True, model="opus")]
        out = self.run_harness({"args": {"entries": entries},
                                "replies": {"e1": "ok"}})
        opts = out["calls"][0]["opts"]
        self.assertEqual("opus", opts["model"])
        self.assertNotIn("agentType", opts)

    def test_unenforced_with_agent_uses_model_never_agent_type(self):
        entries = [_entry("e1", agent="panopticon-scout", enforced=False,
                          model="sonnet")]
        out = self.run_harness({"args": {"entries": entries},
                                "replies": {"e1": "ok"}})
        opts = out["calls"][0]["opts"]
        self.assertEqual("sonnet", opts["model"])
        self.assertNotIn("agentType", opts)

    def test_unenforced_with_agent_and_no_model_names_neither(self):
        entries = [_entry("e1", agent="panopticon-scout", enforced=False)]
        out = self.run_harness({"args": {"entries": entries},
                                "replies": {"e1": "ok"}})
        opts = out["calls"][0]["opts"]
        self.assertNotIn("agentType", opts)
        self.assertNotIn("model", opts)


class TestPromptShape(DispatchScriptTestCase):
    """(e) the prompt's FIRST line is exactly the marker and the second
    names prompt_file."""

    def test_marker_line_first_then_the_pointer_sentence(self):
        entries = [_entry("e7", agent="panopticon-scout", enforced=True)]
        out = self.run_harness({"args": {"entries": entries},
                                "replies": {"e7": "ok"}})
        lines = out["calls"][0]["prompt"].split("\n")
        self.assertEqual("panopticon-entry: e7", lines[0])
        self.assertIn("e7.md", lines[1])


class TestReplyRouting(DispatchScriptTestCase):
    """(f) routing: return_json -> persist {id, text}; self_write/absent
    delivery -> self_wrote with out_file (null when absent) and
    confirmation; a null reply -> missing and in neither list; a thrown
    thunk -> missing."""

    def test_return_json_reply_routes_to_persist(self):
        entries = [_entry("e1", delivery="return_json")]
        out = self.run_harness({"args": {"entries": entries},
                                "replies": {"e1": "the text"}})
        self.assertEqual([{"id": "e1", "text": "the text"}],
                         out["result"]["persist"])
        self.assertEqual([], out["result"]["self_wrote"])
        self.assertEqual([], out["result"]["missing"])

    def test_self_write_delivery_routes_to_self_wrote_with_out_file(self):
        entries = [_entry("e1", delivery="self_write", out_file="e1-out.txt")]
        out = self.run_harness({"args": {"entries": entries},
                                "replies": {"e1": "wrote it"}})
        self.assertEqual([], out["result"]["persist"])
        self.assertEqual(
            [{"id": "e1", "out_file": "e1-out.txt", "confirmation": "wrote it"}],
            out["result"]["self_wrote"])

    def test_absent_delivery_defaults_to_self_write_with_null_out_file(self):
        entries = [_entry("e1")]  # no delivery, no out_file at all
        out = self.run_harness({"args": {"entries": entries},
                                "replies": {"e1": "confirmed"}})
        self.assertEqual([], out["result"]["persist"])
        self.assertEqual(
            [{"id": "e1", "out_file": None, "confirmation": "confirmed"}],
            out["result"]["self_wrote"])

    def test_null_reply_is_missing_and_in_neither_list(self):
        entries = [_entry("e1")]
        out = self.run_harness({"args": {"entries": entries},
                                "replies": {"e1": None}})
        self.assertEqual(["e1"], out["result"]["missing"])
        self.assertEqual([], out["result"]["persist"])
        self.assertEqual([], out["result"]["self_wrote"])

    def test_a_thrown_thunk_is_missing(self):
        entries = [_entry("e1")]
        out = self.run_harness({"args": {"entries": entries},
                                "throws": {"e1": "the subagent died"}})
        self.assertIsNone(out["error"], "the throw is per-entry, inside "
                          "parallel() -- it must not escape as a script error")
        self.assertEqual(["e1"], out["result"]["missing"])
        self.assertEqual([], out["result"]["persist"])
        self.assertEqual([], out["result"]["self_wrote"])


class TestCheckpointEcho(DispatchScriptTestCase):
    """(g) `checkpoint` echoed, `null` when absent."""

    def test_checkpoint_is_echoed(self):
        entries = [_entry("e1")]
        out = self.run_harness({"args": {"checkpoint": "review",
                                        "entries": entries},
                                "replies": {"e1": "ok"}})
        self.assertEqual("review", out["result"]["checkpoint"])

    def test_checkpoint_is_null_when_absent(self):
        entries = [_entry("e1")]
        out = self.run_harness({"args": {"entries": entries},
                                "replies": {"e1": "ok"}})
        self.assertIsNone(out["result"]["checkpoint"])


class TestMetaAndDispatchPhase(DispatchScriptTestCase):
    """(h) meta.name == 'panopticon-dispatch' and meta.phases[0].title ==
    'Dispatch', and every agent call carries phase: 'Dispatch' and label ==
    id."""

    def test_meta_name_and_first_phase_title(self):
        out = self.run_harness({"args": {"entries": [_entry("e1")]},
                                "replies": {"e1": "ok"}})
        self.assertEqual("panopticon-dispatch", out["meta"]["name"])
        self.assertEqual("Dispatch", out["meta"]["phases"][0]["title"])

    def test_every_agent_call_carries_phase_and_label(self):
        entries = [_entry("e1"), _entry("e2"), _entry("e3")]
        out = self.run_harness({
            "args": {"entries": entries},
            "replies": {"e1": "a", "e2": "b", "e3": "c"}})
        self.assertEqual(len(entries), len(out["calls"]))
        for entry, call in zip(entries, out["calls"]):
            self.assertEqual("Dispatch", call["opts"]["phase"])
            self.assertEqual(entry["id"], call["opts"]["label"])


if __name__ == "__main__":
    unittest.main()
