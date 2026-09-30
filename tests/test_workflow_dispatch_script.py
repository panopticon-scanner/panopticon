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

from tests._test_helpers import REPO_ROOT
from tests._test_helpers import skip_or_fail

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
        """The harness's `{meta, calls, result, error, logs}` document for
        `scenario` run against `script` (default: the real dispatch.js).
        `logs` is every `log()` line the script printed, in order."""
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
    enforced WITHOUT an agent -> refused, nothing dispatched (#1783,
    ARC-204863095). unenforced WITH an agent -> refused too, nothing
    dispatched (#2166): the mirror half of the same statement, since the
    #1720 contract is that an unenforced entry never names a shell -- the
    phases set `agent` to None on those. unenforced with no agent (or an
    empty one) -> opts.model, NO agentType."""

    def test_enforced_with_agent_sets_agent_type_never_model(self):
        entries = [_entry("e1", agent="panopticon-scout", enforced=True,
                          model="opus")]
        out = self.run_harness({"args": {"entries": entries},
                                "replies": {"e1": "ok"}})
        opts = out["calls"][0]["opts"]
        self.assertEqual("panopticon-scout", opts["agentType"])
        self.assertNotIn("model", opts)

    def test_enforced_without_agent_is_refused_and_dispatches_nothing(self):
        # ARC-204863095 (#1783): the entry claims the enforced posture the
        # run's own accounting reads, so running it on the unenforced branch
        # would launch it with no registered shell, no host-enforced tool
        # grant and no log line saying so. The refusal is the validation
        # loop's, so nothing is dispatched.
        entries = [_entry("e1", enforced=True, model="opus")]
        out = self.run_harness({"args": {"entries": entries},
                                "replies": {"e1": "ok"}})
        self.assertIsNotNone(out["error"])
        self.assertIn("e1", out["error"])
        self.assertIn("marked enforced", out["error"])
        self.assertEqual([], out["calls"], "no agent should be dispatched")

    def test_an_empty_agent_string_on_an_enforced_entry_is_refused_too(self):
        # `agent: ""` is falsy, so the enforced branch read it exactly as an
        # absent name; the refusal has to read it the same way.
        entries = [_entry("e1", agent="", enforced=True, model="opus")]
        out = self.run_harness({"args": {"entries": entries},
                                "replies": {"e1": "ok"}})
        self.assertIsNotNone(out["error"])
        self.assertIn("e1", out["error"])
        self.assertEqual([], out["calls"], "no agent should be dispatched")

    def test_a_bad_second_entry_refuses_before_the_first_is_dispatched(self):
        # Validation precedes dispatch: a request-integrity refusal must not
        # launch (and charge) the entries that happen to sort before the bad
        # one -- a partly-dispatched batch is exactly what it refuses.
        entries = [_entry("e1", agent="panopticon-scout", enforced=True),
                   _entry("e2", enforced=True, model="opus")]
        out = self.run_harness({"args": {"entries": entries},
                                "replies": {"e1": "ok", "e2": "ok"}})
        self.assertIsNotNone(out["error"])
        self.assertIn("e2", out["error"])
        self.assertEqual([], out["calls"], "e1 must not be dispatched either")

    def test_unenforced_with_agent_is_refused_and_dispatches_nothing(self):
        # #2166: the mirror of the refusal above, and the half B7 left out.
        # The phases set `agent` to None on every unenforced entry, so a shell
        # name on one is a claim this run never made; it used to fall to the
        # `e.model` branch and run there with no refusal and no log line.
        entries = [_entry("e1", agent="panopticon-scout", enforced=False,
                          model="sonnet")]
        out = self.run_harness({"args": {"entries": entries},
                                "replies": {"e1": "ok"}})
        self.assertIsNotNone(out["error"])
        self.assertIn("e1", out["error"])
        self.assertIn("unenforced", out["error"])
        self.assertIn("panopticon-scout", out["error"])
        self.assertEqual([], out["calls"], "no agent should be dispatched")

    def test_an_unenforced_second_entry_naming_a_shell_refuses_before_the_first_is_dispatched(self):
        # The mirror of the two-entry case above: validation precedes dispatch
        # for this refusal too, so the good enforced entry sorted ahead of the
        # bad one is never launched, and never charged.
        entries = [_entry("e1", agent="panopticon-scout", enforced=True),
                   _entry("e2", enforced=False, model="opus",
                          agent="panopticon-domain-panel")]
        out = self.run_harness({"args": {"entries": entries},
                                "replies": {"e1": "ok", "e2": "ok"}})
        self.assertIsNotNone(out["error"])
        self.assertIn("e2", out["error"])
        self.assertEqual([], out["calls"], "e1 must not be dispatched either")

    def test_an_empty_agent_string_on_an_unenforced_entry_is_not_a_shell(self):
        # Mirror of the enforced empty-string case: `agent: ""` is falsy, and
        # the dispatch branch has always read it as an absent name, so the
        # refusal reads it the same way -- `""` is absent on both sides.
        entries = [_entry("e1", agent="", enforced=False, model="sonnet")]
        out = self.run_harness({"args": {"entries": entries},
                                "replies": {"e1": "ok"}})
        self.assertIsNone(out["error"])
        opts = out["calls"][0]["opts"]
        self.assertEqual("sonnet", opts["model"])
        self.assertNotIn("agentType", opts)

    def test_unenforced_without_agent_and_no_model_names_neither(self):
        entries = [_entry("e1", enforced=False)]
        out = self.run_harness({"args": {"entries": entries},
                                "replies": {"e1": "ok"}})
        opts = out["calls"][0]["opts"]
        self.assertNotIn("agentType", opts)
        self.assertNotIn("model", opts)


class TestRefusalsEscapeTheId(DispatchScriptTestCase):
    """(d2) #2166: every validation refusal that prints an id prints it
    through `JSON.stringify`, the JS register of the `%r` that
    `loop_batch.misroute_refusal` uses for the same value. The id is read out
    of the dispatch request, a file inside the reviewed tree, and the refusal
    reaches the operator's terminal -- so a control character, an ANSI escape
    or an embedded newline in it has to arrive as its escape sequence rather
    than as bytes the terminal acts on.

    #2379 decides that register ONCE rather than per line, and extends it to
    the three request-sourced strings the script prints on the paths that run
    AFTER validation passes: the checkpoint in the opening `log()`, the
    progress label the Workflow tool renders, and each id in the closing
    `missing` `log()`. Validation constrains the marker's agreement with the
    id, never the id's bytes, so a valid entry can still carry both. Those
    three go through the script's `shown()`, which escapes only a string
    OUTSIDE the safe charset -- so every id the driver can mint still reads
    as it is typed, and the two halves are pinned separately below. What the
    RESULT document returns stays raw on purpose: those are data the session
    keys on, not terminal text."""

    ESC = "\x1b"
    # `ESC [ 2 K` erases the operator's current line; the newline then forges
    # a second line of output underneath the refusal.
    HOSTILE_ID = "e1" + ESC + "[2K\nfake"
    # The same two bytes in `args.checkpoint`, the other request-sourced value
    # the opening log line prints.
    HOSTILE_CHECKPOINT = "review" + ESC + "[2K\nfake"
    # What JSON.stringify renders those two as -- checked in node, not guessed.
    ESCAPED_ESC = "\\u001b[2K"
    ESCAPED_NEWLINE = "\\n"

    def _refusals(self):
        """One entry per validation refusal that prints an id, each carrying
        HOSTILE_ID and each shaped so that ITS refusal is the one that fires
        (a matching marker wherever the marker is not the point)."""
        return {
            "marker": {"id": self.HOSTILE_ID, "prompt_file": "e1.md"},
            "prompt_file": _entry(self.HOSTILE_ID, prompt_file=""),
            "enforced_without_shell": _entry(self.HOSTILE_ID, enforced=True,
                                             model="opus"),
            "unenforced_with_shell": _entry(self.HOSTILE_ID, enforced=False,
                                            model="opus",
                                            agent="panopticon-domain-panel"),
        }

    def test_the_hostile_id_really_carries_the_raw_bytes(self):
        # Guards the fixture, not the code: without it the assertions in the
        # next test could pass on data that never held an escape or a newline.
        self.assertIn(self.ESC, self.HOSTILE_ID)
        self.assertIn("\n", self.HOSTILE_ID)
        self.assertIn(self.ESC, self.HOSTILE_CHECKPOINT)
        self.assertIn("\n", self.HOSTILE_CHECKPOINT)

    def test_every_refusal_that_prints_an_id_escapes_it(self):
        for name, entry in self._refusals().items():
            with self.subTest(refusal=name):
                out = self.run_harness({"args": {"entries": [entry]},
                                        "replies": {self.HOSTILE_ID: "ok"}})
                self.assertIsNotNone(out["error"], "this shape must be refused")
                self.assertIn(self.ESCAPED_ESC, out["error"])
                self.assertIn(self.ESCAPED_NEWLINE, out["error"])
                self.assertNotIn(
                    self.ESC, out["error"],
                    "a raw ESC byte reached the operator's terminal")
                self.assertNotIn(
                    "\n", out["error"],
                    "a raw newline reached the operator's terminal")
                self.assertEqual([], out["calls"],
                                 "no agent should be dispatched")

    def test_the_label_escapes_the_id(self):
        # #2379, post-validation: this entry is VALID (its marker agrees with
        # its id), so no refusal fires and the id travels on into the progress
        # label the Workflow tool renders.
        out = self.run_harness({"args": {"entries": [_entry(self.HOSTILE_ID)]},
                                "replies": {self.HOSTILE_ID: "ok"}})
        self.assertIsNone(out["error"], "a matching marker passes validation")
        label = out["calls"][0]["opts"]["label"]
        self.assertIn(self.ESCAPED_ESC, label)
        self.assertIn(self.ESCAPED_NEWLINE, label)
        self.assertNotIn(self.ESC, label,
                         "a raw ESC byte reached the operator's terminal")
        self.assertNotIn("\n", label,
                         "a raw newline reached the operator's terminal")
        # The reply still ROUTES: the harness keys its scenario on the
        # prompt's marker -- the binding the read guard uses -- and not on the
        # label, so escaping the label cannot misfile a hostile id's findings.
        self.assertEqual([{"id": self.HOSTILE_ID, "out_file": None,
                           "confirmation": "ok"}], out["result"]["self_wrote"])
        self.assertEqual([], out["result"]["missing"])

    def test_a_safe_id_and_checkpoint_are_printed_as_they_stand(self):
        # The other half of the narrowed register (#2379): `shown()` escapes
        # only a string outside the safe charset, so every id the driver can
        # mint -- and the `'?'` an absent checkpoint falls back to -- reaches
        # the progress tree and the log line unquoted, exactly as before.
        out = self.run_harness({"args": {"checkpoint": "review",
                                         "entries": [_entry("review-app-SEC")]},
                                "replies": {"review-app-SEC": "ok"}})
        self.assertIsNone(out["error"])
        self.assertEqual("review-app-SEC", out["calls"][0]["opts"]["label"])
        self.assertIn(" at checkpoint review", out["logs"][0])
        self.assertNotIn('"', out["logs"][0])
        absent = self.run_harness({"args": {"entries": [_entry("e1")]},
                                   "replies": {"e1": "ok"}})
        self.assertTrue(absent["logs"][0].endswith(" at checkpoint ?"),
                        absent["logs"][0])

    def test_the_checkpoint_log_line_escapes_the_checkpoint(self):
        # #2379: `args.checkpoint` is request-sourced too, and the opening
        # log line is the first thing the operator sees.
        out = self.run_harness({"args": {"checkpoint": self.HOSTILE_CHECKPOINT,
                                         "entries": [_entry("e1")]},
                                "replies": {"e1": "ok"}})
        self.assertIsNone(out["error"])
        opening = out["logs"][0]
        self.assertIn(self.ESCAPED_ESC, opening)
        self.assertIn(self.ESCAPED_NEWLINE, opening)
        self.assertNotIn(self.ESC, opening,
                         "a raw ESC byte reached the operator's terminal")
        self.assertNotIn("\n", opening,
                         "a raw newline reached the operator's terminal")
        # The result still ECHOES the raw checkpoint: that is data the session
        # reads back, not text on its way to a terminal.
        self.assertEqual(self.HOSTILE_CHECKPOINT, out["result"]["checkpoint"])

    def test_the_missing_log_line_escapes_the_ids(self):
        # #2379: a null reply lands the entry in `missing`, and the closing log
        # line names every one of them.
        out = self.run_harness({"args": {"entries": [_entry(self.HOSTILE_ID)]},
                                "replies": {self.HOSTILE_ID: None}})
        self.assertIsNone(out["error"])
        closing = out["logs"][-1]
        self.assertIn("returned nothing", closing)
        self.assertIn(self.ESCAPED_ESC, closing)
        self.assertIn(self.ESCAPED_NEWLINE, closing)
        self.assertNotIn(self.ESC, closing,
                         "a raw ESC byte reached the operator's terminal")
        self.assertNotIn("\n", closing,
                         "a raw newline reached the operator's terminal")
        # `missing` itself stays RAW: the loop keys its pending set on those
        # ids, so escaping them there would be a different id.
        self.assertEqual([self.HOSTILE_ID], out["result"]["missing"])


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
    id. #2379 escapes the label only for an id OUTSIDE the safe charset, and
    no id the driver can mint is -- see `TestRefusalsEscapeTheId` for both
    halves."""

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
