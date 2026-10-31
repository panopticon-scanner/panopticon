"""#3234: the ledger can say WHY. The hook leaves its own reason in a sidecar, `Ledger.record`
joins it to the host's denial row, and nothing in that path can change a decision. A row names
which channel a return-persist reply came through, and a failed self-write keeps its cause."""
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock

import scripts.dispatch as dispatch
import scripts.guard_rules as guard_rules
import scripts.ledger as ledger_mod
import scripts.phases.denials as denials
import scripts.phases.persist as persist
import scripts.read_guard_hook as read_guard_hook
import scripts.runners.base as base
import scripts.runners.claude as claude
import scripts.write_guard_hook as write_guard_hook

SCRIPTS = os.path.dirname(os.path.abspath(guard_rules.__file__))
REPO = os.path.dirname(os.path.dirname(SCRIPTS))
REDACTABLE = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
_NEVER = threading.Event()


class _Run(unittest.TestCase):
    """A review run folder, armed for one entry, and its hooks launched as the hosts launch them."""

    def setUp(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        self.root = os.path.realpath(d)
        self.run_dir = os.path.join(self.root, ".panopticon", "runs", "t")
        os.makedirs(self.run_dir)
        self.sidecar = os.path.join(self.run_dir, guard_rules.DENIALS_FILE)
        self.inside = os.path.join(self.root, "inside.py")
        self.out_file = os.path.join(self.run_dir, "findings-App-SEC.json")
        with open(self.inside, "w", encoding="utf-8") as fh:
            fh.write("x = 1\n")
        self.scope = os.path.join(self.run_dir, "read-scope.json")
        self.allowlist = os.path.join(self.run_dir, "write-allowlist.json")
        self._write(self.scope, {"e1": {"files": [self.inside], "dirs": [], "reads": []}})
        self._write(self.allowlist, {"version": guard_rules.ALLOWLIST_VERSION,
                                     "entries": {"e1": [self.out_file]},
                                     "paths": [self.out_file]})

    @staticmethod
    def _write(path, body):
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(body, fh)

    def _hook(self, name, policy, payload, timeout=60):
        env = {"PATH": os.environ.get("PATH", ""), guard_rules.ENV_ENTRY_ID: "e1"}
        return subprocess.run(["/usr/bin/env", os.path.realpath(sys.executable), "-I",
                               os.path.join(SCRIPTS, name), policy],
                              input=json.dumps(payload), capture_output=True, text=True,
                              cwd=self.root, env=env, timeout=timeout)

    def _read(self, path=None, tool_use_id="t1"):
        return self._hook("read_guard_hook.py", self.scope,
                          {"tool_name": "Read", "tool_use_id": tool_use_id,
                           "tool_input": {"file_path": path or os.path.join(self.root, "other.py")}})

    def _denied_reason(self, proc):
        self.assertEqual(0, proc.returncode, proc.stderr)
        body = json.loads(proc.stdout)["hookSpecificOutput"]
        self.assertEqual("deny", body["permissionDecision"])
        return body["permissionDecisionReason"]

    def _sidecar_rows(self):
        with open(self.sidecar, encoding="utf-8") as fh:
            return [json.loads(line) for line in fh]


class TheHookRecordsItsOwnReasonTest(_Run):
    def test_a_read_denial_leaves_the_reason_it_printed(self):
        reason = self._denied_reason(self._read())
        self.assertEqual([{"tool_use_id": "t1", "tool_name": "Read", "reason": reason}],
                         self._sidecar_rows())

    def test_a_write_denial_leaves_the_reason_it_printed(self):
        reason = self._denied_reason(self._hook(
            "write_guard_hook.py", self.allowlist,
            {"tool_name": "Write", "tool_use_id": "t2",
             "tool_input": {"file_path": os.path.join(self.run_dir, "elsewhere.json")}}))
        self.assertEqual([{"tool_use_id": "t2", "tool_name": "Write", "reason": reason}],
                         self._sidecar_rows())

    def test_an_allowed_call_records_nothing(self):
        proc = self._read(self.inside)
        self.assertEqual(("", 0), (proc.stdout, proc.returncode))
        self.assertFalse(os.path.exists(self.sidecar))

    def test_the_file_is_0600_and_a_reason_is_bounded(self):
        self._read()
        self.assertEqual(0o600, stat.S_IMODE(os.stat(self.sidecar).st_mode))
        guard_rules.record_denial(self.scope, {"tool_use_id": "t3"}, "r" * 5000)
        self.assertEqual(guard_rules.DENIAL_REASON_CAP, len(self._sidecar_rows()[1]["reason"]))

    def test_a_setup_run_records_nothing(self):
        # `setup-scan` holds a directory grant over the whole root, flat `.panopticon/` included.
        flat = os.path.join(self.root, ".panopticon", "read-scope.json")
        guard_rules.record_denial(flat, {"tool_use_id": "t1"}, "r")
        self.assertFalse(os.path.exists(os.path.join(os.path.dirname(flat),
                                                     guard_rules.DENIALS_FILE)))

    def test_only_the_setup_scan_holds_a_directory_grant(self):
        # The premise of the line above and of "no grant reaches the file".
        holders = []
        for folder, _dirs, names in os.walk(SCRIPTS):
            for name in names:
                if name.endswith(".py"):
                    with open(os.path.join(folder, name), encoding="utf-8") as fh:
                        if "scope(dirs=" in fh.read():
                            holders.append(name)
        self.assertEqual(["setup.py"], holders)


class NoChildReachesTheFileTest(_Run):
    def test_a_childs_read_and_grep_of_it_are_denied(self):
        self._read()
        self._denied_reason(self._read(self.sidecar, "t2"))
        self._denied_reason(self._hook("read_guard_hook.py", self.scope,
                                       {"tool_name": "Grep", "tool_use_id": "t3",
                                        "tool_input": {"pattern": "x", "path": self.sidecar}}))

    def test_a_childs_write_and_edit_of_it_are_denied(self):
        for tool in ("Write", "Edit"):
            with self.subTest(tool):
                self._denied_reason(self._hook("write_guard_hook.py", self.allowlist,
                                               {"tool_name": tool, "tool_use_id": "t4",
                                                "tool_input": {"file_path": self.sidecar}}))


class ADiskFaultCannotChangeTheDenyTest(_Run):
    def _assert_still_denies(self):
        proc = self._read()
        self.assertIn("outside your cell's scope", self._denied_reason(proc))
        self.assertEqual("", proc.stderr)     # the fault stays inside the writer

    def test_a_sidecar_that_cannot_be_opened(self):
        os.mkdir(self.sidecar)
        self._assert_still_denies()

    def test_an_unwritable_run_folder(self):
        os.chmod(self.run_dir, 0o500)
        self.addCleanup(os.chmod, self.run_dir, 0o700)
        self._assert_still_denies()
        self.assertFalse(os.path.exists(self.sidecar))

    def test_a_fifo_with_no_reader_neither_blocks_nor_changes_it(self):
        os.mkfifo(self.sidecar)
        self._assert_still_denies()

    def test_a_write_that_never_returns_does_not_hold_the_hook(self):
        with mock.patch.object(guard_rules, "_append_denial", lambda *_a: _NEVER.wait()), \
                mock.patch.object(guard_rules, "_DENIAL_WAIT_SECONDS", 0.01):
            caller = threading.Thread(target=guard_rules.record_denial, daemon=True,
                                      args=(self.scope, {"tool_use_id": "t1"}, "r"))
            caller.start()
            caller.join(30)
        self.assertFalse(caller.is_alive())

    def test_the_decision_is_out_before_the_record_starts(self):
        for hook, policy, payload in (
                (read_guard_hook, self.scope,
                 {"tool_name": "Read", "tool_input": {"file_path": os.path.join(self.root, "o.py")}}),
                (write_guard_hook, self.allowlist,
                 {"tool_name": "Write", "tool_input": {"file_path": os.path.join(self.root, "o")}})):
            with self.subTest(hook.__name__):
                seen = []
                out = io.StringIO()
                with mock.patch.dict(os.environ, {guard_rules.ENV_ENTRY_ID: "e1"}), \
                        mock.patch.object(sys, "stdin", io.StringIO(json.dumps(payload))), \
                        mock.patch.object(sys, "stdout", out), \
                        mock.patch.object(hook, "_trusted_hook_argv"), \
                        mock.patch.object(guard_rules, "record_denial",
                                          side_effect=lambda *_a: seen.append(out.getvalue())):
                    self.assertEqual(0, hook.main([policy]))
                self.assertEqual(1, len(seen))
                self.assertEqual("deny", json.loads(seen[0])["hookSpecificOutput"]["permissionDecision"])

    def test_a_symlink_is_not_followed(self):
        target = os.path.join(self.root, "target.txt")
        with open(target, "w", encoding="utf-8") as fh:
            fh.write("kept\n")
        os.chmod(target, 0o600)               # so the mode check is not what protects it
        os.symlink(target, self.sidecar)
        self._assert_still_denies()
        with open(target, encoding="utf-8") as fh:
            self.assertEqual("kept\n", fh.read())

    def test_a_file_someone_else_could_read_is_not_written(self):
        with open(self.sidecar, "w", encoding="utf-8"):
            pass
        os.chmod(self.sidecar, 0o644)
        self._assert_still_denies()
        self.assertEqual(0, os.path.getsize(self.sidecar))

    def test_the_total_size_is_capped(self):
        with mock.patch.object(guard_rules, "DENIALS_CAP", 1):
            guard_rules.record_denial(self.scope, {"tool_use_id": "t1"}, "first")
            guard_rules.record_denial(self.scope, {"tool_use_id": "t2"}, "second")
        self.assertEqual(["t1"], [r["tool_use_id"] for r in self._sidecar_rows()])


class ParallelLaunchesTest(_Run):
    def test_parallel_appends_do_not_interleave(self):
        program = (
            "import importlib.util, sys\n"
            "spec = importlib.util.spec_from_file_location('g', sys.argv[1])\n"
            "g = importlib.util.module_from_spec(spec); spec.loader.exec_module(g)\n"
            "for n in range(40):\n"
            "    g.record_denial(sys.argv[2], {'tool_use_id': sys.argv[3] + '-%d' % n,\n"
            "                                  'tool_name': 'Grep'}, 'r' * 390)\n")
        procs = [subprocess.Popen(["/usr/bin/env", os.path.realpath(sys.executable), "-I", "-c", program,
                                   os.path.join(SCRIPTS, "guard_rules.py"), self.scope, "p%d" % p])
                 for p in range(6)]
        for proc in procs:
            self.assertEqual(0, proc.wait(timeout=120))
        rows = self._sidecar_rows()          # a torn line would raise here
        self.assertEqual(240, len({r["tool_use_id"] for r in rows}))
        self.assertEqual({"r" * 390}, {r["reason"] for r in rows})



def _result(rows=(), ok=True, text="done", **kw):
    return base.RunResult(entry_id="e1", ok=ok, text=text, usage={}, cost_usd=0.0, model="m",
                          session_id="s", denials=list(rows), error=None if ok else "boom", **kw)


class _LedgerCase(_Run):
    def _row(self, entry=None, result=None, **kw):
        path = os.path.join(self.run_dir, base.LEDGER_FILE)
        if os.path.exists(path):
            os.remove(path)
        ledger_mod.Ledger(self.run_dir).record(entry or {"id": "e1"}, "verify", result or _result(),
                                               "headless", "claude", **kw)
        with open(path, encoding="utf-8") as fh:
            return json.loads(fh.read())

    def _sidecar_lines(self, *rows):
        with open(self.sidecar, "w", encoding="utf-8") as fh:
            for row in rows:
                fh.write((row if isinstance(row, str) else json.dumps(row)) + "\n")


DENIAL = {"tool_name": "Grep", "tool_use_id": "t1", "tool_input": {"pattern": "x", "path": "src"}}


class TheJoinTest(_LedgerCase):
    def test_a_denial_carries_the_hooks_own_reason(self):
        reason = self._denied_reason(self._read())
        row = self._row(result=_result([dict(DENIAL, tool_name="Read")]))
        self.assertEqual(reason, row["denials"][0]["reason"])

    def test_the_reason_is_redacted_and_bounded_at_the_writer(self):
        self._sidecar_lines({"tool_use_id": "t1", "reason": "Read of %s denied" % REDACTABLE},
                            {"tool_use_id": "t2", "reason": "r" * 9000})
        rows = self._row(result=_result([DENIAL, dict(DENIAL, tool_use_id="t2")]))["denials"]
        self.assertNotIn(REDACTABLE, rows[0]["reason"])
        self.assertEqual(guard_rules.DENIAL_REASON_CAP, len(rows[1]["reason"]))

    def test_tool_input_beside_it_stays_as_the_host_wrote_it(self):
        # Stated, not endorsed: the row's `tool_input` is not redacted today, and this change
        # does not move it. Reported to the coordinator.
        denial = dict(DENIAL, tool_input={"pattern": REDACTABLE, "path": "src"})
        self._sidecar_lines({"tool_use_id": "t1", "reason": "r"})
        self.assertEqual(REDACTABLE, self._row(result=_result([denial]))["denials"][0]["tool_input"]["pattern"])

    def test_the_hosts_own_rows_are_not_touched(self):
        self._sidecar_lines({"tool_use_id": "t1", "reason": "r"})
        result = _result([dict(DENIAL)])      # its own dict: a shared one would compare to itself
        self.assertEqual("r", self._row(result=result)["denials"][0]["reason"])
        self.assertEqual([DENIAL], result.denials)

    def test_a_denial_with_no_sidecar_row_has_no_reason_key(self):
        self._sidecar_lines({"tool_use_id": "other", "reason": "r"})
        self.assertEqual([DENIAL], self._row(result=_result([DENIAL]))["denials"])

    def test_no_sidecar_and_no_denials_leave_the_row_as_it_was(self):
        self.assertEqual([DENIAL], self._row(result=_result([DENIAL]))["denials"])
        self.assertEqual([], self._row()["denials"])

    def test_a_row_with_no_tool_use_id_is_written_whole(self):
        # What codex reports: its read broker's failed item, whose own error is on it.
        item = {"type": "mcp_tool_call", "status": "failed", "error": {"message": "denied"}}
        self.assertEqual([item, "text"], self._row(result=_result([item, "text"]))["denials"])

    def test_a_sidecar_that_is_not_a_file_costs_nothing(self):
        for name, make in (("fifo", os.mkfifo), ("directory", os.mkdir)):
            with self.subTest(name):
                make(self.sidecar)
                rows = []
                reader = threading.Thread(target=lambda: rows.append(
                    self._row(result=_result([DENIAL]))["denials"]), daemon=True)
                reader.start()
                reader.join(30)
                self.assertEqual([[DENIAL]], rows)
                (os.rmdir if name == "directory" else os.remove)(self.sidecar)

    def test_a_sidecar_symlink_is_not_read(self):
        target = os.path.join(self.root, "target.jsonl")
        with open(target, "w", encoding="utf-8") as fh:
            fh.write(json.dumps({"tool_use_id": "t1", "reason": "planted"}) + "\n")
        os.symlink(target, self.sidecar)
        self.assertEqual([DENIAL], self._row(result=_result([DENIAL]))["denials"])


class AForgedRowDecidesNothingTest(_LedgerCase):
    def test_it_adds_no_denial_and_moves_no_ok(self):
        self._sidecar_lines({"tool_use_id": "forged", "tool_name": "Write", "reason": "r"},
                            {"tool_use_id": "t1", "reason": "real"})
        row = self._row(result=_result([DENIAL]))
        self.assertEqual(1, len(row["denials"]))
        self.assertEqual("real", row["denials"][0]["reason"])
        self.assertIs(True, row["ok"])
        clean = self._row(result=_result())
        self.assertEqual(([], True), (clean["denials"], clean["ok"]))

    def test_it_cannot_make_a_write_look_denied_to_the_loop(self):
        self._sidecar_lines({"tool_use_id": "t9", "tool_name": "Write",
                             "reason": "write denied"})
        entry = {"id": "e1", "out_file": self.out_file, "delivery": "self_write"}
        result = _result()
        self._row(entry, result)
        self.assertIsNone(denials.every_own_write_denied([(entry, result)]))
        # And the host's own report still stops the batch, whatever the join added to its row.
        denied = _result([{"tool_name": "Write", "tool_use_id": "t9",
                           "tool_input": {"file_path": self.out_file}}])
        self._row(entry, denied)
        self.assertIn("DENIED", denials.every_own_write_denied([(entry, denied)]))

    def test_damaged_lines_are_skipped(self):
        self._sidecar_lines('{"tool_use_id": "t1", "rea', "[1, 2]", "not json",
                            {"tool_use_id": "t1", "reason": 7},
                            {"tool_use_id": "t1", "reason": "the first good one"},
                            {"tool_use_id": "t1", "reason": "a later one"})
        self.assertEqual("the first good one",
                         self._row(result=_result([DENIAL]))["denials"][0]["reason"])


class ReplyChannelTest(_LedgerCase):
    ENVELOPE = {"type": "result", "is_error": False, "session_id": "s", "total_cost_usd": 0.0}

    def _parsed(self, **fields):
        return claude.Runner().parse_envelope("e1", json.dumps(dict(self.ENVELOPE, **fields)), 0)

    def test_the_runner_says_which_channel_answered(self):
        self.assertEqual("structured_output",
                         self._parsed(structured_output={"a": 1}, result="t").reply_via)
        self.assertEqual("result", self._parsed(result="t").reply_via)
        self.assertEqual("result", self._parsed(structured_output={}, result="t").reply_via)

    def test_a_return_persist_row_records_it(self):
        row = self._row({"id": "e1", "delivery": "return_json"},
                        _result(reply_via="structured_output"))
        self.assertEqual("structured_output", row["reply_via"])

    def test_a_refused_reply_keeps_it_because_that_is_the_question(self):
        row = self._row({"id": "e1", "delivery": "return_json"}, _result(reply_via="result"),
                        refusal="persist refused: finding_id_note")
        self.assertEqual(("result", False), (row["reply_via"], row["ok"]))

    def test_a_self_writing_row_does_not(self):
        self.assertNotIn("reply_via", self._row({"id": "e1"}, _result(reply_via="result")))


class SelfWriteCauseTest(_LedgerCase):
    def _entry(self, **kw):
        return dict({"id": "e1", "out_file": self.out_file, "delivery": "self_write"}, **kw)

    def test_a_failed_self_write_keeps_its_cause_and_stays_ok(self):
        row = self._row(self._entry(), _result(text="write permission hasn't been granted"))
        self.assertEqual("write permission hasn't been granted", row["result_head"])
        self.assertIs(True, row["ok"])

    def test_it_is_redacted_and_bounded_like_stderr(self):
        head = self._row(self._entry(), _result(text=REDACTABLE + " " + "x" * 900))["result_head"]
        self.assertNotIn(REDACTABLE, head)
        self.assertEqual(base.STDERR_HEAD, len(head))

    def test_a_good_artifact_keeps_no_head(self):
        with mock.patch.object(persist, "is_done", return_value=True):
            self.assertNotIn("result_head", self._row(self._entry()))

    def test_a_return_persist_entry_keeps_no_head(self):
        self.assertNotIn("result_head", self._row(self._entry(delivery="return_json")))

    def test_a_failed_launch_keeps_stderr_not_a_head(self):
        row = self._row(self._entry(), _result(ok=False, text="partial", stderr="boom"))
        self.assertNotIn("result_head", row)
        self.assertEqual("boom", row["stderr"])

    def test_a_predicate_that_raises_does_not_cost_the_row(self):
        with mock.patch.object(persist, "is_done", side_effect=RuntimeError("x")):
            self.assertNotIn("result_head", self._row(self._entry()))


class NothingDecidesFromThisTest(unittest.TestCase):
    def test_only_the_ledger_and_the_hooks_rule_file_name_these(self):
        names = ("DENIALS_FILE", "guard-denials", "result_head", "reply_via")
        found = set()
        for folder, _dirs, files in os.walk(SCRIPTS):
            for name in files:
                if name.endswith(".py"):
                    with open(os.path.join(folder, name), encoding="utf-8") as fh:
                        text = fh.read()
                    if any(n in text for n in names):
                        found.add(os.path.relpath(os.path.join(folder, name), SCRIPTS))
        self.assertEqual({"guard_rules.py", "ledger.py", "runners/base.py", "runners/claude.py"},
                         found)


class PromptsTest(unittest.TestCase):
    CONFINED = ("advisor.md", "domain-advisor.md", "domain-panel.md", "scout.md")

    def _body(self, role):
        return dispatch.load_template(role)[1]

    def test_every_confined_role_says_a_directory_search_is_denied(self):
        for role in self.CONFINED:
            with self.subTest(role):
                body = self._body(role)
                self.assertIn("grep a file by its path", body)
                self.assertIn("a directory search is denied", body)

    def test_the_advisors_and_the_scout_say_the_grant_is_a_file_list(self):
        for role in ("advisor.md", "domain-advisor.md", "scout.md"):
            with self.subTest(role):
                self.assertIn("Your grant is a list of files, not directories", self._body(role))

    def test_the_rendered_scout_never_offers_glob(self):
        # The frontmatter's `allowed:` drives tool registration and is not part of the body.
        body = self._body("scout.md")
        self.assertNotIn("allowed:", body)
        self.assertEqual(1, body.count("Glob"))
        self.assertIn("Glob is not available in a confined cell", body)

    def test_setup_scan_is_left_alone_because_its_grant_is_the_root(self):
        self.assertNotIn("a directory search is denied", self._body("setup-scan.md"))


if __name__ == "__main__":
    unittest.main()
