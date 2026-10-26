"""#3294: no host is ever handed a tool that runs a command.

`procgroup.kill_group` cannot reach a descendant that calls `setsid()` or
`setpgid()`: it has left the group the kill signals, and `test_procgroup.py`'s
`TestTheEscapeIsADocumentedLimit` pins that it survives. What keeps the
REVIEWED TREE from being that descendant is this file. No role grants an
exec-capable tool on any host, the unenforced paths deny them as well, and
Codex runs with its shell features off. So the only thing that can escape the
kill today is a vendor CLI's own helper process.

A grant that turns one of these on re-opens the gap for every target, so each
failure says what has to land with it.
"""
import unittest

from scripts import codex_host, codex_read_tools, dispatch
from scripts.runners import claude, kimi_home

REOPENS = ("granting exec re-opens #3294: implement the PANOPTICON_LAUNCH token "
           "sweep (design in #3294) before landing this grant")

# Claude's code-execution tools (`runners/claude.py` files them under "code
# execution"), and the subagent spawners that would hand one on.
CLAUDE_EXEC = ("Bash", "BashOutput", "KillShell", "PowerShell", "REPL",
               "Workflow", "Agent", "Task")
# Kimi 0.42's shell, its subagent spawners, and the scheduler that would run
# work after the entry ends.
KIMI_EXEC = ("Bash", "Agent", "AgentSwarm", "CronCreate")
CODEX_EXEC_FEATURES = ("shell_tool", "unified_exec", "shell_snapshot")


class TestNoRoleGrantsExec(unittest.TestCase):

    def test_no_role_template_grants_an_exec_tool(self):
        # Per role, the setup scan included: `allowed_tool_union` is derived
        # from these, and it is what Kimi's deny-list and Claude's unenforced
        # `--tools` allow-list both read.
        exec_tools = set(CLAUDE_EXEC) | set(KIMI_EXEC)
        self.assertIn("setup_scan", dispatch.ROLE_FILES)
        for role, role_file in dispatch.ROLE_FILES.items():
            with self.subTest(role=role):
                meta, _body = dispatch.load_template(role_file)
                granted = set(meta["tool_policy"]["allowed"] or [])
                self.assertFalse(granted & exec_tools, REOPENS)
        self.assertFalse(dispatch.allowed_tool_union() & exec_tools, REOPENS)


class TestEveryHostDeniesExec(unittest.TestCase):

    def test_claude_denies_exec_on_an_unenforced_launch(self):
        self.assertLessEqual(set(CLAUDE_EXEC), set(claude.UNENFORCED_DENIED_TOOLS),
                             REOPENS)

    def test_kimi_disables_exec_in_every_childs_config(self):
        # `build_merged_config` is the per-run config EVERY Kimi child gets,
        # enforced entry or setup scan, whatever the operator's config said.
        disabled = set(kimi_home.build_merged_config(
            {"tools": {"disabled": []}}, "scope.json", "allow.json")["tools"]["disabled"])
        for version, vocabulary in kimi_home.TOOL_VOCABULARY.items():
            with self.subTest(version=version):
                self.assertLessEqual(set(KIMI_EXEC) & vocabulary, disabled, REOPENS)
                self.assertIn("Bash", vocabulary, "Kimi renamed its shell tool; "
                              "update KIMI_EXEC before trusting this pin")

    def test_codex_runs_with_its_shell_features_off(self):
        config = codex_host.safety_config()
        for feature in CODEX_EXEC_FEATURES:
            with self.subTest(feature=feature):
                self.assertIn(feature, codex_host._POLICY_FEATURES, REOPENS)
                self.assertIs(config["features"][feature], False, REOPENS)
        self.assertEqual(config["sandbox_mode"], "read-only", REOPENS)
        # Its one MCP server is ours, and it only reads.
        self.assertEqual({tool["name"] for tool in codex_read_tools.TOOLS},
                         {"read_file", "search", "list_files"}, REOPENS)


if __name__ == "__main__":
    unittest.main()
