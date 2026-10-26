"""#3273 cut 11: the guard hooks share `guard_rules.py`, loaded by path.

The three hooks used to carry copies of these rules, pinned AST-identical
class by class. Now one module holds them, and what is pinned here is the
LOADING: the stanza that finds the module is the same bytes in every hook, a
module that fails to load in any way denies rather than crashing (a crashed
hook is fail-OPEN), and a hook launched the way the hosts launch it --
``<python> -I <abs path>`` -- takes ours and never a planted decoy.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import scripts.codex_read_tools as codex_read_tools
import scripts.guard_rules as guard_rules
import scripts.kimi_guard_hook as kg
import scripts.read_guard_hook as rg
import scripts.write_guard_hook as wg

SCRIPTS = os.path.dirname(os.path.realpath(guard_rules.__file__))
HOOKS = ("read_guard_hook.py", "write_guard_hook.py", "kimi_guard_hook.py")


def _source(name):
    with open(os.path.join(SCRIPTS, name), encoding="utf-8") as fh:
        return fh.read()


def _stanza(source):
    begin = source.index(guard_rules.LOADER_BEGIN)
    end = source.index(guard_rules.LOADER_END, begin) + len(guard_rules.LOADER_END)
    return source[begin:end]


def _definition(source, name):
    """The exact source text of top-level `name` (a def or an assignment)."""
    import ast
    lines = source.splitlines(keepends=True)
    for node in ast.parse(source).body:
        named = getattr(node, "name", None) or (
            node.targets[0].id if isinstance(node, ast.Assign)
            and isinstance(node.targets[0], ast.Name) else None)
        if named == name:
            return "".join(lines[node.lineno - 1:node.end_lineno])
    raise AssertionError("%s defines no %s" % (name, name))


class TestTheVendoredBytes(unittest.TestCase):
    def test_every_vendored_copy_is_byte_identical(self):
        """The ONE byte-equality pin for what cannot be shared.

        The loader stanza is what finds guard_rules.py, so each hook carries
        it; the Codex broker keeps its copy of the 24 lines it shares (see
        guard_rules' docstring for why it does not path-load). Docstrings and
        comments included: byte-identical means a reader standing in any of
        them reads the same thing.
        """
        stanzas = {name: _stanza(_source(name)) for name in HOOKS}
        self.assertEqual(len(set(stanzas.values())), 1,
                         "the loader stanza has drifted between %s" % ", ".join(HOOKS))
        shared, broker = _source("guard_rules.py"), _source("codex_read_tools.py")
        for name in ("SCOPE_KEYS", "_under", "_in_dir_grant"):
            with self.subTest(broker_copy=name):
                self.assertEqual(_definition(broker, name), _definition(shared, name),
                                 "codex_read_tools.%s has drifted from guard_rules'" % name)


class TestTheSharedRules(unittest.TestCase):
    def test_a_root_directory_grant_admits_only_the_root(self):
        # The root edge is what `directory.rstrip(os.sep) or os.sep` is for:
        # without the `or`, `directory` is "" and every absolute path starts
        # with os.sep, so a `/` grant admits the whole filesystem. The broker
        # once lacked the `or`; a copy that answers a grant differently is a
        # confinement hole, not a nit.
        for under in (guard_rules._under, codex_read_tools._under):
            with self.subTest(copy=under.__module__):
                self.assertTrue(under(os.sep, os.sep))
                self.assertFalse(under("/etc/passwd", os.sep))
                self.assertTrue(under("/repo", "/repo"))
                self.assertTrue(under("/repo/x", "/repo"))
                self.assertFalse(under("/repo-other/x", "/repo"))

    def test_every_component_refusal_names_what_it_refuses(self):
        # Fix round 2 (N1): all four carry a `%s`. `allowlist_from_plan`
        # re-raises these with no context of its own, so the constant is the
        # only place the offending path can come from.
        for name in ("SYMLINKED_COMPONENT", "UNMEASURABLE_COMPONENT",
                     "ESCAPED_ARTIFACT_TREE", "PARENT_COMPONENT"):
            with self.subTest(constant=name):
                self.assertIn("%s", getattr(guard_rules, name))

    def test_the_in_package_import_is_the_module_the_probes_patch(self):
        # #3273 cut 11, condition 2: under our package each hook takes the
        # SIBLING module, so a patch on `scripts.guard_rules` is the one the hook
        # calls through. A second, path-loaded copy here would make every such
        # patch vacuous.
        for hook in (rg, wg, kg):
            with self.subTest(hook=hook.__name__):
                self.assertIs(hook.guard_rules, guard_rules)
                self.assertEqual(hook._GUARD_RULES_FAULT, "")
        with mock.patch.object(guard_rules, "bind", return_value="patched") as fake:
            self.assertEqual(rg.guard_rules.bind("a", "t"), "patched")
        fake.assert_called_once_with("a", "t")

    def test_the_hooks_re_export_the_shared_constants(self):
        for hook, names in ((rg, ("ENV_ENTRY_ID", "MARKER_PREFIX", "SCOPE_KEYS")),
                            (wg, ("ENV_ENTRY_ID", "UNBOUND_ENTRY", "ALLOWLIST_VERSION")),
                            (kg, ("ENV_ENTRY_ID", "UNBOUND_ENTRY", "SCOPE_KEYS"))):
            for name in names:
                with self.subTest(hook=hook.__name__, name=name):
                    self.assertIs(getattr(hook, name), getattr(guard_rules, name))


class TestAnUnloadedRuleSetDeniesInProcess(unittest.TestCase):
    """The adjudication contract with the module missing: deny, first."""

    CASES = (
        (rg, lambda: rg.adjudicate({"tool_name": "Read", "tool_input": {}}, "/nowhere")),
        (wg, lambda: wg.adjudicate({"tool_name": "Write", "tool_input": {}}, "/nowhere")),
        (kg, lambda: kg.adjudicate({"tool_name": "Read", "tool_input": {}}, "read", "/nowhere")),
    )

    def test_every_adjudication_denies_and_names_the_fault(self):
        for hook, call in self.CASES:
            with self.subTest(hook=hook.__name__), \
                    mock.patch.object(hook, "guard_rules", None), \
                    mock.patch.object(hook, "_GUARD_RULES_FAULT", "planted fault"):
                allow, reason = call()
                self.assertFalse(allow)
                self.assertIn("planted fault", reason)


class _HookLaunch(unittest.TestCase):
    """Launch a hook exactly as the hosts do: `<python> -I <abs path> ...`."""

    def setUp(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        self.root = os.path.realpath(d)
        self.inside = os.path.join(self.root, "inside.txt")
        self.outside = os.path.join(self.root, "outside.txt")
        for path in (self.inside, self.outside):
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("x")
        self.scope = os.path.join(self.root, "read-scope.json")
        with open(self.scope, "w", encoding="utf-8") as fh:
            json.dump({"e1": {"files": [self.inside], "dirs": [], "reads": []}}, fh)
        self.allowlist = os.path.join(self.root, "write-allowlist.json")
        with open(self.allowlist, "w", encoding="utf-8") as fh:
            json.dump({"version": 2, "entries": {"e1": [self.inside]}, "paths": [self.inside]}, fh)

    def _calls(self):
        """(hook file, argv after it, a payload the real rules DENY)."""
        return (
            ("read_guard_hook.py", [self.scope],
             {"tool_name": "Read", "tool_input": {"file_path": self.outside}}),
            ("write_guard_hook.py", [self.allowlist],
             {"tool_name": "Write", "tool_input": {"file_path": self.outside}}),
            ("kimi_guard_hook.py", ["read", self.scope],
             {"tool_name": "Read", "tool_input": {"path": self.outside}}),
        )

    def _launch(self, python, hook_path, argv, payload, cwd, extra_env=None):
        env = {"PATH": os.environ.get("PATH", ""), "PANOPTICON_ENTRY_ID": "e1"}
        env.update(extra_env or {})
        proc = subprocess.run([python, "-I", hook_path, *argv], input=json.dumps(payload),
                              capture_output=True, text=True, cwd=cwd, env=env, timeout=60)
        return proc

    def _assert_denied(self, proc, fragment=None):
        self.assertEqual(proc.returncode, 0, proc.stderr)
        body = json.loads(proc.stdout)["hookSpecificOutput"]
        self.assertEqual(body["permissionDecision"], "deny")
        if fragment:
            self.assertIn(fragment, body["permissionDecisionReason"])
        return body["permissionDecisionReason"]


class TestABrokenRuleSetDeniesAtLaunch(_HookLaunch):
    """Condition 1: ANY load failure -- not just ImportError -- denies, exit 0.

    Each hook is copied beside a broken guard_rules.py (the loader resolves
    its sibling from its own real directory) and launched `-I`. The payload
    is one the real rules deny too, so what is checked is the REASON: the
    load fault, named, rather than a decision the broken module made.
    """

    BROKEN = {
        "missing": None,
        "raises": "raise RuntimeError('planted: a raise in top-level code')\n",
        "syntax": "def broken(:\n",
        "lacks a name": "ENV_ENTRY_ID = 'PANOPTICON_ENTRY_ID'\n",
    }

    def test_every_failure_kind_denies_in_every_hook(self):
        python = os.path.realpath(sys.executable)
        for hook, argv, payload in self._calls():
            for kind, text in self.BROKEN.items():
                with self.subTest(hook=hook, kind=kind):
                    where = tempfile.mkdtemp(dir=self.root)
                    shutil.copy(os.path.join(SCRIPTS, hook), where)
                    if text is not None:
                        with open(os.path.join(where, "guard_rules.py"), "w",
                                  encoding="utf-8") as fh:
                            fh.write(text)
                    proc = self._launch(python, os.path.join(where, hook), argv, payload,
                                        cwd=self.root)
                    self._assert_denied(proc, "the shared guard rules could not load")

    def test_the_real_rule_set_loads_and_allows_a_granted_read(self):
        # The control: the same launch with the real module beside the hook
        # ALLOWS the granted path, so the denials above are the fault's.
        python = os.path.realpath(sys.executable)
        for hook, argv, payload in self._calls():
            granted = json.loads(json.dumps(payload).replace(self.outside, self.inside))
            with self.subTest(hook=hook):
                proc = self._launch(python, os.path.join(SCRIPTS, hook), argv, granted,
                                    cwd=self.root)
                self.assertEqual((proc.returncode, proc.stdout), (0, ""), proc.stderr)


class TestADecoyNeverAnswersForOurRules(_HookLaunch):
    """A `guard_rules` or `scripts` planted where a careless loader would look.

    Under `-I` sys.path is the stdlib plus the interpreter's site-packages, so
    the decoys go in all the places someone might expect: the cwd, PYTHONPATH
    (which `-I` ignores) and the site-packages of a throwaway venv whose
    interpreter launches the hook. Each decoy is the REAL module plus one side
    effect -- it writes a marker when imported -- so a hook that loaded it
    would still decide correctly and only the marker tells. A loader that
    tried `import scripts.guard_rules` first would take the site-packages one.
    """

    @classmethod
    def setUpClass(cls):
        cls.venv = tempfile.mkdtemp()
        subprocess.run([sys.executable, "-m", "venv", "--without-pip", cls.venv],
                       check=True, capture_output=True, timeout=120)
        cls.python = os.path.join(cls.venv, "bin", "python")
        cls.site = subprocess.run(
            [cls.python, "-I", "-c", "import sysconfig; print(sysconfig.get_paths()['purelib'])"],
            check=True, capture_output=True, text=True, timeout=60).stdout.strip()

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.venv, ignore_errors=True)

    def _plant(self, directory, marker):
        decoy = _source("guard_rules.py") + (
            "\nwith open(%r, 'a', encoding='utf-8') as _fh:\n    _fh.write(__file__ + '\\n')\n"
            % marker)
        os.makedirs(os.path.join(directory, "scripts"), exist_ok=True)
        for path in (os.path.join(directory, "guard_rules.py"),
                     os.path.join(directory, "scripts", "guard_rules.py")):
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(decoy)
        with open(os.path.join(directory, "scripts", "__init__.py"), "w",
                  encoding="utf-8") as fh:
            fh.write("")

    def test_no_planted_decoy_is_ever_imported(self):
        marker = os.path.join(self.root, "decoy-imported.txt")
        pythonpath = os.path.join(self.root, "pythonpath")
        os.makedirs(pythonpath)
        for directory in (self.root, pythonpath, self.site):
            self._plant(directory, marker)
        self.addCleanup(shutil.rmtree, os.path.join(self.site, "scripts"), True)
        self.addCleanup(os.remove, os.path.join(self.site, "guard_rules.py"))
        # The positive control: the venv's interpreter DOES import the
        # site-packages decoy when asked to, so its absence below is the
        # loader's doing, not a decoy nothing could reach.
        subprocess.run([self.python, "-I", "-c", "import scripts.guard_rules"], check=True,
                       capture_output=True, cwd=self.root, timeout=60)
        with open(marker, encoding="utf-8") as fh:
            self.assertIn(os.path.join(self.site, "scripts", "guard_rules.py"), fh.read())
        os.remove(marker)
        for hook, argv, payload in self._calls():
            with self.subTest(hook=hook):
                proc = self._launch(self.python, os.path.join(SCRIPTS, hook), argv, payload,
                                    cwd=self.root, extra_env={"PYTHONPATH": pythonpath})
                self._assert_denied(proc, "outside.txt")
                self.assertFalse(os.path.exists(marker),
                                 "%s imported a planted guard_rules" % hook)


if __name__ == "__main__":
    unittest.main()
