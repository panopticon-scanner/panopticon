"""#3273 cut 11: the guard hooks share `guard_rules.py`, loaded by path.

The three hooks used to carry copies of these rules, pinned AST-identical
class by class. Now one module holds them, and what is pinned here is the
LOADING: the stanza that finds the module is the same bytes in every hook, a
module that fails to load in any way denies rather than crashing (a crashed
hook is fail-OPEN), and a hook launched the way the hosts launch it --
``<python> -I <abs path>`` -- takes ours and never a planted decoy.
"""
import ast
import contextlib
import errno
import inspect
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import unicodedata
from unittest import mock

import scripts.agy_guard_hook as ag
import scripts.codex_host as codex_host
import scripts.codex_read_tools as codex_read_tools
import scripts.dispatch as dispatch
import scripts.gemini_guard_hook as gg
import scripts.guard_rules as guard_rules
import scripts.kimi_guard_hook as kg
import scripts.read_guard_hook as rg
import scripts.runners.claude as runners_claude
import scripts.runners.kimi_home as kimi_home
import scripts.write_guard_hook as wg

SCRIPTS = os.path.dirname(os.path.realpath(guard_rules.__file__))
HOOKS = ("read_guard_hook.py", "write_guard_hook.py", "kimi_guard_hook.py",
         "agy_guard_hook.py", "gemini_guard_hook.py")


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
        for name in ("SCOPE_KEYS", "_under", "_names_keychain", "_in_dir_grant"):
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

    def test_a_scope_path_install_would_never_write_refuses_the_scope(self):
        # M1 (#3411): install() writes absolute, normalised paths only. Anything else on disk was
        # written by someone else, and is refused at load rather than kept as a dead grant.
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        path = os.path.join(d, "scope.json")
        good = os.path.join(d, "a.py")
        for key in guard_rules.SCOPE_KEYS:
            for bad in ("a.py", "./a.py", d + "/x/../a.py", d + "//a.py", d + "/./a.py", d + "/"):
                with self.subTest(key=key, path=bad):
                    with open(path, "w", encoding="utf-8") as fh:
                        json.dump({"e": {key: [good, bad]}}, fh)
                    self.assertEqual((None, "read guard scope is malformed"),
                                     guard_rules._load_scope(path))
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({"e": {"files": [good, 7], "dirs": None}}, fh)
        scopes, error = guard_rules._load_scope(path)
        self.assertEqual("", error)
        self.assertEqual([good], scopes["e"]["files"])
        self.assertEqual([], scopes["e"]["dirs"])

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
        for hook in (rg, wg, kg, ag, gg):
            with self.subTest(hook=hook.__name__):
                self.assertIs(hook.guard_rules, guard_rules)
                self.assertEqual(hook._GUARD_RULES_FAULT, "")
        with mock.patch.object(guard_rules, "bind", return_value="patched") as fake:
            self.assertEqual(rg.guard_rules.bind("a", "t"), "patched")
        fake.assert_called_once_with("a", "t")

    def test_the_hooks_re_export_the_shared_constants(self):
        for hook, names in ((rg, ("ENV_ENTRY_ID", "MARKER_PREFIX", "SCOPE_KEYS")),
                            (wg, ("ENV_ENTRY_ID", "UNBOUND_ENTRY", "ALLOWLIST_VERSION")),
                            (kg, ("ENV_ENTRY_ID", "UNBOUND_ENTRY", "SCOPE_KEYS")),
                            (ag, ("ENV_ENTRY_ID", "UNBOUND_ENTRY", "SCOPE_KEYS")),
                            (gg, ("ENV_ENTRY_ID", "UNBOUND_ENTRY", "SCOPE_KEYS"))):
            for name in names:
                with self.subTest(hook=hook.__name__, name=name):
                    self.assertIs(getattr(hook, name), getattr(guard_rules, name))


class TestTheRuleSetImportsOnlyTheStdlib(unittest.TestCase):
    """The module's own rule: stdlib-only, nothing from `scripts`, nothing relative. A hook
    loads it by path under `-I`, where a sibling import raises and a `scripts` import could
    be answered by a foreign package. #3658 put a tree walk here that `probes/surface` shares;
    the sharing goes OUT of this module, never into it."""

    def test_every_import_anywhere_in_the_module_is_a_stdlib_module(self):
        imported = []
        for node in ast.walk(ast.parse(_source("guard_rules.py"))):
            if isinstance(node, ast.Import):
                imported += [(0, alias.name) for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                imported.append((node.level, node.module or ""))
        self.assertTrue(imported)
        self.assertEqual([], [(level, name) for level, name in imported
                              if level or name.split(".")[0] not in sys.stdlib_module_names])

    def test_the_probe_reads_the_walk_from_here_and_keeps_no_copy(self):
        import scripts.probes.surface as probes_surface
        self.assertIs(guard_rules, probes_surface.guard_rules)
        self.assertFalse(hasattr(probes_surface, "scan_directory"))
        self.assertNotIn("os.scandir", _source(os.path.join("probes", "surface.py")))
        self.assertNotIn("os.walk(", _source(os.path.join("probes", "surface.py")))


class TestAnUnloadedRuleSetDeniesInProcess(unittest.TestCase):
    """The adjudication contract with the module missing: deny, first."""

    CASES = (
        (rg, lambda: rg.adjudicate({"tool_name": "Read", "tool_input": {}}, "/nowhere")),
        (wg, lambda: wg.adjudicate({"tool_name": "Write", "tool_input": {}}, "/nowhere")),
        (kg, lambda: kg.adjudicate({"tool_name": "Read", "tool_input": {}}, "read", "/nowhere")),
        (ag, lambda: ag.adjudicate({"toolCall": {"name": "read_file", "arguments": {}}}, "/nowhere", "/nowhere")),
        (gg, lambda: gg.adjudicate({"tool_name": "read_file", "tool_input": {}}, "/nowhere", "/nowhere")),
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
            ("agy_guard_hook.py", [self.scope, self.allowlist],
             {"hook": "PreToolUse", "lastUserInput": "<!-- panopticon-entry: e1 -->",
              "toolCall": {"name": "read_file", "arguments": {"Path": self.outside}}}),
            ("gemini_guard_hook.py", [self.scope, self.allowlist],
             {"tool_name": "read_file", "tool_input": {"file_path": self.outside}}),
        )

    def _launch(self, python, hook_path, argv, payload, cwd, extra_env=None):
        env = {"PATH": os.environ.get("PATH", ""), "PANOPTICON_ENTRY_ID": "e1",
               "PANOPTICON_READ_SCOPE": self.scope,
               "PANOPTICON_WRITE_ALLOWLIST": self.allowlist,
               # #3436: the read hook checks its row's stamp under the driver's key.
               "PANOPTICON_STATE_DIR": os.environ["PANOPTICON_STATE_DIR"]}
        env.update(extra_env or {})
        # `env` with an ABSOLUTE interpreter executes exactly that file (no PATH
        # search): the process is `<python> -I <hook>`, under a literal launcher.
        proc = subprocess.run(["/usr/bin/env", python, "-I", hook_path, *argv],
                              input=json.dumps(payload), capture_output=True, text=True,
                              cwd=cwd, env=env, timeout=60)
        return proc

    def _assert_denied(self, proc, fragment=None):
        self.assertEqual(proc.returncode, 0, proc.stderr)
        parsed = json.loads(proc.stdout)
        if "hookSpecificOutput" in parsed:
            body = parsed["hookSpecificOutput"]
            self.assertEqual(body["permissionDecision"], "deny")
            reason = body["permissionDecisionReason"]
        else:
            self.assertEqual(parsed["decision"], "deny")
            reason = parsed["reason"]
        if fragment:
            self.assertIn(fragment, reason)
        return reason


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
                if hook in ("agy_guard_hook.py", "gemini_guard_hook.py"):
                    self.assertEqual(proc.returncode, 0, proc.stderr)
                    self.assertEqual({"decision": "allow"}, json.loads(proc.stdout))
                else:
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
        subprocess.run(["/usr/bin/env", sys.executable, "-m", "venv", "--without-pip", cls.venv],
                       check=True, capture_output=True, timeout=120)
        cls.python = os.path.join(cls.venv, "bin", "python")
        cls.site = subprocess.run(
            ["/usr/bin/env", cls.python, "-I", "-c",
             "import sysconfig; print(sysconfig.get_paths()['purelib'])"],
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
        subprocess.run(["/usr/bin/env", self.python, "-I", "-c", "import scripts.guard_rules"],
                       check=True, capture_output=True, cwd=self.root, timeout=60)
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



class TestNoGrantCoversTheKeychain(unittest.TestCase):
    """#3607: every host's read and write tools refuse a macOS Keychain path,
    even inside a granted directory or named by a grant exactly, and through a
    symlink. The tree is a fixture in a temp dir, never the real Keychain, and
    the control row proves the same grants allow an ordinary file."""

    ENV = {"PANOPTICON_ENTRY_ID": "e1"}

    def setUp(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        self.home = os.path.realpath(d)
        self.kdir = os.path.join(self.home, "Library", "Keychains")
        os.makedirs(self.kdir)
        self.kfile = os.path.join(self.kdir, "login.keychain-db")
        self.loose = os.path.join(self.home, "old.keychain")
        self.ok = os.path.join(self.home, "notes.txt")
        self.clean = os.path.join(self.home, "src")
        os.makedirs(self.clean)
        for path in (self.kfile, self.loose, self.ok, os.path.join(self.clean, "a.py")):
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("needle\n")
        self.link = os.path.join(self.home, "innocent.txt")
        os.symlink(self.kfile, self.link)
        self.linkdir = os.path.join(self.home, "lnk")
        os.symlink(self.kdir, self.linkdir)
        self.folded = os.path.join(self.home, "library", "KEYCHAINS", "login.keychain-db")
        self.out_ok = os.path.join(self.home, "out.json")
        self.out_via_link = os.path.join(self.linkdir, "out.json")
        self.out_declared = os.path.join(self.kdir, "out.json")
        # Declared as a Keychain path, resolving to an ordinary folder: the
        # declared half of the write rule is what refuses it.
        plain = os.path.join(self.home, "plain")
        os.makedirs(os.path.join(self.home, "alias", "Library"))
        os.makedirs(plain)
        os.symlink(plain, os.path.join(self.home, "alias", "Library", "Keychains"))
        self.out_alias = os.path.join(self.home, "alias", "Library", "Keychains", "out.json")
        self.scope = os.path.join(self.home, "read-scope.json")
        with open(self.scope, "w", encoding="utf-8") as fh:
            json.dump(rg.scope_from_plan([{"id": "e1", "scope": {
                "files": [self.kfile, self.loose, self.ok], "dirs": [self.home],
                "reads": []}}]), fh)
        # The alias is granted by its RESOLVED path, so only the declared-path
        # half of the rule stands between it and an allowed write.
        grants = [self.out_ok, self.out_via_link, self.out_declared,
                  os.path.join(plain, "out.json")]
        self.allowlist = os.path.join(self.home, "write-allowlist.json")
        with open(self.allowlist, "w", encoding="utf-8") as fh:
            json.dump({"version": 2, "entries": {"e1": grants}, "paths": grants}, fh)

    def _reads(self, path):
        """(host, call) for a file read of `path` in every host's read tool."""
        env = dict(self.ENV)
        return (
            ("claude", lambda: rg.adjudicate(
                {"tool_name": "Read", "tool_input": {"file_path": path}}, self.scope, env)),
            ("kimi", lambda: kg.adjudicate(
                {"tool_name": "Read", "tool_input": {"path": path}}, "read", self.scope, env)),
            ("agy", lambda: ag.adjudicate(
                {"toolCall": {"name": "read_file", "arguments": {"Path": path}}},
                self.scope, self.allowlist, env=env)),
            ("gemini", lambda: gg.adjudicate(
                {"tool_name": "read_file", "tool_input": {"file_path": path}},
                self.scope, self.allowlist, env=env)),
        )

    def _dir_reads(self, path):
        """(host, call) for a directory search of `path` in every host's grep tool."""
        env = dict(self.ENV)
        return (
            ("claude", lambda: rg.adjudicate(
                {"tool_name": "Grep", "tool_input": {"path": path, "pattern": "x"}},
                self.scope, env)),
            ("kimi", lambda: kg.adjudicate(
                {"tool_name": "Grep", "tool_input": {"path": path, "pattern": "x"}},
                "read", self.scope, env)),
            ("agy", lambda: ag.adjudicate(
                {"toolCall": {"name": "grep_search",
                              "arguments": {"SearchPath": path, "Query": "x"}}},
                self.scope, self.allowlist, env=env)),
            ("gemini", lambda: gg.adjudicate(
                {"tool_name": "grep_search", "tool_input": {"dir_path": path, "pattern": "x"}},
                self.scope, self.allowlist, env=env)),
        )

    def _writes(self, path):
        """(host, call) for a write of `path` in every host's write tool."""
        env = dict(self.ENV)
        return (
            ("claude", lambda: wg.adjudicate(
                {"tool_name": "Write", "tool_input": {"file_path": path, "content": "{}"}},
                self.allowlist, env)),
            ("kimi", lambda: kg.adjudicate(
                {"tool_name": "Write", "tool_input": {"path": path, "content": "{}"}},
                "write", self.allowlist, env)),
            ("agy", lambda: ag.adjudicate(
                {"toolCall": {"name": "write_file", "arguments": {"Path": path}}},
                self.scope, self.allowlist, env=env)),
            ("gemini", lambda: gg.adjudicate(
                {"tool_name": "write_file", "tool_input": {"file_path": path, "content": "{}"}},
                self.scope, self.allowlist, env=env)),
        )

    def test_the_predicate_reads_components_folded(self):
        for path in ("/Users/u/Library/Keychains/login.keychain-db",
                     "/Users/u/library/KEYCHAINS/x", "/Library/Keychains/System.keychain",
                     "/Users/u/Library/Keychains", "/tmp/old.keychain", "/tmp/A.KEYCHAIN-DB"):
            with self.subTest(path=path):
                self.assertTrue(guard_rules._names_keychain(path))
        for path in ("/repo/Library/KeychainsX/a", "/repo/keychains/a", "/repo/Keychains/Library",
                     "/repo/a.keychain.txt", "/repo/my-keychain-db", "/repo/Library/a"):
            with self.subTest(path=path):
                self.assertFalse(guard_rules._names_keychain(path))

    def test_the_control_file_is_readable_and_writable_in_every_host(self):
        # #3616: a search over the home itself is now denied (a Keychain lies under it); the
        # control directory is a clean subdirectory of the same grant.
        for host, call in self._reads(self.ok) + self._dir_reads(self.clean) + self._writes(self.out_ok):
            with self.subTest(host=host):
                self.assertEqual((True, ""), call())

    def test_every_host_refuses_a_keychain_read(self):
        for path in (self.kfile, self.loose, self.link, self.folded):
            for host, call in self._reads(path):
                with self.subTest(host=host, path=os.path.relpath(path, self.home)):
                    self.assertFalse(call()[0])

    def test_every_host_refuses_a_search_of_the_keychain_directory(self):
        for path in (self.kdir, self.linkdir):
            for host, call in self._dir_reads(path):
                with self.subTest(host=host, path=os.path.relpath(path, self.home)):
                    self.assertFalse(call()[0])

    def test_every_host_refuses_a_keychain_write_even_when_granted(self):
        for path in (self.out_declared, self.out_via_link, self.out_alias):
            for host, call in self._writes(path):
                with self.subTest(host=host, path=os.path.relpath(path, self.home)):
                    allow, reason = call()
                    self.assertFalse(allow)
                    self.assertIn("cannot be a macOS Keychain path", reason)

    def test_the_codex_broker_refuses_reads_and_never_lists_the_keychain(self):
        reader = codex_read_tools.Reader(
            {"files": [self.kfile, self.ok], "dirs": [self.home], "reads": []}, self.home)
        for path in (self.kfile, self.loose, self.folded):
            with self.subTest(path=os.path.relpath(path, self.home)), \
                    self.assertRaises(ValueError):
                reader._read_file({"path": path})
        listed = reader._list_files({"path": self.home}, "*")["content"][0]["text"]
        self.assertIn("notes.txt", listed)
        self.assertNotIn("keychain", listed.casefold())
        found = reader._search({"path": self.home}, "needle")["content"][0]["text"]
        self.assertIn("notes.txt", found)
        self.assertNotIn("keychain", found.casefold())


class _KeychainTree(unittest.TestCase):
    """#3616 fixture: a home with `Library/Keychains`, a loose `.keychain-db`, a clean `src/`,
    and every host's directory-level tools. Temp dirs only. No tests of its own."""


    ENV = {"PANOPTICON_ENTRY_ID": "e1"}
    SEARCH = "a macOS Keychain path lies under"
    WALK = "was capped or is missing"
    UNWALKED = "could not be read when the scope was armed"

    def setUp(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        self.home = os.path.realpath(d)
        self.library = os.path.join(self.home, "Library")
        self.kdir = os.path.join(self.library, "Keychains")
        self.clean = os.path.join(self.home, "src")
        self.deep = os.path.join(self.home, "deep", "sub")
        for p in (self.kdir, self.clean, self.deep):
            os.makedirs(p)
        self.ok = os.path.join(self.clean, "a.py")
        self.notes = os.path.join(self.home, "notes.txt")
        self.loose = os.path.join(self.deep, "old.keychain-db")
        for path in (os.path.join(self.kdir, "login.keychain-db"), self.ok, self.notes,
                     self.loose):
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("needle\n")
        # Inside the Keychain directory: the walk never descends there, so this link out of
        # the grant is not recorded as an escape, and the Keychain beyond it is not followed.
        self.outside = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.outside, True)
        os.makedirs(os.path.join(self.outside, "Library", "Keychains"))
        os.symlink(self.outside, os.path.join(self.kdir, "out"))
        self.allowlist = os.path.join(self.home, "write-allowlist.json")
        with open(self.allowlist, "w", encoding="utf-8") as fh:
            json.dump({"version": 2, "entries": {"e1": []}, "paths": []}, fh)
        self.scope = self._arm(rg.scope_from_plan([{"id": "e1", "scope": {
            "files": [], "dirs": [self.home], "reads": []}}]))

    def _arm(self, scopes):
        path = os.path.join(self.home, "read-scope-%d.json" % len(os.listdir(self.home)))
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(scopes, fh)
        return path

    def _dir_tools(self, path, scope):
        """(tool, call) for every host's directory-level search and listing over `path`."""
        env = dict(self.ENV)
        return (
            ("claude Grep", lambda: rg.adjudicate(
                {"tool_name": "Grep", "tool_input": {"path": path, "pattern": "x"}}, scope, env)),
            ("claude Glob", lambda: rg.adjudicate(
                {"tool_name": "Glob", "tool_input": {"path": path, "pattern": "**/*"}},
                scope, env)),
            ("kimi Grep", lambda: kg.adjudicate(
                {"tool_name": "Grep", "tool_input": {"path": path, "pattern": "x"}},
                "read", scope, env)),
            ("kimi Glob", lambda: kg.adjudicate(
                {"tool_name": "Glob", "tool_input": {"path": path, "pattern": "*"}},
                "read", scope, env)),
            ("agy grep_search", lambda: ag.adjudicate(
                {"toolCall": {"name": "grep_search",
                              "arguments": {"SearchPath": path, "Query": "x"}}},
                scope, self.allowlist, env=env)),
            ("agy list_dir", lambda: ag.adjudicate(
                {"toolCall": {"name": "list_dir", "arguments": {"DirectoryPath": path}}},
                scope, self.allowlist, env=env)),
            ("agy find_by_name", lambda: ag.adjudicate(
                {"toolCall": {"name": "find_by_name",
                              "arguments": {"SearchDirectory": path, "Pattern": "*"}}},
                scope, self.allowlist, env=env)),
            ("gemini grep_search", lambda: gg.adjudicate(
                {"tool_name": "grep_search", "tool_input": {"dir_path": path, "pattern": "x"}},
                scope, self.allowlist, env=env)),
            ("gemini list_directory", lambda: gg.adjudicate(
                {"tool_name": "list_directory", "tool_input": {"dir_path": path}},
                scope, self.allowlist, env=env)),
            ("gemini glob", lambda: gg.adjudicate(
                {"tool_name": "glob", "tool_input": {"dir_path": path, "pattern": "*"}},
                scope, self.allowlist, env=env)),
        )

    def _reads(self, path, scope):
        env = dict(self.ENV)
        return (
            ("claude", lambda: rg.adjudicate(
                {"tool_name": "Read", "tool_input": {"file_path": path}}, scope, env)),
            ("kimi", lambda: kg.adjudicate(
                {"tool_name": "Read", "tool_input": {"path": path}}, "read", scope, env)),
            ("agy", lambda: ag.adjudicate(
                {"toolCall": {"name": "read_file", "arguments": {"Path": path}}},
                scope, self.allowlist, env=env)),
            ("gemini", lambda: gg.adjudicate(
                {"tool_name": "read_file", "tool_input": {"file_path": path}},
                scope, self.allowlist, env=env)),
        )

class TestASearchOverAKeychainAncestorIsDenied(_KeychainTree):
    """#3616: the Keychain rule (#3607) is checked on the path a call names, so a recursive
    search over an ANCESTOR of a Keychain directory let the host CLI walk into it. The scope's
    arm-time walk records each grant's Keychain paths, and every host's directory-level search
    and listing over one is denied; a capped, failed or missing walk denies them all. Exact
    reads under the same grant are untouched. A fixture tree in a temp dir, never the real
    Keychain, and no real home is walked."""

    def test_the_walk_records_keychain_paths_without_descending_or_following(self):
        escapes, keychains, unwalked = guard_rules.grant_walk([self.home])
        self.assertEqual({self.home: sorted([self.kdir, self.loose])}, keychains)
        self.assertEqual({self.home: []}, escapes)      # the link inside the Keychain is unseen
        self.assertEqual({self.home: []}, unwalked)
        self.assertEqual(escapes, guard_rules.grant_escapes([self.home]))

    def test_every_host_denies_a_search_or_listing_over_an_ancestor(self):
        for path in (self.home, self.library, os.path.join(self.home, "deep")):
            for tool, call in self._dir_tools(path, self.scope):
                with self.subTest(tool=tool, path=os.path.relpath(path, self.home)):
                    allow, reason = call()
                    self.assertFalse(allow)
                    self.assertIn(self.SEARCH, reason)

    def test_a_clean_subdirectory_of_the_same_grant_stays_searchable(self):
        for tool, call in self._dir_tools(self.clean, self.scope):
            with self.subTest(tool=tool):
                self.assertEqual((True, ""), call())

    def test_exact_reads_under_the_same_grant_stay_allowed(self):
        for path in (self.notes, self.ok):
            for host, call in self._reads(path, self.scope):
                with self.subTest(host=host, path=os.path.relpath(path, self.home)):
                    self.assertEqual((True, ""), call())

    def test_a_glob_is_judged_on_its_literal_prefix(self):
        env = dict(self.ENV)
        for pattern, allowed in (("src/*", True), ("src/a.py", True), ("notes.txt", True),
                                 ("missing/*", False),          # #3636: unmeasurable = denied
                                 ("*", False), ("deep/**", False)):
            with self.subTest(pattern=pattern):
                allow, reason = rg.adjudicate(
                    {"tool_name": "Glob", "tool_input": {"path": self.home, "pattern": pattern}},
                    self.scope, env)
                self.assertEqual(allowed, allow, reason)
                if not allowed:
                    self.assertIn(self.SEARCH, reason)

    def test_a_capped_or_missing_walk_denies_every_directory_tool(self):
        escapes, capped, unwalked = guard_rules.grant_walk([self.home], cap=1)
        self.assertEqual(({self.home: None},) * 3, (escapes, capped, unwalked))
        armed = rg.scope_from_plan([{"id": "e1", "scope": {"files": [], "dirs": [self.home],
                                                           "reads": []}}])
        cases = {"capped": dict(armed["e1"], escapes=escapes, keychains=capped,
                                unwalked=unwalked),
                 "missing": {k: v for k, v in armed["e1"].items() if k != "keychains"},
                 "missing unwalked": {k: v for k, v in armed["e1"].items() if k != "unwalked"},
                 "malformed": dict(armed["e1"], keychains={self.home: "x"}),
                 "malformed unwalked": dict(armed["e1"], unwalked={self.home: "x"})}
        for label, scope in cases.items():
            path = self._arm({"e1": scope})
            for tool, call in self._dir_tools(self.clean, path):
                with self.subTest(walk=label, tool=tool):
                    allow, reason = call()
                    self.assertFalse(allow)
                    if "Glob" not in tool and "glob" not in tool and "find" not in tool:
                        self.assertIn(self.WALK, reason)
                        self.assertIn(self.home, reason)
            for host, call in self._reads(self.ok, path):
                with self.subTest(walk=label, read=host):
                    self.assertEqual((True, ""), call())

    def test_the_refusal_is_per_grant(self):
        # A second, clean grant beside the home is searchable on its own.
        other = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, other, True)
        other = os.path.realpath(other)
        scope = self._arm(rg.scope_from_plan([{"id": "e1", "scope": {
            "files": [], "dirs": [self.home, other], "reads": []}}]))
        for tool, call in self._dir_tools(other, scope):
            with self.subTest(tool=tool):
                self.assertEqual((True, ""), call())
        # Even when the home's walk is unknown: only the grant that covers the target counts.
        armed = rg.scope_from_plan([{"id": "e1", "scope": {"files": [], "dirs": [self.home, other],
                                                           "reads": []}}])["e1"]
        armed["keychains"][self.home] = None
        armed["escapes"][self.home] = None
        armed["unwalked"][self.home] = None
        scope = self._arm({"e1": armed})
        for tool, call in self._dir_tools(other, scope):
            with self.subTest(tool=tool, home_walk="unknown"):
                self.assertEqual((True, ""), call())


class TestTheKeychainRuleHoldsAgainstSpellingsLinksAndUnreadableDirs(_KeychainTree):
    """#3635 review: a case or NFD spelling of an ancestor is the same directory on APFS, so the
    rule compares by file identity; an in-grant link into a Keychain (or to an ancestor of one)
    is recorded; agy's find_by_name is checked whatever its Pattern; and a directory the walk
    could not read denies only searches on its own line. Fixtures only."""

    def _aliases(self, path):
        """`path`'s spellings that open the same directory on THIS volume (APFS: all)."""
        rel = os.path.relpath(path, self.home)
        out = []
        for spelled in (rel.lower(), rel.upper(), unicodedata.normalize("NFD", rel)):
            alias = os.path.join(self.home, spelled)
            if alias != path and os.path.exists(alias) and os.path.samefile(alias, path):
                out.append(alias)
        return out

    def test_a_case_or_nfd_spelling_of_an_ancestor_is_denied_on_every_host(self):
        accented = os.path.join(self.home, "Caf\u00e9")
        os.makedirs(os.path.join(accented, "Library", "Keychains"))
        scope = self._arm(rg.scope_from_plan([{"id": "e1", "scope": {
            "files": [], "dirs": [self.home], "reads": []}}]))
        spellings = (self._aliases(self.library) + self._aliases(accented)
                     + self._aliases(os.path.join(accented, "Library")))
        if not spellings:
            self.skipTest("this volume is case- and normalization-sensitive: no alias exists")
        for alias in spellings:
            for tool, call in self._dir_tools(alias, scope):
                with self.subTest(tool=tool, alias=os.path.relpath(alias, self.home)):
                    allow, reason = call()
                    self.assertFalse(allow)
                    self.assertIn(self.SEARCH, reason)

    def test_a_glob_prefix_spelled_differently_is_denied(self):
        env = dict(self.ENV)
        aliases = [os.path.relpath(a, self.home) for a in self._aliases(self.library)]
        if not aliases:
            self.skipTest("this volume is case-sensitive: no alias exists")
        for prefix in aliases:
            pattern = prefix + "/**"
            calls = (
                ("claude Glob", lambda: rg.adjudicate(
                    {"tool_name": "Glob", "tool_input": {"path": self.home, "pattern": pattern}},
                    self.scope, env)),
                ("kimi Glob", lambda: kg.adjudicate(
                    {"tool_name": "Glob", "tool_input": {"path": self.home, "pattern": pattern}},
                    "read", self.scope, env)),
                ("gemini glob", lambda: gg.adjudicate(
                    {"tool_name": "glob", "tool_input": {"dir_path": self.home,
                                                         "pattern": pattern}},
                    self.scope, self.allowlist, env=env)),
                ("gemini grep_search include", lambda: gg.adjudicate(
                    {"tool_name": "grep_search", "tool_input": {
                        "dir_path": self.clean, "pattern": "x",
                        "include_pattern": "../" + pattern}},
                    self.scope, self.allowlist, env=env)))
            for tool, call in calls:
                with self.subTest(tool=tool, pattern=pattern):
                    self.assertFalse(call()[0])

    def test_an_in_grant_link_into_a_keychain_or_to_its_ancestor_is_recorded(self):
        docs = os.path.join(self.home, "docs")
        os.makedirs(docs)
        to_file = os.path.join(docs, "kc")
        os.symlink(os.path.join(self.kdir, "login.keychain-db"), to_file)
        up = os.path.join(self.clean, "up")
        os.symlink(self.home, up)
        # Outside the grant: a link toward the user's Library (HOME is a fixture here, so
        # this is string math on a temp path, never the real home or Keychain).
        user = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, user, True)
        os.makedirs(os.path.join(user, "Library"))
        towards = os.path.join(self.deep, "lib")
        os.symlink(os.path.join(user, "Library"), towards)
        plain = os.path.join(self.deep, "plain")
        os.symlink(self.outside, plain)
        # The same user Library spelled as APFS also opens it (NFD, upper case): the link check
        # is string math, so it folds (NFC + casefold) rather than stat the Keychain side.
        accent = os.path.join(user, "Us\u00e9r")
        os.makedirs(os.path.join(accent, "Library"))
        spelled = os.path.join(user, unicodedata.normalize("NFD", "Us\u00e9r"), "LIBRARY")
        aliased = os.path.exists(spelled) and os.path.samefile(
            spelled, os.path.join(accent, "Library"))
        folded = os.path.join(self.deep, "folded")
        os.symlink(spelled if aliased else os.path.join(accent, "Library"), folded)
        with mock.patch.dict(os.environ, {"HOME": user}):
            escapes, keychains, _ = guard_rules.grant_walk([self.home])
            scope = self._arm(rg.scope_from_plan([{"id": "e1", "scope": {
                "files": [], "dirs": [self.home], "reads": []}}]))
        with mock.patch.dict(os.environ, {"HOME": accent}):
            self.assertIn(folded, guard_rules.grant_walk([self.home])[1][self.home])
        for link in (to_file, up, towards):
            self.assertIn(link, keychains[self.home])
        self.assertNotIn(plain, keychains[self.home])
        self.assertIn(plain, escapes[self.home])
        for path in (docs, self.clean):
            for tool, call in self._dir_tools(path, scope):
                with self.subTest(tool=tool, path=os.path.relpath(path, self.home)):
                    allow, reason = call()
                    self.assertFalse(allow)
                    self.assertIn(self.SEARCH, reason)

    def test_a_refusal_never_stats_a_keychain_path(self):
        # #3616/#3607: panopticon does not touch the Keychain in any form, metadata included:
        # identity is checked on the directories ABOVE each record, never on the record.
        real_stat, statted = os.stat, []

        def spy(path, *a, **k):
            statted.append(os.fspath(path))
            return real_stat(path, *a, **k)
        for path in (self.home, self.library, self.clean):
            for tool, call in self._dir_tools(path, self.scope):
                with mock.patch.object(guard_rules.os, "stat", spy):
                    call()
        self.assertTrue(statted)
        self.assertEqual([], [p for p in statted if guard_rules._names_keychain(p)])

    def test_a_target_the_refusal_cannot_measure_is_denied(self):
        # #3636: fail closed on its own, not because every hook happens to gate on isdir first.
        gone = os.path.join(self.home, "gone")
        scope = {"dirs": [self.home], "keychains": {self.home: [self.kdir]},
                 "unwalked": {self.home: []}}
        self.assertTrue(guard_rules._on_line(gone, self.kdir, self.home))
        reason = guard_rules._keychain_refusal("Grep over %s" % gone, gone, scope)
        self.assertIn(self.SEARCH, reason)
        clean = {"dirs": [self.home], "keychains": {self.home: []}, "unwalked": {self.home: []}}
        self.assertIsNone(guard_rules._keychain_refusal("Grep over %s" % gone, gone, clean))

    def _firm(self, path):
        """`path` under macOS's firmlink spelling, when this volume has one for it."""
        firm = "/System/Volumes/Data" + path
        if os.path.isdir(firm) and os.path.samefile(firm, path):
            return firm
        self.skipTest("no /System/Volumes/Data firmlink spelling on this volume")

    def test_a_link_to_a_keychain_ancestor_under_a_firmlink_spelling_is_recorded(self):
        # #3636: realpath keeps `/System/Volumes/Data/...`, which no string fold maps back, so
        # the link check compares by identity against the directories above each Keychain.
        user = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, user, True)
        os.makedirs(os.path.join(user, "Library"))
        to_home = os.path.join(self.deep, "firm")
        os.symlink(self._firm(user), to_home)
        to_library = os.path.join(self.deep, "firmlib")
        os.symlink(self._firm(os.path.join(user, "Library")), to_library)
        to_grant = os.path.join(self.clean, "firmup")
        os.symlink(self._firm(self.home), to_grant)
        for link in (to_home, to_library, to_grant):
            self.assertTrue(os.path.realpath(link).startswith("/System/Volumes/Data/"))
        with mock.patch.dict(os.environ, {"HOME": user}):
            keychains = guard_rules.grant_walk([self.home])[1][self.home]
            scope = self._arm(rg.scope_from_plan([{"id": "e1", "scope": {
                "files": [], "dirs": [self.home], "reads": []}}]))
        for link in (to_home, to_library, to_grant):
            self.assertIn(link, keychains)
        for tool, call in self._dir_tools(self.clean, scope):
            with self.subTest(tool=tool):
                allow, reason = call()
                self.assertFalse(allow)
                if "Glob" in tool or "glob" in tool:
                    continue            # #2063 denies first: the firmlink spelling reads as leaving
                self.assertIn(self.SEARCH, reason)

    def test_the_arm_time_identity_check_never_stats_a_keychain_path(self):
        user = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, user, True)
        os.makedirs(os.path.join(user, "Library", "Keychains"))
        os.symlink(user, os.path.join(self.deep, "home"))
        os.symlink(self.outside, os.path.join(self.deep, "plain"))
        # A dangling link leads nowhere a walker could follow: never recorded (#3636 F7).
        dangling = os.path.join(self.clean, "dangling")
        os.symlink(os.path.join(self.outside, "nowhere"), dangling)
        real_stat, statted = os.stat, []

        def spy(path, *a, **k):
            statted.append(os.fspath(path))
            return real_stat(path, *a, **k)
        with mock.patch.dict(os.environ, {"HOME": user}), \
                mock.patch.object(guard_rules.os, "stat", spy):
            keychains = guard_rules.grant_walk([self.home])[1][self.home]
        self.assertNotIn(dangling, keychains)
        self.assertIn(os.path.join(self.deep, "home"), keychains)
        self.assertTrue(statted)
        self.assertEqual([], [p for p in statted if guard_rules._names_keychain(p)])

    def test_find_by_name_is_checked_whatever_its_pattern(self):
        for pattern in ("login.keychain-db", "a.py", "*"):
            with self.subTest(pattern=pattern):
                allow, reason = ag.adjudicate(
                    {"toolCall": {"name": "find_by_name", "arguments": {
                        "SearchDirectory": self.home, "Pattern": pattern}}},
                    self.scope, self.allowlist, env=dict(self.ENV))
                self.assertFalse(allow)
                self.assertIn(self.SEARCH, reason)

    def _unreadable(self, grant, name):
        """grant_walk over `grant` as if `grant/name` could not be read (EACCES), without
        changing any permission: os.scandir refuses that one directory."""
        real_scandir, target = os.scandir, os.path.join(grant, name)

        def scandir(path):
            if path == target:
                raise PermissionError(13, "Permission denied", target)
            return real_scandir(path)
        return mock.patch.object(guard_rules.os, "scandir", scandir)

    def test_an_unreadable_directory_denies_only_searches_on_its_line(self):
        repo = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, repo, True)
        data = os.path.join(repo, "data")
        for p in (os.path.join(data, "inner"), os.path.join(repo, "src")):
            os.makedirs(p)
        with self._unreadable(repo, "data"):
            walked = guard_rules.grant_walk([repo])
            scope = self._arm(rg.scope_from_plan([{"id": "e1", "scope": {
                "files": [], "dirs": [repo], "reads": []}}]))
        self.assertEqual(({repo: []}, {repo: []}, {repo: [data]}), walked)
        for path in (repo, data, os.path.join(data, "inner")):          # above, at, below
            for tool, call in self._dir_tools(path, scope):
                with self.subTest(tool=tool, path=os.path.relpath(path, repo)):
                    allow, reason = call()
                    self.assertFalse(allow)
                    if "Glob" in tool or "glob" in tool or "find" in tool:
                        continue
                    self.assertIn(self.UNWALKED, reason)
                    self.assertIn(data, reason)
        for tool, call in self._dir_tools(os.path.join(repo, "src"), scope):
            with self.subTest(tool=tool, path="src (beside it)"):
                self.assertEqual((True, ""), call())


def _grant_walk_before_3658(dirs, cap=guard_rules.ESCAPE_WALK_CAP):
    """`guard_rules.grant_walk` as it was before #3658: the same body over `os.walk`. Kept
    here, and only here, as the reference the explicit-stack walk is compared against."""
    g = guard_rules
    escapes, keychains, unwalked = {}, {}, {}
    for grant in dirs:
        links, found, failed, pointing, seen = [], [], [], [], 0

        def note(exc, failed=failed, grant=grant):
            failed.append(os.path.abspath(getattr(exc, "filename", None) or grant))

        for root, subdirs, files in os.walk(grant, followlinks=False, onerror=note):
            subdirs[:] = [d for d in subdirs if root != grant or d.casefold() != ".git"]
            seen += len(subdirs) + len(files)
            if seen > cap:
                break
            for name in subdirs + files:
                path = os.path.join(root, name)
                if not os.path.islink(path):
                    if g._names_keychain(path):
                        found.append(path)
                    continue
                real = os.path.realpath(path)
                if not g._under(real, grant):
                    links.append(path)
                if g._names_keychain(path) or g._names_keychain(real):
                    found.append(path)
                else:
                    pointing.append((path, real))
            subdirs[:] = [d for d in subdirs if not g._names_keychain(os.path.join(root, d))]
        if seen > cap:
            escapes[grant] = keychains[grant] = unwalked[grant] = None
            continue
        if pointing:
            targets = [g._fold(p) for p in found] + [g._fold(p) for p in g._keychain_homes()]
            above = g._stats([step for p in found for step in g._chain(grant, p)[:-1]]
                             + [step for home in g._keychain_homes()
                                for step in g._chain(os.sep, home)[:-1]])
            found += [path for path, real in pointing
                      if any(g._under(t, g._fold(real)) for t in targets)
                      or g._identical(real, above)]
        escapes[grant] = sorted(links)
        keychains[grant] = sorted(found)
        unwalked[grant] = sorted(set(failed))
    return escapes, keychains, unwalked


def _scandir_failing_stat_on(name):
    """`os.scandir`, except that the entry called `name` cannot be stat'd: what a filesystem
    with no `d_type` does when the `lstat` behind `DirEntry.is_dir` fails."""
    real = os.scandir

    class _NoStat:
        def __init__(self, entry):
            self.name, self.path = entry.name, entry.path

        def is_dir(self, *, follow_symlinks=True):
            raise OSError(errno.EIO, os.strerror(errno.EIO), self.path)

    @contextlib.contextmanager
    def scandir(path):
        with real(path) as entries:
            yield [_NoStat(entry) if entry.name == name else entry for entry in entries]

    return scandir


class TestTheGrantWalkKeepsItsOwnStack(unittest.TestCase):
    """#3658: `grant_walk` ran on `os.walk`, which recurses a frame per level before Python
    3.12 and reads a failed is-directory stat as "a file". It now runs on `iter_tree`, the
    walk the discovery-surface probe shares. What it RECORDS must not have moved."""

    def _tmp(self):
        d = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d, True)
        return d

    def _write(self, *parts):
        path = os.path.join(*parts)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("x\n")
        return path

    def _grants(self):
        """Three grants and an outside: every kind of entry the walk treats differently."""
        outside = self._tmp()
        self._write(outside, "secret.txt")
        os.makedirs(os.path.join(outside, "store"))
        one, two, three = self._tmp(), self._tmp(), self._tmp()
        self._write(one, "src", "pkg", "mod.py")
        self._write(one, "src", "pkg", "deep", "er", "leaf.py")
        os.makedirs(os.path.join(one, "empty"))
        os.symlink(os.path.join(one, "src", "pkg"), os.path.join(one, "src", "in-link"))
        os.symlink(outside, os.path.join(one, "src", "out-dir"))
        os.symlink(os.path.join(outside, "secret.txt"), os.path.join(one, "out-file"))
        os.symlink(os.path.join(one, "nowhere"), os.path.join(one, "dangling"))
        os.symlink("loop", os.path.join(one, "loop"))
        # The top-level `.git` store is not walked, so the link inside it is unseen; a
        # `.git` further down is an ordinary directory.
        self._write(one, ".git", "config")
        os.symlink(outside, os.path.join(one, ".git", "unseen"))
        self._write(one, "vendored", ".git", "config")
        os.symlink(outside, os.path.join(one, "vendored", ".git", "seen"))
        # A Keychain directory (never descended), a loose keychain file, a link to the
        # directory above the Keychain.
        self._write(one, "Library", "Keychains", "login.keychain-db")
        os.symlink(outside, os.path.join(one, "Library", "Keychains", "unseen"))
        self._write(one, "old", "stale.keychain-db")
        os.symlink(os.path.join(one, "Library"), os.path.join(one, "to-library"))
        # `.git` as a link: to a directory in `two`, to a file in `three`.
        self._write(two, "a.py")
        os.symlink(os.path.join(outside, "store"), os.path.join(two, ".git"))
        self._write(three, "b.py")
        os.symlink(os.path.join(outside, "secret.txt"), os.path.join(three, ".git"))
        # A grant whose own path is a link: walked whatever it is, as `os.walk(top)` was.
        behind = self._tmp()
        self._write(behind, "pkg", "c.py")
        os.symlink(os.path.join(behind, "pkg"), os.path.join(behind, "in-link"))
        os.symlink(outside, os.path.join(behind, "pkg", "out-dir"))
        four = os.path.join(self._tmp(), "linked-grant")
        os.symlink(behind, four)
        return outside, [one, two, three, four]

    def test_it_records_exactly_what_the_os_walk_version_recorded(self):
        _outside, grants = self._grants()
        one, two, three, four = grants
        after = guard_rules.grant_walk(grants)
        self.assertEqual(_grant_walk_before_3658(grants), after)
        # The reference is not trusted blind: what this tree must yield, said outright.
        escapes, keychains, unwalked = after
        self.assertEqual(sorted([os.path.join(one, "out-file"),
                                 os.path.join(one, "src", "out-dir"),
                                 os.path.join(one, "vendored", ".git", "seen")]),
                         escapes[one])
        self.assertEqual(sorted([os.path.join(one, "Library", "Keychains"),
                                 os.path.join(one, "old", "stale.keychain-db"),
                                 os.path.join(one, "to-library")]), keychains[one])
        self.assertEqual({one: [], two: [], three: [], four: []}, unwalked)
        # The linked grant was walked, not skipped: the link two levels into it is there.
        self.assertIn(os.path.join(four, "pkg", "out-dir"), escapes[four])

    def test_the_cap_falls_on_the_same_entry_count_as_before(self):
        # Every cap from nothing to past the whole tree: the two walks count the same
        # entries, so they give up -- or do not -- at exactly the same cap.
        _outside, grants = self._grants()
        verdicts = set()
        for cap in range(0, 40):
            with self.subTest(cap=cap):
                after = guard_rules.grant_walk(grants, cap=cap)
                self.assertEqual(_grant_walk_before_3658(grants, cap=cap), after)
                verdicts.add(after[0][grants[0]] is None)
        self.assertEqual({True, False}, verdicts, "the range must straddle the cap")

    def test_a_top_level_git_link_to_a_directory_is_pruned_like_the_directory(self):
        # `os.walk` listed a link to a directory among the directories, so the `.git` prune
        # took it too. Recording it as an escape would deny every wildcard in the grant.
        outside, (_one, two, three, _four) = self._grants()
        self.assertEqual({two: []}, guard_rules.grant_escapes([two]))
        # ...while `.git` as a link to a FILE was never a directory, and is a link out.
        self.assertEqual({three: [os.path.join(three, ".git")]},
                         guard_rules.grant_escapes([three]))
        self.assertTrue(os.path.isdir(os.path.join(outside, "store")))

    def test_exactly_the_cap_is_not_over_the_cap(self):
        # `a/`, `a/f`, `b`: three entries. A cap of three has seen the whole grant.
        grant = self._tmp()
        self._write(grant, "a", "f")
        self._write(grant, "b")
        self.assertEqual(({grant: []},) * 3, guard_rules.grant_walk([grant], cap=3))
        self.assertEqual(({grant: None},) * 3, guard_rules.grant_walk([grant], cap=2))

    def test_a_top_level_git_link_into_a_keychain_is_recorded_and_never_statted(self):
        # The one place this walk still asks a question THROUGH a link is a top-level
        # `.git`. Where that link leads to a Keychain it is not asked: nothing here stats a
        # Keychain, and the link is recorded as the Keychain link it is. (The `os.walk`
        # version stat'd through it, found a directory, and pruned it unrecorded.)
        user, grant = self._tmp(), self._tmp()
        kdir = os.path.join(user, "Library", "Keychains")
        os.makedirs(kdir)
        link = os.path.join(grant, ".git")
        os.symlink(kdir, link)
        real_stat, statted = os.stat, []

        def spy(path, *a, **k):
            statted.append(os.fspath(path))
            return real_stat(path, *a, **k)
        with mock.patch.object(guard_rules.os, "stat", spy):
            escapes, keychains, unwalked = guard_rules.grant_walk([grant])
        self.assertEqual(({grant: [link]}, {grant: [link]}, {grant: []}),
                         (escapes, keychains, unwalked))
        self.assertEqual([], [p for p in statted
                              if p == link or guard_rules._names_keychain(p)])

    def test_iter_tree_asks_nothing_through_a_link(self):
        # `is_dir(follow_symlinks=False)` and `islink` only: no stat that follows, and no
        # realpath. `grant_walk` does its own realpath on the links it is handed, outside.
        outside, (one, _two, _three, four) = self._grants()

        def never(*_a, **_k):
            raise AssertionError("iter_tree looked through a link")
        with mock.patch.object(guard_rules.os, "stat", never), \
                mock.patch.object(guard_rules.os.path, "realpath", never), \
                mock.patch.object(guard_rules.os.path, "isdir", never):
            for top in (one, four):
                visited = [directory for directory, _subdirs, _others
                           in guard_rules.iter_tree(top, self.fail)]
                self.assertIn(top, visited)
                self.assertEqual([], [d for d in visited if os.path.islink(d) and d != top])
        # The Keychain directory is listed by its parent; nothing in the walk opens it
        # unless the caller leaves it in `subdirs` -- `grant_walk` prunes it.
        self.assertTrue(os.path.isdir(os.path.join(outside, "store")))

    def test_a_grant_deeper_than_the_recursion_budget_is_walked_not_crashed(self):
        # `os.walk` on Python 3.11 needs a frame per level; with far fewer to spare than the
        # grant has levels, the walk still reaches the link at the bottom.
        grant, outside = self._tmp(), self._tmp()
        levels, spare = 200, 80
        bottom = os.path.join(grant, *["d"] * levels)
        os.makedirs(bottom)
        os.symlink(outside, os.path.join(bottom, "out"))
        limit = sys.getrecursionlimit()
        sys.setrecursionlimit(len(inspect.stack(0)) + spare)
        try:
            walked = guard_rules.grant_walk([grant])
        finally:
            sys.setrecursionlimit(limit)
        self.assertEqual(({grant: [os.path.join(bottom, "out")]}, {grant: []}, {grant: []}),
                         walked)

    def test_an_entry_whose_stat_fails_is_unwalked_not_a_file(self):
        # It may be a directory nobody visited: said so, by path, like an unreadable one.
        grant, outside = self._tmp(), self._tmp()
        self._write(grant, "src", "a.py")
        os.makedirs(os.path.join(grant, "flaky"))
        os.symlink(outside, os.path.join(grant, "flaky", "out"))
        with mock.patch.object(guard_rules.os, "scandir", _scandir_failing_stat_on("flaky")):
            walked = guard_rules.grant_walk([grant])
        self.assertEqual(({grant: []}, {grant: []}, {grant: [os.path.join(grant, "flaky")]}),
                         walked)

    def test_a_link_whose_target_cannot_be_stat_is_a_link_not_unwalked(self):
        # Nothing is stat'd THROUGH a link. A looping link is in every other checkout; were
        # it "unwalked", every search on its line -- the whole grant -- would be denied.
        grant = self._tmp()
        os.symlink("loop", os.path.join(grant, "loop"))
        os.makedirs(os.path.join(grant, "locked"))
        os.symlink(os.path.join(grant, "locked", "gone"), os.path.join(grant, "behind"))
        os.chmod(os.path.join(grant, "locked"), 0o000)
        self.addCleanup(os.chmod, os.path.join(grant, "locked"), 0o700)
        escapes, _keychains, unwalked = guard_rules.grant_walk([grant])
        self.assertNotIn(os.path.join(grant, "loop"), unwalked[grant])
        self.assertNotIn(os.path.join(grant, "behind"), unwalked[grant])
        self.assertEqual([], escapes[grant])

    def test_iter_tree_walks_in_sorted_order_and_honours_in_place_pruning(self):
        grant = self._tmp()
        for parts in (("b", "x", "f"), ("a", "f"), ("c", "f")):
            self._write(grant, *parts)
        os.symlink(os.path.join(grant, "a"), os.path.join(grant, "b", "link"))
        seen = []
        for directory, subdirs, others in guard_rules.iter_tree(grant, self.fail):
            seen.append((os.path.relpath(directory, grant), list(subdirs), others))
            if "x" in subdirs:
                subdirs.remove("x")
        self.assertEqual([(os.curdir, ["a", "b", "c"], []), ("a", [], ["f"]),
                          ("b", ["x"], ["link"]), ("c", [], ["f"])], seen)


SHELL_TOOLS = ("run_command", "run_shell_command", "Bash", "BashOutput", "KillShell",
               "PowerShell", "REPL", "Shell", "shell", "shell_tool", "unified_exec")
SHELL_GRANT = ("%s: a host child gained a shell. The guards hold no shell reader (#3607 ruled "
               "one unneeded while every host denies shells), so a shell grant needs review: "
               "add the Keychain/`security` refusal with it")


class TestNoHostChildGetsAShell(unittest.TestCase):
    """#3607: the Keychain rule above covers file tools only, because no host's
    child can run a shell. These pins make a future shell grant fail here
    instead of landing quietly."""

    def test_the_strict_guards_deny_every_shell_tool_name(self):
        # Membership first: a shell name in either tool set is a grant, whatever
        # a deny reason says. Then the EXACT refusal, per mode: "allowlist" alone
        # also matches a write tool's "write guard allowlist is unavailable".
        env = {"PANOPTICON_ENTRY_ID": "e1"}
        calls = (
            ("agy", ag, lambda name, mode: ag.adjudicate(
                {"toolCall": {"name": name, "arguments": {"CommandLine": "true"}}},
                "/nowhere", "/nowhere", mode=mode, env=env)),
            ("gemini", gg, lambda name, mode: gg.adjudicate(
                {"tool_name": name, "tool_input": {"command": "true"}},
                "/nowhere", "/nowhere", mode=mode, env=env)))
        for hook, module, call in calls:
            for name in SHELL_TOOLS:
                with self.subTest(hook=hook, tool=name):
                    for tools in (module.ALLOWED_TOOLS, module.READ_TOOLS, module.WRITE_TOOLS):
                        self.assertNotIn(name, tools, SHELL_GRANT % hook)
                    for mode, which in ((None, ""), ("read", "read "), ("write", "write ")):
                        self.assertEqual(
                            (False, "%s is denied: tool is not on the reviewer %sallowlist"
                             % (name, which)),
                            call(name, mode), SHELL_GRANT % hook)

    def test_no_role_template_grants_a_shell(self):
        # The union is what Claude's unenforced `--tools` list and every host's
        # registered shell grant are rendered from.
        granted = set(dispatch.allowed_tool_union()) & set(SHELL_TOOLS)
        self.assertEqual(set(), granted, SHELL_GRANT % "dispatch.allowed_tool_union")

    def test_claude_unenforced_launches_deny_the_shell_tools(self):
        denied = set(runners_claude.UNENFORCED_DENIED_TOOLS)
        for name in ("Bash", "BashOutput", "KillShell", "PowerShell", "REPL"):
            with self.subTest(tool=name):
                self.assertIn(name, denied, SHELL_GRANT % "claude")

    def test_kimi_turns_its_shell_off(self):
        self.assertIn("Bash", kimi_home.disabled_tools(), SHELL_GRANT % "kimi")
        for vocabulary in kimi_home.TOOL_VOCABULARY.values():
            with self.subTest(vocabulary=sorted(vocabulary)[:3]):
                self.assertIn("Bash", kimi_home.disabled_tools(vocabulary), SHELL_GRANT % "kimi")

    def test_codex_keeps_its_shell_features_off(self):
        features = codex_host.safety_config()["features"]
        for name in ("shell_tool", "unified_exec", "shell_snapshot"):
            with self.subTest(feature=name):
                self.assertIs(False, features.get(name), SHELL_GRANT % "codex")


if __name__ == "__main__":
    unittest.main()
