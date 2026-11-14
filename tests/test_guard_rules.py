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


class TestASearchOverAKeychainAncestorIsDenied(unittest.TestCase):
    """#3616: the Keychain rule (#3607) is checked on the path a call names, so a recursive
    search over an ANCESTOR of a Keychain directory let the host CLI walk into it. The scope's
    arm-time walk records each grant's Keychain paths, and every host's directory-level search
    and listing over one is denied; a capped, failed or missing walk denies them all. Exact
    reads under the same grant are untouched. A fixture tree in a temp dir, never the real
    Keychain, and no real home is walked."""

    ENV = {"PANOPTICON_ENTRY_ID": "e1"}
    SEARCH = "a macOS Keychain path lies under"
    WALK = "was capped, failed or is missing"

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

    def test_the_walk_records_keychain_paths_without_descending_or_following(self):
        escapes, keychains = guard_rules.grant_walk([self.home])
        self.assertEqual({self.home: sorted([self.kdir, self.loose])}, keychains)
        self.assertEqual({self.home: []}, escapes)      # the link inside the Keychain is unseen
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
                                 ("*", False), ("deep/**", False)):
            with self.subTest(pattern=pattern):
                allow, reason = rg.adjudicate(
                    {"tool_name": "Glob", "tool_input": {"path": self.home, "pattern": pattern}},
                    self.scope, env)
                self.assertEqual(allowed, allow, reason)
                if not allowed:
                    self.assertIn(self.SEARCH, reason)

    def test_a_capped_failed_or_missing_walk_denies_every_directory_tool(self):
        escapes, capped = guard_rules.grant_walk([self.home], cap=1)
        gone = os.path.join(self.home, "gone")
        self.assertEqual(({gone: None}, {gone: None}), guard_rules.grant_walk([gone]))
        armed = rg.scope_from_plan([{"id": "e1", "scope": {"files": [], "dirs": [self.home],
                                                           "reads": []}}])
        cases = {"capped": dict(armed["e1"], escapes=escapes, keychains=capped),
                 "missing": {k: v for k, v in armed["e1"].items() if k != "keychains"},
                 "malformed": dict(armed["e1"], keychains={self.home: "x"})}
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
