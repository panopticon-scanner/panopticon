"""#3701: a directory is matched as it is spelled, and only a pattern is a pattern.

`glob.glob(os.path.join(directory, "findings-*.json"))` reads the directory as part
of the pattern. A review root at `repo[x]/` then found none of its own findings
files, plans, scout replies or coverage files, and lost every agent finding with no
reason given. `scripts.safe_glob.under` escapes the directory, and it is the one
place `skill/scripts` calls `glob`: the ratchet below fails on any other.
"""
import ast
import json
import os
import tempfile
from pathlib import Path
import unittest
from unittest import mock

from tests._test_helpers import REPO_ROOT

import scripts.collect_usage as collect_usage
import scripts.diff_map as diff_map
import scripts.phases.readiness as readiness
import scripts.probes.kimi_snapshot as kimi_snapshot
import scripts.phases.run_artifacts as run_artifacts
import scripts.phases.validate as validate_phase
import scripts.run_manifest as run_manifest
import scripts.runners.kimi as kimi_runner
import scripts.safe_glob as safe_glob
import scripts.synth.cost as cost_mod
import scripts.synth.coverage_io as coverage_io
import scripts.synth.plan as plan_mod
import scripts.tools_manifest as tools_manifest

SCANNED = "skill/scripts"
OWNER = "skill/scripts/safe_glob.py"
#: Loaded under `python -I` with the standard library alone on `sys.path`, so it cannot
#: import this package. It escapes its directory itself; `test_the_exception_escapes`
#: holds it to that.
STDLIB_ONLY = "skill/scripts/guard_rules.py"
MATCHERS = frozenset({"glob", "iglob", "glob0", "glob1"})


def glob_uses(source):
    """The line numbers where `source` reaches the `glob` module's matchers: called or
    just named, through `import glob`, an alias of it, or `from glob import ...`.
    `glob.escape` and `glob.has_magic` match nothing and are not counted; neither is a
    `.glob()` on anything that is not the module (a `pathlib.Path` takes a pattern only)."""
    tree = ast.parse(source)
    modules, names = set(), set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(alias.asname or alias.name for alias in node.names
                           if alias.name == "glob")
        elif isinstance(node, ast.ImportFrom) and node.module == "glob":
            for alias in node.names:
                if alias.name == "*":
                    names.update(MATCHERS)
                elif alias.name in MATCHERS:
                    names.add(alias.asname or alias.name)
    lines = set()
    for node in ast.walk(tree):
        if (isinstance(node, ast.Attribute) and node.attr in MATCHERS
                and isinstance(node.value, ast.Name) and node.value.id in modules):
            lines.add(node.lineno)
        elif isinstance(node, ast.Name) and node.id in names and isinstance(node.ctx, ast.Load):
            lines.add(node.lineno)
    return sorted(lines)


def offenders(root=REPO_ROOT):
    """{relative path: lines} for every scanned module that reaches a matcher."""
    found = {}
    for path in sorted((Path(root) / SCANNED).rglob("*.py")):
        lines = glob_uses(path.read_text(encoding="utf-8"))
        if lines:
            found[path.relative_to(root).as_posix()] = lines
    return found


class TestOnlyTheOwnerCallsGlob(unittest.TestCase):
    def test_no_other_module_reaches_a_matcher(self):
        found = offenders()
        self.assertIn(OWNER, found)
        extra = {path: lines for path, lines in found.items()
                 if path not in (OWNER, STDLIB_ONLY)}
        self.assertEqual({}, extra, "match under a directory with scripts.safe_glob.under, "
                         "which takes the directory as it is spelled")

    def test_the_exception_escapes(self):
        """`guard_rules` cannot import the helper, so its one call is held to the same
        shape: `glob.glob(os.path.join(glob.escape(<directory>), ...))`."""
        with open(os.path.join(REPO_ROOT, STDLIB_ONLY), encoding="utf-8") as fh:
            source = fh.read()
        self.assertEqual(1, len(glob_uses(source)))
        calls = [node for node in ast.walk(ast.parse(source))
                 if isinstance(node, ast.Call) and ast.unparse(node.func) == "glob.glob"]
        self.assertEqual(1, len(calls))
        (pattern,) = calls[0].args
        self.assertEqual("os.path.join", ast.unparse(pattern.func))
        self.assertEqual("glob.escape", ast.unparse(pattern.args[0].func))

    def test_the_detector_sees_every_ordinary_way_to_reach_one(self):
        reaches = ("import glob\nglob.glob(d)\n",
                   "import glob\nglob.iglob(d)\n",
                   "import glob as _glob\n_glob.glob(d)\n",
                   "import os, glob\nglob.glob(os.path.join(d, '*'))\n",
                   "from glob import glob\nglob(d)\n",
                   "from glob import iglob as find\nfind(d)\n",
                   "from glob import *\niglob(d)\n",
                   "import glob\nmatch = glob.glob\nmatch(d)\n",
                   "import glob\nsorted(map(glob.glob, dirs))\n",
                   "def f():\n    import glob\n    return glob.glob(d)\n",
                   "import glob\nglob.glob1(d, '*')\n")
        for source in reaches:
            with self.subTest(source=source):
                self.assertNotEqual([], glob_uses(source))

    def test_the_detector_leaves_what_matches_nothing_alone(self):
        clean = ("import glob\nglob.escape(d)\n",
                 "import glob\nglob.has_magic(d)\n",
                 "from pathlib import Path\nPath(d).glob('*.py')\n",
                 "paths = tree.glob('*')\n",
                 "note = 'glob.glob(d) reads d as a pattern'\n",
                 "import scripts.safe_glob as safe_glob\nsafe_glob.under(d, '*')\n",
                 "def glob(d):\n    return []\nglob(d)\n",
                 "from fnmatch import fnmatch\nfnmatch(name, '*.py')\n")
        for source in clean:
            with self.subTest(source=source):
                self.assertEqual([], glob_uses(source))

    def test_every_module_under_the_scanned_root_is_read(self):
        with tempfile.TemporaryDirectory() as directory:
            expected = {}
            for relative in ("a.py", "phases/b.py", "synth/deep/c.py"):
                path = Path(directory) / SCANNED / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("import glob\n\nglob.glob(d)\n", encoding="utf-8")
                expected["%s/%s" % (SCANNED, relative)] = [3]
            (Path(directory) / SCANNED / "clean.py").write_text("import os\n", encoding="utf-8")
            self.assertEqual(expected, offenders(directory))


class TestUnder(unittest.TestCase):
    def setUp(self):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        self.base = os.path.realpath(d.name)

    def make(self, *parts):
        path = os.path.join(self.base, *parts)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("{}")
        return path

    def test_the_directory_is_taken_as_it_is_spelled(self):
        for name in ("repo[x]", "re*po", "re?po", "repo[!a]", "repo[", "repo]", "[repo]",
                     "repo[a-z]", "repo[[]", "*", "[x]/inner[y]"):
            with self.subTest(name=name):
                mine = self.make(name, "findings-a.json")
                self.assertEqual([mine], safe_glob.under(os.path.join(self.base, name),
                                                         "findings-*.json"))

    def test_a_sibling_the_spelling_would_match_as_a_pattern_is_not_searched(self):
        """`repo[x]` as a pattern is `repox`: the run read another directory's files."""
        self.make("repox", "findings-theirs.json")
        self.make("repoab", "findings-theirs.json")
        for name in ("repo[x]", "repo*", "repo??", "repo[a-z][a-z]"):
            with self.subTest(name=name):
                os.makedirs(os.path.join(self.base, name), exist_ok=True)
                self.assertEqual([], safe_glob.under(os.path.join(self.base, name),
                                                     "findings-*.json"))
                mine = self.make(name, "findings-mine.json")
                self.assertEqual([mine], safe_glob.under(os.path.join(self.base, name),
                                                         "findings-*.json"))

    def test_the_pattern_is_still_a_pattern_in_every_part(self):
        root = os.path.join(self.base, "home[1]")
        wires = sorted(self.make("home[1]", "sessions", day, session, "wire.jsonl")
                       for day, session in (("d1", "s1"), ("d1", "s2"), ("d2", "s3")))
        self.make("home[1]", "sessions", "d1", "s1", "other.txt")
        self.assertEqual(wires, sorted(safe_glob.under(root, "sessions", "*", "*", "wire.jsonl")))
        self.assertEqual(wires[:2], sorted(safe_glob.under(root, "sessions", "d1", "s?",
                                                           "wire.jsonl")))
        self.assertEqual(wires[2:], safe_glob.under(root, "sessions", "*", "s[3-9]", "*.jsonl"))
        self.assertEqual([], safe_glob.under(root, "sessions", "*", "*", "nothing-*"))

    def test_a_directory_that_is_not_there_matches_nothing(self):
        self.assertEqual([], safe_glob.under(os.path.join(self.base, "absent[x]"), "*"))

    def test_a_path_object_is_a_directory_too(self):
        mine = self.make("repo[x]", "a.json")
        self.assertEqual([mine], safe_glob.under(Path(self.base) / "repo[x]", "*.json"))


class TestEveryReaderOfADirectoryTakesItAsSpelled(unittest.TestCase):
    """Each site that used to glob with its directory in the pattern, under a directory
    named `x[y]`, with a decoy in the sibling `xy` that the name matches as a pattern."""

    NAME, DECOY = "x[y]", "xy"

    def setUp(self):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        self.base = os.path.realpath(d.name)
        self.here = os.path.join(self.base, self.NAME)
        self.decoy = os.path.join(self.base, self.DECOY)

    def write(self, root, relative, document):
        path = os.path.join(root, relative)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(document if isinstance(document, str) else json.dumps(document))
        return path

    def both(self, relative, mine, theirs):
        self.write(self.decoy, relative, theirs)
        return self.write(self.here, relative, mine)

    def test_the_dispatch_plans(self):
        mine = [{"group": "mine", "domain": "SEC", "out_file": "findings-mine-SEC.json"}]
        self.both("dispatch-plan-driver.json", mine,
                  [{"group": "theirs", "domain": "SEC", "out_file": "findings-theirs-SEC.json"}])
        plans, seen, invalid = plan_mod.load_dispatch_plans_detailed(self.here)
        self.assertEqual(([mine], 1, []), (plans, seen, invalid))
        self.assertEqual([mine], plan_mod.load_dispatch_plans(self.here))

    def test_the_scout_replies(self):
        self.both("scout-app.json", {"domains": [], "files": [], "tools": ["semgrep"]},
                  {"domains": [], "files": [], "tools": ["bandit"]})
        self.assertEqual(({"semgrep"}, 1), plan_mod.load_scout_requests(self.here))

    def test_the_coverage_files(self):
        self.both("coverage-app.json", {"group": "mine", "effective": ["SEC"]},
                  {"group": "theirs", "effective": ["SEC"]})
        self.assertEqual(["mine"], [cell["group"]
                                    for cell in coverage_io.load_coverage_files(self.here)])

    def test_the_dispatch_counts(self):
        self.both("dispatch-plan-driver.json",
                  [{"group": "app", "domain": "SEC", "out_file": "findings-app-SEC.json"}], [])
        for name in ("verdicts-app-SEC.json", "verdicts-app-SEC-backup.json", "0123abcd.json"):
            self.write(self.here, os.path.join("verdicts", name), {})
        for folder in (None, os.path.join(self.here, "verdicts")):
            with self.subTest(verdicts_dir=folder):
                counts = cost_mod.driver_cost_counts(self.here, folder, [])
                self.assertEqual((1, 1, 1, 1), tuple(counts[key] for key in (
                    "review_cells", "verify_primary", "verify_backup", "verify_tools")))

    def test_the_reset_sweep(self):
        """`--reset` cleared nothing under such a root, and said nothing."""
        stale = ("findings-app-SEC.json", "coverage-app.json", "scout-app.json",
                 "verify-attempts.json", "dispatch-plan-driver.json")
        kept = [self.write(self.decoy, os.path.join(".panopticon", name), "theirs")
                for name in stale]
        mine = [self.write(self.here, os.path.join(".panopticon", name), "stale")
                for name in stale]
        run_artifacts._clear_run_artifacts(self.here)
        self.assertEqual([], [path for path in mine if os.path.exists(path)])
        self.assertEqual(kept, [path for path in kept if os.path.exists(path)])

    def test_the_report_parts_surfaced_from_a_worktree(self):
        target = os.path.join(self.base, "target")
        manifest = {"run_id": "R", "worktree": self.here, "target": target}
        tag = run_manifest.run_tag(manifest)
        parts = ("report.json", "report_part2.json", "report-discarded.json")
        for part in parts:
            self.write(self.here, os.path.join(".panopticon", "%s-%s" % (tag, part)), {"p": part})
            self.write(self.decoy, os.path.join(".panopticon", "%s-%s" % (tag, part)), {"p": "x"})
        os.makedirs(target)
        with mock.patch.object(diff_map, "release_worktree"):
            validate_phase._finalize_worktree(self.here, manifest)
        for part in parts:
            with open(os.path.join(target, ".panopticon", "%s-%s" % (tag, part)),
                      encoding="utf-8") as fh:
                self.assertEqual({"p": part}, json.load(fh))

    def test_a_sub_skill_under_such_a_home(self):
        mine = self.write(self.here, os.path.join("plugins", "vendor", "skills", "leaf", "SKILL.md"), "#")
        self.write(self.decoy, os.path.join("plugins", "leaf", "SKILL.md"), "#")
        with mock.patch.object(readiness, "SUB_SKILL_ROOTS", (os.path.join(self.here, "plugins"),)):
            self.assertEqual(mine, readiness._find_sub_skill("leaf"))

    def test_the_hosts_transcripts(self):
        project = os.path.join(self.base, "project")
        slug = collect_usage.project_slug(project)
        mine = self.write(self.here, os.path.join(".claude", "projects", slug, "s1.jsonl"), "")
        self.write(self.decoy, os.path.join(".claude", "projects", slug, "s2.jsonl"), "")
        self.assertEqual(mine, collect_usage.find_controller_transcript(project, home=self.here))
        tasks = [self.write(self.here, os.path.join("tasks", name), "") for name in ("a", "b")]
        self.write(self.decoy, os.path.join("tasks", "c"), "")
        self.assertEqual(tasks, collect_usage.find_task_transcripts(
            None, tasks_dir=os.path.join(self.here, "tasks")))
        agents = [
            self.write(self.here, os.path.join(".claude", "projects", slug, "s1", "subagents",
                                               "agent-1.jsonl"), ""),
            self.write(self.here, os.path.join(".claude", "projects", slug, "s1", "subagents",
                                               "workflows", "w", "agent-2.jsonl"), "")]
        self.assertEqual(sorted(agents), sorted(collect_usage.find_task_transcripts(mine)))

    def test_the_dependency_manifests_of_a_target(self):
        self.write(self.decoy, "requirements-dev.txt", "x==1\n")
        os.makedirs(self.here)
        self.assertEqual([], tools_manifest.dependency_audit_applicable(self.here))
        self.write(self.here, "requirements-dev.txt", "x==1\n")
        self.assertEqual(["python"], tools_manifest.dependency_audit_applicable(self.here))

    def test_the_kimi_wire_files(self):
        wire = os.path.join("sessions", "d", "s1", "agents", "main", "wire.jsonl")
        mine = self.write(self.here, wire, "")
        self.write(self.decoy, wire.replace("s1", "s2"), "")
        self.assertEqual(mine, kimi_runner.wire_path(self.here, "s1"))
        self.assertIsNone(kimi_runner.wire_path(self.here, "s2"))

    def test_the_kimi_tool_snapshots(self):
        record = {"type": "llm.tools_snapshot", "tools": ["Read"], "agent": "mine.md"}
        wire = os.path.join("sessions", "d", "s1", "agents", "main", "wire.jsonl")
        mine = self.write(self.here, wire, json.dumps(record) + "\n")
        self.write(self.decoy, wire, json.dumps(dict(record, agent="theirs.md")) + "\n")
        self.assertEqual(([({"Read"}, "mine", mine)], ""),
                         kimi_snapshot._kimi_wire_snapshots(self.here))


if __name__ == "__main__":
    unittest.main()
