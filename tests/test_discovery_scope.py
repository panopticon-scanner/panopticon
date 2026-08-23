"""Scope/delta orchestration tests: base resolution, changed-files parity,
--scope-changed, and --scope-files behavior."""
import json
import types
import unittest
from unittest import mock

from discovery_test_helpers import (
    orchestrator, FakeRun, repo_with_matrix, repo_with_exclude,
    git_cmd, git_output,
)


class TestDeltaOrchestration(unittest.TestCase):
    def test_resolve_base_precedence(self):
        # explicit wins even if others resolve
        self.assertEqual(
            orchestrator.resolve_base(".", explicit="v1.0", pr_base="main",
                              runner=FakeRun({"v1.0^{commit}", "main^{commit}"})),
            ("v1.0", "explicit"))
        self.assertEqual(
            orchestrator.resolve_base(".", pr_base="release",
                              runner=FakeRun({"release^{commit}"}))[1],
            "pr-base")

    def test_resolve_base_bad_explicit_fails_loud_no_fallthrough(self):
        # explicit given but unresolvable -> (None,'unresolved'); NOT main.
        self.assertEqual(
            orchestrator.resolve_base(".", explicit="nope",
                              runner=FakeRun({"main^{commit}"})),
            (None, "unresolved"))

    def test_resolve_base_fallback_and_no_head1(self):
        self.assertEqual(orchestrator.resolve_base(".", runner=FakeRun({"main^{commit}"})),
                         ("main", "fallback"))
        self.assertEqual(orchestrator.resolve_base(".", runner=FakeRun({"master^{commit}"})),
                         ("master", "fallback"))
        # nothing resolves (no main/master, no HEAD~1 tried) -> unresolved
        self.assertEqual(orchestrator.resolve_base(".", runner=FakeRun(set())),
                         (None, "unresolved"))

    def test_prune_fixture_files_standard_vs_redteam(self):
        paths = ["src/app.py", "tests/fixtures/vuln/main.rs"]
        self.assertEqual(orchestrator.prune_fixture_files(paths, include_fixtures=False),
                         ["src/app.py"])
        self.assertEqual(orchestrator.prune_fixture_files(paths, include_fixtures=True), paths)


class TestResolveBaseOriginFallback(unittest.TestCase):
    """#947 FIXME-3: a machine-derived pr_base prefers origin/<name> (fresh
    remote) over a possibly-stale local branch; explicit --base never falls
    through."""

    def _runner_resolving(self, *refs):
        def run(argv, *args, **kwargs):
            class R:
                pass
            r = R()
            ref = argv[-1]
            r.returncode = 0 if ref.rstrip("^{commit}") in refs else 1
            r.stdout = "abc\n" if r.returncode == 0 else ""
            return r
        return run

    def test_pr_base_prefers_origin_ref(self):
        base, src = orchestrator.resolve_base("/r", pr_base="main",
                                      runner=self._runner_resolving("origin/main", "main"))
        self.assertEqual((base, src), ("origin/main", "pr-base"))

    def test_pr_base_falls_back_to_local_when_origin_absent(self):
        base, src = orchestrator.resolve_base("/r", pr_base="main",
                                      runner=self._runner_resolving("main"))
        self.assertEqual((base, src), ("main", "pr-base"))

    def test_explicit_base_never_tries_origin(self):
        base, src = orchestrator.resolve_base("/r", explicit="release-2",
                                      runner=self._runner_resolving("origin/release-2"))
        self.assertEqual((base, src), (None, "unresolved"))


class TestChangedFilesRenameParity(unittest.TestCase):
    """#978: discovery's changed-file diff must use the same rename semantics
    as diff_map.hunk_map (--find-renames), so the reviewed file set and the
    on-diff hunk map can never diverge on a similarity-threshold edge."""

    def test_diff_invocation_includes_find_renames(self):
        calls = []

        def fake_git(repo, args):
            calls.append(list(args))
            r = types.SimpleNamespace(stdout="")
            if args and args[0] == "merge-base":
                r.stdout = "abc123\n"
            return r

        # orch IS discovery (import discovery as orch); patching orch._git
        # patches discovery._git directly, which is also what
        # discovery.collect_changed_files's bare _git(...) global lookup
        # resolves through -- no cross-module duplication needed post-A2.
        with mock.patch.object(orchestrator, "_git", side_effect=fake_git):
            orchestrator.collect_changed_files("/tmp/x", base="main")
        diff_calls = [a for a in calls if a and a[0] == "diff"]
        self.assertTrue(diff_calls, "no git diff invocation captured")
        for a in diff_calls:
            self.assertIn("--find-renames", a)


def test_repo_scan_scope_changed_restricts_and_emits_diff_hunks(tmp_path):
    import discovery as orchestrator
    repo = repo_with_matrix(tmp_path)   # commits Auth + Checkout matrix + files
    # create a new commit changing one checkout file
    (repo / "src/checkout/pay.py").write_text("x=2\n")
    git_cmd(repo, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-aqm", "c2")
    out = repo / ".panopticon" / "groups.json"
    rc = orchestrator.main(["--repo-scan", "--scope-changed", "--base", "HEAD~1",
                            str(repo), "--out", str(out)])
    assert rc == 0
    groups = json.loads(out.read_text())["groups"]
    files = sorted(f for g in groups for f in g["files"])
    assert files == ["src/checkout/pay.py"]                       # restricted to changed
    hunks = json.loads((repo/".panopticon"/"diff-hunks.json").read_text())
    assert hunks["base"] and "src/checkout/pay.py" in hunks["hunks"]


def test_repo_scan_scope_changed_bad_base_exits_2_no_artifact(tmp_path):
    import discovery as orchestrator
    repo = repo_with_matrix(tmp_path)
    out = repo / ".panopticon" / "groups.json"
    assert orchestrator.main(["--repo-scan","--scope-changed","--base","nope", str(repo), "--out", str(out)]) == 2
    assert not (repo/".panopticon"/"diff-hunks.json").exists()


def test_repo_scan_scope_files_with_base_emits_diff_hunks(tmp_path):
    import discovery as orchestrator
    repo = repo_with_matrix(tmp_path)
    (repo / "src/checkout/pay.py").write_text("x=2\n")
    git_cmd(repo, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-aqm", "c2")
    out = repo / ".panopticon" / "groups.json"
    # --repo (not the positional target) precedes --scope-files here -- nargs="+"
    # would otherwise greedily swallow a trailing positional target (same
    # convention as the existing --files tests).
    rc = orchestrator.main(["--repo", str(repo), "--repo-scan", "--scope-files",
                            "src/checkout/pay.py", "--base", "HEAD~1",
                            "--out", str(out)])
    assert rc == 0
    groups = json.loads(out.read_text())["groups"]
    files = sorted(f for g in groups for f in g["files"])
    assert files == ["src/checkout/pay.py"]
    hunks = json.loads((repo/".panopticon"/"diff-hunks.json").read_text())
    assert hunks["base"] and "src/checkout/pay.py" in hunks["hunks"]


def test_repo_scan_scope_files_without_base_emits_no_diff_hunks(tmp_path):
    import discovery as orchestrator
    repo = repo_with_matrix(tmp_path)
    out = repo / ".panopticon" / "groups.json"
    rc = orchestrator.main(["--repo", str(repo), "--repo-scan", "--scope-files",
                            "src/checkout/pay.py", "--out", str(out)])
    assert rc == 0
    groups = json.loads(out.read_text())["groups"]
    files = sorted(f for g in groups for f in g["files"])
    assert files == ["src/checkout/pay.py"]
    assert not (repo/".panopticon"/"diff-hunks.json").exists()


def test_repo_scan_scope_files_applies_exclude_paths(tmp_path):
    # #1136 delta-path parity: --scope-files rebuilds the file set from the
    # user's explicit list, NOT from the exclude-pruned `allf`. A vendored file
    # named in the delta must still be pruned by committed exclude_paths (never
    # grouped/reviewed), and the disclosed count must reflect the delta set (1),
    # not the whole-repo count.
    import discovery as orchestrator
    repo = repo_with_exclude(tmp_path)
    out = repo / ".panopticon" / "groups.json"
    rc = orchestrator.main(["--repo", str(repo), "--repo-scan", "--scope-files",
                            "src/checkout/pay.py", "vendor/dep.py",
                            "--out", str(out)])
    assert rc == 0
    doc = json.loads(out.read_text())
    files = sorted(f for g in doc["groups"] for f in g["files"])
    assert files == ["src/checkout/pay.py"]            # vendor/dep.py pruned
    assert doc["exclude_paths"] == ["vendor/**"]
    assert doc["excluded_count"] == 1                  # delta count, not whole-repo


def test_repo_scan_scope_changed_applies_exclude_paths(tmp_path):
    # Same parity guard on the --scope-changed path (rebuilds from git-diff
    # output). A changed vendored file must not slip past exclude_paths.
    import discovery as orchestrator
    repo = repo_with_exclude(tmp_path)
    (repo / "src/checkout/pay.py").write_text("x=2\n")
    (repo / "vendor/dep.py").write_text("y=2\n")
    git_cmd(repo, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-aqm", "c2")
    out = repo / ".panopticon" / "groups.json"
    rc = orchestrator.main(["--repo-scan", "--scope-changed", "--base", "HEAD~1",
                            str(repo), "--out", str(out)])
    assert rc == 0
    doc = json.loads(out.read_text())
    files = sorted(f for g in doc["groups"] for f in g["files"])
    assert files == ["src/checkout/pay.py"]            # vendor/dep.py pruned
    assert doc["excluded_count"] == 1


def _repo_with_fixture_corpus(tmp_path, exclude_paths=True):
    import os
    repo = tmp_path
    (repo / ".panopticon").mkdir(parents=True)
    for p in ["src/real.py", "tests/fixtures/vuln/app.py"]:
        os.makedirs(os.path.dirname(repo / p), exist_ok=True)
        (repo / p).write_text("x=1\n")
    yml = "groups:\n  Real:\n    match: ['src/**']\n    panels: [SEC]\n"
    if exclude_paths:
        yml += "exclude_paths: ['tests/fixtures/**']\n"
    (repo / ".panopticon" / "groups.yml").write_text(yml)
    git_cmd(repo, "init", "-q")
    git_cmd(repo, "add", "-A")
    git_cmd(repo, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "x")
    return repo


def test_redteam_exclude_paths_prunes_fixture_corpus_before_grouping(tmp_path):
    # #8c regression: redteam mode keeps test-fixture corpora in scope by design
    # (a red team wants the attack surface), so a self-scan of deliberately-
    # vulnerable fixtures leaks noise. A committed top-level `exclude_paths:` must
    # override that inclusion and drop the corpus BEFORE grouping -- so no review
    # cell of ANY domain sees it (SEC included, which per-group `exclude:` cannot
    # silence -- #1084). Run-6 leaked 16 illusory HIGHs precisely because the
    # committed config reached for the `exclude:`-sink, not `exclude_paths:`.
    import discovery as orchestrator
    repo = _repo_with_fixture_corpus(tmp_path, exclude_paths=True)
    out = repo / ".panopticon" / "groups.json"
    rc = orchestrator.main(["--repo", str(repo), "--repo-scan",
                            "--security", "redteam", "--out", str(out)])
    assert rc == 0
    doc = json.loads(out.read_text())
    files = sorted(f for g in doc["groups"] for f in g["files"])
    assert files == ["src/real.py"]                       # fixture corpus pruned
    assert "tests/fixtures/vuln/app.py" not in files
    assert doc["exclude_paths"] == ["tests/fixtures/**"]
    assert doc["excluded_count"] == 1


def test_redteam_without_exclude_paths_keeps_fixture_corpus(tmp_path):
    # Control proving exclude_paths did the work above, not #434 fixture pruning:
    # in redteam mode WITHOUT exclude_paths the fixture corpus IS grouped (the
    # #434 prune is standard-mode-only), which is exactly the run-6 leak vector.
    import discovery as orchestrator
    repo = _repo_with_fixture_corpus(tmp_path, exclude_paths=False)
    out = repo / ".panopticon" / "groups.json"
    rc = orchestrator.main(["--repo", str(repo), "--repo-scan",
                            "--security", "redteam", "--out", str(out)])
    assert rc == 0
    doc = json.loads(out.read_text())
    files = sorted(f for g in doc["groups"] for f in g["files"])
    assert "tests/fixtures/vuln/app.py" in files           # kept -> the leak vector
    assert "exclude_paths" not in doc


def test_repo_scan_scope_changed_pr_base_resolves_origin_only_base(tmp_path):
    # Finding B (B1 regression lock): the gh-detected PR base must flow through
    # the --pr-base channel so resolve_base applies its origin/<base> preference
    # (#947). This repo has the base ONLY as refs/remotes/origin/main -- there is
    # NO local `main` branch -- exactly the shape acquire_pr leaves (it fetches
    # only the PR head). Under the OLD code path (the base threaded as an explicit
    # --base main) resolve_base would treat "main" as explicit, fail to resolve
    # it, and return 2 with no artifact. With --pr-base it resolves to origin/main.
    import discovery as orchestrator
    repo = repo_with_matrix(tmp_path)   # commits Auth + Checkout matrix + files
    base_sha = git_output(repo, "rev-parse", "HEAD").strip()
    # Base lives ONLY as a remote-tracking ref; rename the local default branch
    # away so no local `main` (or `master`) can satisfy an explicit resolve.
    git_cmd(repo, "update-ref", "refs/remotes/origin/main", base_sha)
    git_cmd(repo, "branch", "-m", "work")
    # A committed change on top of the origin/main base so there IS a delta.
    (repo / "src/checkout/pay.py").write_text("x=2\n")
    git_cmd(repo, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-aqm", "c2")
    # Sanity: no local `main` branch exists (only origin/main).
    branches = git_output(repo, "branch", "--format=%(refname:short)").split()
    assert "main" not in branches

    out = repo / ".panopticon" / "groups.json"
    rc = orchestrator.main(["--repo-scan", "--scope-changed", "--pr-base", "main",
                            str(repo), "--out", str(out)])
    assert rc == 0                                              # did NOT return 2
    groups = json.loads(out.read_text())["groups"]
    files = sorted(f for g in groups for f in g["files"])
    assert files == ["src/checkout/pay.py"]                    # restricted to changed
    hunks = json.loads((repo/".panopticon"/"diff-hunks.json").read_text())
    assert hunks["base"] == "origin/main"                      # origin-preference won
    assert "src/checkout/pay.py" in hunks["hunks"]


def test_repo_scan_scope_changed_explicit_base_ignores_pr_base(tmp_path):
    # --base (explicit user override) still takes precedence over --pr-base and
    # never falls through: a bad explicit base fails loudly even when a valid
    # --pr-base is present (resolve_base's explicit-never-fallthrough contract).
    import discovery as orchestrator
    repo = repo_with_matrix(tmp_path)
    out = repo / ".panopticon" / "groups.json"
    rc = orchestrator.main(["--repo-scan", "--scope-changed",
                            "--base", "nope", "--pr-base", "main",
                            str(repo), "--out", str(out)])
    assert rc == 2
    assert not (repo/".panopticon"/"diff-hunks.json").exists()
