"""Surface filtering and scope resolution for discovery."""
import fnmatch
import os
import subprocess
import sys

from scripts import claim_scope
from scripts import discovery_catalog
from scripts import dot_paths
from scripts import safe_git
from scripts import tests_axis


# Directory NAMES pruned from --repo-scan discovery walking. These are build
# artifacts, dependency trees, caches, VCS internals, and scratch/audit copies
# that otherwise dominate the discovered group set (real runs: ~90% of files
# venv/cache trees; 34 of 63 groups stale tmp/audit-* copies). Matched by exact
# basename at every depth. Keep this list as the single maintenance point:
# codex_read_tools.EXCLUDED_DIRECTORIES is a stdlib-only COPY of it (that
# broker launches under `python -I` and cannot import this module), and a
# parity test fails if the two drift apart.
EXCLUDE_DIRS = frozenset({
    ".git", ".hg", ".svn",          # VCS internals
    ".venv", "venv", "node_modules",  # dependency / virtualenv trees
    "__pycache__",                  # bytecode cache
    ".pytest_cache", ".mypy_cache", ".ruff_cache", ".tox",  # tool caches
    "htmlcov", ".eggs",             # coverage / build artifacts
    "tmp",                          # scratch + audit copies
})

# Directory basename GLOBS pruned from discovery (e.g. "<pkg>.egg-info").
EXCLUDE_DIR_GLOBS = ("*.egg-info",)

# Test-fixture corpus markers (#434). Intentionally-vulnerable fixture apps
# under these roots dominate standard self-scans when discovery hands them to
# review agents (run-3: 67 findings incl. 11 CRITICAL, all planted noise) —
# the same rationale as ingest_tools' F-CAL-2 exclude_globs, extended to the
# agentic path. Pruned only in standard mode; redteam scans include them (a
# red team wants the whole attack surface). A dir merely named "fixtures"
# outside a test parent is real code and is NOT a marker.
FIXTURE_DIR_BASENAMES = frozenset({"testdata", "__fixtures__"})
FIXTURE_PARENT_DIRS = frozenset({"tests", "test", "spec"})
def _git(repo, args, timeout=30, text=True):
    """Run a trusted, bounded git probe in repo with check=True -- the shared
    invocation for discovery's six git call sites; each caller's try/except
    owns failures.

    #2006: `repo` is the TARGET. This used to launch bare `git` off the
    inherited PATH with the target's own config live, so a target that set
    `core.fsmonitor` (or a `filter.*.clean` on a file `status` must compare)
    got its command RUN during discovery -- reproduced through
    `_worktree_dirty`, which runs before dispatch. `safe_git.probe` resolves
    git outside the target's outermost checkout, launches it with a fresh
    allowlisted environment and `core.fsmonitor=false`, and preflights the
    target's effective config so a command filter is refused rather than
    executed. That refusal arrives as OSError, which every caller's
    `except Exception` already treats as "git failed" -- loud, never an
    empty answer that reads as clean."""
    proc = safe_git.probe(repo, list(args), timeout=timeout, text=text)
    if proc.returncode != 0:
        raise subprocess.CalledProcessError(proc.returncode, proc.args,
                                            proc.stdout, proc.stderr)
    return proc
def test_candidates(path):
    """Generate candidate test file paths for a given implementation file."""
    d, base = os.path.split(path)
    stem, ext = os.path.splitext(base)
    names = []
    if ext == ".rb":
        names = ["%s_spec%s" % (stem, ext), "%s_test%s" % (stem, ext)]
    elif ext == ".go":
        names = ["%s_test%s" % (stem, ext)]
    elif ext in (".ts", ".tsx", ".js", ".jsx"):
        names = ["%s.test%s" % (stem, ext), "%s.spec%s" % (stem, ext)]
    elif ext == ".py":
        names = ["test_%s.py" % stem, "%s_test.py" % stem]
    elif ext == ".java":
        names = ["%sTest.java" % stem]
    elif ext == ".cs":
        names = ["%sTests.cs" % stem]
    dirs = [d]
    if d.startswith("app/"):
        dirs.append("spec/" + d[len("app/"):])
    if d.startswith("src/"):
        dirs.append("test/" + d[len("src/"):])
        dirs.append("tests/" + d[len("src/"):])
    dirs += ["spec", "test", "tests"]
    cands = []
    for dd in dirs:
        for nm in names:
            cands.append((dd + "/" + nm) if dd else nm)
    return cands

def related_tests(repo, impl_files):
    """Find test files related to given implementation files."""
    found = set()
    for f in impl_files:
        for cand in test_candidates(f):
            if os.path.isfile(os.path.join(repo, cand)):
                found.add(cand.replace(os.sep, "/"))
    return sorted(found)

def _is_excluded_dir(name):
    """Return True if a directory basename is discovery noise (denylist)."""
    if name in EXCLUDE_DIRS:
        return True
    return any(fnmatch.fnmatch(name, g) for g in EXCLUDE_DIR_GLOBS)

def _is_fixture_dir(rel):
    """True if a repo-relative dir path is a test-fixture corpus root (#434)."""
    parts = rel.split("/")
    if parts[-1] in FIXTURE_DIR_BASENAMES:
        return True
    return (parts[-1] == "fixtures" and len(parts) >= 2
            and parts[-2] in FIXTURE_PARENT_DIRS)

def _ancestor_dirs(rel):
    parts = rel.split("/")
    return ["/".join(parts[:i]) for i in range(1, len(parts))]  # excludes the file itself

def prune_fixture_files(paths, include_fixtures):
    """Drop files under a fixture corpus dir (standard mode); keep all in redteam."""
    if include_fixtures:
        return list(paths)
    return [p for p in paths if not any(_is_fixture_dir(d) for d in _ancestor_dirs(p))]
# #1576 (run-13 OPS-4065418712): the most reviewable files one discovery hands
# back. Exclusion, partitioning, the four narrowing scopes and max_per_group
# chunking all run on the list this bound already built, so none of them bound it.
# Chosen well above any real target: the largest repository in the calibration pool
# is ~35k files, so only a runaway or hostile tree can reach it.
DISCOVERED_FILES_MAX = 200_000


def _cap_discovered(files, info):
    """`files` bounded to DISCOVERED_FILES_MAX, disclosing what it dropped.

    The input is sorted, so the kept prefix is deterministic rather than whichever
    paths the filesystem or the index happened to yield first. Records `files_seen`
    / `files_truncated` on `info` when the caller supplied one.
    """
    seen = len(files)
    if info is not None:
        info["files_seen"] = seen
        info["files_truncated"] = max(0, seen - DISCOVERED_FILES_MAX)
    if seen <= DISCOVERED_FILES_MAX:
        return files
    print("panopticon: discovery found %d reviewable files and is reviewing the "
          "first %d (DISCOVERED_FILES_MAX); %d file(s) are NOT in this run's "
          "surface" % (seen, DISCOVERED_FILES_MAX, seen - DISCOVERED_FILES_MAX),
          file=sys.stderr)
    return files[:DISCOVERED_FILES_MAX]
def _is_confined_regular(repo, rel):
    """True for a non-symlink regular file whose target remains in *repo*."""
    full = os.path.join(repo, rel)
    return (not os.path.islink(full) and os.path.isfile(full)
            and claim_scope.confined_to_root(repo, rel))

_PRUNE_CLASSES = ("dot_path", "exclude_dir", "git_segment")   # #2377 disclosure

def _filter_reviewable(paths, include_fixtures, pruned_fixtures, isfile, info=None):
    """Apply the discovery policy to a candidate path list.

    One filter for every file list discovery builds (#2272), so each gets
    the treatment the walk applies inline: EXCLUDE_DIRS / EXCLUDE_DIR_GLOBS on every
    ancestor segment (a repo that TRACKS node_modules still shouldn't review it), the
    one ``dot_paths.allowed`` policy, the #434 fixture prune (recorded in
    ``pruned_fixtures``), and the ``.git``-segment drop: a gitlink or nested-repo
    artifact is never a reviewable file (#500 saw ``design-system/.git`` leak into
    group lists). ``isfile`` is injected so the pure filtering logic stays
    unit-testable; on the git path it also drops gitlink directory entries and index
    entries deleted from disk.

    Everything but the fixture prune dropped SILENTLY on both paths until #2377, so
    ``info``, when a dict, gets a per-class count in ``info["pruned"]`` -- counted
    HERE, where one place serves both paths, and printed once per run from the
    block rather than once per path.
    """
    pruned = dict.fromkeys(_PRUNE_CLASSES, 0)
    if info is not None:
        info["pruned"] = pruned              # a FRESH dict: the last pass wins
    out = []
    for rel in sorted(set(paths)):
        parts = rel.split("/")
        if ".git" in parts:                  # first: it is also a dot path
            pruned["git_segment"] += 1
            continue
        if not dot_paths.allowed(rel):
            pruned["dot_path"] += 1
            continue
        skip = False
        for j, seg in enumerate(parts[:-1]):
            prefix = "/".join(parts[:j + 1])
            if _is_excluded_dir(seg):
                pruned["exclude_dir"] += 1
                skip = True
                break
            if not include_fixtures and _is_fixture_dir(prefix):
                if pruned_fixtures is not None and prefix not in pruned_fixtures:
                    pruned_fixtures.append(prefix)
                skip = True
                break
        if skip or not isfile(rel):
            continue
        out.append(rel)
    return out
def _norm_scope_path(repo, p):
    """Normalize a --scope-file/--scope-files path to the repo-relative spelling
    discover_repo_files keys on (#5.0-17): relativize an absolute path under
    repo, strip a leading './', collapse '..', forward slashes. So `-f
    ./src/app.py` and `-f /abs/repo/src/app.py` both match the discovered
    `src/app.py` instead of hard-failing 'not found among discovered repo files'."""
    p = str(p or "")
    if os.path.isabs(p):
        try:
            p = os.path.relpath(p, repo)
        except ValueError:
            pass
    return os.path.normpath(p).replace(os.sep, "/") if p else p


_SCOPE_ECHO_LIMIT = 200


def _echo_scope_path(raw):
    """One operator-supplied path, bounded, for a one-line stderr refusal: the
    value is argv, and an unbounded echo of argv is a diagnostic nobody reads."""
    s = str(raw or "")
    return repr(s[:_SCOPE_ECHO_LIMIT] + "…" if len(s) > _SCOPE_ECHO_LIMIT
                else s)


def _confine_scope_path(repo, raw, universe, flag):
    """Normalize ONE operator-supplied scope path and refuse it unless it names
    a file of the target tree. Returns the repo-relative spelling, or None
    after printing the refusal -- the caller exits 2.

    #2023: the singular `--scope-file` refused anything not among the discovered
    files; the plural `--scope-files` only normalized and pruned, so
    `--files ../../../../private/tmp/x` was accepted and landed verbatim in
    groups.json -- and from there in the dispatch plan, the reviewed file set
    and a report attached to a PR, naming a path that was never in the
    repository. BOTH branches route through here so the two cannot drift apart
    again; test_discovery_scope.py pins that by mutating this function and
    requiring both to refuse.

    Two conditions. ``claim_scope.confined_to_root`` is the confinement proper:
    it compares realpaths, so neither a `..` walk nor a symlink whose target
    leaves the tree resolves inside the root. It is handed the NORMALIZED
    repo-relative path and never `os.path.join(repo, p)`, because it joins onto
    the root itself (#2450). Membership in ``universe`` -- the caller's reviewed
    file set -- is the narrower one: a path can sit inside the repo and still
    not be a file this scan reviews (untracked, gitignored, nonexistent, or a
    fixture corpus in standard mode). An empty entry normalizes to "" and the
    predicate refuses it outright, which is the true answer for it.
    """
    p = _norm_scope_path(repo, raw)
    if not claim_scope.confined_to_root(repo, p):
        print("%s %s resolves outside the repository root %s"
              % (flag, _echo_scope_path(raw), _echo_scope_path(repo)),
              file=sys.stderr)
        return None
    if p not in universe:
        print("%s %s not found among discovered repo files"
              % (flag, _echo_scope_path(raw)), file=sys.stderr)
        return None
    return p
def _resolve_scope(args, repo, allf, catalog, info, pruned_fixtures, excluded_files,
                   carved_files, _apply_exclude):
    """The four --scope-* resolvers: (scoped, excluded, carved), or the exit code (#3395)."""
    scoped = None
    if args.scope_group:
        if args.scope_group not in catalog:
            print("unknown group %r for --scope-group" % args.scope_group,
                  file=sys.stderr)
            return 2
        assigned, _, _ = discovery_catalog.assign_scoped(
            allf, catalog,
            prefixes=tests_axis.distinguishing_prefixes(catalog))
        scoped = assigned.get(args.scope_group, [])
        carved_files = []           # #1757: carved files reach no catalog group
        if not scoped:
            # The third member of --scope-file/--scope-dir's family: a group
            # that EXISTS in the committed matrix but whose `match` assigns no
            # tracked file. Exiting 0 with `groups: []` made the scope's own
            # mistake look like a finished scan -- and, since #1643, made the
            # driver end the run blaming the artifact instead of the flag.
            print("--scope-group %r matched no tracked files"
                  % args.scope_group, file=sys.stderr)
            return 2
    elif args.scope_dir:
        d = args.scope_dir.strip("/") + "/"
        scoped = [f for f in allf if f.startswith(d)]
        carved_files = [f for f in carved_files if f.startswith(d)]      # #1757
        if not scoped:
            print("--scope-dir %r matched no tracked files"
                  % args.scope_dir, file=sys.stderr)
            return 2
    elif args.scope_file is not None:
        # `is not None`, not truthiness: `-f ""` (an unset shell variable) used to skip
        # this branch and review the WHOLE repository at rc 0; the helper refuses an
        # empty entry, normalizes (#5.0-17) and clamps to the repo, as it does for the
        # plural (#2023). `allf` is this branch's whole universe: nothing prunes after
        # it, so a path the committed `exclude_paths:` already dropped must refuse here.
        sf = _confine_scope_path(repo, args.scope_file, allf, "--scope-file")
        if sf is None:
            return 2
        scoped = [sf] + [t for t in related_tests(repo, [sf]) if t in allf]
        carved_files = []           # #1757: `sf` came OUT of pruned `allf`
    elif args.scope_files:
        # #2023: confine EVERY entry the way the singular confines its one --
        # inside the repo root, and a file this scan discovered -- BEFORE any of
        # them can reach groups.json and the artifacts downstream of it. Fail
        # closed on the first bad entry: a silent drop would hand the operator a
        # narrower review than the one they asked for, with no line saying so.
        #
        # The universe rejoins `excluded_files` because a committed
        # `exclude_paths:` glob is review-scope policy, not confinement, and
        # #1136 requires a named-but-excluded file to be PRUNED from the scope
        # (rc 0, disclosed in `excluded_count`) rather than refuse the run.
        # `_apply_exclude` below is what prunes it, so every entry that survives this
        # branch is in `allf` -- the same invariant the singular gets from its own
        # membership test. `prune_fixture_files` cannot fire on that universe any more
        # (standard mode pruned the corpora before `excluded_files` came off the
        # listing, redteam keeps them); it stays for a universe that ever widens.
        universe = set(allf) | set(excluded_files) | set(carved_files)
        entries: list[str] = []
        for raw in args.scope_files:
            p = _confine_scope_path(repo, raw, universe, "--scope-files")
            if p is None:
                return 2
            entries.append(p)
        scoped = prune_fixture_files(entries, args.security == "redteam")
        scoped, excluded_files, carved_files = _apply_exclude(scoped)  # parity (#1136)
    return scoped, excluded_files, carved_files
