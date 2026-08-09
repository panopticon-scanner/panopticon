#!/usr/bin/env python3
"""Resolve panopticon targets (files, dirs, groups, repos) to grouped file
lists. Stdlib-only; run BEFORE dispatching review subagents.
"""
import argparse
import fnmatch
import functools
import glob
import json
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import diff_map  # noqa: E402 (sibling on sys.path, same pattern as dispatch.py)

DEFAULT_MAX_PER_GROUP = 15

PANEL_PRIORITY = ["security", "redteam", "architecture", "database", "code", "test"]


def panels_in_priority_order(panels):
    """Sort panel names by PANEL_PRIORITY; unknown panels sort last (stable)."""
    return sorted(panels, key=lambda p: PANEL_PRIORITY.index(p)
                  if p in PANEL_PRIORITY else len(PANEL_PRIORITY))


# Directory NAMES pruned from --repo-scan discovery walking. These are build
# artifacts, dependency trees, caches, VCS internals, and scratch/audit copies
# that otherwise dominate the discovered group set (real runs: ~90% of files
# venv/cache trees; 34 of 63 groups stale tmp/audit-* copies). Matched by exact
# basename at every depth. Keep this list as the single maintenance point.
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

# Dot-dir subtrees that ARE reviewable and must survive the blanket dotdir skip.
# Targeted on purpose: .github/workflows is a top-risk CI/CD surface. Do NOT
# widen this to all dotdirs — that reintroduces .git / .venv noise.
ALLOWED_DOTDIR_SUBTREES = (".github/workflows",)

TEST_PATTERNS = [
    r"_spec\.rb$",
    r"_test\.rb$",
    r"_test\.go$",
    r"\.test\.[cm]?[jt]sx?$",   # .test.js/ts/jsx/tsx + .test.mjs/cjs/mts/cts
    r"\.spec\.[cm]?[jt]sx?$",   # .spec.js/ts/... + ESM/CJS variants
    r"(^|/)__tests__/",          # Jest/Mocha suites by directory, any suffix
    r"(^|/)test_[^/]+\.py$",
    r"_tests?\.py$",             # foo_test.py AND foo_tests.py (plural)
    r"Test\.java$",
    r"Tests\.cs$",
    r"Test\.php$",               # PHPUnit
    r"_test\.exs$",              # Elixir ExUnit
]

ARCHITECTURE_PATTERNS = [
    r"(^|/)(\.github|\.circleci|\.gitlab)/",
    r"(^|/)Dockerfile",
    r"(^|/)docker-compose",
    r"(^|/)(k8s|kubernetes|helm|charts)/",
    r"(^|/)\.dockerignore$",
    r"(^|/)\.editorconfig$",
    r"(^|/)\.gitignore$",
    r"(^|/)(README|CONTRIBUTING|LICENSE)",
]

DATABASE_PATTERNS = [
    r"\.sql$",
    r"(^|/)(migrations|migrate)/",
    r"(_migration|\.migration)\.",
]


def is_test_file(path):
    """Return True if path matches any test file pattern."""
    return any(re.search(p, path) for p in TEST_PATTERNS)


def is_architecture_file(path):
    """Return True if path matches any architecture/infrastructure pattern."""
    return any(re.search(p, path) for p in ARCHITECTURE_PATTERNS)


def is_database_file(path):
    """Return True if path matches any database/migration pattern."""
    return any(re.search(p, path) for p in DATABASE_PATTERNS)


def compute_group_surfaces(files):
    """Return architecture/database surface labels for a group of files.

    These surface labels travel with the group metadata so the scout and the
    dispatch template can reason about repo-scope / data surfaces without
    re-deriving them from filenames.
    """
    surfaces = set()
    for f in files:
        if is_architecture_file(f):
            surfaces.add("architecture")
        if is_database_file(f):
            surfaces.add("database")
    return sorted(surfaces)


def compute_group_panels(files, security_mode="standard"):
    """Return default panel schedule for a group.

    Panels are a starting plan; the scout may refine them based on the actual
    code surfaces. In redteam mode the security panel is replaced by redteam.
    """
    panels = ["code"]
    if any(is_test_file(f) for f in files):
        panels.append("test")
    if security_mode == "redteam":
        panels.append("redteam")
    else:
        panels.append("security")
    if any(is_architecture_file(f) for f in files):
        panels.append("architecture")
    if any(is_database_file(f) for f in files):
        panels.append("database")
    return panels_in_priority_order(panels)


def _git(repo, args, timeout=30):
    """Run git -C repo with check=True — the shared invocation for this
    module's six git call sites; each caller's try/except owns failures."""
    return subprocess.run(["git", "-C", repo, *args],
                          capture_output=True, text=True, check=True,
                          timeout=timeout)


def collect_changed_files(repo, base=None):
    """Collect repo-relative paths changed since the merge base (or HEAD~1).

    When ``base`` is given (a resolved ref name or sha), the changed set is
    computed against ``merge-base(HEAD, base)`` -- the SAME computation
    ``diff_map.hunk_map`` uses to build the on-diff hunk map -- with NO
    HEAD~1 fallback: an unresolvable ``base`` returns None (a bad delta base
    is a loud failure upstream, never a silent downgrade). This keeps the
    reviewed file set and the on-diff hunk map scoped to one shared base.

    When ``base`` is None (legacy/no-delta callers), tries the default
    upstream branches (main, then master) first and falls back to HEAD~1 only
    as the last resort of THIS no-base path.

    Only files that still exist in the working tree are returned. Returns
    None if no git history is available.
    """
    if base is not None:
        try:
            mb = _git(repo, ["merge-base", "HEAD", base]).stdout.strip()
        except Exception:
            return None
        if not mb:
            return None
    else:
        mb = None
        for branch in ("main", "master"):
            try:
                mb = _git(repo, ["merge-base", "HEAD", branch]).stdout.strip()
                if mb:
                    break
            except Exception:
                continue
        if not mb:
            try:
                mb = _git(repo, ["rev-parse", "HEAD~1"]).stdout.strip()
            except Exception:
                return None
    changed = set()
    try:
        out = _git(repo, ["diff", "--name-only", "--diff-filter=d", mb])
        for p in out.stdout.splitlines():
            p = p.strip()
            if p:
                changed.add(p)
    except Exception:
        return None
    # Include new untracked files so a branch with only added files isn't empty.
    try:
        out = _git(repo, ["ls-files", "--others", "--exclude-standard"])
        for p in out.stdout.splitlines():
            p = p.strip()
            if p:
                changed.add(p)
    except Exception:
        pass
    out = []
    for p in sorted(changed):
        full = os.path.join(repo, p)
        if os.path.isfile(full) and _within(repo, full):
            out.append(p.replace(os.sep, "/"))
    return out


def chunk_files(files, max_per=15):
    """Group files into balanced chunks by directory, each with at most max_per files."""
    if max_per < 1:
        raise ValueError("max_per must be >= 1")
    by_dir = {}
    for f in files:
        by_dir.setdefault(os.path.dirname(f), []).append(f)
    blocks = []
    for d in sorted(by_dir):
        members = sorted(by_dir[d])
        for i in range(0, len(members), max_per):
            blocks.append(members[i:i + max_per])
    chunks, cur = [], []
    for block in blocks:
        if cur and len(cur) + len(block) > max_per:
            chunks.append(cur)
            cur = []
        cur.extend(block)
    if cur:
        chunks.append(cur)
    return chunks


def parse_group_arg(arg):
    """Parse group name and optional facet from group[facet] format."""
    m = re.match(r"^\s*([^\[\]]+?)\s*(?:\[\s*([^\[\]]+?)\s*\])?\s*$", arg)
    if not m:
        return arg.strip(), None
    return m.group(1), m.group(2)


def _split_inline_list(rest):
    return [x.strip().strip("'\"") for x in rest[1:-1].split(",") if x.strip()]


def _glob_to_re(pat):
    """Compile one gitignore-flavored glob to a regex over repo-relative paths.

    Semantics (#499): ``*`` and ``?`` stay within a path segment, ``**``
    crosses segments, and a pattern containing no ``/`` matches the basename
    at any depth (gitignore's unanchored form). Patterns with a ``/`` are
    anchored to the repo root.
    """
    anchored = "/" in pat
    out, i = [], 0
    while i < len(pat):
        c = pat[i]
        if c == "*":
            if pat[i:i + 3] == "**/":
                out.append(r"(?:[^/]+/)*")
                i += 3
            elif pat[i:i + 2] == "**":
                out.append(r".*")
                i += 2
            else:
                out.append(r"[^/]*")
                i += 1
        elif c == "?":
            out.append(r"[^/]")
            i += 1
        else:
            out.append(re.escape(c))
            i += 1
    body = "".join(out)
    if not anchored:
        body = r"(?:.*/)?" + body
    return re.compile("^" + body + "$")


def match_patterns(path, patterns):
    """gitignore-style decision for one path against an ordered pattern list.

    Later patterns override earlier ones (last match wins); a ``!`` prefix
    negates, so ``["skill/scripts/**", "!skill/scripts/tools/**"]`` claims
    the scripts tree except the tools subtree.
    """
    matched = False
    for pat in patterns:
        negate = pat.startswith("!")
        if negate:
            pat = pat[1:]
        if _glob_to_re(pat).match(path):
            matched = not negate
    return matched


def assign_by_catalog(files, catalog):
    """Assign files to catalog groups that declare ``match`` patterns (#499).

    Groups claim files in catalog order, first match wins, each file lands in
    at most one group. Returns ``(assigned, leftovers)`` where ``assigned``
    maps group name -> sorted files (empty groups omitted) and ``leftovers``
    are files no group matched — the coverage gap the caller must disclose.
    """
    # Precompile each group's patterns once so regexes are not rebuilt per file.
    matchable = []
    for name, g in catalog.items():
        if g.get("match"):
            compiled = []
            for pat in g["match"]:
                negate = pat.startswith("!")
                compiled.append((negate, _glob_to_re(pat[1:] if negate else pat)))
            matchable.append((name, compiled))
    assigned = {name: [] for name, _ in matchable}
    leftovers = []
    for f in files:
        for name, compiled in matchable:
            matched = False
            for negate, rx in compiled:
                if rx.match(f):
                    matched = not negate
            if matched:
                assigned[name].append(f)
                break
        else:
            leftovers.append(f)
    return ({n: sorted(fs) for n, fs in assigned.items() if fs},
            sorted(leftovers))


def _parse_catalog_yaml(text):
    """Parse the documented catalog structure (2-space indent):

        groups:
          <Group>:
            patterns:
              - <glob>            # or: patterns: [<glob>, ...]
            facets:
              <Facet>: [<kw>, ...]  # or block list under the facet name
    """
    groups = {}
    group = None      # current group name
    section = None    # "patterns" | "facets"
    facet = None      # current facet name (within facets)
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip(" "))
        stripped = line.strip()
        if indent == 0:
            if stripped.rstrip(":") != "groups":
                raise ValueError("expected top-level 'groups:'")
            continue
        if indent == 2 and stripped.endswith(":"):
            group = stripped[:-1].strip()
            groups[group] = {"patterns": [], "facets": {}, "match": []}
            section = None
            facet = None
            continue
        if indent == 4:
            key, _, rest = stripped.partition(":")
            key = key.strip()
            rest = rest.strip()
            if key in ("patterns", "match"):
                section = key
                facet = None
                if rest.startswith("[") and rest.endswith("]"):
                    groups[group][key] = _split_inline_list(rest)
                    section = None
            elif key == "facets":
                section = "facets"
                facet = None
            else:
                raise ValueError("unexpected key at indent 4: %r" % key)
            continue
        if indent == 6:
            if section in ("patterns", "match") and stripped.startswith("- "):
                groups[group][section].append(stripped[2:].strip().strip("'\""))
                continue
            if section == "facets":
                key, _, rest = stripped.partition(":")
                facet = key.strip()
                rest = rest.strip()
                if rest.startswith("[") and rest.endswith("]"):
                    groups[group]["facets"][facet] = _split_inline_list(rest)
                    facet = None
                else:
                    groups[group]["facets"][facet] = []
                continue
        if indent == 8 and section == "facets" and facet and stripped.startswith("- "):
            groups[group]["facets"][facet].append(stripped[2:].strip().strip("'\""))
            continue
        raise ValueError("cannot parse catalog line: %r" % raw)
    return groups


def _to_list(val):
    """Normalise a YAML scalar, sequence, or None into a list."""
    if val is None:
        return []
    if isinstance(val, str):
        return [val]
    return list(val)


def load_catalog(repo):
    """Load file group catalog from .panopticon/groups.yml or parse YAML fallback."""
    path = os.path.join(repo, ".panopticon", "groups.yml")
    if not os.path.isfile(path):
        return {}
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    try:
        try:
            import yaml
            data = yaml.safe_load(text) or {}
            raw = data.get("groups") or {}
            out = {}
            for name, body in raw.items():
                body = body or {}
                out[name] = {
                    "patterns": _to_list(body.get("patterns")),
                    "match": _to_list(body.get("match")),
                    "facets": {k: _to_list(v) for k, v in (body.get("facets") or {}).items()},
                }
            return out
        except ImportError:
            return _parse_catalog_yaml(text)
    except Exception as e:
        print("catalog parse error: %s" % e, file=sys.stderr)
        return {}


@functools.lru_cache(maxsize=None)
def _repo_realpath(repo):
    """The repo root's realpath, cached: _within runs once per candidate file
    on large expansions, and realpath lstats every path component."""
    return os.path.realpath(repo)


def _within(repo, path):
    repo_r = _repo_realpath(repo)
    p_r = os.path.realpath(path)
    return p_r == repo_r or p_r.startswith(repo_r + os.sep)


def expand_patterns(repo, patterns):
    """Expand glob patterns to repo-relative file paths, filtering for files within repo."""
    found = set()
    for pat in patterns:
        for hit in glob.glob(os.path.join(repo, pat), recursive=True):
            if os.path.isfile(hit) and _within(repo, hit):
                found.add(os.path.relpath(hit, repo).replace(os.sep, "/"))
    return sorted(found)


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


def _on_allowed_dotdir_path(rel):
    """True if rel is (a prefix of / inside) an allowlisted dot-dir subtree."""
    return any(
        rel == allowed or allowed.startswith(rel + "/") or rel.startswith(allowed + "/")
        for allowed in ALLOWED_DOTDIR_SUBTREES
    )


def _is_fixture_dir(rel):
    """True if a repo-relative dir path is a test-fixture corpus root (#434)."""
    parts = rel.split("/")
    if parts[-1] in FIXTURE_DIR_BASENAMES:
        return True
    return (parts[-1] == "fixtures" and len(parts) >= 2
            and parts[-2] in FIXTURE_PARENT_DIRS)


def resolve_base(repo, explicit=None, pr_base=None, runner=subprocess.run):
    """(base_ref, source). First candidate that resolves to a real commit:
    explicit -> pr_base -> main -> master. No HEAD~1. A given explicit/pr_base
    that does NOT resolve returns (None,'unresolved') without falling through -
    a bad --base is a loud failure, not a silent downgrade to a branch tip."""
    def _resolves(ref):
        r = runner(["git", "-C", repo, "rev-parse", "--verify", "-q", ref + "^{commit}"],
                   capture_output=True, text=True)
        return r.returncode == 0
    if explicit:
        return (explicit, "explicit") if _resolves(explicit) else (None, "unresolved")
    if pr_base:
        return (pr_base, "pr-base") if _resolves(pr_base) else (None, "unresolved")
    for ref in ("main", "master"):
        if _resolves(ref):
            return ref, "fallback"
    return None, "unresolved"


def _ancestor_dirs(rel):
    parts = rel.split("/")
    return ["/".join(parts[:i]) for i in range(1, len(parts))]  # excludes the file itself


def prune_fixture_files(paths, include_fixtures):
    """Drop files under a fixture corpus dir (standard mode); keep all in redteam."""
    if include_fixtures:
        return list(paths)
    return [p for p in paths if not any(_is_fixture_dir(d) for d in _ancestor_dirs(p))]


def write_diff_hunks(repo, base, source, out_path, tolerance, includes_uncommitted):
    """Write .panopticon/diff-hunks.json (#449) for the delta-review synth step.

    ``base_commit``/``delta_start``/``delta_end`` anchor the artifact to real
    commits (``diff_map.diff_anchors``) so a later reviewer can reconstruct the
    exact delta even if branch tips move.
    """
    hmap = diff_map.hunk_map(repo, base) if base else {}
    anchors = diff_map.diff_anchors(repo, base) if base else {
        "base_commit": None, "delta_start": None, "delta_end": None}
    artifact = {"base": base, "base_source": source,
                "base_commit": anchors["base_commit"],
                "delta_start": anchors["delta_start"],
                "delta_end": anchors["delta_end"],
                "includes_uncommitted": includes_uncommitted,
                "diff_context": tolerance,
                "files_changed": len(hmap),
                "hunks": {p: [list(r) for r in rs] for p, rs in hmap.items()}}
    os.makedirs(os.path.dirname(os.path.abspath(out_path)) or ".", exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(artifact, fh, indent=2)
        fh.write("\n")


def _hunks_path_for(out):
    """Path for diff-hunks.json: alongside --out's directory, else the default
    .panopticon/ location. Shared by every mode that emits the artifact so the
    placement rule has one definition."""
    return (os.path.join(os.path.dirname(os.path.abspath(out)), "diff-hunks.json")
            if out else os.path.join(".panopticon", "diff-hunks.json"))


def resolve_base_or_die(repo, explicit, pr_base, on_fail=None):
    """Resolve the delta base, or fail loudly and return None.

    Returns ``(base, source)`` on success — the SAME base every downstream
    step (the reviewed file set via ``collect_changed_files``, and the on-diff
    hunk map via ``write_diff_hunks``) must share (Finding A: they used to
    resolve independently and could disagree). On an unresolvable base it
    prints the loud failure message, runs ``on_fail()`` (e.g. release a
    worktree), and returns None — the caller then ``return 2`` with NO
    artifact written. Does NOT itself emit diff-hunks.json; callers resolve
    the base FIRST, then compute the file set against it, THEN write the
    artifact.
    """
    base, source = resolve_base(repo, explicit=explicit, pr_base=pr_base)
    if base is None:
        print("panopticon: could not resolve a base ref for delta review.\n"
              "  Anchor the review to a fixed commit or a base-branch tip:\n"
              "  pass --base <ref|sha>, or ensure main/master exists.",
              file=sys.stderr)
        if on_fail:
            on_fail()
        return None
    return base, source


def _resolve_or_die(repo, out, explicit, pr_base, diff_context,
                    includes_uncommitted, on_fail=None):
    """Resolve base and emit diff-hunks.json, or fail loudly (return False).

    Returns True after writing the artifact; on an unresolvable base it prints a
    loud message, runs ``on_fail()`` (e.g. release a worktree), and returns
    False — the caller then ``return 2`` with NO artifact written. An
    unresolvable base is a loud orchestrator-level failure, not a soft
    INCONCLUSIVE deferred to synthesize (#449 redirect).

    Used only by the ``--files`` mode, whose file set is explicit (no
    coherence concern between file set and hunk map — see ``resolve_base_or_die``
    for the modes that need the base resolved before the file set is built).
    """
    res = resolve_base_or_die(repo, explicit, pr_base, on_fail=on_fail)
    if res is None:
        return False
    base, source = res
    write_diff_hunks(repo, base, source, _hunks_path_for(out), diff_context,
                     includes_uncommitted)
    return True


def _git_listed_files(repo):
    """Repo-relative paths git considers reviewable surface, or None.

    ``git ls-files --cached --others --exclude-standard`` = tracked files plus
    intentional-but-uncommitted new files, minus everything the TARGET's own
    .gitignore excludes (#500: a raw walk swept 17,253 files on a repo whose
    git surface was 528 — 94% gitignored runtime data, including encrypted
    user blobs). Returns None when repo isn't a git worktree or git fails,
    so the caller can fall back to walking.
    """
    try:
        out = _git(repo, ["ls-files", "--cached", "--others",
                          "--exclude-standard"], timeout=60)
    except Exception:
        return None
    return [p.strip() for p in out.stdout.splitlines() if p.strip()]


def _filter_reviewable(paths, include_fixtures, pruned_fixtures, isfile):
    """Apply the discovery policy to a candidate path list.

    Shared by both discovery methods so the git listing gets the same
    treatment the walk gives: EXCLUDE_DIRS / EXCLUDE_DIR_GLOBS on every
    ancestor segment (a repo that TRACKS node_modules still shouldn't review
    it), the targeted dot-dir policy, the fixture-corpus pruning (#434,
    recorded in ``pruned_fixtures`` for disclosure), and — git path only in
    practice — dropping anything with a ``.git`` segment: a gitlink or
    nested-repo artifact is never a reviewable file (#500 saw
    ``design-system/.git`` leak into group lists). ``isfile`` is injected so
    the pure filtering logic stays unit-testable; on the git path it also
    drops gitlink directory entries and index entries deleted from disk.
    """
    out = []
    for rel in sorted(set(paths)):
        parts = rel.split("/")
        if ".git" in parts:
            continue
        skip = False
        for j, seg in enumerate(parts[:-1]):
            prefix = "/".join(parts[:j + 1])
            if _is_excluded_dir(seg):
                skip = True
                break
            if seg.startswith(".") and not _on_allowed_dotdir_path(prefix):
                skip = True
                break
            if not include_fixtures and _is_fixture_dir(prefix):
                if pruned_fixtures is not None and prefix not in pruned_fixtures:
                    pruned_fixtures.append(prefix)
                skip = True
                break
        if skip:
            continue
        # Root-level dotfiles follow the walk's policy: excluded unless inside
        # an allowlisted subtree.
        if len(parts) == 1 and parts[0].startswith(".") \
                and not _on_allowed_dotdir_path(rel):
            continue
        if not isfile(rel):
            continue
        out.append(rel)
    return out


def discover_repo_files(repo, include_fixtures=False, pruned_fixtures=None,
                        info=None):
    """Discover reviewable files, returning sorted repo-relative paths.

    Git targets: the listing comes from ``git ls-files`` so the target's own
    .gitignore defines the surface (#500); non-git targets fall back to an
    os.walk that prunes EXCLUDE_DIRS / EXCLUDE_DIR_GLOBS and skips
    dot-directories EXCEPT the targeted ALLOWED_DOTDIR_SUBTREES
    (e.g. .github/workflows). Both methods share ``_filter_reviewable``'s
    policy; ``info`` (a dict, when supplied) records which ``method`` ran so
    the artifact can disclose it.

    Unless ``include_fixtures`` (redteam), test-fixture corpus roots
    (``_is_fixture_dir``) are pruned too; each pruned root is appended to
    ``pruned_fixtures`` when a list is supplied so the caller can disclose
    the exclusion rather than let it pass silently.
    """
    listed = _git_listed_files(repo)
    if listed is not None:
        if info is not None:
            info["method"] = "git-ls-files"
        return _filter_reviewable(
            listed, include_fixtures, pruned_fixtures,
            isfile=lambda rel: os.path.isfile(os.path.join(repo, rel)))
    if info is not None:
        info["method"] = "walk"
    out = []
    for dirpath, dirnames, filenames in os.walk(repo):
        rel_dir = os.path.relpath(dirpath, repo)
        rel_dir = "" if rel_dir == "." else rel_dir.replace(os.sep, "/")
        kept = []
        for dn in dirnames:
            if _is_excluded_dir(dn):
                continue
            child = (rel_dir + "/" + dn) if rel_dir else dn
            if dn.startswith(".") and not _on_allowed_dotdir_path(child):
                continue
            if not include_fixtures and _is_fixture_dir(child):
                if pruned_fixtures is not None:
                    pruned_fixtures.append(child)
                continue
            kept.append(dn)
        dirnames[:] = kept
        for fn in filenames:
            rel = (rel_dir + "/" + fn) if rel_dir else fn
            top = rel.split("/", 1)[0]
            # Files under a dot-dir top are surfaced only inside an allowlisted subtree.
            if top.startswith(".") and not _on_allowed_dotdir_path(rel):
                continue
            out.append(rel)
    return sorted(out)


def _looks_risky(path):
    """Crude heuristic for risky code surfaces until scout provides them."""
    lowered = path.lower()
    return any(k in lowered for k in ("auth", "login", "password", "payment", "pii", "encrypt", "token", "api"))


def _compute_depth(files, panels, security_mode):
    """Assign shallow/standard/deep based on surfaces, panel mix, and security mode."""
    if security_mode == "redteam":
        return "deep"
    risky_files = any(
        is_architecture_file(f) or is_database_file(f) or _looks_risky(f)
        for f in files
    )
    if risky_files:
        return "standard"
    if any(p in ("security", "redteam", "database") for p in panels):
        return "standard"
    return "shallow"


def _group_obj(name, files, security_mode):
    """Build one group entry: panels, surfaces, and depth for a file set."""
    panels = compute_group_panels(files, security_mode)
    return {
        "name": name,
        "files": files,
        "surfaces": compute_group_surfaces(files),
        "panels": panels,
        "depth": _compute_depth(files, panels, security_mode),
    }


def catalog_groups(files, catalog, max_per_group, security_mode):
    """Build stable, catalog-named groups for --repo-scan (#499).

    Files are assigned by ``assign_by_catalog``; a matched group larger than
    ``max_per_group`` splits into ``<name>_<i>`` chunks, and leftover files
    keep the legacy ``._N`` chunk naming. Returns ``(groups, leftovers)``;
    callers must surface ``leftovers`` (the coverage gap), never drop it.
    """
    named, leftovers = assign_by_catalog(files, catalog)
    groups = []
    for name, fs in named.items():
        chunks = chunk_files(fs, max_per_group)
        if len(chunks) == 1:
            groups.append(_group_obj(name, chunks[0], security_mode))
        else:
            groups.extend(_group_obj("%s_%d" % (name, i + 1), c, security_mode)
                          for i, c in enumerate(chunks))
    groups.extend(_group_obj("._%d" % (i + 1), c, security_mode)
                  for i, c in enumerate(chunk_files(leftovers, max_per_group)))
    return groups, leftovers


def build_result(repo, mode, target, facet, impl, tests,
                 max_per_group=DEFAULT_MAX_PER_GROUP, group_files=None,
                 security_mode="standard"):
    """Build resolved target result with file groups, implementation, and test lists.

    Groups are chunked from ``group_files`` when provided, else from ``impl``.
    Passing ``group_files`` lets a caller (e.g. --repo-scan) surface test
    sources in groups while keeping counts["implementation"] impl-only.
    """
    chunks = chunk_files(impl if group_files is None else group_files, max_per_group)
    base = os.path.basename(target.rstrip("/")) or target or "root"
    groups = [_group_obj("%s_%d" % (base, i + 1), c, security_mode)
              for i, c in enumerate(chunks)]
    return {
        "security_mode": security_mode,
        "mode": mode,
        "target": target,
        "facet": facet,
        "groups": groups,
        "tests": tests,
        "counts": {
            "implementation": len(impl),
            "tests": len(tests),
            "groups": len(groups),
        },
    }


def emit(obj, fh=None):
    """Serialize and emit object as indented JSON to stdout or a file."""
    fh = fh or sys.stdout
    json.dump(obj, fh, indent=2)
    fh.write("\n")


def main(argv=None):
    """Resolve panopticon targets to grouped file lists and emit as JSON."""
    ap = argparse.ArgumentParser(description="panopticon target resolver")
    ap.add_argument("target", nargs="?", default=None,
                    help="Repository path (overrides --repo)")
    ap.add_argument("--repo", default=".")
    ap.add_argument("--max-per-group", type=int, default=DEFAULT_MAX_PER_GROUP)
    ap.add_argument("--out", default=None,
                    help="Write JSON output to this file instead of stdout")
    ap.add_argument("--security", choices=["standard", "redteam"], default="standard",
                    help="Security review mode")
    ap.add_argument("--base", default=None,
                    help="Base ref/sha for --changes/--pr/--files delta review")
    ap.add_argument("--diff-context", type=int, default=5,
                    help="Lines of tolerance for on-diff classification (default 5)")
    modes = ap.add_mutually_exclusive_group(required=True)
    modes.add_argument("--group", metavar="NAME")
    modes.add_argument("--directory", metavar="DIR")
    modes.add_argument("--file", metavar="PATH")
    modes.add_argument("--files", nargs="+", metavar="PATH")
    modes.add_argument("--changes", "-c", action="store_true",
                       help="Review changed files vs delta base (--base, else "
                            "main/master; no HEAD~1 -- an unresolvable base "
                            "fails loudly)")
    modes.add_argument("--pr", type=int, metavar="N",
                       help="Review GitHub PR N in an isolated worktree")
    modes.add_argument("--repo-scan", action="store_true")
    args = ap.parse_args(argv)
    if args.max_per_group < 1:
        print("--max-per-group must be >= 1", file=sys.stderr)
        return 2
    repo = os.path.abspath(args.target if args.target is not None else args.repo)

    result = None
    if args.group:
        name, facet = parse_group_arg(args.group)
        catalog = load_catalog(repo)
        if name not in catalog:
            print("unknown group %r; run explore (-e) to build the catalog" % name,
                  file=sys.stderr)
            return 2
        impl = [f for f in expand_patterns(repo, catalog[name]["patterns"])
                if not is_test_file(f)]
        result = build_result(repo, "group", name, facet, impl, related_tests(repo, impl),
                              args.max_per_group, security_mode=args.security)

    elif args.directory:
        d = args.directory.strip("/")
        allf = expand_patterns(repo, [d + "/**/*"])
        impl = [f for f in allf if not is_test_file(f)]
        tests = [f for f in allf if is_test_file(f)]
        result = build_result(repo, "directory", d, None, impl, tests, args.max_per_group,
                              security_mode=args.security)

    elif args.file:
        if not os.path.isfile(os.path.join(repo, args.file)):
            print("no such file: %s" % args.file, file=sys.stderr)
            return 2
        result = build_result(repo, "file", args.file, None, [args.file],
                              related_tests(repo, [args.file]), args.max_per_group,
                              security_mode=args.security)

    elif args.files:
        files = prune_fixture_files(args.files, args.security == "redteam")
        impl = [f for f in files if not is_test_file(f)]
        tests = [f for f in files if is_test_file(f)]
        result = build_result(repo, "files", "changeset", None, impl,
                              sorted(set(tests) | set(related_tests(repo, impl))), args.max_per_group,
                              security_mode=args.security)
        # Delta artifact only when --base is an explicit request; plain --files
        # (no --base) is a normal review and emits no diff-hunks.json (#449).
        if args.base and not _resolve_or_die(repo, args.out, args.base, None,
                                             args.diff_context, includes_uncommitted=True):
            return 2

    elif args.changes:
        # --changes always requests a delta review; the base is resolved FIRST
        # (Finding A) so the reviewed file set (collect_changed_files) and the
        # on-diff hunk map (write_diff_hunks) are computed against the SAME
        # base, never two independently-resolved ones. An unresolvable base is
        # a loud failure, not a soft INCONCLUSIVE deferred to synthesize (#449).
        res = resolve_base_or_die(repo, args.base, None)
        if res is None:
            return 2
        base, source = res
        changed = collect_changed_files(repo, base=base)
        if changed is None:
            print("could not determine changed files; is %s a git repository?" % repo,
                  file=sys.stderr)
            return 2
        changed = prune_fixture_files(changed, args.security == "redteam")
        if not changed:
            print("no changed files found", file=sys.stderr)
            return 0
        impl = [f for f in changed if not is_test_file(f)]
        tests = [f for f in changed if is_test_file(f)]
        result = build_result(repo, "changes", "changes", None, impl,
                              sorted(set(tests) | set(related_tests(repo, impl))), args.max_per_group,
                              security_mode=args.security)
        write_diff_hunks(repo, base, source, _hunks_path_for(args.out),
                         args.diff_context, True)

    elif args.pr is not None:
        acq = diff_map.acquire_pr(args.pr, repo=repo)
        wt = acq["worktree"]
        try:
            # --pr always requests a delta review; base resolved FIRST so the
            # file set and hunk map share it (Finding A, as in --changes
            # above). An unresolvable base releases the worktree first, then
            # fails loudly — no artifact (#449).
            res = resolve_base_or_die(
                wt, args.base, acq["base"],
                on_fail=lambda: diff_map.release_worktree(wt, repo=repo))
            if res is None:
                return 2
            base, source = res
            changed = prune_fixture_files(collect_changed_files(wt, base=base) or [],
                                          args.security == "redteam")
            impl = [f for f in changed if not is_test_file(f)]
            tests = [f for f in changed if is_test_file(f)]
            result = build_result(wt, "changes", "changes", None, impl,
                                  sorted(set(tests) | set(related_tests(wt, impl))),
                                  args.max_per_group, security_mode=args.security)
            # The worktree is clean at the PR head so the working-tree diff is
            # committed-only (includes_uncommitted=False).
            write_diff_hunks(wt, base, source, _hunks_path_for(args.out),
                             args.diff_context, False)
            result["worktree"] = wt   # recorded; SKILL cleanup releases it post-review
        except Exception:
            diff_map.release_worktree(wt, repo=repo)
            raise

    else:
        # --repo-scan
        pruned_fixtures = []
        info = {}
        allf = discover_repo_files(repo,
                                   include_fixtures=(args.security == "redteam"),
                                   pruned_fixtures=pruned_fixtures,
                                   info=info)
        impl = [f for f in allf if not is_test_file(f)]
        tests = [f for f in allf if is_test_file(f)]
        # Group impl AND real test sources so tests aren't silently dropped (only
        # their __pycache__ artifacts used to reach a group); counts stay impl-only.
        result = build_result(repo, "repo", ".", None, impl, tests, args.max_per_group,
                              group_files=impl + tests, security_mode=args.security)
        result["discovery"] = {"method": info.get("method")}
        catalog = load_catalog(repo)
        if any(g.get("match") for g in catalog.values()):
            groups, leftovers = catalog_groups(allf, catalog, args.max_per_group,
                                               args.security)
            result["groups"] = groups
            result["counts"]["groups"] = len(groups)
            result["counts"]["ungrouped"] = len(leftovers)
            result["ungrouped_files"] = leftovers
            if leftovers:
                print("catalog coverage: %d file(s) matched no group's `match` "
                      "patterns and fell back to ._N chunks — see "
                      "ungrouped_files; extend .panopticon/groups.yml to cover "
                      "them: %s"
                      % (len(leftovers), ", ".join(leftovers[:10])
                         + (" …" if len(leftovers) > 10 else "")),
                      file=sys.stderr)
        if pruned_fixtures:
            result["excluded"] = {"fixture_dirs": sorted(pruned_fixtures)}
            print("fixture exclusion (%s mode): pruned %d fixture corpus dir(s): %s "
                  "— intentionally-vulnerable test corpora do not gate a standard "
                  "scan; use --security redteam to include them"
                  % (args.security, len(pruned_fixtures),
                     ", ".join(sorted(pruned_fixtures))), file=sys.stderr)

    if args.out:
        os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
        with open(args.out, "w", encoding="utf-8") as fh:
            emit(result, fh)
    else:
        emit(result)
    return 0


if __name__ == "__main__":
    sys.exit(main())
