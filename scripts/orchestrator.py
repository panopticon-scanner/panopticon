#!/usr/bin/env python3
"""Resolve panopticon targets (files, dirs, groups, repos) to grouped file
lists. Stdlib-only; run BEFORE dispatching review subagents.
"""
import argparse
import fnmatch
import glob
import json
import os
import re
import subprocess
import sys

DEFAULT_MAX_PER_GROUP = 15

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

# Dot-dir subtrees that ARE reviewable and must survive the blanket dotdir skip.
# Targeted on purpose: .github/workflows is a top-risk CI/CD surface. Do NOT
# widen this to all dotdirs — that reintroduces .git / .venv noise.
ALLOWED_DOTDIR_SUBTREES = (".github/workflows",)

TEST_PATTERNS = [
    r"_spec\.rb$",
    r"_test\.rb$",
    r"_test\.go$",
    r"\.test\.[jt]sx?$",
    r"\.spec\.[jt]sx?$",
    r"(^|/)test_[^/]+\.py$",
    r"_test\.py$",
    r"Test\.java$",
    r"Tests\.cs$",
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
    return panels


def collect_changed_files(repo):
    """Collect repo-relative paths changed since the merge base (or HEAD~1).

    Tries the default upstream branches first, then falls back to HEAD~1. Only
    files that still exist in the working tree are returned. Returns None if no
    git history is available.
    """
    base = None
    for branch in ("main", "master"):
        try:
            out = subprocess.run(
                ["git", "-C", repo, "merge-base", "HEAD", branch],
                capture_output=True, text=True, check=True, timeout=30,
            )
            base = out.stdout.strip()
            if base:
                break
        except Exception:
            continue
    if not base:
        try:
            out = subprocess.run(
                ["git", "-C", repo, "rev-parse", "HEAD~1"],
                capture_output=True, text=True, check=True, timeout=30,
            )
            base = out.stdout.strip()
        except Exception:
            return None
    changed = set()
    try:
        out = subprocess.run(
            ["git", "-C", repo, "diff", "--name-only", "--diff-filter=d", base],
            capture_output=True, text=True, check=True, timeout=30,
        )
        for p in out.stdout.splitlines():
            p = p.strip()
            if p:
                changed.add(p)
    except Exception:
        return None
    # Include new untracked files so a branch with only added files isn't empty.
    try:
        out = subprocess.run(
            ["git", "-C", repo, "ls-files", "--others", "--exclude-standard"],
            capture_output=True, text=True, check=True, timeout=30,
        )
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
            groups[group] = {"patterns": [], "facets": {}}
            section = None
            facet = None
            continue
        if indent == 4:
            key, _, rest = stripped.partition(":")
            key = key.strip()
            rest = rest.strip()
            if key == "patterns":
                section = "patterns"
                facet = None
                if rest.startswith("[") and rest.endswith("]"):
                    groups[group]["patterns"] = _split_inline_list(rest)
                    section = None
            elif key == "facets":
                section = "facets"
                facet = None
            else:
                raise ValueError("unexpected key at indent 4: %r" % key)
            continue
        if indent == 6:
            if section == "patterns" and stripped.startswith("- "):
                groups[group]["patterns"].append(stripped[2:].strip().strip("'\""))
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
                    "patterns": list(body.get("patterns") or []),
                    "facets": {k: list(v or []) for k, v in (body.get("facets") or {}).items()},
                }
            return out
        except ImportError:
            return _parse_catalog_yaml(text)
    except Exception as e:
        print("catalog parse error: %s" % e, file=sys.stderr)
        return {}


def _within(repo, path):
    repo_r = os.path.realpath(repo)
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


def discover_repo_files(repo):
    """Walk repo for reviewable files, returning sorted repo-relative paths.

    Prunes EXCLUDE_DIRS / EXCLUDE_DIR_GLOBS (noise: caches, deps, VCS, scratch)
    and skips dot-directories, EXCEPT the targeted ALLOWED_DOTDIR_SUBTREES
    (e.g. .github/workflows) which are pulled back in. Replaces the old
    glob('**/*') scan, which skipped every dotdir (hiding .github/workflows)
    and descended into venv/tmp/node_modules/etc.
    """
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
    groups = []
    for i, c in enumerate(chunks):
        panels = compute_group_panels(c, security_mode)
        depth = _compute_depth(c, panels, security_mode)
        groups.append({
            "name": "%s_%d" % (base, i + 1),
            "files": c,
            "surfaces": compute_group_surfaces(c),
            "panels": panels,
            "depth": depth,
        })
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
    modes = ap.add_mutually_exclusive_group(required=True)
    modes.add_argument("--group", metavar="NAME")
    modes.add_argument("--directory", metavar="DIR")
    modes.add_argument("--file", metavar="PATH")
    modes.add_argument("--files", nargs="+", metavar="PATH")
    modes.add_argument("--changes", "-c", action="store_true",
                       help="Review changed files vs merge base (fallback HEAD~1)")
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
        impl = [f for f in args.files if not is_test_file(f)]
        tests = [f for f in args.files if is_test_file(f)]
        result = build_result(repo, "files", "changeset", None, impl,
                              sorted(set(tests) | set(related_tests(repo, impl))), args.max_per_group,
                              security_mode=args.security)

    elif args.changes:
        changed = collect_changed_files(repo)
        if changed is None:
            print("could not determine changed files; is %s a git repository?" % repo,
                  file=sys.stderr)
            return 2
        if not changed:
            print("no changed files found", file=sys.stderr)
            return 0
        impl = [f for f in changed if not is_test_file(f)]
        tests = [f for f in changed if is_test_file(f)]
        result = build_result(repo, "changes", "changes", None, impl,
                              sorted(set(tests) | set(related_tests(repo, impl))), args.max_per_group,
                              security_mode=args.security)

    else:
        # --repo-scan
        allf = discover_repo_files(repo)
        impl = [f for f in allf if not is_test_file(f)]
        tests = [f for f in allf if is_test_file(f)]
        # Group impl AND real test sources so tests aren't silently dropped (only
        # their __pycache__ artifacts used to reach a group); counts stay impl-only.
        result = build_result(repo, "repo", ".", None, impl, tests, args.max_per_group,
                              group_files=impl + tests, security_mode=args.security)

    if args.out:
        os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
        with open(args.out, "w", encoding="utf-8") as fh:
            emit(result, fh)
    else:
        emit(result)
    return 0


if __name__ == "__main__":
    sys.exit(main())
