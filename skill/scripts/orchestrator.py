#!/usr/bin/env python3
"""Resolve panopticon targets (files, dirs, groups, repos) to grouped file
lists. Stdlib-only; run BEFORE dispatching review subagents.
"""
import argparse
import glob
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import diff_map  # noqa: E402 (sibling on sys.path, same pattern as dispatch.py)
import plan_contract  # noqa: E402
from setup_flow import (  # noqa: E402  (setup wrapping extracted in P6.4)
    SETUP_GITIGNORE_ENTRIES, _seed_groups_manifest, _ensure_gitignore,  # noqa: F401
    _seed_config, setup_readiness, _repo_spine_summary, render_scan_brief,  # noqa: F401
    _VOCAB_PATH, _AFFINITY_PATH,  # noqa: F401
)
from discovery import (  # noqa: F401  (P6.5 Slice A: primitives moved to discovery)
    discover_repo_files, assign_by_catalog, load_catalog, catalog_groups,
    related_tests, is_test_file, is_architecture_file, is_database_file,
    prune_fixture_files, build_result,
    write_diff_hunks, panels_in_priority_order,
    compute_group_panels, chunk_files, _compute_depth, _validate_artifact_output,
    _worktree_dirty, _hunks_path_for, emit, _matrix_catalog, _committed_matrix,
    FIXTURE_DIR_BASENAMES, FIXTURE_PARENT_DIRS, PANEL_PRIORITY, TEST_PATTERNS,
    _glob_to_re, match_patterns, _filter_reviewable, _parse_catalog_yaml,
    test_candidates, _within,
)
# NOTE: `_git`, `collect_changed_files`, `resolve_base`, `resolve_base_or_die`
# are DELIBERATELY NOT imported from discovery -- they stay defined below,
# verbatim-duplicated in discovery.py too. Several TestPrMode/
# TestChangedFilesRenameParity tests mock `orch._git` / `orch.resolve_base`
# and then exercise `orch.main([...])` or call the outer function
# (`orch.collect_changed_files` / `orch.resolve_base_or_die`, which calls
# `resolve_base` internally) directly; a plain re-import would make those
# patches a no-op, since the callee's __globals__ would be discovery's dict,
# not orchestrator's (mock.patch.object only rebinds the target module's own
# attribute slot -- see task-A1-report.md).

DEFAULT_MAX_PER_GROUP = 15


def _git(repo, args, timeout=30, text=True):
    """Run git -C repo with check=True — the shared invocation for this
    module's six git call sites; each caller's try/except owns failures."""
    return subprocess.run(["git", "-C", repo, *args],
                          capture_output=True, text=text, check=True,
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
        # --find-renames: same rename semantics as diff_map.hunk_map, so the
        # reviewed file set and the on-diff hunk map can never diverge on a
        # similarity-threshold edge (#978).
        out = _git(repo, ["diff", "--name-only", "--diff-filter=d",
                          "--find-renames", mb])
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
        # #947 FIXME-3: acquire_pr fetches only the PR head, so the base may
        # exist locally only as origin/<name> -- and a STALE local branch of
        # that name would silently mis-anchor the delta. Prefer the remote
        # ref, fall back to the bare name; a machine-derived pr_base may try
        # both (unlike an explicit --base, which never falls through).
        origin_ref = "origin/%s" % pr_base
        if _resolves(origin_ref):
            return origin_ref, "pr-base"
        return (pr_base, "pr-base") if _resolves(pr_base) else (None, "unresolved")
    for ref in ("main", "master"):
        if _resolves(ref):
            return ref, "fallback"
    return None, "unresolved"


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


def parse_group_arg(arg):
    """Parse group name and optional facet from group[facet] format."""
    m = re.match(r"^\s*([^\[\]]+?)\s*(?:\[\s*([^\[\]]+?)\s*\])?\s*$", arg)
    if not m:
        return arg.strip(), None
    return m.group(1), m.group(2)


def expand_patterns(repo, patterns):
    """Expand glob patterns to repo-relative file paths, filtering for files within repo."""
    found = set()
    for pat in patterns:
        for hit in glob.glob(os.path.join(repo, pat), recursive=True):
            if os.path.isfile(hit) and _within(repo, hit):
                found.add(os.path.relpath(hit, repo).replace(os.sep, "/"))
    return sorted(found)


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


def run_setup_ingest(repo=".", proposal_path=None, out=sys.stdout):
    """Thin CLI wrapper over setup_flow.ingest_proposal (extracted P6.4).
    Preserves the exact printed output + exit codes.

    Re-checks the bundled-data paths against orchestrator's own (re-exported)
    _VOCAB_PATH/_AFFINITY_PATH before delegating: setup_flow.ingest_proposal
    guards its OWN module-level copies, which a test (or caller) patching
    orchestrator._VOCAB_PATH would not otherwise reach (P6.4 TestSetupScanFlow
    regression: test_ingest_without_bundled_data_fails_loudly)."""
    if not (os.path.isfile(_VOCAB_PATH) and os.path.isfile(_AFFINITY_PATH)):
        print("data error: bundled vocabulary/affinity data is missing "
              "(expected %s, %s)" % (_VOCAB_PATH, _AFFINITY_PATH), file=out)
        return 1
    import setup_flow
    res = setup_flow.ingest_proposal(repo, proposal_path)
    if not res["ok"]:
        for line in res["errors"]:
            print(line, file=out)
        return 1
    diff, disclosure = res["diff"], res["disclosure"]
    print("draft groups.yml written: %s" % res["draft"], file=out)
    print("  new groups:     %s" % (", ".join(
        g["name"] for g in diff["new_groups"]) or "(none)"), file=out)
    print("  extended:       %s" % (", ".join(
        g["name"] for g in diff["extended_groups"]) or "(none)"), file=out)
    print("  dropped (redundant): %s" % (", ".join(
        diff["dropped_redundant"]) or "(none)"), file=out)
    if disclosure.get("collisions"):
        for c in disclosure["collisions"]:
            print("  merged duplicate capability %s into group %s"
                  % (c["capability"], c["name"]), file=out)
    for g in disclosure.get("groups", []):
        print("  %s: %s (%s)" % (
            g["name"], "custom" if g["custom"] else "matched",
            g["floor_source"]), file=out)
    print("review the draft, then move it to .panopticon/groups.yml and commit "
          "(setup never overwrites your committed file).", file=out)
    return 0


def run_setup(repo=".", host=None, runner=subprocess.run, environ=None,
             out=sys.stdout, vocabulary_path=None):
    """#485 + P2: provision, then render the setup-scan brief (or fall back to
    the deterministic top-dir seed when no vocabulary is available).

    Spec §8: the scan path is provision -> render brief -> STOP. The flat
    top-dir groups.yml (_seed_groups_manifest) is the vocabulary-ABSENT
    fallback ONLY (spec §6/§7) -- it must NEVER be seeded unconditionally,
    or a later `--ingest` would read that flat catalog back as the
    "committed" baseline, find no leftover files, and additive-merge would
    drop every real capability group as redundant (C1)."""
    added = _ensure_gitignore(repo)
    print("gitignore: %s" % ("added %s" % ", ".join(added) if added else "ok"),
          file=out)
    cfg, cfg_created = _seed_config(repo)
    print("config: %s (%s)" % (cfg, "created" if cfg_created else "existing"),
          file=out)

    import setup_proposal as sp
    vpath = vocabulary_path or _VOCAB_PATH
    vocab, verr = sp.load_vocabulary(vpath) if os.path.isfile(vpath) \
        else ({"names": []}, ["absent"])
    if vocab["names"] and not verr:
        brief = render_scan_brief(repo, vocab)
        print("scan brief: %s" % brief, file=out)
        print("  → dispatch it as the read-only setup-scan agent, save the "
              "proposal to .panopticon/setup-proposal.json, then run "
              "`panopticon setup --ingest`.", file=out)
    else:
        path, created, names = _seed_groups_manifest(repo)
        print("groups manifest: %s (%s; %d group(s))"
              % (path, "created" if created else "existing", len(names)), file=out)
        print("vocabulary absent -- scan skipped; using the deterministic "
              "top-dir seed above (edit + commit it by hand).", file=out)

    checks = setup_readiness(repo, host=host, runner=runner, environ=environ)
    gaps = [c for c in checks if c[1] is False]
    print("", file=out)
    for name, ok, detail in checks:
        mark = "OK " if ok else ("-- " if ok is None else "GAP")
        print("  [%s] %-16s %s" % (mark, name, detail), file=out)
    print("", file=out)
    if gaps:
        print("NOT READY -- %d gap(s) above; fix each and re-run --setup"
              % len(gaps), file=out)
        return 1
    print("READY -- repo is provisioned for a panopticon run", file=out)
    return 0


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
    ap.add_argument("--pr-base", default=None,
                    help="PR base branch (gh-detected) for --repo-scan "
                         "--scope-changed; resolved with origin/<base> "
                         "preference (#947). None for -c/--files.")
    ap.add_argument("--diff-context", type=int, default=5,
                    help="Lines of tolerance for on-diff classification (default 5)")
    # Scope filters (P6.2): apply only with --repo-scan -- they narrow the
    # discovered file universe before the SAME matrix assignment runs, rather
    # than switching modes. Read only in the --repo-scan branch below.
    scope = ap.add_mutually_exclusive_group()
    scope.add_argument("--scope-file", metavar="PATH", default=None)
    scope.add_argument("--scope-dir", metavar="DIR", default=None)
    scope.add_argument("--scope-group", metavar="NAME", default=None)
    scope.add_argument("--scope-changed", action="store_true")
    scope.add_argument("--scope-files", nargs="+", metavar="PATH", default=None)
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
    modes.add_argument("--setup", action="store_true",
                       help="First-run provisioning + readiness check (#485): "
                            "seed a committable groups.yml, scaffold "
                            ".panopticon/ + gitignore + config, then report "
                            "READY or the exact gaps (exit 1)")
    ap.add_argument("--ingest", nargs="?", const="", default=None,
                    help="With --setup: ingest a setup-scan proposal JSON "
                         "(default .panopticon/setup-proposal.json) and write "
                         "the groups.yml draft")
    args = ap.parse_args(argv)
    if args.setup:
        if args.ingest is not None:
            return run_setup_ingest(".", proposal_path=(args.ingest or None))
        return run_setup(".", host=None)
    if args.ingest is not None:
        print("panopticon: --ingest has no effect without --setup -- ignoring",
              file=sys.stderr)
    if args.max_per_group < 1:
        print("--max-per-group must be >= 1", file=sys.stderr)
        return 2
    repo = os.path.abspath(args.target if args.target is not None else args.repo)
    try:
        plan_contract.artifact_root(repo)
    except ValueError as exc:
        print("panopticon: %s" % exc, file=sys.stderr)
        return 2
    if args.out:
        try:
            _validate_artifact_output(repo, args.out)
        except ValueError as exc:
            print("panopticon: %s" % exc, file=sys.stderr)
            return 2

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
            # #955: the SKILL runs scout/tools/fan-out/synthesize with the
            # worktree as cwd, where they expect .panopticon/groups.json and
            # .panopticon/diff-hunks.json. Stage both so the worktree is
            # pipeline-ready on exit -- previously they landed only in the
            # invoking cwd/stdout and the operator had to hand-copy them (and
            # re-running discovery to fix that leaked a second worktree).
            wt_pan = plan_contract.artifact_root(wt)
            os.makedirs(wt_pan, exist_ok=True)
            write_diff_hunks(wt, base, source,
                             os.path.join(wt_pan, "diff-hunks.json"),
                             args.diff_context, False)
            with open(os.path.join(wt_pan, "groups.json"), "w",
                      encoding="utf-8") as fh:
                emit(result, fh)
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
        catalog = _matrix_catalog(repo)   # SEC-3: parse_groups-validated matrix read
        # P6.2: --scope-file/--scope-dir/--scope-group narrow the discovered
        # universe to a target BEFORE the same matrix assignment below runs --
        # a scope filter, not a new mode. No scope arg -> scoped stays None ->
        # allf/impl/tests/result are untouched (byte-identical no-scope path).
        scoped = None
        _delta = None
        if args.scope_group:
            if args.scope_group not in catalog:
                print("unknown group %r for --scope-group" % args.scope_group,
                      file=sys.stderr)
                return 2
            assigned, _ = assign_by_catalog(allf, {args.scope_group:
                                                   catalog[args.scope_group]})
            scoped = assigned.get(args.scope_group, [])
        elif args.scope_dir:
            d = args.scope_dir.strip("/") + "/"
            scoped = [f for f in allf if f.startswith(d)]
            if not scoped:
                print("--scope-dir %r matched no tracked files"
                      % args.scope_dir, file=sys.stderr)
                return 2
        elif args.scope_file:
            if args.scope_file not in allf:
                print("--scope-file %r not found among discovered repo files"
                      % args.scope_file, file=sys.stderr)
                return 2
            scoped = [args.scope_file] + [t for t in related_tests(repo, [args.scope_file])
                                          if t in allf]
        elif args.scope_changed:
            res = resolve_base_or_die(repo, args.base, args.pr_base)
            if res is None:
                return 2
            base, source = res
            changed = collect_changed_files(repo, base=base)
            if changed is None:
                print("could not determine changed files; is %s a git repo?" % repo,
                      file=sys.stderr)
                return 2
            scoped = prune_fixture_files(changed, args.security == "redteam")
            _delta = (base, source)
        elif args.scope_files:
            scoped = prune_fixture_files(list(args.scope_files),
                                        args.security == "redteam")
            _delta = None
            if args.base:
                res = resolve_base_or_die(repo, args.base, None)
                if res is None:
                    return 2
                _delta = res
        if scoped is not None:
            allf = scoped
            impl = [f for f in allf if not is_test_file(f)]
            tests = [f for f in allf if is_test_file(f)]
            result = build_result(repo, "repo", ".", None, impl, tests,
                                  args.max_per_group, group_files=impl + tests,
                                  security_mode=args.security)
            result["discovery"] = {"method": info.get("method")}
        if _delta is not None:
            base, source = _delta
            includes_uncommitted = _worktree_dirty(repo)   # True for -c live tree; False for a clean --pr worktree
            write_diff_hunks(repo, base, source,
                             _hunks_path_for(args.out), args.diff_context,
                             includes_uncommitted)
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
