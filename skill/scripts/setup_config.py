"""Setup config seeding: what `driver setup` writes into a target before the
scan, and the reads of the committed root config it needs to do so -- the
`.gitignore` block, the flat/groups manifest seed, the refusal that runs
before any write (`config_refusal`), `provision`, `migrate_config` (the only
reader of the legacy matrix file), and the committed `settings:` resolution
(`config_overrides`, `_draft_settings`). Split out of `setup_flow.py` along
the #1589 seams (#3405); nothing here imports `setup_flow` or its other
siblings.

#1577 (SEC-D1C): the artifact writes here go through the driver's own
confined O_NOFOLLOW writers rather than a plain open(); a target repo can
commit `.gitignore` as a symlink. Imported as a module, not as names
(tests/test_layout.py rule 1).
"""
import os
import re
import subprocess
import sys

from scripts import discovery
from scripts import repo_config  # #1681: the one place the config names live
from scripts import config_schema  # #1681 Plan 2: the settings trust classes
from scripts import groups_schema  # #2229: the committed-config schema owner
from scripts import safe_git  # #2006: the target-facing git probe
from scripts import plan_contract  # #3409: the artifact directory's name
from scripts import run_manifest  # #3602: pre-write HEAD baseline receipt
from scripts.phases import runio


# #1135: this block ignores run artifacts under .panopticon/ while leaving the
# directory itself visible. Applied ONLY to a repo that does not already ignore
# the .panopticon DIRECTORY outright -- see _ensure_gitignore.
#
# #1681: the committed config is at the REPO ROOT now, not under .panopticon/,
# so nothing under the blanket is meant to be committed -- neither a per-file
# negation nor the `!.panopticon/` directory one that used to re-include the
# directory so the legacy matrix file could be committed out of it (fix round
# 3, M5). `.panopticon/*` ignores the CONTENTS and leaves the directory itself
# visible on its own, so re-including it buys a target nothing and re-exposes a
# directory of run artifacts to the next `git add .`. The DRAFT is at the root
# too, and it is derived, so it joins the always-ignore list below.
_PANOPTICON_ARTIFACT_ENTRIES = [
    plan_contract.ARTIFACT_DIR + "/*",
]
_DRAFT_IGNORE_ENTRY = repo_config.DRAFT_NAME
_ALWAYS_IGNORE_ENTRIES = [".claude/settings.local.json", _DRAFT_IGNORE_ENTRY]
# Un-negatable blanket directory ignores: re-including anything under one of
# these would require REWRITING the line (git cannot re-include a file whose
# parent directory is excluded). We leave them untouched (#1135). The
# `.panopticon/*` form is NOT here -- it is negation-compatible, so a missing
# negation is simply appended.
_PANOPTICON_DIR_BLANKET = {
    plan_contract.ARTIFACT_DIR, plan_contract.ARTIFACT_DIR + "/",
    "/" + plan_contract.ARTIFACT_DIR, "/" + plan_contract.ARTIFACT_DIR + "/",
    # #run7 ARC-A2B: a `**/`-prefixed blanket also excludes the directory, so
    # git cannot re-include anything out of it -- treat it as un-negatable too
    # (else provision() would append an artifact block that can't take effect
    # and spuriously rewrites .gitignore).
    "**/" + plan_contract.ARTIFACT_DIR, "**/" + plan_contract.ARTIFACT_DIR + "/",
}

# #1509: the set above enumerates SPELLINGS, and it missed the glob form
# `.panopticon*/` -- which this project's own .gitignore uses deliberately, so a
# preserved run renamed `.panopticon.prev-<stamp>` stays ignored. Setup then read
# the repo as un-blanketed, appended the committable block, and its
# `!.panopticon/` negation RE-EXPOSED the whole directory: a repo's own policy
# rewritten for a spelling nobody had listed, without being asked.
#
# Enumerating one more spelling would just move the goalposts. `git check-ignore`
# is authoritative and understands every form, so it decides whenever the target
# is a checkout; this pattern is the fallback for targets that are not.
_PANOPTICON_BLANKET_RE = re.compile(
    r"^/?(\*\*/)?" + re.escape(plan_contract.ARTIFACT_DIR) + r"\*?/?$")


# The forms that ignore only the directory's CONTENTS. A negation can still
# re-include a file under these, so they are committable-compatible.
_CONTENTS_FORM_RE = re.compile(
    r"^/?(\*\*/)?" + re.escape(plan_contract.ARTIFACT_DIR) + r"/\*{1,2}$")

_CHECK_IGNORE_LINE = re.compile(r"^(.*):(\d+):(.*)$")

# The file `_git_blanket_pattern` asks git about: a real setup artifact INSIDE
# `.panopticon/`, which is what makes the answer meaningful (see its docstring).
_BLANKET_PROBE_PATH = os.path.join(plan_contract.ARTIFACT_DIR, "setup-report.md")


def _git_blanket_pattern(repo, runner=subprocess.run):
    """The .gitignore pattern git says ignores a file under `.panopticon/`.

    Returns the pattern string, "" when git says nothing ignores it, or None
    when git could not answer (not a checkout, git missing, unexpected exit) --
    None falls back to pattern matching rather than guessing.

    Asks about a FILE INSIDE the directory, never the directory itself.
    Measured: `check-ignore -- .panopticon` answers 0 in a repo with no commits
    and 1 in the same repo once it has one, for the identical `.panopticon*/`
    pattern -- so the directory query cannot be trusted. The file query is
    stable, and git's answer names the pattern that actually applies, which is
    what decides negatability."""
    # #2006 fix round 2: `repo` is the reviewed tree, and this ran bare `git` with
    # NO `env=` at all -- so the target's `core.fsmonitor` executed during setup,
    # and an inherited `GIT_DIR` answered for a DIFFERENT repository than the one
    # asked about. `safe_git.probe` closes both; `runner` stays the seam.
    try:
        r = safe_git.probe(repo, ["check-ignore", "-v", "--", _BLANKET_PROBE_PATH],
                           runner=runner, timeout=10)
    except safe_git.RepositoryRefused as exc:
        # Same shape validate, discovery and the run manifest print. Returning
        # None is the documented "git could not answer" path (pattern matching
        # decides), so setup continues -- but never silently.
        print("setup: target Git probe REFUSED (%s); the reviewed tree's own Git "
              "configuration is not trusted to run, so the gitignore pattern is "
              "inferred instead of asked for" % exc, file=sys.stderr, flush=True)
        return None
    except Exception:                                     # noqa: BLE001
        return None
    if r.returncode == 1:
        return ""                          # git is sure: nothing ignores it
    if r.returncode != 0:
        return None                        # 128 = not a git repository
    line = (r.stdout or "").split("\t", 1)[0]
    m = _CHECK_IGNORE_LINE.match(line.strip())
    return m.group(3) if m else None


def _dir_blanket_ignored(repo, have):
    """Whether the .panopticon DIRECTORY itself is already ignored.

    That is the question that matters: git cannot re-include a file whose parent
    directory is excluded, so a directory blanket is un-negatable and must be
    left alone. `.panopticon/*` ignores the CONTENTS, not the directory, so it is
    committable-compatible and correctly reads False here."""
    pattern = _git_blanket_pattern(repo)
    if pattern is not None:
        # Ignored by a CONTENTS-form pattern is not a blanket: the negation
        # block still works there, which is the whole distinction.
        return bool(pattern) and not _CONTENTS_FORM_RE.match(pattern)
    return bool(have & _PANOPTICON_DIR_BLANKET) or any(
        _PANOPTICON_BLANKET_RE.match(line) for line in have)


def _seed_groups_manifest(repo):
    """#485(1): write a STARTER committable root config from the repo's
    top-level directory spine -- deterministic, never clobbers an existing
    one. Returns (path, created:bool, group_names). Through the ONE writer
    (setup_proposal.dump_config_yaml), so the seed carries `version: 1`."""
    path = os.path.join(repo, repo_config.CONFIG_NAMES[0])
    committed = repo_config.resolve(repo).path      # the alias name wins if it is the one on disk
    if committed is not None:
        names = list((discovery.load_catalog(repo) or {}).keys())
        return committed, False, names
    from scripts import setup_proposal as sp
    files = discovery.discover_repo_files(repo)
    tops = sorted({p.split("/", 1)[0] for p in files
                   if "/" in p and not p.startswith(".")})
    # #1108/#1481: directory names are untrusted target content -- keep only names the
    # schema accepts without error (no invalid name, case/chunk twin or Ungrouped sink).
    candidate = {t: {"match": ["%s/**" % t]} for t in tops}
    parsed, _errors = groups_schema.parse_groups({"groups": candidate})
    colliding = groups_schema.colliding_ids(parsed)
    valid = {n: {"match": candidate[n]["match"]} for n in parsed if n not in colliding}
    text = sp.dump_config_yaml(valid)
    # #run7 COD-F1B: create atomically; O_EXCL closes the check-then-truncate
    # TOCTOU so a concurrent seed can never clobber a file that appeared after
    # the check. O_NOFOLLOW: never through a planted link (#1577).
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags, 0o644)
    except FileExistsError:
        names = list((discovery.load_catalog(repo) or {}).keys())
        return path, False, names
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text)
    return path, True, list(valid)


seed_groups_manifest = _seed_groups_manifest
seed_flat_manifest = _seed_groups_manifest


def _ensure_gitignore(repo):
    """#485(2)/#1135: make sure run artifacts and the local hook settings never
    get committed, WITHOUT ever rewriting existing .gitignore content -- only
    missing entries are appended.

    Returns the list of entries appended. If the repo already blanket-ignores
    the .panopticon DIRECTORY (``_PANOPTICON_DIR_BLANKET``), that ignore is left
    exactly as-is: the ``.panopticon/*`` artifact block is NOT applied (applying
    it used to migrate the line in place -- a spurious working-tree modification
    that also re-exposed the directory, #1135). A fresh repo (or one already
    using the ``.panopticon/*`` form) gets the full block; any already-present
    entry is skipped so re-runs are true no-ops.

    #1681: the committed config is at the root, so nothing here decides whether
    it is trackable -- the always-ignore entries (the local hook settings and
    the derived root DRAFT) are appended either way. Nothing under
    ``.panopticon/`` is committable, so nothing written here re-includes it
    (fix round 3, M5).

    #1509: "already blanket-ignores" is decided by ``git check-ignore`` where
    possible, not by matching spellings -- the literal set missed the glob form
    and its negation then re-exposed the directory."""
    gi = os.path.join(repo, ".gitignore")
    try:
        with open(gi, encoding="utf-8") as fh:
            existing = fh.read()
    except OSError:
        existing = ""
    have = {ln.strip() for ln in existing.splitlines()}
    dir_blanket = _dir_blanket_ignored(repo, have)
    wanted = list(_ALWAYS_IGNORE_ENTRIES)
    if not dir_blanket:
        wanted = _PANOPTICON_ARTIFACT_ENTRIES + wanted
    added = [e for e in wanted if e not in have]
    if added:
        with runio._open_a_nofollow(gi) as fh:   # #1577: never append through a link
            if existing and not existing.endswith("\n"):
                fh.write("\n")
            fh.write("# panopticon run artifacts (--setup #485)\n")
            for e in added:
                fh.write(e + "\n")
    return added


def _git_path_clean(repo, path):
    """Whether ``path`` has no index/worktree status before setup writes it.

    This is the provenance half of #3602: a digest taken after setup cannot
    distinguish its append from an edit already present before setup. Probe
    the one path first and fail closed (False) on a non-repository, refusal,
    failed probe, or any status record.
    """
    try:
        result = safe_git.probe(
            repo, ["status", "--porcelain", "-z", "--", path], timeout=15
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return result.returncode == 0 and not (result.stdout or "")


def config_refusal(repo):
    """The reasons SETUP must not write against this tree, or [] (#1681 I2).

    `driver run` fails loud on an authored-but-invalid root config; setup was
    the one path that proceeded. `discovery._committed_matrix` and
    `_committed_exclude_paths` answered `{}`/`[]` for ANY unreadable document,
    so ingest merged against an empty matrix, dropped the operator's
    `exclude_paths:`, and told them to move a draft that discards their own
    matrix over the real file. Both raise now (#2229); this turns the refusal
    into a named status before either runs.

    Refuses on the document's ERRORS (no `version: 1`, over-cap, unparseable,
    a legacy-only tree) and on the RESOLVER's own disclosures -- a refused
    symlink at either name resolves to no document with no error at all, and
    both names present is an ambiguity nothing should be written against.

    And on the SCHEMA's errors, per the owner ruling 2026-09-27 (#2189): a
    scalar `match:`, a non-mapping `groups:`, an invalid or reserved group name
    used to reach the merge as a raw body -- character-split, crashing `driver
    setup` with an AttributeError and no JSON status, or quietly proposing a
    catalog over the operator's own. A run degrades per-entry; a WRITE cannot.

    The informational disclosures `read_document` adds on TOP of a readable
    document -- the retired JSON config, a legacy matrix file beside a valid
    root config, unknown top-level keys -- are deliberately not refusals: they
    are printed elsewhere, and a first run on a tree with no config at all is
    the ordinary case, not a fault."""
    doc = repo_config.read_document(repo)
    reasons = list(doc.errors) + list(repo_config.resolve(repo).disclosures)
    if doc.doc is not None:
        _groups, schema_errors = groups_schema.parse_groups(doc.doc)
        _globs, exclude_errors = groups_schema.parse_exclude_paths(doc.doc)
        reasons += schema_errors + exclude_errors
    if not reasons:
        return []
    return reasons + ["fix it or delete it; nothing was written"]


def provision(repo):
    """Scaffold the .gitignore entries (idempotent). Returns a summary.
    #1681: the JSON config is retired (its keys live under `settings:`), and a
    tree whose root config cannot be read -- a legacy-only tree, an invalid
    one, a refused symlink -- is refused with its own remedy before the first
    byte is written (`config_refusal`); setup does not read the legacy file."""
    refusal = config_refusal(repo)
    if refusal:
        raise ValueError("; ".join(refusal))
    gitignore_clean = _git_path_clean(repo, ".gitignore")
    gitignore_baseline = (run_manifest.git_path_baseline(repo, ".gitignore")
                          if gitignore_clean else None)
    added = _ensure_gitignore(repo)
    return {"gitignore_added": added,
            # Consumed by phases.setup immediately: only this combination says
            # the post-write identity belongs wholly to setup (#3602).
            "gitignore_setup_owned": bool(added and gitignore_clean
                                            and gitignore_baseline is not None),
            "gitignore_setup_baseline": gitignore_baseline,
            "legacy_present": repo_config.legacy_present(repo),
            "stale_config_json": repo_config.stale_config_json(repo)}


def migrate_config(repo):
    """`driver migrate-config`: the ONLY reader of the legacy matrix file
    `repo_config.LEGACY_GROUPS_PATH` (#1681, ruling 3: no fallback). Reads it
    through the same cap and schema, writes the root config through the one
    writer with committed order preserved, leaves the legacy file for the
    operator to delete, refuses if a root config already exists -- or if the
    resolver merely DISCLOSED one (a refused symlink at either name resolves
    to no path, and overwriting it would destroy the operator's link).
    Returns (path, message)."""
    # Nested, not module level: the driver's import path stays third-party-free (#2369).
    import yaml
    from scripts import setup_proposal as sp
    res = repo_config.resolve(repo)
    if res.path is not None or res.disclosures:
        # Not `res.path is not None` alone: a REFUSED symlink at either config
        # name resolves to no path WITH a disclosure, so that guard read an
        # operator's own `<config> -> elsewhere` link as "nothing there" and let
        # the write below through -- and `runio._open_w_nofollow`'s
        # unlink-and-retry then destroyed the link and wrote a regular file in
        # its place. Anything the resolver has something to say about is a
        # config this verb must not overwrite.
        raise ValueError("; ".join(res.disclosures)
                         or "%s already exists; nothing to migrate" % res.path)
    legacy = os.path.join(repo, repo_config.LEGACY_GROUPS_PATH)
    if not os.path.isfile(legacy) or os.path.islink(legacy):
        raise ValueError("no `%s` to migrate" % repo_config.LEGACY_GROUPS_PATH)
    with open(legacy, "rb") as fh:
        data = fh.read(repo_config.MAX_CONFIG_BYTES + 1)
    if len(data) > repo_config.MAX_CONFIG_BYTES:
        raise ValueError("%s exceeds %d bytes; refused" % (legacy, repo_config.MAX_CONFIG_BYTES))
    try:
        # The cap, the shape, the schema and the PARSE are all refusals in one
        # currency: `driver migrate-config` catches ValueError and prints it, so
        # a YAMLError escaping here would be a traceback where every sibling
        # refusal is a message.
        doc = yaml.safe_load(data.decode("utf-8")) or {}
    except (UnicodeDecodeError, yaml.YAMLError) as exc:
        raise ValueError("%s unreadable: %s" % (legacy, exc)) from exc
    if not isinstance(doc, dict):
        raise ValueError("%s must be a mapping" % legacy)
    # #2229: the owner normalizes, validates and shapes -- this verb had its own
    # copy of all three, reaching across for `discovery._leaf_body`.
    raw, errors, disclosures = groups_schema.normalize_groups_mapping(doc.get("groups"))
    for line in disclosures:
        print("%s: %s" % (repo_config.LEGACY_GROUPS_PATH, line), file=sys.stderr)
    parsed, parse_errors = groups_schema.parse_groups({"groups": raw})
    excludes, exclude_errors = groups_schema.parse_exclude_paths(doc)
    errors += parse_errors + exclude_errors
    if errors:
        raise ValueError("%s: %s" % (legacy, "; ".join(errors)))
    groups = groups_schema.committed_bodies(parsed)
    path = os.path.join(repo, repo_config.CONFIG_NAMES[0])
    with runio._open_w_nofollow(path) as fh:
        fh.write(sp.dump_config_yaml(groups, exclude_paths=excludes))
    return path, ("wrote %s from %s; review it, commit it, then delete %s"
                  % (path, repo_config.LEGACY_GROUPS_PATH, repo_config.LEGACY_GROUPS_PATH))


_CONFIG_INT_KEYS = ("max_per_group", "max_groups")


def config_overrides(repo):
    """The size-policy overrides from the root config's `settings:` (#1681),
    CLAMPED to their bands (Plan 2, ruling 6b).

    Returns `{"max_per_group": int|None, "max_groups": int|None}`. The clamp
    happens HERE as well as at run time because setup is where the numbers
    become a committed matrix: a `max_per_group: 5000` that reached
    `build_spine` would plan one cell over the whole repo and then be clamped
    on every later run, so the agent would plan against arithmetic no run
    ever applies. Disclosures go to stderr, as `_committed_exclude_paths`
    does -- setup is interactive.
    """
    return {k: _committed_settings(repo).get(k) for k in _CONFIG_INT_KEYS}


def _committed_settings(repo):
    """The committed config's EFFECTIVE settings (#1681 Plan 2): what the
    trust classes let through, clamped, with every disclosure printed once.

    One resolution behind both readers below, so `config_overrides` keeps the
    two-int answer the plan pins while `_draft_settings` can still see the
    other grain keys the operator committed.
    """
    doc = repo_config.read_document(repo)
    resolved = config_schema.resolve_settings(
        {}, config_schema.parse_settings(doc.doc or {}))
    for line in resolved.disclosures:
        print("setup: %s" % line, file=sys.stderr)
    return resolved.effective


def _draft_settings(repo, max_per_group, max_groups):
    """The `settings:` mapping the draft carries: every GRAIN key the operator
    already committed, overlaid by the sizes they passed on this invocation.

    #1504, one key over: the draft is what the completion message tells them
    to move over the committed file, so a key it does not carry is a key they
    lose by following our own instructions. #1681 Plan 2 narrows what "a key"
    means -- the effective grain keys, never a gate or operator-only one. A
    committed `security: redteam` is refused at run time either way, and
    copying it into the draft would suggest that promoting the draft makes it
    stick. The CLI is not clamped (the operator's call), but a value outside
    the band is warned about here, because the file they are about to commit
    WILL be clamped on every run that reads it.
    """
    # Every GRAIN key the committed file resolves, not just the two sizes:
    # `config_overrides` answers with the size knobs alone (its signature is
    # pinned), so building the draft from it dropped a committed
    # `include_fixtures` -- a working grain setting lost by following our own
    # promotion instruction (final review F3). A gate or operator-only key is
    # still never carried: `effective` cannot hold an operator key at all, and
    # copying a honoured gate key would suggest that promoting the draft makes
    # it stick.
    settings = {k: v for k, v in _committed_settings(repo).items()
                if config_schema.CLASS_OF.get(k) == "grain"}
    for key, value in (("max_per_group", max_per_group), ("max_groups", max_groups)):
        if value is None:
            continue
        settings[key] = value
        low, high = config_schema.CLAMPS[key]
        if not low <= value <= high:
            print("setup: --%s %d is outside the committed band %d-%d; the draft "
                  "carries it, and a run will clamp it to %d"
                  % (key.replace("_", "-"), value, low, high,
                     min(max(value, low), high)), file=sys.stderr)
    return {k: v for k, v in settings.items() if v is not None}
