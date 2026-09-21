"""Driver I/O core: paths, artifact reads/writes, child processes, the review root."""
import copy
import functools
import json
import os
import shutil
import subprocess
import sys

import scripts.config_schema as config_schema
import scripts.diff_map as diff_map
import scripts.evidence as evidence
import scripts.groups_schema as groups_schema
import scripts.hosts as hosts
import scripts.ocrdb as ocrdb
import scripts.redact as redact
import scripts.repo_config as repo_config
import scripts.run_manifest as run_manifest
import scripts.safe_write as safe_write


CHECKPOINT_KINDS = ("scout", "review", "verify", "scan")

# The skill/scripts directory -- the parent of this package, not its own
# directory: `_script()` and `phases.child._child_env()` resolve sibling entry
# scripts and the child PYTHONPATH against it, and both used to read it from
# driver.py's own __file__. Pinned by ScriptsDirTest.
_SCRIPTS_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def _redact_output(text):
    # #run7 SEC-B2C: the patterns live in scripts.redact, single-sourced with
    # synthesize's report-body redaction so the two can never drift.
    return redact.redact(text)

class DriverError(Exception):
    """A hard phase failure. main() converts it to a status:'error' result."""

def _script(name):
    return os.path.join(_SCRIPTS_DIR, name)

# §5.1 per-run folders. These artifacts stay at `.panopticon/` top-level: setup
# files, the resume anchors (run-manifest / setup-manifest), the cross-run EPSS
# cache, the transient write-guard allowlist (the hook reads it CWD-relative and is
# run-context-free), and the compat report symlinks. EVERY other artifact is per-run
# and routes into `.panopticon/runs/<tag>/`. The durable reports live top-level and
# tag-named (`<tag>-report.json`), so the run folder can be cleared — reclaiming the
# findings/verdicts bulk — without losing any report.
_TOP_LEVEL = frozenset({
    "run-manifest.json", "setup-manifest.json",
    "setup-proposal.json", "setup-complete.json", "setup-scan-brief.md",
    "setup-spine.json", "setup-report.md", "setup-report.json",
    # #1507: setup's dispatch request + prompts. These used to route through the
    # per-run resolver, which meant they landed in whatever `runs/latest` pointed
    # at -- an unrelated review run, whose own dispatch-request.json setup then
    # overwrote. Setup is not a run; its artifacts live beside its siblings above.
    "setup-dispatch-request.json", "setup-prompts",
    "epss-cache.json", "write-allowlist.json",
    "report.json", "report.json.html",
})

HOST_CAPABILITIES = "host-capabilities.json"

def _run_tag(review_root):
    """The active run's folder name from the manifest, or None before one exists
    (setup / pre-discovery) — callers then fall back to the flat top-level."""
    return run_manifest.run_tag(run_manifest.load_manifest(review_root))

def _pano(review_root, *parts):
    """Resolve a `.panopticon` artifact path: top-level for setup/anchor/cache/report
    (`_TOP_LEVEL`), else per-run under `.panopticon/runs/<tag>/`. The manifest anchors
    the tag, so every done-predicate (which stats a `_pano` path) resolves the same
    folder on every resume."""
    base = os.path.join(review_root, ".panopticon")
    if parts and parts[0] not in _TOP_LEVEL:
        tag = _run_tag(review_root)
        if tag is not None:
            return os.path.join(base, "runs", tag, *parts)
    return os.path.join(base, *parts)

def _report_out(review_root):
    """The durable, top-level, tag-named report path passed to synthesize as --out;
    `_part2.json` and `.html` derive from this stem, so all three land top-level and
    tag-named. Falls back to flat `report.json` when there is no manifest."""
    tag = _run_tag(review_root)
    name = f"{tag}-report.json" if tag else "report.json"
    return os.path.join(review_root, ".panopticon", name)

def _confine_link_parent(link_path):
    """The real directory `_relink` may write into, or a DriverError naming the
    component that is not one (#1574 COD-E2B).

    `_relink` was the one artifact writer in this module with no confinement:
    it checked `islink`/`exists` on the LINK and nothing on the path leading to
    it, so a target that force-commits `.panopticon/runs` as a symlink (the
    `git add -f` vector `_manifest_committed` documents) redirected an
    `os.remove` + `os.symlink` to `<elsewhere>/latest` on the first `driver
    run`, before any phase executed. Anchor on the path's own `.panopticon`
    segment, exactly as `_confine_artifact_path` does, and require every
    component of the link's PARENT to be a real directory -- `realpath` equal to
    the path joined so far. The final component is deliberately exempt: it IS
    the symlink being written, and `runs/latest` is a legitimate one.

    Returns the parent with any symlinked ANCESTOR of `.panopticon` resolved
    (`/tmp` -> `/private/tmp` on macOS is not a plant), so the caller's
    `makedirs`/`symlink` cannot re-traverse what was just vetted. A path with no
    `.panopticon` segment is not an artifact path and is left be.
    """
    parent = os.path.dirname(os.path.abspath(link_path))
    parts = parent.split(os.sep)
    if ".panopticon" not in parts:
        return parent
    cut = parts.index(".panopticon")
    base = os.sep.join(parts[:cut + 1]) or os.sep
    if os.path.islink(base):
        raise DriverError(
            "refusing to relink through a symlinked artifact directory: %s" % base)
    real = os.path.realpath(base)
    for seg in parts[cut + 1:]:
        real = os.path.join(real, seg)
        if os.path.realpath(real) != real:
            raise DriverError(
                "refusing to relink through a symlinked path component: %s" % real)
    return real

def _relink(link_path, target_name):
    """Create or replace a relative symlink `link_path -> target_name` (same dir).

    Confined (`_confine_link_parent`) and atomic: the new link is created beside
    the destination and `os.replace`d onto it, which swaps the LINK rather than
    following it and never leaves the path missing for a reader. The old
    remove-then-create pair was both a window and, on a planted parent, a
    delete primitive outside the tree."""
    parent = _confine_link_parent(link_path)
    os.makedirs(parent, exist_ok=True)
    final = os.path.join(parent, os.path.basename(link_path))
    tmp = "%s.relink-%d.tmp" % (final, os.getpid())
    if os.path.islink(tmp) or os.path.exists(tmp):
        os.remove(tmp)                        # our own leftover, never the target's
    os.symlink(target_name, tmp)
    try:
        os.replace(tmp, final)
    except OSError:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise

def _ensure_run_symlinks(review_root):
    """Point `.panopticon/runs/latest` at the active run folder (best-effort; a
    platform without symlinks simply skips it — the tag-named paths still work).

    #1574: best-effort covers OSError only. A DriverError from the confinement
    is a planted path component, not a platform limitation, and propagates."""
    tag = _run_tag(review_root)
    if not tag:
        return
    try:
        _relink(os.path.join(review_root, ".panopticon", "runs", "latest"), tag)
    except OSError:
        pass

def _prompt_safe(text):
    """Neutralize characters that could break prompt-line structure so a hostile
    filename cannot inject bullet lines into a reviewer's prompt (#1190 AGT-A1A).
    C0/C1 control chars, DEL, and the Unicode line/paragraph separators are
    rendered as inert \\xNN / \\uNNNN escapes; ordinary characters (including
    non-ASCII) pass through unchanged, so legitimate paths are untouched."""
    out = []
    for ch in text:
        o = ord(ch)
        if o < 0x20 or o == 0x7f or 0x80 <= o <= 0x9f or o in (0x2028, 0x2029):
            out.append("\\x%02x" % o if o < 0x100 else "\\u%04x" % o)
        else:
            out.append(ch)
    return "".join(out)

def _abs_files(review_root, files):
    """A cell's files absolutized against review_root (#975) — RAW, un-sanitised.

    The ONE place this expression is spelled (#1607). It was inlined at four
    sites beside `_abs_file_list`, which applied it again per line: the entry's
    `files` and the prose the prompt carries agreed by inspection rather than
    by construction, against plan 2b's rule that no path expression is written
    twice.

    Un-sanitised on purpose: the read-guard matches these byte-for-byte after
    realpath (spec §7.2), so nothing here may touch the bytes. `_prompt_safe`
    belongs at the point the paths become a prompt — which is `_abs_file_list`,
    below, and nowhere else.
    """
    return [os.path.abspath(os.path.join(review_root, f)) for f in files]

def _abs_file_list(review_root, files):
    """Bullet list of a cell's files absolutized against review_root (#975): the
    reviewer subagent inherits the HOST's cwd, not review_root/the --pr worktree,
    so a bare-relative path resolves against the wrong tree. File-list specific —
    do NOT route tests or other bullet lists through this; they stay
    repo-relative. Paths are prompt-sanitized (#1190) so a control char in a
    filename cannot inject prompt lines.

    The resolution itself is `_abs_files`: same list, same order, sanitized for
    prose here only."""
    return "\n".join(
        "- " + _prompt_safe(path)
        for path in _abs_files(review_root, files)
    ) or "- (no files)"

def _load_json(path):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None

# The no-follow artifact open lives in `scripts.safe_write` (#1735), not here:
# `run_manifest` needs it for the manifest's own `<name>.tmp` staging write and
# may not import this package (layout rule 3 -- `phases/*` imports
# `run_manifest`, not the other way), and `synth/*` may not either. An alias of
# a definition from OUTSIDE the package is what rule 4 leaves legal and asks to
# justify: ~15 call sites across `phases/` and `setup_flow.py` -- and the
# suite's one `mock.patch("scripts.phases.runio._open_w_nofollow")` -- spell it
# with these names, so keeping them is what keeps ONE patch target for them.
# tests/test_safe_write.py pins the identity, so a second implementation
# cannot appear behind the alias.
_confine_artifact_path = safe_write.confine_artifact_path
_open_w_nofollow = safe_write.open_w_nofollow
_open_a_nofollow = safe_write.open_a_nofollow

def _write_json(path, data, atomic=False):
    """Write `data` as the artifact at `path`.

    `atomic` (F6) writes `<path>.tmp` and `os.replace`s it into place -- the
    same tmp-then-rename `persist.write_reply` uses -- for a file a reader can
    catch mid-write. The default stays the in-place O_TRUNC write: a
    once-per-run artifact nobody is watching does not need a second inode, and
    the symlink defence is identical either way (the tmp goes through the same
    `_open_w_nofollow`, and `os.replace` onto a symlinked destination replaces
    the LINK, never the file it points at). `usage.json` is the caller that
    asks for it: the loop rewrites it once per ENTRY now, while host children
    are live in the reviewed tree and the guide invites an operator to read it
    as a progress surface. A failed atomic write can leave the `.tmp` behind;
    the artifact it would have replaced is untouched, which is the point."""
    _confine_artifact_path(path)              # SEC-X0X: before makedirs, which would
    os.makedirs(os.path.dirname(path), exist_ok=True)   # otherwise follow a symlinked dir
    target = path + ".tmp" if atomic else path
    with _open_w_nofollow(target) as fh:
        json.dump(data, fh, indent=2, sort_keys=True)
    if atomic:
        os.replace(target, path)
    return path

def session_dir(manifest):
    """Where the HOST SESSION runs -- NOT the review root, NOT the target.

    See synthesize.py's #calibration-2/#calibration-4 comment; this is that
    expression, single-sourced so the PROBE that gates the token ledger
    (probes.claude.probe_usage_source, via driver._establish_host_posture) and
    the COLLECTOR that builds it (synthesize._collect_host_usage) cannot
    disagree about which transcript they mean. They did disagree: the probe
    was handed `args.target` and refuted off the scanned repo's slug, which
    took `meta.cost.tokens` to null on every external-target run while the
    collector was looking somewhere else entirely.

    `session_dir` is deliberately not a manifest FIELD in the anti-drift sense
    -- driver.run() assigns it in memory after write_manifest -- so a resume
    that needs it passes --session-dir again. cwd is the default because it is
    correct for the documented `driver run <target>` invocation.
    """
    return (manifest or {}).get("session_dir") or os.getcwd()

def host_evidence(review_root):
    """This run's capability evidence, or {} when there is none.

    {} is not an error path: `hosts.posture()` turns it into all-unknown, which
    means nothing is enforced. An absent or unreadable artifact must fail
    CLOSED (spec 5, 9.2) -- on claude as much as on any exotic host -- and
    that is the whole reason this returns a mapping rather than raising.

    I3: the old one-liner promised that and did not deliver it. `or {}` only
    covers a FALSY parse -- null, 0, "", [], {} -- so a JSON body that parsed
    to a truthy non-mapping went straight into `.get` and raised
    AttributeError: `[1,2]`, `"hello"` and `5` all crashed the run, and
    `{"capabilities": 7}` returned the integer 7 as though it were evidence.
    `hosts.posture` was hardened for exactly this shape ("a crash mid-run is
    not failing closed -- it is failing"), but the LOADER that feeds it was
    not, and `requests.require_unenforced_ack` consumes this output raw. This
    file is written to a `.panopticon` path a hostile target can pre-commit,
    so "unparseable value" and "unparseable container" are the same defect.
    """
    body = _load_json(_pano(review_root, HOST_CAPABILITIES))
    caps = body.get("capabilities") if isinstance(body, dict) else None
    return caps if isinstance(caps, dict) else {}

def host_cli_flags(review_root):
    """This run's OPERATIONAL CLI facts (hosts.CLI_FLAGS), or {} (D10 F1).

    The sibling of `host_evidence`, reading the other block of the same
    artifact and failing closed the same way: {} means nobody asked the CLI,
    and every consumer reads that as "do not use the flag". Separate from the
    capabilities block on purpose -- these facts gate nothing, and
    `driver._establish_host_posture` must not refuse a resume because the
    operator upgraded their CLI mid-run."""
    body = _load_json(_pano(review_root, HOST_CAPABILITIES))
    flags = body.get(hosts.CLI_FLAGS) if isinstance(body, dict) else None
    return flags if isinstance(flags, dict) else {}

def _json_parses(path):
    return _load_json(path) is not None

def _load_return_json(path):
    """Read a RETURN-PERSIST artifact -- a file whose content an AGENT produced as
    its reply and the HOST wrote to disk verbatim -- tolerating the markdown fence
    or prose preamble a chat reply wraps JSON in.

    run-9 showed this is a property of the RETURN channel, not prompt wording: on
    one model in one session, 233/233 self-write files were clean JSON while 0/25
    scouts and 94/95 tool advisors came back fence-wrapped, even under an explicit
    "raw JSON only, no fences" instruction -- because a model's final
    conversational turn looks like a chat reply and instructions do not reliably
    suppress the wrapper. So the confirm-it-parses step on a returned file MUST
    unwrap, or an unparseable-but-recoverable scout reads as "no output" and the
    run re-dispatches it forever. Uses the same tolerant reader
    (evidence.load_json_tolerant) the tool-verdict path already relies on.

    Distinct from _load_json, which stays STRICT: it reads artifacts the driver
    itself writes (groups.json, out-file hashes, run manifests, the derived
    coverage-*.json), where a markdown fence would signal tampering rather than a
    chat wrapper and must never be silently accepted. Returns the parsed value, or
    None when unrecoverable."""
    try:
        with open(path, encoding="utf-8") as fh:
            body = fh.read()
    except OSError:
        return None
    try:
        return evidence.load_json_tolerant(body)
    except ValueError:
        return None

def _return_json_parses(path):
    return _load_return_json(path) is not None

def _disclose(lines):
    for line in lines:
        print("driver: %s" % line, file=sys.stderr)

@functools.lru_cache(maxsize=8)
def _parse_committed_groups(path, _mtime):
    """Parse + validate the root config, memoized on (path, mtime) so a single
    `driver run` re-parses the file at most once per content version instead
    of once per group/phase (#1033). The disclosures print HERE, where a cache
    MISS is what runs -- that is what makes "once per content version" true
    rather than once per caller. The key covers this file's own content only:
    whether the OTHER accepted name, or a retired `.panopticon/` settings file,
    is ALSO present is not part of it, so such a disclosure can go stale until
    this file's mtime moves (accepted -- the parsed content is always fresh).
    Never mutate the returned structures; callers get deep copies via
    load_committed_groups."""
    doc = repo_config.read_document(os.path.dirname(path))
    _disclose(doc.disclosures)
    if doc.doc is None:
        return {}, list(doc.errors)
    return groups_schema.parse_groups(doc.doc)

def load_committed_groups(review_root):
    """Parse the committed root config via groups_schema (P1). Every branch is
    repo_config's to decide -- this reads the document ONCE and reports what it
    says. A MISSING file is an error (the driver run requires a committed
    matrix -- `driver setup` produces it), not an empty success; a legacy
    `.panopticon/` matrix file with no root file is refused with the migration
    remedy (#1681, no fallback); and a REFUSED candidate -- a symlink at either
    accepted name -- is disclosed on stderr before that missing-file error, so
    a config sitting right there is never silently reported as absent."""
    doc = repo_config.read_document(review_root)
    if doc.path is None:
        if doc.errors:
            # Legacy-only tree: read_document already carries the remedy.
            return {}, list(doc.errors)
        # Nothing accepted and nothing authored -- but a candidate may have
        # been REFUSED (a symlink at either name), and that refusal is the
        # whole reason there is no config to read. Say it out loud.
        _disclose(doc.disclosures)
        return {}, ["no committed %s at %s -- run `panopticon setup` first"
                    % (repo_config.CONFIG_NAMES[0], review_root)]
    try:
        mtime = os.path.getmtime(doc.path)
    except OSError as exc:
        return {}, ["%s unreadable: %s" % (doc.path, exc)]
    groups, errors = _parse_committed_groups(doc.path, mtime)
    # Deep-copy so a caller mutating its result can never corrupt the shared
    # cache entry the next phase reads.
    return copy.deepcopy(groups), list(errors)

def committed_settings(review_root):
    """The root config's `settings:` section, parsed and classified (#1681
    Plan 2), empty when there is no usable config (missing, refused, or
    legacy-only -- none of which raises).

    Returns `config_schema.Parsed`: what the file ASKED for, what type-checks,
    and what was refused. It does NOT decide what any of it is worth -- the
    clamp and the ratchet need the command line, which only the driver has,
    so `driver._resolve_config` applies `config_schema.resolve_settings` on
    top of this and is the one place that prints the disclosures.
    """
    doc = repo_config.read_document(review_root)
    return config_schema.parse_settings(doc.doc or {})

def committed_exclude_paths(review_root):
    """The root config's top-level `exclude_paths:` globs, or `[]` (#1740).

    `exclude_paths:` pruned DISCOVERY and nothing else, so a repo that
    committed `tests/fixtures/**` still had every scanner walk the corpus and
    every fixture finding ingested -- and once #1740 made the fixture prune a
    disclosed, gate-counted class, the report's own redteam gate could FAIL on
    a directory the committed policy had already scoped out. The tools phase
    passes these to `run_tools --exclude` and the synthesize phase to
    `synthesize --tools-exclude`, so ONE committed policy governs the agentic
    scope, the scanners and the gate.

    Same parse seam `discovery._committed_exclude_paths` reads
    (`groups_schema.parse_exclude_paths` over `repo_config.read_document`), not
    a second copy of the rule -- two answers to "what did the repo exclude?"
    is the drift this shares a definition to avoid.

    Tolerant, and SILENT about errors: a missing, refused or invalid config
    yields `[]` rather than taking a run down, and discovery has already
    printed whatever was wrong with it (re-printing once per phase is noise).
    Erring toward [] is the safe direction -- it scopes nothing out, so a
    broken config can never quietly un-gate a finding.
    """
    doc = repo_config.read_document(review_root)
    globs, _errors = groups_schema.parse_exclude_paths(doc.doc or {})
    return globs

def _load_ocrdb_bundle():
    """ocrdb.load_bundle, converting a malformed-bundle ValueError into a
    DriverError so a corrupt bundle is a clean status:error, not a raw traceback
    that crashes the driver mid-phase (#1034)."""
    try:
        return ocrdb.load_bundle()
    except ValueError as exc:
        raise DriverError("OCRDb bundle unreadable: %s" % exc)

def resolve_review_root(target, base=None, pr=None, runner=subprocess.run):
    """Resolve the single review root, pinned once in the manifest (spec §5).

    - pr given: acquire the deterministic PR worktree (diff_map); its path is
      the root.
    - git repo: `git rev-parse --show-toplevel` from the target.
    - non-git: the target directory itself, symlinks resolved (#1640) -- every
      branch returns a resolved path, so nothing downstream has to ask.
    Returns (review_root, worktree, pr_base): worktree is the PR worktree to
    release at validate (else None); pr_base is the PR's base branch as read
    by the acquire (else None), for `run()` to pin as the manifest base.
    """
    if pr is not None:
        info = diff_map.acquire_pr(pr, repo=target, runner=runner)
        return info["worktree"], info["worktree"], info["base"]
    target = os.path.abspath(target)
    start = target if os.path.isdir(target) else os.path.dirname(target)
    try:
        # #run7 OPS-A1A: bound the probe. This runs at the very start of EVERY
        # `driver run`/`setup`, before any phase timeout; a wedged index.lock,
        # fsmonitor/watchman hook, credential prompt, or hung network FS would
        # otherwise block the whole resumable driver indefinitely. Catch the
        # timeout locally -- run()'s outer handler doesn't cover SubprocessError,
        # so it would escape as an uncaught traceback -- and fall through to the
        # existing non-git return.
        proc = runner(["git", "-C", start, "rev-parse", "--show-toplevel"],
                      capture_output=True, text=True, timeout=15)
        if proc.returncode == 0 and proc.stdout.strip():
            return os.path.realpath(proc.stdout.strip()), None, None
    except (OSError, subprocess.SubprocessError):
        pass
    # #1640: RESOLVED, like the git branch above (and like the --pr branch,
    # whose worktree sits under that resolved repo). This fallback used to hand
    # the root back as given, so a non-git directory reviewed through a symlink
    # (`~/work/proj -> /Volumes/x/proj`) produced findings paths whose
    # review-root component was itself a link -- which the write guard now
    # refuses by name, for what is the operator's own path rather than an
    # attack. Resolving here is what makes the guard's rule and the driver's
    # own path derivation agree, on every branch of this function.
    return os.path.realpath(start if os.path.isdir(start) else target), None, None

def _confined_to_root(review_root, path):
    """True iff the claim path resolves inside review_root. An absolute path or a
    `../`-escape resolves outside and is rejected (#1096) -- the claim's
    location.file is LLM/panel-supplied (steerable by injection planted in the
    reviewed repo), so it must not be able to point a downstream advisor at files
    outside the review tree.

    #run7 ARC-F2A: resolve SYMLINKS (realpath), not just `..`/join (abspath). A
    committed in-tree symlink whose lexical path starts with root+sep (e.g.
    `src/evil -> /etc/passwd`) passed the old abspath check, then the backup
    advisor's unconfined Read followed it out of the repo. realpath on a
    non-existent tail resolves the existing prefix and appends the rest lexically,
    so a legitimate not-yet-written path still confines correctly."""
    if not isinstance(path, str) or not path:
        return False
    root = os.path.realpath(review_root)
    full = os.path.realpath(os.path.join(root, path))
    return full == root or full.startswith(root + os.sep)

_DEFAULTS = {"host": "claude", "security": "standard"}

# Which host DRIVES this invocation, and on whose authority. Lifted out of
# `orchestrate._resolve_host` in #1637 P10 fix round 2, unchanged in behaviour:
# `driver readiness` has to gate on the host `driver loop` would pick, and
# `phases/` may not import `orchestrate` (tests/test_layout.py rule 3), so a
# copy in the preflight would have been a second precedence able to drift from
# the one it is checking. It belongs here anyway -- every ingredient already
# did: `_DEFAULTS` above, `_foreign_manifest` below, and `run_manifest`.
#
# `host` is the CLI's `--host` (None when absent) rather than an `args`
# namespace, because the two callers carry different shapes: `driver loop`'s
# args have `--reset` and the preflight's deliberately do not.
HOST_SOURCES = ("--host", "manifest", "default")


def resolve_host(host, review_root, reset=False):
    """(name, source) -- which host this invocation dispatches for (I5).

    `--host` when given; otherwise the RUN's own host, off its manifest.
    `driver.run` is manifest-authoritative about this -- it refuses a `--host`
    that contradicts the manifest as flag drift -- so a resume WITHOUT the flag
    is still a generic (or, for a run that predates a retirement, gemini) run.
    Resolving off `_DEFAULTS["host"]` instead dispatched claude agents into it,
    with no refusal anywhere on the path.

    A `--reset` run re-mints the manifest from argv, so the OUTGOING manifest
    must not steer this invocation: fall through to the default, which is what
    `driver.run` is about to write.

    The host it resolves may no longer be SELECTABLE: a run started before a
    family PR's row was retired resumes off its own manifest. That is caught by
    the caller (`orchestrate.loop`), not here, because this returns a name and
    the refusal is a status document.

    A FOREIGN manifest is ignored on exactly the terms `driver.run` ignores it
    (#1093 / #run8 AGT-C1A, `_foreign_manifest`): a target can force-commit its
    own `.panopticon/run-manifest.json`, and driver.run discards such a file and
    rebuilds from the real CLI args. Reading it here unconditionally handed the
    TARGET the choice of which family's agents got dispatched at it -- a
    committed `"host": "gemini"` steered this invocation's runner while the run
    itself proceeded as claude. Same check, same call shape, so the two cannot
    drift on what "the run's host" means.

    `source` is which of those three rules answered, for a surface that has to
    tell an operator WHY it assumed a host (`driver readiness`). The loop
    ignores it.
    """
    if host:
        return host, "--host"
    if not reset:
        manifest = run_manifest.load_manifest(review_root)
        if not _foreign_manifest(manifest, review_root,
                                 run_manifest.manifest_path(review_root)):
            named = (manifest or {}).get("host")
            if named:
                return named, "manifest"
    return _DEFAULTS["host"], "default"

def _error_status(message):
    return {"status": "error", "phase": None, "checkpoint": None, "group": None,
            "dispatch_request": None, "request_sha256": None, "advanced": [],
            "message": message}

def _manifest_committed(review_root, manifest_file):
    """True if `manifest_file` is TRACKED by git in review_root -- i.e. it was
    committed INTO the target (an attacker `git add -f`-ing past the
    `.panopticon/` gitignore), never written by a prior driver run, whose
    manifest stays gitignored/untracked.

    #run8 AGT-C1A: this is the robust, non-secret foreign-manifest signal. The
    old review_root-stamp check treated the operator's local checkout path as
    unguessable, but CI checkout paths ($GITHUB_WORKSPACE, /home/runner/work/...)
    are public, so an attacker could forge a matching stamp. A committed file
    cannot be forged into looking untracked. A non-git target, a missing file,
    or any git error yields False (nothing was committed, so nothing to distrust
    on this basis; the stamp check still applies)."""
    if not manifest_file or not os.path.isfile(manifest_file):
        return False
    git_bin = shutil.which("git") or "git"
    try:
        rel = os.path.relpath(manifest_file, review_root)
        r = subprocess.run(  # nosec B603
            [git_bin, "-C", review_root, "ls-files", "--error-unmatch", "--", rel],
            capture_output=True, text=True, timeout=30,
            env={"PATH": os.environ.get("PATH", "")})
    except Exception:
        return False
    return r.returncode == 0

def _foreign_manifest(manifest, review_root, manifest_file=None):
    """#1093 / #run8 AGT-C1A: True if a loaded manifest was NOT written by a
    prior run in THIS tree, so it must be discarded and rebuilt from the real CLI
    args rather than trusted as run config (a target that force-commits its own
    `.panopticon/run-manifest.json` could preset flags.tools:false to skip the
    scan, or flags.fail_on to force gate:PASS).

    Two independent signals, either sufficient:
      * the manifest FILE is git-tracked in review_root (`_manifest_committed`)
        -- the primary, non-secret check: a driver-written resume manifest is
        gitignored/untracked, so a tracked one was committed by the target.
      * the stamped `review_root` differs from this checkout (the original #1093
        signal, kept as a fallback for a non-git target where nothing is tracked
        and for a manifest carried over from another machine)."""
    if not isinstance(manifest, dict):
        return False
    if _manifest_committed(review_root, manifest_file):
        return True
    return manifest.get("review_root") != os.path.abspath(review_root)
