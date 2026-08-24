"""The 5.0 resumable driver: a table-driven phase state machine.

`driver run` advances through PHASES, executing deterministic work itself and
STOPPING at each dispatch checkpoint (writing dispatch-request.json). The phase
cursor is never stored — it is recomputed from disk (`first not-done phase`)
every invocation, so a crash/compaction/interrupt resumes identically. See
docs/superpowers/specs/2026-08-15-panopticon-5.0-driver-skeleton-design.md.
"""
import argparse
import copy
import dataclasses
import functools
import glob as _glob
import json
import os
import re
import shutil
import subprocess
import sys


# #5.0-01: when run directly (`python3 skill/scripts/driver.py run ...`, the
# documented entrypoint) the package roots are not on sys.path, so the
# `import scripts.*` below crash with ModuleNotFoundError. Bootstrap the same
# roots _child_env() puts on PYTHONPATH for subprocesses. Idempotent under
# pytest, whose conftest already provides them.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))                   # skill/scripts
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # skill

import yaml  # noqa: E402

import scripts.coverage_model as coverage_model  # noqa: E402
import scripts.diff_map as diff_map  # noqa: E402
import scripts.dispatch as dispatch  # noqa: E402
import scripts.evidence as evidence  # noqa: E402
import scripts.group_runner as group_runner  # noqa: E402
import scripts.groups_schema as groups_schema  # noqa: E402
import scripts.ingest_tools as ingest_tools  # noqa: E402
import scripts.ocrdb as ocrdb  # noqa: E402
import scripts.plan_contract as plan_contract  # noqa: E402
import scripts.run_tools as run_tools  # noqa: E402
import scripts.run_manifest as run_manifest  # noqa: E402
import scripts.score_gate as score_gate  # noqa: E402
import scripts.setup_flow as setup_flow  # noqa: E402
import scripts.synthesize as synthesize  # noqa: E402

CHECKPOINT_KINDS = ("scout", "review", "verify", "scan")

_SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))


def _redact_output(text):
    if not text:
        return ""
    redacted = re.sub(r"(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{16,}", "[REDACTED_TOKEN]", str(text))
    redacted = re.sub(r"(?:sk-[A-Za-z0-9_-]{16,})", "[REDACTED_KEY]", redacted)
    redacted = re.sub(r"(?i)(bearer\s+)[A-Za-z0-9._-]{16,}", r"\1[REDACTED]", redacted)
    return redacted


class DriverError(Exception):
    """A hard phase failure. main() converts it to a status:'error' result."""


def _script(name):
    return os.path.join(_SCRIPTS_DIR, name)


def _child_env():
    """Env for subprocessed panopticon CLIs. They do `import scripts.*` (a
    namespace package) plus BARE imports of both skill/scripts modules (e.g.
    `import evidence`) and repo-root scripts/ modules (e.g. `import file_issues`),
    so PYTHONPATH must mirror tests/conftest.py exactly: skill, skill/scripts,
    and <repo>/scripts."""
    scripts_dir = _SCRIPTS_DIR                         # .../skill/scripts
    skill_dir = os.path.dirname(scripts_dir)           # .../skill
    repo_root = os.path.dirname(skill_dir)             # .../panopticon
    repo_scripts = os.path.join(repo_root, "scripts")  # .../panopticon/scripts
    env = dict(os.environ)
    parts = [skill_dir, scripts_dir, repo_scripts]
    env["PYTHONPATH"] = os.pathsep.join(
        parts + ([env["PYTHONPATH"]] if env.get("PYTHONPATH") else []))
    return env


# §5.1 per-run folders. These artifacts stay at `.panopticon/` top-level: setup
# files, the resume anchors (run-manifest / setup-manifest), the cross-run EPSS
# cache, the transient write-guard allowlist (the hook reads it CWD-relative and is
# run-context-free), and the compat report symlinks. EVERY other artifact is per-run
# and routes into `.panopticon/runs/<tag>/`. The durable reports live top-level and
# tag-named (`<tag>-report.json`), so the run folder can be cleared — reclaiming the
# findings/verdicts bulk — without losing any report.
_TOP_LEVEL = frozenset({
    "config.json", "groups.yml", "groups.yml.draft",
    "run-manifest.json", "setup-manifest.json",
    "setup-proposal.json", "setup-complete.json", "setup-scan-brief.md",
    "epss-cache.json", "write-allowlist.json",
    "report.json", "report.json.html",
})


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


def _relink(link_path, target_name):
    """Create or replace a relative symlink `link_path -> target_name` (same dir)."""
    os.makedirs(os.path.dirname(link_path), exist_ok=True)
    try:
        if os.path.islink(link_path) or os.path.exists(link_path):
            os.remove(link_path)
    except OSError:
        pass
    os.symlink(target_name, link_path)


def _ensure_run_symlinks(review_root):
    """Point `.panopticon/runs/latest` at the active run folder (best-effort; a
    platform without symlinks simply skips it — the tag-named paths still work)."""
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


def _abs_file_list(review_root, files):
    """Bullet list of files absolutized against review_root (#975): the reviewer
    subagent inherits the HOST's cwd, not review_root/the --pr worktree, so a
    bare-relative path resolves against the wrong tree. File-list specific — do
    NOT route tests or other bullet lists through this; they stay repo-relative.
    Paths are prompt-sanitized (#1190) so a control char in a filename cannot
    inject prompt lines."""
    return "\n".join(
        "- " + _prompt_safe(os.path.abspath(os.path.join(review_root, f)))
        for f in files
    ) or "- (no files)"


def _load_json(path):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def _open_w_nofollow(path):
    """Open `path` for writing, refusing to follow a symlink at the final path
    component. A target repo (untrusted under redteam) can pre-commit a
    `.panopticon` artifact path as a symlink to a file the invoking user can
    write (a dotfile, authorized_keys, ...); plain open() would follow it and
    clobber that target. O_NOFOLLOW makes the open fail on a symlink; we then
    replace the link with a fresh regular file instead of writing through it
    (#1095 -- mirrors run_manifest's exclusive-create precedent)."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags, 0o644)
    except OSError:
        if os.path.islink(path):
            os.unlink(path)                       # neutralize the link, never follow it
            fd = os.open(path, flags, 0o644)
        else:
            raise
    return os.fdopen(fd, "w", encoding="utf-8")


def _write_json(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with _open_w_nofollow(path) as fh:
        json.dump(data, fh, indent=2, sort_keys=True)
    return path


def _json_parses(path):
    return _load_json(path) is not None


@functools.lru_cache(maxsize=8)
def _parse_committed_groups(path, _mtime):
    """Parse + validate groups.yml, memoized on (path, mtime) so a single
    `driver run` re-parses the file at most once per content version instead of
    once per group/phase (#1033). `_mtime` is part of the cache key only — a
    changed file busts the entry. Never mutate the returned structures; callers
    get deep copies via load_committed_groups."""
    with open(path, encoding="utf-8") as fh:
        doc = yaml.safe_load(fh)
    return groups_schema.parse_groups(doc if isinstance(doc, dict) else {})


def load_committed_groups(review_root):
    """Parse the committed groups.yml via groups_schema (P1). A MISSING file is
    an error (the driver run requires a committed matrix — `panopticon setup`
    produces it), not an empty success."""
    path = _pano(review_root, "groups.yml")
    try:
        mtime = os.path.getmtime(path)
    except FileNotFoundError:
        return {}, ["no committed groups.yml at %s — run `panopticon setup` first"
                    % path]
    except OSError as exc:
        return {}, ["groups.yml unreadable: %s" % exc]
    try:
        groups, errors = _parse_committed_groups(path, mtime)
    except (OSError, yaml.YAMLError) as exc:
        return {}, ["groups.yml unreadable: %s" % exc]
    # Deep-copy so a caller mutating its result can never corrupt the shared
    # cache entry the next phase reads.
    return copy.deepcopy(groups), list(errors)


# Hard bound per phase so a wedged discovery/synthesize or a hung tool runner
# cannot block the whole (resumable, CI-automatable) driver indefinitely (#1094).
# discovery/synthesize are fast; the tools phase is a generous backstop above
# run_tools' own per-tool TOOL_TIMEOUT=900 -- it catches a wedged run_tools
# harness, not a single slow scanner.
_CHILD_TIMEOUTS = {"discovery": 600, "tools": 7200, "synthesize": 600}
_CHILD_TIMEOUT_DEFAULT = 600


def _run_child(cmd, review_root, phase, timeout=None):
    """subprocess.run for a deterministic phase, converting a spawn-level OSError
    (ENOENT on the interpreter, EMFILE, a bad cwd, ...) or a phase timeout into a
    DriverError so run()'s handler yields a clean status:error instead of a raw
    traceback or an unbounded hang (#1033; #1094; #1021/5.0-14 covered only the
    --pr acquire path). Returns the CompletedProcess on a normal spawn — a
    non-zero exit is the caller's to interpret, not a spawn error."""
    if timeout is None:
        timeout = _CHILD_TIMEOUTS.get(phase, _CHILD_TIMEOUT_DEFAULT)
    try:
        return subprocess.run(cmd, cwd=review_root, capture_output=True,  # nosec B603
                              text=True, env=_child_env(), timeout=timeout)
    except subprocess.TimeoutExpired:
        raise DriverError("%s: %s timed out after %ss"
                          % (phase, cmd[1] if len(cmd) > 1 else cmd[0], timeout))
    except OSError as exc:
        raise DriverError("%s: could not spawn %s: %s"
                          % (phase, cmd[1] if len(cmd) > 1 else cmd[0], exc))


def _load_ocrdb_bundle():
    """ocrdb.load_bundle, converting a malformed-bundle ValueError into a
    DriverError so a corrupt bundle is a clean status:error, not a raw traceback
    that crashes the driver mid-phase (#1034)."""
    try:
        return ocrdb.load_bundle()
    except ValueError as exc:
        raise DriverError("OCRDb bundle unreadable: %s" % exc)


def discovery_done(review_root, manifest):
    return _json_parses(_pano(review_root, "groups.json"))


def discovery_execute(review_root, manifest):
    _groups, errors = load_committed_groups(review_root)
    if errors:
        raise DriverError("discovery: " + "; ".join(errors))
    out = _pano(review_root, "groups.json")
    cmd = [sys.executable, _script("discovery.py"), "--repo-scan",
           "--security", manifest.get("security_mode", "standard"),
           review_root, "--out", out]
    scope = manifest.get("scope") or {"mode": "repo"}
    mode = scope.get("mode")
    if mode == "changed":
        cmd += ["--scope-changed"]
    elif mode == "files":
        cmd += ["--scope-files"] + list(scope.get("target") or [])
    else:
        _scope_arg = {"file": "--scope-file", "directory": "--scope-dir",
                      "group": "--scope-group"}.get(mode)
        if _scope_arg and scope.get("target"):
            cmd += [_scope_arg, scope["target"]]
    if manifest.get("base"):
        cmd += ["--base", manifest["base"]]
    if manifest.get("pr_base"):
        cmd += ["--pr-base", manifest["pr_base"]]
    _dc = (manifest.get("flags") or {}).get("diff_context")
    if _dc is not None:
        cmd += ["--diff-context", str(_dc)]
    proc = _run_child(cmd, review_root, "discovery")
    if not _json_parses(out):
        raise DriverError(
            "discovery: discovery --repo-scan produced no groups.json "
            "(rc=%s): %s" % (proc.returncode, _redact_output((proc.stderr or proc.stdout)[:400])))
    return PhaseResult(kind="advanced", message="discovery: groups.json written")


def resolve_review_root(target, base=None, pr=None, runner=subprocess.run):
    """Resolve the single review root, pinned once in the manifest (spec §5).

    - pr given: acquire the deterministic PR worktree (diff_map); its path is
      the root.
    - git repo: `git rev-parse --show-toplevel` from the target.
    - non-git: the target directory itself.
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
        proc = runner(["git", "-C", start, "rev-parse", "--show-toplevel"],
                      capture_output=True, text=True)
        if proc.returncode == 0 and proc.stdout.strip():
            return os.path.realpath(proc.stdout.strip()), None, None
    except OSError:
        pass
    return (start if os.path.isdir(start) else target), None, None


@dataclasses.dataclass(frozen=True)
class Phase:
    name: str
    kind: str        # "deterministic" | "checkpoint" | "mixed"
    done: object     # callable(review_root, manifest) -> bool
    execute: object  # callable(review_root, manifest) -> PhaseResult


_PHASE_RESULT_KINDS = ("advanced", "checkpoint")


@dataclasses.dataclass
class PhaseResult:
    kind: str                     # "advanced" | "checkpoint"
    checkpoint: str = None        # scout|review|verify (iff kind == "checkpoint")
    group: str = None
    dispatch_request: str = None  # absolute path (iff checkpoint)
    message: str = ""

    def __post_init__(self):
        # #1033: reject an unknown kind loudly. run_engine treats anything that
        # isn't "checkpoint" as "advanced", so a typo ("advance") or a status
        # string ("complete"/"error") would be silently mishandled otherwise.
        if self.kind not in _PHASE_RESULT_KINDS:
            raise ValueError("unknown PhaseResult kind: %r" % self.kind)


def _first_not_done(phases, review_root, manifest):
    for phase in phases:
        if not phase.done(review_root, manifest):
            return phase
    return None


def run_engine(review_root, manifest, phases, max_steps=None):
    """Advance the state machine from disk. Repeatedly executes the first
    not-done phase until a checkpoint stops it or every phase is done. Returns a
    status dict; never exits (the CLI owns process exit).

    The cursor is recomputed every iteration, so a mixed phase that advances one
    unit at a time is simply re-selected until its done() is satisfied.
    """
    advanced = []
    # Progress guard: a buggy phase that returns "advanced" but never satisfies
    # done() would spin forever. Cap the work and fail loudly. The bound is far
    # above any real (phase-count + group-count) unit total.
    if max_steps is None:
        max_steps = 10000
    for _ in range(max_steps):
        phase = _first_not_done(phases, review_root, manifest)
        if phase is None:
            return {"status": "complete", "phase": None, "checkpoint": None,
                    "group": None, "dispatch_request": None,
                    "advanced": advanced, "message": "all phases complete"}
        result = phase.execute(review_root, manifest)
        if result.kind == "checkpoint":
            return {"status": "checkpoint", "phase": phase.name,
                    "checkpoint": result.checkpoint, "group": result.group,
                    "dispatch_request": result.dispatch_request,
                    "advanced": advanced,
                    "message": result.message or ("%s checkpoint" % result.checkpoint)}
        if phase.name not in advanced:
            advanced.append(phase.name)
    raise RuntimeError(
        "driver engine exceeded %d steps without completing — a phase returned "
        "'advanced' without satisfying its done() predicate" % max_steps)


def emit_status(status, stream=None):
    """Print the status JSON and return the process exit code: 0 for
    checkpoint/complete, 1 for error. The CLI does `sys.exit(emit_status(...))`."""
    (stream or sys.stdout).write(json.dumps(status) + "\n")
    return 1 if status.get("status") == "error" else 0


def write_dispatch_request(review_root, run_id, checkpoint, group, entries):
    """Write the single per-(group, checkpoint) dispatch-request.json and return
    its ABSOLUTE path. Host-agnostic: entries carry only neutral fields and any
    paths inside them must already be absolute (spec §4). The request is rolling
    — the durable state is the entries' out_files, not this file."""
    if checkpoint not in CHECKPOINT_KINDS:
        raise ValueError("unknown checkpoint kind: %r" % checkpoint)
    request = {"schema_version": 1, "run_id": run_id, "checkpoint": checkpoint,
               "group": group, "entries": list(entries)}
    path = _pano(review_root, "dispatch-request.json")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with _open_w_nofollow(path) as fh:
        json.dump(request, fh, indent=2)
    return os.path.abspath(path)


def load_dispatch_request(review_root):
    """The parsed .panopticon/dispatch-request.json (or None if absent/invalid).
    The host reads req['entries'] to install the write-guard
    (write_guard_hook.install(entries)) and to dispatch the checkpoint's cells."""
    return _load_json(_pano(review_root, "dispatch-request.json"))


def _discovered_groups(review_root):
    """(name, files) per group from discovery's groups.json."""
    data = _load_json(_pano(review_root, "groups.json")) or {}
    return [(g.get("name"), g.get("files") or [])
            for g in (data.get("groups") or [])
            if isinstance(g, dict) and g.get("name")]


def _scout_entry(review_root, manifest, group, files, host):
    """One host-agnostic scout dispatch entry (spec §4). The scout body +
    tool-policy line come from dispatch.render_prompt; the assignment is
    appended. Enforcement is host-declared (claude registers panopticon-scout)."""
    body = dispatch.render_prompt("scout.md", {}, host)
    security = manifest.get("security_mode", "standard")
    file_list = _abs_file_list(review_root, files)
    # #1053: ground the scout's tool recommendation in the real adapter registry
    # so it can only name scanners that exist -- an ungrounded scout invents
    # pytest/pylint/ruff/... and #1031 can only disclose them as
    # requested_unavailable noise. The list is the single source of truth from
    # run_tools, appended here so it reaches enforced and generic scouts alike.
    registry = ", ".join(run_tools.recommendable_tools())
    prompt = (body
              + "\n\n## Assignment\n\nGroup: %s\nSecurity mode: %s\n\nFiles:\n%s\n"
                % (group, security, file_list)
              + "\n## Available scanners\n\nRecommend `tools` ONLY from this "
                "registry — these are the only scanners that can run. Emit `[]` "
                "if none apply; never invent a tool name:\n%s\n" % registry
              + "\nReturn the ScopeProfile JSON for this group.")
    enforced = host == "claude"
    return {"id": "scout-%s" % group,
            "agent": dispatch.registered_agent_name("scout.md") if enforced else None,
            "enforced": enforced,
            "model": None,
            "prompt": prompt,
            "out_file": os.path.abspath(_pano(review_root, "scout-%s.json" % group))}


def coverage_done(review_root, manifest):
    # Vacuously done when discovery produced no groups (empty target); otherwise
    # done once every discovered group has a coverage file. (Evaluated only after
    # discovery, an earlier phase, so groups.json is already present.)
    return all(_json_parses(_pano(review_root, "coverage-%s.json" % g))
               for g, _ in _discovered_groups(review_root))


def _chunk_parent(name):
    """The committed parent of a discovery chunk `<name>_<i>` (#5.0-10), or None
    if `name` is not a `<something>_<digits>` chunk. Leftover `._N` chunks map to
    parent '.', never in the matrix, so they correctly keep an empty floor."""
    if not name or "_" not in name:
        return None
    head, _, tail = name.rpartition("_")
    return head if head and tail.isdigit() else None


# #3: bound the return-persist re-dispatch loop so a deterministically-broken
# host fails loud instead of re-dispatching the same garbage forever.
_MAX_SCOUT_ATTEMPTS = 3


def _scout_shape_errors(scout):
    """Load-bearing structural checks on a returned ScopeProfile -- a
    dependency-free subset of `scope-profile-schema.json` (jsonschema is an
    OPTIONAL, test-only dep, so the driver can't lean on it at runtime). Checks
    only the invariants the coverage/dispatch path actually indexes; returns []
    when the shape is safe to consume, else human-readable errors.

    The one that bit run-6: `lenses` must be an object of panel -> ARRAY. Two of
    26 scouts returned panel -> object; that parses as JSON, slips past the dict
    gate below, and only blows up later as an uncaught ValueError inside
    `dispatch._panel_lenses` (or an AttributeError in `depth_planner.plan_lenses`)
    -- a mid-dispatch crash instead of a clean re-dispatch."""
    if not isinstance(scout, dict):
        return ["not a JSON object"]
    errs = []
    for field in ("domains", "languages", "surfaces", "files", "tools"):
        v = scout.get(field)
        if v is not None and not isinstance(v, list):
            errs.append("`%s` must be an array" % field)
    lenses = scout.get("lenses")
    if lenses is not None:
        if not isinstance(lenses, dict):
            errs.append("`lenses` must be an object of panel -> array")
        else:
            for panel, arr in lenses.items():
                if not isinstance(arr, list):
                    errs.append("`lenses.%s` must be an array (got %s)"
                                % (panel, type(arr).__name__))
                    continue
                for i, lens in enumerate(arr):
                    if not (isinstance(lens, dict)
                            and "name" in lens and "spawn" in lens):
                        errs.append("`lenses.%s[%d]` must be an object with "
                                    "name+spawn" % (panel, i))
    return errs


def _bump_scout_attempts(review_root, group):
    """Persisted per-group re-dispatch counter that bounds #3's retry loop.
    Lives alongside the scout outputs, so --reset clears it with them."""
    path = _pano(review_root, "scout-attempts.json")
    data = _load_json(path) if _json_parses(path) else {}
    if not isinstance(data, dict):
        data = {}
    n = int(data.get(group, 0)) + 1
    data[group] = n
    _write_json(path, data)
    return n


def coverage_execute(review_root, manifest):
    """Emit ALL pending scouts in one checkpoint (#1056), then compute each
    group's coverage as the floor widened by the scout's valid domains. Returns
    after one unit of work; the engine re-selects coverage until every group has
    a coverage file. Re-emits only the still-missing scouts on resume."""
    matrix, errors = load_committed_groups(review_root)
    if errors:
        # #1091: fail loud like discovery_execute -- a missing/corrupt groups.yml
        # on a RESUME (discovery is already done, so its gate never re-runs) would
        # otherwise silently yield matrix={}, dropping the committed floor/exclude.
        raise DriverError("coverage: " + "; ".join(errors))
    host = manifest.get("host", "claude")
    groups = _discovered_groups(review_root)
    # #1056: scouts are independent and there is exactly one per group, so a
    # per-group checkpoint (like the review fan-out) would be no better than the
    # old sequential loop -- run-5's 21 groups cost ~40 min of pure profiling
    # round-trips. Emit EVERY pending scout in one checkpoint so the host
    # dispatches them concurrently; on a crash/resume this re-emits only the
    # scouts that still have no output (durable state = the entries' out_files).
    pending_scouts = []
    for g, f in groups:
        if _json_parses(_pano(review_root, "coverage-%s.json" % g)):
            continue
        sp = _pano(review_root, "scout-%s.json" % g)
        if not _json_parses(sp):
            pending_scouts.append((g, f))          # no output yet
            continue
        # #3: a scout that PARSES as JSON but has the wrong shape (run-6: 2/26
        # returned `lenses` as panel->object instead of panel->array) would slip
        # past the dict gate in the coverage loop below and corrupt lens spawning
        # downstream. Validate the load-bearing structure at the return-persist
        # accept boundary; on a mismatch, DISCARD the garbage and re-dispatch that
        # one scout. Cap the retries so a deterministically-broken host fails loud.
        errs = _scout_shape_errors(_load_json(sp))
        if errs:
            n = _bump_scout_attempts(review_root, g)
            print("scout output for group %s failed shape validation "
                  "(attempt %d/%d): %s"
                  % (g, n, _MAX_SCOUT_ATTEMPTS, "; ".join(errs)),
                  file=sys.stderr, flush=True)
            if n >= _MAX_SCOUT_ATTEMPTS:
                raise DriverError(
                    "scout for group %s returned schema-invalid output %d times "
                    "(fix the agent or `--reset`): %s" % (g, n, "; ".join(errs)))
            try:
                os.remove(sp)                       # discard -> re-dispatch fresh
            except OSError:
                pass
            pending_scouts.append((g, f))
    if pending_scouts:
        entries = [_scout_entry(review_root, manifest, g, f, host)
                   for g, f in pending_scouts]
        req = write_dispatch_request(review_root, manifest["run_id"],
                                     "scout", None, entries)
        return PhaseResult(kind="checkpoint", checkpoint="scout", group=None,
                           dispatch_request=req,
                           message="scout checkpoint for %d group(s)"
                                   % len(entries))
    # Every group now has a scout output -> compute coverage (one group per call:
    # local work, no dispatch, so the cadence is unchanged and cheap).
    for group, files in groups:
        if _json_parses(_pano(review_root, "coverage-%s.json" % group)):
            continue
        scout_path = _pano(review_root, "scout-%s.json" % group)
        # #5.0-12: a scout that returns a non-object (e.g. a JSON array) parses as
        # JSON but would slip past `or {}` (a non-empty list is truthy) and crash
        # `.get` with an uncaught AttributeError. Validate the shape at the gate
        # and fail loud (status:error) instead.
        scout = _load_json(scout_path)
        if not isinstance(scout, dict):
            raise DriverError("scout output for group %s is not a JSON object" % group)
        raw = scout.get("domains") or []
        spec = matrix.get(group)
        if spec is None:
            parent = _chunk_parent(group)   # #5.0-10: a >15-file group split into
            if parent is not None:          # <name>_<i> chunks inherits its parent's
                spec = matrix.get(parent)   # committed floor/exclude/tests
        spec = spec or {}
        floor = spec.get("floor", set())
        # net against floor here so disclosure["scout_added"] reports only the
        # genuinely NEW domains (a domain already on the floor isn't "added").
        scout_added = {d for d in raw if d in groups_schema.DOMAINS} - set(floor)
        scout_invalid = sorted(set(raw) - groups_schema.DOMAINS)
        # #5.0-19: gate the universal-tier floor on this group's observable
        # surface, so a testless / db-free / single-module group does not spend
        # a DAT/TST/ARC cell manufacturing noise (BursarBuddy calibration:
        # those cells produced 59 of 97 noise findings and caught 0 vulns). COD
        # stays universal; a scout that requested a domain still gets it via
        # scout_added regardless of the gate, so this only drops floor domains
        # the scout omitted AND whose surface is objectively absent.
        gated_floor = coverage_model.applicable_global_floor(files, scout)
        effective, disclosure = coverage_model.effective_panels(
            floor, scout_added, spec.get("exclude", set()),
            global_floor=gated_floor)
        cov = {
            "schema_version": 1,
            "group": group,
            "floor": disclosure["floor"],
            "excluded": disclosure["excluded"],
            "scout_added": disclosure["scout_added"],   # new domains, exclude-netted
            "scout_invalid": scout_invalid,             # dropped, disclosed
            "global_floor_suppressed": sorted(          # #5.0-19: surface absent
                coverage_model.GLOBAL_FLOOR - gated_floor),
            "effective": sorted(effective),
            "scout_file": os.path.abspath(scout_path),
            "run_id": manifest["run_id"],
        }
        # #8c/#7: a committed `exclude` naming a NON_EXCLUDABLE domain (SEC,
        # #1084) is OVERRIDDEN -- effective_panels discloses it as
        # `exclude_rejected`, but the coverage-write used to DROP that key. So an
        # operator who reached for a fixture-corpus `exclude:`-sink got a SILENT
        # SEC panel on deliberately-vulnerable code, and 16 illusory HIGHs
        # reached the gate (run-6). Persist the override AND warn loudly: to drop
        # a path corpus entirely (fixtures included, SEC included), use top-level
        # `exclude_paths:`, which prunes before grouping so no domain reviews it.
        rejected = disclosure.get("exclude_rejected")
        if rejected:
            cov["exclude_rejected"] = rejected
            print("coverage: group %s exclude %s was OVERRIDDEN (non-excludable) "
                  "-- these domains still run. To drop paths entirely (e.g. a "
                  "fixture corpus), use top-level `exclude_paths:` in groups.yml, "
                  "not per-group `exclude:`." % (group, ", ".join(rejected)),
                  file=sys.stderr)
        _write_json(_pano(review_root, "coverage-%s.json" % group), cov)
        return PhaseResult(kind="advanced",
                           message="coverage: group %s (floor+scout)" % group)
    return PhaseResult(kind="advanced", message="coverage: complete")


def tools_done(review_root, manifest):
    return _json_parses(_pano(review_root, "tools-ran.json"))


def tools_execute(review_root, manifest):
    if (manifest.get("flags") or {}).get("tools") is False:
        _write_json(_pano(review_root, "tools-ran.json"),
                    {"schema_version": 1, "ran": False, "skipped": True, "crashed": False,
                     "note": "tools disabled (--no-tools)",
                     "returncode": None, "run_id": manifest["run_id"]})
        return PhaseResult(kind="advanced", message="tools: skipped (--no-tools)")
    out_dir = _pano(review_root, "tools")
    # #1031: --manifest records the deterministic adapter set (selected/produced/
    # missing) so synthesize can certify tool coverage against what the runner
    # actually resolved, not the scout's advisory tool list.
    cmd = [sys.executable, _script("run_tools.py"), "--target", review_root,
           "--out", out_dir, "--deps",
           "--run-id", manifest.get("run_id") or "",   # #17: manifest self-identifies
           "--manifest", _pano(review_root, "tools-manifest.json")]
    proc = _run_child(cmd, review_root, "tools")
    produced = os.path.isdir(out_dir) and bool(os.listdir(out_dir))
    # #1033: a real scanner/runner CRASH (non-zero exit + no output) is NOT a
    # benign Docker-absent skip (exit 0 + no output). Distinguish them: record a
    # `crashed` marker + a loud stderr line, but still advance -- tools are
    # best-effort and #1031's manifest gate already fails certification when a
    # selected adapter produces nothing, so the run stays honest without a hard
    # stop that a missing Docker image doesn't deserve.
    crashed = (not produced) and proc.returncode not in (0, None)
    raw_err = (proc.stderr or "").strip()[:300]
    note = "" if produced else (_redact_output(raw_err)
                                or ("tool scan crashed" if crashed
                                    else "no tool output produced"))
    _write_json(_pano(review_root, "tools-ran.json"),
                {"schema_version": 1, "ran": produced, "skipped": not produced, "crashed": crashed,
                 "note": note, "returncode": proc.returncode,
                 "run_id": manifest["run_id"]})
    if crashed:
        sys.stderr.write("driver: tool scan CRASHED (rc=%s) — %s\n"
                         % (proc.returncode, note))
    elif not produced:
        sys.stderr.write("driver: tool scan produced no output — %s\n" % note)
    return PhaseResult(kind="advanced",
                       message="tools: %s" % (
                           "produced output" if produced
                           else ("CRASHED — " + note if crashed
                                 else "SKIPPED — " + note)))


def _effective_domains(review_root, group):
    cov = _load_json(_pano(review_root, "coverage-%s.json" % group)) or {}
    return list(cov.get("effective") or [])


def _get_valid_cell_data(review_root, manifest, group, domain):
    data = _load_json(_pano(review_root, "findings-%s-%s.json" % (group, domain)))
    if not (isinstance(data, dict) and isinstance(data.get("findings"), list)):
        return None
    meta = data.get("_panopticon")
    if (isinstance(meta, dict) and meta.get("run_id") == manifest.get("run_id")
            and meta.get("domain") == domain and meta.get("group") == group):
        return data
    return None


def _cell_done(review_root, manifest, group, domain):
    return _get_valid_cell_data(review_root, manifest, group, domain) is not None


def _render_menu(bundle, domain):
    lines = ["%s %s (%s)" % (m["code"], m["name"], m["severity"])
             for m in ocrdb.domain_menu(bundle, domain)]
    return "\n".join(lines) or "(no OCRDb bundle vendored — use general %s judgment)" % domain


def _render_criteria(bundle, domain):
    """The domain's explicit OCRDb pass/fail criteria for the advisor to grade a
    claim against, one code per line. Codes without criteria are omitted (they
    fall back to the menu one-liner). A domain with no criteria at all renders a
    note, so the {criteria} lens is never a blank section (#1035)."""
    blocks = ["%s %s — %s" % (c["code"], c["name"], c["criteria"])
              for c in ocrdb.domain_criteria(bundle, domain)]
    return "\n".join(blocks) or (
        "(no explicit OCRDb criteria for the %s domain in this bundle — grade "
        "against the menu one-liners above)" % domain)


# --- #1131 tool-aware review (SEC-first PoC) ---------------------------------
# Hand a review cell the static-analysis tool findings that already landed in
# its files, as a "don't re-derive" MAP (never an answer key): the reviewer
# skips re-deriving them and instead escalates any deeper issue a tool can't
# reach. SEC-only for now — every tool finding is panel:"security", so SEC needs
# no rule->domain routing, just file->group (which the cell's `files` already
# give us); other domains need a rule/CWE->domain index (deferred). The
# independent tool-verify round is untouched; this is purely a prompt input.
_TOOL_HIT_DOMAINS = frozenset({"SEC"})
_TOOL_HITS_CAP = 40


@functools.lru_cache(maxsize=None)
def _ingested_tool_findings(review_root, include_fixtures):
    """All normalized tool findings for this run, memoized per (review_root,
    include_fixtures). Mirrors the driver's tool-verify ingest (same
    include_fixtures) so the review-time map reflects the SAME findings the
    independent tool-verify round adjudicates. Returns () when the tools dir is
    absent or ingest fails — the map is advisory and must never break a review."""
    tools_dir = _pano(review_root, "tools")
    if not os.path.isdir(tools_dir):
        return ()
    try:
        findings, _disp = ingest_tools.ingest_dir_detailed(
            tools_dir, None, include_fixtures=include_fixtures)
    except Exception:  # noqa: BLE001 - advisory input; never break review on it
        return ()
    return tuple(findings)


def _format_tool_hits(hits):
    """Render a cell's already-reported tool findings as a 'don't re-derive'
    map. Empty string when there are none, so the prompt section vanishes for
    cells/domains with no hits."""
    if not hits:
        return ""
    lines = []
    for h in hits[:_TOOL_HITS_CAP]:
        loc = h.get("location") or {}
        f = loc.get("file") or "?"
        ln = loc.get("line_start")
        where = "%s:%s" % (f, ln) if ln else f
        rule = (h.get("tool_evidence") or {}).get("rule_id") or h.get("category") or "?"
        title = " ".join(str(h.get("title") or "").split())
        lines.append("- %s · %s · %s · %s"
                     % (where, rule, h.get("severity") or "?", title))
    extra = len(hits) - _TOOL_HITS_CAP
    if extra > 0:
        lines.append("- …and %d more tool finding(s) in these files." % extra)
    return (
        "## Tool findings already reported in your files\n\n"
        "Static-analysis tools already flagged the items below in the files you're "
        "reviewing, and they are verified independently — do **not** re-file them as "
        "your own findings. Your two jobs:\n\n"
        "1. **Skip re-deriving these.** Spend your attention on what tools cannot see.\n"
        "2. **Escalate when there is more.** If a hit exposes a deeper issue a tool "
        "cannot reach — the root cause, cross-file blast radius, a real exploit path, "
        "or a systemic pattern — file THAT finding and cite the `rule_id` it builds "
        "on. A bare restatement of a tool hit is not a finding.\n\n"
        + "\n".join(lines) + "\n\n"
    )


def _tool_hits_for_cell(review_root, manifest, domain, files):
    """The 'don't re-derive' tool-hit map (#1131) for one review cell, or '' when
    the domain is out of PoC scope or no tool hit lands in the cell's files."""
    if domain not in _TOOL_HIT_DOMAINS:
        return ""
    wanted = set(files or ())
    if not wanted:
        return ""
    findings = _ingested_tool_findings(review_root,
                                       _tools_include_fixtures(manifest))
    hits = [f for f in findings
            if ((f.get("location") or {}).get("file")) in wanted]
    hits.sort(key=lambda h: (str((h.get("location") or {}).get("file") or ""),
                             (h.get("location") or {}).get("line_start") or 0))
    return _format_tool_hits(hits)


def _cell_entry(review_root, manifest, group, domain, files, tests, host, bundle):
    file_list = _abs_file_list(review_root, files)
    test_list = "\n".join("- " + t for t in tests) or "- (no tests)"
    out_file = os.path.abspath(_pano(review_root, "findings-%s-%s.json" % (group, domain)))
    prompt = dispatch.render_prompt("domain-panel.md", {
        "domain": domain, "group": group, "file_list": file_list,
        "tests": test_list, "security_mode": manifest.get("security_mode", "standard"),
        "menu": _render_menu(bundle, domain),
        "criteria": _render_criteria(bundle, domain), "run_id": manifest["run_id"],
        "tool_hits": _tool_hits_for_cell(review_root, manifest, domain, files),
        "out_file": out_file}, host)
    enforced = host == "claude"
    return {"id": "review-%s-%s" % (group, domain),
            "agent": dispatch.registered_agent_name("domain-panel.md") if enforced else None,
            "enforced": enforced, "model": None, "prompt": prompt, "out_file": out_file}


def _load_cell_findings(review_root, manifest, group, domain):
    """The cell's reviewer findings, normalized + id-assigned exactly as
    synthesize.load_findings does, or None when the cell file is absent/mismatched.
    Ids match synthesize's so the advisor's finding_id echo binds at synthesis.

    Strips synthesize.AGENT_FORBIDDEN_FIELDS (source/reinforced/corroborated/
    corroborated_by/evidence) before normalizing, mirroring synthesize.load_findings:
    a raw panel finding must never carry a self-asserted `evidence.status` into
    score_gate.should_engage_primary, or a forged "rejected" (factor 0.0) would
    let a finding duck the F_p gate entirely.

    verify_execute/verify_done feed this RAW per-cell list straight into
    score_gate.should_engage_primary -- no cross-cell dedup. synthesize's own
    engagement check (engaged_matrix_cells) scores the deduped/aggregated list
    produced by prepare_for_queue instead, so synth-engaged is a subset of
    driver-engaged, never the reverse. This is a bounded, safe discrepancy:
    verify_done gates synthesize (every driver-engaged cell already has a
    bundle before synthesize runs), but meta.coverage.verify_matrix.engaged can
    undercount when exact-duplicate findings collapse in dedup."""
    data = _get_valid_cell_data(review_root, manifest, group, domain)
    if data is None:
        return None
    out = []
    for f in data.get("findings") or []:
        if not isinstance(f, dict):
            continue
        raw = dict(f)
        for k in synthesize.AGENT_FORBIDDEN_FIELDS:
            raw.pop(k, None)
        nf = synthesize.normalize_finding(raw)
        # #1109: never trust an agent-supplied id -- always content-derive it, so
        # a crafted/colliding well-formed id can't bind a downstream verdict to
        # the wrong finding. Kept in lockstep with synthesize.load_findings so the
        # advisor's finding_id echo still binds at synthesis.
        nf["id"] = evidence.matrix_finding_id(nf)
        out.append(nf)
    return out


def _verify_out_file(review_root, group, domain, stage):
    suffix = "-backup" if stage == "backup" else ""
    return os.path.abspath(_pano(review_root, "verdicts",
                                 "verdicts-%s-%s%s.json" % (group, domain, suffix)))


def _verify_cell_done(review_root, manifest, group, domain, stage):
    data = _load_json(_verify_out_file(review_root, group, domain, stage))
    if not (isinstance(data, dict) and isinstance(data.get("verdicts"), list)):
        return False
    meta = data.get("_panopticon") or {}
    return (meta.get("run_id") == manifest.get("run_id")
            and meta.get("domain") == domain and meta.get("group") == group
            and meta.get("stage", "primary") == stage)


def _render_findings(cell):
    """The cell's claims as a compact JSON array the advisor adjudicates."""
    slim = [{"id": f["id"], "code": f.get("code"), "severity": f["severity"],
             "title": f["title"], "category": f.get("category"),
             "location": f.get("location"), "description": f.get("description", "")}
            for f in cell]
    return json.dumps(slim, indent=2)


def _verify_entry(review_root, manifest, group, domain, files, cell, host, bundle, stage):
    file_list = _abs_file_list(review_root, files)
    out_file = _verify_out_file(review_root, group, domain, stage)
    prompt = dispatch.render_prompt("domain-advisor.md", {
        "domain": domain, "group": group, "file_list": file_list,
        "findings": _render_findings(cell), "menu": _render_menu(bundle, domain),
        "criteria": _render_criteria(bundle, domain),   # #1035
        "run_id": manifest["run_id"], "stage": stage, "out_file": out_file}, host)
    # #975: pin the review root for the advisor too. Unlike the scout/panel file
    # list above, the findings JSON's `location` fields are carried verbatim from
    # the panel's raw claims and stay repo-relative on disk (_render_findings) —
    # Part A's abspath can't reach into that payload. The advisor inherits the
    # HOST's cwd (the user's checkout), never review_root/the --pr worktree, so
    # without this header a relative `location` resolves against the wrong tree.
    prompt = ("Repo root: %s\nEvery relative path in the claims below resolves "
              "against this root -- read files THERE, never in your session's "
              "default checkout.\n\n%s" % (os.path.abspath(review_root), prompt))
    enforced = host == "claude"
    return {"id": "verify-%s-%s-%s" % (group, domain, stage),
            "agent": dispatch.registered_agent_name("domain-advisor.md") if enforced else None,
            "enforced": enforced, "model": None, "prompt": prompt, "out_file": out_file}


def _driver_plan_entries(review_root, manifest):
    """The declared review cells as a matrix domain-cell dispatch plan
    (#5.0-16). Computed DETERMINISTICALLY from groups.json (each discovered
    group) x its effective domains -- the SAME two sources review_execute
    dispatches from (_discovered_groups x _effective_domains) -- with the EXACT
    out_file spelling _cell_entry uses, so synthesize.reconcile_findings_files
    sees no missing/unexpected on a clean run. `enforced` mirrors _cell_entry so
    synthesize.derive_tool_policy_mode reports the run's real posture rather than
    defaulting to "advisory". No `files`/`role` -- this is a declaration of
    which out_files must exist, not a scope grant or a cost row."""
    enforced = manifest.get("host", "claude") == "claude"
    entries = []
    for group, _files in _discovered_groups(review_root):
        for domain in _effective_domains(review_root, group):
            entries.append({
                "group": group, "domain": domain, "enforced": enforced,
                "out_file": os.path.abspath(
                    _pano(review_root, "findings-%s-%s.json" % (group, domain)))})
    return entries


def _write_driver_plan(review_root, manifest):
    """Write .panopticon/dispatch-plan-driver.json declaring every review cell
    (#5.0-16 H2), so synthesize's reconcile_findings_files (undeclared-file
    detection) is live on the driver path. Idempotent: written once, only when
    cells exist; a later call is a no-op if the file is already present (the
    cell set is fixed once coverage completes, which gates the review phase).
    An empty target (no cells) writes NO plan -- reconcile then stays a correct
    no-op rather than flagging an empty plan."""
    path = _pano(review_root, synthesize.DRIVER_DISPATCH_PLAN)
    if os.path.isfile(path):
        return path
    entries = _driver_plan_entries(review_root, manifest)
    if not entries:
        return None
    return _write_json(path, entries)


def _snapshot_review_out_files(review_root, manifest):
    """Snapshot a sha256 per declared review cell at the review->verify boundary
    (#5.0-16 H3), so synthesize's verify_out_file_hashes (content-substitution
    detection) is live on the driver path. Runs after review_done (every cell
    written) and before any verify-phase agent can touch a findings file, so a
    later substitution -- e.g. by a rogue advisor on the unenforced generic host
    -- is caught. Idempotent AND one-way: if the snapshot already exists it is
    NOT rewritten -- re-hashing after a substitution would mask it."""
    path = _pano(review_root, "out-file-hashes.json")
    if os.path.isfile(path):
        return path
    entries = _driver_plan_entries(review_root, manifest)
    if not entries:
        return None
    group_runner.snapshot_out_files(entries, out_path=os.path.abspath(path))
    return path if os.path.isfile(path) else None


def review_done(review_root, manifest):
    groups = _discovered_groups(review_root)
    if not groups:
        return True   # vacuous (no groups)
    return all(_cell_done(review_root, manifest, g, d)
               for g, _ in groups for d in _effective_domains(review_root, g))


def review_execute(review_root, manifest):
    # #5.0-16 H2: declare every review cell before dispatching any, so an
    # injected/undeclared findings file is caught by reconcile at synthesis.
    _write_driver_plan(review_root, manifest)
    host = manifest.get("host", "claude")
    bundle = _load_ocrdb_bundle()
    # group tests come from the committed matrix (parse_groups tests field)
    matrix, errors = load_committed_groups(review_root)
    if errors:
        # #1092: same resume-reachable gap as coverage -- a corrupt groups.yml
        # would silently drop every group's committed tests from the prompts.
        raise DriverError("review: " + "; ".join(errors))
    # #5: batch EVERY pending review cell across ALL groups into one checkpoint
    # (like the scout fan-out, #1056) instead of one group per round trip -- run-6
    # serialized 26 groups into 26 sequential trips while the host can dispatch
    # ~20 agents at once. group=None marks a batch; each entry is self-describing
    # (group+domain in its id/out_file), and the host installs the write-guard
    # from the full entry set, so the fail-closed allowlist still covers every cell
    # (_write_driver_plan above already declared them all for reconcile).
    all_entries, ngroups = [], 0
    for group, files in _discovered_groups(review_root):
        domains = _effective_domains(review_root, group)
        pending = [d for d in domains if not _cell_done(review_root, manifest, group, d)]
        if not pending:
            continue
        ngroups += 1
        tests = sorted((matrix.get(group) or {}).get("tests") or [])
        all_entries.extend(
            _cell_entry(review_root, manifest, group, d, files, tests, host, bundle)
            for d in pending)
    if all_entries:
        req = write_dispatch_request(review_root, manifest["run_id"], "review",
                                     None, all_entries)
        return PhaseResult(kind="checkpoint", checkpoint="review", group=None,
                           dispatch_request=req,
                           message="review: %d cell(s) across %d group(s)"
                                   % (len(all_entries), ngroups))
    return PhaseResult(kind="advanced", message="review: all cells complete")


def verify_execute(review_root, manifest):
    # #5.0-16 H3: snapshot every declared cell's bytes at the review->verify
    # boundary (idempotent) BEFORE any advisor runs, so a verify-phase
    # substitution is caught. review_done gates this phase, so all cells exist.
    _snapshot_review_out_files(review_root, manifest)
    os.makedirs(_pano(review_root, "verdicts"), exist_ok=True)
    host = manifest.get("host", "claude")
    bundle = _load_ocrdb_bundle()
    # PRIMARY round: one advisor per engaged (>= F_p), not-yet-verified cell.
    # #5: batch every pending primary advisor across ALL groups into one
    # checkpoint (like review + scout), instead of one group per round trip. The
    # BACKUP and TOOL rounds below stay sequential -- they depend on the primary
    # verdicts being complete first (verify_done gates them on all-primary-done).
    all_entries, ngroups = [], 0
    for group, files in _discovered_groups(review_root):
        pending = []
        for domain in _effective_domains(review_root, group):
            cell = _load_cell_findings(review_root, manifest, group, domain)
            if cell is None or not score_gate.should_engage_primary(cell):
                continue   # unreviewed, or below-gate: unverified + disclosed at synth
            if _verify_cell_done(review_root, manifest, group, domain, "primary"):
                continue
            pending.append((domain, cell))
        if pending:
            ngroups += 1
            all_entries.extend(
                _verify_entry(review_root, manifest, group, d, files, c,
                              host, bundle, "primary") for d, c in pending)
    if all_entries:
        req = write_dispatch_request(review_root, manifest["run_id"], "verify",
                                     None, all_entries)
        return PhaseResult(kind="checkpoint", checkpoint="verify", group=None,
                           dispatch_request=req,
                           message="verify: %d primary advisor(s) across %d group(s)"
                           % (len(all_entries), ngroups))
    # BACKUP round (Task 4 fills this branch).
    backup = _verify_backup_execute(review_root, manifest, host, bundle)
    if backup is not None:
        return backup
    # TOOL round (#5.0-03): dispatch a per-finding advisor for each tool finding
    # so synthesize can promote tool_confirmed and stop counting them unanswered.
    tools = _verify_tools_execute(review_root, manifest, host)
    if tools is not None:
        return tools
    return PhaseResult(kind="advanced", message="verify: all cells verified")


def verify_done(review_root, manifest):
    for group, _files in _discovered_groups(review_root):
        for domain in _effective_domains(review_root, group):
            cell = _load_cell_findings(review_root, manifest, group, domain)
            if cell is None or not score_gate.should_engage_primary(cell):
                continue
            if not _verify_cell_done(review_root, manifest, group, domain, "primary"):
                return False
    return (_verify_backup_done(review_root, manifest)
            and _verify_tools_done(review_root, manifest))


def _cell_backup_findings(review_root, manifest, group, domain):
    """The cell's primary-CONFIRMED findings that sit in a category scoring
    >= F_b on primary-stage evidence — the adversarial backup's scope. [] when
    the primary bundle is absent or no category clears F_b."""
    cell = _load_cell_findings(review_root, manifest, group, domain)
    if not cell:
        return []
    primary = _load_json(_verify_out_file(review_root, group, domain, "primary"))
    if not (isinstance(primary, dict) and isinstance(primary.get("verdicts"), list)):
        return []
    by_fid = {str(v.get("finding_id")): v for v in primary["verdicts"]
              if isinstance(v, dict) and v.get("finding_id")}
    for f in cell:
        f["evidence"] = evidence.derive_evidence(f, by_fid.get(str(f["id"])))
    by_cat = {}
    for f in cell:
        by_cat.setdefault(f.get("category") or "general", []).append(f)
    out = []
    for cat_findings in by_cat.values():
        if score_gate.should_summon_backup(cat_findings):
            out += [f for f in cat_findings
                    if (f["evidence"].get("status") == "advisor_confirmed")]
    return out


def _confined_to_root(review_root, path):
    """True iff the claim path resolves lexically inside review_root. An absolute
    path or a `../`-escape resolves outside and is rejected (#1096) -- the claim's
    location.file is LLM/panel-supplied (steerable by injection planted in the
    reviewed repo), so it must not be able to point a downstream advisor at files
    outside the review tree."""
    if not isinstance(path, str) or not path:
        return False
    root = os.path.abspath(review_root)
    full = os.path.abspath(os.path.join(root, path))
    return full == root or full.startswith(root + os.sep)


def _backup_scope_files(review_root, files, scope):
    """The files a backup advisor needs: the ones its scoped (advisor-confirmed,
    >= F_b) claims cite -- not the whole cell. The domain-advisor is claim-driven
    and its Read/Grep/Glob are unconfined, so a narrow list preserves coverage
    while dropping the whole-cell re-read cost (#1029). Falls back to the full
    group `files` if ANY scoped claim lacks a resolvable location.file, or names
    one that escapes review_root (absolute/`../` -- untrusted, #1096) -- a backup
    must never refute blind, and never read outside the tree."""
    located = []
    for f in scope:
        loc = f.get("location") if isinstance(f, dict) else None
        path = loc.get("file") if isinstance(loc, dict) else None
        if not path or not _confined_to_root(review_root, path):
            return list(files)
        if path not in located:
            located.append(path)
    return located or list(files)


def _verify_backup_execute(review_root, manifest, host, bundle):
    for group, files in _discovered_groups(review_root):
        pending = []
        for domain in _effective_domains(review_root, group):
            scope = _cell_backup_findings(review_root, manifest, group, domain)
            if not scope:
                continue
            if _verify_cell_done(review_root, manifest, group, domain, "backup"):
                continue
            pending.append((domain, scope))
        if pending:
            # #1029: the backup re-reads only its scoped claims' files, not the
            # whole group -- coverage-preserving (claim-driven, unconfined reads).
            entries = [_verify_entry(review_root, manifest, group, d,
                                     _backup_scope_files(review_root, files, c), c,
                                     host, bundle, "backup") for d, c in pending]
            req = write_dispatch_request(review_root, manifest["run_id"], "verify",
                                         group, entries)
            return PhaseResult(kind="checkpoint", checkpoint="verify", group=group,
                               dispatch_request=req,
                               message="verify: %d backup advisor(s) for group %s"
                               % (len(entries), group))
    return None


def _verify_backup_done(review_root, manifest):
    for group, _files in _discovered_groups(review_root):
        for domain in _effective_domains(review_root, group):
            if _cell_backup_findings(review_root, manifest, group, domain) \
                    and not _verify_cell_done(review_root, manifest, group, domain, "backup"):
                return False
    return True


def _tools_include_fixtures(manifest):
    """Whether tool-finding ingestion keeps test-fixture-corpus findings.

    ONE source of truth, shared by _tool_verify_queue (the driver's tool
    verify queue) and synthesize_execute (the --include-fixtures it forwards),
    so the driver and synthesize ingest the IDENTICAL set of tool findings.
    Fingerprint/id parity of the tool-verify queue depends on this agreement:
    if the driver ingested fixtures synthesize prunes (or vice versa),
    synthesize could queue a tool finding the driver never dispatched an
    advisor for -> unanswered -> a spurious INCONCLUSIVE.

    #1055: keyed on the explicit --include-fixtures flag ALONE. Redteam no
    longer auto-includes fixture TOOL findings -- adjudicating designed-
    vulnerable fixture CVEs (e.g. TR-010 on vulnerable-rust/Cargo.lock) burned
    verify budget to re-reject scaffolding by construction. Fixture CONTENT
    injection-hunting is unaffected: it is a review-panel job (groups.yml
    routing), independent of this tool-finding flag. Pass --include-fixtures
    to opt in to tool coverage of fixtures (incl. under redteam)."""
    flags = manifest.get("flags") or {}
    return bool(flags.get("include_fixtures"))


def _tool_verify_queue(review_root, manifest):
    """The tool-sourced verify-queue entries, computed EXACTLY as synthesize
    will, so their queue_ids AND finding ids match synthesize's for the same
    tool output. Returns a list of (queue_id, finding); [] when the tool scan
    did not run.

    Runs synthesize's OWN combined pipeline (agent findings from the cell files
    PLUS the ingested tool findings) -> prepare_for_queue -> build_verify_queue,
    then filters to is_tool_sourced entries. The full combined pipeline (not a
    tool-only slice) is what guarantees FINDING-ID parity: aggregate_tool_findings
    chooses its survivor for a repeated rule using the AGENT findings' loci, so a
    tool-only pipeline could keep a different survivor -- same fingerprint/queue_id
    but a different finding id -- and synthesize's match_verdict enforces the
    finding_id echo, so a mismatched id would drop the driver's verdict and force
    the very INCONCLUSIVE this phase exists to prevent. Feeding the identical
    inputs through the identical functions makes the (queue_id, id) pair the tool
    findings carry here byte-identical to what synthesize's report exports.

    Additive only: this CALLS synthesize.load_findings/normalize_finding/
    prepare_for_queue and evidence.build_verify_queue; it changes none of them.
    include_fixtures/group/exclude are pinned to synthesize's main() tool-ingest
    call (group=None, exclude_globs=None) for identity; _tools_include_fixtures
    is the value synthesize_execute forwards."""
    ran = (_load_json(_pano(review_root, "tools-ran.json")) or {}).get("ran")
    tools_dir = _pano(review_root, "tools")
    if not ran or not os.path.isdir(tools_dir):
        return []
    findings = synthesize.load_findings(
        sorted(_glob.glob(_pano(review_root, "findings-*.json"))))
    tool_findings, _disp = ingest_tools.ingest_dir_detailed(
        tools_dir, None, include_fixtures=_tools_include_fixtures(manifest))
    for tf in tool_findings:
        findings.append(synthesize.normalize_finding(tf))
    prepared, _integration = synthesize.prepare_for_queue(findings)
    flags = manifest.get("flags") or {}
    # #18: match synthesize's --max-verify DEFAULT (None = uncapped), not a
    # hardcoded 100. build_verify_queue caps the COMBINED queue and this method
    # only then filters to tool-sourced entries -- so a 100 cap, with agent
    # findings sorting first, STARVES tool findings (run-7: synthesize queued 36
    # tool findings, this dispatched only 6, leaving 30 permanently unanswered and
    # making tool_confirmed:0 an artifact, not a measurement). The docstring above
    # promises this queue is "computed EXACTLY as synthesize will" -- so it must
    # take the same default. (The manifest never carries max_verify today, so this
    # is uncapped in practice; if it ever does, it matches synthesize by key.)
    max_verify = flags.get("max_verify")
    queue, _cut = evidence.build_verify_queue(prepared, max_verify=max_verify)
    return [(e["queue_id"], e["finding"]) for e in queue
            if evidence.is_tool_sourced(e["finding"])]


def _tool_verdict_out_file(review_root, queue_id):
    """Where a tool finding's advisor verdict lands: verdicts/<queue_id>.json --
    the SAME directory the cell verdict bundles use, but a single-verdict file
    keyed by queue_id (synthesize's evidence.load_verdicts_detailed picks it up;
    load_verdict_bundles skips it as not-a-bundle)."""
    return os.path.abspath(_pano(review_root, "verdicts", "%s.json" % queue_id))


def _tool_verdict_done(review_root, queue_id):
    """A tool-finding verdict is settled once verdicts/<queue_id>.json parses as
    a single-verdict file synthesize will load -- a dict carrying a valid verdict
    value. Mirrors evidence.load_verdicts_detailed's own acceptance test (tolerant
    parse, VERDICT_VALUES), so 'done' means 'synthesize will match it', and a
    truncated/garbled return re-dispatches rather than reading as done."""
    path = _tool_verdict_out_file(review_root, queue_id)
    try:
        with open(path, encoding="utf-8") as fh:
            data = evidence.load_json_tolerant(fh.read())
    except (OSError, ValueError):
        return False
    return (isinstance(data, dict)
            and str(data.get("verdict", "")).upper() in evidence.VERDICT_VALUES)


def _tool_verify_entry(review_root, manifest, queue_id, finding, host):
    """One per-finding advisor (advisor.md) dispatch entry for a tool finding.

    Return-persist by construction: advisor.md is Read/Grep/Glob only (no Write),
    so the advisor RETURNS a verdict JSON and the HOST writes it to out_file --
    `delivery: return_json` flags that, exactly like the scout/setup-scan
    return-persist entries. Reuses render_prompt('advisor.md', {claim_json}) and
    the repo-root pin from dispatch.render_advisor_prompts. NO run_id echo line:
    the driver writes no verify-queue.json, so synthesize's verdict_run_id is None
    and match_verdict binds on the finding_id echo alone."""
    out_file = _tool_verdict_out_file(review_root, queue_id)
    claim = json.dumps(finding, indent=2, ensure_ascii=False)
    prompt = dispatch.render_prompt("advisor.md", {"claim_json": claim}, host)
    prompt = ("Repo root: %s\nEvery relative path in the claim below resolves "
              "against this root -- read files THERE, never in your session's "
              "default checkout.\n\n%s" % (os.path.abspath(review_root), prompt))
    enforced = host == "claude"
    return {"id": "verify-tool-%s" % queue_id,
            "agent": dispatch.registered_agent_name("advisor.md") if enforced else None,
            "enforced": enforced, "model": None, "prompt": prompt,
            "out_file": out_file, "delivery": "return_json"}


def _verify_tools_execute(review_root, manifest, host):
    """Emit the tool-finding verify checkpoint when any tool finding still lacks
    a verdict; None when every tool finding is verified (or none exist). Runs as
    a round of the verify phase after primary/backup cells."""
    pending = [(qid, f) for qid, f in _tool_verify_queue(review_root, manifest)
               if not _tool_verdict_done(review_root, qid)]
    if not pending:
        return None
    entries = [_tool_verify_entry(review_root, manifest, qid, f, host)
               for qid, f in pending]
    req = write_dispatch_request(review_root, manifest["run_id"], "verify",
                                 "tools", entries)
    return PhaseResult(kind="checkpoint", checkpoint="verify", group="tools",
                       dispatch_request=req,
                       message="verify: %d tool advisor(s)" % len(entries))


def _verify_tools_done(review_root, manifest):
    return all(_tool_verdict_done(review_root, qid)
               for qid, _f in _tool_verify_queue(review_root, manifest))


def synthesize_done(review_root, manifest):
    # §5.1: gate on the durable tag-named report, not the convenience symlink, so
    # resume never depends on symlink creation having succeeded.
    return _json_parses(_report_out(review_root))


def synthesize_execute(review_root, manifest):
    # #5.0-16 fallback: guarantee both integrity artifacts exist once, after
    # review and before synthesize, even when the verify phase was vacuously
    # done (no engaged cell -> verify_execute never ran, so no agent ran either
    # -- the snapshot here still captures authentic post-review bytes). Both are
    # idempotent no-ops when review_execute/verify_execute already wrote them.
    _write_driver_plan(review_root, manifest)
    _snapshot_review_out_files(review_root, manifest)
    findings = sorted(_glob.glob(_pano(review_root, "findings-*.json")))
    verdicts_dir = _pano(review_root, "verdicts")
    os.makedirs(verdicts_dir, exist_ok=True)   # empty in P3 (verify is a no-op)
    report = _report_out(review_root)   # §5.1: durable, top-level, tag-named
    flags = manifest.get("flags") or {}
    cmd = [sys.executable, _script("synthesize.py"),
           "--out", report,
           "--groups", _pano(review_root, "groups.json"),
           "--security", manifest.get("security_mode", "standard"),
           "--run-id", manifest.get("run_id") or "",   # §5.1: X0X report provenance
           "--verdicts-dir", verdicts_dir]
    if (_load_json(_pano(review_root, "tools-ran.json")) or {}).get("ran"):
        cmd += ["--tools-dir", _pano(review_root, "tools")]
        # Pin synthesize's fixture posture to the tool-verify queue's
        # (#5.0-03): both must ingest the SAME tool findings or synthesize
        # could queue one the driver never dispatched a verdict for. Also
        # closes the latent gap where the manifest captured include_fixtures
        # but synthesize_execute never forwarded it.
        if _tools_include_fixtures(manifest):
            cmd += ["--include-fixtures"]
    for flag, key in (("--fail-on", "fail_on"), ("--severity", "severity"),
                      ("--gate-scope", "gate_scope")):
        if flags.get(key):
            cmd += [flag, str(flags[key])]
    diff_hunks = _pano(review_root, "diff-hunks.json")
    if os.path.isfile(diff_hunks):
        cmd += ["--diff-hunks", diff_hunks]
    if flags.get("diff_context") is not None:
        cmd += ["--diff-context", str(flags["diff_context"])]
    cmd += findings
    proc = _run_child(cmd, review_root, "synthesize")
    # A failing gate exits non-zero but still writes the report — that is a valid
    # outcome, not a driver error. Only an ABSENT report is a failure.
    if not _json_parses(report):
        raise DriverError("synthesize produced no report.json (rc=%s): %s"
                          % (proc.returncode, _redact_output((proc.stderr or proc.stdout)[:400])))
    # §5.1: point the flat compat paths at the latest tag-named report, so every
    # existing reader of report.json / report.json.html resolves it unchanged, and
    # refresh runs/latest. The tag-named files are the durable top-level outputs;
    # the run folder can be cleared without touching them.
    tag = _run_tag(review_root)
    if tag:
        try:   # compat symlinks are best-effort; the tag-named report is authoritative
            _relink(_pano(review_root, "report.json"), f"{tag}-report.json")
            if os.path.exists(f"{report}.html"):
                _relink(_pano(review_root, "report.json.html"),
                        f"{tag}-report.json.html")
        except OSError:
            pass
        _ensure_run_symlinks(review_root)
    return PhaseResult(kind="advanced", message="synthesize: report.json written")


def capture_tree_baseline(review_root, runner=subprocess.run):
    """Snapshot the clean-tree baseline once (run start). No-op for a non-git
    target (returns None)."""
    baseline = _pano(review_root, "tree-baseline.txt")
    if os.path.exists(baseline):
        return baseline
    try:
        proc = runner(["git", "-C", review_root, "status", "--porcelain", "-z"],
                      capture_output=True, text=True, timeout=15)
        if proc.returncode != 0:
            return None
    except (subprocess.SubprocessError, OSError):
        return None
    os.makedirs(os.path.dirname(baseline), exist_ok=True)
    with _open_w_nofollow(baseline) as fh:
        fh.write(proc.stdout)
    return baseline


def _porcelain_z_records(output):
    """Parse `git status --porcelain -z` into a set of (XY, paths) records. Paths
    are RAW -- `-z` disables core.quotePath, so a non-ASCII name is emitted
    verbatim between NULs instead of C-quoted (`".panopticon/\\303\\251.py"`),
    which the old line-split mis-flagged. A rename/copy (X in R/C) carries BOTH
    endpoints: the entry's own (new) path plus the NUL-separated original path
    that immediately follows it (#1033/SEC-1)."""
    tokens = output.split("\0")
    records = set()
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if not tok:
            i += 1
            continue
        xy, path = tok[:2], tok[3:]
        if xy[:1] in ("R", "C") and i + 1 < len(tokens):
            records.add((xy, (path, tokens[i + 1])))   # (new, original)
            i += 2
        else:
            records.add((xy, (path,)))
            i += 1
    return records


def _outside_panopticon(path):
    """First path component is not `.panopticon` (a real boundary check:
    '.panopticon-evil.py' is NOT under .panopticon/)."""
    return path.split("/", 1)[0] != ".panopticon"


def _tree_delta(review_root, runner):
    """NEW porcelain records (vs. baseline) that touch a path outside
    .panopticon/. Empty when there is no baseline (non-git) — nothing to compare.
    A rename is checked on BOTH endpoints (#1033/SEC-1): a rename moving a real
    file INTO .panopticon/ still changed the outside tree via its source, which
    the old destination-only check silently missed."""
    try:
        with open(_pano(review_root, "tree-baseline.txt"), encoding="utf-8") as fh:
            baseline = _porcelain_z_records(fh.read())
    except OSError:
        return []
    try:
        proc = runner(["git", "-C", review_root, "status", "--porcelain", "-z"],
                      capture_output=True, text=True, timeout=15)
        if proc.returncode != 0:
            return []
    except (subprocess.SubprocessError, OSError):
        return []
    new = _porcelain_z_records(proc.stdout) - baseline
    return sorted("%s %s" % (xy, " -> ".join(paths)) for xy, paths in new
                  if any(_outside_panopticon(p) for p in paths))


def validate_done(review_root, manifest):
    data = _load_json(_pano(review_root, "validate.json"))
    return (isinstance(data, dict) and data.get("run_id") == manifest.get("run_id")
            and data.get("tree_clean") is True)


def validate_execute(review_root, manifest, runner=subprocess.run):
    delta = _tree_delta(review_root, runner)
    # The PR worktree (when review_root IS the worktree) is released by run()
    # AFTER the run completes, NOT here: releasing mid-machine would delete the
    # review root (report.json + manifest) and break cursor derivation. (Ruling A)
    _write_json(_pano(review_root, "validate.json"),
                {"schema_version": 1, "run_id": manifest["run_id"],
                 "tree_clean": not delta, "unexpected_changes": delta})
    if delta:
        raise DriverError("validate: reviewer side effects outside .panopticon/: "
                          + "; ".join(delta[:10]))
    return PhaseResult(kind="advanced", message="validate: clean tree")


def _finalize_worktree(review_root, manifest):
    """On a completed --pr run, review_root IS the disposable worktree. Surface
    report.json to the caller's target .panopticon/ BEFORE releasing the worktree
    so the deliverable survives disposal (spec §4: no leak + report available).
    Best-effort surface; release is tolerant. No-op when there is no worktree."""
    worktree = manifest.get("worktree")
    if not worktree:
        return
    target = manifest.get("target") or review_root
    tag = run_manifest.run_tag(manifest)
    src_dir = os.path.join(review_root, ".panopticon")
    dst_dir = os.path.join(target, ".panopticon")
    # §5.1: surface the durable, top-level, tag-named outputs (report + optional
    # split part + html) so the caller's report is complete and self-consistent even
    # when split, then re-link report.json there. Falls back to a flat report.json
    # copy if there is no tag (no manifest — should not happen post-run).
    names = ([f"{tag}-report.json", f"{tag}-report_part2.json",
              f"{tag}-report.json.html"] if tag else ["report.json"])
    for name in names:
        src, dst = os.path.join(src_dir, name), os.path.join(dst_dir, name)
        if os.path.realpath(src) != os.path.realpath(dst) and os.path.isfile(src):
            try:
                os.makedirs(dst_dir, exist_ok=True)
                shutil.copyfile(src, dst)
            except OSError:
                pass
    if tag and os.path.isfile(os.path.join(dst_dir, f"{tag}-report.json")):
        try:
            _relink(os.path.join(dst_dir, "report.json"), f"{tag}-report.json")
            if os.path.isfile(os.path.join(dst_dir, f"{tag}-report.json.html")):
                _relink(os.path.join(dst_dir, "report.json.html"),
                        f"{tag}-report.json.html")
        except OSError:
            pass
    diff_map.release_worktree(worktree, repo=target)


SETUP_MANIFEST = "setup-manifest.json"


def _setup_manifest_path(review_root):
    return _pano(review_root, SETUP_MANIFEST)


def load_setup_manifest(review_root):
    return _load_json(_setup_manifest_path(review_root))


def _read_text(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def _setup_scan_entry(review_root, prompt):
    """One return-persist dispatch entry for the read-only setup-scan agent
    (mirrors _scout_entry): the host dispatches it, gets proposal JSON back, and
    persists it to out_file.

    Unlike scout/panel/advisor roles, setup-scan is NEVER enforced: it is not in
    dispatch.ROLE_FILES, so no `panopticon-setup-scan` shell is ever registered
    for any host — dispatching it as "enforced" would ask the host to invoke a
    subagent that doesn't exist. It is read-only + return-persist by template
    tool_policy (Read/Grep/Glob only), so a plain general-purpose dispatch is
    sufficient and safe.
    """
    return {"id": "setup-scan",
            "agent": None,
            "enforced": False,
            "model": None,
            "prompt": prompt,
            "out_file": os.path.abspath(_pano(review_root, "setup-proposal.json"))}


def scan_done(review_root, manifest):
    return (_json_parses(_pano(review_root, "setup-proposal.json"))
            or _json_parses(_pano(review_root, "setup-complete.json")))


def scan_execute(review_root, manifest):
    """Provision + render the scan brief -> setup-scan checkpoint (vocab present);
    or flat-seed + readiness + a fallback-complete marker (vocab absent, Task 3)."""
    host = manifest.get("host", "claude")
    prov = setup_flow.provision(review_root)
    note = prov.get("gitignore_note")   # #1135: groups.yml needs `git add -f`
    vocab, present = setup_flow.load_bundled_vocabulary(manifest.get("vocabulary_path"))
    if not present:
        return _scan_fallback(review_root, manifest, host, note=note)   # Task 3
    brief_path = setup_flow.render_scan_brief(review_root, vocab)
    entry = _setup_scan_entry(review_root, _read_text(brief_path))
    req = write_dispatch_request(review_root, manifest["run_id"], "scan", None, [entry])
    msg = "setup-scan checkpoint" + ((" — " + note) if note else "")
    return PhaseResult(kind="checkpoint", checkpoint="scan", group=None,
                       dispatch_request=req, message=msg)


def ingest_done(review_root, manifest):
    return (os.path.isfile(_pano(review_root, "groups.yml.draft"))
            or _json_parses(_pano(review_root, "setup-complete.json")))


def ingest_execute(review_root, manifest):
    res = setup_flow.ingest_proposal(review_root)
    if not res["ok"]:
        raise DriverError("ingest: " + "; ".join(res["errors"]))
    return PhaseResult(kind="advanced",
                       message="setup: draft written %s" % res["draft"])


SETUP_PHASES = (
    Phase("scan", "checkpoint", scan_done, scan_execute),
    Phase("ingest", "deterministic", ingest_done, ingest_execute),
)


_SETUP_ARTIFACTS = ("setup-scan-brief.md", "setup-proposal.json",
                    "groups.yml.draft", "setup-complete.json", SETUP_MANIFEST)


def _clear_setup_artifacts(review_root):
    """Remove derived setup artifacts + the setup-manifest for --reset. NEVER
    touches the committed groups.yml."""
    for name in _SETUP_ARTIFACTS:
        try:
            os.remove(_pano(review_root, name))
        except OSError:
            pass


def _scan_fallback(review_root, manifest, host, note=None):
    """Vocab-absent path (parity with orchestrator.run_setup): flat top-dir seed
    + readiness gate, then a fallback-complete marker so both setup phases'
    done-predicates are satisfied -> run_engine completes without a checkpoint
    and without entering ingest."""
    path, created, names = setup_flow.seed_flat_manifest(review_root)
    checks = setup_flow.readiness(review_root, host=host)
    gaps = [c[0] for c in checks if c[1] is False]
    _write_json(_pano(review_root, "setup-complete.json"), {
        "schema_version": 1,
        "mode": "fallback", "seed": path, "created": created, "groups": names,
        "readiness": [[c[0], c[1], c[2]] for c in checks],
        "gaps": gaps, "run_id": manifest["run_id"]})
    msg = ("setup: vocab-absent fallback — flat seed %s; readiness %s"
           % (path, "OK" if not gaps else "gaps: " + ", ".join(gaps)))
    if note:   # #1135: surface the "groups.yml needs `git add -f`" note
        msg += " — " + note
    return PhaseResult(kind="advanced", message=msg)


def _drop_stale_fallback_marker(review_root):
    """A vocab-absent run wrote a mode:"fallback" setup-complete.json. Once the
    vocabulary is available again, that marker is stale — a real scan should
    supersede the flat seed. Remove it so the engine re-scans (self-healing; no
    --reset needed). No-op when there is no fallback marker or vocab is still
    absent."""
    marker = _load_json(_pano(review_root, "setup-complete.json"))
    if not (isinstance(marker, dict) and marker.get("mode") == "fallback"):
        return
    _vocab, present = setup_flow.load_bundled_vocabulary(None)
    if present:
        try:
            os.remove(_pano(review_root, "setup-complete.json"))
        except OSError:
            pass


def run_setup_flow(args, runner=subprocess.run, phases=SETUP_PHASES):
    """The `driver setup` entrypoint: a separate two-phase flow (NOT a run
    phase). Resolves the review root, pins a minimal setup-manifest once, and
    advances scan->ingest through run_engine. Writes a draft; the owner reviews
    and commits it."""
    review_root, _wt, _pr = resolve_review_root(args.target, runner=runner)
    if getattr(args, "reset", False):
        _clear_setup_artifacts(review_root)               # Task 3
    _drop_stale_fallback_marker(review_root)
    manifest = load_setup_manifest(review_root)
    if manifest is None:
        manifest = {"schema_version": 1, "run_id": run_manifest.new_run_id(),
                    "target": os.path.abspath(args.target),
                    "host": args.host or _DEFAULTS["host"],
                    "vocabulary_path": None}
        _write_json(_setup_manifest_path(review_root), manifest)
    try:
        result = run_engine(review_root, manifest, phases)
    except DriverError as exc:
        return _error_status(str(exc))
    if result.get("status") == "complete":
        if os.path.isfile(_pano(review_root, "groups.yml.draft")):
            result["message"] = ("setup complete — review .panopticon/groups.yml.draft, "
                                 "move it to .panopticon/groups.yml, and commit")
        else:
            msg = ("setup complete — vocab-absent fallback seeded a flat "
                  ".panopticon/groups.yml; review, edit, and commit it")
            gaps = (_load_json(_pano(review_root, "setup-complete.json")) or {}).get("gaps") or []
            if gaps:
                msg += (" — readiness gaps: %s (fix before running a review)"
                       % ", ".join(gaps))
            result["message"] = msg
    return result


_DEFAULTS = {"host": "claude", "security": "standard"}

_RESET_GLOBS = ("groups.json", "coverage-*.json", "scout-*.json", "tools-ran.json",
                "validate.json",
                "report.json", "dispatch-request.json", "tree-baseline.txt",
                "verify-queue.json", "findings-*.json",
                # #5.0-07: stale delta artifacts must not survive a --reset and
                # silently delta-scope (or content-check) the next run.
                # #5.0-16: the driver's own dispatch plan clears too, so a
                # --reset run re-declares cells from fresh coverage.
                "diff-hunks.json", "out-file-hashes.json",
                "dispatch-plan-driver.json")

PHASES = (
    Phase("discovery", "deterministic", discovery_done, discovery_execute),
    Phase("coverage", "mixed", coverage_done, coverage_execute),
    Phase("tools", "deterministic", tools_done, tools_execute),
    Phase("review", "checkpoint", review_done, review_execute),
    Phase("verify", "mixed", verify_done, verify_execute),
    Phase("synthesize", "deterministic", synthesize_done, synthesize_execute),
    Phase("validate", "deterministic", validate_done, validate_execute),
)


def _cli_flags(args):
    if getattr(args, "tools", False) and getattr(args, "no_tools", False):
        raise ValueError("cannot specify both --tools and --no-tools")
    tools = False if getattr(args, "no_tools", False) else (
        True if getattr(args, "tools", False) else None)
    values = {"fail_on": getattr(args, "fail_on", None),
              "severity": getattr(args, "severity", None),
              "gate_scope": getattr(args, "gate_scope", None),
              "diff_context": getattr(args, "diff_context", None),
              "tools": tools,
              "include_fixtures": True if getattr(args, "include_fixtures", False) else None}
    return {k: values.get(k) for k in run_manifest._FLAG_KEYS}


def _scope_from_args(args):
    """The {mode,target} scope implied by -f/-d/-g, or None if none was given
    (a bare re-invocation with no scope opinion — mirrors host/security_mode/
    base/flags: None never conflicts in conflicting_flags, and build_manifest
    defaults a None scope to {"mode":"repo","target":None} itself)."""
    if getattr(args, "scope_file", None):
        return {"mode": "file", "target": args.scope_file}
    if getattr(args, "scope_dir", None):
        return {"mode": "directory", "target": args.scope_dir}
    if getattr(args, "scope_group", None):
        return {"mode": "group", "target": args.scope_group}
    if getattr(args, "scope_changed", False):
        return {"mode": "changed", "target": None}
    if getattr(args, "scope_files", None):
        return {"mode": "files", "target": list(args.scope_files)}
    return None


def _clear_run_artifacts(review_root):
    """--reset: clear the current run's working folder (findings / verdicts /
    coverage / scouts / dispatch / ...) so a fresh run starts, while KEEPING the
    durable top-level tag-named report — reset reclaims the scratch, not the
    deliverable (§5.1). NEVER touches groups.yml (the committed matrix) or another
    run's folder/report. MUST run BEFORE the manifest is removed, so the tag still
    resolves; with no/corrupt manifest it degrades to the legacy flat sweep."""
    base = os.path.join(review_root, ".panopticon")
    tag = _run_tag(review_root)
    if tag:
        shutil.rmtree(os.path.join(base, "runs", tag), ignore_errors=True)
        # runs/latest now dangles (its target folder is gone) — drop the pointer;
        # report.json is left pointing at the kept durable report.
        try:
            os.remove(os.path.join(base, "runs", "latest"))
        except OSError:
            pass
    # Migration safety: sweep any legacy FLAT run artifacts a pre-5.1 run may have
    # left at top-level. The report.json SYMLINK points at the durable tag-named
    # report and is kept; only a STALE FLAT report.json (a real file — pre-5.1 or
    # a corrupt/orphaned state) is swept, preserving the I1 no-resume-on-stale-data
    # invariant. The tag-named reports themselves are never in _RESET_GLOBS.
    for pat in _RESET_GLOBS:
        for path in _glob.glob(os.path.join(base, pat)):
            if os.path.basename(path) == "report.json" and os.path.islink(path):
                continue
            try:
                os.remove(path)
            except OSError:
                pass
    for sub in ("tools", "verdicts"):
        shutil.rmtree(os.path.join(base, sub), ignore_errors=True)


def build_parser():
    parser = argparse.ArgumentParser(prog="driver")
    sub = parser.add_subparsers(dest="verb", required=True)
    # #1033: `next` was a silent, undifferentiated alias of `run` (run() is
    # already idempotent + resumes from disk), so it's removed rather than kept
    # as a confusing second spelling.
    for verb in ("run",):
        p = sub.add_parser(verb)
        p.add_argument("target", nargs="?", default=".")
        p.add_argument("--host", default=None, choices=["claude", "generic", "gemini"])
        p.add_argument("--security", default=None, choices=["standard", "redteam"])
        p.add_argument("--base", default=None)
        p.add_argument("--pr", type=int, default=None)
        p.add_argument("--reset", action="store_true")
        p.add_argument("--fail-on", default=None)
        p.add_argument("--severity", default=None)
        p.add_argument("--gate-scope", default=None)
        p.add_argument("--diff-context", type=int, default=None)
        tools_group = p.add_mutually_exclusive_group()
        tools_group.add_argument("--tools", action="store_true")
        tools_group.add_argument("--no-tools", action="store_true")
        p.add_argument("--include-fixtures", action="store_true")
        scope = p.add_mutually_exclusive_group()
        scope.add_argument("-f", "--file", dest="scope_file", default=None)
        scope.add_argument("-d", "--directory", dest="scope_dir", default=None)
        scope.add_argument("-g", "--group", dest="scope_group", default=None)
        scope.add_argument("-c", "--changes", dest="scope_changed",
                           action="store_true")
        scope.add_argument("--files", dest="scope_files", nargs="+", default=None)
    sp = sub.add_parser("setup")
    sp.add_argument("target", nargs="?", default=".")
    sp.add_argument("--host", default=None, choices=["claude", "generic", "gemini"])
    sp.add_argument("--reset", action="store_true")
    return parser


def _error_status(message):
    return {"status": "error", "phase": None, "checkpoint": None, "group": None,
            "dispatch_request": None, "advanced": [], "message": message}


def _foreign_manifest(manifest, review_root):
    """#1093: True if a loaded run-manifest was NOT written by a prior run in
    THIS tree. build_manifest stamps `review_root` as this-machine abspath, so a
    manifest whose stamped review_root differs is not a legitimate resume state --
    most likely a target repo that committed its own `.panopticon/run-manifest.json`
    to preset attacker-chosen flags (e.g. flags.tools:false to skip the scan, or
    flags.fail_on to force gate:PASS). Such a manifest must be discarded and
    rebuilt from the real CLI args, never trusted as run config."""
    return (isinstance(manifest, dict)
            and manifest.get("review_root") != os.path.abspath(review_root))


def run(args, runner=subprocess.run, phases=PHASES):
    # #5.0-14: resolving the review root can fail loudly for a --pr run (gh
    # auth/network, a bad PR number, worktree acquisition) — keep it inside the
    # status protocol instead of letting a raw RuntimeError escape run().
    try:
        review_root, worktree, pr_base = resolve_review_root(
            args.target, base=args.base, pr=args.pr, runner=runner)
    except (RuntimeError, ValueError, OSError) as exc:
        return _error_status("could not resolve review root: %s" % exc)
    if args.pr is not None:
        # A PR is a changed-files delta by definition. manifest["base"] holds the
        # user's EXPLICIT override only (anti-drift key); the gh-detected PR base
        # flows separately via manifest["pr_base"] -> orchestrator --pr-base, so
        # resolve_base applies its origin/<base> preference (#947 / spec §4 L51).
        base = args.base
        scope = {"mode": "changed", "target": None}
    else:
        base = args.base
        scope = _scope_from_args(args)
    # #5.0-09: verify .panopticon is a real in-repo directory BEFORE any write or
    # delete under it. A committed .panopticon symlink in a hostile target (or PR
    # fork checkout) would otherwise redirect the driver's own reset/manifest/
    # baseline writes outside the repo, because discovery's artifact_root guard
    # runs only later, inside the discovery subprocess.
    try:
        plan_contract.artifact_root(review_root)
    except ValueError as exc:
        if worktree:
            diff_map.release_worktree(worktree, repo=args.target)
        return _error_status("unsafe artifact root: %s" % exc)
    if args.reset:
        _clear_run_artifacts(review_root)   # §5.1: resolve the tag before the manifest goes
        run_manifest.reset_run(review_root)
    manifest = run_manifest.load_manifest(review_root)
    if _foreign_manifest(manifest, review_root):
        # #1093: a target-committed run-manifest.json (foreign review_root) could
        # preset flags to skip tools / force gate:PASS. Drop it and rebuild from
        # the real CLI args, exactly like a corrupt manifest below.
        print("driver: ignoring foreign run-manifest.json (stamped review_root "
              "%r != %r)" % (manifest.get("review_root"), os.path.abspath(review_root)),
              file=sys.stderr, flush=True)
        manifest = None
    if manifest is None:
        # I1: no manifest means no prior run should count — clear any stale
        # derived artifacts so done()-predicates never resume on another run's
        # data (a lost/corrupt manifest, a partially-failed reset, or a
        # pre-existing 4.x groups.json).
        # #5.0-13: load_manifest also returns None for a CORRUPT (present-but-
        # unparseable) manifest — remove it first so write_manifest (write-once)
        # can't raise an uncaught FileExistsError and wedge the run.
        _clear_run_artifacts(review_root)
        run_manifest.reset_run(review_root)
        manifest = run_manifest.build_manifest(
            target=args.target, review_root=review_root,
            host=args.host or _DEFAULTS["host"],
            security_mode=args.security or _DEFAULTS["security"],
            base=base, flags=_cli_flags(args), worktree=worktree,
            scope=scope, pr=args.pr, pr_base=pr_base)
        run_manifest.write_manifest(review_root, manifest)
    else:
        conflicts = run_manifest.conflicting_flags(
            manifest, host=args.host, security_mode=args.security,
            base=base, flags=_cli_flags(args), scope=scope, pr=args.pr)
        if conflicts:
            return _error_status("flag drift (use --reset to start over): "
                                 + "; ".join(conflicts))
    # #1: a bare re-invocation of an ALREADY-complete run matches every manifest
    # field (conflicting_flags treats a None incoming value as no-conflict), so it
    # would advance straight to "complete" and hand back a possibly-stale report as
    # though it were a fresh scan -- the worst failure mode for a review tool.
    # Refuse loudly and name --reset instead; the durable report stays on disk.
    # (Guarded by `not args.reset`: a --reset run just cleared its derived
    # artifacts, so it can never be already-complete at this point.)
    if not args.reset and _first_not_done(phases, review_root, manifest) is None:
        report = _pano(review_root, "report.json")
        loc = report if os.path.exists(report) else review_root
        return _error_status(
            "run already complete (report at %s) -- use `--reset` to start a new "
            "run" % loc)
    # §5.1: point runs/latest at the active run folder now that the manifest (hence
    # the tag) is established — so the pointer exists throughout the run, not just
    # after synthesize writes the report.
    _ensure_run_symlinks(review_root)
    # I2: capture the clean-tree baseline unconditionally and BEFORE the engine
    # runs. Idempotent (returns the existing baseline if present) -> no-op on a
    # normal resume, but self-heals a baseline that a mid-first-run interrupt
    # left missing (which had silently disabled the clean-tree guard).
    capture_tree_baseline(review_root, runner=runner)
    try:
        result = run_engine(review_root, manifest, phases)
    except DriverError as exc:
        return _error_status(str(exc))
    if result.get("status") == "complete":
        _finalize_worktree(review_root, manifest)
    return result


def main(argv=None):
    args = build_parser().parse_args(argv)
    if args.verb == "setup":
        return emit_status(run_setup_flow(args))
    return emit_status(run(args))


if __name__ == "__main__":
    sys.exit(main())
