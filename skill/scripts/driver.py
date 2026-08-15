"""The 5.0 resumable driver: a table-driven phase state machine.

`driver run` advances through PHASES, executing deterministic work itself and
STOPPING at each dispatch checkpoint (writing dispatch-request.json). The phase
cursor is never stored — it is recomputed from disk (`first not-done phase`)
every invocation, so a crash/compaction/interrupt resumes identically. See
docs/superpowers/specs/2026-08-15-panopticon-5.0-driver-skeleton-design.md.
"""
import dataclasses
import glob as _glob  # noqa: F401 -- shared helper import; used by later phases (Tasks 5-9)
import json
import os
import subprocess
import sys

import yaml

import scripts.coverage_model as coverage_model
import scripts.diff_map as diff_map
import scripts.dispatch as dispatch
import scripts.groups_schema as groups_schema

CHECKPOINT_KINDS = ("scout", "review", "verify")

_SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))


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


def _pano(review_root, *parts):
    return os.path.join(review_root, ".panopticon", *parts)


def _load_json(path):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def _write_json(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, sort_keys=True)
    return path


def _json_parses(path):
    return _load_json(path) is not None


def load_committed_groups(review_root):
    """Parse the committed groups.yml via groups_schema (P1). A MISSING file is
    an error (the driver run requires a committed matrix — `panopticon setup`
    produces it), not an empty success."""
    path = _pano(review_root, "groups.yml")
    try:
        with open(path, encoding="utf-8") as fh:
            doc = yaml.safe_load(fh)
    except FileNotFoundError:
        return {}, ["no committed groups.yml at %s — run `panopticon setup` first"
                    % path]
    except (OSError, yaml.YAMLError) as exc:
        return {}, ["groups.yml unreadable: %s" % exc]
    return groups_schema.parse_groups(doc if isinstance(doc, dict) else {})


def discovery_done(review_root, manifest):
    return _json_parses(_pano(review_root, "groups.json"))


def discovery_execute(review_root, manifest):
    _groups, errors = load_committed_groups(review_root)
    if errors:
        raise DriverError("discovery: " + "; ".join(errors))
    out = _pano(review_root, "groups.json")
    cmd = [sys.executable, _script("orchestrator.py"), "--repo-scan",
           "--security", manifest.get("security_mode", "standard"),
           review_root, "--out", out]
    proc = subprocess.run(cmd, cwd=review_root, capture_output=True, text=True,
                          env=_child_env())
    if not _json_parses(out):
        raise DriverError(
            "discovery: orchestrator --repo-scan produced no groups.json "
            "(rc=%s): %s" % (proc.returncode, (proc.stderr or proc.stdout)[:400]))
    return PhaseResult(kind="advanced", message="discovery: groups.json written")


def resolve_review_root(target, base=None, pr=None, runner=subprocess.run):
    """Resolve the single review root, pinned once in the manifest (spec §5).

    - pr given: acquire a disposable PR worktree (diff_map); its path is the root.
    - git repo: `git rev-parse --show-toplevel` from the target.
    - non-git: the target directory itself.
    Returns (review_root, worktree); worktree is the PR worktree to release at
    validate, else None.
    """
    if pr is not None:
        info = diff_map.acquire_pr(pr, repo=target, runner=runner)
        return info["worktree"], info["worktree"]
    target = os.path.abspath(target)
    start = target if os.path.isdir(target) else os.path.dirname(target)
    try:
        proc = runner(["git", "-C", start, "rev-parse", "--show-toplevel"],
                      capture_output=True, text=True)
        if proc.returncode == 0 and proc.stdout.strip():
            return os.path.realpath(proc.stdout.strip()), None
    except OSError:
        pass
    return (start if os.path.isdir(start) else target), None


@dataclasses.dataclass(frozen=True)
class Phase:
    name: str
    kind: str        # "deterministic" | "checkpoint" | "mixed"
    done: object     # callable(review_root, manifest) -> bool
    execute: object  # callable(review_root, manifest) -> PhaseResult


@dataclasses.dataclass
class PhaseResult:
    kind: str                     # "advanced" | "checkpoint"
    checkpoint: str = None        # scout|review|verify (iff kind == "checkpoint")
    group: str = None
    dispatch_request: str = None  # absolute path (iff checkpoint)
    message: str = ""


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
    path = os.path.join(review_root, ".panopticon", "dispatch-request.json")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(request, fh, indent=2)
    return os.path.abspath(path)


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
    file_list = "\n".join("- " + f for f in files) or "- (no files)"
    prompt = (body
              + "\n\n## Assignment\n\nGroup: %s\nSecurity mode: %s\n\nFiles:\n%s\n"
                % (group, security, file_list)
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


def coverage_execute(review_root, manifest):
    """Per group: emit the scout checkpoint (streamed) if its output is absent,
    else compute FLOOR coverage. Returns after one unit of work; the engine
    re-selects coverage until every group has a coverage file."""
    matrix, _errors = load_committed_groups(review_root)
    host = manifest.get("host", "claude")
    for group, files in _discovered_groups(review_root):
        if _json_parses(_pano(review_root, "coverage-%s.json" % group)):
            continue
        scout_path = _pano(review_root, "scout-%s.json" % group)
        if not _json_parses(scout_path):
            entry = _scout_entry(review_root, manifest, group, files, host)
            req = write_dispatch_request(review_root, manifest["run_id"],
                                         "scout", group, [entry])
            return PhaseResult(kind="checkpoint", checkpoint="scout", group=group,
                               dispatch_request=req,
                               message="scout checkpoint for group %s" % group)
        spec = matrix.get(group) or {}
        effective, disclosure = coverage_model.effective_panels(
            spec.get("floor", set()), set(), spec.get("exclude", set()))
        _write_json(_pano(review_root, "coverage-%s.json" % group), {
            "group": group,
            "floor": disclosure["floor"],
            "excluded": disclosure["excluded"],
            "scout_added": [],   # P4 bridges scout panel-names -> domain codes
            "effective": sorted(effective),
            "scout_file": os.path.abspath(scout_path),
            "run_id": manifest["run_id"],
        })
        return PhaseResult(kind="advanced",
                           message="coverage: group %s (floor)" % group)
    return PhaseResult(kind="advanced", message="coverage: complete")
