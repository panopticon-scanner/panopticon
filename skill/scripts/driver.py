"""The 5.0 resumable driver: a table-driven phase state machine.

`driver run` advances through PHASES, executing deterministic work itself and
STOPPING at each dispatch checkpoint (writing dispatch-request.json). The phase
cursor is never stored — it is recomputed from disk (`first not-done phase`)
every invocation, so a crash/compaction/interrupt resumes identically. See
docs/superpowers/specs/2026-08-15-panopticon-5.0-driver-skeleton-design.md.
"""
import argparse
import dataclasses
import glob as _glob
import json
import os
import shutil
import subprocess
import sys

import yaml

import scripts.coverage_model as coverage_model
import scripts.diff_map as diff_map
import scripts.dispatch as dispatch
import scripts.evidence as evidence
import scripts.groups_schema as groups_schema
import scripts.ocrdb as ocrdb
import scripts.run_manifest as run_manifest
import scripts.score_gate as score_gate
import scripts.synthesize as synthesize

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
    else compute coverage as floor widened by the scout's valid domains.
    Returns after one unit of work; the engine re-selects coverage until
    every group has a coverage file."""
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
        # scout landed -> widen coverage by the scout's valid domains (P4 bridge)
        scout = _load_json(scout_path) or {}
        raw = scout.get("domains") or []
        spec = matrix.get(group) or {}
        floor = spec.get("floor", set())
        # net against floor here so disclosure["scout_added"] reports only the
        # genuinely NEW domains (a domain already on the floor isn't "added").
        scout_added = {d for d in raw if d in groups_schema.DOMAINS} - set(floor)
        scout_invalid = sorted(set(raw) - groups_schema.DOMAINS)
        effective, disclosure = coverage_model.effective_panels(
            floor, scout_added, spec.get("exclude", set()))
        _write_json(_pano(review_root, "coverage-%s.json" % group), {
            "group": group,
            "floor": disclosure["floor"],
            "excluded": disclosure["excluded"],
            "scout_added": disclosure["scout_added"],   # new domains, exclude-netted
            "scout_invalid": scout_invalid,             # dropped, disclosed
            "effective": sorted(effective),
            "scout_file": os.path.abspath(scout_path),
            "run_id": manifest["run_id"],
        })
        return PhaseResult(kind="advanced",
                           message="coverage: group %s (floor+scout)" % group)
    return PhaseResult(kind="advanced", message="coverage: complete")


def tools_done(review_root, manifest):
    return _json_parses(_pano(review_root, "tools-ran.json"))


def tools_execute(review_root, manifest):
    if (manifest.get("flags") or {}).get("tools") is False:
        _write_json(_pano(review_root, "tools-ran.json"),
                    {"ran": False, "skipped": True, "note": "tools disabled (--no-tools)",
                     "returncode": None, "run_id": manifest["run_id"]})
        return PhaseResult(kind="advanced", message="tools: skipped (--no-tools)")
    out_dir = _pano(review_root, "tools")
    cmd = [sys.executable, _script("run_tools.py"), "--target", review_root,
           "--out", out_dir, "--deps"]
    proc = subprocess.run(cmd, cwd=review_root, capture_output=True, text=True,
                          env=_child_env())
    produced = os.path.isdir(out_dir) and bool(os.listdir(out_dir))
    note = "" if produced else ((proc.stderr or "").strip()[:300] or "no tool output produced")
    _write_json(_pano(review_root, "tools-ran.json"),
                {"ran": produced, "skipped": not produced, "note": note,
                 "returncode": proc.returncode, "run_id": manifest["run_id"]})
    if not produced:
        sys.stderr.write("driver: tool scan produced no output — %s\n" % note)
    return PhaseResult(kind="advanced",
                       message="tools: %s" % ("produced output" if produced
                                              else "SKIPPED — " + note))


def _noop_done(name):
    def done(review_root, manifest):
        data = _load_json(_pano(review_root, name))
        return isinstance(data, dict) and data.get("run_id") == manifest.get("run_id")
    return done


def _effective_domains(review_root, group):
    cov = _load_json(_pano(review_root, "coverage-%s.json" % group)) or {}
    return list(cov.get("effective") or [])


def _cell_done(review_root, manifest, group, domain):
    data = _load_json(_pano(review_root, "findings-%s-%s.json" % (group, domain)))
    if not (isinstance(data, dict) and isinstance(data.get("findings"), list)):
        return False
    meta = data.get("_panopticon")
    return (isinstance(meta, dict) and meta.get("run_id") == manifest.get("run_id")
            and meta.get("domain") == domain and meta.get("group") == group)


def _render_menu(bundle, domain):
    lines = ["%s %s (%s)" % (m["code"], m["name"], m["severity"])
             for m in ocrdb.domain_menu(bundle, domain)]
    return "\n".join(lines) or "(no OCRDb bundle vendored — use general %s judgment)" % domain


def _cell_entry(review_root, manifest, group, domain, files, tests, host, bundle):
    file_list = "\n".join("- " + f for f in files) or "- (no files)"
    test_list = "\n".join("- " + t for t in tests) or "- (no tests)"
    out_file = os.path.abspath(_pano(review_root, "findings-%s-%s.json" % (group, domain)))
    prompt = dispatch.render_prompt("domain-panel.md", {
        "domain": domain, "group": group, "file_list": file_list,
        "tests": test_list, "security_mode": manifest.get("security_mode", "standard"),
        "menu": _render_menu(bundle, domain), "run_id": manifest["run_id"],
        "out_file": out_file}, host)
    enforced = host == "claude"
    return {"id": "review-%s-%s" % (group, domain),
            "agent": dispatch.registered_agent_name("domain-panel.md") if enforced else None,
            "enforced": enforced, "model": None, "prompt": prompt, "out_file": out_file}


def _load_cell_findings(review_root, manifest, group, domain):
    """The cell's reviewer findings, normalized + id-assigned exactly as
    synthesize.load_findings does, or None when the cell file is absent/mismatched.
    Ids match synthesize's so the advisor's finding_id echo binds at synthesis."""
    if not _cell_done(review_root, manifest, group, domain):
        return None
    data = _load_json(_pano(review_root, "findings-%s-%s.json" % (group, domain)))
    out = []
    for f in data.get("findings") or []:
        if not isinstance(f, dict):
            continue
        nf = synthesize.normalize_finding(dict(f))
        if not synthesize.ID_RE.match(nf.get("id") or ""):
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
    file_list = "\n".join("- " + f for f in files) or "- (no files)"
    out_file = _verify_out_file(review_root, group, domain, stage)
    prompt = dispatch.render_prompt("domain-advisor.md", {
        "domain": domain, "group": group, "file_list": file_list,
        "findings": _render_findings(cell), "menu": _render_menu(bundle, domain),
        "run_id": manifest["run_id"], "stage": stage}, host)
    enforced = host == "claude"
    return {"id": "verify-%s-%s-%s" % (group, domain, stage),
            "agent": dispatch.registered_agent_name("domain-advisor.md") if enforced else None,
            "enforced": enforced, "model": None, "write_mode": "return",
            "prompt": prompt, "out_file": out_file}


def review_done(review_root, manifest):
    groups = _discovered_groups(review_root)
    if not groups:
        return True   # vacuous (no groups)
    return all(_cell_done(review_root, manifest, g, d)
               for g, _ in groups for d in _effective_domains(review_root, g))


def review_execute(review_root, manifest):
    host = manifest.get("host", "claude")
    bundle = ocrdb.load_bundle()
    # group tests come from the committed matrix (parse_groups tests field)
    matrix, _errors = load_committed_groups(review_root)
    for group, files in _discovered_groups(review_root):
        domains = _effective_domains(review_root, group)
        pending = [d for d in domains if not _cell_done(review_root, manifest, group, d)]
        if not pending:
            continue
        tests = sorted((matrix.get(group) or {}).get("tests") or [])
        entries = [_cell_entry(review_root, manifest, group, d, files, tests, host, bundle)
                   for d in pending]
        req = write_dispatch_request(review_root, manifest["run_id"], "review", group, entries)
        return PhaseResult(kind="checkpoint", checkpoint="review", group=group,
                           dispatch_request=req,
                           message="review: %d cell(s) for group %s" % (len(entries), group))
    return PhaseResult(kind="advanced", message="review: all cells complete")


def verify_execute(review_root, manifest):
    os.makedirs(_pano(review_root, "verdicts"), exist_ok=True)
    host = manifest.get("host", "claude")
    bundle = ocrdb.load_bundle()
    # PRIMARY round: one advisor per engaged (>= F_p), not-yet-verified cell,
    # streamed per group (first group with pending work emits, like review_execute).
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
            entries = [_verify_entry(review_root, manifest, group, d, files, c,
                                     host, bundle, "primary") for d, c in pending]
            req = write_dispatch_request(review_root, manifest["run_id"], "verify",
                                         group, entries)
            return PhaseResult(kind="checkpoint", checkpoint="verify", group=group,
                               dispatch_request=req,
                               message="verify: %d primary advisor(s) for group %s"
                               % (len(entries), group))
    # BACKUP round (Task 4 fills this branch).
    backup = _verify_backup_execute(review_root, manifest, host, bundle)
    if backup is not None:
        return backup
    return PhaseResult(kind="advanced", message="verify: all cells verified")


def verify_done(review_root, manifest):
    for group, _files in _discovered_groups(review_root):
        for domain in _effective_domains(review_root, group):
            cell = _load_cell_findings(review_root, manifest, group, domain)
            if cell is None or not score_gate.should_engage_primary(cell):
                continue
            if not _verify_cell_done(review_root, manifest, group, domain, "primary"):
                return False
    return _verify_backup_done(review_root, manifest)


def _verify_backup_execute(review_root, manifest, host, bundle):
    return None   # Task 4


def _verify_backup_done(review_root, manifest):
    return True   # Task 4


def synthesize_done(review_root, manifest):
    return _json_parses(_pano(review_root, "report.json"))


def synthesize_execute(review_root, manifest):
    findings = sorted(_glob.glob(_pano(review_root, "findings-*.json")))
    verdicts_dir = _pano(review_root, "verdicts")
    os.makedirs(verdicts_dir, exist_ok=True)   # empty in P3 (verify is a no-op)
    report = _pano(review_root, "report.json")
    flags = manifest.get("flags") or {}
    cmd = [sys.executable, _script("synthesize.py"),
           "--out", report,
           "--groups", _pano(review_root, "groups.json"),
           "--security", manifest.get("security_mode", "standard"),
           "--verdicts-dir", verdicts_dir]
    if (_load_json(_pano(review_root, "tools-ran.json")) or {}).get("ran"):
        cmd += ["--tools-dir", _pano(review_root, "tools")]
    for flag, key in (("--fail-on", "fail_on"), ("--severity", "severity"),
                      ("--gate-scope", "gate_scope")):
        if flags.get(key):
            cmd += [flag, str(flags[key])]
    diff_hunks = _pano(review_root, "diff-hunks.json")
    if os.path.isfile(diff_hunks):
        cmd += ["--diff-hunks", diff_hunks]
    cmd += findings
    proc = subprocess.run(cmd, cwd=review_root, capture_output=True, text=True,
                          env=_child_env())
    # A failing gate exits non-zero but still writes the report — that is a valid
    # outcome, not a driver error. Only an ABSENT report is a failure.
    if not _json_parses(report):
        raise DriverError("synthesize produced no report.json (rc=%s): %s"
                          % (proc.returncode, (proc.stderr or proc.stdout)[:400]))
    return PhaseResult(kind="advanced", message="synthesize: report.json written")


def capture_tree_baseline(review_root, runner=subprocess.run):
    """Snapshot the clean-tree baseline once (run start). No-op for a non-git
    target (returns None)."""
    baseline = _pano(review_root, "tree-baseline.txt")
    if os.path.exists(baseline):
        return baseline
    proc = runner(["git", "-C", review_root, "status", "--porcelain"],
                  capture_output=True, text=True)
    if proc.returncode != 0:
        return None
    os.makedirs(os.path.dirname(baseline), exist_ok=True)
    with open(baseline, "w", encoding="utf-8") as fh:
        fh.write(proc.stdout)
    return baseline


def _delta_path(line):
    """The current working-tree path from a porcelain v1 line 'XY <path>'.
    For a rename ('R  old -> new') the DESTINATION is what matters."""
    path = line[3:]
    if " -> " in path:
        path = path.split(" -> ", 1)[1]
    return path


def _tree_delta(review_root, runner):
    """NEW porcelain lines (vs. baseline) whose path is outside .panopticon/.
    Empty when there is no baseline (non-git) — nothing to compare."""
    try:
        with open(_pano(review_root, "tree-baseline.txt"), encoding="utf-8") as fh:
            baseline = set(fh.read().splitlines())
    except OSError:
        return []
    proc = runner(["git", "-C", review_root, "status", "--porcelain"],
                  capture_output=True, text=True)
    if proc.returncode != 0:
        return []
    new = set(proc.stdout.splitlines()) - baseline
    # NEW/changed porcelain lines whose FIRST PATH COMPONENT is not `.panopticon`
    # (a real boundary check: '.panopticon-evil.py' is NOT under .panopticon/).
    return sorted(line for line in new
                  if _delta_path(line).split("/", 1)[0] != ".panopticon")


def validate_done(review_root, manifest):
    data = _load_json(_pano(review_root, "validate.json"))
    return (isinstance(data, dict) and data.get("run_id") == manifest.get("run_id")
            and data.get("tree_clean") is True)


def validate_execute(review_root, manifest, runner=subprocess.run):
    delta = _tree_delta(review_root, runner)
    worktree = manifest.get("worktree")
    if worktree:
        diff_map.release_worktree(worktree, repo=review_root)   # tolerant
    _write_json(_pano(review_root, "validate.json"),
                {"run_id": manifest["run_id"], "tree_clean": not delta,
                 "unexpected_changes": delta})
    if delta:
        raise DriverError("validate: reviewer side effects outside .panopticon/: "
                          + "; ".join(delta[:10]))
    return PhaseResult(kind="advanced", message="validate: clean tree")


_DEFAULTS = {"host": "claude", "security": "standard"}

_RESET_GLOBS = ("groups.json", "coverage-*.json", "scout-*.json", "tools-ran.json",
                "validate.json",
                "report.json", "dispatch-request.json", "tree-baseline.txt",
                "verify-queue.json", "findings-*.json")

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
    tools = False if getattr(args, "no_tools", False) else (
        True if getattr(args, "tools", False) else None)
    return {"fail_on": args.fail_on, "severity": args.severity,
            "gate_scope": args.gate_scope, "diff_context": args.diff_context,
            "tools": tools,
            "include_fixtures": True if args.include_fixtures else None}


def _clear_run_artifacts(review_root):
    """Remove the manifest's derived artifacts for --reset. NEVER touches
    groups.yml (the committed matrix)."""
    pano = _pano(review_root)
    for pat in _RESET_GLOBS:
        for path in _glob.glob(os.path.join(pano, pat)):
            try:
                os.remove(path)
            except OSError:
                pass
    for sub in ("tools", "verdicts"):
        shutil.rmtree(os.path.join(pano, sub), ignore_errors=True)


def build_parser():
    parser = argparse.ArgumentParser(prog="driver")
    sub = parser.add_subparsers(dest="verb", required=True)
    for verb in ("run", "next"):
        p = sub.add_parser(verb)
        p.add_argument("target", nargs="?", default=".")
        p.add_argument("--host", default=None, choices=["claude", "generic"])
        p.add_argument("--security", default=None, choices=["standard", "redteam"])
        p.add_argument("--base", default=None)
        p.add_argument("--pr", type=int, default=None)
        p.add_argument("--reset", action="store_true")
        p.add_argument("--fail-on", default=None)
        p.add_argument("--severity", default=None)
        p.add_argument("--gate-scope", default=None)
        p.add_argument("--diff-context", type=int, default=None)
        p.add_argument("--tools", action="store_true")
        p.add_argument("--no-tools", action="store_true")
        p.add_argument("--include-fixtures", action="store_true")
    return parser


def _error_status(message):
    return {"status": "error", "phase": None, "checkpoint": None, "group": None,
            "dispatch_request": None, "advanced": [], "message": message}


def run(args, runner=subprocess.run, phases=PHASES):
    # C1: the driver's --pr resume is not implemented — diff_map.acquire_pr is
    # non-idempotent, so re-invocation re-acquires a fresh worktree, never finds
    # the prior manifest, loops re-emitting scout, and leaks worktrees. Refuse
    # loudly (before resolve_review_root, so acquire_pr is never called) rather
    # than ship a path that silently restarts. Use the 4.x pipeline for PR
    # reviews until driver --pr lands.
    if args.pr is not None:
        return _error_status(
            "driver --pr (PR review) is not supported yet — use the 4.x "
            "pipeline for PR reviews; driver --pr resume lands in a later "
            "5.0.x slice")
    review_root, worktree = resolve_review_root(args.target, base=args.base,
                                                pr=None, runner=runner)
    if args.reset:
        run_manifest.reset_run(review_root)
        _clear_run_artifacts(review_root)
    manifest = run_manifest.load_manifest(review_root)
    if manifest is None:
        # I1: no manifest means no prior run should count — clear any stale
        # derived artifacts so done()-predicates never resume on another run's
        # data (a lost/corrupt manifest, a partially-failed reset, or a
        # pre-existing 4.x groups.json).
        _clear_run_artifacts(review_root)
        manifest = run_manifest.build_manifest(
            target=args.target, review_root=review_root,
            host=args.host or _DEFAULTS["host"],
            security_mode=args.security or _DEFAULTS["security"],
            base=args.base, flags=_cli_flags(args), worktree=worktree)
        run_manifest.write_manifest(review_root, manifest)
    else:
        conflicts = run_manifest.conflicting_flags(
            manifest, host=args.host, security_mode=args.security,
            base=args.base, flags=_cli_flags(args))
        if conflicts:
            return _error_status("flag drift (use --reset to start over): "
                                 + "; ".join(conflicts))
    # I2: capture the clean-tree baseline unconditionally and BEFORE the engine
    # runs. Idempotent (returns the existing baseline if present) -> no-op on a
    # normal resume, but self-heals a baseline that a mid-first-run interrupt
    # left missing (which had silently disabled the clean-tree guard).
    capture_tree_baseline(review_root, runner=runner)
    try:
        return run_engine(review_root, manifest, phases)
    except DriverError as exc:
        return _error_status(str(exc))


def main(argv=None):
    args = build_parser().parse_args(argv)
    return emit_status(run(args))


if __name__ == "__main__":
    sys.exit(main())
