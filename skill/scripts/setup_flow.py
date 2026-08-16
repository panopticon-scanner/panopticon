#!/usr/bin/env python3
"""Setup/ingest flow: scaffold a target repo (.gitignore, config.json), render
the setup-scan brief, and ingest a setup-scan proposal into a groups.yml
draft. Extracted from orchestrator.py (P6.4) so the driver can call it
directly without going through the orchestrator CLI wrapper.
"""
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import plan_contract  # noqa: E402


def _orch():
    """Lazy handle to orchestrator's discovery primitives (transitional; P6.5
    relocates these out of orchestrator). Function-level import breaks the
    module-load cycle (orchestrator imports setup_flow at top level)."""
    import orchestrator
    return orchestrator


SETUP_GITIGNORE_ENTRIES = [
    ".panopticon/*",
    "!.panopticon/",
    "!.panopticon/groups.yml",
    ".claude/settings.local.json",
]


def _seed_groups_manifest(repo):
    """#485(1): write a STARTER committable groups.yml from the repo's
    top-level directory spine -- deterministic, never clobbers an existing
    manifest. Returns (path, created:bool, group_names)."""
    artifact_dir = plan_contract.artifact_root(repo)
    path = os.path.join(artifact_dir, "groups.yml")
    if os.path.isfile(path):
        names = list((_orch().load_catalog(repo) or {}).keys())
        return path, False, names
    files = _orch().discover_repo_files(repo)
    tops = sorted({p.split("/", 1)[0] for p in files
                   if "/" in p and not p.startswith(".")})
    os.makedirs(os.path.dirname(path), exist_ok=True)
    lines = ["# panopticon groups catalog -- seeded by --setup (#485).",
             "# gitignore-flavored globs; first matching group wins; edit and commit.",
             "groups:"]
    for t in tops:
        lines.append("  %s:" % t)
        lines.append("    match:")
        lines.append("      - %s/**" % t)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    return path, True, tops


seed_flat_manifest = _seed_groups_manifest


def _ensure_gitignore(repo):
    """#485(2): make sure run artifacts and the local hook settings never get
    committed. Appends only the MISSING entries; idempotent."""
    gi = os.path.join(repo, ".gitignore")
    try:
        existing = open(gi, encoding="utf-8").read()
    except OSError:
        existing = ""
    lines = existing.splitlines()
    migrated = False
    for index, line in enumerate(lines):
        if line.strip() == ".panopticon/":
            lines[index] = ".panopticon/*"
            migrated = True
    if migrated:
        existing = "\n".join(lines) + ("\n" if lines else "")
        with open(gi, "w", encoding="utf-8") as fh:
            fh.write(existing)
    have = {ln.strip() for ln in existing.splitlines()}
    added = [e for e in SETUP_GITIGNORE_ENTRIES if e not in have]
    if added:
        with open(gi, "a", encoding="utf-8") as fh:
            if existing and not existing.endswith("\n"):
                fh.write("\n")
            fh.write("# panopticon run artifacts (--setup #485)\n")
            for e in added:
                fh.write(e + "\n")
    return added


def _seed_config(repo):
    """#485/#486: scaffold .panopticon/config.json with the gh-account field
    (null = inherit ambient) when absent."""
    path = os.path.join(repo, ".panopticon", "config.json")
    if os.path.isfile(path):
        return path, False
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"gh_config_dir": None}, fh, indent=1)
        fh.write("\n")
    return path, True


def setup_readiness(repo, host=None, runner=subprocess.run, environ=None):
    """#485(3): the preflight. Returns a list of (name, ok, detail) checks.

    ok is True/False/None -- None means informational (not gating READY).
    Every failing check carries its fix in `detail`.
    """
    import dispatch  # noqa: E402 -- sibling flat import, same as diff_map
    env = environ if environ is not None else os.environ
    checks = []

    r = runner(["docker", "version"], capture_output=True, text=True)
    docker_ok = getattr(r, "returncode", 1) == 0
    checks.append(("docker", docker_ok,
                   "ok" if docker_ok else
                   "docker unavailable -- install/start Docker or run with --no-tools"))
    if docker_ok:
        r2 = runner(["docker", "image", "inspect", "panopticon-tools"],
                    capture_output=True, text=True)
        img_ok = getattr(r2, "returncode", 1) == 0
        checks.append(("tools-image", img_ok,
                       "ok" if img_ok else
                       "panopticon-tools image absent for this arch -- build/pull "
                       "it (see DEVELOPMENT.md; multi-arch: #461)"))

    git_marker = os.path.join(repo, ".git")
    root_ok = os.path.isdir(git_marker) or os.path.isfile(git_marker)
    checks.append(("target-root", root_ok,
                   "ok" if root_ok else
                   "cwd is not a git repo root -- run the pipeline from the "
                   "TARGET repo root (#483)"))

    nvd = bool(env.get("NVD_API_KEY")) or os.path.isfile(os.path.join(repo, ".env"))
    checks.append(("nvd-api-key", None,
                   "present" if nvd else
                   "absent -- dependency-check will be skipped/slow; export "
                   "NVD_API_KEY or add it to .env (never commit it)"))

    resolved_host = host or dispatch._detect_host()
    if resolved_host == "codex":
        codex = runner(["codex", "--version"], capture_output=True, text=True)
        codex_ok = getattr(codex, "returncode", 1) == 0
        checks.append(("codex-cli", codex_ok,
                       "ok" if codex_ok else
                       "Codex CLI unavailable -- install/authenticate `codex`; "
                       "role TOML profiles are optional for codex_exec"))
        checks.append(("enforced-shells", True,
                       "codex_exec enforces read-only execution; role TOML profiles optional"))
    else:
        reg_dir = dispatch._registration_dir(resolved_host, None)
        missing_shells = [role for role, rf in sorted(dispatch.ROLE_FILES.items())
                          if role in ("panel_review", "lens_sweep")
                          and not dispatch._is_registered(reg_dir, rf, resolved_host)]
        checks.append(("enforced-shells", not missing_shells,
                       "ok" if not missing_shells else
                       "unregistered reviewer shell(s): %s -- run python3 "
                       "skill/scripts/dispatch.py --emit-host-agents <host> and "
                       "start a fresh session" % ", ".join(missing_shells)))

    try:
        catalog = _matrix_catalog(repo) or {}
    except Exception:
        catalog = {}
    if catalog:
        empty = [name for name, g in catalog.items() if not g.get("match")]
        checks.append(("groups-manifest", not empty,
                       "%d group(s)" % len(catalog) if not empty else
                       "group(s) with no match patterns: %s" % ", ".join(map(str, empty))))
    else:
        checks.append(("groups-manifest", None,
                       "no committable manifest yet -- --setup seeds one; "
                       "files fall back to ._N chunks until you commit it"))
    return checks


readiness = setup_readiness


_SKILL_DATA = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
_VOCAB_PATH = os.path.join(_SKILL_DATA, "capability_vocabulary.yml")
_AFFINITY_PATH = os.path.join(_SKILL_DATA, "capability_affinity.yml")


def _repo_spine_summary(repo):
    """A compact, deterministic spine the scan brief hands the agent as a
    starting point (the agent still explores read-only for itself)."""
    files = _orch().discover_repo_files(repo)
    tops = sorted({p.split("/", 1)[0] for p in files if "/" in p})
    manifests = sorted({os.path.basename(p) for p in files
                        if os.path.basename(p) in (
                            "pyproject.toml", "package.json", "go.mod",
                            "Cargo.toml", "pom.xml", "requirements.txt")})
    return "top-level: %s\nmanifests: %s" % (
        ", ".join(tops) or "(none)", ", ".join(manifests) or "(none)")


def render_scan_brief(repo, vocabulary):
    """Render the setup-scan agent brief to .panopticon/setup-scan-brief.md."""
    import dispatch
    brief = dispatch.render_prompt("setup-scan.md", {
        "repo_spine": _repo_spine_summary(repo),
        "vocabulary_labels": ", ".join(vocabulary["names"]),
    })
    path = os.path.join(plan_contract.artifact_root(repo), "setup-scan-brief.md")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(brief)
    return path


def _committed_matrix(repo):
    """Committed groups.yml as serializable {name: {match, tests, panels, exclude}},
    preserving committed field ORDER verbatim (never-clobber is byte-faithful).
    Empty when none is committed (first run -> adopt-all)."""
    path = os.path.join(repo, ".panopticon", "groups.yml")
    if not os.path.isfile(path):
        return {}
    import yaml
    import groups_schema
    with open(path, encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    raw = data.get("groups") or {}
    if isinstance(raw, list):  # legacy list form (Task 5)
        raw = {g.get("name"): g for g in raw
               if isinstance(g, dict) and g.get("name")}
    # Validate only; errors are non-fatal on read (disclosed, not blocking) --
    # the raw-order bodies below are returned regardless of what parse_groups
    # finds.
    _, errs = groups_schema.parse_groups({"groups": raw})
    for e in errs:
        print("committed groups.yml: %s" % e, file=sys.stderr)
    out = {}
    for name, body in raw.items():
        body = body or {}
        out[name] = {
            "match": list(body.get("match") or []),
            "tests": list(body.get("tests") or []),
            "panels": list(body.get("panels") or []),
            "exclude": list(body.get("exclude") or []),
        }
    return out


committed_matrix = _committed_matrix


def _matrix_catalog(repo):
    """The committed matrix as parse_groups-NORMALIZED groups for --repo-scan /
    readiness: {name: {match: [...], tests, floor, exclude}} with `match`
    VALIDATED (a scalar/invalid match normalizes to [] -- never char-split).
    Errors are disclosed (stderr), not fatal (the driver's load_committed_groups
    gates fatally upstream). Empty {} when no groups.yml is committed."""
    path = os.path.join(repo, ".panopticon", "groups.yml")
    if not os.path.isfile(path):
        return {}
    import yaml
    import groups_schema
    try:
        with open(path, encoding="utf-8") as fh:
            doc = yaml.safe_load(fh) or {}
    except (OSError, yaml.YAMLError) as e:
        print("groups.yml unreadable: %s" % e, file=sys.stderr)
        return {}
    groups, errs = groups_schema.parse_groups(doc if isinstance(doc, dict) else {})
    for e in errs:
        print("committed groups.yml: %s" % e, file=sys.stderr)
    return groups


matrix_catalog = _matrix_catalog


def provision(repo):
    """Scaffold .gitignore entries + config.json (idempotent). Returns a summary."""
    added = _ensure_gitignore(repo)
    cfg, created = _seed_config(repo)
    return {"gitignore_added": added, "config_path": cfg, "config_created": created}


def load_bundled_vocabulary(vocabulary_path=None):
    """Load the bundled capability vocabulary. Returns (vocab, present: bool).
    present is False when the file is absent or the parse yields no names."""
    import setup_proposal as sp
    vpath = vocabulary_path or _VOCAB_PATH
    if not os.path.isfile(vpath):
        return {"names": []}, False
    vocab, verr = sp.load_vocabulary(vpath)
    if verr or not vocab.get("names"):
        return {"names": []}, False
    return vocab, True


def ingest_proposal(repo=".", proposal_path=None):
    """Ingest a setup-scan proposal -> assemble (affinity floors) -> additive-merge
    vs committed groups.yml -> write .panopticon/groups.yml.draft. Returns a
    structured result (see plan). Never clobbers a committed groups.yml; no draft
    is written on any failure. No printing."""
    import setup_proposal as sp
    if not (os.path.isfile(_VOCAB_PATH) and os.path.isfile(_AFFINITY_PATH)):
        return {"ok": False, "errors": [
            "data error: bundled vocabulary/affinity data is missing "
            "(expected %s, %s)" % (_VOCAB_PATH, _AFFINITY_PATH)]}
    vocab, verr = sp.load_vocabulary(_VOCAB_PATH)
    affinity, aerr = sp.load_affinity(_AFFINITY_PATH, vocab)
    if verr or aerr:
        return {"ok": False, "errors": ["data error: %s" % e for e in verr + aerr]}
    proposal_path = proposal_path or os.path.join(
        plan_contract.artifact_root(repo), "setup-proposal.json")
    try:
        with open(proposal_path, encoding="utf-8") as fh:
            proposal = json.load(fh)
    except (OSError, ValueError) as e:
        return {"ok": False, "errors": [
            "cannot read proposal %s: %s" % (proposal_path, e)]}
    assembled, disclosure = sp.assemble(proposal, vocab, affinity)
    if assembled is None:
        return {"ok": False, "errors": (
            ["proposal rejected -- no draft written:"]
            + ["  - %s" % e for e in disclosure["errors"]])}
    committed = committed_matrix(repo)
    leftovers = _orch().assign_by_catalog(
        _orch().discover_repo_files(repo),
        {n: {"match": b["match"]} for n, b in committed.items()})[1]
    claims = _orch().assign_by_catalog(
        leftovers, {n: {"match": b["match"]} for n, b in assembled.items()})[0]
    merged, diff = sp.merge_additive(committed, assembled, claims)
    draft = os.path.join(plan_contract.artifact_root(repo), "groups.yml.draft")
    with open(draft, "w", encoding="utf-8") as fh:
        fh.write(sp.dump_groups_yaml(merged))
    return {"ok": True, "draft": draft, "diff": diff, "disclosure": disclosure}
