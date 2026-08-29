#!/usr/bin/env python3
"""Setup/ingest flow: scaffold a target repo (.gitignore, config.json), render
the setup-scan brief, and ingest a setup-scan proposal into a groups.yml
draft. Extracted from orchestrator.py (P6.4) so the driver can call it
directly without going through the orchestrator CLI wrapper.
"""
import json
import os
import re
import subprocess
import sys

import yaml

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import plan_contract  # noqa: E402
import discovery  # noqa: E402  (P6.5 Slice A: discovery primitives, moved off orchestrator)


# #1135: the committable block ignores run artifacts under .panopticon/ while
# keeping groups.yml trackable. Applied ONLY to a repo that does not already
# ignore the .panopticon DIRECTORY outright -- see _ensure_gitignore.
_PANOPTICON_COMMITTABLE_ENTRIES = [
    ".panopticon/*",
    "!.panopticon/",
    "!.panopticon/groups.yml",
]
_ALWAYS_IGNORE_ENTRIES = [".claude/settings.local.json"]
# Un-negatable blanket directory ignores: making groups.yml committable under
# any of these would require REWRITING the line (git cannot re-include a file
# whose parent directory is excluded). We leave them untouched (#1135). The
# `.panopticon/*` form is NOT here -- it is committable-compatible, so missing
# negations are simply appended.
_PANOPTICON_DIR_BLANKET = {
    ".panopticon", ".panopticon/", "/.panopticon", "/.panopticon/",
    # #run7 ARC-A2B: a `**/`-prefixed blanket also excludes the directory, so
    # git cannot re-include groups.yml out of it -- treat it as un-negatable too
    # (else provision() would append a committable block that can't take effect
    # and spuriously rewrites .gitignore).
    "**/.panopticon", "**/.panopticon/",
}


def _seed_groups_manifest(repo):
    """#485(1): write a STARTER committable groups.yml from the repo's
    top-level directory spine -- deterministic, never clobbers an existing
    manifest. Returns (path, created:bool, group_names)."""
    artifact_dir = plan_contract.artifact_root(repo)
    path = os.path.join(artifact_dir, "groups.yml")
    if os.path.isfile(path):
        names = list((discovery.load_catalog(repo) or {}).keys())
        return path, False, names
    import groups_schema  # noqa: E402
    files = discovery.discover_repo_files(repo)
    tops = sorted({p.split("/", 1)[0] for p in files
                   if "/" in p and not p.startswith(".")})
    # #1108: a top-level directory name is untrusted target content -- it may
    # legally contain ':', '#', quotes, even embedded newlines. Build the
    # manifest as a data structure, drop any name the schema rejects (injection
    # chars, '..', control chars), and serialize via yaml.safe_dump. Never
    # hand-format untrusted names into YAML text: the emitted file is the
    # authoritative routing config consumed in this same setup run.
    candidate = {t: {"match": ["%s/**" % t]} for t in tops}
    parsed, _errors = groups_schema.parse_groups({"groups": candidate})
    valid = {name: {"match": candidate[name]["match"]} for name in parsed}
    body = yaml.safe_dump({"groups": valid}, sort_keys=True,
                          default_flow_style=False, allow_unicode=True)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    header = ("# panopticon groups catalog -- seeded by --setup (#485).\n"
              "# gitignore-flavored globs; first matching group wins; edit and commit.\n")
    # #run7 COD-F1B: create atomically. The isfile() guard above is a fast path,
    # not a lock -- O_EXCL closes the check-then-truncate TOCTOU so a concurrent
    # seed can never clobber a manifest that appeared after the check. A racing
    # loser observes FileExistsError and reports the existing manifest (created
    # False) rather than overwriting it.
    try:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
    except FileExistsError:
        names = list((discovery.load_catalog(repo) or {}).keys())
        return path, False, names
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(header + body)
    return path, True, list(valid)


seed_groups_manifest = _seed_groups_manifest
seed_flat_manifest = _seed_groups_manifest


def _ensure_gitignore(repo):
    """#485(2)/#1135: make sure run artifacts and the local hook settings never
    get committed, WITHOUT ever rewriting existing .gitignore content -- only
    missing entries are appended.

    Returns (added, groups_yml_committable). If the repo already blanket-ignores
    the .panopticon DIRECTORY (``_PANOPTICON_DIR_BLANKET``), that ignore is left
    exactly as-is: the committable ``.panopticon/*`` + negation block is NOT
    applied (applying it used to migrate the line in place -- a spurious
    working-tree modification that also re-exposed the directory, #1135). There
    groups.yml stays ignored -- still readable by the driver, committable once
    with ``git add -f``. A fresh repo (or one already using the
    committable-compatible ``.panopticon/*`` form) gets the full block; any
    already-present entry is skipped so re-runs are true no-ops."""
    gi = os.path.join(repo, ".gitignore")
    try:
        with open(gi, encoding="utf-8") as fh:
            existing = fh.read()
    except OSError:
        existing = ""
    have = {ln.strip() for ln in existing.splitlines()}
    dir_blanket = bool(have & _PANOPTICON_DIR_BLANKET)
    wanted = list(_ALWAYS_IGNORE_ENTRIES)
    if not dir_blanket:
        wanted = _PANOPTICON_COMMITTABLE_ENTRIES + wanted
    added = [e for e in wanted if e not in have]
    if added:
        with open(gi, "a", encoding="utf-8") as fh:
            if existing and not existing.endswith("\n"):
                fh.write("\n")
            fh.write("# panopticon run artifacts (--setup #485)\n")
            for e in added:
                fh.write(e + "\n")
    groups_yml_committable = (not dir_blanket) or (
        "!.panopticon/groups.yml" in have)
    return added, groups_yml_committable


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


# Hard bound on each readiness probe so an installed-but-hung tool (Docker
# Desktop stuck starting, a wedged daemon socket, a stalled codex CLI) cannot
# freeze the preflight (#1106). A timeout or a missing binary yields None, which
# the getattr(..., "returncode", 1) checks below read as a failed probe.
_PROBE_TIMEOUT = 30


def _probe(runner, cmd):
    try:
        return runner(cmd, capture_output=True, text=True, timeout=_PROBE_TIMEOUT)
    except (subprocess.TimeoutExpired, OSError):
        return None


def _check_docker(runner):
    checks = []
    r = _probe(runner, ["docker", "version"])
    docker_ok = getattr(r, "returncode", 1) == 0
    checks.append(("docker", docker_ok,
                   "ok" if docker_ok else
                   "docker unavailable -- install/start Docker or run with --no-tools"))
    if docker_ok:
        r2 = _probe(runner, ["docker", "image", "inspect", "panopticon-tools"])
        img_ok = getattr(r2, "returncode", 1) == 0
        checks.append(("tools-image", img_ok,
                       "ok" if img_ok else
                       "panopticon-tools image absent for this arch -- build/pull "
                       "it (see DEVELOPMENT.md; multi-arch: #461)"))
    return checks


def _check_git_root(repo):
    git_marker = os.path.join(repo, ".git")
    root_ok = os.path.isdir(git_marker) or os.path.isfile(git_marker)
    return ("target-root", root_ok,
            "ok" if root_ok else
            "cwd is not a git repo root -- run the pipeline from the "
            "TARGET repo root (#483)")

def _check_nvd_key(repo, env):
    nvd_in_file = False
    env_path = os.path.join(repo, ".env")
    if os.path.isfile(env_path):
        try:
            with open(env_path, "r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if line.startswith("NVD_API_KEY=") and len(line.split("=", 1)[1].strip()) > 0:
                        nvd_in_file = True
                        break
        except OSError:
            pass
    nvd = bool(env.get("NVD_API_KEY")) or nvd_in_file
    return ("nvd-api-key", None,
            "present" if nvd else
            "absent -- dependency-check will be skipped/slow; export "
            "NVD_API_KEY or add it to .env (never commit it)")


def _check_host_shells(host, runner):
    import dispatch  # noqa: E402
    resolved_host = host or dispatch._detect_host()
    checks = []
    if resolved_host == "codex":
        codex = _probe(runner, ["codex", "--version"])
        codex_ok = getattr(codex, "returncode", 1) == 0
        checks.append(("codex-cli", codex_ok,
                       "ok" if codex_ok else
                       "Codex CLI unavailable -- install/authenticate `codex`; "
                       "role TOML profiles are optional for codex_exec"))
        checks.append(("enforced-shells", True,
                       "codex_exec enforces read-only execution; role TOML profiles optional"))
    elif resolved_host == "generic":
        checks.append(("enforced-shells", None,
                       "generic host runs reviewers unenforced (prompt-advisory "
                       "tool policy); no shell registration to verify"))
    else:
        reg_dir = dispatch._registration_dir(resolved_host, None)
        _driver_roles = ("scout", "domain_panel", "domain_advisor")
        # #run7 ARC-A4C: this is a hand-maintained shadow of the ACTIVE driver
        # roles. If a role is renamed/removed in dispatch.ROLE_FILES, the filter
        # below would silently drop its shell from the readiness check. Trip
        # loudly instead so the drift is caught at the source.
        _unknown_roles = [r for r in _driver_roles if r not in dispatch.ROLE_FILES]
        if _unknown_roles:
            raise RuntimeError(
                "setup_flow._driver_roles out of sync with dispatch.ROLE_FILES: %s"
                % ", ".join(_unknown_roles))
        missing_shells = [role for role, rf in sorted(dispatch.ROLE_FILES.items())
                          if role in _driver_roles
                          and not dispatch._is_registered(reg_dir, rf, resolved_host)]
        checks.append(("enforced-shells", not missing_shells,
                       "ok" if not missing_shells else
                       "unregistered reviewer shell(s): %s -- run python3 "
                       "skill/scripts/dispatch.py --emit-host-agents <host> and "
                       "start a fresh session" % ", ".join(missing_shells)))
    return checks


def _check_groups_manifest(repo):
    path = os.path.join(repo, ".panopticon", "groups.yml")
    if not os.path.exists(path):
        return ("groups-manifest", None,
                "no committable manifest yet -- --setup seeds one; "
                "files fall back to ._N chunks until you commit it")
    try:
        with open(path, encoding="utf-8") as fh:
            yaml.safe_load(fh)
    except (OSError, yaml.YAMLError) as exc:
        return ("groups-manifest", False,
                "corrupt groups.yml manifest: %s" % exc)
    catalog = discovery._matrix_catalog(repo) or {}
    empty = [name for name, g in catalog.items() if not g.get("match")]
    return ("groups-manifest", not empty,
            "%d group(s)" % len(catalog) if not empty else
            "group(s) with no match patterns: %s" % ", ".join(map(str, empty)))


def setup_readiness(repo, host=None, runner=subprocess.run, environ=None):
    """#485(3): the preflight. Returns a list of (name, ok, detail) checks.

    ok is True/False/None -- None means informational (not gating READY).
    Every failing check carries its fix in `detail`.
    """
    env = environ if environ is not None else os.environ
    checks = []
    checks.extend(_check_docker(runner))
    checks.append(_check_git_root(repo))
    checks.append(_check_nvd_key(repo, env))
    checks.extend(_check_host_shells(host, runner))
    checks.append(_check_groups_manifest(repo))
    return checks


readiness = setup_readiness


_SKILL_DATA = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
_VOCAB_PATH = os.path.join(_SKILL_DATA, "capability_vocabulary.yml")
_AFFINITY_PATH = os.path.join(_SKILL_DATA, "capability_affinity.yml")


def _sanitize_spine_token(token):
    s = re.sub(r"[\x00-\x1f\x7f-\x9f`]", "", str(token or "")).strip()
    return repr(s) if any(c in s for c in " \n\r\t\"'") else s


def _repo_spine_summary(repo):
    """A compact, deterministic spine the scan brief hands the agent as a
    starting point (the agent still explores read-only for itself). Sanitizes
    untrusted repo paths against prompt injection (#1120)."""
    files = discovery.discover_repo_files(repo)
    tops = sorted({_sanitize_spine_token(p.split("/", 1)[0]) for p in files if "/" in p})
    manifests = sorted({_sanitize_spine_token(os.path.basename(p)) for p in files
                        if os.path.basename(p) in (
                            "pyproject.toml", "package.json", "go.mod",
                            "Cargo.toml", "pom.xml", "requirements.txt")})
    return "top-level: %s\nmanifests: %s" % (
        ", ".join(tops) or "(none)", ", ".join(manifests) or "(none)")


def _format_vocabulary_hints(vocabulary):
    """Render vocabulary['hints'] ({name: [globs]}) as one line per label
    that has hints: '- <name>: <comma-joined globs>'. Labels with no hints
    are omitted. These are non-authoritative starting suggestions (#2-data
    spec §2.1/§10.6) -- setup-scan.md labels them as such to the classifier."""
    hints = vocabulary.get("hints") or {}
    lines = []
    for name in vocabulary.get("names", []):
        globs = hints.get(name) or []
        if globs:
            lines.append("- %s: %s" % (name, ", ".join(globs)))
    return "\n".join(lines)


def render_scan_brief(repo, vocabulary):
    """Render the setup-scan agent brief to .panopticon/setup-scan-brief.md."""
    import dispatch
    brief = dispatch.render_prompt("setup-scan.md", {
        "repo_spine": _repo_spine_summary(repo),
        "vocabulary_labels": ", ".join(vocabulary["names"]),
        "vocabulary_hints": _format_vocabulary_hints(vocabulary),
    })
    path = os.path.join(plan_contract.artifact_root(repo), "setup-scan-brief.md")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(brief)
    return path


# _committed_matrix/_matrix_catalog RELOCATED to discovery.py (P6.5 Slice A):
# they read .panopticon/groups.yml via yaml + groups_schema.parse_groups and
# depend on nothing else from setup_flow. Aliases kept so existing callers
# (setup_flow.committed_matrix / setup_flow.matrix_catalog) still resolve.
committed_matrix = discovery._committed_matrix
matrix_catalog = discovery._matrix_catalog


def provision(repo):
    """Scaffold .gitignore entries + config.json (idempotent). Returns a summary."""
    added, groups_yml_committable = _ensure_gitignore(repo)
    cfg, created = _seed_config(repo)
    summary = {"gitignore_added": added, "config_path": cfg,
               "config_created": created,
               "groups_yml_committable": groups_yml_committable}
    if not groups_yml_committable:
        # #1135: we left an existing blanket .panopticon ignore untouched, so
        # groups.yml is not trackable until the user force-adds it once.
        summary["gitignore_note"] = (
            "existing .gitignore already ignores the .panopticon/ directory; left "
            "it untouched (#1135). Commit the capability manifest with "
            "`git add -f .panopticon/groups.yml`.")
    return summary


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


# #1107: hard cap on the untrusted proposal file (a scanned repo can ship
# .panopticon/setup-proposal.json directly). Bounds the bytes read before parse.
_MAX_PROPOSAL_BYTES = 1_048_576   # 1 MiB -- far above any legitimate proposal


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
        # #run10 COD-F1B: the cap used to be os.path.getsize() and then a separate
        # unbounded open()+json.load() -- a stat-then-open pair. The bytes actually
        # read were never bounded: a proposal that grows (or a path swapped) between
        # the two calls, or any file whose size cannot be trusted from a stat (a
        # FIFO/proc-like path reports 0), was slurped whole. The target repo supplies
        # this file, so bound the READ itself: take cap+1 bytes and refuse if the
        # extra byte materialized -- the cap is then a property of what we consumed,
        # not of a prior observation.
        with open(proposal_path, "rb") as fh:
            raw = fh.read(_MAX_PROPOSAL_BYTES + 1)
        if len(raw) > _MAX_PROPOSAL_BYTES:
            return {"ok": False, "errors": [
                "proposal %s exceeds the %d-byte cap -- refusing to ingest"
                % (proposal_path, _MAX_PROPOSAL_BYTES)]}
        proposal = json.loads(raw.decode("utf-8"))
    except (OSError, ValueError) as e:
        return {"ok": False, "errors": [
            "cannot read proposal %s: %s" % (proposal_path, e)]}
    assembled, disclosure = sp.assemble(proposal, vocab, affinity)
    if assembled is None:
        return {"ok": False, "errors": (
            ["proposal rejected -- no draft written:"]
            + ["  - %s" % e for e in disclosure["errors"]])}
    committed = committed_matrix(repo)
    leftovers = discovery.assign_by_catalog(
        discovery.discover_repo_files(repo),
        {n: {"match": b["match"]} for n, b in committed.items()})[1]
    claims = discovery.assign_by_catalog(
        leftovers, {n: {"match": b["match"]} for n, b in assembled.items()})[0]
    merged, diff = sp.merge_additive(committed, assembled, claims)
    draft = os.path.join(plan_contract.artifact_root(repo), "groups.yml.draft")
    with open(draft, "w", encoding="utf-8") as fh:
        fh.write(sp.dump_groups_yaml(merged))
    return {"ok": True, "draft": draft, "diff": diff, "disclosure": disclosure}
