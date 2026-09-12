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
import grouping_engine  # noqa: E402  (5.2: stage-3 size policy + setup report)
import coverage_model  # noqa: E402  (5.2: the surfaces enum for the brief)
from scripts import hosts  # noqa: E402  (#1344 F2: host readiness reads the registry)
from scripts import host_probes  # noqa: E402  (#1344 F3b: readiness probes live posture)
from scripts import host_disclosure  # noqa: E402  (#1344 F3b: one voice for the posture)


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

# #1509: the set above enumerates SPELLINGS, and it missed the glob form
# `.panopticon*/` -- which this project's own .gitignore uses deliberately, so a
# preserved run renamed `.panopticon.prev-<stamp>` stays ignored. Setup then read
# the repo as un-blanketed, appended the committable block, and its
# `!.panopticon/` negation RE-EXPOSED groups.yml: the #1135 failure mode
# recurring for a spelling nobody had listed, silently flipping the repo's policy
# from "groups.yml is local" to "groups.yml is committable".
#
# Enumerating one more spelling would just move the goalposts. `git check-ignore`
# is authoritative and understands every form, so it decides whenever the target
# is a checkout; this pattern is the fallback for targets that are not.
_PANOPTICON_BLANKET_RE = re.compile(r"^/?(\*\*/)?\.panopticon\*?/?$")


# The forms that ignore only the directory's CONTENTS. A negation can still
# re-include a file under these, so they are committable-compatible.
_CONTENTS_FORM_RE = re.compile(r"^/?(\*\*/)?\.panopticon/\*{1,2}$")

_CHECK_IGNORE_LINE = re.compile(r"^(.*):(\d+):(.*)$")

# The roles the DRIVER dispatches and therefore needs registered shells for.
# #1606: was a hand-kept three-tuple shadowing host_probes.DRIVER_ROLES and
# leaving `advisor` unchecked; now the same object, one source of truth
# (dispatch.ROLE_FILES, via host_probes -- dispatch itself is imported lazily
# below, script-style).
_driver_roles = host_probes.DRIVER_ROLES


def _git_blanket_pattern(repo, runner=subprocess.run):
    """The .gitignore pattern git says ignores `.panopticon/groups.yml`.

    Returns the pattern string, "" when git says nothing ignores it, or None
    when git could not answer (not a checkout, git missing, unexpected exit) --
    None falls back to pattern matching rather than guessing.

    Asks about a FILE INSIDE the directory, never the directory itself.
    Measured: `check-ignore -- .panopticon` answers 0 in a repo with no commits
    and 1 in the same repo once it has one, for the identical `.panopticon*/`
    pattern -- so the directory query cannot be trusted. The file query is
    stable, and git's answer names the pattern that actually applies, which is
    what decides negatability."""
    try:
        r = runner(["git", "-C", repo, "check-ignore", "-v", "--",
                    os.path.join(".panopticon", "groups.yml")],
                   capture_output=True, text=True, timeout=10)
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
    already-present entry is skipped so re-runs are true no-ops.

    #1509: "already blanket-ignores" is decided by ``git check-ignore`` where
    possible, not by matching spellings -- the literal set missed the glob form
    and its negation then re-exposed groups.yml."""
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


def _check_host_shells(host, runner, repo_root=None):
    """Report what this host's registration actually looks like, and -- for a
    host with a real shell format -- what its capability posture proves right
    now.

    Rebuilt on the registry (#1344 F2). Previously this function asserted
    ("enforced-shells", True, "codex_exec enforces read-only execution") for
    codex -- an execution path that had been removed, for a host --host does
    not accept -- and sent gemini into the shell-registration branch, whose
    remedy line told the operator to run `--emit-host-agents gemini`, which
    raises. Neither is expressible now: a host either declares a shell format
    and gets checked, or declares none and says so.

    `ok=None` means NOT APPLICABLE, not "failed". setup's renderer already
    distinguishes the three.

    `repo_root` defaults to None on purpose: `_check_host_shells` has call
    sites that cannot supply it (a module-level fixture in
    tests/phases/test_setup.py evaluates this at collection time, before any
    mock is in place) and the brief's own fixture-driven tests call this with
    just (host, runner). A missing repo_root is not a silent guess -- it is
    handed straight to `host_probes.run_probes` as `review_root`, and a probe
    that cannot resolve a real tree (`probe_shadow_shells` joins it with a
    relative path) raises, which the try/except below turns into an honest
    "could not be probed" rather than a crash. The one production caller,
    `setup_readiness`, always has a real repo and passes it.
    """
    import dispatch  # noqa: E402
    resolved_host = host or dispatch._detect_host()
    row = hosts.spec(resolved_host)
    checks = []

    if row is None:
        checks.append(("enforced-shells", False,
                       "unknown host %r -- known hosts are %s"
                       % (resolved_host, "|".join(hosts.known_hosts()))))
        return checks

    # The one check the old codex branch actually performed, kept. F3 moves
    # this to a registry `probes` field; until then it is a named exception
    # with a reason, not a stray host test. `codex` is reachable here even
    # though `--host codex` is refused, because `_detect_host()` can return it
    # from a live Codex session.
    if resolved_host == "codex":
        codex = _probe(runner, ["codex", "--version"])
        codex_ok = getattr(codex, "returncode", 1) == 0
        checks.append(("codex-cli", codex_ok,
                       "ok" if codex_ok else
                       "Codex CLI unavailable -- install/authenticate `codex`"))

    # Registering no enforcement shells is a fact about ONE check, not an
    # exemption from disclosure. This used to `return checks` here, so gemini
    # and generic -- the two driver-selectable hosts that claim NOTHING, and
    # therefore the two whose whole story is five-of-five-unproven -- left
    # readiness with a single line naming the host and no capability, no probe
    # and no remedy. 5.1 names no shell-less exemption. Control falls through
    # to the probing block below instead, which is written once and runs for
    # every known host.
    if not row.shell_format:
        checks.append(("enforced-shells", None,
                       "%s registers no enforcement shells; reviewers run "
                       "with a prompt-advisory tool policy" % resolved_host))
    else:
        reg_dir = dispatch._registration_dir(resolved_host, None)
        # (#run7 ARC-A4C's out-of-sync trip is gone: _driver_roles derives from
        # dispatch.ROLE_FILES, so it cannot name a role that does not exist.)
        missing_shells = [role for role, rf in sorted(dispatch.ROLE_FILES.items())
                          if role in _driver_roles
                          and not dispatch._is_registered(reg_dir, rf, resolved_host)]
        checks.append(("enforced-shells", not missing_shells,
                       "ok" if not missing_shells else
                       "unregistered reviewer shell(s): %s -- run python3 "
                       "skill/scripts/dispatch.py --emit-host-agents %s and start "
                       "a fresh session"
                       % (", ".join(missing_shells), resolved_host)))

    # 5.1 surface 4. `driver setup` has no run directory, so there is no
    # artifact to read -- readiness PROBES. That is the point: this is where
    # an operator looks before a run to find out what to fix, and the remedy
    # is the reason the line exists at all.
    try:
        fresh = host_probes.run_probes(resolved_host, repo_root)
    except Exception as exc:            # noqa: BLE001 -- readiness never crashes
        checks.append(("host-capabilities", None,
                       "posture could not be probed: %s" % exc))
        return checks
    # THREE outcomes, read off host_disclosure's own contract rather than
    # re-derived from `lines()`. `lines()` returns [] for two different
    # reasons -- everything is proven, and the envelope is unreadable -- and
    # `if not gaps: ALL_PROVEN` collapsed them, reporting a probe that produced
    # nothing as a PASSING check that everything was verified. That is the
    # exact inversion headline()'s docstring exists to forbid.
    head = host_disclosure.headline(fresh)
    gaps = host_disclosure.lines(fresh)
    if head == host_disclosure.ALL_PROVEN:
        checks.append(("host-capabilities", True, head))
        return checks
    checks.append(("host-capabilities", None, head))
    if head == host_disclosure.NO_EVIDENCE:
        # Nothing was measured, so there is no per-capability verdict to
        # report. Enumerating five capabilities against an envelope that
        # yielded no posture would print five lines that name a capability and
        # nothing else -- "unenforced" alone, which 5.1 calls a mood.
        return checks
    # Past the NO_EVIDENCE branch `fresh` is necessarily a dict with a string
    # host and a dict `capabilities` -- headline() would have returned
    # NO_EVIDENCE otherwise -- so this read cannot raise.
    posture = hosts.posture(resolved_host, fresh.get("capabilities"))
    for capability in hosts.unproven(posture):
        # The state comes off the POSTURE map, not off raw `capabilities`: the
        # masked posture is the one every other surface renders, and a second
        # derivation of one fact is free to drift from it.
        #
        # refuted is a fault the operator can act on; unknown is NOT
        # APPLICABLE -- read_scope_confined is unknown on every host today and
        # must not report as a failure nobody can clear.
        ok = False if posture[capability] == hosts.REFUTED else None
        line = [g for g in gaps if g.startswith(capability)]
        checks.append(("host-capability:" + capability, ok,
                       line[0] if line else capability))
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
    checks.extend(_check_host_shells(host, runner, repo))
    checks.append(_check_groups_manifest(repo))
    return checks


readiness = setup_readiness


_SKILL_DATA = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
_VOCAB_PATH = os.path.join(_SKILL_DATA, "capability_vocabulary.yml")
_AFFINITY_PATH = os.path.join(_SKILL_DATA, "capability_affinity.yml")
_LAYERS_PATH = os.path.join(_SKILL_DATA, "layer_vocabulary.yml")


def _sanitize_spine_token(token):
    s = re.sub(r"[\x00-\x1f\x7f-\x9f`]", "", str(token or "")).strip()
    return repr(s) if any(c in s for c in " \n\r\t\"'") else s


# --- 5.2 stage 1: the spine (spec §5.1) -------------------------------------
# Deterministic, bounded, sanitized (#1120). Everything the setup-scan agent is
# told about the repo before it explores for itself comes from here, and the
# same numbers (cap, ceiling, code_files) are what stage 3 applies -- the spine
# is persisted to .panopticon/setup-spine.json so the two cannot drift.

_SPINE_FILE = "setup-spine.json"
_MAX_TREE_ROWS = 80            # depth-2 directory rows rendered into the brief
_MAX_TEST_TREE_ROWS = 20
_MAX_MANIFESTS = 20
_MAX_LANGUAGES = 6
_MAX_MANIFEST_BYTES = 65536    # bounded read of an untrusted manifest
_EXT_LANG = {
    ".py": "Python", ".go": "Go", ".rs": "Rust", ".js": "JavaScript",
    ".jsx": "JavaScript", ".mjs": "JavaScript", ".cjs": "JavaScript",
    ".ts": "TypeScript", ".tsx": "TypeScript", ".rb": "Ruby", ".java": "Java",
    ".kt": "Kotlin", ".kts": "Kotlin", ".cs": "C#", ".php": "PHP", ".c": "C",
    ".h": "C", ".cpp": "C++", ".cc": "C++", ".cxx": "C++", ".hpp": "C++",
    ".swift": "Swift", ".scala": "Scala", ".ex": "Elixir", ".exs": "Elixir",
    ".erl": "Erlang", ".hs": "Haskell", ".dart": "Dart", ".lua": "Lua",
    ".sh": "Shell", ".bash": "Shell", ".vue": "Vue", ".svelte": "Svelte",
    ".m": "Objective-C", ".zig": "Zig", ".clj": "Clojure", ".sql": "SQL",
}
# Manifest basenames the framework probe reads (depth <= 2, so monorepo
# packages count) and the substrings that name a framework in each.
_MANIFEST_NAMES = frozenset({
    "package.json", "pyproject.toml", "requirements.txt", "setup.py", "setup.cfg",
    "go.mod", "Cargo.toml", "Gemfile", "pom.xml", "build.gradle",
    "build.gradle.kts", "composer.json", "mix.exs", "Package.swift",
    "pubspec.yaml", "CMakeLists.txt", "Makefile",
})
_FRAMEWORK_HINTS = {
    "package.json": (("\"react\"", "React"), ("\"next\"", "Next.js"),
                     ("\"vue\"", "Vue"), ("\"nuxt\"", "Nuxt"),
                     ("\"@angular/core\"", "Angular"), ("\"svelte\"", "Svelte"),
                     ("\"express\"", "Express"), ("\"fastify\"", "Fastify"),
                     ("\"@nestjs/core\"", "NestJS"), ("\"koa\"", "Koa"),
                     ("\"electron\"", "Electron")),
    "pyproject.toml": (("django", "Django"), ("flask", "Flask"),
                       ("fastapi", "FastAPI"), ("starlette", "Starlette"),
                       ("tornado", "Tornado"), ("sqlalchemy", "SQLAlchemy")),
    "requirements.txt": (("django", "Django"), ("flask", "Flask"),
                         ("fastapi", "FastAPI"), ("starlette", "Starlette"),
                         ("tornado", "Tornado"), ("sqlalchemy", "SQLAlchemy")),
    "go.mod": (("github.com/gin-gonic/gin", "Gin"), ("github.com/labstack/echo", "Echo"),
               ("github.com/gorilla/mux", "Gorilla"), ("github.com/go-chi/chi", "chi"),
               ("github.com/gofiber/fiber", "Fiber"), ("google.golang.org/grpc", "gRPC"),
               ("gorm.io/gorm", "GORM"), ("github.com/spf13/cobra", "Cobra")),
    "Cargo.toml": (("actix-web", "Actix"), ("axum", "Axum"), ("rocket", "Rocket"),
                   ("tokio", "Tokio"), ("diesel", "Diesel"), ("sqlx", "SQLx"),
                   ("clap", "clap")),
    "Gemfile": (("rails", "Rails"), ("sinatra", "Sinatra"), ("hanami", "Hanami")),
    "pom.xml": (("spring-boot", "Spring Boot"), ("springframework", "Spring"),
                ("quarkus", "Quarkus"), ("micronaut", "Micronaut")),
    "build.gradle": (("spring-boot", "Spring Boot"), ("springframework", "Spring"),
                     ("ktor", "Ktor"), ("android", "Android")),
    "build.gradle.kts": (("spring-boot", "Spring Boot"), ("ktor", "Ktor"),
                         ("android", "Android")),
    "composer.json": (("laravel/framework", "Laravel"), ("symfony/", "Symfony"),
                      ("slim/slim", "Slim")),
    "mix.exs": (("phoenix", "Phoenix"), ("ecto", "Ecto")),
    "pubspec.yaml": (("flutter", "Flutter"),),
}


def _depth2_rows(files):
    """`{node: (files, dominant_ext)}` over the depth-2 directory tree: a file
    rolls up to its first two path segments (`crates/searcher/src/x.rs` ->
    `crates/searcher`), a file one level deep to its top directory, a root
    file to `.`. Dominant ext = the most common extension under the node
    (ties -> alphabetical); `-` when the files have none."""
    counts, exts = {}, {}
    for f in files:
        parts = f.split("/")
        node = "/".join(parts[:-1][:2]) or "."
        counts[node] = counts.get(node, 0) + 1
        ext = os.path.splitext(parts[-1])[1].lower()
        if ext:
            bucket = exts.setdefault(node, {})
            bucket[ext] = bucket.get(ext, 0) + 1
    rows = {}
    for node, n in counts.items():
        bucket = exts.get(node) or {}
        dom = min(bucket, key=lambda e: (-bucket[e], e)) if bucket else "-"
        rows[node] = (n, dom)
    return rows


def _detect_frameworks(repo, manifests):
    """Framework names whose marker substring appears in a manifest (bounded
    read, case-insensitive). Sorted, deduplicated; a manifest that cannot be
    read contributes nothing."""
    found = set()
    for rel in manifests:
        hints = _FRAMEWORK_HINTS.get(os.path.basename(rel))
        if not hints:
            continue
        try:
            with open(os.path.join(repo, rel), encoding="utf-8", errors="replace") as fh:
                text = fh.read(_MAX_MANIFEST_BYTES).casefold()
        except OSError:
            continue
        for marker, name in hints:
            if marker.casefold() in text:
                found.add(name)
    return sorted(found)


def build_spine(repo, max_per_group=None, max_groups=None, files=None):
    """Stage 1 (spec §5.1): everything mechanical the setup agent is told
    before it explores. `files` defaults to `discovery.discover_repo_files`;
    pass the list to keep a test hermetic. The cap resolves CLI > config >
    default and the ceiling CLI > config > `grouping_engine.ceiling_for`,
    exactly as `ingest_proposal` resolves them, so the numbers the agent
    plans against are the numbers stage 3 applies.

    Returns a JSON-serializable mapping (`schema_version` 1):
      files:      {total, code, commons, test_tree}
      cap, ceiling, ceiling_source ("cli" | "config" | "formula")
      tree:       [{path, files, ext}] depth-2 rows, most files first
      tree_more:  directories not listed (row cap)
      languages:  [{language, files}] over CODE files, most first
      manifests:  [path] dependency manifests at depth <= 2
      frameworks: [name] detected from the manifests
      claimed:    {"committed": {flat id: n}, "commons": {category: n},
                   "groups_yml": bool} -- every committed leaf is listed, a
                  leaf whose globs match nothing today as 0
      test_trees: [{path, files}] depth-2 directories the Tests sweep will take
    Every repo-derived token is passed through `_sanitize_spine_token`."""
    if files is None:
        files = discovery.discover_repo_files(repo)
    files = sorted(files)
    overrides = config_overrides(repo)
    cap = max_per_group or overrides["max_per_group"] or discovery.DEFAULT_MAX_PER_GROUP
    kinds = grouping_engine.classify_files(files)
    code_files, n_commons, n_tests = grouping_engine.count_code_files(files)
    if max_groups:
        ceiling, source = int(max_groups), "cli"
    elif overrides["max_groups"]:
        ceiling, source = overrides["max_groups"], "config"
    else:
        ceiling, source = grouping_engine.ceiling_for(code_files, cap), "formula"
    san = _sanitize_spine_token
    rows = _depth2_rows(files)
    ordered = sorted(rows, key=lambda n: (-rows[n][0], n))
    tree = [{"path": san(n), "files": rows[n][0], "ext": san(rows[n][1])}
            for n in ordered[:_MAX_TREE_ROWS]]
    langs = {}
    for f, kind in kinds.items():
        if kind == "code":
            lang = _EXT_LANG.get(os.path.splitext(f)[1].lower())
            if lang:
                langs[lang] = langs.get(lang, 0) + 1
    languages = [{"language": lang, "files": langs[lang]}
                 for lang in sorted(langs, key=lambda x: (-langs[x], x))[:_MAX_LANGUAGES]]
    manifests = [f for f in files
                 if os.path.basename(f) in _MANIFEST_NAMES and f.count("/") <= 2]
    frameworks = _detect_frameworks(repo, manifests)
    committed = committed_matrix(repo)
    import setup_proposal as sp
    committed_view = {n: {"match": list(b.get("match") or []),
                          "tests": list(b.get("tests") or [])}
                      for n, b in sp.flatten_groups(committed).items()}
    assigned, leftovers = discovery.assign_by_catalog(files, committed_view)
    commons_counts, test_dirs = {}, {}
    for f in leftovers:
        kind = kinds[f]
        if kind.startswith("commons:"):
            cat = kind.split(":", 1)[1]
            commons_counts[cat] = commons_counts.get(cat, 0) + 1
        elif kind == "tests":
            node = "/".join(f.split("/")[:-1][:2]) or "."
            test_dirs[node] = test_dirs.get(node, 0) + 1
    test_rows = sorted(test_dirs, key=lambda n: (-test_dirs[n], n))
    return {
        "schema_version": 1,
        "files": {"total": len(files), "code": code_files, "commons": n_commons,
                  "test_tree": n_tests},
        "cap": cap, "ceiling": ceiling, "ceiling_source": source,
        "tree": tree, "tree_more": max(0, len(rows) - _MAX_TREE_ROWS),
        "languages": languages,
        "manifests": [san(m) for m in manifests[:_MAX_MANIFESTS]],
        "frameworks": frameworks,
        "claimed": {"committed": {san(n): len(assigned.get(n, [])) for n in sorted(committed_view)},
                    "commons": dict(sorted(commons_counts.items())),
                    "groups_yml": bool(committed)},
        "test_trees": [{"path": san(n), "files": test_dirs[n]}
                       for n in test_rows[:_MAX_TEST_TREE_ROWS]],
    }


def format_spine(spine):
    """The `{repo_spine}` section of the brief: tree, languages, frameworks,
    manifests, what is already claimed, and the test trees with the sweep
    instruction (spec §5.1). Deterministic; no timestamps."""
    out = ["Depth-2 directory tree (a row counts the files that roll up to that node: "
           "a file directly under a top-level directory counts there, deeper files "
           "under their depth-2 directory; then the dominant extension):", ""]
    for row in spine["tree"]:
        out.append("    %-40s %5d  %s" % (row["path"], row["files"], row["ext"]))
    if spine.get("tree_more"):
        out.append("    (+%d more directories not listed)" % spine["tree_more"])
    langs = ", ".join("%s (%d)" % (x["language"], x["files"]) for x in spine["languages"])
    out += ["", "Languages (code files): %s" % (langs or "(none recognised)"),
            "Frameworks (from manifests): %s" % (", ".join(spine["frameworks"]) or "(none detected)"),
            "Manifests: %s" % (", ".join(spine["manifests"]) or "(none)"), ""]
    committed = spine["claimed"]["committed"]
    if committed:
        out.append("Already claimed by the committed groups.yml (these win; do not re-propose "
                   "them; 0 = its globs match nothing today):")
        out += ["    %-40s %5d" % (n, k) for n, k in committed.items()]
    elif spine["claimed"].get("groups_yml"):
        out.append("Already claimed by the committed groups.yml: nothing (it has no match: globs).")
    else:
        out.append("Already claimed by the committed groups.yml: nothing (no groups.yml).")
    commons = spine["claimed"]["commons"]
    if commons:
        out.append("Claimed by the Commons classifier (docs/CI/build/config/deps -- not yours to group):")
        out += ["    %-40s %5d" % (n, k) for n, k in commons.items()]
    else:
        out.append("Claimed by the Commons classifier: nothing.")
    if spine["test_trees"]:
        out += ["", "Test trees (the Tests sweep will catch these; claim only unit tests "
                    "scoped to your verticals via each group's `tests`):"]
        out += ["    %-40s %5d" % (t["path"], t["files"]) for t in spine["test_trees"]]
    else:
        out += ["", "Test trees: none detected (colocated tests belong to the vertical beside them)."]
    return "\n".join(out)


def format_budget(spine):
    """The `{budget}` section of the brief: the size arithmetic and the layer
    instruction (spec §5.1)."""
    f = spine["files"]
    how = {"cli": "from --max-groups", "config": "from .panopticon/config.json",
           "formula": "= max(%d, 2 * ceil(code_files / cap))" % grouping_engine.MIN_CEILING
           }[spine["ceiling_source"]]
    return "\n".join([
        "- files: %d total = %d code + %d commons + %d test tree"
        % (f["total"], f["code"], f["commons"], f["test_tree"]),
        "- cap (files per review group, --max-per-group): %d" % spine["cap"],
        # #1506: name the population, or the agent reads the ceiling as a
        # budget for EVERY leaf and proposes fewer verticals than the repo
        # affords. `Tests` and the Commons categories are the engine's, formed
        # after the proposal, and are not charged to this number.
        "- ceiling (CODE review groups this repo affords): %d %s -- `Tests` and "
        "the Commons categories are formed by the engine and are not counted "
        "against it" % (spine["ceiling"], how),
        "- propose `layers` ONLY for a vertical you estimate OVER the cap (%d files); "
        "a layer under %d files merges back into its parent"
        % (spine["cap"], grouping_engine.FLOOR),
        "- aim for verticals of roughly cap/2 files or more; over the ceiling, the "
        "smallest layers are collapsed first and verticals are never merged",
    ])


def write_spine(repo, spine):
    path = os.path.join(plan_contract.artifact_root(repo), _SPINE_FILE)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(spine, fh, indent=1, sort_keys=True)
        fh.write("\n")
    return path


def read_spine(repo):
    """The persisted spine, or None when absent/unreadable/not a v1 mapping."""
    path = os.path.join(plan_contract.artifact_root(repo), _SPINE_FILE)
    try:
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, ValueError):
        return None
    if not isinstance(doc, dict) or doc.get("schema_version") != 1:
        return None
    return doc


def _render_catalog_entry(name, entry, hints):
    """One catalog entry as the brief shows it: the prose the classifier is
    graded against (#1500), the aliases it may use, the hints it may NOT
    treat as authoritative, and the pool anchors. Missing fields are simply
    omitted (fixtures stay minimal; shipped data is checked by
    tests/test_catalog_data.py)."""
    lines = ["### %s" % name]
    for key, label in (("definition", "Definition"), ("boundary", "Boundary")):
        value = entry.get(key)
        if isinstance(value, str) and value.strip():
            lines.append("%s: %s" % (label, value.strip()))
    aliases = [a for a in (entry.get("aliases") or []) if isinstance(a, str)]
    if aliases:
        lines.append("Aliases: %s" % ", ".join(aliases))
    if hints:
        lines.append("Hints (non-authoritative): %s" % ", ".join(hints))
    examples = ["%s `%s`" % (ex.get("repo"), ex.get("path"))
                for ex in (entry.get("examples") or [])
                if isinstance(ex, dict) and ex.get("repo") and ex.get("path")]
    if examples:
        lines.append("Examples: %s" % "; ".join(examples))
    see_also = [x for x in (entry.get("see_also") or []) if isinstance(x, str)]
    if see_also:
        lines.append("See also: %s" % ", ".join(see_also))
    return "\n".join(lines)


def _render_catalog(catalog):
    """`### name` blocks for every catalog name, in file order, separated by a
    blank line. Works on the 5.0 shape too (`names` + `hints`, no `entries`)."""
    entries = catalog.get("entries") or {}
    hints = catalog.get("hints") or {}
    blocks = []
    for name in catalog.get("names") or []:
        entry = entries.get(name) or {}
        entry_hints = [h for h in (hints.get(name) or entry.get("hints") or [])
                       if isinstance(h, str)]
        blocks.append(_render_catalog_entry(name, entry, entry_hints))
    return "\n\n".join(blocks)


def render_capability_catalog(vocabulary):
    """The `{capability_catalog}` section of the brief: every capability's
    definition, boundary, aliases, hints, examples and see_also (spec §5.1
    "catalogs, full prose"; closes #1500 -- the calibrated prose finally
    reaches the classifier)."""
    return _render_catalog(vocabulary) or "(no capability catalog bundled)"


def render_layer_catalog(layers):
    """The `{layer_catalog}` section: the layer entries in the same shape, or
    a one-line notice when no layer catalog is present (then the agent is told
    not to propose layers)."""
    if not layers or not layers.get("names"):
        return "(no layer catalog bundled -- do not propose `layers`)"
    return _render_catalog(layers)


def load_bundled_layers(layers_path=None):
    """Load the bundled layer vocabulary. Returns (layers, present: bool),
    mirroring `load_bundled_vocabulary`: present is False when the file is
    absent or the parse yields no names or reports errors."""
    import setup_proposal as sp
    lpath = layers_path or _LAYERS_PATH
    if not os.path.isfile(lpath):
        return {"names": []}, False
    layers, lerr = sp.load_layers(lpath)
    if lerr or not layers.get("names"):
        return {"names": []}, False
    return layers, True


def render_scan_brief(repo, vocabulary, layers=None, spine=None):
    """Render the setup-scan agent brief to .panopticon/setup-scan-brief.md
    (spec §5.1): the spine and size arithmetic, both catalogs in full prose,
    the surfaces enum for profiles. `spine` is `build_spine(...)`; None builds
    one with default sizes. `layers` is `load_bundled_layers()[0]`; None
    renders the no-layers notice."""
    import dispatch
    spine = spine or build_spine(repo)
    brief = dispatch.render_prompt("setup-scan.md", {
        "repo_spine": format_spine(spine),
        "budget": format_budget(spine),
        "capability_catalog": render_capability_catalog(vocabulary),
        "layer_catalog": render_layer_catalog(layers),
        "surfaces": ", ".join(sorted(coverage_model.SURFACES)),
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


_CONFIG_INT_KEYS = ("max_per_group", "max_groups")


def config_overrides(repo):
    """The size-policy overrides from `.panopticon/config.json` (spec §5.3:
    `max_groups` and the cap are overridable in config). Returns
    `{"max_per_group": int|None, "max_groups": int|None}`; a key is honoured
    only as a positive int (bool is not an int here), anything else -- missing
    file, unparsable JSON, a string, zero -- reads as None so a target repo
    cannot wedge setup through its config."""
    out = {k: None for k in _CONFIG_INT_KEYS}
    try:
        with open(os.path.join(repo, ".panopticon", "config.json"), encoding="utf-8") as fh:
            cfg = json.load(fh)
    except (OSError, ValueError):
        return out
    if not isinstance(cfg, dict):
        return out
    for key in _CONFIG_INT_KEYS:
        value = cfg.get(key)
        if isinstance(value, int) and not isinstance(value, bool) and value >= 1:
            out[key] = value
    return out


# #1107: hard cap on the untrusted proposal file (a scanned repo can ship
# .panopticon/setup-proposal.json directly). Bounds the bytes read before parse.
_MAX_PROPOSAL_BYTES = 1_048_576   # 1 MiB -- far above any legitimate proposal


def _committed_exclude_paths(repo):
    """The committed groups.yml's top-level `exclude_paths`, [] when absent.

    Read from the raw document rather than from committed_matrix, which returns
    the `groups:` mapping alone (#1504)."""
    path = os.path.join(plan_contract.artifact_root(repo), "groups.yml")
    if not os.path.isfile(path):
        return []
    import groups_schema  # noqa: E402
    try:
        with open(path, encoding="utf-8") as fh:
            doc = yaml.safe_load(fh) or {}
    except (OSError, yaml.YAMLError):
        return []            # a corrupt committed file is disclosed elsewhere
    globs, _errors = groups_schema.parse_exclude_paths(doc)
    return globs


def ingest_proposal(repo=".", proposal_path=None, max_per_group=None, max_groups=None):
    """Ingest a setup-scan proposal -> assemble (aliases, layers, floors) ->
    stage 3 (grouping_engine.plan_groups: scoped assignment, Tests sweep,
    Commons, layers, ceiling) -> additive-merge vs committed groups.yml ->
    write .panopticon/groups.yml.draft + setup-report.md/.json. Returns a
    structured result: ok, draft, diff, disclosure, report, report_path.
    Never clobbers a committed groups.yml; nothing is written on any failure.
    No printing.

    The cap and the ceiling resolve CLI argument > config.json > default
    (`discovery.DEFAULT_MAX_PER_GROUP`; `grouping_engine.ceiling_for`)."""
    import setup_proposal as sp
    paths = (_VOCAB_PATH, _AFFINITY_PATH, _LAYERS_PATH)
    if not all(os.path.isfile(p) for p in paths):
        return {"ok": False, "errors": [
            "data error: bundled vocabulary/affinity/layer data is missing "
            "(expected %s, %s, %s)" % paths]}
    vocab, verr = sp.load_vocabulary(_VOCAB_PATH)
    affinity, aerr = sp.load_affinity(_AFFINITY_PATH, vocab)
    layers, lerr = sp.load_layers(_LAYERS_PATH)
    if verr or aerr or lerr:
        return {"ok": False, "errors": ["data error: %s" % e for e in verr + aerr + lerr]}
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
    assembled, disclosure = sp.assemble(proposal, vocab, affinity, layers=layers)
    if assembled is None:
        return {"ok": False, "errors": (
            ["proposal rejected -- no draft written:"]
            + ["  - %s" % e for e in disclosure["errors"]])}
    overrides = config_overrides(repo)
    cap = max_per_group or overrides["max_per_group"] or discovery.DEFAULT_MAX_PER_GROUP
    ceiling = max_groups or overrides["max_groups"]
    committed = committed_matrix(repo)
    planned = grouping_engine.plan_groups(
        discovery.discover_repo_files(repo), committed, assembled, cap, ceiling=ceiling)
    merged, diff = sp.merge_additive(committed, planned["groups"], planned["claims"])
    report = planned["report"]
    # Serialize everything BEFORE opening any file: a serializer failure must
    # not leave a truncated draft beside a missing report.
    # #1504: the merge above shapes the `groups:` mapping only. Any top-level
    # key the operator committed -- today `exclude_paths` (#1136) -- has to be
    # carried across explicitly, or the draft they are told to move over the
    # committed file silently drops it and puts an excluded corpus back in
    # scope for every domain and every tool scan.
    draft_text = sp.dump_groups_yaml(
        merged, exclude_paths=_committed_exclude_paths(repo))
    report_text = grouping_engine.format_report(report, disclosure)
    report_json = json.dumps({"schema_version": 1, "report": report, "disclosure": disclosure,
                              "diff": diff}, indent=1, sort_keys=True) + "\n"
    root = plan_contract.artifact_root(repo)
    draft = os.path.join(root, "groups.yml.draft")
    report_path = os.path.join(root, "setup-report.md")
    for path, text in ((draft, draft_text), (report_path, report_text),
                       (os.path.join(root, "setup-report.json"), report_json)):
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
    return {"ok": True, "draft": draft, "diff": diff, "disclosure": disclosure,
            "report": report, "report_path": report_path}
