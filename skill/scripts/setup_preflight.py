"""Setup readiness/preflight: the checks `driver setup` runs before it writes
anything, each an `(name, ok, detail)` triple where `ok` is True, False or
None (not measured). Split out of `setup_flow.py` along the #1589 seams
(#3405); `setup_readiness` / `readiness` is the entry, and
`phases/setup_readiness.py` renders what it returns.

Readiness spawns host CLIs (`docker`, `codex --version`) through ONE seam,
`DEFAULT_RUNNER` below, which tests/conftest.py's `LAUNCH_SEAMS` swaps for a
refusal. Nothing here imports `setup_flow` or its other siblings.
"""
import os
import subprocess

from scripts import discovery
from scripts import repo_config  # #1681: the one place the config names live
from scripts import hosts  # #1344 F2: host readiness reads the registry
import scripts.probes.common as probes_common  # #1627: the shared probe helpers
from scripts import host_disclosure  # #1344 F3b: one voice for the posture
import scripts.runners.gemini_home as gemini_home
from scripts import tools_image  # #3407: the local image name

host_auth_hazard = gemini_home.host_auth_hazard
host_hazard_code = gemini_home.host_hazard_code
HAZARD_MESSAGES = gemini_home.HAZARD_MESSAGES


# The roles the DRIVER dispatches and therefore needs registered shells for.
# #1606: was a hand-kept three-tuple shadowing probes.common.DRIVER_ROLES and
# leaving `advisor` unchecked; now the same object, one source of truth
# (dispatch.ROLE_FILES, via probes.common -- dispatch itself is imported lazily
# below, script-style).
_driver_roles = probes_common.DRIVER_ROLES


# Hard bound on each readiness probe so an installed-but-hung tool (Docker
# Desktop stuck starting, a wedged daemon socket, a stalled codex CLI) cannot
# freeze the preflight (#1106). A timeout or a missing binary yields None, which
# the getattr(..., "returncode", 1) checks below read as a failed probe.
_PROBE_TIMEOUT = 30

# The probe launcher, as a MODULE attribute rather than a default argument, so
# one monkeypatch can refuse every un-injected probe in the suite. Readiness
# spawns a HOST CLI here (`codex --version` below), which the guardrails forbid
# a test to reach; with `runner=subprocess.run` in the signature the autouse
# guard in tests/conftest.py could not see it, and N-M3's own tests walked
# straight through. tests/test_host_launch_guard.py now finds this seam by
# walking the AST rather than trusting anyone to remember it.
DEFAULT_RUNNER = subprocess.run


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
        r2 = _probe(runner, ["docker", "image", "inspect", tools_image.LOCAL_NAME])
        img_ok = getattr(r2, "returncode", 1) == 0
        checks.append(("tools-image", img_ok,
                       "ok" if img_ok else
                       "%s image absent for this arch -- build/pull "
                       "it (see DEVELOPMENT.md; multi-arch: #461)" % tools_image.LOCAL_NAME))
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


def _check_host_shells(host, runner, repo_root, envelope):
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

    `repo_root` and `envelope` are required routing inputs (#3535). The driver
    establishes one posture for that tree before setup begins; readiness only
    renders that envelope. Re-probing here used weaker arguments, contradicted
    the disclosure already emitted for the invocation, and scanned the same
    untrusted tree twice. Keeping the tree explicit makes call sites name what
    the envelope describes even though this renderer never touches it.
    """
    from scripts import dispatch
    resolved_host = host or dispatch._detect_host()
    row = hosts.spec(resolved_host)
    checks: list[tuple[str, bool | None, str]] = []

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
    # exemption from disclosure. This used to `return checks` here, so generic
    # (and gemini when #1621 retired it before #3494 restored it) -- any
    # registry row that claims NOTHING, and whose whole story is
    # five-of-five-unproven -- left
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
        checks.append(("enforced-shells", not (missing_shells or row.registration_refusal),
                       row.registration_refusal or ("ok" if not missing_shells else
                       "unregistered reviewer shell(s): %s -- run python3 "
                       "skill/scripts/dispatch.py --emit-host-agents %s and start "
                       "a fresh session"
                       % (", ".join(missing_shells), resolved_host))))

    # 5.1 surface 4: this is where an operator looks BEFORE a run to find out
    # what to fix, and the remedy is the reason the line exists at all. What
    # it renders is this invocation's OWN posture, handed in by the caller
    # that established it (#1603 fix round 1) -- the only way surface 4 can
    # agree with surfaces 1-3 about the same invocation.
    fresh = envelope
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
    # #1600: the SELECTION is host_disclosure's, not a second copy of it.
    # This used to write the `hosts.posture()` -> `hosts.unproven()` chain
    # itself and then look each row's text up in `gaps` by prefix match --
    # `lines()` computes the identical chain internally, so a bug confined to
    # its own filtering was invisible here, and the cross-surface consistency
    # guard failed on 2 surfaces of 3 rather than 3 of 3. One selection, made
    # once, rendered by `lines()` and consumed here in the SAME ORDER, so the
    # row carries the whole disclosed sentence rather than whatever a prefix
    # search happened to find (and never the bare capability name, which is
    # "unenforced" alone -- a mood, not a disclosure).
    #
    # refuted is a fault the operator can act on; unknown is NOT APPLICABLE --
    # read_scope_confined is proven on claude (read-guard-armed) and unknown on
    # every other host, and an unknown must not report as a failure nobody can
    # clear.
    # `strict=True`: a plain zip truncates to the shorter sequence, so a filter
    # that ever appears in `lines()` would make readiness quietly drop rows --
    # the invisible drift this whole change exists to end. Loud instead.
    for (capability, state), line in zip(host_disclosure.unproven_rows(fresh),
                                         gaps, strict=True):
        ok = False if state == hosts.REFUTED else None
        checks.append(("host-capability:" + capability, ok, line))
    return checks


def _check_groups_manifest(repo):
    """The readiness row for the committed config. NEVER raises: `phases/
    readiness` calls this directly, and a refused document (#1681: an invalid
    one, or a tree still carrying only the legacy matrix file) has to come back
    as a failed ROW carrying its remedy, not as a traceback out of a preflight.
    """
    doc = repo_config.read_document(repo)
    if doc.errors:
        return ("groups-manifest", False, "; ".join(doc.errors))
    if doc.path is None:
        # A REFUSAL resolves to no document and no error -- a symlink at either
        # config name is the case that matters (`repo_config.resolve` declines
        # to follow it). Reading only `doc.doc` would report that planted link
        # as "nothing configured yet": an informational row for a refusal, and
        # a silent fall back to whole-repo chunking.
        #
        # The RESOLVER's disclosures, not the document's: those are refusals
        # (and the both-present note, which cannot reach this branch -- it
        # comes with a path). `read_document` adds informational lines too --
        # a leftover retired JSON config -- and a stale file an operator has
        # not deleted is not a fault this row may gate a run on. `scan_execute`
        # prints that one.
        refusals = repo_config.resolve(repo).disclosures
        if refusals:
            return ("groups-manifest", False, "; ".join(refusals))
    if doc.doc is None:
        return ("groups-manifest", None,
                "no committable config yet -- --setup seeds one; "
                "files fall back to <directory>_N chunks until you commit it")
    try:
        catalog = discovery._matrix_catalog(repo) or {}
    except ValueError as exc:
        # Belt and braces: `read_document` above answered without errors, so
        # this is a refusal only the catalog can see. A row, not a traceback.
        return ("groups-manifest", False, str(exc))
    empty = [name for name, g in catalog.items() if not g.get("match")]
    return ("groups-manifest", not empty,
            "%d group(s)" % len(catalog) if not empty else
            "group(s) with no match patterns: %s" % ", ".join(map(str, empty)))


def setup_readiness(repo, host=None, runner=None, environ=None, *, envelope):
    """#485(3): the preflight. Returns a list of (name, ok, detail) checks.

    ok is True/False/None -- None means informational (not gating READY).
    Every failing check carries its fix in `detail`.

    `runner` defaults to the module's DEFAULT_RUNNER, read HERE rather than in
    the signature, because one of the probes below starts a host CLI and the
    suite's guard has to be able to refuse it.

    `envelope` is this invocation's established capability posture. It is
    required and keyword-only: readiness never creates a second posture with
    a different probe context (#3535).
    """
    runner = DEFAULT_RUNNER if runner is None else runner
    env = environ if environ is not None else os.environ
    checks = []
    checks.extend(_check_docker(runner))
    checks.append(_check_git_root(repo))
    checks.append(_check_nvd_key(repo, env))
    checks.extend(_check_host_shells(host, runner, repo, envelope))
    checks.append(_check_groups_manifest(repo))
    return checks


readiness = setup_readiness
