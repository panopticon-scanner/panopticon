#!/usr/bin/env python3
"""Detect the panopticon-tools Docker image and run selected scanners against a
read-only mount of the target. Scan-time network is DISABLED for all tools
(assets are baked into the image); parse-only adapters never execute target
code; roslyn-secguard executes target build logic inside a no-egress,
no-secret container (recorded in report meta); pip-audit/npm-audit run only
under --online. Degrades gracefully when Docker is absent. Stdlib-only."""
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from scripts import groups_schema
from scripts import executable
from scripts.tools import ADAPTERS, ONLINE_ONLY
from scripts.tools import egress
from scripts.tools.base import SECURITY_FLAG
from scripts import plan_contract
from scripts import procgroup
from scripts import scanner_config
from scripts import tool_capture
from scripts import tools_manifest
from scripts import venv_scope
from scripts.progress import NullProgress, make_progress
from scripts.tools.legacy_sarif import (
    LEGACY_SARIF_TOOLS, SEMGREP_SCANNER_SCOPE_ARGS, TOOL_CMD, with_semgrep_excludes)

# #1762 (ARC-2609514778) part 1 of 4: the scanner-owned configuration block moved
# to `scanner_config` whole. These names stay bound HERE because something still
# reads them through `run_tools.<name>`: the two exclude tuples are read by
# `tests/test_run_tools_core.py`, `tests/test_run_tools_dispatch.py` and
# `tests/test_venv_scope.py` (part 4 took their one reader here,
# `_bandit_exclude_value`); `_working_dir_flags` and the dispatch loop spell
# `TARGET_MOUNT` (`tests/test_code_scanning_reports.py` pins it against the
# report side); two of the five ledgers the manifest reads back move with the
# block and are cleared by `run_tools()`; and the staged-config constants are
# read by `tests/test_run_tools_core.py` and `tests/test_run_tools_dispatch.py`.
# A ledger is the SAME dict object either way, so `.clear()`/`.pop()` here and
# `[tool] = ...` there address one ledger.
#
# CONSTANTS ONLY, and every one a READ binding. `mock.patch` of a name that moved
# must target `scanner_config`, where the moved code looks it up -- patching a
# binding here reaches nothing, whether or not the name appears below. So no moved
# FUNCTION is bound here: every call `run_tools` still makes is spelled
# `scanner_config.<name>`, and the moved functions it no longer calls at all are
# not re-bound either. The `tool_capture`, `tools_manifest` and `venv_scope`
# blocks below obey the same rule.
# `tests/test_scanner_config.py::TestThePatchRuleIsOneRule` enforces both halves
# from all four modules' own ASTs, and holds the same list each block binds.
#
# `noqa: F401` marks the ones only a TEST reads through this module: ruff cannot
# see a use from here, and an `__all__` would silence it by also narrowing a
# star-import nothing asks for.
from scripts.scanner_config import (
    BANDIT_DEFAULT_EXCLUDES,      # noqa: F401
    BANDIT_SCANNER_EXCLUDES,      # noqa: F401
    BANDIT_INI_NAME,              # noqa: F401
    BANDIT_INI_TEXT,              # noqa: F401
    CONFIG_TARGET_BANDIT,         # noqa: F401
    SCANNER_CONFIG_MOUNT,         # noqa: F401
    SCANNER_OWNED_CONFIG,         # noqa: F401
    TRIVY_IGNOREFILE_NAME,        # noqa: F401
    TRIVY_IGNOREFILE_TEXT,        # noqa: F401
    TARGET_MOUNT,                 # `_working_dir_flags` and the two `-v` specs
    _SCANNER_CONFIG_POSTURE,      # two of the manifest's five ledgers, both
    _SUPPRESSION_POSTURE,         # cleared by `run_tools()`; only this one popped
)

# #1762 (ARC-2609514778, ARC-3243338950) part 2 of 4: the capture path -- one
# container run supervised, bounded, classified, redacted and written -- moved
# to `tool_capture` whole. Three names stay bound HERE, all three READ bindings
# under the same patch rule as the block above: `run_tools()` multiplies
# `TOOL_TIMEOUT` into the egress session's ceiling and
# `tests/test_run_tools_containment.py` reads it through this module;
# `ingest_tools` imports `MAX_TOOL_OUTPUT_BYTES` from here as the shared cap and
# `tests/test_run_tools_core.py` and `tests/test_run_tools_languages.py` read it
# through this module (part 3 took its one reader here, the manifest's eslint
# capture read, with the writer); and `_REDACTED_CAPTURES` is the ledger
# `run_tools()` clears and the dispatch loop discards a withdrawn capture from --
# the SAME set object either way, so `.clear()` here and `.add()` there address
# one ledger. `_capture_run` is the one moved FUNCTION this module still calls,
# and it is called `tool_capture._capture_run(...)`.
from scripts.tool_capture import (
    MAX_TOOL_OUTPUT_BYTES,        # noqa: F401
    TOOL_TIMEOUT,
    _REDACTED_CAPTURES,
)

# #1762 (ARC-2609514778) part 3 of 4: the tools manifest -- `tools-manifest.json`'s
# schema, its `excluded_dirs` row builder and the two posture ledgers whose only
# reader is the writer -- moved to `tools_manifest` whole. Three names stay bound
# HERE, all three READ bindings under the same patch rule as the blocks above:
# `VENV_MAX_DEPTH` is read through this module by `tests/test_run_tools_core.py`
# and `tests/test_tools_manifest.py`; both posture maps are cleared by
# `run_tools()` and filled by the dispatch loop where the argv is built -- the
# SAME dict object either way.
from scripts.tools_manifest import (
    VENV_MAX_DEPTH,               # noqa: F401
    _IGNORE_FILE_POSTURE,
    _NETWORK_POSTURE,
)

# #1762 (ARC-2609514778) part 4 of 4: the virtualenv scope -- finding the
# virtualenvs under the target, deciding which of them a scanner's exclusion knob
# may be handed, and rendering that onto each tool's argv -- moved to
# `venv_scope` whole, with the manifest rows it produces still published by
# `tools_manifest.write_manifest`. ONE name stays bound HERE, a READ binding
# under the same patch rule as the blocks above: `VENV_MARKER` is read through
# this module by `tests/test_run_tools_core.py` and
# `tests/test_run_tools_dispatch.py`, which plant the marker the walk keys on
# (`ingest_tools` imports it, and `has_venv_shape`, from `venv_scope` directly --
# one predicate and one token for the scan side and the ingest side). The three
# moved FUNCTIONS this module still calls are spelled `venv_scope.<name>`:
# `find_virtualenvs` and `partition_venv_dirs` in `run_tools()`'s own default and
# in `main`, and `_with_venv_excludes` in the dispatch loop.
#
# `REDTEAM`/`SECURITY_MODES` did NOT move: the mode vocabulary is
# `scripts.tools.base`'s, this module's pair is the local mirror its argparse
# `choices` reads (and `venv_scope` imports `REDTEAM` from `tools.base`, as
# `scanner_config` does).
from scripts.venv_scope import (
    VENV_MARKER,                  # noqa: F401
)

# JS/TS SAST runs via the eslint-security ADAPTER (bundled flat config);
# the legacy bare-eslint tool can never run on arbitrary targets (eslint >=9
# requires a project eslint.config.js) and was retired from language selection
# (calibration 2026-08-03: perpetual "tool eslint exited 2; skipping").
LANG_TOOL = {"python": "bandit", "go": "gosec"}

# Phase 1 adapters selected by ecosystem detection; they are dispatched through
# _run_adapter.py inside the panopticon-tools container.
PHASE1_ADAPTERS = {"pip-audit", "npm-audit", "osv-scanner", "eslint-security"}

# Phase 2 adapters selected by applicability to the target repo.
PHASE2_ADAPTERS = {
    "brakeman", "bundler-audit", "spotbugs", "dependency-check",
    "cargo-audit", "roslyn-secguard",
}

# Always-on SARIF scanners select_tools seeds regardless of language.
BASE_TOOLS = {"semgrep", "gitleaks", "trivy"}

def recommendable_tools(languages=None, target=None):
    """The scanner universe the scout may recommend from.

    Ungated (no args) this is the full ground truth run_tools can select (#1053):
    the always-on SARIF tools + every language-keyed SAST tool + the Phase-1/2
    adapters. An ungrounded scout would otherwise invent pytest/pylint/ruff/...
    (none are adapters), which #1031 could only disclose as requested_unavailable
    noise after the fact. Excludes the retired bare `eslint` (eslint >=9 can't run
    on arbitrary targets; JS/TS SAST runs via the eslint-security adapter).

    run-9 (E1): a scout handed the FULL universe requests brakeman/gosec/cargo-audit
    /spotbugs/roslyn-secguard/... on a pure-Python repo -- tools the runner can
    never select, so each becomes a `requested_unavailable` disclosure. Passing
    `languages` (from detect_languages) filters the language-keyed SAST to those
    languages, and `target` filters the adapters to those actually applicable
    (select_adapters) -- so the scout sees exactly the set the runner would select
    and cannot manufacture cross-language over-request noise. The always-on SARIF
    tools stay offered (broadly applicable)."""
    lang_tools = set(LANG_TOOL.values())
    if languages is not None:
        lang_tools = {LANG_TOOL[lang] for lang in languages if lang in LANG_TOOL}
    adapters = PHASE1_ADAPTERS | PHASE2_ADAPTERS
    if target is not None:
        adapters &= set(select_adapters(target).keys())
    return sorted(BASE_TOOLS | lang_tools | adapters)

# The gating docker probe runs before any tool; bound it so a wedged daemon
# socket cannot hang the whole scan pipeline (#1112).
DOCKER_PROBE_TIMEOUT = 30

# #run8 OPS-D1A: TOOL_TIMEOUT bounds wall-clock and MAX_TOOL_OUTPUT_BYTES the
# captured stdout; NEITHER bounds the in-container memory/CPU/PID footprint, so
# a target that drives a scanner to allocate pathologically (a recursive archive
# fed to dependency-check) can destabilize the host/CI runner long before either
# cap. Every container this module and the fixture runner launch gets a hard
# ceiling (the runner's two only since #1767, ARC-3859414366). Retunable via env;
# an empty value drops that ceiling (both memory flags, or --cpus, or --pids-limit).
CONTAINER_MEMORY = os.environ.get("PANOPTICON_TOOL_MEMORY", "6g")
CONTAINER_CPUS = os.environ.get("PANOPTICON_TOOL_CPUS", "4")
CONTAINER_PIDS_LIMIT = os.environ.get("PANOPTICON_TOOL_PIDS", "1024")

def resource_limit_flags():
    """docker-run resource ceilings for the containers this module and
    `run_fixture_tests.py` launch, beside `scanner_config.privilege_drop_flags`.
    The two OTHER launch sites that splice those flags size their own footprint
    instead: the egress sidecar (`egress.PROXY_LIMITS`, tighter on purpose) and
    the daily `adapter-integration` fixture lanes (none, stated in the workflow).

    --memory-swap is pinned equal to --memory so an adversarial allocation is
    OOM-killed at the ceiling rather than spilling into swap and merely dragging
    the host to a crawl. Any flag whose env override is empty is omitted."""
    flags = []
    if CONTAINER_MEMORY:
        flags += ["--memory", CONTAINER_MEMORY, "--memory-swap", CONTAINER_MEMORY]
    if CONTAINER_CPUS:
        flags += ["--cpus", CONTAINER_CPUS]
    if CONTAINER_PIDS_LIMIT:
        flags += ["--pids-limit", CONTAINER_PIDS_LIMIT]
    return flags


def validate_output_dir(target, out_dir):
    """Reject default artifact output through a target-controlled symlink."""
    logical_root = os.path.join(os.path.abspath(target), ".panopticon")
    candidate = os.path.abspath(out_dir)
    try:
        under_artifacts = os.path.commonpath([logical_root, candidate]) == logical_root
    except ValueError:
        under_artifacts = False
    if under_artifacts:
        safe_root = plan_contract.artifact_root(target)
        if os.path.commonpath([os.path.realpath(safe_root), os.path.realpath(candidate)]) \
                != os.path.realpath(safe_root):
            raise ValueError("scanner output escapes the target artifact directory")
    return out_dir


def docker_available(image="panopticon-tools", runner=None, target=None):
    """Check if the specified Docker image is available."""
    runner = runner or subprocess.run
    try:
        root = target or os.getcwd()
        resolved = executable.resolve("docker", root, os.environ.get("PATH", ""))
        docker_env = executable.sanitize_startup_environment(os.environ)
        docker_env["PATH"] = resolved.path_env
        res = runner([resolved.path, "image", "inspect", image],
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                     timeout=DOCKER_PROBE_TIMEOUT, env=docker_env)
        return getattr(res, "returncode", 1) == 0
    except (FileNotFoundError, executable.ExecutableResolutionError):
        # docker binary genuinely absent -- the one benign case; stay quiet.
        return False
    except Exception as e:  # noqa: BLE001
        # A wedged daemon (TimeoutExpired), socket permission denial, broken
        # pipe, etc. are real faults, not "no docker here". Swallowing them
        # silently let the whole tool-scan phase no-op while the run reported
        # success (OPS-E1A). Return False (skip) but say WHY on stderr.
        print("docker probe for image %r failed: %s: %s"
              % (image, type(e).__name__, e), file=sys.stderr)
        return False


_LANG_EXTS = {".py": "python", ".go": "go",
              ".js": "javascript", ".jsx": "javascript",
              ".ts": "typescript", ".tsx": "typescript"}
_DETECT_PRUNE = {".git", ".venv", "venv", "node_modules", "__pycache__",
                 ".pytest_cache", ".mypy_cache", ".ruff_cache", ".tox", "tmp",
                 # #1138: vendored / generated / sample trees carry foreign-language
                 # files that are NOT the project's own source. A single stray file
                 # here used to trigger that language's SAST tool (e.g. a vendored
                 # .go making gosec run on a Python repo), which then produced
                 # nothing and read as a "selected-but-unproduced" tool-coverage
                 # gap. Prune the dirs where a foreign-language file is definitively
                 # not project source; conservatively leave tests/ alone (a real
                 # test suite IS legitimate language surface).
                 "vendor", "third_party", "third-party", "testdata", "fixtures",
                 "examples", "example", "dist", "build", "target", "site-packages",
                 "docs"}


def detect_languages(target):
    """Best-effort language detection by source-file extension.

    The bare CLI invocation (README/CI) passes no --languages, which previously
    meant the language-keyed SAST tools (bandit/gosec/eslint) NEVER ran
    (calibration 2026-08-03). Walks with noise-dir pruning; stops once every
    known language is seen.
    """
    found = set()
    want = set(_LANG_EXTS.values())
    for dirpath, dirnames, filenames in os.walk(target):
        dirnames[:] = [d for d in dirnames
                       if d not in _DETECT_PRUNE and not d.startswith(".")]
        for fn in filenames:
            lang = _LANG_EXTS.get(os.path.splitext(fn)[1].lower())
            if lang:
                found.add(lang)
                if found == want:
                    return sorted(found)
    return sorted(found)


# #1740 (ARC-F2A): the scan half of the security mode `security_gate` keys on.
# Mirrored here rather than imported, because `security_gate` imports THIS
# module (through `ingest_tools`) and the runner must not depend on the gate.
REDTEAM = "redteam"
SECURITY_MODES = ("standard", REDTEAM)


def select_tools(languages, has_deps):
    """Select security scanners based on detected languages and dependency status."""
    tools = ["semgrep", "gitleaks"]
    if has_deps:
        tools.append("trivy")
    for lang in languages or []:
        t = LANG_TOOL.get(str(lang).lower())
        if t and t not in tools:
            tools.append(t)
    return tools


def select_adapters(target: str, adapters: dict | None = None) -> dict:
    """Return the subset of adapters applicable to the target repo."""
    adapters = adapters or ADAPTERS
    return {name: adapter for name, adapter in adapters.items() if adapter.is_applicable(target)}


def _is_excluded(rel, exclude_globs):
    """True if a repo-relative path matches any exclusion glob.

    #1740 fix round 2: GITIGNORE semantics, through the one translator
    `discovery` reads the same committed `exclude_paths:` lines with
    (`groups_schema.matched_glob`). It was `fnmatch` here, where `*` spans `/`
    and a trailing `/` matches nothing -- so `tests/*` covered the whole
    subtree on this side and only the direct children on discovery's, and
    `docs/` covered a tree there and nothing here. Subtree is spelled `**`.
    """
    rel = str(rel).replace(os.sep, "/")
    return groups_schema.matched_glob(rel, exclude_globs, "run_tools") is not None


def partition_by_exclusion(adapters, target, exclude_globs):
    """Split applicable adapters into (required, excluded_scope).

    An adapter is `excluded_scope` when it exposes ``applicable_files`` and
    EVERY such file matches an --exclude glob: its entire surface is outside the
    gate's scope, so a missing run cannot hide a gate-relevant finding — it is
    disclosed, not required. Adapters without file-level applicability (their
    trigger is a manifest/lockfile, not an excludable source tree) stay
    required. With no exclusions, nothing is demoted.
    """
    required, excluded_scope = [], []
    for name, adapter in adapters.items():
        lister = getattr(adapter, "applicable_files", None)
        files = list(lister(target)) if callable(lister) else []
        if exclude_globs and files and all(
                _is_excluded(os.path.relpath(f, target), exclude_globs) for f in files):
            excluded_scope.append(name)
        else:
            required.append(name)
    return required, excluded_scope


def collect_sanitization(adapters, target):
    """`{adapter: report}` for every adapter that discloses what it did NOT scan.

    The sibling of `partition_by_exclusion` and the same shape of channel: the
    runner asks the adapter a question ON THE HOST, in process, and hands the
    answer to `write_manifest`. An adapter answers by exposing
    `sanitization_report(target)`; today only pip-audit does (#1646), where the
    answer is "these requirement lines were not audited, because auditing them
    would have run the target's build backend".

    A parallel field, never an overload of `excluded_scope`: that one names
    adapters whose whole surface fell outside the gate's scope, and folding a
    PARTIAL audit into it would read as "this adapter was not required".

    Tolerant: the method reads target-controlled files, so a crash inside it
    must cost the disclosure, never the scan. The failure is announced --
    silently dropping the disclosure is the same species of hole the field
    exists to close.
    """
    out = {}
    for name, adapter in sorted(adapters.items()):
        reporter = getattr(adapter, "sanitization_report", None)
        if not callable(reporter):
            continue
        try:
            report = reporter(target)
        except Exception as exc:   # noqa: BLE001 -- disclosure must not sink the scan
            print("adapter %s could not report what it sanitized: %s" % (name, exc),
                  file=sys.stderr)
            continue
        if isinstance(report, dict):
            out[name] = report
    return out


def filter_online(chosen, online):
    """Drop ONLINE_ONLY adapters unless --online was given, with a notice."""
    if online:
        return list(chosen)
    kept = [t for t in chosen if t not in ONLINE_ONLY]
    for t in chosen:
        if t in ONLINE_ONLY:
            print("adapter %s needs network; skipped (offline substitute: "
                  "osv-scanner). Re-run with --online to include it." % t,
                  file=sys.stderr)
    return kept


# #1646 C1(b) / #1877: the container working directory for EVERY scanner
# dispatch. The image ends `WORKDIR /src` and `/src` is the target mount, so a
# container that starts there hands its scanner the reviewed repository as the
# directory its OWN config resolution walks from -- pip deciding a requirement
# is a local archive on a bare SUFFIX match and running a committed
# `evil.tar.gz`'s build backend or npm reading `.npmrc`. Semgrep's independent
# scan-root ignores are neutralised on its argv. Gitleaks' source-root read is
# handled by `scanner_config`'s conditional overlay. The cwd rule is uniform: every
# scanner container starts OUTSIDE the
# mount. Docker CREATES a `-w` directory that does not exist, so this one is
# empty by construction and needs nothing in the image, and no argv changes --
# every tool already names its scan root by absolute path.
#
# TWO scanners are the exception, and both say so EXPLICITLY (`-w /src`)
# rather than leaning on the image's WORKDIR. For each, the cwd is a SCAN
# INPUT rather than a config-lookup surface, so moving it does not harden the
# scan, it deletes it:
#   gosec -- its argv is the CWD-RELATIVE go package pattern `./...`, which
#     go/packages resolves through `go list` from the module root, so a
#     container started anywhere else scans an empty directory.
#   eslint-security -- under flat config the `files`/`ignores` base path is
#     the process cwd whenever the config is named with `--config`, and
#     anything outside that base is classified "external". Measured on the
#     pinned eslint 10.9.0: from a scratch cwd the adapter produced NO output
#     and exit 2, "located outside of the base path". A config-object
#     `basePath` was tried first and does not widen the root base.
# Each adapter makes the same call at the Popen level, for the same reason and
# with the argument recorded against it there and in
# tests/tools/test_adapter_cwd_confinement.py's allowlist.
#
# Belt and braces: the adapters ALSO pass their own scratch cwd to `run_tool`
# (`tools.base.scratch_cwd`), so an `invoke()` that runs outside this
# dispatcher -- a host-side test, a future runner -- is confined too, with no
# docker flag in front of it.
ADAPTER_EMPTY_CWD = "/panopticon-empty-cwd"
DISPATCH_KEEPS_TARGET_CWD = ("gosec", "eslint-security")


def _working_dir_flags(tool):
    """`-w` for *tool*'s container: outside the mount for every scanner but
    the two in DISPATCH_KEEPS_TARGET_CWD, for which the cwd is a scan input
    (see above)."""
    inside = tool in DISPATCH_KEEPS_TARGET_CWD
    return ["-w", TARGET_MOUNT if inside else ADAPTER_EMPTY_CWD]


def _popen_runner(cmd, stdout=None, stderr=None, timeout=None, env=None):
    """The default PRODUCTION runner (#1111 / run7 COD-A2A).

    Returns a live subprocess.Popen so tool_capture._capture_run streams the
    child's stdout through that module's _stream_and_write bounded sink -- the
    memory guard #1111 advertised but never reached, because the old default
    (subprocess.run) buffers the ENTIRE output in memory before returning and
    thus always took the drop path. `timeout` is accepted for call-signature
    parity with the subprocess.run seam but is NOT honored here: Popen has no
    timeout=, so the wall-clock bound is enforced by _stream_and_write's
    watchdog instead (which also bounds a hung streaming read, something a
    single subprocess.run timeout could not do mid-buffer)."""
    return subprocess.Popen(cmd, stdout=stdout, stderr=stderr, env=env)


class _DockerRunner:
    """Bind one runner seam to the trusted Docker child environment."""

    def __init__(self, runner, env):
        self._panopticon_runner = runner
        self._panopticon_env = env

    def __call__(self, cmd, **kwargs):
        kwargs["env"] = self._panopticon_env
        return self._panopticon_runner(cmd, **kwargs)


class _DockerContext:
    """The resolved Docker identity and the exact environment bound to it."""

    def __init__(self, executable_path, env):
        self.executable = executable_path
        self.env = env


def run_tools(target, tools, out_dir, image="panopticon-tools",
              runner=None, online=False, progress=None, venv_dirs=None,
              run_id=None, security_mode="standard", exclude_globs=()):
    """Run selected security tools and adapters in Docker against target.

    Legacy SARIF tools use their hard-coded ``TOOL_CMD`` invocation. New Phase 1
    adapters are dispatched through ``scripts/_run_adapter.py`` inside the
    container so the same fat image is used for local and CI runs.

    `venv_dirs` (#1638 P09) are the virtualenvs the scanners that expose an
    exclusion knob are told to skip; None detects them here, so a direct caller
    gets the exclusion without asking -- through `partition_venv_dirs`, so the
    default can never hand a scanner something the rules forbid. main() passes
    its own list so the walk is done once and the manifest discloses exactly what
    the scan was told to skip.

    `security_mode` (#1839) is the same `--security` value `partition_venv_dirs`
    reads, carried all the way to the argv: under `redteam` the scanners are
    told to stop honouring the inline suppression COMMENTS in the target's own
    source, and the adapter dispatches name the mode so the argv built inside
    the container can make the same choice. `standard` is the conservative
    default for a caller that named no mode: an operator scanning their own
    repository, where an inline suppression is their reviewed decision and is
    honoured, and DISCLOSED on the manifest. This repository's own CI
    (`security.yml` and the fork-PR `security-fork.yml`) scans in `redteam`, so
    nothing target-authored is honoured on either check (owner ruling of
    2026-09-26; the workflows move in their own PR).

    `run_id` (#1645) names this run's egress network and proxy sidecar, so a
    leftover from a crashed run is recognisable. The whole loop runs inside one
    `scripts.tools.egress.session`: with an ONLINE_ONLY adapter selected that
    session is a `--internal` network plus an allowlisting proxy, and with none
    selected it is inert and every argv below is byte-identical to before.
    """
    runner = runner or _popen_runner   # #run7 COD-A2A: stream by default, don't buffer-then-drop
    # This run's redaction ledger starts empty, so `write_manifest` reports what
    # THIS scan's captures went through and never inherits a previous one's
    # (#1639 P11 F5).
    _REDACTED_CAPTURES.clear()
    # #1839 (review round 1 I2): the default PARTITIONS. The raw
    # `find_virtualenvs` list still holds the rows nothing may be told to skip
    # -- a `pyvenv.cfg` with no environment under it, a name no exclusion value
    # can carry -- so handing it straight to the knobs reproduced the finding on
    # this module's own convenience path. `standard` is the conservative default
    # for a caller that named no mode: it skips MORE than redteam would.
    if venv_dirs is None:
        venv_dirs = venv_scope.partition_venv_dirs(
            venv_scope.find_virtualenvs(target))[0]
    validate_output_dir(target, out_dir)
    os.makedirs(out_dir, exist_ok=True)
    tools = filter_online(tools, online)
    resolved = executable.resolve("docker", target, os.environ.get("PATH", ""))
    docker_bin = resolved.path
    docker_env = executable.sanitize_startup_environment(os.environ)
    docker_env["PATH"] = resolved.path_env
    docker_context = _DockerContext(docker_bin, docker_env)

    # One environment for scanner launches and every egress control-plane
    # command. The wrapper preserves the injected runner seam while making an
    # unsafe nested PATH impossible in production.
    docker_runner = _DockerRunner(runner, docker_env)
    # #1317: NullProgress by default, so the five call sites below need no
    # `if progress:` guard and the runner's behaviour is byte-identical unless
    # a caller opts in.
    progress = progress or NullProgress()
    total = len(tools)
    progress.header(target, total)
    # #1645: what the runner OBSERVED itself granting each tool, the same
    # construction as `tool_capture._REDACTED_CAPTURES` -- cleared here, filled
    # where the argv is built, read back by `write_manifest`. A claim written
    # from intent would survive the flags going away; this one does not.
    _NETWORK_POSTURE.clear()
    _SUPPRESSION_POSTURE.clear()   # #1839: this run's, never the last one's
    _SCANNER_CONFIG_POSTURE.clear()
    _IGNORE_FILE_POSTURE.clear()
    tools_manifest._SCANNER_SCOPE_POSTURE.clear()
    with egress.session(docker_bin, tools, docker_runner, run_id=run_id,
                        max_seconds=TOOL_TIMEOUT * total
                        + egress.SIDECAR_SLACK) as online_egress:
        written = _run_selected(target, tools, out_dir, image, docker_runner,
                                progress, total, venv_dirs, docker_context,
                                online_egress, security_mode, exclude_globs)
    progress.footer(len(written), total)
    return written


def _run_selected(target, tools, out_dir, image, runner, progress, total,
                  venv_dirs, docker_context, online_egress,
                  security_mode="standard", exclude_globs=()):
    """The dispatch loop, one docker invocation per selected tool.

    Split out of `run_tools` only so the `egress.session` context (#1645) does
    not re-indent sixty lines of unchanged dispatch; it returns the paths it
    wrote, exactly as the loop did inline.
    """
    written = []
    docker_bin = docker_context.executable
    for index, tool in enumerate(tools, 1):
        # #1645 ruling 2: an online adapter whose egress could not be
        # established does NOT fall back to Docker's default bridge. It is
        # skipped, and `write_manifest` turns this posture into an
        # `excluded_scope` entry carrying the reason -- so the gap is
        # certified against, exactly like an absent scanner.
        if online_egress.refuses(tool):
            _NETWORK_POSTURE[tool] = egress.UNAVAILABLE
            progress.note("[%d/%d] %s skipped: online egress unavailable"
                          % (index, total, tool))
            continue
        # Legacy SARIF path (kept for backward compatibility). Gitleaks uses
        # its adapter so the scanner-owned rule config reaches production.
        cmd = TOOL_CMD.get(tool)
        if cmd and tool != "gitleaks":
            cmd = list(cmd)   # never mutate the shared TOOL_CMD entry
            cmd = venv_scope._with_venv_excludes(tool, cmd, venv_dirs)  # #1638 P09
            cmd = with_semgrep_excludes(tool, cmd, exclude_globs)
            # #1839: under redteam, stop honouring the suppression COMMENTS in
            # the target's own source. No-op under standard, where they are
            # honoured and `suppression_comments` says so.
            cmd = scanner_config._with_suppression_flags(
                tool, cmd, security_mode)
            tools_manifest._record_semgrep_scope(tool, cmd, SEMGREP_SCANNER_SCOPE_ARGS)
            out_path = os.path.join(out_dir, "%s.sarif" % tool)
            # #1839 / #run7: bandit's ini and trivy's ignorefile are the
            # SCANNER's, constants staged in a scratch this target never
            # controls and mounted read-only beside the target mount. No-op for
            # every other tool.
            with scanner_config._scanner_owned_config(
                    tool, cmd, security_mode, target) as (cmd, config_mount):
                if cmd is None:   # staging failed: that one tool only (N3)
                    progress.note("[%d/%d] %s skipped: scanner-owned config "
                                  "could not be staged" % (index, total, tool))
                    continue
                docker = ([docker_bin, "run", "--rm"] + resource_limit_flags()
                          + scanner_config.privilege_drop_flags()
                          + _working_dir_flags(tool)
                          + config_mount
                          + ["--network", "none",
                             "-v", "%s:%s:ro" % (os.path.abspath(target), TARGET_MOUNT),
                             image] + cmd)
                _NETWORK_POSTURE[tool] = egress.NO_NETWORK
                scanner_config._record_suppression_posture(
                    tool, scanner_config._suppression_flag_on(tool, cmd),
                    security_mode)
                scanner_config._record_scanner_config(tool, cmd)
                with progress.tool(tool, index, total) as step:
                    done = step.finish(
                        tool_capture._capture_run("tool", tool, docker,
                                                  out_path, runner,
                                                  docker_context=docker_context))
            if done:
                written.append(done)
            continue

        # Phase 1 adapter dispatch path.
        adapter = ADAPTERS.get(tool)
        if adapter:
            ext = "sarif" if tool in LEGACY_SARIF_TOOLS else "json"
            out_path = os.path.join(out_dir, "%s.%s" % (tool, ext))
            docker = ([docker_bin, "run", "--rm"] + resource_limit_flags()
                      + scanner_config.privilege_drop_flags())
            if online_egress.serves(tool):
                docker.extend(online_egress.flags_for(tool))
                _NETWORK_POSTURE[tool] = online_egress.posture_for(tool)
            else:
                docker.extend(["--network", "none"])
                _NETWORK_POSTURE[tool] = egress.NO_NETWORK
            docker.extend(_working_dir_flags(tool))
            # Mount the checkout's adapter code over the image's baked-in copy
            # so local adapter fixes take effect without an image rebuild
            # (calibration 2026-08-03: fixed adapters silently kept failing
            # because the image carried the stale code).
            scripts_dir = os.path.dirname(os.path.abspath(__file__))
            with scanner_config._adapter_ignore_overlay(
                    tool, target, security_mode) as (
                    ignore_mount, ignore_posture, ignore_identity):
                if ignore_mount is None:
                    _NETWORK_POSTURE.pop(tool, None)
                    progress.note("[%d/%d] %s skipped: ignore-file "
                                  "mount unavailable" % (index, total, tool))
                    continue
                docker.extend([
                    "-v", "%s:%s:ro" % (os.path.abspath(target), TARGET_MOUNT),
                    "-v", "%s:/opt/panopticon/scripts:ro" % scripts_dir])
                docker.extend(ignore_mount)
                docker.extend([image, "python3", "/opt/panopticon/scripts/_run_adapter.py",
                               SECURITY_FLAG, security_mode, tool])
                # The adapter appends gitleaks' inline-comment flag in the
                # container; its declared mode and this dispatch argv are the
                # available host-side observation.
                adapter_mode = scanner_config._adapter_security_mode(docker)
                scanner_config._record_suppression_posture(
                    tool,
                    adapter_mode == REDTEAM
                    and scanner_config.SUPPRESSION_COMMENTS.get(
                        tool, (None, None))[1] is not None
                    and bool(getattr(adapter, "reads_security_mode", False)),
                    adapter_mode)
                with progress.tool(tool, index, total) as step:
                    done = tool_capture._capture_run(
                        "adapter", tool, docker, out_path, runner,
                        docker_context=docker_context)
                    if tool == "gitleaks" and security_mode == REDTEAM:
                        mountpoint = os.path.join(target, ".gitleaksignore")
                        try:
                            identity_unchanged = (
                                scanner_config._ignore_path_identity(mountpoint)
                                == ignore_identity)
                        except OSError:
                            identity_unchanged = False
                        if not identity_unchanged:
                            if done:
                                os.unlink(done)
                                done = None
                            _REDACTED_CAPTURES.discard(tool)
                            _NETWORK_POSTURE.pop(tool, None)
                            _SUPPRESSION_POSTURE.pop(tool, None)
                            progress.note("[%d/%d] %s skipped: ignore-file "
                                          "mountpoint changed during capture"
                                          % (index, total, tool))
                    done = step.finish(done)
                if done and tool == "gitleaks":
                    # Check our assembled Docker argv for the overlay spec.
                    # This does not establish what Docker eventually mounted.
                    mounted = (ignore_mount and len(ignore_mount) == 2
                               and ignore_mount[0] == "-v"
                               and ignore_mount[1] in docker)
                    _IGNORE_FILE_POSTURE[tool] = (
                        "neutralised" if ignore_posture == "neutralised" and mounted
                        else "honoured" if ignore_posture == "neutralised"
                        else ignore_posture)
            if done:
                written.append(done)
            continue

        # Neither path claims it. Not silent-but-fine: the manifest already
        # discloses it (selected without produced puts it in `missing`), so
        # this line is the log catching up with what the artifact will say,
        # not a new control.
        progress.note("[%d/%d] %s skipped: no runner registered"
                      % (index, total, tool))
    return written


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(description="panopticon tool runner")
    ap.add_argument("--target", default=".")
    ap.add_argument("--out", default=os.path.join(".panopticon", "tools"))
    ap.add_argument("--tools", nargs="*", default=None)
    ap.add_argument("--languages", nargs="*", default=[])
    ap.add_argument("--deps", action="store_true")
    ap.add_argument("--online", action="store_true", help="allow pip-audit/npm-audit to reach their advisory APIs")
    ap.add_argument("--manifest", default=None,
                    help="Write selected/produced scanner coverage JSON")
    ap.add_argument("--run-id", default=None,
                    help="Stamp this run's id into the manifest so synthesize can "
                         "refuse to certify against another run's manifest (#17)")
    ap.add_argument("--progress", action="store_true",
                    help="Emit one stderr line per tool as the scan proceeds "
                         "(#1317). OFF by default: the driver builds its "
                         "tool-scan failure note from this process's first 300 "
                         "stderr characters, and progress would crowd the real "
                         "error out of it. CI passes it; the driver must not.")
    ap.add_argument("--exclude", action="append", default=[],
                    help="Path glob whose files are out of gate scope; an "
                         "adapter applicable only to excluded files is disclosed "
                         "as excluded_scope, not required (repeatable). Pass the "
                         "same globs the gate uses.")
    # #1740: the same flag `security_gate` takes, and the same meaning -- under
    # redteam a directory is not excluded from the scan on its NAME alone. Only
    # the virtualenv skip reads it; every other decision here is mode-blind.
    ap.add_argument("--security", dest="security_mode", default="standard",
                    choices=list(SECURITY_MODES),
                    help="redteam: scan virtualenvs detected by NAME alone "
                         "(no pyvenv.cfg), so the gate has findings to re-admit")
    a = ap.parse_args(argv)
    excluded_scope = []
    if a.tools is not None:
        if a.exclude:
            # partition_by_exclusion iterates adapters.items(), so it needs a
            # DICT (as select_adapters returns below) -- a list here raised an
            # uncaught AttributeError, crashing the whole CLI before any scan on
            # the documented `--tools ... --exclude ...` combination (COD-X0X).
            matched_adapters = {t: ADAPTERS[t] for t in a.tools if t in ADAPTERS}
            required_names, excluded_scope = partition_by_exclusion(
                matched_adapters, a.target, a.exclude)
            chosen = required_names + [t for t in a.tools if t not in ADAPTERS]
        else:
            chosen = a.tools
    else:
        selected_adapters = select_adapters(a.target)
        required_names, excluded_scope = partition_by_exclusion(
            selected_adapters, a.target, a.exclude)
        phase1 = [name for name in required_names if name in PHASE1_ADAPTERS]
        phase2 = [name for name in required_names if name in PHASE2_ADAPTERS]
        languages = a.languages or detect_languages(a.target)
        chosen = select_tools(languages, a.deps) + phase1 + phase2
    effective = filter_online(chosen, a.online)
    # #1646: what the adapters refused to hand their scanners. Computed from the
    # EFFECTIVE set (an adapter filtered out offline audited nothing, so it has
    # nothing to disclose) and before the docker check, because the answer is a
    # filesystem read that holds on the skip path too.
    sanitized = collect_sanitization(
        {t: ADAPTERS[t] for t in effective if t in ADAPTERS}, a.target)
    # #1638 P09: one walk, two consumers. #1740: and one mode decides which of
    # the detected directories the scanners are actually told to skip.
    skip_dirs, venv_rows = venv_scope.partition_venv_dirs(
        venv_scope.find_virtualenvs(a.target), a.security_mode)
    if not docker_available(target=a.target):
        print("panopticon-tools image not available; skipping tool scan", file=sys.stderr)
        # Still disclose the skip through the coverage manifest. Without this,
        # a caller who passed --manifest as its coverage-gating signal cannot
        # tell 'docker absent, whole scan skipped' from '--manifest never
        # passed' -- both leave no file. Every OTHER skip surface in this module
        # stays visible via write_manifest's `missing` list (produced=[] -> the
        # whole selected set lands in `missing`), so this one must too, rather
        # than returning success (0) with the artifact silently discarded
        # (COD-X0X #1406). The selection above is pure filesystem/logic and needs
        # no docker, so `effective` is a faithful record of what WOULD have run.
        if a.manifest:
            tools_manifest.write_manifest(
                a.manifest, effective, [], excluded_scope=excluded_scope,
                run_id=a.run_id, excluded_dirs=venv_rows,
                sanitized=sanitized, exclude_globs=a.exclude)
        return 0
    paths = run_tools(a.target, effective, a.out, online=a.online,
                      progress=make_progress(a.progress), venv_dirs=skip_dirs,
                      run_id=a.run_id, security_mode=a.security_mode,
                      exclude_globs=a.exclude)
    if a.manifest:
        tools_manifest.write_manifest(
            a.manifest, effective, paths, excluded_scope=excluded_scope,
            run_id=a.run_id, excluded_dirs=venv_rows,
            sanitized=sanitized, exclude_globs=a.exclude)
    print("\n".join(paths))
    return 0


if __name__ == "__main__":
    sys.exit(procgroup.sigterm_as_interrupt(main))  # #2507: as driver.py does; never at import
