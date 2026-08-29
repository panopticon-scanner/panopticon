#!/usr/bin/env python3
"""Detect the panopticon-tools Docker image and run selected scanners against a
read-only mount of the target. Scan-time network is DISABLED for all tools
(assets are baked into the image); parse-only adapters never execute target
code; roslyn-secguard executes target build logic inside a no-egress,
no-secret container (recorded in report meta); pip-audit/npm-audit run only
under --online. Degrades gracefully when Docker is absent. Stdlib-only.
"""
import fnmatch
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from scripts.tools import ADAPTERS, ONLINE_ONLY
from scripts import plan_contract
from scripts.tools.legacy_sarif import LEGACY_SARIF_TOOLS, TOOL_CMD

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

# Max seconds to let a single docker-run tool invocation run before it's killed;
# prevents a hung tool from blocking the whole batch (CD-007).
TOOL_TIMEOUT = 900
# The gating docker probe runs before any tool; bound it so a wedged daemon
# socket cannot hang the whole scan pipeline (#1112).
DOCKER_PROBE_TIMEOUT = 30

# #run8 OPS-D1A: bound the blast radius of an adversarial target that drives a
# scanner to allocate pathologically. TOOL_TIMEOUT bounds wall-clock and
# MAX_TOOL_OUTPUT_BYTES bounds captured stdout, but NEITHER bounds the
# in-container memory/CPU/PID footprint while a tool runs -- an OOM inside the
# container (a recursive archive fed to dependency-check, a pathological input
# to a SAST parser) can exhaust or destabilize the host/CI runner well before
# the 900s timeout or the output cap is reached. Every `docker run` gets a hard
# resource ceiling. Operators can retune via env without a code change; setting
# a value to the empty string drops that individual flag (e.g. on a cgroup that
# rejects --pids-limit).
CONTAINER_MEMORY = os.environ.get("PANOPTICON_TOOL_MEMORY", "6g")
CONTAINER_CPUS = os.environ.get("PANOPTICON_TOOL_CPUS", "4")
CONTAINER_PIDS_LIMIT = os.environ.get("PANOPTICON_TOOL_PIDS", "1024")


def _resource_limit_flags():
    """docker-run resource-ceiling flags applied to every tool/adapter container.

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


def docker_available(image="panopticon-tools", runner=None):
    """Check if the specified Docker image is available."""
    runner = runner or subprocess.run
    try:
        res = runner(["docker", "image", "inspect", image],
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                     timeout=DOCKER_PROBE_TIMEOUT)
        return getattr(res, "returncode", 1) == 0
    except FileNotFoundError:
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
    """True if a repo-relative path matches any exclusion glob (fnmatch `*`
    spans `/`, so `tests/fixtures/*` covers the whole subtree)."""
    rel = str(rel).replace(os.sep, "/")
    return any(fnmatch.fnmatch(rel, g) for g in exclude_globs or [])


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


MAX_TOOL_OUTPUT_BYTES = 50 * 1024 * 1024


def _popen_runner(cmd, stdout=None, stderr=None, timeout=None):
    """The default PRODUCTION runner (#1111 / run7 COD-A2A).

    Returns a live subprocess.Popen so _capture_run streams the child's stdout
    through _stream_and_write's bounded sink -- the memory guard #1111 advertised
    but never reached, because the old default (subprocess.run) buffers the ENTIRE
    output in memory before returning and thus always took the drop path. `timeout`
    is accepted for call-signature parity with the subprocess.run seam but is NOT
    honored here: Popen has no timeout=, so the wall-clock bound is enforced by
    _stream_and_write's watchdog instead (which also bounds a hung streaming read,
    something a single subprocess.run timeout could not do mid-buffer)."""
    return subprocess.Popen(cmd, stdout=stdout, stderr=stderr)


def _capture_run(label, tool, docker, out_path, runner):
    """Run one docker tool/adapter invocation and land its stdout at out_path.

    Streams stdout into a bounded sink so adversarial/large target output does
    not accumulate unbounded in orchestrator memory (#1111). On exceeding the
    byte cap the output is truncated with a marker and a stderr notice, but the
    file is still written so the tool is recorded as produced rather than
    silently skipped.
    """
    try:
        os.remove(out_path)
    except OSError:
        pass
    # #run9 OPS-D1A: give a `docker run` a --cidfile so _stream_and_write can
    # `docker kill` the real container on a watchdog timeout -- proc.kill() reaches
    # only the CLI client. The cidfile must NOT pre-exist (docker refuses to start),
    # so it lives in a fresh temp dir cleaned up here. Inserted right after `run`.
    docker_bin = cidfile = cid_dir = None
    if (len(docker) >= 2 and os.path.basename(str(docker[0])) == "docker"
            and docker[1] == "run"):
        docker_bin = docker[0]
        cid_dir = tempfile.mkdtemp(prefix="pano-cid-")
        cidfile = os.path.join(cid_dir, "cid")
        docker = docker[:2] + ["--cidfile", cidfile] + docker[2:]
    try:
        proc = runner(docker, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                      timeout=TOOL_TIMEOUT)
        # Backward compat: tests may inject a CompletedProcess-like runner.
        if hasattr(proc, "stdout") and isinstance(proc.stdout, (bytes, type(None))):
            return _write_completed(label, tool, proc, out_path)
        return _stream_and_write(label, tool, proc, out_path,
                                 docker_bin=docker_bin, cidfile=cidfile)
    except subprocess.TimeoutExpired:
        print("%s %s timed out after %ss; skipping" % (label, tool, TOOL_TIMEOUT),
              file=sys.stderr)
    except Exception as e:  # noqa: BLE001
        print("%s %s failed: %s; skipping" % (label, tool, e), file=sys.stderr)
    finally:
        if cid_dir:
            shutil.rmtree(cid_dir, ignore_errors=True)
    return None


def _write_completed(label, tool, res, out_path):
    """Legacy path for runner callables that return a CompletedProcess."""
    if getattr(res, "returncode", 1) not in (0, 1):
        excerpt = (getattr(res, "stderr", b"") or b"")[-500:].decode(
            "utf-8", errors="replace").strip()
        print("%s %s exited %s; skipping%s" % (
            label, tool, res.returncode,
            (" — " + excerpt) if excerpt else ""), file=sys.stderr)
        return None
    out_bytes = res.stdout or b""
    if len(out_bytes) > MAX_TOOL_OUTPUT_BYTES:
        print("%s %s output exceeded %d byte limit; skipping" % (
            label, tool, MAX_TOOL_OUTPUT_BYTES), file=sys.stderr)
        return None
    if not out_bytes.strip():
        print("%s %s produced no output on a selected target; recording as "
              "missing (fail-closed, #1051)" % (label, tool), file=sys.stderr)
        return None
    return _atomic_write(out_path, out_bytes)


def _drain(stream):
    """Read and discard the rest of a stream past the byte cap so the child is
    never left blocked on a full pipe. #run7 QAL-D1A: shared by both truncation
    branches in _stream_and_write (previously an inline duplicate)."""
    while stream.read(64 * 1024):
        pass


def _stream_and_write(label, tool, proc, out_path, timeout=TOOL_TIMEOUT,
                      docker_bin=None, cidfile=None):
    """Stream stdout from a Popen-like object with an explicit byte cap AND a
    wall-clock deadline.

    The byte cap keeps a large/adversarial target's output from accumulating in
    memory (#1111). The deadline is enforced by a watchdog that kills the child
    at `timeout`: a Popen has no ``timeout=`` of its own, so without it a hung or
    trickle-slow tool would block the streaming ``read()`` (or the post-cap
    ``_drain`` of an infinite producer) forever -- restoring the bound that the
    old buffered ``subprocess.run(timeout=...)`` path provided (#run7 COD-A2A)."""
    timed_out = {"hit": False}

    def _kill_container():
        # #run9 OPS-D1A: proc.kill() SIGKILLs the `docker run` CLI client, which
        # cannot forward the signal to the daemon -- the `--rm` container keeps
        # running (and is never removed). When we recorded its id via --cidfile,
        # stop it directly. Best-effort: an empty/absent cidfile (container not
        # started yet) or a docker error is a no-op.
        if not (docker_bin and cidfile):
            return
        try:
            with open(cidfile, encoding="utf-8") as fh:
                cid = fh.read().strip()
        except OSError:
            return
        if not cid:
            return
        try:
            subprocess.run([docker_bin, "kill", cid], capture_output=True, timeout=10)
        except (subprocess.SubprocessError, OSError):
            pass

    def _watchdog():
        # Kill the child so the blocking read()/drain unblocks at EOF, and stop the
        # container it launched (OPS-D1A) so a hung tool leaves nothing running.
        timed_out["hit"] = True
        try:
            proc.kill()
        except Exception:
            pass
        _kill_container()

    timer = threading.Timer(timeout, _watchdog)
    timer.daemon = True
    timer.start()
    try:
        with tempfile.SpooledTemporaryFile(max_size=1024 * 1024) as spool:
            truncated = False
            try:
                while True:
                    chunk = proc.stdout.read(64 * 1024)
                    if not chunk:
                        break
                    room = MAX_TOOL_OUTPUT_BYTES - spool.tell()
                    if room <= 0:
                        truncated = True
                        _drain(proc.stdout)   # discard remaining stdout, unstored
                        break
                    if len(chunk) > room:
                        spool.write(chunk[:room])
                        truncated = True
                        _drain(proc.stdout)
                        break
                    spool.write(chunk)
                stderr = proc.stderr.read()
                # The watchdog guarantees the child terminates, so wait() is bounded.
                rc = proc.wait()
            finally:
                try:
                    proc.stdout.close()
                except Exception:
                    pass
                try:
                    proc.stderr.close()
                except Exception:
                    pass
                if proc.poll() is None:
                    try:
                        proc.kill()
                    except Exception:
                        pass
                    _kill_container()      # OPS-D1A: stop the container, not just the client

            # A watchdog kill lands rc < 0 (signal). Only treat it as a timeout
            # when the child did NOT finish cleanly first -- else a tool that
            # completed a hair before the deadline (rc 0/1) would be misreported.
            if timed_out["hit"] and rc not in (0, 1):
                print("%s %s timed out after %ss; skipping" % (label, tool, timeout),
                      file=sys.stderr)
                return None

            if rc not in (0, 1):
                excerpt = (stderr or b"")[-500:].decode("utf-8", errors="replace").strip()
                print("%s %s exited %s; skipping%s" % (
                    label, tool, rc,
                    (" — " + excerpt) if excerpt else ""), file=sys.stderr)
                return None

            if spool.tell() == 0:
                print("%s %s produced no output on a selected target; recording as "
                      "missing (fail-closed, #1051)" % (label, tool), file=sys.stderr)
                return None

            if truncated:
                marker = (
                    "\n\n[TRUNCATED by panopticon: output exceeded %d byte limit; "
                    "only the first %d bytes were retained]\n" % (
                        MAX_TOOL_OUTPUT_BYTES, MAX_TOOL_OUTPUT_BYTES)
                ).encode("utf-8")
                print("%s %s output exceeded %d byte limit; truncated and retained "
                      "with marker" % (label, tool, MAX_TOOL_OUTPUT_BYTES),
                      file=sys.stderr)
                # Write only up to the cap, then append the marker for the tail.
                spool.seek(0)
                payload = spool.read(MAX_TOOL_OUTPUT_BYTES)
                payload += marker
                return _atomic_write(out_path, payload)

            spool.seek(0)
            return _atomic_write(out_path, spool.read())
    finally:
        timer.cancel()


def _atomic_write(out_path, data):
    """Atomically replace out_path with data."""
    fd, temp_path = tempfile.mkstemp(
        prefix=".%s-" % os.path.basename(out_path),
        dir=os.path.dirname(out_path) or ".")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(temp_path, out_path)
    finally:
        try:
            os.remove(temp_path)
        except OSError:
            pass
    return out_path


def run_tools(target, tools, out_dir, image="panopticon-tools", runner=None, online=False):
    """Run selected security tools and adapters in Docker against target.

    Legacy SARIF tools use their hard-coded ``TOOL_CMD`` invocation. New Phase 1
    adapters are dispatched through ``scripts/_run_adapter.py`` inside the
    container so the same fat image is used for local and CI runs.
    """
    runner = runner or _popen_runner   # #run7 COD-A2A: stream by default, don't buffer-then-drop
    validate_output_dir(target, out_dir)
    os.makedirs(out_dir, exist_ok=True)
    tools = filter_online(tools, online)
    written = []
    docker_bin = shutil.which("docker") or "docker"
    for tool in tools:
        # Legacy SARIF path (kept for backward compatibility).
        cmd = TOOL_CMD.get(tool)
        if cmd:
            cmd = list(cmd)   # never mutate the shared TOOL_CMD entry
            # #run7: bandit AUTO-DISCOVERS .bandit config files by walking the
            # scanned tree. A nested checkout (a git worktree, a vendored repo)
            # with its own .bandit makes bandit ERROR ("Multiple .bandit files
            # found - ... choose one with --ini") and emit EMPTY output -- a
            # selected-but-unproduced tool that silently blocked coverage
            # certification on a worktree-heavy checkout (run-7). Pin the target's
            # own .bandit with --ini to bypass discovery; it still honors that
            # config's own excludes (incl. .worktrees/.git), so a clean single-
            # config repo is byte-unchanged. Only when the target actually has a
            # .bandit -- otherwise bandit runs with its built-in defaults.
            if tool == "bandit" and os.path.isfile(os.path.join(target, ".bandit")):
                cmd = cmd[:1] + ["--ini", "/src/.bandit"] + cmd[1:]
            out_path = os.path.join(out_dir, "%s.sarif" % tool)
            docker = ([docker_bin, "run", "--rm"] + _resource_limit_flags()
                      + ["--network", "none",
                         "-v", "%s:/src:ro" % os.path.abspath(target), image] + cmd)
            done = _capture_run("tool", tool, docker, out_path, runner)
            if done:
                written.append(done)
            continue

        # Phase 1 adapter dispatch path.
        adapter = ADAPTERS.get(tool)
        if adapter:
            ext = "sarif" if tool in LEGACY_SARIF_TOOLS else "json"
            out_path = os.path.join(out_dir, "%s.%s" % (tool, ext))
            docker = [docker_bin, "run", "--rm"] + _resource_limit_flags()
            if tool not in ONLINE_ONLY:
                docker.extend(["--network", "none"])
            # Mount the checkout's adapter code over the image's baked-in copy
            # so local adapter fixes take effect without an image rebuild
            # (calibration 2026-08-03: fixed adapters silently kept failing
            # because the image carried the stale code).
            scripts_dir = os.path.dirname(os.path.abspath(__file__))
            docker.extend([
                "-v", "%s:/src:ro" % os.path.abspath(target),
                "-v", "%s:/opt/panopticon/scripts:ro" % scripts_dir, image,
                "python3", "/opt/panopticon/scripts/_run_adapter.py", tool])
            done = _capture_run("adapter", tool, docker, out_path, runner)
            if done:
                written.append(done)
    return written


def write_manifest(path, selected, written, excluded_scope=(), run_id=None):
    """Write the exact selected/produced scanner set for coverage gating.

    `excluded_scope` names adapters that were applicable but whose entire
    surface fell under the gate's --exclude globs; they are disclosed (never
    required), and are kept out of `selected` so the missing-set invariant
    holds.
    """
    selected = list(dict.fromkeys(str(tool) for tool in selected))
    produced = sorted({os.path.splitext(os.path.basename(p))[0] for p in written})
    payload = {"schema_version": 1, "run_id": run_id,
               "selected": selected, "produced": produced,
               "missing": sorted(set(selected) - set(produced)),
               "excluded_scope": sorted(dict.fromkeys(str(t) for t in excluded_scope))}
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
        fh.write("\n")
    return payload


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
    ap.add_argument("--exclude", action="append", default=[],
                    help="Path glob whose files are out of gate scope; an "
                         "adapter applicable only to excluded files is disclosed "
                         "as excluded_scope, not required (repeatable). Pass the "
                         "same globs the gate uses.")
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
    if not docker_available():
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
            write_manifest(a.manifest, effective, [], excluded_scope=excluded_scope,
                           run_id=a.run_id)
        return 0
    paths = run_tools(a.target, effective, a.out, online=a.online)
    if a.manifest:
        write_manifest(a.manifest, effective, paths, excluded_scope=excluded_scope,
                       run_id=a.run_id)
    print("\n".join(paths))
    return 0


if __name__ == "__main__":
    sys.exit(main())
