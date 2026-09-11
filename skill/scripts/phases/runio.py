"""Driver I/O core: paths, artifact reads/writes, child processes, the review root."""
import copy
import functools
import json
import os
import shutil
import subprocess
import yaml

import scripts.diff_map as diff_map
import scripts.evidence as evidence
import scripts.groups_schema as groups_schema
import scripts.ocrdb as ocrdb
import scripts.redact as redact
import scripts.run_manifest as run_manifest


CHECKPOINT_KINDS = ("scout", "review", "verify", "scan")

# The skill/scripts directory -- the parent of this package, not its own
# directory: `_script()` and `_child_env()` resolve sibling entry scripts and
# the child PYTHONPATH against it, and both used to read it from driver.py's
# own __file__. Pinned by ScriptsDirTest.
_SCRIPTS_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def _redact_output(text):
    # #run7 SEC-B2C: the patterns live in scripts.redact, single-sourced with
    # synthesize's report-body redaction so the two can never drift.
    return redact.redact(text)

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

def _confine_artifact_path(path):
    """Reject a `.panopticon` artifact path whose REAL location escapes the real
    `.panopticon` via a symlinked component (#run9 SEC-X0X). plan_contract.
    artifact_root() vets only the TOP-LEVEL `.panopticon` (once, at run start) and
    _open_w_nofollow's O_NOFOLLOW only the FINAL component, so a hostile target can
    plant an INTERMEDIATE symlink (`.panopticon/runs -> /elsewhere`) that a write
    would traverse. Anchor on the path's own `.panopticon` segment and require the
    realpath (which resolves any symlinked intermediate dir) to stay inside the
    real root. A planted `runs` link resolves outside and is rejected; a legit
    not-yet-created path resolves lexically against its real parent and passes, and
    the intentional `runs/latest` link (which points WITHIN `.panopticon`) passes.
    A path with no `.panopticon` segment is not an artifact path and is left be."""
    apath = os.path.abspath(path)
    parts = apath.split(os.sep)
    if ".panopticon" not in parts:
        return
    root = os.sep.join(parts[:parts.index(".panopticon") + 1]) or os.sep
    real_root = os.path.realpath(root)
    real = os.path.realpath(apath)
    if not (real == real_root or real.startswith(real_root + os.sep)):
        raise ValueError(
            "artifact path escapes .panopticon via a symlinked component: %r" % path)

def _open_w_nofollow(path):
    """Open `path` for writing, refusing to follow a symlink at the final path
    component. A target repo (untrusted under redteam) can pre-commit a
    `.panopticon` artifact path as a symlink to a file the invoking user can
    write (a dotfile, authorized_keys, ...); plain open() would follow it and
    clobber that target. O_NOFOLLOW makes the open fail on a symlink; we then
    replace the link with a fresh regular file instead of writing through it
    (#1095 -- mirrors run_manifest's exclusive-create precedent).

    #run9 SEC-X0X: O_NOFOLLOW guards only the FINAL component, so confine the whole
    resolved path to the real `.panopticon` first -- an intermediate symlinked dir
    (`.panopticon/runs -> /elsewhere`) would otherwise carry this write outside."""
    _confine_artifact_path(path)
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
    _confine_artifact_path(path)              # SEC-X0X: before makedirs, which would
    os.makedirs(os.path.dirname(path), exist_ok=True)   # otherwise follow a symlinked dir
    with _open_w_nofollow(path) as fh:
        json.dump(data, fh, indent=2, sort_keys=True)
    return path

def host_evidence(review_root):
    """This run's capability evidence, or {} when there is none.

    {} is not an error path: `hosts.posture()` turns it into all-unknown, which
    means nothing is enforced. An absent or unreadable artifact must fail
    CLOSED (spec 5, 9.2) -- on claude as much as on any exotic host -- and
    that is the whole reason this returns a mapping rather than raising.
    """
    return (_load_json(_pano(review_root, HOST_CAPABILITIES)) or {}).get(
        "capabilities") or {}

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
    return (start if os.path.isdir(start) else target), None, None

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

def _error_status(message):
    return {"status": "error", "phase": None, "checkpoint": None, "group": None,
            "dispatch_request": None, "advanced": [], "message": message}

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
