#!/usr/bin/env python3
"""The gh transport every filing tool shares (#3404, moved out of triage.py).

Which `gh` binary runs (`trusted_path`, `gh_bin`: never the ambient PATH,
#1650), which account it runs as (`declared_gh_config_dir`, `gh_env`: #486),
and the one retry ladder around it (`attempt_gh`, `gh`: #1103). `triage`,
`file_issues`, `file_fixmes`, `code_scanning_audit` and `reconcile_apply` all
launch gh through here. `triage` re-exports these names for one release; a
test that patches one must patch THIS module, where the code reads it.
"""
import functools
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

# The standalone CLI bootstrap triage.py uses: anchor on this checkout so the
# owner of the legacy config name is found from any cwd.
_SKILL_SCRIPTS = Path(__file__).resolve().parents[1] / "skill" / "scripts"
if str(_SKILL_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SKILL_SCRIPTS))
from repo_config import LEGACY_CONFIG_JSON  # noqa: E402


# The repository the filing tools file against and link into (#3407): one
# spelling, here because every tool that files already imports this module
# and it imports none of them back.
REPO_SLUG = "panopticon-scanner/panopticon"

RATE_HINTS = ("rate limit", "secondary rate", "abuse detection",
              "was submitted too quickly")


CONFIG_PATH = LEGACY_CONFIG_JSON


# #1650 / SEC-D1B (CWE-427). The `gh` invoked from this module performs
# authenticated issue comments, edits, closures, label creation and milestone
# mutation as the automation account, so WHICH binary that is may not be
# decided by whoever controls the ambient PATH: prepending one writable
# directory was enough to substitute the CLI, and the substitute inherits the
# credentials. These fixed system directories, plus the one below, are the only
# places looked.
TRUSTED_PATH = "/usr/local/bin:/usr/bin:/bin:/opt/homebrew/bin"


def trusted_path(home=None):
    """TRUSTED_PATH, plus the operator's own `~/.local/bin` -- LAST.

    R1/M2: the four system directories alone did not hold this project's `gh`
    (installed under `~/.local/bin`, as `pip --user` and a release tarball both
    do), so `triage.py apply` and `reconcile_apply.py` refused outright on the
    owner's own workstation -- the triage-apply half of the filing SOP.

    This is a widening, not a loosening: both halves are FIXED strings over a
    HOME this process chose, never `os.environ["PATH"]`, so the CWE-427
    property is unchanged -- an attacker who can prepend a directory to PATH
    still cannot substitute the binary. Appended last so a system install
    always wins over a per-user one.
    """
    home = home if home is not None else os.path.expanduser("~")
    if not home:
        return TRUSTED_PATH          # never a CWD-relative `.local/bin`
    return os.pathsep.join([TRUSTED_PATH, os.path.join(home, ".local", "bin")])


def gh_bin(home=None):
    """The absolute `gh` to launch, resolved against `trusted_path` and nothing else.

    `home` is the HOME the child will run under, so the directory searched is
    the one the launch will actually see; it defaults to this process's.

    Refuses rather than falling back to the bare name: a bare `gh` handed to
    subprocess is resolved by exactly the search this function exists to
    replace, so a fallback would reopen the door on every machine where the
    trusted resolution failed.
    """
    searched = trusted_path(home)
    found = shutil.which("gh", path=searched)
    if not found:
        raise RuntimeError(
            "gh is not on the trusted PATH (%s), and this tool will not resolve "
            "it through the ambient environment: install gh there, or run the "
            "mutation by hand" % searched)
    return found


def declared_gh_config_dir(config_path=None):
    """Legacy configuration's `gh_config_dir`, or None when it declares none.

    #486: the DECLARED account, so every gh subprocess the tools spawn uses it
    instead of whatever ambient credential the shell happens to carry (the
    thebeamishsociety wrong-account incident: default cred lacked push, the 404
    was swallowed). Raises on a corrupt/unreadable config or a non-string
    value, so we fail closed rather than silently inherit the wrong credential
    (#1101). A config that is absent, or names no directory, is not a failure
    -- it is the caller saying nothing, and `gh_env` decides what that means.
    """
    if config_path is None:
        config_path = CONFIG_PATH   # late-bound so tests/patches can retarget
    try:
        with open(config_path, encoding="utf-8") as fh:
            cfg = json.load(fh)
    except FileNotFoundError:
        return None
    except (OSError, ValueError) as exc:
        raise ValueError(f"corrupt or unreadable panopticon config ({config_path}): {exc}") from exc
    if not isinstance(cfg, dict):
        raise ValueError(f"invalid config {config_path}: expected object")
    d = cfg.get("gh_config_dir")
    if d is None:
        return None
    if not isinstance(d, str) or not d:
        raise ValueError(f"invalid gh_config_dir in {config_path!r}: expected string, got {d!r}")
    return d


# What gh itself needs to decide WHICH ACCOUNT it is, and nothing else. Both
# are gh's own documented variables; everything else the shell carries
# (credentials for other services, a hostile PATH) stays out.
_GH_AUTH_PASSTHROUGH = ("GH_TOKEN",)


def gh_env(config_path=None):
    """The environment every gh subprocess runs under: BUILT, never copied.

    #1650: this used to return None (inherit everything) when no config
    declared a directory, and otherwise `dict(os.environ)` with one key
    changed -- so PATH passed through untouched in BOTH branches, and PATH is
    what chooses the binary.

    R1/M3: building it must not go so far as to lose the ACCOUNT. The repo's
    own config holds `{"gh_config_dir": null}`, so an operator exporting
    `GH_CONFIG_DIR=~/.config/gh-psyberone` was relying on inheritance; dropping
    it leaves gh on `$HOME/.config/gh`, the DEFAULT credential, which is the
    wrong account for this project -- exactly the incident #486 exists to
    prevent, reintroduced by the hardening meant to protect it. So:
    GH_CONFIG_DIR is declared-in-config first, ambient second, unset last.
    gh's own `GH_TOKEN` is carried through ONLY when no directory is in
    effect: gh lets an ambient token override stored credentials, so carrying
    it beside a declared directory would let the shell's account beat the
    declared one -- the precedence #486 forbids.

    Everything else is built: HOME (gh's own state) and the trusted PATH.
    """
    home = os.path.expanduser("~")
    env = {"HOME": home, "PATH": trusted_path(home)}
    directory = declared_gh_config_dir(config_path) or os.environ.get("GH_CONFIG_DIR")
    if directory:
        env["GH_CONFIG_DIR"] = os.path.expanduser(directory)
        return env
    for name in _GH_AUTH_PASSTHROUGH:
        value = os.environ.get(name)
        if value:
            env[name] = value
    return env


# Hard bound on each gh invocation so a hung gh (interactive auth prompt on a
# misconfigured GH_CONFIG_DIR, a stalled TLS handshake, a GitHub outage) engages
# the retry/backoff below instead of blocking the unattended pipeline (#1103).
GH_TIMEOUT = 120


def _run_gh(argv, **kwargs):
    """`subprocess.run` with argv[0] replaced by the trusted absolute `gh`.

    The call sites build `["gh", ...]` because that is what the command reads
    as; the resolution happens HERE, once, so no call site can spell it
    differently (#1650). Resolved against the HOME the child will actually run
    under, so the binary looked for and the binary launched agree.
    """
    home = (kwargs.get("env") or {}).get("HOME")
    return subprocess.run([gh_bin(home)] + list(argv)[1:], **kwargs)


def default_gh_runner():
    """subprocess.run partial carrying the config-declared env (#486), a hard
    timeout (#1103) and the trusted-path resolution (#1650). Kept as a factory
    so gh_env is re-read per call site construction -- tests inject their own
    runner and never hit this."""
    return functools.partial(_run_gh, env=gh_env(), timeout=GH_TIMEOUT)


# One retry ladder for every gh subprocess call in the repo. It used to be two:
# this module's gh() and file_issues.create() each carried the same 5-attempt,
# 60*attempt, RATE_HINTS-sniffing loop, and they had ALREADY diverged in
# behaviour (#run11 ARC-A3A / QAL-D1A). file_fixmes.py's own comment records the
# same drift happening once before.
GH_ATTEMPTS = 5


def backoff_seconds(attempt):
    """The project's single retry schedule."""
    return 60 * attempt


def _backoff(message, attempt, sleep):
    seconds = backoff_seconds(attempt)
    print("%s; backing off %ds" % (message, seconds), file=sys.stderr, flush=True)
    sleep(seconds)


def attempt_gh(argv, runner, sleep, retry_empty_stdout=False, on_empty=None,
               what=None):
    """Run `argv` through the shared gh retry ladder.

    Returns (outcome, payload), one of:
      ("ok", stdout) ("adopted", value) ("timeout", None) ("empty", None)
      ("failed", stderr)

    The ladder lives here alone -- attempt cap, backoff schedule, rate-limit
    heuristics, TimeoutExpired handling. What EXHAUSTION MEANS stays with the
    caller, because the two callers genuinely disagree: gh() raises so a caller
    cannot silently continue, while file_issues.create() returns None so the
    finding is left un-ledgered for a resumed run. That is why this reports an
    outcome instead of deciding one.

    `on_empty` is consulted when an attempt exits 0 with NO stdout, before
    backing off: return a value to adopt as the result, or None to keep retrying.
    """
    label = what or " ".join(argv[:4])
    for attempt in range(1, GH_ATTEMPTS + 1):
        final = attempt == GH_ATTEMPTS
        try:
            r = runner(argv, capture_output=True, text=True)
        except subprocess.TimeoutExpired:
            # Without a timeout the retry logic never engages, because
            # subprocess.run never returns; a hang is a retryable failure (#1103).
            if final:
                return "timeout", None
            _backoff("%s timed out (attempt %d)" % (label, attempt), attempt, sleep)
            continue
        if r.returncode == 0:
            if not retry_empty_stdout or (r.stdout or "").strip():
                return "ok", r.stdout
            if on_empty is not None:
                adopted = on_empty()
                if adopted is not None:
                    return "adopted", adopted
            if final:
                return "empty", None
            _backoff("empty stdout on rc=0 (attempt %d)" % attempt, attempt, sleep)
            continue
        err = (r.stderr or "").strip()
        if any(h in err.lower() for h in RATE_HINTS) and not final:
            _backoff("rate limited (attempt %d)" % attempt, attempt, sleep)
            continue
        return "failed", err
    return "failed", "exhausted %d attempts" % GH_ATTEMPTS


def gh(argv, runner=None, sleep=time.sleep):
    if runner is None:
        runner = default_gh_runner()
    outcome, payload = attempt_gh(argv, runner, sleep)
    if outcome == "ok":
        return payload
    label = " ".join(argv[:4])
    if outcome == "timeout":
        raise RuntimeError("%s timed out after retries" % label)
    raise RuntimeError("%s failed: %s" % (label, payload))
