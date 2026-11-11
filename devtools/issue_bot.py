"""The gh plumbing every issue-reporting workflow script shares (#3563).

Moved out of `report_pin_bump.py` (#3420) so it exists once:

- `run_gh` runs only the argv shapes the CALLER allows, with a trusted gh and no
  ambient PATH, interpreter or loader hooks; the child sees GH_TOKEN (or, when
  run by hand, GH_CONFIG_DIR) and nothing else from the environment;
- `error_text` turns gh's stderr into one bounded, inert, redacted line;
- `bot_issues` lists issues authored by the workflow bot, checked twice: by the
  REST `creator` filter and again per entry, so a look-alike filed by anyone
  else is never edited or closed. A full page is refused rather than guessed past.

Each caller keeps its own command allowlist. None of them may allow `gh issue
reopen`: a closed issue stays closed.
"""
from __future__ import annotations

import functools
import json
import os
from pathlib import Path
import re
import subprocess
from typing import Callable

# The checked-out repository supplies this audited resolver, but it is never
# searched for the gh executable.
from scripts.executable import resolve
from scripts import inert
from scripts import redact

TRUSTED_PATH = "/usr/local/bin:/usr/bin:/bin:/opt/homebrew/bin"
PROCESS_TIMEOUT = 120
BOT = "github-actions[bot]"
# The most of a gh error a script prints (#3420). The text is gh's, not ours,
# so it is redacted and made inert before it is cut.
ERROR_TEXT_CAP = 600
# One lookup page. A full page could hide an existing issue, and a run that missed it would
# file a duplicate, so a full page is refused rather than guessed past (#3557 review).
PAGE = 100

REPO = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
NUMBER = re.compile(r"[1-9][0-9]{0,9}\Z")
_STATES = ("open", "closed")
_SINCE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T00:00:00Z\Z")


def lookup(repo: str, state: str = "open", since: str | None = None) -> str:
    """The one REST path a bot-issue lookup uses."""
    if not REPO.fullmatch(repo or "") or state not in _STATES:
        raise RuntimeError("invalid issue lookup")
    if since is not None and not _SINCE.fullmatch(since):
        raise RuntimeError("invalid issue lookup")
    return ("repos/%s/issues?state=%s&creator=github-actions%%5Bbot%%5D%s&per_page=%d"
            % (repo, state, "" if since is None else "&since=" + since, PAGE))


def is_lookup(argument: str, state: str = "open", since: bool = False) -> bool:
    """Whether `argument` is exactly a `lookup()` path, for a caller's allowlist."""
    pattern = (r"repos/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/issues\?state=%s"
               r"&creator=github-actions%%5Bbot%%5D%s&per_page=%d"
               % (re.escape(state),
                  r"&since=[0-9]{4}-[0-9]{2}-[0-9]{2}T00:00:00Z" if since else "", PAGE))
    return bool(re.fullmatch(pattern, argument))


def run_gh(command: list[str], cwd: Path,
           allowed: Callable[[list[str]], bool]) -> subprocess.CompletedProcess[str]:
    """Run one of the caller's allowed gh commands with a trusted gh and GH_TOKEN.

    Even a mistaken new call site cannot turn this into a generic process
    runner; the child gets no ambient PATH or interpreter/loader startup hooks.
    """
    if not (isinstance(command, list) and command and command[0] == "gh"
            and all(isinstance(a, str) and a for a in command)
            and "reopen" not in command[1:3] and allowed(command)):
        raise RuntimeError("unexpected issue-report executable or arguments")
    selected = resolve(command[0], cwd, path=TRUSTED_PATH)
    env = {"HOME": os.path.expanduser("~"), "PATH": selected.path_env, "LC_ALL": "C"}
    if os.environ.get("GH_TOKEN"):
        env["GH_TOKEN"] = os.environ["GH_TOKEN"]
    elif os.environ.get("GH_CONFIG_DIR"):
        env["GH_CONFIG_DIR"] = os.environ["GH_CONFIG_DIR"]
    # Same bounded, injectable subprocess.run partial pattern as
    # devtools/file_issues.py; the executable is absolute and the environment
    # is built above rather than inherited from the checkout.
    runner = functools.partial(subprocess.run, cwd=cwd, env=env,
                               timeout=PROCESS_TIMEOUT, text=True,
                               capture_output=True, check=False)
    try:
        return runner([selected.path, *command[1:]])
    except subprocess.TimeoutExpired:
        raise RuntimeError("gh timed out") from None


def error_text(text: str | None) -> str:
    """A gh error as one bounded, inert line (#3420).

    The workflow token is masked by value and known secret shapes by
    `redact`. Every control character, escape and line break is spelled
    (`\\x1b`, `\\x0a`), so the text can't style the log or start a new
    line, such as an Actions `::` command. The output is at most
    ERROR_TEXT_CAP characters, and a cut never splits a spelling.
    """
    raw = (text or "").strip()
    token = os.environ.get("GH_TOKEN", "")
    if token:
        raw = raw.replace(token, "[REDACTED]")
    raw = redact.redact_diagnostic(raw, ERROR_TEXT_CAP + 1)
    pieces = [inert.spelled(ord(ch)) if ord(ch) in inert.INERT_ESCAPE_CODE_POINTS
              else ch for ch in raw]
    if sum(map(len, pieces)) > ERROR_TEXT_CAP:
        kept, used = [], 0
        for piece in pieces:
            if used + len(piece) > ERROR_TEXT_CAP - 3:
                break
            kept.append(piece)
            used += len(piece)
        pieces = kept + ["..."]
    return "".join(pieces) or "(no error text)"


def checked(command: list[str], cwd: Path, runner) -> str:
    """gh's stdout, or a RuntimeError naming the subcommand and gh's inert error."""
    result = runner(command, cwd)
    if result.returncode:
        raise RuntimeError("gh %s failed: %s" % (command[1], error_text(result.stderr)))
    return result.stdout


def bot_issues(repo: str, cwd: Path, runner, matches: Callable[[str], bool], *,
               state: str = "open", since: str | None = None) -> list[dict]:
    """Issues authored by the workflow bot whose title `matches`, newest first.

    The REST `creator` filter does the author check server-side and each entry
    is checked again here, so a look-alike issue opened by anyone else never
    counts: it can neither silence a report nor be edited or closed by it.
    """
    raw = checked(["gh", "api", lookup(repo, state, since)], cwd, runner)
    try:
        entries = json.loads(raw)
    except ValueError:
        raise RuntimeError("gh api returned malformed issue JSON") from None
    if not isinstance(entries, list):
        raise RuntimeError("gh api returned malformed issue JSON")
    if len(entries) >= PAGE:
        raise RuntimeError("the issue lookup returned a full page of %d; refusing to report "
                           "rather than risk filing a duplicate" % PAGE)
    found = []
    for entry in entries:
        if not isinstance(entry, dict) or "pull_request" in entry:
            continue
        user = entry.get("user")
        number, title = entry.get("number"), entry.get("title")
        if (isinstance(user, dict) and user.get("login") == BOT and user.get("type") == "Bot"
                and isinstance(number, int) and not isinstance(number, bool) and number > 0
                and isinstance(title, str) and matches(title)):
            found.append({"number": number, "title": title, "body": entry.get("body") or ""})
    return sorted(found, key=lambda issue: issue["number"], reverse=True)
