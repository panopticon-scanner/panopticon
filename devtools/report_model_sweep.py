#!/usr/bin/env python3
"""Open or update the monthly model-list sweep issue (#3563).

Host model lists go stale as providers ship and retire models (the 2026-11-10
Gemini incident). The model-sweep workflow runs this on the 1st of each month.
It keeps ONE issue authored by `github-actions[bot]`, titled
`model-list sweep due: YYYY-MM` (UTC month):

- this month's issue open: its body is refreshed (a re-dispatch), and any
  duplicate of it is closed;
- this month's issue closed: a human finished the sweep, so nothing is
  reopened or filed;
- otherwise it is created.

Every older sweep issue still open is closed as superseded. The body lists each
model table with its `models-verified` date, stalest first, then every host's
role -> model rows, from devtools/model_inventory.py. It makes no provider API
calls (no keys in CI) and edits nothing: a human or a seat does the sweep and
opens the PR.
"""
from __future__ import annotations

import argparse
import datetime
import os
from pathlib import Path
import re
import subprocess
import sys

if __name__ == "__main__":  # run by path: puts skill/ on sys.path (#3505)
    import runpy
    runpy.run_path(os.path.join(os.path.dirname(os.path.realpath(__file__)), "_skill_bootstrap.py"))
import issue_bot
import model_inventory

TITLE_PREFIX = "model-list sweep due: "
LEAD = "The monthly model-list sweep is due."
BODY_CAP = 30000
_MONTH = re.compile(r"[0-9]{4}-(0[1-9]|1[0-2])\Z")
_TITLE = re.compile(r"model-list sweep due: [0-9]{4}-(0[1-9]|1[0-2])\Z")
SUPERSEDED = "Superseded by #%d, the %s sweep."
_SUPERSEDED = re.compile(r"Superseded by #[1-9][0-9]{0,9}, the [0-9]{4}-(0[1-9]|1[0-2]) sweep\.\Z")
DUPLICATE = "Duplicate of #%d; closing."
_DUPLICATE = re.compile(r"Duplicate of #[1-9][0-9]{0,9}; closing\.\Z")
_CREATED = re.compile(r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/issues/"
                      r"([1-9][0-9]{0,9})\Z")
CHECKLIST = (
    "Provider model lists and deprecation pages read for every host; the URLs and the date "
    "are in each table's `models-verified` marker.",
    "Retired or deprecated models replaced; the flagship and fast tiers are current.",
    "Alias vs pinned ID decided per host: an alias moves silently when the CLI updates.",
    "`KNOWN_MODELS` / `MODEL_ALIASES` in step with the profiles: every default allowlisted.",
    "A CHANGELOG line for each model change, since a model change can move findings.",
)


def _cell(value) -> str:
    return "-" if value in (None, "") else str(value).replace("|", "\\|")


def body(tables: list, today: datetime.date) -> str:
    """The issue body: tables stalest first, every model row, the checklist."""
    lines = [LEAD, "",
             "Check each table below against its provider's current model list and "
             + "deprecation pages, update it in a reviewed PR, and refresh its "
             + "`models-verified` marker (the grammar is in `devtools/model_inventory.py`). "
             + "Close this issue when the sweep is done; next month's run opens a new one.",
             "", "## Tables, stalest first", "",
             "| table | verified | age (days) | where | sources |", "|---|---|---|---|---|"]
    for t in model_inventory.stalest_first(tables):
        marker = t.marker
        lines.append("| `%s` | %s | %s | `%s:%d` | %s |" % (
            t.name, marker.date.isoformat() if marker else "**unverified**",
            max(0, (today - marker.date).days) if marker else "-", t.path, t.line,
            _cell(" ".join(marker.urls)) if marker else "-"))
    lines += ["", "## Models", "", "| host | role | model | allowlisted | detail |",
              "|---|---|---|---|---|"]
    for t in tables:
        for row in t.rows:
            lines.append("| %s | %s | %s | %s | %s |" % (
                _cell(row["host"]), _cell(row["role"]),
                "`%s`" % _cell(row["model"]) if row["model"] else "(inherit)",
                _cell(row["allowlisted"]), _cell(row["detail"])))
    lines += ["", "## Checklist", ""] + ["- [ ] " + item for item in CHECKLIST]
    lines += ["", "Filed by the model-sweep workflow (#3563). It never reopens an issue."]
    text = "\n".join(lines)
    if not _body_ok(text):
        raise RuntimeError("the sweep issue body failed validation; refusing to report")
    return text


def _body_ok(text: str) -> bool:
    return (isinstance(text, str) and len(text) <= BODY_CAP and text.startswith(LEAD)
            and not any(ord(ch) < 32 and ch != "\n" for ch in text))


def _allowed_command(command: list[str]) -> bool:
    """Only the gh argv shapes this script emits; data stays in its own arguments."""
    if not isinstance(command, list) or not all(isinstance(a, str) and a for a in command):
        return False
    repo, number = issue_bot.REPO.fullmatch, issue_bot.NUMBER.fullmatch
    if command[:2] == ["gh", "api"] and len(command) == 3:
        return (issue_bot.is_lookup(command[2], "open")
                or issue_bot.is_lookup(command[2], "closed", since=True))
    if command[:3] == ["gh", "issue", "create"] and len(command) == 9:
        return (command[3] == "--repo" and bool(repo(command[4]))
                and command[5] == "--title" and bool(_TITLE.fullmatch(command[6]))
                and command[7] == "--body" and _body_ok(command[8]))
    if command[:3] == ["gh", "issue", "edit"] and len(command) == 8:
        return (bool(number(command[3])) and command[4] == "--repo" and bool(repo(command[5]))
                and command[6] == "--body" and _body_ok(command[7]))
    if command[:3] == ["gh", "issue", "close"] and len(command) == 8:
        return (bool(number(command[3])) and command[4] == "--repo" and bool(repo(command[5]))
                and command[6] == "--comment"
                and bool(_SUPERSEDED.fullmatch(command[7]) or _DUPLICATE.fullmatch(command[7])))
    return False


def _run(command: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    """Run only this script's gh commands, through issue_bot's trusted runner."""
    return issue_bot.run_gh(command, cwd, _allowed_command)


def report(repo: str, month: str, text: str, *, cwd: Path = Path("."), runner=None) -> str:
    """Converge the bot's sweep issues on this month's; returns what was done."""
    runner = runner or _run
    if not issue_bot.REPO.fullmatch(repo or ""):
        raise RuntimeError("invalid repository")
    if not _MONTH.fullmatch(month or ""):
        raise RuntimeError("invalid month")
    title = TITLE_PREFIX + month
    sweeps = issue_bot.bot_issues(repo, cwd, runner, lambda t: bool(_TITLE.fullmatch(t)))
    current = [issue for issue in sweeps if issue["title"] == title]
    older = [issue for issue in sweeps if issue["title"] != title]
    done = []
    if current:
        keep, *duplicates = current
        target = keep["number"]
        for issue in duplicates:
            issue_bot.checked(["gh", "issue", "close", str(issue["number"]), "--repo", repo,
                               "--comment", DUPLICATE % target], cwd, runner)
        if keep["body"] == text:
            done.append("issue #%d is current" % target)
        else:
            issue_bot.checked(["gh", "issue", "edit", str(target), "--repo", repo,
                               "--body", text], cwd, runner)
            done.append("updated issue #%d" % target)
        if duplicates:
            done.append("closed %d duplicate(s)" % len(duplicates))
    else:
        closed = issue_bot.bot_issues(repo, cwd, runner, lambda t: t == title,
                                      state="closed", since=month + "-01T00:00:00Z")
        if closed:
            target = closed[0]["number"]
            done.append("the %s sweep is done (#%d closed); nothing filed" % (month, target))
        else:
            out = issue_bot.checked(["gh", "issue", "create", "--repo", repo, "--title", title,
                                     "--body", text], cwd, runner)
            created = _CREATED.fullmatch(out.strip())
            if not created:
                raise RuntimeError("gh issue create printed no issue URL; older sweep issues "
                                   "were left open")
            target = int(created.group(1))
            done.append("opened issue #%d" % target)
    for issue in older:
        issue_bot.checked(["gh", "issue", "close", str(issue["number"]), "--repo", repo,
                           "--comment", SUPERSEDED % (target, month)], cwd, runner)
    if older:
        done.append("closed %d older sweep issue(s)" % len(older))
    return "; ".join(done)


def _summary(month: str, outcome: str) -> None:
    line = "model-list sweep %s: %s" % (month, outcome)
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if path:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write("- %s\n" % line)
    print("::notice title=model-list sweep::%s" % line)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.parse_args(argv)
    today = datetime.datetime.now(datetime.timezone.utc).date()
    month = today.strftime("%Y-%m")
    try:
        text = body(model_inventory.inventory(today=today), today)
        outcome = report(os.environ.get("GITHUB_REPOSITORY", ""), month, text)
        _summary(month, outcome)
    except (RuntimeError, OSError, ValueError, model_inventory.yaml.YAMLError) as exc:
        print("report-model-sweep: %s" % issue_bot.error_text(str(exc)), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
