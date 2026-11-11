"""#3563: `devtools/report_model_sweep.py`, the monthly model-list sweep issue.

The gh runner is a fake that keeps issue state; no network, no provider calls.
"""
import datetime
import json
import subprocess

import pytest

import issue_bot
import model_inventory as mi
import report_model_sweep as rms

REPO = "owner/repo"
MONTH = "2026-12"
TITLE = "model-list sweep due: 2026-12"
BOT = {"login": "github-actions[bot]", "type": "Bot"}
TODAY = datetime.date(2026, 12, 1)


def body_text(extra=""):
    return rms.LEAD + "\n\nbody" + extra


class FakeGh:
    """Open and closed issues; every command must pass the script's own allowlist."""

    def __init__(self, open_issues=(), closed=(), fail=None, create_out=None):
        self.open = [dict(i) for i in open_issues]
        self.closed = [dict(i) for i in closed]
        self.calls = []
        self.fail = fail
        self.create_out = create_out
        self.next = 500

    def __call__(self, command, cwd):
        assert rms._allowed_command(command), command
        self.calls.append(command)
        if self.fail and command[:len(self.fail[0])] == self.fail[0]:
            return subprocess.CompletedProcess(command, 1, "", self.fail[1])
        if command[1] == "api":
            rows = self.closed if "state=closed" in command[2] else self.open
            return subprocess.CompletedProcess(command, 0, json.dumps(rows), "")
        if command[2] == "create":
            self.next += 1
            self.open.append(issue(self.next, command[6], command[8]))
            out = self.create_out if self.create_out is not None else (
                "https://github.com/%s/issues/%d\n" % (REPO, self.next))
            return subprocess.CompletedProcess(command, 0, out, "")
        number = int(command[3])
        if command[2] == "edit":
            next(i for i in self.open if i["number"] == number)["body"] = command[7]
        if command[2] == "close":
            row = next(i for i in self.open if i["number"] == number)
            self.open.remove(row)
            self.closed.append(dict(row, comment=command[7]))
        return subprocess.CompletedProcess(command, 0, "", "")

    def writes(self):
        return [c for c in self.calls if c[1] != "api"]


def issue(number, title, body="old", user=BOT):
    return {"number": number, "title": title, "body": body, "user": user}


def run(gh, text=None):
    return rms.report(REPO, MONTH, text or body_text(), runner=gh)


# --- convergence --------------------------------------------------------------------------------
def test_a_first_run_opens_this_months_issue():
    gh = FakeGh()
    assert run(gh) == "opened issue #501"
    assert gh.writes() == [["gh", "issue", "create", "--repo", REPO, "--title", TITLE,
                            "--body", body_text()]]


def test_a_new_month_opens_and_closes_last_months_as_superseded():
    gh = FakeGh([issue(40, "model-list sweep due: 2026-11")])
    assert run(gh) == "opened issue #501; closed 1 older sweep issue(s)"
    assert gh.closed[0]["comment"] == "Superseded by #501, the 2026-12 sweep."
    assert [i["number"] for i in gh.open] == [501]


def test_a_redispatch_edits_this_months_issue_in_place():
    gh = FakeGh([issue(41, TITLE, "stale body")])
    assert run(gh) == "updated issue #41"
    assert gh.writes() == [["gh", "issue", "edit", "41", "--repo", REPO, "--body", body_text()]]


def test_an_unchanged_issue_is_left_alone():
    gh = FakeGh([issue(41, TITLE, body_text())])
    assert run(gh) == "issue #41 is current" and gh.writes() == []


def test_duplicates_of_this_months_issue_are_closed_onto_the_newest():
    gh = FakeGh([issue(41, TITLE), issue(45, TITLE)])
    assert run(gh) == "updated issue #45; closed 1 duplicate(s)"
    assert gh.closed[0]["number"] == 41 and gh.closed[0]["comment"] == "Duplicate of #45; closing."


def test_a_closed_sweep_this_month_is_done_never_reopened_or_refiled():
    gh = FakeGh(closed=[issue(41, TITLE)])
    assert run(gh) == "the 2026-12 sweep is done (#41 closed); nothing filed"
    assert gh.writes() == []
    assert not any("reopen" in c for c in gh.calls)


def test_a_done_sweep_still_closes_an_older_open_one():
    gh = FakeGh([issue(30, "model-list sweep due: 2026-10")], closed=[issue(41, TITLE)])
    assert run(gh).endswith("closed 1 older sweep issue(s)")
    assert gh.closed[-1]["comment"] == "Superseded by #41, the 2026-12 sweep."


def test_the_closed_lookup_is_bounded_to_this_month():
    gh = FakeGh()
    run(gh)
    assert ["gh", "api", issue_bot.lookup(REPO, "closed", "2026-12-01T00:00:00Z")] in gh.calls


def test_look_alikes_are_never_touched():
    gh = FakeGh([issue(41, TITLE, user={"login": "someone", "type": "User"}),
                 issue(42, "model-list sweep due: 2026-12 (copy)"),
                 issue(43, "pin-freshness: trivy 1.0.0 -> 2.0.0")])
    assert run(gh) == "opened issue #501"
    assert all(c[2] == "create" for c in gh.writes())


def test_a_create_without_an_issue_url_is_red_and_closes_nothing():
    gh = FakeGh([issue(40, "model-list sweep due: 2026-11")], create_out="created\n")
    with pytest.raises(RuntimeError, match="no issue URL"):
        run(gh)
    assert [c[2] for c in gh.writes()] == ["create"]


def test_a_failed_lookup_is_red_not_absence():
    gh = FakeGh(fail=(["gh", "api"], "unavailable"))
    with pytest.raises(RuntimeError, match="gh api failed: unavailable"):
        run(gh)
    assert gh.writes() == []


@pytest.mark.parametrize("repo, month", [("a b", MONTH), (REPO, "2026-13"), (REPO, "2026-1"),
                                         ("", MONTH)])
def test_bad_repo_or_month_is_refused(repo, month):
    with pytest.raises(RuntimeError, match="invalid"):
        rms.report(repo, month, body_text(), runner=FakeGh())


# --- the command allowlist ----------------------------------------------------------------------
@pytest.mark.parametrize("command", [
    ["gh", "issue", "reopen", "41", "--repo", REPO],
    ["gh", "api", issue_bot.lookup(REPO) + "&x=1"],
    ["gh", "api", "repos/owner/repo/issues?state=all&creator=github-actions%5Bbot%5D"
                  "&per_page=100"],
    ["gh", "issue", "create", "--repo", REPO, "--title", "model-list sweep due: 2026-13",
     "--body", body_text()],
    ["gh", "issue", "create", "--repo", REPO, "--title", TITLE, "--body", "not the lead"],
    ["gh", "issue", "create", "--repo", REPO, "--title", TITLE, "--body",
     body_text("\r\n::error::forged")],
    ["gh", "issue", "create", "--repo", REPO, "--title", TITLE, "--body",
     body_text("x" * rms.BODY_CAP)],
    ["gh", "issue", "edit", "41", "--repo", REPO, "--title", TITLE, "--body", body_text()],
    ["gh", "issue", "edit", "0", "--repo", REPO, "--body", body_text()],
    ["gh", "issue", "close", "41", "--repo", REPO, "--comment", "anything"],
    ["gh", "issue", "close", "41", "--repo", "a b", "--comment", "Duplicate of #4; closing."],
    ["gh", "pr", "create", "--repo", REPO], ["sh", "-c", "x"],
])
def test_the_allowlist_refuses_every_other_shape(command):
    assert not rms._allowed_command(command)


def test_the_runner_goes_through_issue_bot_with_this_allowlist(monkeypatch, tmp_path):
    monkeypatch.setattr(issue_bot, "resolve", lambda *_a, **_k: pytest.fail("resolved"))
    with pytest.raises(RuntimeError, match="unexpected"):
        rms._run(["gh", "issue", "reopen", "41"], tmp_path)


# --- the body -----------------------------------------------------------------------------------
def tables():
    def marker(date):
        return mi.Marker(date, ("https://example.test/models",)) if date else None
    profiles = mi.Table("profiles:gemini", "skill/reference/model-profiles.yml", 75,
                        marker(datetime.date(2026, 11, 10)),
                        rows=[{"host": "gemini", "role": "scout", "model": "gemini-a",
                               "detail": "", "allowlisted": "yes"},
                              {"host": "gemini", "role": "setup_scan", "model": None,
                               "detail": "", "allowlisted": "-"}])
    kimi = mi.Table("profiles:kimi", "skill/reference/model-profiles.yml", 2, None,
                    rows=[{"host": "kimi", "role": "scout", "model": "a|b",
                           "detail": "alias=k", "allowlisted": "-"}])
    return [profiles, kimi]


def test_the_body_lists_stalest_first_with_ages_rows_and_the_checklist():
    text = rms.body(tables(), TODAY)
    assert text.startswith(rms.LEAD) and rms._body_ok(text)
    kimi = text.index("| `profiles:kimi` | **unverified** | - |")
    gemini = text.index("| `profiles:gemini` | 2026-11-10 | 21 | "
                        "`skill/reference/model-profiles.yml:75` | https://example.test/models |")
    assert kimi < gemini
    assert "| gemini | scout | `gemini-a` | yes | - |" in text
    assert "| gemini | setup_scan | (inherit) | - | - |" in text
    assert "`a\\|b`" in text
    assert text.count("- [ ] ") == len(rms.CHECKLIST)


def test_a_body_that_fails_validation_is_refused():
    rows = tables()
    rows[1].rows[0]["model"] = "x\x1b[2J"
    with pytest.raises(RuntimeError, match="failed validation"):
        rms.body(rows, TODAY)


def test_the_real_inventory_renders_a_valid_body():
    assert rms._body_ok(rms.body(mi.inventory(today=TODAY), TODAY))


# --- main ---------------------------------------------------------------------------------------
def test_main_writes_a_summary_and_a_notice(monkeypatch, tmp_path, capsys):
    gh = FakeGh()
    monkeypatch.setattr(rms, "_run", gh)
    monkeypatch.setenv("GITHUB_REPOSITORY", REPO)
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(tmp_path / "s.md"))
    assert rms.main([]) == 0
    month = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m")
    assert (tmp_path / "s.md").read_text() == (
        "- model-list sweep %s: opened issue #501\n" % month)
    assert capsys.readouterr().out == (
        "::notice title=model-list sweep::model-list sweep %s: opened issue #501\n" % month)


def test_main_is_red_and_inert_on_failure(monkeypatch, capsys):
    monkeypatch.setattr(rms, "_run", FakeGh(fail=(["gh", "api"], "boom\n::error::x")))
    monkeypatch.setenv("GITHUB_REPOSITORY", REPO)
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    assert rms.main([]) == 1
    err = capsys.readouterr().err
    assert err.count("\n") == 1
    assert "boom\\x0a::error::x" in err


def test_main_is_red_on_a_bad_marker(monkeypatch, capsys):
    def bad(today=None):
        raise mi.MarkerError("profiles:x: malformed models-verified marker")
    monkeypatch.setattr(mi, "inventory", bad)
    monkeypatch.setattr(rms, "_run", lambda *_: pytest.fail("gh was called"))
    assert rms.main([]) == 1
    assert "malformed models-verified marker" in capsys.readouterr().err
