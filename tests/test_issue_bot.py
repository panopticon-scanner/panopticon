"""#3563: `devtools/issue_bot.py`, the gh plumbing the issue-reporting scripts share.

Behaviour moved here from report_pin_bump (#3420) without change; these pins hold
it on its own, with injected gh runners and no network.
"""
import json
import subprocess
from types import SimpleNamespace

import pytest

import issue_bot

REPO = "owner/repo"
BOT_USER = {"login": "github-actions[bot]", "type": "Bot"}


def entry(number, title, user=BOT_USER, **extra):
    return dict({"number": number, "title": title, "user": user, "body": "b%s" % number}, **extra)


def runner_for(entries, seen=None):
    def run(command, cwd):
        if seen is not None:
            seen.append(command)
        return subprocess.CompletedProcess(command, 0, json.dumps(entries), "")
    return run


def lookup_titles(entries, matches=lambda t: t.startswith("want"), **kw):
    return [i["title"] for i in issue_bot.bot_issues(REPO, ".", runner_for(entries), matches,
                                                      **kw)]


# --- the lookup path ----------------------------------------------------------------------------
def test_the_lookup_path_is_creator_filtered_and_one_page():
    assert issue_bot.lookup(REPO) == (
        "repos/owner/repo/issues?state=open&creator=github-actions%5Bbot%5D&per_page=100")
    assert issue_bot.lookup(REPO, "closed", "2026-12-01T00:00:00Z") == (
        "repos/owner/repo/issues?state=closed&creator=github-actions%5Bbot%5D"
        "&since=2026-12-01T00:00:00Z&per_page=100")


@pytest.mark.parametrize("args", [("a b",), (REPO, "all"), (REPO, "open", "2026-12-01"),
                                  (REPO, "closed", "2026-12-01T05:00:00Z"), ("",)])
def test_a_lookup_out_of_shape_is_refused(args):
    with pytest.raises(RuntimeError, match="invalid issue lookup"):
        issue_bot.lookup(*args)


def test_is_lookup_matches_exactly_the_built_paths():
    assert issue_bot.is_lookup(issue_bot.lookup(REPO))
    assert issue_bot.is_lookup(issue_bot.lookup(REPO, "closed", "2026-12-01T00:00:00Z"),
                               "closed", since=True)
    assert not issue_bot.is_lookup(issue_bot.lookup(REPO, "closed", "2026-12-01T00:00:00Z"))
    assert not issue_bot.is_lookup(issue_bot.lookup(REPO), "closed", since=True)
    assert not issue_bot.is_lookup(issue_bot.lookup(REPO) + "&state=all")
    assert not issue_bot.is_lookup(issue_bot.lookup(REPO).replace("per_page=100", "per_page=5"))


# --- bot_issues: the negative controls ----------------------------------------------------------
def test_only_bot_authored_issues_with_a_matching_title_count_newest_first():
    entries = [entry(3, "want a"), entry(9, "want b"), entry(5, "other")]
    assert lookup_titles(entries) == ["want b", "want a"]


@pytest.mark.parametrize("user", [
    {"login": "github-actions[bot]", "type": "User"},
    {"login": "someone", "type": "Bot"},
    {"login": "github-actions", "type": "Bot"},
    "github-actions[bot]", None,
])
def test_a_look_alike_author_never_counts(user):
    assert lookup_titles([entry(4, "want x", user=user)]) == []


def test_a_pull_request_row_never_counts():
    assert lookup_titles([entry(4, "want x", pull_request={"url": "u"})]) == []


@pytest.mark.parametrize("number", [0, -1, True, "4", None, 1.5])
def test_a_malformed_number_never_counts(number):
    assert lookup_titles([entry(number, "want x")]) == []


def test_a_title_mismatch_or_non_string_never_counts():
    assert lookup_titles([entry(4, "nope want"), entry(5, None), entry(6, ["want"])]) == []


@pytest.mark.parametrize("count, refused", [(issue_bot.PAGE - 1, False), (issue_bot.PAGE, True)])
def test_a_full_page_is_refused(count, refused):
    entries = [entry(n, "other %d" % n) for n in range(1, count + 1)]
    if refused:
        with pytest.raises(RuntimeError, match="full page of 100"):
            lookup_titles(entries)
    else:
        assert lookup_titles(entries) == []


@pytest.mark.parametrize("raw", ["not json", "{}", "null"])
def test_malformed_json_is_an_error_not_absence(raw):
    def run(command, cwd):
        return subprocess.CompletedProcess(command, 0, raw, "")
    with pytest.raises(RuntimeError, match="malformed issue JSON"):
        issue_bot.bot_issues(REPO, ".", run, lambda t: True)


def test_a_failed_lookup_is_red_and_inert():
    def run(command, cwd):
        return subprocess.CompletedProcess(command, 1, "", "boom\n::error::forged")
    with pytest.raises(RuntimeError, match=r"gh api failed: boom\\x0a::error::forged"):
        issue_bot.bot_issues(REPO, ".", run, lambda t: True)


def test_the_state_and_since_reach_the_lookup():
    seen = []
    issue_bot.bot_issues(REPO, ".", runner_for([], seen), lambda t: True, state="closed",
                         since="2026-12-01T00:00:00Z")
    assert seen == [["gh", "api", issue_bot.lookup(REPO, "closed", "2026-12-01T00:00:00Z")]]


# --- run_gh -------------------------------------------------------------------------------------
def test_run_gh_refuses_what_the_caller_does_not_allow(monkeypatch, tmp_path):
    monkeypatch.setattr(issue_bot, "resolve", lambda *_a, **_k: pytest.fail("resolved"))
    for command in (["gh", "api", "x"], ["sh", "-c", "x"], ["gh", ""], "gh api x", []):
        with pytest.raises(RuntimeError, match="unexpected"):
            issue_bot.run_gh(command, tmp_path, lambda c: c == ["gh", "ok"])


def test_run_gh_never_reopens_even_when_a_caller_allows_it(monkeypatch, tmp_path):
    monkeypatch.setattr(issue_bot, "resolve", lambda *_a, **_k: pytest.fail("resolved"))
    for command in (["gh", "issue", "reopen", "7"], ["gh", "reopen"]):
        with pytest.raises(RuntimeError, match="unexpected"):
            issue_bot.run_gh(command, tmp_path, lambda c: True)


def test_run_gh_uses_a_trusted_gh_and_only_the_token(monkeypatch, tmp_path):
    monkeypatch.setenv("GH_TOKEN", "inert-test-token")
    monkeypatch.setenv("GH_CONFIG_DIR", str(tmp_path / "wrong-account"))
    monkeypatch.setenv("LD_PRELOAD", str(tmp_path / "evil.so"))
    monkeypatch.setattr(issue_bot, "resolve", lambda program, cwd, path: SimpleNamespace(
        path="/usr/bin/gh", path_env="/usr/bin:/bin"))
    seen = []

    def fake_run(argv, **kwargs):
        seen.append((argv, kwargs))
        return subprocess.CompletedProcess(argv, 0, "ok", "")
    monkeypatch.setattr(issue_bot.subprocess, "run", fake_run)
    assert issue_bot.run_gh(["gh", "ok"], tmp_path, lambda c: True).stdout == "ok"
    argv, kwargs = seen[0]
    assert argv == ["/usr/bin/gh", "ok"]
    assert set(kwargs["env"]) == {"HOME", "PATH", "LC_ALL", "GH_TOKEN"}
    assert kwargs["timeout"] == issue_bot.PROCESS_TIMEOUT


def test_run_gh_falls_back_to_the_config_dir_by_hand(monkeypatch, tmp_path):
    monkeypatch.delenv("GH_TOKEN", raising=False)
    monkeypatch.setenv("GH_CONFIG_DIR", str(tmp_path / "account"))
    monkeypatch.setattr(issue_bot, "resolve", lambda program, cwd, path: SimpleNamespace(
        path="/usr/bin/gh", path_env="/usr/bin:/bin"))
    seen = []
    monkeypatch.setattr(issue_bot.subprocess, "run", lambda argv, **kw: seen.append(kw) or
                        subprocess.CompletedProcess(argv, 0, "", ""))
    issue_bot.run_gh(["gh", "ok"], tmp_path, lambda c: True)
    assert seen[0]["env"]["GH_CONFIG_DIR"] == str(tmp_path / "account")
    assert "GH_TOKEN" not in seen[0]["env"]


def test_error_text_masks_the_token_and_is_bounded(monkeypatch):
    monkeypatch.setenv("GH_TOKEN", "inert-test-token")
    shown = issue_bot.error_text("x inert-test-token \x1b" + "y" * 2000)
    assert "inert-test-token" not in shown and "\\x1b" in shown
    assert len(shown) <= issue_bot.ERROR_TEXT_CAP and shown.endswith("...")
    assert issue_bot.error_text("  ") == "(no error text)"
