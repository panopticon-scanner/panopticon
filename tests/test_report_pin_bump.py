"""#3420: a verified pin bump is reported as one issue per family; gh is an injected fake."""
import json
import subprocess
from types import SimpleNamespace

import pytest

import bump_pins
from devtools import report_pin_bump as rpt


REPO = "owner/repo"
SHA_A, SHA_B = "a" * 64, "b" * 64
DIGEST_OLD, DIGEST_NEW = "sha256:" + "1" * 64, "sha256:" + "2" * 64
LOOKUP = "repos/owner/repo/issues?state=open&creator=github-actions%5Bbot%5D&per_page=100"


def bump(family="trivy", pinned="1.0.0", latest="2.0.0", values=None, stale=True):
    if values is None:
        values = {"AMD64": SHA_A, "ARM64": SHA_B} if family in ("trivy", "rustup") else {}
    return rpt.Bump(family, pinned, latest, values, stale)


def bot_issue(number, title, body="", **user):
    return {"number": number, "title": title, "body": body,
            "user": {"login": "github-actions[bot]", "type": "Bot", **user}}


class FakeGh:
    """Answers the issue lookup from `issues`; records every other call."""

    def __init__(self, issues=(), fail=None):
        self.issues, self.fail, self.calls = list(issues), fail, []

    def __call__(self, command, cwd):
        assert rpt._allowed_command(command), command     # every call is one the runner allows
        self.calls.append(command)
        if self.fail and command[:3] == self.fail[0]:
            return subprocess.CompletedProcess(command, 1, "", self.fail[1])
        if command[:2] == ["gh", "api"]:
            return subprocess.CompletedProcess(command, 0, json.dumps(self.issues), "")
        return subprocess.CompletedProcess(command, 0, "", "")

    def writes(self):
        return [c for c in self.calls if c[:2] != ["gh", "api"]]


# --- converging the family's issues ------------------------------------------------------
def test_a_stale_family_with_no_issue_opens_one():
    gh = FakeGh()
    b = bump()
    assert rpt.report(b, REPO, runner=gh) == "opened an issue"
    assert gh.writes() == [["gh", "issue", "create", "--repo", REPO, "--title",
                            "pin-freshness: trivy 1.0.0 -> 2.0.0", "--body", b.body]]
    assert "- AMD64 SHA256: `%s`" % SHA_A in b.body and "usual review" in b.body


def test_an_issue_for_an_older_version_is_edited_to_the_latest():
    gh = FakeGh([bot_issue(7, "pin-freshness: trivy 1.0.0 -> 1.5.0")])
    b = bump()
    assert rpt.report(b, REPO, runner=gh) == "updated issue #7"
    assert gh.writes() == [["gh", "issue", "edit", "7", "--repo", REPO, "--title", b.title,
                            "--body", b.body]]


def test_a_current_issue_is_left_alone():
    b = bump()
    gh = FakeGh([bot_issue(7, b.title, b.body)])
    assert rpt.report(b, REPO, runner=gh) == "issue #7 is current"
    assert gh.writes() == []


def test_duplicate_bot_issues_converge_to_the_newest():
    b = bump()
    gh = FakeGh([bot_issue(3, "pin-freshness: trivy 1.0.0 -> 1.1.0"),
                 bot_issue(9, "pin-freshness: trivy 1.0.0 -> 1.5.0"),
                 bot_issue(5, b.title, b.body)])
    assert rpt.report(b, REPO, runner=gh) == "updated issue #9; closed 2 duplicate(s)"
    assert gh.writes() == [
        ["gh", "issue", "close", "5", "--repo", REPO, "--comment", "Duplicate of #9; closing."],
        ["gh", "issue", "close", "3", "--repo", REPO, "--comment", "Duplicate of #9; closing."],
        ["gh", "issue", "edit", "9", "--repo", REPO, "--title", b.title, "--body", b.body]]


def test_a_caught_up_pin_closes_every_bot_issue_for_its_family():
    gh = FakeGh([bot_issue(4, "pin-freshness: trivy 1.0.0 -> 2.0.0"),
                 bot_issue(6, "pin-freshness: trivy 1.0.0 -> 1.5.0"),
                 bot_issue(8, "pin-freshness: rustup 1.0.0 -> 2.0.0")])
    assert rpt.report(bump(pinned="2.0.0", stale=False), REPO, runner=gh) == (
        "up to date; closed 2 issue(s)")
    assert gh.writes() == [
        ["gh", "issue", "close", "6", "--repo", REPO, "--comment", rpt.CAUGHT_UP],
        ["gh", "issue", "close", "4", "--repo", REPO, "--comment", rpt.CAUGHT_UP]]


def test_a_pin_moved_past_the_reported_version_closes_the_issue():
    # Reported 1.0.0 -> 1.5.0; a hand bump went straight to 2.0.0, which is now latest.
    gh = FakeGh([bot_issue(4, "pin-freshness: trivy 1.0.0 -> 1.5.0")])
    rpt.report(bump(pinned="2.0.0", latest="2.0.0", stale=False), REPO, runner=gh)
    assert gh.writes() == [["gh", "issue", "close", "4", "--repo", REPO,
                            "--comment", rpt.CAUGHT_UP]]


def test_up_to_date_with_no_issue_touches_nothing():
    gh = FakeGh()
    assert rpt.report(bump(pinned="2.0.0", stale=False), REPO, runner=gh) == "up to date"
    assert gh.writes() == []


@pytest.mark.parametrize("planted", [
    {"number": 2, "title": "pin-freshness: trivy 1.0.0 -> 9.9.9", "body": "",
     "user": {"login": "mallory", "type": "User"}},
    {"number": 2, "title": "pin-freshness: trivy 1.0.0 -> 9.9.9", "body": "",
     "user": {"login": "github-actions[bot]", "type": "User"}},
    {"number": 2, "title": "pin-freshness: trivy 1.0.0 -> 9.9.9", "body": "",
     "user": {"login": "dependabot[bot]", "type": "Bot"}},
    {"number": 2, "title": "pin-freshness: trivy 1.0.0 -> 9.9.9", "body": "",
     "user": {"login": "github-actions[bot]", "type": "Bot"}, "pull_request": {}},
    {"number": True, "title": "pin-freshness: trivy 1.0.0 -> 9.9.9", "body": "",
     "user": {"login": "github-actions[bot]", "type": "Bot"}},
    bot_issue(2, "pin-freshness: trivyish 1.0.0 -> 9.9.9"),
])
def test_a_look_alike_issue_neither_silences_the_report_nor_is_touched(planted):
    gh = FakeGh([planted])
    assert rpt.report(bump(), REPO, runner=gh) == "opened an issue"
    assert [c[2] for c in gh.writes()] == ["create"]
    assert not any("2" == c[3] for c in gh.writes())
    gh = FakeGh([planted])
    rpt.report(bump(pinned="2.0.0", stale=False), REPO, runner=gh)
    assert gh.writes() == []


def test_the_lookup_and_the_title_use_the_same_prefix():
    b = bump(family="rust-toolchain", pinned="1.99.0", latest="1.99.1")
    gh = FakeGh([bot_issue(3, b.title, b.body)])
    assert rpt.report(b, REPO, runner=gh) == "issue #3 is current"
    assert b.title.startswith(rpt.TITLE_PREFIX + "rust-toolchain ")


@pytest.mark.parametrize("raw", ["not json", "{}", '{"a": 1}'])
def test_a_malformed_lookup_fails_closed(raw):
    def runner(command, cwd):
        return subprocess.CompletedProcess(command, 0, raw, "")
    with pytest.raises(RuntimeError, match="malformed issue JSON"):
        rpt.report(bump(), REPO, runner=runner)


def test_an_invalid_repository_is_refused_before_gh():
    with pytest.raises(RuntimeError, match="invalid repository"):
        rpt.report(bump(), "", runner=lambda *_: pytest.fail("gh was called"))


# --- validation: nothing unvalidated from upstream reaches gh ------------------------------
@pytest.mark.parametrize("family, pinned, latest, values", [
    ("trivy", "1.0.0", "2.0.0\n::error::forged", {}),
    ("trivy", "1.0.0", "2.0.0 --repo evil/evil", {}),
    ("trivy", "1.0.0", "v2.0.0", {}),
    ("rust-toolchain", "1.0.0", "nightly", {}),
    ("tinyproxy", DIGEST_OLD, "sha256:" + "G" * 64, {}),
    ("tinyproxy", DIGEST_OLD, "2.0.0", {}),
    ("trivy", "1.0.0", "2.0.0", {"AMD64": "z" * 64}),
    ("trivy", "1.0.0", "2.0.0", {"AMD64\n": SHA_A}),
    ("trivy", "1.0.0\x1b[2J", "2.0.0", {}),
])
def test_a_hostile_upstream_value_is_refused(family, pinned, latest, values):
    with pytest.raises(RuntimeError, match="failed validation; refusing to report"):
        rpt.Bump(family, pinned, latest, values, True)


def test_a_hostile_latest_version_never_reaches_gh(tmp_path, monkeypatch, capsys):
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text("ARG TRIVY_VERSION=1.0.0\n")
    monkeypatch.setattr(bump_pins, "current_trivy_pin", lambda text: ("1.0.0", {}))
    monkeypatch.setattr(bump_pins, "latest_trivy_version", lambda: "2.0.0\n::error::forged")
    monkeypatch.setattr(bump_pins, "verified_trivy_shas", lambda v: {"AMD64": SHA_A})
    monkeypatch.setattr(rpt, "_run", lambda *_: pytest.fail("gh was called"))
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("GITHUB_REPOSITORY", REPO)
    assert rpt.main(["trivy"]) == 1
    err = capsys.readouterr().err
    assert "refusing to report" in err and "::error::forged" not in err


def test_verification_runs_before_any_report(tmp_path, monkeypatch, capsys):
    (tmp_path / "Dockerfile").write_text("")
    monkeypatch.setattr(bump_pins, "current_trivy_pin", lambda text: ("1.0.0", {}))
    monkeypatch.setattr(bump_pins, "latest_trivy_version", lambda: "2.0.0")

    def refuse(version):
        raise RuntimeError("Trivy 2.0.0 AMD64: published sha256 differs from archive")
    monkeypatch.setattr(bump_pins, "verified_trivy_shas", refuse)
    monkeypatch.setattr(rpt, "_run", lambda *_: pytest.fail("gh was called"))
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("GITHUB_REPOSITORY", REPO)
    assert rpt.main(["trivy"]) == 1
    assert "published sha256 differs" in capsys.readouterr().err


def _patch_family(monkeypatch, family, pinned, latest, shas=None):
    if family == "rustup":
        monkeypatch.setattr(bump_pins, "current_rustup_pin",
                            lambda text: (pinned, {"AMD64": SHA_A, "ARM64": SHA_A}))
        monkeypatch.setattr(bump_pins, "latest_rustup_version", lambda: latest)
        monkeypatch.setattr(bump_pins, "verified_rustup_shas", lambda v: shas)
    elif family == "trivy":
        monkeypatch.setattr(bump_pins, "current_trivy_pin",
                            lambda text: (pinned, {"AMD64": SHA_A, "ARM64": SHA_A}))
        monkeypatch.setattr(bump_pins, "latest_trivy_version", lambda: latest)
        monkeypatch.setattr(bump_pins, "verified_trivy_shas", lambda v: shas)
    elif family == "rust-toolchain":
        monkeypatch.setattr(bump_pins, "current_rust_toolchain_pin", lambda text: pinned)
        monkeypatch.setattr(bump_pins, "latest_rust_toolchain_version", lambda: latest)
    else:
        monkeypatch.setattr(bump_pins, "current_proxy_digest", lambda text: pinned)
        monkeypatch.setattr(bump_pins, "latest_proxy_digest", lambda: latest)


@pytest.mark.parametrize("family, pinned, latest, shas, stale", [
    ("rustup", "1.0.0", "1.1.0", {"AMD64": SHA_B, "ARM64": SHA_B}, True),
    ("rustup", "1.1.0", "1.1.0", None, False),
    ("trivy", "1.0.0", "1.1.0", {"AMD64": SHA_B, "ARM64": SHA_B}, True),
    ("trivy", "1.1.0", "1.1.0", {"AMD64": SHA_A, "ARM64": SHA_A}, False),
    ("trivy", "1.1.0", "1.1.0", {"AMD64": SHA_B, "ARM64": SHA_A}, True),   # re-published
    ("rust-toolchain", "1.99.0", "1.99.1", None, True),
    ("rust-toolchain", "1.99.1", "1.99.1", None, False),
    ("tinyproxy", DIGEST_OLD, DIGEST_NEW, None, True),
    ("tinyproxy", DIGEST_NEW, DIGEST_NEW, None, False),
])
def test_verify_reads_each_family_through_bump_pins(tmp_path, monkeypatch, family, pinned,
                                                    latest, shas, stale):
    (tmp_path / "Dockerfile").write_text("")
    (tmp_path / "egress.py").write_text("")
    _patch_family(monkeypatch, family, pinned, latest, shas)
    got = rpt.verify(family, dockerfile=str(tmp_path / "Dockerfile"),
                     proxy_source=str(tmp_path / "egress.py"))
    assert (got.pinned, got.latest, got.stale) == (pinned, latest, stale)


def test_an_up_to_date_rustup_does_not_download_to_verify(tmp_path, monkeypatch):
    (tmp_path / "Dockerfile").write_text("")
    _patch_family(monkeypatch, "rustup", "1.1.0", "1.1.0")
    monkeypatch.setattr(bump_pins, "verified_rustup_shas", lambda v: pytest.fail("downloaded"))
    assert rpt.verify("rustup", dockerfile=str(tmp_path / "Dockerfile")).stale is False


def test_an_incomplete_rustup_pin_is_refused(tmp_path, monkeypatch):
    (tmp_path / "Dockerfile").write_text("")
    monkeypatch.setattr(bump_pins, "current_rustup_pin", lambda text: ("1.0.0", {"AMD64": SHA_A}))
    with pytest.raises(RuntimeError, match="rustup pin is incomplete"):
        rpt.verify("rustup", dockerfile=str(tmp_path / "Dockerfile"))


def test_a_tinyproxy_title_uses_a_short_digest_and_the_body_the_full_one():
    b = bump("tinyproxy", DIGEST_OLD, DIGEST_NEW)
    assert b.title == "pin-freshness: tinyproxy sha256:111111111111 -> sha256:222222222222"
    assert DIGEST_NEW in b.body and "linux/amd64 and linux/arm64" in b.body
    assert rpt._TITLE.fullmatch(b.title)


# --- main: summary, annotation, exit status --------------------------------------------------
def _main(monkeypatch, tmp_path, gh, family="trivy", pinned="1.0.0", latest="2.0.0"):
    (tmp_path / "Dockerfile").write_text("")
    summary = tmp_path / "summary.md"
    sha = SHA_A if pinned == latest else SHA_B     # same release: same checksums as pinned
    _patch_family(monkeypatch, family, pinned, latest, {"AMD64": sha, "ARM64": sha})
    monkeypatch.setattr(rpt, "_run", gh)
    monkeypatch.setattr(rpt, "_read", lambda path: "")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("GITHUB_REPOSITORY", REPO)
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    return rpt.main([family]), summary


def test_a_stale_run_writes_a_summary_line_and_a_notice(tmp_path, monkeypatch, capsys):
    code, summary = _main(monkeypatch, tmp_path, FakeGh())
    assert code == 0
    assert summary.read_text() == "- trivy: pinned 1.0.0, latest 2.0.0; opened an issue\n"
    assert capsys.readouterr().out == (
        "::notice title=trivy pin update available::trivy: pinned 1.0.0, latest 2.0.0; "
        "opened an issue\n")


def test_a_stale_tinyproxy_is_a_warning(tmp_path, monkeypatch, capsys):
    code, _ = _main(monkeypatch, tmp_path, FakeGh(), "tinyproxy", DIGEST_OLD, DIGEST_NEW)
    assert code == 0
    assert capsys.readouterr().out.startswith("::warning title=tinyproxy pin update available::")


def test_an_up_to_date_run_prints_no_annotation(tmp_path, monkeypatch, capsys):
    code, summary = _main(monkeypatch, tmp_path, FakeGh(), pinned="2.0.0")
    assert code == 0 and "up to date" in summary.read_text()
    assert "::" not in capsys.readouterr().out


HOSTILE_STDERR = (
    "HTTP 403: Resource not accessible by integration\r\n::error::forged\x1b[2J"
    " token inert-test-token and ghp_" + "A" * 36 + " " + "z" * 5000)


def test_a_gh_failure_is_red_and_says_why_bounded_and_inert(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("GH_TOKEN", "inert-test-token")
    code, _ = _main(monkeypatch, tmp_path,
                    FakeGh(fail=(["gh", "issue", "create"], HOSTILE_STDERR)))
    assert code == 1
    err = capsys.readouterr().err
    assert err.startswith("report-pin-bump: trivy: gh issue failed: HTTP 403: Resource not "
                          "accessible by integration\\x0d\\x0a::error::forged\\x1b[2J token "
                          "[REDACTED] and ")
    assert err.endswith("...\n") and err.count("\n") == 1
    assert "inert-test-token" not in err and "ghp_" + "A" * 36 not in err


def test_a_failed_lookup_is_red_not_absence(tmp_path, monkeypatch):
    gh = FakeGh(fail=(["gh", "api", LOOKUP], "lookup unavailable"))
    code, _ = _main(monkeypatch, tmp_path, gh)
    assert code == 1 and gh.writes() == []


# --- the gh boundary ---------------------------------------------------------------------------
@pytest.mark.parametrize("command", [
    ["sh", "-c", "evil"], ["gh", "pr", "create", "--repo", REPO], ["gh", "auth", "login"],
    ["gh", "api", "repos/owner/repo/pulls?state=all"],
    ["gh", "api", "repos/owner/repo/issues?state=all&creator=github-actions%5Bbot%5D"
                  "&per_page=100"],
    ["gh", "issue", "create", "--repo", REPO, "--title", "anything", "--body",
     "The pin-freshness workflow found x"],
    ["gh", "issue", "create", "--repo", REPO, "--title", "pin-freshness: trivy 1.0.0 -> 2.0.0",
     "--body", "The pin-freshness workflow found x\r\n::error::forged"],
    ["gh", "issue", "create", "--repo", REPO, "--title", "pin-freshness: trivy 1.0.0 -> 2.0.0",
     "--body", "unrelated body"],
    ["gh", "issue", "close", "7", "--repo", REPO, "--comment", "anything"],
    ["gh", "issue", "close", "0", "--repo", REPO, "--comment", rpt.CAUGHT_UP],
    ["gh", "issue", "edit", "7", "--repo", "a b", "--title",
     "pin-freshness: trivy 1.0.0 -> 2.0.0", "--body", "The pin-freshness workflow found x"],
])
def test_the_runner_rejects_any_other_command(tmp_path, monkeypatch, command):
    monkeypatch.setattr(rpt, "resolve", lambda *_a, **_k: pytest.fail("reached resolution"))
    with pytest.raises(RuntimeError, match="unexpected"):
        rpt._run(command, tmp_path)


def test_the_runner_uses_a_trusted_gh_and_only_the_token(tmp_path, monkeypatch):
    monkeypatch.setenv("GH_TOKEN", "inert-test-token")
    monkeypatch.setenv("GH_CONFIG_DIR", str(tmp_path / "wrong-account"))
    monkeypatch.setenv("PYTHONPATH", str(tmp_path))
    monkeypatch.setenv("LD_PRELOAD", str(tmp_path / "evil.so"))
    monkeypatch.setattr(rpt, "resolve", lambda program, cwd, path: SimpleNamespace(
        path="/usr/bin/gh", path_env="/usr/bin:/bin"))
    seen = []

    def fake_run(argv, **kwargs):
        seen.append((argv, kwargs))
        return subprocess.CompletedProcess(argv, 0, "[]", "")
    monkeypatch.setattr(rpt.subprocess, "run", fake_run)
    query = ("repos/owner/repo/issues?state=open&creator=github-actions%5Bbot%5D"
             "&per_page=100")
    assert rpt._run(["gh", "api", query], tmp_path).stdout == "[]"
    argv, kwargs = seen[0]
    assert argv == ["/usr/bin/gh", "api", query]
    assert kwargs["env"]["GH_TOKEN"] == "inert-test-token"
    assert set(kwargs["env"]) == {"HOME", "PATH", "LC_ALL", "GH_TOKEN"}
    assert kwargs["timeout"] == rpt.PROCESS_TIMEOUT and kwargs["cwd"] == tmp_path


def test_a_gh_timeout_is_a_named_failure(tmp_path, monkeypatch):
    monkeypatch.setattr(rpt, "resolve", lambda program, cwd, path: SimpleNamespace(
        path="/usr/bin/gh", path_env="/usr/bin:/bin"))

    def expire(argv, **kwargs):
        raise subprocess.TimeoutExpired(argv, kwargs["timeout"])
    monkeypatch.setattr(rpt.subprocess, "run", expire)
    with pytest.raises(RuntimeError, match="gh timed out"):
        rpt._run(["gh", "issue", "close", "7", "--repo", REPO, "--comment", rpt.CAUGHT_UP],
                 tmp_path)


@pytest.mark.parametrize("stderr, shown", [
    ("", "(no error text)"),
    ("  \n", "(no error text)"),
    ("x" * rpt.ERROR_TEXT_CAP, "x" * rpt.ERROR_TEXT_CAP),
    ("x" * (rpt.ERROR_TEXT_CAP + 1), "x" * (rpt.ERROR_TEXT_CAP - 3) + "..."),
    ("\x1b" * rpt.ERROR_TEXT_CAP, "\\x1b" * ((rpt.ERROR_TEXT_CAP - 3) // 4) + "..."),
])
def test_error_text_cap_is_exact_and_never_splits_a_spelling(stderr, shown):
    assert rpt._error_text(stderr) == shown


def test_the_generated_body_passes_the_runners_own_check():
    for family, pinned, latest in (("trivy", "1.0.0", "2.0.0"), ("rustup", "1.0.0", "2.0.0"),
                                   ("rust-toolchain", "1.0.0", "2.0.0"),
                                   ("tinyproxy", DIGEST_OLD, DIGEST_NEW)):
        b = bump(family, pinned, latest)
        assert rpt._body_ok(b.body) and rpt._TITLE.fullmatch(b.title), family


# --- #3557 review: a full lookup page, and the two cases that are not a bump --------------------
@pytest.mark.parametrize("count, refused", [(rpt.PAGE - 1, False), (rpt.PAGE, True)])
def test_a_full_lookup_page_is_refused_rather_than_guessed_past(count, refused):
    others = [bot_issue(n, "something else %d" % n) for n in range(1, count + 1)]
    gh = FakeGh(others)
    if refused:
        with pytest.raises(RuntimeError, match="full page of 100; refusing to report"):
            rpt.report(bump(), REPO, runner=gh)
        assert gh.writes() == []
    else:
        assert rpt.report(bump(), REPO, runner=gh) == "opened an issue"


def test_same_version_new_checksums_is_a_warning_not_a_bump(tmp_path, monkeypatch, capsys):
    b = bump(pinned="2.0.0", latest="2.0.0")
    assert b.kind == "checksums" and b.warns
    assert b.title == "pin-freshness: trivy 2.0.0 -> 2.0.0 (checksums changed)"
    assert "Checksums changed for the same version: verify before applying." in b.body
    assert rpt._TITLE.fullmatch(b.title) and rpt._body_ok(b.body)
    (tmp_path / "Dockerfile").write_text("")
    _patch_family(monkeypatch, "trivy", "2.0.0", "2.0.0", {"AMD64": SHA_B, "ARM64": SHA_B})
    monkeypatch.setattr(rpt, "_run", FakeGh())
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("GITHUB_REPOSITORY", REPO)
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    assert rpt.main(["trivy"]) == 0
    assert capsys.readouterr().out.startswith(
        "::warning title=trivy checksums changed for the same version::")


@pytest.mark.parametrize("family", ["trivy", "rustup", "rust-toolchain"])
def test_a_pin_ahead_of_upstream_is_a_warning_never_a_downgrade(family):
    b = bump(family, pinned="2.0.0", latest="1.9.0", values={})
    assert b.kind == "ahead" and b.warns
    assert b.title == "pin-freshness: %s 2.0.0 -> 1.9.0 (pinned is ahead)" % family
    assert "newer than upstream's latest release" in b.body
    assert "Check whether `2.0.0` was yanked upstream" in b.body
    assert "it would downgrade the pin" in b.body and "Apply with" not in b.body
    assert rpt._TITLE.fullmatch(b.title) and rpt._body_ok(b.body)


def test_versions_compare_numerically_not_as_text():
    assert bump(pinned="1.10.0", latest="1.9.0", values={}).kind == "ahead"
    assert bump(pinned="1.9.0", latest="1.10.0").kind == "bump"


def test_an_ahead_rustup_does_not_download_the_older_release(tmp_path, monkeypatch):
    (tmp_path / "Dockerfile").write_text("")
    _patch_family(monkeypatch, "rustup", "1.30.0", "1.29.3")
    monkeypatch.setattr(bump_pins, "verified_rustup_shas", lambda v: pytest.fail("downloaded"))
    got = rpt.verify("rustup", dockerfile=str(tmp_path / "Dockerfile"))
    assert (got.kind, got.values) == ("ahead", {})


def test_an_ahead_pin_edits_the_familys_existing_issue():
    b = bump(pinned="2.0.0", latest="1.9.0", values={})
    gh = FakeGh([bot_issue(4, "pin-freshness: trivy 1.0.0 -> 2.0.0")])
    assert rpt.report(b, REPO, runner=gh) == "updated issue #4"
    assert gh.writes()[0][7] == "pin-freshness: trivy 2.0.0 -> 1.9.0 (pinned is ahead)"


def test_an_ordinary_bump_is_still_a_notice():
    b = bump()
    assert (b.kind, b.warns) == ("bump", False)
    assert "(" not in b.title
