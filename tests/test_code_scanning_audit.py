import json
import subprocess
from types import SimpleNamespace

import pytest

import code_scanning_audit as audit


SHA = "1" * 40
OLD_SHA = "2" * 40
NEW_SHA = "3" * 40
SECURITY_ID = "11111111-1111-4111-8111-111111111111"
CODEQL_ID = "22222222-2222-4222-8222-222222222222"
REPOSITORY = "panopticon-scanner/panopticon"


def head(sha=SHA):
    return {"object": {"sha": sha}}


def status(value="complete", **extra):
    value = {"processing_status": value, "errors": []} | extra
    return value


def analysis_row(tool, *, sarif_id=SECURITY_ID, sha=SHA):
    security = tool != "CodeQL"
    key = (audit.SECURITY_ANALYSIS_KEY if security
           else audit.CODEQL_ANALYSIS_KEY)
    return {
        "ref": audit.MAIN_REF,
        "commit_sha": sha,
        "analysis_key": key,
        "environment": json.dumps({} if security else {"language": "python"}),
        "category": key if security else audit.CODEQL_CATEGORY,
        "error": "",
        "warning": "",
        "results_count": 0,
        "sarif_id": sarif_id if security else CODEQL_ID,
        "tool": {"name": tool},
    }


def security_rows():
    return [analysis_row(tool) for tool in sorted(audit.SECURITY_TOOLS)]


def alert(number=7, severity="note", sha=SHA):
    return {
        "number": number,
        "state": "open",
        "tool": {"name": "Semgrep OSS"},
        "rule": {"id": "python.lang.security.audit.rule", "severity": severity},
        "most_recent_instance": {
            "ref": audit.MAIN_REF,
            "commit_sha": sha,
            "location": {"path": "src/app.py", "start_line": 9},
        },
        "html_url": "https://attacker.invalid/ignored",
        "message": {"text": "SECRET-SCANNER-MESSAGE"},
    }


class FakeRunner:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def __call__(self, argv, **kwargs):
        self.calls.append((list(argv), kwargs))
        if not self.responses:
            raise AssertionError("unexpected API call: %r" % argv)
        response = self.responses.pop(0)
        if isinstance(response, BaseException):
            raise response
        if isinstance(response, SimpleNamespace):
            return response
        return SimpleNamespace(returncode=0, stdout=json.dumps(response), stderr="")


def target(**overrides):
    values = {
        "repository": REPOSITORY,
        "server_url": "https://github.com",
        "ref": audit.MAIN_REF,
        "sha": SHA,
        "security_sarif_id": SECURITY_ID,
    }
    values.update(overrides)
    return audit.validate_target(**values)


def success_responses(alert_pages=None):
    return [
        head(), status(), security_rows(), [analysis_row("CodeQL")], status(),
        *(alert_pages if alert_pages is not None else [[]]), head(),
    ]


def run_with(responses, *, attempts=3):
    runner = FakeRunner(responses)
    output = []
    sleeps = []
    instance = audit.MainAudit(
        target(), runner, sleep=sleeps.append, output=output.append,
        poll_attempts=attempts, poll_delay=0.25,
    )
    return instance, runner, output, sleeps


def params(call):
    argv = call[0]
    return dict(argv[i + 1].split("=", 1)
                for i, arg in enumerate(argv[:-1]) if arg == "-f")


def endpoints(runner):
    return [call[0][call[0].index("X-GitHub-Api-Version: 2022-11-28") + 1]
            for call in runner.calls]


def test_exact_completed_five_analysis_zero_open_state_passes():
    instance, runner, output, sleeps = run_with(success_responses())

    assert instance.run() == {"analyses": 5, "open_alerts": 0}
    assert output == [
        "Validated complete code-scanning analyses: 5",
        "Open code-scanning alerts on refs/heads/main: 0",
    ]
    assert sleeps == []
    assert runner.responses == []
    assert all(call[0][2:4] == ["--hostname", "github.com"]
               for call in runner.calls)
    assert all(call[1] == {"capture_output": True, "text": True}
               for call in runner.calls)
    assert params(runner.calls[2]) == {
        "sarif_id": SECURITY_ID, "per_page": "100"}
    assert params(runner.calls[3]) == {
        "ref": audit.MAIN_REF, "tool_name": "CodeQL", "sort": "created",
        "direction": "desc", "per_page": "1"}
    assert params(runner.calls[5]) == {
        "state": "open", "ref": audit.MAIN_REF,
        "per_page": "100", "page": "1"}


def test_dismissed_findings_are_absent_from_the_open_query_without_a_baseline():
    # The API's state=open view is the disposition authority. A dismissed
    # finding is absent; the helper has no alert-number/fingerprint allowlist.
    responses = success_responses()
    responses[1]["dismissed_results_elsewhere"] = 53
    instance, _runner, output, _sleeps = run_with(responses)
    instance.run()
    assert output[-1].endswith(": 0")
    assert not hasattr(audit, "ALLOWLIST")


@pytest.mark.parametrize("severity", ["note", "warning", "error"])
def test_any_open_alert_level_fails_with_only_bounded_fields(severity):
    row = alert(severity=severity)
    row["rule"]["id"] += "\nsecond-line"
    instance, _runner, output, _sleeps = run_with(
        success_responses([[row]]))

    with pytest.raises(audit.AuditError, match="1 open code-scanning alert"):
        instance.run()

    rendered = "\n".join(output)
    assert "Open code-scanning alerts on refs/heads/main: 1" in rendered
    assert "#7 Semgrep OSS" in rendered
    assert severity in rendered
    assert "src/app.py:9" in rendered
    assert ("https://github.com/%s/security/code-scanning/7" % REPOSITORY
            in rendered)
    assert "attacker.invalid" not in rendered
    assert "SECRET-SCANNER-MESSAGE" not in rendered
    assert "\nsecond-line" not in rendered


def test_more_than_one_page_is_fully_collected_before_alert_failure():
    first = [alert(number=n) for n in range(1, 101)]
    second = [alert(number=101)]
    instance, runner, output, _sleeps = run_with(
        success_responses([first, second]))

    with pytest.raises(audit.AuditError, match="101 open"):
        instance.run()

    alert_calls = [call for call in runner.calls
                   if any(arg.endswith("code-scanning/alerts")
                          for arg in call[0])]
    assert [params(call)["page"] for call in alert_calls] == ["1", "2"]
    assert output[1].endswith(": 101")
    assert len(output) == 103


def test_failure_on_later_alert_page_cannot_become_a_short_clean_listing():
    first = [alert(number=n) for n in range(1, 101)]
    failed = SimpleNamespace(returncode=1, stdout="", stderr="SECRET-BODY")
    responses = success_responses([first, failed])
    # success_responses JSON-encodes ordinary values, so place the result in
    # the queue directly and remove the now-unreachable final-head response.
    responses = responses[:6] + [failed]
    instance, runner, output, _sleeps = run_with(responses)

    with pytest.raises(audit.AuditError) as caught:
        instance.run()

    assert "open alerts page 2" in str(caught.value)
    assert "SECRET-BODY" not in str(caught.value)
    assert output == []
    assert params(runner.calls[-1])["page"] == "2"


@pytest.mark.parametrize("payload, message", [
    ({}, "malformed Security SARIF status"),
    (status("pending"), "Security SARIF upload is pending"),
    (status("failed"), "Security SARIF upload is failed"),
    (status("complete", errors=["scanner secret"]), "processing errors"),
])
def test_missing_pending_failed_or_errored_security_upload_fails(payload, message):
    instance, _runner, output, _sleeps = run_with([head(), payload])
    with pytest.raises(audit.AuditError, match=message):
        instance.run()
    assert output == []


def test_codeql_can_arrive_late_with_a_bounded_injected_clock():
    responses = [
        head(), status(), security_rows(),
        [], head(),
        [analysis_row("CodeQL", sha=OLD_SHA)], head(),
        [analysis_row("CodeQL")], status(), [], head(),
    ]
    instance, _runner, output, sleeps = run_with(responses, attempts=3)

    instance.run()

    assert sleeps == [0.25, 0.25]
    assert output[-1].endswith(": 0")


def test_absent_codeql_fails_at_the_poll_bound():
    responses = [
        head(), status(), security_rows(),
        [], head(), [], head(),
    ]
    instance, _runner, output, sleeps = run_with(responses, attempts=2)

    with pytest.raises(audit.AuditError, match="not available after 2 attempts"):
        instance.run()

    assert sleeps == [0.25]
    assert output == []


def test_pending_codeql_upload_is_polled_and_proven_complete_separately():
    codeql = [analysis_row("CodeQL")]
    responses = [
        head(), status(), security_rows(),
        codeql, status("pending"), head(),
        codeql, status(), [], head(),
    ]
    instance, runner, output, sleeps = run_with(responses, attempts=2)

    instance.run()

    assert sleeps == [0.25]
    sarif_endpoints = [p for p in endpoints(runner) if "/sarifs/" in p]
    assert sarif_endpoints == [
        "repos/%s/code-scanning/sarifs/%s" % (REPOSITORY, SECURITY_ID),
        "repos/%s/code-scanning/sarifs/%s" % (REPOSITORY, CODEQL_ID),
        "repos/%s/code-scanning/sarifs/%s" % (REPOSITORY, CODEQL_ID),
    ]
    assert output[-1].endswith(": 0")


def test_failed_codeql_upload_fails_even_when_the_analysis_row_matches():
    responses = [
        head(), status(), security_rows(),
        [analysis_row("CodeQL")], status("failed"),
    ]
    instance, _runner, output, _sleeps = run_with(responses)
    with pytest.raises(audit.AuditError, match="CodeQL SARIF upload is failed"):
        instance.run()
    assert output == []


@pytest.mark.parametrize("field, value", [
    ("ref", "refs/heads/other"),
    ("commit_sha", OLD_SHA),
    ("analysis_key", "wrong-key"),
    ("category", "wrong-category"),
    ("environment", '{"language":"python"}'),
    ("sarif_id", "33333333-3333-4333-8333-333333333333"),
    ("error", "upload error"),
    ("warning", "upload warning"),
])
def test_wrong_security_analysis_identity_or_notification_fails(field, value):
    rows = security_rows()
    rows[0][field] = value
    instance, _runner, output, _sleeps = run_with([head(), status(), rows])
    with pytest.raises(audit.AuditError):
        instance.run()
    assert output == []


def test_duplicate_or_missing_security_tool_fails():
    duplicate = security_rows()
    duplicate[-1]["tool"]["name"] = duplicate[0]["tool"]["name"]
    instance, _runner, _output, _sleeps = run_with(
        [head(), status(), duplicate])
    with pytest.raises(audit.AuditError, match="duplicate tool"):
        instance.run()

    # A short set is the ingestion race, so it is polled (one attempt here)
    # and then fails closed: waiting never invents the missing tool.
    missing = security_rows()[:-1]
    instance, _runner, _output, sleeps = run_with(
        [head(), status(), missing, head()], attempts=1)
    with pytest.raises(audit.AuditError, match="exactly 4"):
        instance.run()
    assert sleeps == []


def test_security_analyses_can_arrive_late_with_a_bounded_injected_clock():
    # GitHub ingests one upload's four analyses asynchronously, so the first
    # read of the list can see none of them and the next only some (#2022).
    responses = [
        head(), status(),
        [], head(),
        security_rows()[:2], head(),
        security_rows(),
        [analysis_row("CodeQL")], status(), [], head(),
    ]
    instance, runner, output, sleeps = run_with(responses, attempts=3)

    instance.run()

    assert sleeps == [0.25, 0.25]
    assert output[-1].endswith(": 0")
    assert runner.responses == []


def test_analyses_that_never_complete_fail_saying_what_was_seen_and_expected():
    # One expected tool plus a row this audit does not expect: the message
    # names tools from SECURITY_TOOLS only, never a string from the response.
    rogue = analysis_row("Bandit")
    rogue["tool"]["name"] = "SECRET-SCANNER"
    partial = [analysis_row("Bandit"), rogue]
    instance, _runner, output, sleeps = run_with(
        [head(), status(), partial, head(), partial, head()], attempts=2)

    with pytest.raises(audit.AuditError) as caught:
        instance.run()

    message = str(caught.value)
    assert "must contain exactly 4 analyses" in message
    assert "after 2 attempts saw 2" in message
    assert "present: Bandit" in message
    assert "missing: Gitleaks, Semgrep OSS, Trivy" in message
    assert "SECRET-SCANNER" not in message
    assert sleeps == [0.25]
    assert output == []


def test_a_surplus_analysis_row_fails_closed_without_burning_the_poll():
    # Waiting can only add rows, so a count above the expected four is final.
    instance, _runner, output, sleeps = run_with(
        [head(), status(), security_rows() + [analysis_row("Bandit")]])

    with pytest.raises(audit.AuditError, match="exactly 4 analyses; saw 5"):
        instance.run()

    assert sleeps == []
    assert output == []


def test_main_moving_during_the_analyses_wait_stops_the_poll():
    instance, _runner, output, sleeps = run_with(
        [head(), status(), [], head(NEW_SHA)])
    with pytest.raises(audit.AuditError, match="superseded"):
        instance.run()
    assert sleeps == []
    assert output == []


@pytest.mark.parametrize("overrides", [
    {"poll_attempts": 0}, {"poll_attempts": -1}, {"poll_delay": -0.25},
])
def test_an_unusable_poll_bound_is_rejected_before_any_request(overrides):
    runner = FakeRunner([])
    with pytest.raises(ValueError, match="invalid polling bound"):
        audit.MainAudit(target(), runner, **overrides)
    assert runner.calls == []


@pytest.mark.parametrize("field, value", [
    ("ref", "refs/heads/other"),
    ("analysis_key", "wrong-key"),
    ("category", "wrong-category"),
    ("environment", "{}"),
    ("error", "CodeQL error"),
    ("warning", "CodeQL warning"),
])
def test_wrong_codeql_identity_or_notification_fails(field, value):
    row = analysis_row("CodeQL")
    row[field] = value
    instance, _runner, output, _sleeps = run_with(
        [head(), status(), security_rows(), [row]])
    with pytest.raises(audit.AuditError):
        instance.run()
    assert output == []


def test_main_moving_initially_or_after_collection_is_never_clean():
    instance, _runner, output, _sleeps = run_with([head(NEW_SHA)])
    with pytest.raises(audit.AuditError, match="superseded"):
        instance.run()
    assert output == []

    responses = success_responses()
    responses[-1] = head(NEW_SHA)
    instance, _runner, output, _sleeps = run_with(responses)
    with pytest.raises(audit.AuditError, match="superseded"):
        instance.run()
    assert output == []


def test_main_moving_during_codeql_wait_stops_the_poll():
    instance, _runner, output, sleeps = run_with([
        head(), status(), security_rows(), [], head(NEW_SHA),
    ])
    with pytest.raises(audit.AuditError, match="superseded"):
        instance.run()
    assert sleeps == []
    assert output == []


def test_stale_alert_instance_and_duplicate_page_id_fail_closed():
    instance, _runner, output, _sleeps = run_with(
        success_responses([[alert(sha=OLD_SHA)]]))
    with pytest.raises(audit.AuditError, match="stale"):
        instance.run()
    assert output == []

    rows = [alert(number=n) for n in range(1, 101)]
    instance, _runner, output, _sleeps = run_with(
        success_responses([rows, [alert(number=1)]]))
    with pytest.raises(audit.AuditError, match="duplicate"):
        instance.run()
    assert output == []


@pytest.mark.parametrize("response, expected", [
    (SimpleNamespace(returncode=0, stdout="", stderr="SECRET"), "no JSON"),
    (SimpleNamespace(returncode=0, stdout="{bad", stderr="SECRET"), "malformed JSON"),
    (SimpleNamespace(returncode=1, stdout="SECRET", stderr="SECRET"), "request failed"),
    (subprocess.TimeoutExpired(["gh"], 120, stderr="SECRET"), "timed out"),
    (RuntimeError("SECRET trusted-path failure"), "could not start"),
])
def test_transport_errors_are_fail_closed_and_secret_safe(response, expected):
    runner = FakeRunner([response])
    reader = audit.GitHubReader(target(), runner)
    with pytest.raises(audit.AuditError) as caught:
        reader.get("repos/%s/fixed" % REPOSITORY, "test request")
    assert expected in str(caught.value)
    assert "SECRET" not in str(caught.value)


@pytest.mark.parametrize("responses, expected", [
    ([[]], "malformed main ref"),
    ([head(), []], "malformed Security SARIF status"),
    ([head(), status(), {}], "malformed Security analyses"),
])
def test_malformed_api_shapes_do_not_become_empty_success(responses, expected):
    instance, _runner, output, _sleeps = run_with(responses)
    with pytest.raises(audit.AuditError, match=expected):
        instance.run()
    assert output == []


@pytest.mark.parametrize("overrides, expected", [
    ({"repository": "owner/repo/extra"}, "repository"),
    ({"repository": "../repo"}, "repository"),
    ({"server_url": "http://github.com"}, "trusted https://github.com"),
    ({"server_url": "https://user@github.com"}, "trusted https://github.com"),
    ({"server_url": "https://github.com/api"}, "trusted https://github.com"),
    ({"server_url": "https://attacker.invalid"}, "trusted https://github.com"),
    ({"server_url": "https://github.com:8443"}, "trusted https://github.com"),
    ({"ref": "refs/heads/release"}, "refs/heads/main"),
    ({"sha": "1" * 39}, "40-hex"),
    ({"security_sarif_id": ""}, "missing"),
    ({"security_sarif_id": "not-a-uuid"}, "malformed"),
])
def test_request_identifiers_are_validated_before_network(overrides, expected):
    with pytest.raises(audit.AuditError, match=expected):
        target(**overrides)


def test_response_urls_are_never_used_as_api_endpoints():
    responses = success_responses()
    responses[1]["analyses_url"] = "https://attacker.invalid/steal-token"
    for row in responses[2]:
        row["url"] = "https://attacker.invalid/analysis"
    instance, runner, _output, _sleeps = run_with(responses)
    instance.run()
    joined = " ".join(" ".join(call[0]) for call in runner.calls)
    assert "attacker.invalid" not in joined
    assert all(path.startswith("repos/%s/" % REPOSITORY)
               for path in endpoints(runner))


def test_main_builds_only_the_hardened_default_runner(monkeypatch):
    marker = object()
    seen = []
    monkeypatch.setattr(audit.triage, "default_gh_runner", lambda: marker)

    class StubAudit:
        def __init__(self, audit_target, runner):
            seen.append((audit_target, runner))

        def run(self):
            return {"analyses": 5, "open_alerts": 0}

    monkeypatch.setattr(audit, "MainAudit", StubAudit)
    rc = audit.main([
        "--repository", REPOSITORY,
        "--server-url", "https://github.com",
        "--ref", audit.MAIN_REF,
        "--sha", SHA,
        "--sarif-id", SECURITY_ID,
    ])
    assert rc == 0
    assert seen[0][1] is marker
