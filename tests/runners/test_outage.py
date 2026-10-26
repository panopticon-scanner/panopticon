"""`runners/outage.py`: whose failure was that, and what the loop does about a
batch of them (#1623)."""
import contextlib
import io
import time
import unittest

import pytest

import scripts.runners.base as base
import scripts.runners.outage as outage


# --- #3273 cut 10: every classifier case, in ONE table -----------------------
#
# Each row is (origin, surface, class, gate). `class` is what `classify_failure`
# must answer, or None where the case only ever pinned the gate. `gate` is
# "pass" (`cli_error` returns the text unchanged), "block" (it returns None) or
# None (the case is not about the gate). The origin tag is the review finding
# or issue the case was written for, so a flipped row fails by name:
#   #1623  the original corpus: host shapes, and failures that only MENTION them
#   N1     the CLI-framing gate vs the agent's own opening words
#   N2     `Permission denied` is the OS's English, never the provider's
#   N3     a provider error OBJECT, read by its structure
#   N5     a delimiter is necessary, not sufficient: host-shaped content must follow
#   N6     `code` and 500 qualify a status only inside the provider's object
#   N7     the same envelope as raw JSON on stderr
#   #1729  Claude's subscription-limit line (no `error` object at all)
#   C2     tool and test output that `_S` let through as a KIND
#   I3     a name between "limit" and the `· resets` delimiter
#   I4     a curly apostrophe
#   I5     the older `|<epoch>` form and the N-hour form, and their negatives
# C1 (the ReDoS filler) is a time bound, not a row: `test_a_50kb_pathological_...`.
H, E = outage.HOST_FAILURE, outage.ENTRY_FAILURE
_RUN14 = "You've hit your session limit · resets 10:10am (America/Chicago)"
CLASSIFIER_CASES = (
    # #1623: the shapes the issue names, across four families, and the rest of the shipped surfaces
    *(("#1623", s, H, None) for s in (
        "provider.auth_error: 403", "kimi -p exited 1: provider.auth_error: 403",
        "stream error: exceeded rate limit", "429 Too Many Requests",
        "429 RESOURCE_EXHAUSTED: Quota exceeded for quota metric",
        "You exceeded your current quota", "Error: 403 Forbidden",
        'API Error: 401 {"type":"authentication_error"}', "Invalid API key - please run /login",
        "quota exceeded for this organization", "Your credit balance is too low",
        "503 Service Unavailable", "upstream connect error", "Overloaded", "rate_limit_error",
        "insufficient_quota")),
    # #1623: real entry-class failures whose text merely MENTIONS the vocabulary
    *(("#1623", s, E, None) for s in (
        'claude -p exited 1: {"findings": [{"title": "Missing authentication on /admin"}]}',
        "claude -p reported is_error: the handler returns 403 for a signed-out user; "
        "see src/auth/view.py",
        "claude -p exited 1: TypeError: unsupported operand type at synth/render.py line 403",
        "claude -p reported is_error: cannot read tests/fixtures/rate limit harness README",
        "kimi -p exited 1: no such file or directory: src/billing/quota.py",
        "claude -p exited 1: the repo has 429 python files; I could not finish in the turn budget",
        "codex exited with status 1: assertion failed: expected 200, got 503 in "
        "tests/test_gateway.py",
        "claude -p reported is_error: the OAuth callback in src/login.py has no state parameter",
        "always", "flaky", "concurrency cap", "is_error", "persist refused: shape check failed",
        "claude -p timed out after 300s", "codex timed out after 500s",
        "kimi -p timed out after 403s",            # a duration, not a status
        "could not launch kimi: [Errno 2] No such file or directory",
        "claude -p printed no JSON envelope (exit 2)", "codex returned no final message",
        "enforcement shell not registered at /tmp/x/panopticon-domain-panel.sh",
        "ValueError: Codex requires delivery: return_json; it cannot self-write")),
    # N2: the provider's wire kind is a host failure; every OS `Permission denied` line is not
    ("N2", "permission_denied", H, None),
    *(("N2", s, E, None) for s in (
        "grep: /repo/.git/objects/pack: Permission denied",
        "find: '/repo/node_modules/.cache': Permission denied",
        "PermissionError: [Errno 13] Permission denied: '/repo/.panopticon/runs'",
        "Error: EACCES: permission denied, open '/tmp/panopticon-kimi-x/config.toml'",
        "kimi: could not open the session wire file: Permission denied",
        "warning: unable to access '/repo/.git/config': Permission denied")),
    # N3: each status key qualifies its own number; a bare message from the agent's side does not
    *(("N3", s, H, None) for s in (
        {"type": "authentication_error", "message": "invalid x-api-key"},
        {"error": {"type": "rate_limit_error", "message": "slow down"}},
        {"status": 429, "message": "please retry"}, {"code": "insufficient_quota"},
        {"code": 403, "message": "Forbidden"}, {"code": 401, "message": "Unauthorized"},
        {"error": {"code": 403, "message": "Forbidden"}}, {"statusCode": 429, "message": "slow down"},
        {"status_code": 429}, {"http_status": 503}, {"error_code": 500, "message": "internal"},
        {"type": "permission_error"}, {"type": "api_error", "status": 500})),
    *(("N3", s, E, None) for s in (
        {"message": "the cell found a 403 handler"}, {"message": "src/billing/quota.py is missing"},
        {"type": "api_error"}, {"file": "/repo/src/login.py", "line": 403})),
    # #1623: no surface at all is the entry's own failure
    *(("#1623", s, E, None) for s in (None, "", {})),
    # N1: the CLI's own renderings pass the gate; the agent's opening words never do
    *(("N1", s, H, "pass") for s in (
        "API Error: 403 Forbidden", 'API Error: 401 {"type":"authentication_error"}',
        "API Error: 429 Too Many Requests", "Invalid API key - please run /login",
        "Invalid API key · Please run /login", "Overloaded", "Error: 503 Service Unavailable")),
    *(("N1", s, None, "block") for s in (
        "API Error responses leak stack traces; the 429 Too Many Requests branch "
        "returns the upstream body verbatim",
        "Authentication error handling is missing in src/login.py",
        "Rate limit exceeded responses are not handled",
        "Overloaded __eq__ hides the 403 Forbidden check",
        "Invalid API key handling: the 401 Unauthorized path logs the key",
        "Credit balance is too low is rendered to the user verbatim",
        '{"findings": [{"title": "API Error: 403 Forbidden is not handled"}]}', "", None)),
    # #1729: the run-14 line and its siblings pass; prose that mentions a limit does not
    *(("#1729", s, H, "pass") for s in (
        _RUN14, _RUN14 + "\n",
        "You've hit your usage limit · resets 3:10pm (America/Chicago)",
        "You've reached your weekly (7-day) usage limit · resets 1:10am (America/Chicago)",
        "You've hit your weekly limit · resets 10:10am (America/Chicago)")),
    *(("#1729", s, E, "block") for s in (
        "You've hit your session limit handling is wrong in src/quota.py",
        "the per-user usage limit is never enforced (src/quota.py:41)",
        "session limit", "The weekly limit report is generated by cron",
        '{"findings": [{"title": "You\'ve hit your session limit is shown to users verbatim"}]}',
        "usage limit exceeded responses are not handled")),
    # I3 / I4 / I5: fix round 1's genuine renderings
    ("I3", "You've reached your usage limit for Claude Opus 4.5 · resets 3:10pm (America/Chicago)",
     H, "pass"),
    ("I4", "You’ve hit your session limit · resets 10:10am (America/Chicago)", H, "pass"),
    ("I5", "Claude AI usage limit reached|1758400000", H, "pass"),
    ("I5", "5-hour limit reached · resets 3pm", H, "pass"),
    ("I5", "The 5-hour limit reached counter is reset nightly (src/quota.py)", E, "block"),
    ("I5", "Claude AI usage limit reached is shown as a toast", E, "block"),
    # C2: identifiers and tool output are never a KIND
    *(("C2", s, E, "block") for s in (
        "pytest: FAILED tests/test_quota.py::test_usage_limit_reached",
        "ruff: `hit_your_plan_limit()` is unused",
        "mypy: the daily limit reached branch is unreachable",
        "The monthly limit exceeded banner is never shown",
        "raise QuotaError('weekly limit reached')")),
    # N5: a prose sentence behind the framing is not the CLI; the genuine framings still are
    *(("N5", s, None, "block") for s in (
        "error: 500 lines reviewed", "Error: 500 lines reviewed across 12 files; no blocking issues",
        "Error: 401 handling is missing in src/auth/view.py", "Error: 403 responses are never logged",
        "API Error: the 429 rate limit path is unhandled",
        "API Error: 401 handling is absent -- src/login.py returns the body verbatim",
        "Overloaded: the scheduler drops tasks under burst load (src/sched.py:41)",
        "Overloaded - the queue never drains; see worker.py",
        "Invalid API key, invalid session token and invalid nonce are all logged at INFO")),
    *(("N5", s, H, "pass") for s in (
        "API Error: 429 {\"type\":\"error\",\"error\":{\"type\":\"rate_limit_error\"}}",
        "API Error: 529 {\"type\":\"overloaded_error\"}", "Error: 503 Service Unavailable",
        "Error: 429 Too Many Requests", "API Error: 401 Unauthorized",
        "API Error: 500 Internal Server Error", "API Error: 503 upstream connect error",
        "Invalid API key, please run /login", "Invalid API key", "Overloaded",
        "API Error: 502 Bad Gateway")),
    # N6: tool stderr counting errors is not the provider; its object still qualifies its number
    *(("N6", s, E, None) for s in (
        "mypy: Found 500 errors in 42 files (checked 118 source files)",
        "eslint: 500 problems (500 errors, 0 warnings)", "error: 500 problems found",
        "Compilation failed: 500 errors", "the code (403 lines) was reviewed", "exit code 500",
        "npm ERR! code 500", "internal error code 500 while reading the cache", "500 errors",
        "Found 500 error(s)")),
    *(("N6", s, H, None) for s in (
        {"code": 403, "message": "Forbidden"}, {"statusCode": 429}, {"http_status": 503},
        {"type": "permission_error"}, {"type": "api_error", "status": 500},
        {"error": {"code": 500, "type": "api_error"}})),
    # N7: the envelope on stderr is read through its quotes; JSON with a mere number is not
    *(("N7", s, H, None) for s in (
        '{"error":{"status":403,"message":"Forbidden"}}', '{"error":{"code":403,"message":"Forbidden"}}',
        '{"status_code":429,"message":"slow down"}', '{"http_status":503}', '{"statusCode":429}',
        '{"error":{"message":"Forbidden"},"status":403}',
        'opening noise\n{"error":{"status":403,"message":"Forbidden"}}\nclosing noise')),
    *(("N7", s, E, None) for s in (
        '{"file":"src/api.py","line":403}', '{"error":"at line 403 of src/api.py"}',
        "kimi -p timed out after 403s", '{"findings":[{"severity":"HIGH","line":500}]}',
        'opening noise\n{"findings":[{"code":403,"title":"ordinary finding"}]}\nclosing noise')),
)


# The N1 rows by role, for `tests/runners/test_claude.py`, which feeds the same
# texts through the Claude envelope: the CLI's own renderings, and the agent's
# opening words (the plain-text ones; `""`, None and the JSON body are gate-only).
N1_CLI_ERRORS = tuple(row[1] for row in CLASSIFIER_CASES if row[0] == "N1" and row[3] == "pass")
N1_AGENT_OPENERS = tuple(row[1] for row in CLASSIFIER_CASES
                         if row[0] == "N1" and row[3] == "block" and row[1]
                         and not row[1].startswith("{"))


@pytest.mark.parametrize(
    "origin,surface,expected,gate", CLASSIFIER_CASES,
    ids=["%s:%s" % (row[0], repr(row[1])[:60]) for row in CLASSIFIER_CASES])
def test_the_classifier_case(origin, surface, expected, gate):
    if gate == "pass":
        assert outage.cli_error(surface) == surface
    elif gate == "block":
        assert outage.cli_error(surface) is None
    if expected is not None:
        assert outage.classify_failure(surface) == expected


class TestTheHostOutageClassifier(unittest.TestCase):
    """#1623: the seam between a family's result and the classifier. The
    cases themselves are the table above."""

    def test_a_failed_result_classifies_from_the_host_surface_not_the_message(self):
        composed = "claude -p exited 1: the finding is that /admin returns 403 Forbidden"
        self.assertEqual(outage.ENTRY_FAILURE,
                         base.RunResult.failed("e1", composed).failure_class)
        self.assertEqual(outage.HOST_FAILURE,
                         base.RunResult.failed("e1", composed,
                                               host_error="provider.auth_error: 403").failure_class)

    def test_a_family_may_refine_it_at_its_own_construction(self):
        # The seam's ruling: the default classifier covers the shipped
        # surfaces, and a family that knows better says so rather than
        # patching this module.
        res = base.RunResult.failed("e1", "always", failure_class=outage.HOST_FAILURE)
        self.assertEqual(outage.HOST_FAILURE, res.failure_class)
        direct = base.RunResult(entry_id="e1", ok=False, text="", usage={}, cost_usd=None,
                                model=None, session_id=None, denials=[],
                                error="claude -p exited 1: 429 rate limit",
                                host_error="429 Too Many Requests",
                                failure_class=outage.ENTRY_FAILURE)
        self.assertEqual(outage.ENTRY_FAILURE, direct.failure_class)

    def test_a_direct_construction_is_classified_too(self):
        # `claude.parse_envelope` builds its non-zero-exit failure through the
        # plain constructor, not through `failed`.
        res = base.RunResult(entry_id="e1", ok=False, text="", usage={}, cost_usd=None,
                             model=None, session_id=None, denials=[],
                             error="claude -p exited 1: whatever the agent said",
                             host_error="API Error: 403 Forbidden")
        self.assertEqual(outage.HOST_FAILURE, res.failure_class)

    def test_a_successful_result_is_not_a_failure_of_either_kind(self):
        res = base.RunResult(entry_id="e1", ok=True, text="{}", usage={}, cost_usd=None,
                             model=None, session_id=None, denials=[], error=None)
        self.assertEqual(outage.ENTRY_FAILURE, res.failure_class)


class TestNoCatastrophicBacktrackingInTheFiller(unittest.TestCase):
    """Coordinator review round 1, Critical 1: `(?:\\S+{s}){0,3}?` with
    `{s} = [\\s_.-]` overlaps `\\S` on `_`/`.`/`-`, so a long separator-free
    token backtracks cubically trying every way to split it between the
    filler's `\\S+` and its own separator class. Reachable from
    `classify_failure` directly (kimi/codex hand over their whole stderr) and
    from `cli_error` (`_HOST_HEAD`, which `_CLI_ERROR` embeds, is built out of
    `_KINDS`). Fixed by making the filler's own separator whitespace-only
    (`\\s`), which is disjoint from `\\S` -- there is no character either side
    can claim, so there is nothing left to backtrack over.
    """

    @pytest.mark.serial
    def test_a_50kb_pathological_filler_stays_well_under_a_second(self):
        # Shaped like the reviewer's own repro (`"exceeded your " + "a-"*n`),
        # ~50 KB total, with an `API Error: 500` head so this ALSO drives
        # `cli_error` down its own vulnerable path: `_HOST_HEAD` (embedding
        # `_KINDS`) is what its first branch's lookahead tries once a status
        # is seen, so the same filler backtracking is reachable there too,
        # not only through `classify_failure`'s direct KIND search.
        payload = "API Error: 500 exceeded your " + "a-" * 25000
        start = time.monotonic()
        outage.classify_failure(payload)
        elapsed_classify = time.monotonic() - start
        start = time.monotonic()
        outage.cli_error(payload)
        elapsed_cli_error = time.monotonic() - start
        self.assertLess(elapsed_classify, 1.0, elapsed_classify)
        self.assertLess(elapsed_cli_error, 1.0, elapsed_cli_error)


class TestTheFailureTally(unittest.TestCase):
    """#1623: the loop's per-entry streaks, and the host-outage verdict read
    off them. Here rather than in orchestrate.py because the classification and
    everything decided from it have one owner (and orchestrate.py is an entry
    script at its size ceiling)."""

    def _fail(self, error, host_error=None):
        """A failed launch. `host_error` is the HOST's own surface -- the only
        thing classified -- and absent is the ordinary case: the entry's own
        failure, which is what the streaks are for."""
        return base.RunResult.failed("e", error, host_error=host_error)

    def _ok(self):
        return base.RunResult(entry_id="e", ok=True, text="{}", usage={}, cost_usd=None,
                              model=None, session_id=None, denials=[], error=None)

    def test_an_entry_failure_charges_that_entry_and_nothing_else(self):
        tally = outage.FailureTally("claude")
        tally.record("a", self._fail("always"))
        tally.record("b", self._ok())
        self.assertIsNone(tally.settle())
        self.assertEqual({"a": 1}, tally.streaks)

    def test_a_clean_launch_clears_the_streak(self):
        tally = outage.FailureTally("claude")
        for _ in range(2):
            tally.record("a", self._fail("always"))
            tally.settle()
        tally.record("a", self._ok())
        tally.settle()
        self.assertEqual({}, tally.streaks)

    def test_a_refused_reply_is_the_entrys_failure_whatever_the_host_said(self):
        # persist refusing a reply is panopticon's own verdict: the launch
        # itself came back fine, so nothing about it can be the host's fault.
        tally = outage.FailureTally("claude")
        tally.record("a", self._ok(), refusal="persist refused: 403 findings were not adjudicated")
        self.assertIsNone(tally.settle())
        self.assertEqual({"a": 1}, tally.streaks)

    def test_a_whole_batch_of_host_failures_charges_nobody_and_pauses(self):
        tally = outage.FailureTally("kimi")
        for eid in ("a", "b", "c", "d"):
            tally.record(eid, self._fail("kimi -p exited 1: Error: 403 Forbidden",
                                         host_error="Error: 403 Forbidden"))
        message = tally.settle()
        self.assertEqual({}, tally.streaks)
        self.assertTrue(message.startswith("paused:"), message)
        self.assertIn("kimi", message)                       # the host
        self.assertIn(outage.HOST_FAILURE, message)            # the failure class
        self.assertIn("4", message)                          # the count
        self.assertIn(outage.RESUME_ADVICE, message)          # the way back, bounds named

    def test_a_mixed_batch_charges_only_the_entry_class_failures(self):
        # #1721: the VERDICT this used to pin -- "a mixed batch is not an
        # outage" -- is the defect. The run the 403 opened is still open when
        # the batch ends (an entry-class failure neither extends nor closes
        # it), so it pauses; what is unchanged, and is what this test is for,
        # is the CHARGE.
        tally = outage.FailureTally("claude")
        tally.record("a", self._fail("claude -p exited 1: 403 Forbidden",
                                     host_error="403 Forbidden"), seq=0)
        tally.record("b", self._fail("always"), seq=1)
        self.assertIsNotNone(tally.settle())
        self.assertEqual({"b": 1}, tally.streaks)
        # ...and a batch whose run a later success closed is not an outage at all
        tally.record("a", self._fail("claude -p exited 1: 403 Forbidden",
                                     host_error="403 Forbidden"), seq=0)
        tally.record("b", self._fail("always"), seq=1)
        tally.record("c", self._ok(), seq=2)
        self.assertIsNone(tally.settle())
        self.assertEqual({"b": 2}, tally.streaks)

    def test_a_batch_with_no_failures_at_all_is_not_an_outage(self):
        tally = outage.FailureTally("claude")
        tally.record("a", self._ok())
        self.assertIsNone(tally.settle())

    def test_settling_closes_the_batch(self):
        tally = outage.FailureTally("claude")
        tally.record("a", self._fail("403 Forbidden", host_error="403 Forbidden"))
        self.assertIsNotNone(tally.settle())
        self.assertIsNone(tally.settle())                    # the next batch is empty

    # ---- #1721: the trailing-run rule -------------------------------------
    #
    # All-or-nothing made ONE entry-class failure anywhere in a batch cancel a
    # real outage: no pause, no attempt given back, every cell charged. What
    # settles a batch now is whether it ENDED in a run of host-class failures.

    def test_a_trailing_run_pauses_despite_an_earlier_entry_class_failure(self):
        tally = outage.FailureTally("kimi")
        tally.record("a", self._ok(), seq=0)
        tally.record("b", self._fail("kimi -p exited 1: All files read"), seq=1)
        for i, eid in enumerate(("c", "d", "e")):
            tally.record(eid, self._fail("kimi -p exited 1: 403 Forbidden",
                                         host_error="provider.auth_error: 403 Forbidden"),
                         seq=2 + i)
        message = tally.settle()
        self.assertTrue(message.startswith("paused:"), message)
        self.assertEqual({"b": 1}, tally.streaks)          # only the entry-class one is charged
        self.assertEqual(["c", "d", "e"], tally.uncharged)

    def test_a_success_that_was_in_flight_before_the_outage_does_not_cancel_it(self):
        # The pool is FIFO, so a launch that STARTED before the first 403 can
        # still land after it. That says nothing about the host being back.
        tally = outage.FailureTally("kimi")
        tally.record("b", self._fail("403", host_error="403 Forbidden"), seq=3)
        tally.record("a", self._ok(), seq=1)               # launched before the outage
        self.assertIsNotNone(tally.settle())

    def test_a_success_launched_after_the_outage_closes_the_run(self):
        tally = outage.FailureTally("kimi")
        for seq, eid in ((0, "a"), (1, "b")):
            tally.record(eid, self._fail("403", host_error="403 Forbidden"), seq=seq)
        self.assertTrue(tally.outage(2))
        tally.record("c", self._ok(), seq=2)               # the host is back
        self.assertFalse(tally.outage(2))
        self.assertIsNone(tally.settle())
        self.assertEqual({}, tally.streaks)                # ...and the 403s cost nobody
        self.assertEqual(["a", "b"], tally.uncharged)

    def test_an_entry_class_failure_neither_opens_extends_nor_closes_the_run(self):
        tally = outage.FailureTally("kimi")
        tally.record("a", self._fail("its own fault"), seq=0)
        self.assertFalse(tally.outage(1))                  # opens nothing
        self.assertIsNone(tally.settle())
        tally.record("b", self._fail("403", host_error="403 Forbidden"), seq=0)
        tally.record("c", self._fail("its own fault"), seq=1)
        self.assertFalse(tally.outage(2), "an entry-class failure extended the run")
        tally.record("d", self._fail("403", host_error="403 Forbidden"), seq=2)
        self.assertTrue(tally.outage(2), "an entry-class failure closed the run")

    def test_the_short_circuit_needs_two_launches_or_a_whole_pool_round(self):
        for width, threshold in ((None, 2), (1, 2), (2, 2), (4, 4), (8, 8)):
            tally = outage.FailureTally("kimi")
            for seq in range(threshold):
                self.assertFalse(tally.outage(width), (width, seq))
                tally.record("e%d" % seq, self._fail("403", host_error="403 Forbidden"),
                             seq=seq)
            self.assertTrue(tally.outage(width), width)

    def test_the_stop_remembers_the_count_a_later_success_erases(self):
        # The loop's "stopped launching after N" line is read off the moment
        # the stop FIRED. `_trailing` by then is whatever the drain left --
        # zero, when a success with a later seq closed the run -- and
        # "stopped launching after 0 host-class failure(s)" says nothing.
        tally = outage.FailureTally("kimi")
        self.assertIsNone(tally.stopped_at)
        for seq in range(2):
            tally.record("e%d" % seq, self._fail("403", host_error="403 Forbidden"), seq=seq)
            tally.outage(2)
        self.assertEqual(2, tally.stopped_at)
        tally.record("e9", self._ok(), seq=9)              # the in-flight success lands
        self.assertFalse(tally.outage(2), "the run should have closed")
        self.assertEqual(2, tally.stopped_at, "the stop's own count was overwritten")
        self.assertIsNone(tally.settle(3))                 # ...and it was not an outage
        self.assertIsNone(tally.stopped_at, "stopped_at outlived its batch")

    def test_the_pause_says_how_many_entries_were_never_launched(self):
        tally = outage.FailureTally("kimi")
        for seq in range(2):
            tally.record("e%d" % seq, self._fail("403", host_error="403 Forbidden"), seq=seq)
        message = tally.settle(70)
        self.assertIn("70", message)
        self.assertIn(outage.HOST_OUTAGE_CLAUSE, message)  # the guide quotes this verbatim

    def test_host_pause_redacts_secret_and_keeps_safe_context(self):
        tally = outage.FailureTally("kimi")
        secret = "sk-ant-api03-AAAABBBBCCCCDDDD"
        for seq in range(2):
            tally.record("e%d" % seq, self._fail(
                "provider rejected key " + secret,
                host_error="API Error: 403 Forbidden for key " + secret), seq=seq)
        message = tally.settle(4)
        self.assertIn(outage.HOST_OUTAGE_CLAUSE, message)
        self.assertIn("provider rejected key", message)
        self.assertIn("4", message)
        self.assertNotIn(secret, message)

    def test_uncharged_lists_the_host_class_ids_and_resets_per_batch(self):
        tally = outage.FailureTally("kimi")
        tally.record("a", self._ok(), seq=0)
        tally.record("b", self._fail("its own fault"), seq=1)
        tally.record("c", self._fail("403", host_error="403 Forbidden"), seq=2)
        tally.settle()
        self.assertEqual(["c"], tally.uncharged)
        tally.record("d", self._ok(), seq=0)
        tally.settle()
        self.assertEqual([], tally.uncharged)

    def test_the_cap_message_names_the_entry_the_count_and_its_last_error(self):
        tally = outage.FailureTally("claude")
        for _ in range(3):
            tally.record("a", self._fail("always"))
            tally.settle()
        self.assertIsNone(tally.exhausted([{"id": "a"}], 4))
        message = tally.exhausted([{"id": "a"}, {"id": "b"}], 3)
        self.assertIn("entry a failed 3 consecutive launches", message)
        self.assertIn("last: always", message)

    def test_exhausted_entry_redacts_secret_and_keeps_failure_context(self):
        tally = outage.FailureTally("claude")
        secret = "sk-ant-api03-AAAABBBBCCCCDDDD"
        for _ in range(3):
            tally.record("a", self._fail("entry parse failure with key " + secret))
            tally.settle()
        message = tally.exhausted([{"id": "a"}], 3)
        self.assertIn("entry a failed 3 consecutive launches", message)
        self.assertIn("last: entry parse failure with key", message)
        self.assertNotIn(secret, message)

    def test_an_entry_the_host_failed_never_reaches_the_cap(self):
        tally = outage.FailureTally("kimi")
        for _ in range(9):
            tally.record("a", self._fail("kimi -p exited 1: 429 rate limit",
                                         host_error="429 Too Many Requests"))
            tally.settle()
        self.assertIsNone(tally.exhausted([{"id": "a"}], 3))

    # #2506: the backoff, which is the cap above read the other way round. The
    # cap bounds an entry that is STUCK; with nothing at all between iterations
    # an unrecognised host hiccup spends all three of a merely flaky entry's
    # launches within seconds and parks it.

    def _waited(self, tally, pending, mode="headless", jitter=0.0):
        """One iteration's wait: what was returned, what was slept, what the
        operator was told, and what the rng was asked for. Both seams are
        injected -- a unit test may not sleep, and a jittered schedule is not
        a schedule anyone can assert."""
        slept, asked, err = [], [], io.StringIO()

        def rng(low, high):
            asked.append((low, high))
            return jitter

        with contextlib.redirect_stderr(err):
            returned = tally.pause_before_launch(mode, pending, sleep=slept.append,
                                                 jitter=rng)
        return returned, slept, err.getvalue(), asked

    def _streak(self, tally, entry_id, n, host_error=None):
        """`n` consecutive failed launches of `entry_id`, one batch each."""
        for _ in range(n):
            tally.record(entry_id, self._fail("transient", host_error=host_error))
            tally.settle()
        return tally

    def test_an_entry_that_has_not_failed_is_not_waited_for(self):
        tally = outage.FailureTally("claude")
        self.assertEqual((0.0, [], "", []), self._waited(tally, [{"id": "a"}]))

    def test_the_wait_doubles_with_the_streak_and_stops_at_the_cap(self):
        # 2 s then 4 s are the only two waits a re-launch is ever reached on,
        # since the cap parks the entry at the third failure: six seconds plus
        # jitter is the whole schedule's cost to an entry. The ceiling is
        # pinned anyway -- it is what bounds a cap a later run raises.
        for streak, expected in ((1, 2.0), (2, 4.0), (3, 8.0), (9, 8.0)):
            with self.subTest(streak=streak):
                tally = self._streak(outage.FailureTally("claude"),
                                     "a", streak)
                returned, slept, line, _asked = self._waited(tally, [{"id": "a"}])
                self.assertEqual(expected, returned)
                self.assertEqual([expected], slept)
                self.assertIn("waiting %.1fs" % expected, line)
        self.assertEqual(8, outage.LAUNCH_BACKOFF_CAP_S)

    def test_the_jitter_adds_at_most_a_quarter_of_the_wait(self):
        # Entries that failed together would otherwise come back in lockstep.
        tally = self._streak(outage.FailureTally("claude"), "a", 1)
        returned, slept, _line, asked = self._waited(tally, [{"id": "a"}], jitter=0.25)
        self.assertEqual([(0, outage.LAUNCH_BACKOFF_JITTER)], asked)
        self.assertEqual(0.25, outage.LAUNCH_BACKOFF_JITTER)
        self.assertEqual(2.5, returned)
        self.assertEqual([2.5], slept)

    def test_session_mode_never_waits_because_a_human_advances_it(self):
        tally = self._streak(outage.FailureTally("claude"), "a", 2)
        self.assertEqual((0.0, [], "", []),
                         self._waited(tally, [{"id": "a"}], mode="session"))

    def test_the_line_is_printed_once_and_counts_what_is_re_launched(self):
        tally = outage.FailureTally("claude")
        self._streak(tally, "a", 2)
        self._streak(tally, "b", 1)
        _returned, _slept, line, _asked = self._waited(
            tally, [{"id": "a"}, {"id": "b"}, {"id": "c"}])
        # The worst streak among them sets the wait; the count is what is
        # being RE-launched, which is neither the batch nor the whole pool.
        self.assertEqual(["driver loop: waiting 4.0s before re-launching 2 entries "
                          "after a failed launch"], line.splitlines())
        _r, _s, one, _a = self._waited(tally, [{"id": "b"}])
        self.assertIn("re-launching 1 entry after", one)

    def test_a_clean_launch_clears_the_wait_with_the_streak(self):
        tally = self._streak(outage.FailureTally("claude"), "a", 2)
        tally.record("a", self._ok())
        tally.settle()
        self.assertEqual((0.0, [], "", []), self._waited(tally, [{"id": "a"}]))

    def test_an_entry_the_host_failed_is_never_waited_for_either(self):
        # The wait is keyed on the streak, and a host-class failure charges
        # none of it -- the same reason such an entry never reaches the cap.
        tally = self._streak(outage.FailureTally("kimi"), "a", 3,
                             host_error="429 Too Many Requests")
        self.assertEqual((0.0, [], "", []), self._waited(tally, [{"id": "a"}]))

    def test_a_pending_entry_that_is_not_a_dict_is_not_waited_for(self):
        # `exhausted` reads `pending` the same defensive way.
        tally = self._streak(outage.FailureTally("claude"), "a", 2)
        self.assertEqual((0.0, [], "", []), self._waited(tally, ["a", None]))
