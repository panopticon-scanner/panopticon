"""`runners/outage.py`: whose failure was that, and what the loop does about a
batch of them (#1623)."""
import unittest

import scripts.runners.base as base
import scripts.runners.outage as outage


class TestTheHostOutageClassifier(unittest.TestCase):
    """#1623: 243 of the 247 failed launches in the Kimi evidence run were ONE
    `provider.auth_error: 403` -- the host, not the entries -- and the loop
    charged every one of them to the entry that happened to be holding it.

    What is classified is the HOST's own error surface (`RunResult.host_error`),
    never the composed `error` text: on two of the three shipped families that
    text is built out of up to 200 characters of the AGENT's output, so a cell
    reviewing `src/billing/quota.py` would otherwise report its own findings as
    a quota outage. The match is anchored on structured shapes -- an error KIND
    the provider names, or a status sitting next to its reason -- not on a
    substring anywhere in a sentence.
    """

    HOST = (
        # the shapes #1623 itself names, across four families
        "provider.auth_error: 403",
        "kimi -p exited 1: provider.auth_error: 403",
        "stream error: exceeded rate limit",
        "429 Too Many Requests",
        "429 RESOURCE_EXHAUSTED: Quota exceeded for quota metric",
        "You exceeded your current quota",
        # ...and the rest of the shipped surfaces
        "Error: 403 Forbidden",
        'API Error: 401 {"type":"authentication_error"}',
        "Invalid API key - please run /login",
        "quota exceeded for this organization",
        "Your credit balance is too low",
        "503 Service Unavailable",
        "upstream connect error",
        "Overloaded",
        "rate_limit_error",
        "insufficient_quota",
    )
    ENTRY = (
        # The review's corpus: REAL entry-class failures whose text merely
        # MENTIONS the vocabulary of an outage -- a finding about auth, a path
        # under src/billing/, a line number that happens to be 403. Every one
        # of these read `host` before the classifier was anchored, and a batch
        # of them stopped the run.
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
        # ...and every other failure this suite and the three families produce
        "always", "flaky", "concurrency cap", "is_error",
        "persist refused: shape check failed",
        "claude -p timed out after 300s",
        "codex timed out after 500s",
        "kimi -p timed out after 403s",          # the number is a duration, not a status
        "could not launch kimi: [Errno 2] No such file or directory",
        "claude -p printed no JSON envelope (exit 2)",
        "codex returned no final message",
        "enforcement shell not registered at /tmp/x/panopticon-domain-panel.sh",
        "ValueError: Codex requires delivery: return_json; it cannot self-write",
    )

    def test_the_provider_side_surfaces_read_as_a_host_failure(self):
        for host_error in self.HOST:
            with self.subTest(host_error=host_error):
                self.assertEqual(outage.HOST_FAILURE, outage.classify_failure(host_error))

    def test_a_failure_that_merely_mentions_the_vocabulary_is_the_entrys_own(self):
        for text in self.ENTRY:
            with self.subTest(text=text):
                self.assertEqual(outage.ENTRY_FAILURE, outage.classify_failure(text))

    def test_a_provider_error_object_is_read_by_its_structure(self):
        for surface in ({"type": "authentication_error", "message": "invalid x-api-key"},
                        {"error": {"type": "rate_limit_error", "message": "slow down"}},
                        {"status": 429, "message": "please retry"},
                        {"code": "insufficient_quota"}):
            with self.subTest(surface=surface):
                self.assertEqual(outage.HOST_FAILURE, outage.classify_failure(surface))
        self.assertEqual(outage.ENTRY_FAILURE,
                         outage.classify_failure({"message": "the cell found a 403 handler"}))

    def test_no_surface_at_all_is_an_entry_failure(self):
        # A family that recorded no host error said nothing about the host, and
        # the loop treats silence as the entry's own failure -- which is what
        # every failure was before #1623.
        self.assertEqual(outage.ENTRY_FAILURE, outage.classify_failure(None))
        self.assertEqual(outage.ENTRY_FAILURE, outage.classify_failure(""))
        self.assertEqual(outage.ENTRY_FAILURE, outage.classify_failure({}))

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

    def test_the_cli_error_reader_takes_only_the_clis_own_rendering(self):
        # How a family tells the host's words from the agent's inside ONE text
        # field: the CLI's error prefix, anchored at the start.
        self.assertEqual("API Error: 403 Forbidden",
                         outage.cli_error("API Error: 403 Forbidden"))
        self.assertIsNone(outage.cli_error(
            '{"findings": [{"title": "API Error: 403 Forbidden is not handled"}]}'))
        self.assertIsNone(outage.cli_error(""))
        self.assertIsNone(outage.cli_error(None))


class TestTheFailureTally(unittest.TestCase):
    """#1623: the loop's per-entry streaks, and the host-outage verdict read
    off them. Here rather than in orchestrate.py because the classification and
    everything decided from it have one owner (and orchestrate.py is an entry
    script at its size ceiling)."""

    def _args(self, **kw):
        return type("Args", (), dict({"target": "/tmp/repo", "mode": "headless",
                                      "pr": None, "base": None, "setup": False}, **kw))()

    def _fail(self, error, host_error=None):
        """A failed launch. `host_error` is the HOST's own surface -- the only
        thing classified -- and absent is the ordinary case: the entry's own
        failure, which is what the streaks are for."""
        return base.RunResult.failed("e", error, host_error=host_error)

    def _ok(self):
        return base.RunResult(entry_id="e", ok=True, text="{}", usage={}, cost_usd=None,
                              model=None, session_id=None, denials=[], error=None)

    def test_an_entry_failure_charges_that_entry_and_nothing_else(self):
        tally = outage.FailureTally("claude", self._args())
        tally.record("a", self._fail("always"))
        tally.record("b", self._ok())
        self.assertIsNone(tally.settle())
        self.assertEqual({"a": 1}, tally.streaks)

    def test_a_clean_launch_clears_the_streak(self):
        tally = outage.FailureTally("claude", self._args())
        for _ in range(2):
            tally.record("a", self._fail("always"))
            tally.settle()
        tally.record("a", self._ok())
        tally.settle()
        self.assertEqual({}, tally.streaks)

    def test_a_refused_reply_is_the_entrys_failure_whatever_the_host_said(self):
        # persist refusing a reply is panopticon's own verdict: the launch
        # itself came back fine, so nothing about it can be the host's fault.
        tally = outage.FailureTally("claude", self._args())
        tally.record("a", self._ok(), refusal="persist refused: 403 findings were not adjudicated")
        self.assertIsNone(tally.settle())
        self.assertEqual({"a": 1}, tally.streaks)

    def test_a_whole_batch_of_host_failures_charges_nobody_and_pauses(self):
        tally = outage.FailureTally("kimi", self._args())
        for eid in ("a", "b", "c", "d"):
            tally.record(eid, self._fail("kimi -p exited 1: Error: 403 Forbidden",
                                         host_error="Error: 403 Forbidden"))
        message = tally.settle()
        self.assertEqual({}, tally.streaks)
        self.assertTrue(message.startswith("paused:"), message)
        self.assertIn("kimi", message)                       # the host
        self.assertIn(outage.HOST_FAILURE, message)            # the failure class
        self.assertIn("4", message)                          # the count
        self.assertIn("driver.py loop", message)             # the exact resume command
        self.assertIn("--host kimi", message)

    def test_a_mixed_batch_charges_only_the_entry_class_failures(self):
        tally = outage.FailureTally("claude", self._args())
        tally.record("a", self._fail("claude -p exited 1: 403 Forbidden",
                                     host_error="403 Forbidden"))
        tally.record("b", self._fail("always"))
        self.assertIsNone(tally.settle())                    # not an outage
        self.assertEqual({"b": 1}, tally.streaks)

    def test_a_batch_with_no_failures_at_all_is_not_an_outage(self):
        tally = outage.FailureTally("claude", self._args())
        tally.record("a", self._ok())
        self.assertIsNone(tally.settle())

    def test_settling_closes_the_batch(self):
        tally = outage.FailureTally("claude", self._args())
        tally.record("a", self._fail("403 Forbidden", host_error="403 Forbidden"))
        self.assertIsNotNone(tally.settle())
        self.assertIsNone(tally.settle())                    # the next batch is empty

    def test_the_cap_message_names_the_entry_the_count_and_its_last_error(self):
        tally = outage.FailureTally("claude", self._args())
        for _ in range(3):
            tally.record("a", self._fail("always"))
            tally.settle()
        self.assertIsNone(tally.exhausted([{"id": "a"}], 4))
        message = tally.exhausted([{"id": "a"}, {"id": "b"}], 3)
        self.assertIn("entry a failed 3 consecutive launches", message)
        self.assertIn("last: always", message)

    def test_an_entry_the_host_failed_never_reaches_the_cap(self):
        tally = outage.FailureTally("kimi", self._args())
        for _ in range(9):
            tally.record("a", self._fail("kimi -p exited 1: 429 rate limit",
                                         host_error="429 Too Many Requests"))
            tally.settle()
        self.assertIsNone(tally.exhausted([{"id": "a"}], 3))

    def test_the_resume_command_carries_the_flags_that_resolve_the_same_run(self):
        tally = outage.FailureTally("codex", self._args(target="/tmp/repo", pr=7, mode="headless"))
        tally.record("a", self._fail("codex exited with status 1: 503 Service Unavailable",
                                     host_error="503 Service Unavailable"))
        message = tally.settle()
        self.assertIn("--pr 7", message)
        self.assertIn("/tmp/repo", message)
        self.assertIn("--mode headless", message)
