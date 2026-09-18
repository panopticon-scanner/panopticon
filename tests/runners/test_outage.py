"""`runners/outage.py`: whose failure was that, and what the loop does about a
batch of them (#1623)."""
import unittest
from unittest import mock

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
        "permission_denied",              # the provider's wire kind, not the OS's English
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
        # N2. kimi and codex hand over their WHOLE stderr as the host surface,
        # so every EACCES line from the CLI or a tool it spawned arrives here.
        # `permission denied` is the OS's English, not a shape any provider
        # emits -- and a run told to wait for the provider and re-run
        # reproduces a local file-mode problem for ever.
        "grep: /repo/.git/objects/pack: Permission denied",
        "find: '/repo/node_modules/.cache': Permission denied",
        "PermissionError: [Errno 13] Permission denied: '/repo/.panopticon/runs'",
        "Error: EACCES: permission denied, open '/tmp/panopticon-kimi-x/config.toml'",
        "kimi: could not open the session wire file: Permission denied",
        "warning: unable to access '/repo/.git/config': Permission denied",
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
        # N3: the flattener joins key by key and `message` comes last, so a
        # status under `code`/`statusCode` and its reason in `message` were
        # never adjacent -- which is exactly what the status rule requires.
        # Each status key now qualifies its own number, and the camelCase and
        # `http_` spellings are read rather than dropped. These are the
        # CANONICAL shapes, not exotic ones, and missing them is the old
        # #1623 behaviour: the cells burn.
        for surface in ({"type": "authentication_error", "message": "invalid x-api-key"},
                        {"error": {"type": "rate_limit_error", "message": "slow down"}},
                        {"status": 429, "message": "please retry"},
                        {"code": "insufficient_quota"},
                        {"code": 403, "message": "Forbidden"},
                        {"code": 401, "message": "Unauthorized"},
                        {"error": {"code": 403, "message": "Forbidden"}},
                        {"statusCode": 429, "message": "slow down"},
                        {"status_code": 429},
                        {"http_status": 503},
                        {"error_code": 500, "message": "internal"},
                        {"type": "permission_error"},
                        {"type": "api_error", "status": 500}):
            with self.subTest(surface=surface):
                self.assertEqual(outage.HOST_FAILURE, outage.classify_failure(surface))
        # ...and a bare message from the agent's side of the world still is not
        for surface in ({"message": "the cell found a 403 handler"},
                        {"message": "src/billing/quota.py is missing"},
                        {"type": "api_error"},
                        {"file": "/repo/src/login.py", "line": 403}):
            with self.subTest(surface=surface):
                self.assertEqual(outage.ENTRY_FAILURE, outage.classify_failure(surface))

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

    # The CLI's own error renderings, which this gate exists to let through.
    CLI_ERRORS = (
        "API Error: 403 Forbidden",
        'API Error: 401 {"type":"authentication_error"}',
        "API Error: 429 Too Many Requests",
        "Invalid API key - please run /login",
        "Invalid API key \u00b7 Please run /login",
        "Overloaded",
        "Error: 503 Service Unavailable",
    )
    # ...and the AGENT's own opening words, which it must not. Every one of
    # these is a plausible first sentence of a review cell's reply, and every
    # one of them started with a prefix the gate used to accept on sight --
    # after which the anchored classifier ran over the WHOLE reply, so any
    # outage vocabulary anywhere in it flipped the class.
    AGENT_OPENERS = (
        "API Error responses leak stack traces; the 429 Too Many Requests branch "
        "returns the upstream body verbatim",
        "Authentication error handling is missing in src/login.py",
        "Rate limit exceeded responses are not handled",
        "Overloaded __eq__ hides the 403 Forbidden check",
        "Invalid API key handling: the 401 Unauthorized path logs the key",
        "Credit balance is too low is rendered to the user verbatim",
    )

    def test_the_cli_error_reader_takes_only_the_clis_own_rendering(self):
        # How a family tells the host's words from the agent's inside ONE text
        # field. The prefix must be followed by the DELIMITER a CLI actually
        # emits -- a colon, a middot, a dash, or the end of the line -- never
        # by more prose, or the gate is just a list of English sentence
        # openings.
        for text in self.CLI_ERRORS:
            with self.subTest(text=text):
                self.assertEqual(text, outage.cli_error(text))
                self.assertEqual(outage.HOST_FAILURE, outage.classify_failure(outage.cli_error(text)))
        for text in self.AGENT_OPENERS:
            with self.subTest(text=text):
                self.assertIsNone(outage.cli_error(text))
        self.assertIsNone(outage.cli_error(
            '{"findings": [{"title": "API Error: 403 Forbidden is not handled"}]}'))
        self.assertIsNone(outage.cli_error(""))
        self.assertIsNone(outage.cli_error(None))


class TestTheClassifierAfterTheR2ReReview(unittest.TestCase):
    """Item 25d PR 1, R2 re-review N5/N6/N7 (closed by the controller)."""

    # N5: the CLI framing must be followed by host-shaped content. A finding
    # that opens with `Error: 401 handling…` or `Overloaded: the scheduler…`
    # is the agent talking, however it is delimited.
    PROSE_FRAMINGS = (
        "error: 500 lines reviewed",
        "Error: 500 lines reviewed across 12 files; no blocking issues",
        "Error: 401 handling is missing in src/auth/view.py",
        "Error: 403 responses are never logged",
        "API Error: the 429 rate limit path is unhandled",
        "API Error: 401 handling is absent -- src/login.py returns the body verbatim",
        "Overloaded: the scheduler drops tasks under burst load (src/sched.py:41)",
        "Overloaded - the queue never drains; see worker.py",
        "Invalid API key, invalid session token and invalid nonce are all logged at INFO",
    )
    GENUINE_FRAMINGS = (
        "API Error: 429 {\"type\":\"error\",\"error\":{\"type\":\"rate_limit_error\"}}",
        "API Error: 529 {\"type\":\"overloaded_error\"}",
        "Error: 503 Service Unavailable",
        "Error: 429 Too Many Requests",
        "API Error: 401 Unauthorized",
        "API Error: 500 Internal Server Error",
        "API Error: 503 upstream connect error",
        "Invalid API key, please run /login",
        "Invalid API key",
        "Overloaded",
        "API Error: 502 Bad Gateway",
    )

    def test_a_prose_sentence_behind_the_framing_is_not_the_cli(self):
        # The gate is the whole defence on this path: the claude `result`
        # string reaches the classifier only when `cli_error` lets it through.
        for text in self.PROSE_FRAMINGS:
            with self.subTest(text=text):
                self.assertIsNone(outage.cli_error(text))

    def test_the_genuine_renderings_still_pass_the_framing(self):
        for text in self.GENUINE_FRAMINGS:
            with self.subTest(text=text):
                self.assertEqual(text, outage.cli_error(text))
                self.assertEqual(outage.HOST_FAILURE, outage.classify_failure(text))

    # N6: `code` and 500 qualify a status only inside the provider's error
    # OBJECT; in free text (kimi's and codex's whole stderr) they are what a
    # tool says about the code under review.
    TOOL_STDERR = (
        "mypy: Found 500 errors in 42 files (checked 118 source files)",
        "eslint: 500 problems (500 errors, 0 warnings)",
        "error: 500 problems found",
        "Compilation failed: 500 errors",
        "the code (403 lines) was reviewed",
        "exit code 500",
        "npm ERR! code 500",
        "internal error code 500 while reading the cache",
        "500 errors",
        "Found 500 error(s)",
    )
    OBJECT_SHAPES = (
        {"code": 403, "message": "Forbidden"},
        {"statusCode": 429},
        {"http_status": 503},
        {"type": "permission_error"},
        {"type": "api_error", "status": 500},
        {"error": {"code": 500, "type": "api_error"}},
    )

    def test_tool_stderr_counting_errors_is_not_the_provider(self):
        for text in self.TOOL_STDERR:
            with self.subTest(text=text):
                self.assertEqual(outage.ENTRY_FAILURE, outage.classify_failure(text))

    def test_the_provider_object_still_qualifies_its_own_number(self):
        for obj in self.OBJECT_SHAPES:
            with self.subTest(obj=obj):
                self.assertEqual(outage.HOST_FAILURE, outage.classify_failure(obj))

    # N7: the same envelope arriving as raw JSON on a family's stderr.
    RAW_JSON = (
        '{"error":{"status":403,"message":"Forbidden"}}',
        '{"error":{"code":403,"message":"Forbidden"}}',
        '{"status_code":429,"message":"slow down"}',
        '{"http_status":503}',
        '{"statusCode":429}',
        '{"error":{"message":"Forbidden"},"status":403}',
    )
    RAW_JSON_ENTRY = (
        '{"file":"src/api.py","line":403}',
        '{"error":"at line 403 of src/api.py"}',
        "kimi -p timed out after 403s",
        '{"findings":[{"severity":"HIGH","line":500}]}',
    )

    def test_a_json_envelope_on_stderr_is_read_through_its_quotes(self):
        for text in self.RAW_JSON:
            with self.subTest(text=text):
                self.assertEqual(outage.HOST_FAILURE, outage.classify_failure(text))

    def test_json_that_merely_contains_a_number_is_not(self):
        for text in self.RAW_JSON_ENTRY:
            with self.subTest(text=text):
                self.assertEqual(outage.ENTRY_FAILURE, outage.classify_failure(text))


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
        self.assertIn("driver loop", message)                # the exact resume command
        self.assertIn("--host kimi", message)

    def test_a_mixed_batch_charges_only_the_entry_class_failures(self):
        # #1721: the VERDICT this used to pin -- "a mixed batch is not an
        # outage" -- is the defect. The run the 403 opened is still open when
        # the batch ends (an entry-class failure neither extends nor closes
        # it), so it pauses; what is unchanged, and is what this test is for,
        # is the CHARGE.
        tally = outage.FailureTally("claude", self._args())
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
        tally = outage.FailureTally("claude", self._args())
        tally.record("a", self._ok())
        self.assertIsNone(tally.settle())

    def test_settling_closes_the_batch(self):
        tally = outage.FailureTally("claude", self._args())
        tally.record("a", self._fail("403 Forbidden", host_error="403 Forbidden"))
        self.assertIsNotNone(tally.settle())
        self.assertIsNone(tally.settle())                    # the next batch is empty

    # ---- #1721: the trailing-run rule -------------------------------------
    #
    # All-or-nothing made ONE entry-class failure anywhere in a batch cancel a
    # real outage: no pause, no attempt given back, every cell charged. What
    # settles a batch now is whether it ENDED in a run of host-class failures.

    def test_a_trailing_run_pauses_despite_an_earlier_entry_class_failure(self):
        tally = outage.FailureTally("kimi", self._args())
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
        tally = outage.FailureTally("kimi", self._args())
        tally.record("b", self._fail("403", host_error="403 Forbidden"), seq=3)
        tally.record("a", self._ok(), seq=1)               # launched before the outage
        self.assertIsNotNone(tally.settle())

    def test_a_success_launched_after_the_outage_closes_the_run(self):
        tally = outage.FailureTally("kimi", self._args())
        for seq, eid in ((0, "a"), (1, "b")):
            tally.record(eid, self._fail("403", host_error="403 Forbidden"), seq=seq)
        self.assertTrue(tally.outage(2))
        tally.record("c", self._ok(), seq=2)               # the host is back
        self.assertFalse(tally.outage(2))
        self.assertIsNone(tally.settle())
        self.assertEqual({}, tally.streaks)                # ...and the 403s cost nobody
        self.assertEqual(["a", "b"], tally.uncharged)

    def test_an_entry_class_failure_neither_opens_extends_nor_closes_the_run(self):
        tally = outage.FailureTally("kimi", self._args())
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
            tally = outage.FailureTally("kimi", self._args())
            for seq in range(threshold):
                self.assertFalse(tally.outage(width), (width, seq))
                tally.record("e%d" % seq, self._fail("403", host_error="403 Forbidden"),
                             seq=seq)
            self.assertTrue(tally.outage(width), width)

    def test_the_pause_says_how_many_entries_were_never_launched(self):
        tally = outage.FailureTally("kimi", self._args())
        for seq in range(2):
            tally.record("e%d" % seq, self._fail("403", host_error="403 Forbidden"), seq=seq)
        message = tally.settle(70)
        self.assertIn("70", message)
        self.assertIn(outage.HOST_OUTAGE_CLAUSE, message)  # the guide quotes this verbatim

    def test_uncharged_lists_the_host_class_ids_and_resets_per_batch(self):
        tally = outage.FailureTally("kimi", self._args())
        tally.record("a", self._ok(), seq=0)
        tally.record("b", self._fail("its own fault"), seq=1)
        tally.record("c", self._fail("403", host_error="403 Forbidden"), seq=2)
        tally.settle()
        self.assertEqual(["c"], tally.uncharged)
        tally.record("d", self._ok(), seq=0)
        tally.settle()
        self.assertEqual([], tally.uncharged)

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

    def test_the_resume_command_names_the_program_this_process_was_started_as(self):
        # #495: `python3 skill/scripts/driver.py` is the GUIDE's placeholder
        # for the install directory, so hard-coding it prints a path that does
        # not exist on an installed skill. Read off argv, with the abbreviated
        # form every other runtime hint uses as the fallback.
        tally = outage.FailureTally("claude", self._args())
        with mock.patch.object(outage.sys, "argv", ["/opt/panopticon/skill/scripts/driver.py",
                                                    "loop"]):
            self.assertEqual("python3 /opt/panopticon/skill/scripts/driver.py",
                             outage.program())
            self.assertIn("python3 /opt/panopticon/skill/scripts/driver.py loop",
                          tally.resume_command())
        with mock.patch.object(outage.sys, "argv", ["/usr/local/bin/pytest"]):
            self.assertEqual("driver", outage.program())

    def test_the_resume_command_never_carries_reset(self):
        # It would discard the very run the line exists to resume.
        args = self._args()
        args.reset = True
        self.assertNotIn("--reset", outage.FailureTally("claude", args).resume_command())

    def test_the_resume_command_carries_the_flags_that_resolve_the_same_run(self):
        tally = outage.FailureTally("codex", self._args(target="/tmp/repo", pr=7, mode="headless"))
        tally.record("a", self._fail("codex exited with status 1: 503 Service Unavailable",
                                     host_error="503 Service Unavailable"))
        message = tally.settle()
        self.assertIn("--pr 7", message)
        self.assertIn("/tmp/repo", message)
        self.assertIn("--mode headless", message)
