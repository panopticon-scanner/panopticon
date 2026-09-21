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
import tempfile
import unittest

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
    """#1697: the ten forms the module docstring ruled, each as a live step."""

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

    # A subshell written tight: the reader has no paren grammar, so `(curl`
    # is one word and the fetch at its head is unseen; the spaced spelling is
    # read. KEPT -- closing it is a grouping model the flat reader lacks.
    def test_a_fetch_at_the_head_of_a_tight_subshell_is_unseen(self):
        tight = "(curl -sfL https://example.test/payload -o /tmp/payload || true)\n"
        self.assertEqual([], wg.fetches(tight))
        self.accepted(("get", tight), ("run", "chmod +x /tmp/payload\n"))

    def test_the_same_subshell_with_a_space_is_read(self):
        spaced = "( curl -sfL https://example.test/payload -o /tmp/payload || true )\n"
        self.assertEqual(1, len(wg.fetches(spaced)), wg.fetches(spaced))
        self.flagged(("get", spaced), ("run", "chmod +x /tmp/payload\n"))

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
        # quoted script is read as hardened rather than as unread.
        self.accepted(("run", 'sh -c "curl -sfL https://example.test/p -o /tmp/p; '
                              'echo %s  /tmp/p | sha256sum -c -; '
                              'chmod +x /tmp/p"\n' % HEX))

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
            lines = []
            self.assertEqual(1, wg.main([path], out=lines.append))
            self.assertTrue(any("install" in ln for ln in lines), lines)

    def test_a_clean_workflow_exits_zero(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "ok.yml")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(self.WORKFLOW.replace(
                    "curl -fsSL https://example.test/i.sh | sh", "make test"))
            self.assertEqual(0, wg.main([path], out=lambda _line: None))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
