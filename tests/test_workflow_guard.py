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

import workflow_guard as wg
from workflow_guard import Fetch

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

    def test_a_plain_check_still_counts(self):
        self.assertIsNone(
            self.swallowed('echo "%s  /tmp/payload" | sha256sum -c -\n' % HEX))

    def test_a_check_joined_with_and_still_counts(self):
        self.assertIsNone(self.swallowed(
            'echo "%s  /tmp/payload" | sha256sum -c - && echo verified\n' % HEX))


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
