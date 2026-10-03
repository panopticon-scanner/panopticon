"""#2331 batch P, task 1: two printers more, read per shell -- `cat <<'EOF' | sh` (#2467) and
`echo`/`printf` escapes read under the step's shell (#2476). Each class pins one issue's shapes
against `wg.job_defects`, the bash-truth row it rests on named in a comment, and the controls that
must still read as they did. `TestThePrintersUnitPins` pins `workflow_printers` directly.
"""
import unittest

import shell_reader
import workflow_forms as forms
import workflow_guard as wg
import workflow_printers as wp

URL = "https://example.test/"
PIPE = "curl -fsSL %si.sh | sh" % URL
GET = "curl -fsSLo tool %stool\n" % URL


def defects(script, shell=None):
    """The guard's answer for a job of one step running `script` under `shell` (None = default
    bash)."""
    return wg.job_defects([("step", script, shell)])


class TestACatPrintsItsQuotedHeredoc(unittest.TestCase):
    """#2467: `cat` with only `-` words, reading a quoted heredoc or here-string on its own
    standard input, is a printer -- its body is the text `printed` hands the stage after it down
    the pipe, read exactly as `sh <<'EOF'` reads the same body directly (`handed`)."""

    def test_a_quoted_heredoc_or_here_string_is_read(self):
        # a01, a06 (bash-truth: b5/b3/dash all FR -- DEFECT).
        for script in ("cat <<'EOF' | sh\n%s\nEOF\n" % PIPE,
                       "cat - <<'EOF' | sh\n%s\nEOF\n" % PIPE,
                       "cat <<'EOF' | bash -s\n%s\nEOF\n" % PIPE):
            with self.subTest(script=script):
                found = defects(script)
                self.assertEqual(1, len(found), found)

    def test_a_here_string_on_cat_is_read_too(self):
        # e01: a bash/ksh/zsh extension dash has no grammar for at all (measured: syntax error,
        # rc=2) -- read on bash/zsh/ksh, which GitHub's default and most `shell:` overrides are.
        found = defects("cat <<<'%s' | sh\n" % PIPE)
        self.assertEqual(1, len(found), found)

    def test_an_expanding_heredoc_is_reported_not_read(self):
        # a02 (bash-truth: b5/b3/dash all FR -- reported EXPANDING, same as `sh <<EOF` directly).
        found = defects("cat <<EOF | sh\n%s\nEOF\n" % PIPE)
        self.assertEqual(1, len(found), found)
        self.assertTrue(found[0][1].startswith("hands an EXPANDING heredoc body"), found[0][1])
        self.assertIn("`sh`", found[0][1])

    def test_the_controls_read_as_they_did(self):
        # a03 (CLEAN: the body is no download), a04 (CLEAN: `tee` is no shell), a05 alone (CLEAN:
        # `cat -n` is no printer -- R-P5 -- bash-truth "1: command not found"), `cat`'s file-operand
        # rule (R-P5, beside #2293's pre-existing `cat tool | sh`).
        for script in ("cat <<'EOF' | sh\necho hi\nEOF\n",
                       "cat <<'EOF' | tee x.sh\n%s\nEOF\n" % PIPE,
                       "cat -n <<'EOF' | sh\n%s\nEOF\n" % PIPE,
                       "echo hi > notes.txt\ncat notes.txt | sh\n"):
            with self.subTest(script=script):
                self.assertEqual([], defects(script))
        # `cat -n` beside an already-reported use of the SAME download: exactly the one row the
        # use's own fetch-and-exec sentence gives, no second row about the `cat -n` heredoc.
        found = defects(GET + "cat -n <<'EOF' | sh\n%s\nEOF\n" % PIPE + "sh tool\n")
        self.assertEqual(1, len(found), found)
        self.assertIn("running it under `sh`", found[0][1])
        # GET + `cat tool | sh` is still the pre-existing file rule, unaffected.
        self.assertTrue(defects(GET + "cat tool | sh\n"))

    def test_a_check_in_front_clears_it_as_the_printer_idiom_does(self):
        # Mirrors `TestAProgramPipedFromAPrinter.test_a_program_a_printer_spells_out_is_read`'s
        # check idiom: a checksum naming the download, immediately before the statement that runs
        # it, clears `cat <<'EOF' | sh` exactly as it clears `echo 'sh tool' | sh` written out.
        check = "echo '%s  tool' | sha256sum -c -%s\ncat <<'EOF' | sh\nsh tool\nEOF\n"
        self.assertEqual([], defects(GET + check % ("a" * 64, "")))
        self.assertTrue(defects(GET + check % ("a" * 64, " || true")))

    def test_a_check_inside_the_quoted_body_mirrors_sh_eof_exactly(self):
        # A checksum-then-use INSIDE the quoted heredoc body resolves exactly as the identical body
        # does when `sh <<'EOF'` reads it directly (`stdin_heredoc`) -- no `-e` holds inside either
        # nested `sh` invocation, so this is the SAME non-clearing answer both ways, proving `cat`
        # delegates to the one path rather than a new one.
        body = "echo '%s  tool' | sha256sum -c -\nsh tool\n" % ("a" * 64)
        direct = defects(GET + "sh <<'EOF'\n%sEOF\n" % body)
        via_cat = defects(GET + "cat <<'EOF' | sh\n%sEOF\n" % body)
        self.assertEqual(direct, via_cat)
        self.assertEqual(1, len(via_cat))
        # r82, r83: with `set -e` inside the body, the checksum's failure DOES stop the nested
        # `sh` before `sh tool` runs -- CLEAR both ways, same proof as above.
        cleared = "set -e\n" + body
        direct_e = defects(GET + "sh <<'EOF'\n%sEOF\n" % cleared)
        via_cat_e = defects(GET + "cat <<'EOF' | sh\n%sEOF\n" % cleared)
        self.assertEqual(direct_e, via_cat_e)
        self.assertEqual([], via_cat_e)


class TestEchoAndPrintfReadPerShell(unittest.TestCase):
    """#2476: `echo`'s backslash escapes are read as the step's shell decodes them (bash: literal
    unless `-e` stands with no `E` after it; every other shell, `sh` on ubuntu among them: always
    -- `-e`/`-E` are text there); a `printf` format decodes under every shell."""

    def test_echo_tab_bash_literal_sh_decodes(self):
        # b01 (bash-truth: b5/b3 F- -- CLEAN; dash FR -- DEFECT).
        script = GET + "echo 'sh\\ttool' | sh\n"
        self.assertEqual([], defects(script))
        self.assertEqual([], defects(script, "bash"))
        found = defects(script, "sh")
        self.assertEqual(1, len(found), found)
        self.assertIn("tool", found[0][1])
        self.assertNotIsInstance(found[0][1], forms._Quiet)

    def test_echo_dash_e_decodes_under_bash_not_sh(self):
        # b02 (bash-truth: b5/b3 FR -- DEFECT; dash: `-e` is unknown to its echo and prints as
        # text, so nothing resembling `tool` runs -- CLEAN under `sh`).
        script = GET + "echo -e 'sh\\ttool' | sh\n"
        found = defects(script)
        self.assertEqual(1, len(found), found)
        self.assertNotIsInstance(found[0][1], forms._Quiet)
        self.assertEqual([], defects(script, "sh"))

    def test_echo_dash_e_dash_E_bash_last_wins(self):
        # bash: `-e` then `-E` after it -- "last wins" turns decoding back off.
        self.assertEqual([], defects(GET + "echo -e -E 'sh\\ttool' | sh\n"))

    def test_echo_plain_space_runs_under_every_shell(self):
        # b03 (bash-truth: b5/b3/dash all FR -- DEFECT; no escape, nothing to decode).
        script = GET + "echo 'sh tool' | sh\n"
        for shell in (None, "bash", "sh"):
            with self.subTest(shell=shell):
                self.assertEqual(1, len(defects(script, shell)))

    def test_echo_x_hex_is_outside_the_table_both_ways(self):
        # b04 (bash-truth: F- on all three -- CLEAN; plain `echo` with no `-e` never decodes it
        # either way, so this row's own truth is CLEAN regardless). `\\x` itself is outside this
        # module's table in EVERY reading (unlike here, bash's `-e` and `printf` DO decode it in
        # reality, measured r19 bash FR -- a documented, accepted gap, not modeled, fail-closed).
        # Bare, with no fetch anywhere in the job, this is Idle with nothing to stand beside.
        bare = "echo 'sh\\x20tool' | sh\n"
        self.assertEqual([], defects(bare))
        self.assertEqual([], defects(bare, "sh"))
        # Beside an unchecked download (GET, nothing verifies it) under `sh`, the unspelled reason
        # stands alone as a `_PRINTED` `_Quiet` row -- the same rule `test_a_program_it_does_not_
        # spell_out_is_reported_unread` already pins for `echo "$X" | sh` beside GET: a fetch
        # nothing checks, beside a form this guard cannot read, is kept rather than silent (#2481).
        found = defects(GET + bare, "sh")
        self.assertEqual(1, len(found), found)
        self.assertIsInstance(found[0][1], forms._Quiet)
        self.assertIn("does not spell out", found[0][1])
        # Under bash, `\\x` is never decoded at all, so `printed` hands the LITERAL garbage word on
        # instead of leaving it unspelled -- no shell reads it as `tool`, so still clean beside GET.
        self.assertEqual([], defects(GET + bare))
        # Beside an ALREADY-reported, confirmed use of the same download, the unspelled reason is
        # kept: one `_PRINTED` `_Quiet` row more than `GET + "sh tool\\n"` alone gives.
        baseline = defects(GET + "sh tool\n")
        self.assertEqual(1, len(baseline))
        found = defects(GET + bare + "sh tool\n", "sh")
        self.assertEqual(2, len(found), found)
        self.assertTrue(any(isinstance(why, forms._Quiet) for _n, why in found))

    def test_echo_backslash_n_must_not_be_a_new_fail_open(self):
        # b05: bash-truth says "whatever the reader gives; must not be a NEW fail-open". Under
        # bash (no decode), the literal `sh\\ntool` is one word no shell reads as two: CLEAN.
        # Under `sh` (decodes), `\\n` becomes a real newline, splitting the text into the two
        # LINES `sh` and `tool` -- measured, NOTHING runs: a bare `tool` on its own line is not
        # on PATH, so dash says "not found" (F-). The guard's D here is an OVER-report, not a
        # correct catch -- accepted, the safe direction (not a fail-open).
        script = GET + "echo 'sh\\ntool' | sh\n"
        self.assertEqual([], defects(script))
        found = defects(script, "sh")
        self.assertEqual(1, len(found), found)
        self.assertIn("running it", found[0][1])

    def test_echo_backslash_c_truncates_under_sh_not_bash(self):
        # b06 (bash-truth: dash FR -- DEFECT, `\\c` ends the text there, leaving exactly `sh tool`;
        # b5/b3 F- -- CLEAN, the whole literal text including `\\c ignored` is one unreadable line).
        script = GET + "echo 'sh tool\\c ignored' | sh\n"
        self.assertEqual([], defects(script))
        found = defects(script, "sh")
        self.assertEqual(1, len(found), found)
        self.assertNotIsInstance(found[0][1], forms._Quiet)

    def test_echo_double_backslash_decodes_to_one_under_sh(self):
        # b07 (bash-truth: dash FR -- DEFECT; b5/b3 F- -- CLEAN). The raw text carries TWO literal
        # backslashes before `tool`; `sh`'s decode halves that to one, which the INNER `sh`'s own
        # tokenizer then strips (backslash + any char = that char, unquoted) down to plain `tool`.
        script = GET + "echo 'sh \\\\tool' | sh\n"
        self.assertEqual([], defects(script))
        found = defects(script, "sh")
        self.assertEqual(1, len(found), found)
        self.assertNotIsInstance(found[0][1], forms._Quiet)

    def test_echo_dash_E_is_text_under_sh_and_bash_alike(self):
        # b09 (bash-truth: F- on all three -- CLEAN). Under bash, `-E` alone (no `-e` first) never
        # turns decoding on. Under `sh`, `-E` is not an option at all (only `-n` is) -- it is TEXT,
        # not a flag, so the first echoed word is literally `-E`, not `sh`.
        script = GET + "echo -E 'sh\\ttool' | sh\n"
        self.assertEqual([], defects(script))
        self.assertEqual([], defects(script, "sh"))

    def test_printf_format_always_decodes(self):
        # b10 (bash-truth: b5/b3/dash all FR -- DEFECT; printf's format decodes under every shell).
        script = GET + "printf 'sh\\ttool\\n' | sh\n"
        for shell in (None, "bash", "sh"):
            with self.subTest(shell=shell):
                found = defects(script, shell)
                self.assertEqual(1, len(found), found)
                self.assertNotIsInstance(found[0][1], forms._Quiet)

    def test_printf_percent_s_word_is_literal(self):
        # b11 (bash-truth: F- on all three -- CLEAN). `%s`'s WORD argument is never decoded, only
        # the format string is -- `\\t` inside the word stays literal text, two words run together.
        self.assertEqual([], defects(GET + "printf '%s\\n' 'sh\\ttool' | sh\n"))

    def test_printf_percent_b_word_decodes(self):
        # c01 (bash-truth measured for this task: b5/b3/dash all FR -- DEFECT). Unlike `%s`, `%b`'s
        # word IS decoded, with the same table `echo`'s own text and every format use.
        script = GET + "printf '%b\\n' 'sh\\ttool' | sh\n"
        for shell in (None, "bash", "sh"):
            with self.subTest(shell=shell):
                found = defects(script, shell)
                self.assertEqual(1, len(found), found)
                self.assertNotIsInstance(found[0][1], forms._Quiet)

    def test_a_check_in_front_clears_printf_too(self):
        # The same check idiom, with `printf` as the reported use's printer instead of `echo`.
        check = "echo '%s  tool' | sha256sum -c -\n" % ("a" * 64)
        self.assertEqual([], defects(GET + check + "printf 'sh tool\\n' | sh\n"))

    def test_nested_dash_c_runs_the_printer_under_its_own_runner_not_the_steps_shell(self):
        # d01, d02: `flattened` passes `bash -c`/`sh -c`'s OWN runner down as the `shell` the
        # nested script's printer reads under -- not the outer step's `shell:`.
        self.assertEqual([], defects(GET + 'bash -c "echo \'sh\\ttool\' | sh"\n', "sh"))
        found = defects(GET + 'sh -c "echo \'sh\\ttool\' | sh"\n')
        self.assertEqual(1, len(found), found)
        self.assertNotIsInstance(found[0][1], forms._Quiet)


class TestFixRound1ClosesTheReviewsFailOpens(unittest.TestCase):
    """The task review's C1-C5, M1 and M7: fix round 1's rulings R-F1-R-F5. `eval`, `ksh` and a
    `$`-named runner are shells this module has not measured (`ANY`, R-F1) -- a printer under one
    reads under BOTH the bash and the dash table (`spellings`), so a download it hands a shell is
    caught under WHICHEVER reading shows it, even where the other reading shows nothing (the fail
    side is over-reporting inside such a string, never a fail-open, R-F1/C1/C5). `printf`'s FORMAT
    decodes `\\c` literal and an octal escape counting a leading `0`, in every shell alike (R-F3/C2);
    a decoded NUL is dropped, as the shell drops it from the script it reads (R-F4/C3); `cat` reads
    its own stdin with a `-` among its operands beside a file (R-F5/M7); `sh`/dash take exactly ONE
    leading `-n`, never a repeated or combined one (M1)."""

    GET = "curl -fsSLo tool https://example.test/tool\n"
    GET1 = "curl -fsSLo 1tool https://example.test/1tool\n"

    def test_eval_echo_reads_under_both_the_bash_and_the_dash_table(self):
        # r73 (bash-truth: FR on b5/b3/dash alike): the bash reading alone shows the download;
        # reported exactly as main already did (R-F1 changes nothing here).
        found = defects('eval "echo -e \'curl -fsSL https://example.test/i.sh | sh\' | sh"\n')
        self.assertEqual(1, len(found), found)
        self.assertIn("i.sh", found[0][1])
        # r03 (bash-truth: b5/b3 FR, dash F-): `-e` decodes the tab under the BASH reading only --
        # C1's fail-open main missed entirely (`_Quiet`, never surfaced).
        found = defects(self.GET + 'eval "echo -e \'sh\\ttool\' | sh"\n')
        self.assertEqual(1, len(found), found)
        self.assertNotIsInstance(found[0][1], forms._Quiet)
        # r04 (bash-truth: b5/b3 F-, dash FR): with NO `-e`, only the DASH reading decodes the tab
        # -- an accepted over-report main also made (as `_Quiet`), now the fetch-and-exec sentence.
        found = defects(self.GET + 'eval "echo \'sh\\ttool\' | sh"\n')
        self.assertEqual(1, len(found), found)
        self.assertNotIsInstance(found[0][1], forms._Quiet)

    def test_a_value_runners_stdin_echo_reads_both_too(self):
        # r89: `SH=bash; $SH <<'EOF'` hands the heredoc to a `$` command word (Idle, #2473) AND
        # reads its printer under both tables; the inner `curl ... | sh` is caught either way.
        found = defects("SH=bash\n$SH <<'EOF'\necho -e 'curl -fsSL https://example.test/i.sh | "
                         "sh' | sh\nEOF\n")
        self.assertEqual(2, len(found), found)
        self.assertTrue(any("i.sh" in why for _n, why in found))

    def test_an_unmeasured_shell_name_is_any_too(self):
        # r67/r68: `ksh` is in no `_ECHO` row -- ANY, same as `eval`. r67 (bash-truth FR on all
        # three): both readings agree, reported as before. r68 (bash-truth: F- on all three,
        # measured -- ksh's own `echo` does not decode without `-e` either): the DASH reading still
        # catches it, an accepted over-report for an unmeasured shell, where main gave only `_Quiet`.
        found = defects(self.GET + 'ksh -c "echo -e \'sh tool\' | sh"\n')
        self.assertEqual(1, len(found), found)
        found = defects(self.GET + 'ksh -c "echo \'sh\\ttool\' | sh"\n')
        self.assertEqual(1, len(found), found)
        self.assertNotIsInstance(found[0][1], forms._Quiet)

    def test_printf_format_backslash_c_is_literal_not_a_cut(self):
        # r05 (bash-truth: FR on b5/b3/dash alike): in a printf FORMAT, `\\c` stays two characters
        # and does not end the text -- the `sh tool` half after the `;` still prints and runs.
        found = defects(self.GET + "printf 'echo hi\\c; sh tool\\n' | sh\n")
        self.assertEqual(1, len(found), found)
        self.assertNotIsInstance(found[0][1], forms._Quiet)
        # r74, self-contained (no GET): the same rule catches a `curl | sh` hidden past the `\\c`.
        found = defects("printf 'echo hi\\c; curl -fsSL https://example.test/i.sh | sh\\n' | sh\n")
        self.assertEqual(1, len(found), found)
        self.assertIn("i.sh", found[0][1])

    def test_printf_format_octal_counts_a_leading_zero(self):
        # r06 (bash-truth: FR on b5/b3/dash alike): `\\0043` decodes `\\004` (EOT, dropped by the
        # shell that reads it) then the literal `3`, leaving `3; sh tool` -- `sh tool` still runs.
        found = defects(self.GET + "printf '\\0043; sh tool\\n' | sh\n")
        self.assertEqual(1, len(found), found)
        self.assertNotIsInstance(found[0][1], forms._Quiet)
        # r29: `\\0401tool` decodes `\\040` (a space) then literal `1tool` -- `sh 1tool` runs the
        # download named `1tool`, not the `tool` of the other pins.
        found = defects(self.GET1 + "printf 'sh\\0401tool\\n' | sh\n")
        self.assertEqual(1, len(found), found)
        self.assertIn("1tool", found[0][1])

    def test_a_decoded_nul_is_dropped(self):
        # r38, r65 (bash-truth: FR on b5/b3, dash F- -- `-e` is unknown to dash's echo): the BASH
        # reading decodes the octal NUL and drops it, leaving `sh tool`/`sh to`+`ol` whole.
        for script in (self.GET + "echo -e 'sh tool\\0000' | sh\n",
                       self.GET + "echo -e 'sh to\\00ol' | sh\n"):
            with self.subTest(script=script):
                found = defects(script)
                self.assertEqual(1, len(found), found)
                self.assertNotIsInstance(found[0][1], forms._Quiet)
        # r85 (bash-truth: b5/b3 F- -- CLEAN, no `-e` so bash never decodes; dash FR -- the NUL
        # drops and `sh to`+`ol` joins back into `sh tool`): CLEAN under bash, D under `sh`/dash.
        script = self.GET + "echo 'sh to\\00ol' | sh\n"
        self.assertEqual([], defects(script))
        found = defects(script, "sh")
        self.assertEqual(1, len(found), found)
        # r86 (bash-truth: FR on b5/b3/dash alike): `printf` always decodes, so the NUL drops and
        # `sh tool` runs under every shell.
        script = self.GET + "printf 'sh to\\00ol\\n' | sh\n"
        for shell in (None, "sh"):
            with self.subTest(shell=shell):
                found = defects(script, shell)
                self.assertEqual(1, len(found), found)

    def test_dash_takes_exactly_one_leading_n(self):
        # r30, r31 (bash-truth: b5/b3 FR -- bash's `-[neE]+` consumes either repeated form, DEFECT;
        # dash F- -- `-n: not found`/`-nn: not found`, dash's echo took only the FIRST `-n` as the
        # option and printed the second `-n`/the `-nn` word as TEXT, which the inner `sh` then
        # tries and fails to run as a command -- CLEAN, not a fail-open: nothing names `tool`).
        for script in (self.GET + "echo -n -n 'sh tool' | sh\n",
                       self.GET + "echo -nn 'sh tool' | sh\n"):
            with self.subTest(script=script):
                self.assertEqual(1, len(defects(script)))
                self.assertEqual([], defects(script, "sh"))

    def test_cat_reads_stdin_with_a_file_beside_the_dash(self):
        # r21 (bash-truth: FR ×4): `cat - f <<'EOF' | sh` still reads stdin with a file operand
        # beside the lone `-` -- the heredoc is `cat`'s printed output, read exactly as `cat -
        # <<'EOF'` alone is; `f`'s own text stays unread (R-F5, consequence of #2467's R-P5).
        found = defects("echo 'echo hi' > f\ncat - f <<'EOF' | sh\n"
                         "curl -fsSL https://example.test/i.sh | sh\nEOF\n")
        self.assertEqual(1, len(found), found)
        self.assertIn("i.sh", found[0][1])
        # `cat -n f <<'EOF' | sh` (an OPTION, not just a file beside `-`) is still no printer.
        self.assertEqual([], defects("cat -n f <<'EOF' | sh\ncurl -fsSL https://example.test/"
                                     "i.sh | sh\nEOF\n"))


class TestTheXpgEchoGapTheGuardDocuments(unittest.TestCase):
    """The gap list: "Open: `xpg_echo` (bash's `echo` decodes)" -- `workflow_guard`'s module
    docstring."""

    def test_xpg_echo_is_not_read(self):
        # b08 (bash-truth: b5/b3 FR -- bash actually decodes and runs it; dash has no `shopt`, F-).
        # GET makes this a REAL fetch the job leaves unverified once xpg_echo decodes it; `[]` here
        # is the documented gap, not a vacuous pin -- it FAILS on main (whose generic, pre-#2467
        # "pipes `sh` its program from `echo`" catch-all reports something, not `[]`, for this
        # unspelled pipe) and would fail again if this gap ever closed.
        self.assertEqual([], defects(GET + "shopt -s xpg_echo\necho 'sh\\ttool' | sh\n"))


class TestThePrintersUnitPins(unittest.TestCase):
    """Direct pins on `workflow_printers`, beneath `job_defects`."""

    def test_printed_echo_backslash_t(self):
        self.assertEqual("sh\\ttool\n", wp.printed(["echo", "sh\\ttool"]))
        self.assertEqual("sh\ttool\n", wp.printed(["echo", "sh\\ttool"], shell="sh"))
        self.assertEqual("sh\ttool\n", wp.printed(["echo", "-e", "sh\\ttool"]))

    def test_printed_echo_x_hex_is_unspelled_both_ways(self):
        self.assertIsNone(wp.printed(["echo", "sh\\x20tool"], shell="sh"))
        self.assertIsNone(wp.printed(["echo", "-e", "sh\\x20tool"]))

    def test_printed_printf_tab_decodes(self):
        self.assertEqual("sh\ttool\n", wp.printed(["printf", "sh\\ttool\\n"]))

    def test_printed_cat_reads_its_quoted_heredoc(self):
        stages = shell_reader.statements("cat <<'EOF' | sh\nbody text\nEOF\n")[0].stages
        self.assertEqual("body text", wp.printed(["cat"], stages[0]))

    def test_handed_carries_the_heredoc_down_the_pipe(self):
        stages = shell_reader.statements("cat <<'EOF' | sh\nbody text\nEOF\n")[0].stages
        self.assertEqual(("body text", False), wp.handed(stages[1], stages[0]))

    def test_decoded_backslash_c_and_octal(self):
        self.assertEqual("a", wp._decoded("a\\cb"))
        self.assertEqual("A", wp._decoded("\\0101"))


if __name__ == "__main__":
    unittest.main()
