"""#2331 batch P, task 1: two printers more, read per shell -- `cat <<'EOF' | sh` (#2467) and
`echo`/`printf` escapes read under the step's shell (#2476); then a pass-through stage between the
printer and the shell (#2478). Task 2: a printer reaching a shell through a substitution (#2487,
#2495) and the `echo` inside a `$(...)` read under the shell that runs it (#2728). Each class pins
one issue's shapes against `wg.job_defects`, the bash-truth row it rests on named in a comment, and
the controls that must still read as they did. `TestThePrintersUnitPins` pins `workflow_printers`
directly, as the last tests of `TestAPrinterThroughASubstitution` do its substitution helpers.
"""
import unittest

import shell_reader
import shell_wrappers
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
        # a03 (CLEAN: the body is no download), a04 (CLEAN: `tee` is no shell), `cat`'s file-operand
        # rule (R-P5, beside #2293's pre-existing `cat tool | sh`).
        for script in ("cat <<'EOF' | sh\necho hi\nEOF\n",
                       "cat <<'EOF' | tee x.sh\n%s\nEOF\n" % PIPE,
                       "echo hi > notes.txt\ncat notes.txt | sh\n"):
            with self.subTest(script=script):
                self.assertEqual([], defects(script))
        # a05, flipped by fix round 4 (R-F14): `cat -n` reads its own stdin, so its body is read
        # as written -- an OVER-report (bash-truth -- x4, measured as g01: `-n` numbers the line,
        # so the inner `sh` runs `1`, "1: command not found"), the price of reading every option's
        # `cat` as printing its body, rather than leaving `cat -u`/`-s`/`-v` (FR x4) unread.
        found = defects("cat -n <<'EOF' | sh\n%s\nEOF\n" % PIPE)
        self.assertEqual(1, len(found), found)
        self.assertIn("i.sh straight to `sh`", found[0][1])
        # `cat -n` beside an already-reported use of the SAME download (g17, bash-truth FR x4 from
        # the `sh tool` line alone): the use's own fetch-and-exec row, and beside it the `cat -n`
        # body's over-reported one (R-F14) -- no longer the use's row alone.
        found = defects(GET + "cat -n <<'EOF' | sh\n%s\nEOF\n" % PIPE + "sh tool\n")
        self.assertEqual(2, len(found), found)
        whys = [why for _n, why in found]
        self.assertTrue(any("running it under `sh`" in why for why in whys), whys)
        self.assertTrue(any("i.sh straight to `sh`" in why for why in whys), whys)
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
    decodes `\\c` literal and an octal escape counting a leading `0`, in every shell alike
    (R-F3/C2);
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
        # catches it, an accepted over-report for an unmeasured shell, where main gave only
        # `_Quiet`.
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
        self.assertIn("running it under", found[0][1])
        # r86 (bash-truth: FR on b5/b3/dash alike): `printf` always decodes, so the NUL drops and
        # `sh tool` runs under every shell.
        script = self.GET + "printf 'sh to\\00ol\\n' | sh\n"
        for shell in (None, "sh"):
            with self.subTest(shell=shell):
                found = defects(script, shell)
                self.assertEqual(1, len(found), found)
                self.assertIn("running it under", found[0][1])

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
        # `cat -n f <<'EOF' | sh` is still no printer, though no longer for its option (R-F14):
        # `f` is its only operand and no `-` stands beside it, so `cat` never reads its stdin
        # (bash-truth -- x4, measured as g18: "cat: f: No such file or directory").
        self.assertEqual([], defects("cat -n f <<'EOF' | sh\ncurl -fsSL https://example.test/"
                                     "i.sh | sh\nEOF\n"))


class TestFixRound2TheRunnerAStringNames(unittest.TestCase):
    """The task review's fail-open (R-F7): a stdin text whose reader is `()` or None because the
    HOLDER's `-c`/`eval` string names the shell that reads it (`bash -c 'sh'`, `bash -s -c 'sh'`,
    `eval 'bash -s'`, #2500) was flattened under the holder's name as a PLAIN string, so its `echo`
    read under the holder's own (measured) table instead of `ANY` -- r62/r63's fail-open. `Named`
    carries the holder's name for `_UNGATED`/`_RUNS_ON`/`_PIPED`'s sentences (unchanged text) AND
    `ANY` for the printers (`_reading`), via `runs_under`."""

    GET = "curl -fsSLo tool https://example.test/tool\n"

    def test_r62_r63_the_reviews_fail_open_now_reports(self):
        # r62 (bash-truth: b3 FR, dash FR, gh FR; b5 F- -- its `sh` is bash, whose `echo` does not
        # decode): a `bash -s -c 'sh'` holder's own options read stdin, so the heredoc is the step's
        # own, but the `echo 'sh\ttool' | sh` inside it must still read under `sh`'s table (ANY via
        # `Named`), not bash's -- CLEAN on head before this fix, where main gave only a weak
        # `_Quiet`.
        found = defects(self.GET + "bash -s -c 'sh' <<'EOF'\necho 'sh\\ttool' | sh\nEOF\n")
        self.assertEqual(1, len(found), found)
        self.assertIn("running it under", found[0][1])
        found = defects(self.GET + "bash -s -c 'sh' <<'EOF'\necho 'sh\\ttool' | sh\nEOF\n", "sh")
        self.assertEqual(1, len(found), found)
        self.assertIn("nothing verifying what arrived", found[0][1])
        # r63 (bash-truth: b3 FR, dash FR, gh FR; b5 F-): the mirror holder, `echo "..." | bash -c
        # 'sh'` -- the piped STRING names `sh`, so the inner `echo` must read under `sh` too.
        found = defects(self.GET + "echo \"echo 'sh\\ttool' | sh\" | bash -c 'sh'\n")
        self.assertEqual(1, len(found), found)
        self.assertIn("running it under", found[0][1])
        found = defects(self.GET + "echo \"echo 'sh\\ttool' | sh\" | bash -c 'sh'\n", "sh")
        self.assertEqual(1, len(found), found)
        self.assertIn("running it under", found[0][1])

    def test_n01_bash_c_sh_holder_beside_its_must_trip_control(self):
        # n01 (bash-truth: b3 FR, dash FR, gh FR; b5 F-): `bash -c 'sh'` without r62's `-s` -- the
        # SAME string-names-the-shell shape, one level simpler. CLEAN before this fix.
        found = defects(self.GET + "bash -c 'sh' <<'EOF'\necho 'sh\\ttool' | sh\nEOF\n")
        self.assertEqual(1, len(found), found)
        self.assertIn("running it under", found[0][1])
        # n02, the must-trip control (bash-truth: FR x4, spelled under EVERY reading -- no escape
        # to decode at all): a plain space needs no R-F7 to catch, and never did -- loud on main's
        # scripts too (its own pre-#2467 generic `echo`-into-`sh` catch-all already reports this).
        found = defects(self.GET + "bash -c 'sh' <<'EOF'\necho 'sh tool' | sh\nEOF\n")
        self.assertEqual(1, len(found), found)
        self.assertIn("running it under", found[0][1])

    def test_n03_n04_the_fix_is_narrow(self):
        # n03 (bash-truth: F- x4): no `-c` STRING at all -- `bash <<'EOF'` is the holder running
        # its OWN heredoc directly, read under bash's OWN (measured, literal) table, same as any
        # top-level `echo` with no `-e`. CLEAN, unaffected by R-F7: the fix is only for a STRING
        # that names a shell, never for a holder reading its own stdin.
        self.assertEqual([], defects(self.GET + "bash <<'EOF'\necho 'sh\\ttool' | sh\nEOF\n"))
        # n04 (bash-truth: F- x4): `bash $X <<'EOF'` with `X=-s` -- a VALUE among the holder's own
        # words (#2485) that may resolve to a `-c STRING` at runtime exactly as `X='-c sh'` does
        # (v01, R-F9) -- `runs_under` cannot tell this from v01's shape, so it is D now, the
        # over-report R-F1 already accepts for a runner the guard is not sure of, not n03's CLEAN.
        found = defects(self.GET + "X=-s\nbash $X <<'EOF'\necho 'sh\\ttool' | sh\nEOF\n")
        self.assertEqual(1, len(found), found)
        self.assertIn("running it under", found[0][1])

    def test_n05_sh_holder_was_already_right(self):
        # n05 (bash-truth: b3 FR, dash FR, gh FR; b5 F-): `sh $X <<'EOF'` with `X=-s` -- `sh` itself
        # is a MEASURED row, and it is both the holder AND the reader here (no `-c` string at all),
        # so this was never the r62/r63 fail-open: loud already at 55cacce3 (before this round),
        # unaffected by it -- a confirmed-correct control, not a new catch (measured, not
        # predicted).
        found = defects(self.GET + "X=-s\nsh $X <<'EOF'\necho 'sh\\ttool' | sh\nEOF\n")
        self.assertEqual(1, len(found), found)
        self.assertIn("running it under", found[0][1])
        found = defects(self.GET + "X=-s\nsh $X <<'EOF'\necho 'sh\\ttool' | sh\nEOF\n", "sh")
        self.assertEqual(1, len(found), found)
        self.assertIn("running it under", found[0][1])

    def test_n06_the_mirror_shape_too(self):
        # n06 (bash-truth: FR x4 -- every column agrees): the mirror of r62/r63, `sh -c 'bash -s'`
        # -- the string names `bash`, so the inner `echo -e 'sh\ttool' | sh` must read under
        # `bash`'s table too (ANY via `Named`), where `-e` decodes the tab regardless of which
        # reading wins. CLEAN before this fix.
        found = defects(self.GET + "sh -c 'bash -s' <<'EOF'\necho -e 'sh\\ttool' | sh\nEOF\n")
        self.assertEqual(1, len(found), found)
        self.assertIn("running it under", found[0][1])
        found = defects(self.GET + "sh -c 'bash -s' <<'EOF'\necho -e 'sh\\ttool' | sh\nEOF\n", "sh")
        self.assertEqual(1, len(found), found)
        self.assertIn("running it under", found[0][1])

    def test_n07_an_eval_holder_reads_both_ways_and_reports(self):
        # n07 (bash-truth: F- x4 -- an accepted over-report for an unmeasured runner, same family
        # as r68/ksh): `eval` has never been in `_ECHO`, so it already read as `ANY` by the lookup
        # miss alone (R-F1), with no `Named` involved at all. A POSITIVE against main, which gave
        # only the printer's `_Quiet` here (re-review #2's R2-M2): the fetch-and-exec sentence
        # under both keys, as at 55cacce3 -- R-F7 changed nothing for it, which is all the old
        # name ("is unaffected") ever showed.
        found = defects(self.GET + "eval 'bash -s' <<'EOF'\necho 'sh\\ttool' | sh\nEOF\n")
        self.assertEqual(1, len(found), found)
        self.assertIn("running it under", found[0][1])
        found = defects(self.GET + "eval 'bash -s' <<'EOF'\necho 'sh\\ttool' | sh\nEOF\n", "sh")
        self.assertEqual(1, len(found), found)
        self.assertIn("running it under", found[0][1])

    def test_the_ungated_sentence_still_names_the_holder_not_any(self):
        # The controller's own naive fix (a bare `ANY` in the hook) broke `_UNGATED`'s sentence,
        # which must keep naming the HOLDER ("bash"), never "any" -- r62's holder shape, with a
        # check inside the body so its own statement earns an `_UNGATED` credit.
        check = "echo '%s  tool' | sha256sum -c -" % ("a" * 64)
        script = self.GET + "bash -s -c 'sh' <<'EOF'\n%s\nchmod +x tool\n./tool\nEOF\n" % check
        found = [w for _step, w in wg.job_defects([("step", script, None)], strict=True)]
        self.assertTrue(any(forms._UNGATED % "bash" in str(w) for w in found), found)
        self.assertFalse(any(forms._UNGATED % wp.ANY in str(w) for w in found), found)

    def test_named_wraps_a_runner_name_for_the_printers_alone(self):
        self.assertEqual("bash", wp.Named("bash"))
        self.assertEqual("bash", "%s" % wp.Named("bash"))
        self.assertIs(wp.ANY, wp.Named("bash").runner)
        self.assertEqual(["sh\\ttool\n", "sh\ttool\n"],
                          wp.spellings(["echo", "sh\\ttool"], None, wp.Named("bash")))
        self.assertEqual(["sh\\ttool\n"], wp.spellings(["echo", "sh\\ttool"], None, "bash"))

    def test_runs_under_wraps_only_a_strings_own_holder(self):
        bash_c = forms.runs_under(["bash", "-c", "sh"], None, "bash")
        self.assertIsInstance(bash_c, wp.Named)
        self.assertIs(wp.ANY, bash_c.runner)
        bash_s_c = forms.runs_under(["bash", "-s", "-c", "sh"], (), "bash")
        self.assertIsInstance(bash_s_c, wp.Named)
        self.assertIs(wp.ANY, bash_s_c.runner)
        vanishing = forms.runs_under(["bash", "$X"], None, "bash")
        self.assertIsInstance(vanishing, wp.Named)
        self.assertIs(wp.ANY, vanishing.runner)
        self.assertEqual("sh", forms.runs_under(["sudo", "sh"], ["sh"], "sudo"))


class TestFixRound3TwoReadingsAndAVanishingValue(unittest.TestCase):
    """The scoped re-review's two new Criticals. NC1 (R-F8): `stdin_scripts` gave both spellings of
    one `echo` the SAME reader, so a check the bash reading spells cleared the use the dash reading
    ran -- x11/x07's fail-open. NC2 (R-F9): a VALUE among a holder's own words may hand its body to
    another shell at runtime (`bash $X <<'EOF'` with `X='-c sh'`), so `runs_under` must read it as
    `Named` too, not under the holder's own table -- v01-v04's fail-open."""

    GET = "curl -fsSLo tool https://example.test/tool\n"

    def test_x11_x07_two_readings_of_one_echo_are_unsure(self):
        # x11 (bash-truth: b5 F-, b3 FR, dash FR, gh FR): `sh <<'EOF'` wrapping x07's eval line --
        # CLEAN on head before R-F8 (main gave only a weak `_Quiet`); the bash-literal reading of
        # the inner `echo` spells no check, but the SAME reader was handed to the dash-decoding
        # reading too, so a check the bash reading never spells cleared the download the decoding
        # reading actually runs. Both readings are Unsure now -- D under the default key.
        check = "echo %s  tool | sha256sum -c -" % ("a" * 64)
        x11 = self.GET + "sh <<'EOF'\neval \"echo 'sh\\ttool\\c; %s' | sh\"\nEOF\n" % check
        found = defects(x11)
        self.assertEqual(1, len(found), found)
        self.assertIn("running it under", found[0][1])
        # x07 (bash-truth: b5 F-, b3 F-, dash FR, gh F-): the same eval line at the step's own top,
        # no `sh <<'EOF'` wrapper -- D under `shell: sh` too, now that neither reading counts.
        x07 = self.GET + "eval \"echo 'sh\\ttool\\c; %s' | sh\"\n" % check
        found = defects(x07)
        self.assertEqual(1, len(found), found)
        self.assertIn("running it under", found[0][1])
        found = defects(x07, "sh")
        self.assertEqual(1, len(found), found)
        self.assertIn("running it under", found[0][1])

    def test_x09_x12_x10_the_controls_still_read_as_they_did(self):
        # x09/x12 (D|D as before, `echo hi` in place of the check -- no check in EITHER reading to
        # begin with, so R-F8 changes nothing here): x09 at the top, x12 under `sh <<'EOF'`.
        x09 = self.GET + "eval \"echo 'sh\\ttool\\c; echo hi' | sh\"\n"
        x12 = self.GET + "sh <<'EOF'\neval \"echo 'sh\\ttool\\c; echo hi' | sh\"\nEOF\n"
        for step, script in (("x09", x09), ("x12", x12)):
            for shell in (None, "sh"):
                with self.subTest(step=step, shell=shell):
                    found = defects(script, shell)
                    self.assertEqual(1, len(found), found)
                    self.assertIn("running it under", found[0][1])
        # x10 (the control without `eval`'s ANY wrapping: ONE measured reading, bash's own) --
        # CLEAN under bash (no `-e`, no decode), D under `sh`/dash (always decodes).
        check = "echo %s  tool | sha256sum -c -" % ("a" * 64)
        x10 = self.GET + "echo 'sh\\ttool\\c; %s' | sh\n" % check
        self.assertEqual([], defects(x10))
        found = defects(x10, "sh")
        self.assertEqual(1, len(found), found)
        self.assertIn("running it under", found[0][1])

    def test_v01_v04_a_vanishing_value_may_hand_the_body_elsewhere(self):
        # v01 (bash-truth: F- FR FR FR): `X='-c sh'; bash $X <<'EOF'` -- the VALUE `$X` may resolve
        # to a `-c STRING` that hands the body to `sh`, same family as r62/r63's STRING shape, but
        # `_stdin` names no reader at all for a holder with no `-s` and a value among its words, so
        # `runs_under` must read it as `Named` on that ground too (R-F9) -- D under both keys.
        v01 = self.GET + "X='-c sh'\nbash $X <<'EOF'\necho 'sh\\ttool' | sh\nEOF\n"
        # v02 (bash-truth: FR x4): the mirror, `X='-c bash'; sh $X <<'EOF'` with `echo -e` -- D
        # under both keys, the tab decodes regardless of which reading wins once `Named` is in play.
        v02 = self.GET + "X='-c bash'\nsh $X <<'EOF'\necho -e 'sh\\ttool' | sh\nEOF\n"
        # v03 (bash-truth: FR x4): v02's body under `sh -s $X` -- `-s` makes the reader the
        # holder's own argv, but `$X` still stands among its words, so `runs_under`'s word test
        # (`_may_spell_option`, R-F12) still routes it to `Named`, not the plain-name branch. D
        # under both keys.
        v03 = self.GET + "X='-c bash'\nsh -s $X <<'EOF'\necho -e 'sh\\ttool' | sh\nEOF\n"
        # v04 (bash-truth: F- FR FR FR): v01's body under `bash -s $X` -- the same `-s`-plus-value
        # shape as v03, the other way round. D under both keys.
        v04 = self.GET + "X='-c sh'\nbash -s $X <<'EOF'\necho 'sh\\ttool' | sh\nEOF\n"
        for step, script in (("v01", v01), ("v02", v02), ("v03", v03), ("v04", v04)):
            for shell in (None, "sh"):
                with self.subTest(step=step, shell=shell):
                    found = defects(script, shell)
                    self.assertEqual(1, len(found), found)
                    self.assertIn("running it under", found[0][1])

    def test_bash_s_c_echo_hi_control_still_reads_under_bash(self):
        # The one shape R-F9 must NOT touch: `bash -s -c 'echo hi' <<'EOF'` -- `-s` makes the
        # reader the holder's own argv, and no word of its own may spell an option (`-c`'s STRING
        # `echo hi` holds no expansion: `_may_spell_option`, R-F12), so `runs_under`'s plain-name
        # branch still applies -- CLEAN, read under bash's own (literal) table, same as n03.
        self.assertEqual([], defects(
            self.GET + "bash -s -c 'echo hi' <<'EOF'\necho 'sh\\ttool' | sh\nEOF\n"))

    def test_runs_under_reads_a_value_among_the_holders_words_as_named(self):
        # v01/v04's shape: `_stdin` gives `None` for a holder with no `-s` and a value among its
        # words -- `runs_under` now reads it `Named`, `ANY` for the printers.
        v01_shape = forms.runs_under(["bash", "$X"], None, "bash")
        self.assertIsInstance(v01_shape, wp.Named)
        self.assertIs(wp.ANY, v01_shape.runner)
        # v03/v04's shape: `-s` present, so `_stdin` gives the holder's OWN argv as reader, but a
        # value still stands among its words -- `_may_spell_option` (R-F12) keeps it out of the
        # plain-name branch.
        argv = ["sh", "-s", "$X"]
        v03_shape = forms.runs_under(argv, argv, "sh")
        self.assertIsInstance(v03_shape, wp.Named)
        self.assertIs(wp.ANY, v03_shape.runner)


class TestFixRound3CatDashDashReadsStdin(unittest.TestCase):
    """The review's x23 (R-F10): `--` ends `cat`'s options and is no option itself, so `cat --
    <<'EOF'` still reads its own stdin -- `_cat_reads_stdin` wrongly counted the bare `--` as an
    option word and read it as no printer at all."""

    def test_cat_dashdash_alone_or_with_a_dash_reads_stdin(self):
        # x23 (CLEAN on main and head before this fix, in all four shell/holder pairings): a bare
        # `cat --` reads its own stdin, same as `cat` alone.
        found = defects("cat -- <<'EOF' | sh\ncurl -fsSL https://example.test/i.sh | sh\nEOF\n")
        self.assertEqual(1, len(found), found)
        self.assertIn("i.sh", found[0][1])
        # `cat -- - <<'EOF' | sh`: the explicit `-` after `--` reads stdin too, same as `cat --`.
        found = defects("cat -- - <<'EOF' | sh\ncurl -fsSL https://example.test/i.sh | sh\nEOF\n")
        self.assertEqual(1, len(found), found)
        self.assertIn("i.sh", found[0][1])

    def test_a_file_operand_rules_it_out_an_earlier_option_no_longer_does(self):
        # `cat -- f <<'EOF' | sh` prints `f` only, like `cat f` -- the heredoc is `cat`'s own data,
        # unread (no printer: `f` alone, no `-`, among its operands).
        self.assertEqual([], defects(
            "cat -- f <<'EOF' | sh\ncurl -fsSL https://example.test/i.sh | sh\nEOF\n"))
        # x23d `cat -n -- <<'EOF' | sh`, flipped by fix round 4 (R-F14): an option word before the
        # `--` no longer rules the `cat` out -- it has no operand, so it reads its stdin, and its
        # body is read as written. An OVER-report (bash-truth -- x4: `-n` numbers the line, so the
        # inner `sh` runs `1`, "1: command not found"), R-F14's named price.
        found = defects("cat -n -- <<'EOF' | sh\ncurl -fsSL https://example.test/i.sh | sh\nEOF\n")
        self.assertEqual(1, len(found), found)
        self.assertIn("i.sh straight to `sh`", found[0][1])


class TestFixRound4(unittest.TestCase):
    """Re-review #2's R2-C1, R2-C2, R2-I1 and R2-M1 (rulings R-F11-R-F14). R-F11: an `echo` whose
    readings are one spelled and one unspelled is a text no shell is sure of -- the readings are
    counted BEFORE the None one is dropped -- so a check the spelled one holds no longer clears the
    printer the unspelled one leaves. R-F12: a word that may spell an option anywhere among the
    holder's words before `--` (an option's value slot, `-o $X`/`-O $X`, or an option word that
    expands, `-$X`) may hand the body to another shell, so its printers read both ways. R-F13: an
    EXPANDING body a `cat` hands down a pipe is no printer for `unprinted`, so `_unread_stdin`
    reports it inside a `$(...)` too. R-F14: a `cat` reading its stdin prints its body as written,
    options or not, and the FIRST `--` ends its options wherever it stands. Truth columns are b5,
    b3, dash and gh (GitHub's default pairing), measured on this box, whose `cat` is BSD's."""

    GET = "curl -fsSLo tool https://example.test/tool\n"
    CHECK = "echo %s  tool | sha256sum -c -" % ("a" * 64)
    PIPE = "curl -fsSL https://example.test/i.sh | sh\n"
    FETCH_EXEC = "fetches https://example.test/tool -> tool and running it under `sh`"

    def test_y01_y09_a_check_one_reading_spells_no_longer_clears_the_unspelled_one(self):
        # y01 (bash-truth: F- FR FR FR), y02 (F- F- FR F-), y03 (F- FR FR FR), y08 (F- F- FR F-),
        # y09 (F- FR FR FR): x11, x07 and v04 with an out-of-table `\x` in the `echo` text, so
        # `spellings` gives bash's literal reading and a None (the decoding one stops at `\x`).
        # The None was dropped BEFORE the count, so the spelled text kept the REAL reader and its
        # check cleared the printer `unprinted` raises for the unspelled reading: CLEAN under both
        # keys at c3113439. Now that text is `Unsure` and the printer's `_Quiet` stands -- main's
        # answer. Not the fetch-and-exec sentence: the reading that runs `tool` is the unspelled
        # one, and no reading this module spells uses `tool` (bash's runs one word, `shttool…`).
        sh_eval = "sh <<'EOF'\neval \"echo '%s' | sh\"\nEOF\n"
        steps = {"y01": self.GET + sh_eval % ("echo \\x; sh\\ttool\\c; " + self.CHECK),
                 "y02": self.GET + "eval \"echo 'echo \\x; sh\\ttool\\c; %s' | sh\"\n" % self.CHECK,
                 "y03": self.GET + "X='-c sh'\nbash -s $X <<'EOF'\necho 'echo \\x; sh\\ttool\\c; "
                        "%s' | sh\nEOF\n" % self.CHECK,
                 "y08": self.GET + "eval \"echo 'sh\\ttool; echo \\x; %s' | sh\"\n" % self.CHECK,
                 "y09": self.GET + sh_eval % ("sh\\ttool; echo \\x; " + self.CHECK)}
        for step, script in steps.items():
            for shell in (None, "sh"):
                with self.subTest(step=step, shell=shell):
                    found = defects(script, shell)
                    self.assertEqual(1, len(found), found)
                    self.assertIsInstance(found[0][1], forms._Quiet)
                    self.assertIn("pipes `sh` its program from `echo`", found[0][1])
        # y07 (bash-truth: F- FR FR FR): y01 with no check at all -- the `_Quiet` it always had,
        # which y01-y09 now share: a check in the spelled reading changes nothing.
        y07 = self.GET + sh_eval % "echo \\x; sh\\ttool\\c; echo hi"
        for shell in (None, "sh"):
            with self.subTest(step="y07", shell=shell):
                found = defects(y07, shell)
                self.assertEqual(1, len(found), found)
                self.assertIsInstance(found[0][1], forms._Quiet)

    def test_y10_y11_a_download_a_spelled_reading_holds_is_still_reported(self):
        # y10 (bash-truth: FR x4; `[spelled, None]`) and y11 (FR x4; two spelled readings): an
        # `eval`'s `echo` printing `curl … | sh` -- D+D under both keys, as at c3113439. y10: the
        # printer's words fetch as written (`_PRINTED`, loud) beside the spelled text's `curl |
        # sh`; y11: each reading's `curl | sh`.
        y10 = "eval \"echo 'curl -fsSL https://example.test/i.sh | sh; echo \\x' | sh\"\n"
        y11 = "eval \"echo 'curl -fsSL https://example.test/i.sh | sh; echo \\t' | sh\"\n"
        for step, script in (("y10", y10), ("y11", y11)):
            for shell in (None, "sh"):
                with self.subTest(step=step, shell=shell):
                    found = defects(script, shell)
                    self.assertEqual(2, len(found), found)
                    self.assertFalse(any(isinstance(w, forms._Quiet) for _n, w in found), found)
                    self.assertTrue(any("i.sh straight to `sh`" in w for _n, w in found), found)

    def test_stdin_scripts_counts_a_none_reading_before_it_drops_it(self):
        # `[spelled, None]` under `Named("bash")` (`ANY` for the printers): ONE text, and no reader.
        stages = shell_reader.statements("echo 'echo \\x; sh\\ttool' | sh\n")[0].stages
        argv = shell_reader.command(stages[1].argv)
        self.assertEqual(["echo \\x; sh\\ttool\n", None],
                         wp.spellings(shell_reader.command(stages[0].argv), stages[0],
                                      wp.Named("bash")))
        texts = forms.stdin_scripts(argv, stages[1], stages[:1], wp.Named("bash"))
        self.assertEqual(["echo \\x; sh\\ttool\n"], texts)
        self.assertIsNone(texts[0].reader)
        # One spelled reading alone keeps the real reader (bash's own table: `[spelled]`).
        texts = forms.stdin_scripts(argv, stages[1], stages[:1], "bash")
        self.assertEqual(["echo \\x; sh\\ttool\n"], texts)
        self.assertIs(argv, texts[0].reader)

    def test_z04_z06_a_value_in_an_option_slot_hands_the_body_on(self):
        # z04 `bash -o $X` (X='posix -c sh'), z05 `bash -$X` (X='c sh'), z06 `bash -O $X`
        # (X='extglob -c sh'); bash-truth for each: F- FR FR FR -- the value becomes `-c sh`, and
        # `sh` reads the body and decodes the tab. `runs_under` asked `candidates`, which never
        # weighs an option's value slot or reads `-$X` as more than a letter cluster with no `c`,
        # so it gave the plain `bash` and its literal table: CLEAN under both keys at c3113439.
        # Now a word before `--` that may spell an option (`_may_spell_option`) makes it `Named`.
        body = "<<'EOF'\necho 'sh\\ttool' | sh\nEOF\n"
        steps = {"z04": "X='posix -c sh'\nbash -o $X ", "z05": "X='c sh'\nbash -$X ",
                 "z06": "X='extglob -c sh'\nbash -O $X "}
        for step, holder in steps.items():
            for shell in (None, "sh"):
                with self.subTest(step=step, shell=shell):
                    found = defects(self.GET + holder + body, shell)
                    self.assertEqual(1, len(found), found)
                    self.assertIn(self.FETCH_EXEC + " with nothing verifying what arrived",
                                  found[0][1])

    def test_r_f12_reads_the_other_holders_as_they_were(self):
        body = "<<'EOF'\necho 'sh\\ttool' | sh\nEOF\n"
        # Plain `bash` (CLEAN, every column F-): z01 `bash -s -- "$VALUE"` (the value is past
        # `--`, a parameter), z08 `bash -s -c 'echo hi'`, s01 `bash -s -c 'echo $X'` (the `$` is
        # inside a string bash runs itself and begins no word: measured F- x4, `echo` prints
        # `-c sh` and nothing reads the body), n03 `bash <<'EOF'` (no word at all).
        clean = {"z01": "VALUE='-c sh'\nbash -s -- \"$VALUE\" ",
                 "z08": "bash -s -c 'echo hi' ",
                 "s01": "export X='-c sh'\nbash -s -c 'echo $X' ", "n03": "bash "}
        for step, holder in clean.items():
            for shell in (None, "sh"):
                with self.subTest(step=step, shell=shell):
                    self.assertEqual([], defects(self.GET + holder + body, shell))
        # `Named`, as before R-F12: n04 `X=-s; bash $X` (F- x4, R-F9's accepted over-report) and
        # z02 `bash "$X"` (F- x4: bash refuses the one word `-c sh`) -- the fail-closed price of
        # reading every `$` word that may spell an option, quoted or not -- and v01 `bash $X`
        # (F- FR FR FR).
        loud = {"n04": "X=-s\nbash $X ", "z02": "X='-c sh'\nbash \"$X\" ",
                "v01": "X='-c sh'\nbash $X "}
        for step, holder in loud.items():
            for shell in (None, "sh"):
                with self.subTest(step=step, shell=shell):
                    found = defects(self.GET + holder + body, shell)
                    self.assertEqual(1, len(found), found)
                    self.assertIn(self.FETCH_EXEC, found[0][1])
        # z09 `S=sh; bash -s -c "$S"` (F- FR FR FR): a `-c` string that is a `$` word may name the
        # shell reading the body too -- the download the body runs (c3113439: a `_Quiet` alone)
        # beside the hand-off's `Idle`, which #2703 (fold 8) raises for the `$S` string as a value
        # stdin reader where `dynamic_program`'s `_Quiet` stood (main reports that `Idle` too).
        for shell in (None, "sh"):
            with self.subTest(step="z09", shell=shell):
                found = defects(self.GET + "S=sh\nbash -s -c \"$S\" " + body, shell)
                self.assertEqual(2, len(found), found)
                self.assertIs(forms.Idle, type(found[0][1]))
                self.assertIn("to `$S`, a command word", found[0][1])
                self.assertIn(self.FETCH_EXEC, found[1][1])

    def test_runs_under_weighs_every_word_before_dashdash(self):
        for argv in (["bash", "-o", "$X"], ["bash", "-$X"], ["bash", "-O", "$X"]):
            with self.subTest(argv=argv):
                runner = forms.runs_under(argv, argv, "bash")
                self.assertIsInstance(runner, wp.Named)
                self.assertIs(wp.ANY, runner.runner)
        for argv in (["bash", "-s", "--", "$VALUE"], ["bash", "-s", "-c", "echo $X"]):
            with self.subTest(argv=argv):
                self.assertIs(str, type(forms.runs_under(argv, argv, "bash")))
                self.assertEqual("bash", forms.runs_under(argv, argv, "bash"))

    def test_f01_f09_f02_an_expanding_cat_body_in_a_substitution_is_reported(self):
        # f01 (bash-truth: FR x4) and f09 (-- x4, `echo hi`): `x=$(cat <<EOF | sh …)`. #2702's
        # order lets `unread_program` speak first inside a substitution, and `unprinted` took the
        # EXPANDING `cat` for a printer it cannot spell: a `_Quiet` nothing kept, CLEAN under both
        # keys at c3113439 (D at 240d72a4). That `cat` is no printer now, so `_unread_stdin`
        # speaks: the EXPANDING sentence, fetch or no fetch.
        f01 = "x=$(cat <<EOF | sh\n%sEOF\n)\n" % self.PIPE
        f09 = "x=$(cat <<EOF | sh\necho hi\nEOF\n)\n"
        for step, script in (("f01", f01), ("f09", f09)):
            for shell in (None, "sh"):
                with self.subTest(step=step, shell=shell):
                    found = defects(script, shell)
                    self.assertEqual(1, len(found), found)
                    self.assertTrue(found[0][1].startswith("hands an EXPANDING heredoc body"),
                                    found[0][1])
                    self.assertIn("`sh`", found[0][1])
        # f02 (FR x4): f01 beside GET and `sh tool` -- D+D, where c3113439 gave Q+D.
        for shell in (None, "sh"):
            with self.subTest(step="f02", shell=shell):
                found = defects(self.GET + f01 + "sh tool\n", shell)
                self.assertEqual(2, len(found), found)
                self.assertFalse(any(isinstance(w, forms._Quiet) for _n, w in found), found)
                self.assertTrue(found[0][1].startswith("hands an EXPANDING heredoc body"))
                self.assertIn(self.FETCH_EXEC, found[1][1])

    def test_the_other_expanding_and_value_shapes_read_as_they_did(self):
        expanding = "hands an EXPANDING heredoc body"
        in_subst = "hands a script to `%s` inside a command substitution"
        # f03 `x=$(cat <<'EOF' | sh …)` (FR x4): the quoted body, read inside the substitution.
        # f04/f11 `x=$(sh <<EOF …)` (FR x4 / -- x4) and f05/f13 top-level `cat <<EOF | sh` (FR x4 /
        # -- x4): the EXPANDING sentence. f06 `x=$($CMD <<'EOF' …)` (FR x4): #2598's own sentence.
        cases = (("f03", "x=$(cat <<'EOF' | sh\n%sEOF\n)\n" % self.PIPE, in_subst % "sh"),
                 ("f04", "x=$(sh <<EOF\n%sEOF\n)\n" % self.PIPE, expanding),
                 ("f11", "x=$(sh <<EOF\necho hi\nEOF\n)\n", expanding),
                 ("f05", "cat <<EOF | sh\n%sEOF\n" % self.PIPE, expanding),
                 ("f13", "cat <<EOF | sh\necho hi\nEOF\n", expanding),
                 ("f06", "CMD=sh\nx=$($CMD <<'EOF'\n%sEOF\n)\n" % self.PIPE, in_subst % "$CMD"))
        for step, script, why in cases:
            for shell in (None, "sh"):
                with self.subTest(step=step, shell=shell):
                    found = defects(script, shell)
                    self.assertEqual(1, len(found), found)
                    self.assertTrue(found[0][1].startswith(why), found[0][1])
        # e01 `cat <<'EOF' | $CMD` and e05 `cat <<EOF | $CMD` (FR x4): the `$CMD` hand-off `Idle`
        # beside the body's `curl | sh`, I+D as at c3113439 -- `unprinted` never weighs a `$` word.
        for step, heredoc in (("e01", "<<'EOF'"), ("e05", "<<EOF")):
            for shell in (None, "sh"):
                with self.subTest(step=step, shell=shell):
                    found = defects("CMD=sh\ncat %s | $CMD\n%sEOF\n" % (heredoc, self.PIPE), shell)
                    self.assertEqual(2, len(found), found)
                    self.assertIs(forms.Idle, type(found[0][1]))
                    self.assertIn("i.sh straight to `sh`", found[1][1])

    def test_a_cat_reading_its_stdin_prints_its_body_whatever_its_options(self):
        # Each bash-truth FR x4 (BSD `cat` here; GNU's, per its manual, prints these the same):
        # `-u`, `-s`, `-v` (an ASCII body) and `-t` (a body without a tab) print the body whole;
        # z11 `cat - --` and `cat - -- -n` read `-` first (BSD then fails on the file `--`/`-n`,
        # GNU takes `--` as the end of its options); `-n` before `true; curl … | sh` spoils only
        # `true`, and `-e` after `curl … | sh; true` only `true$`. CLEAN under both keys before.
        cases = {"-u": "cat -u", "-s": "cat -s", "-v": "cat -v", "-t": "cat -t",
                 "z11": "cat - --", "- -- -n": "cat - -- -n"}
        for step, cat in cases.items():
            for shell in (None, "sh"):
                with self.subTest(step=step, shell=shell):
                    found = defects("%s <<'EOF' | sh\n%sEOF\n" % (cat, self.PIPE), shell)
                    self.assertEqual(1, len(found), found)
                    self.assertIn("i.sh straight to `sh`", found[0][1])
        for option, body in (("-n", "true; " + self.PIPE),
                             ("-e", self.PIPE.rstrip("\n") + "; true\n")):
            with self.subTest(option=option, body=body):
                found = defects("cat %s <<'EOF' | sh\n%sEOF\n" % (option, body))
                self.assertEqual(1, len(found), found)
                self.assertIn("i.sh straight to `sh`", found[0][1])
        # `cat -u <<EOF | sh` (FR x4): an EXPANDING body is `_unread_stdin`'s, options or not.
        found = defects("cat -u <<EOF | sh\n%sEOF\n" % self.PIPE)
        self.assertEqual(1, len(found), found)
        self.assertTrue(found[0][1].startswith("hands an EXPANDING heredoc body"), found[0][1])

    def test_an_option_that_spoils_or_empties_the_body_is_over_reported(self):
        # R-F14's price, D under both keys though nothing runs the download: `-n`/`-b` (-- x4: the
        # number is the line's first word, "1: command not found"), `-e` (F- x4: `curl` runs, but
        # `sh$` is no command), and `-l` (-- x4: BSD's lock fails on a pipe, GNU has no `-l`).
        # `-E`, `-T` and `-A` are -- x4 HERE, where BSD's `cat` refuses them ("illegal option");
        # GNU's takes them, per its manual: `-T` prints the tab-free body whole (a real catch
        # there), `-E`/`-A` end each line with `$` (F-, as `-e`).
        for option in ("-n", "-b", "-e", "-l", "-E", "-T", "-A"):
            for shell in (None, "sh"):
                with self.subTest(option=option, shell=shell):
                    found = defects("cat %s <<'EOF' | sh\n%sEOF\n" % (option, self.PIPE), shell)
                    self.assertEqual(1, len(found), found)
                    self.assertIn("i.sh straight to `sh`", found[0][1])

    def test_the_first_dashdash_ends_the_options_and_a_file_operand_still_rules_it_out(self):
        # z10 `cat -- --` and `cat -- -n` (-- x4 each): every word after the first `--` is an
        # operand, here a FILE that does not exist, and no `-` stands among them, so `cat` never
        # reads its stdin -- CLEAN, as main and c3113439 were.
        for cat in ("cat -- --", "cat -- -n"):
            for shell in (None, "sh"):
                with self.subTest(cat=cat, shell=shell):
                    self.assertEqual([], defects("%s <<'EOF' | sh\n%sEOF\n" % (cat, self.PIPE),
                                                 shell))

    def test_cat_reads_stdin_unit_pins(self):
        for argv in (["cat"], ["cat", "-u"], ["cat", "-n", "--"], ["cat", "-", "--"],
                     ["cat", "-", "--", "-n"], ["cat", "f", "-"], ["cat", "--", "-"]):
            with self.subTest(argv=argv):
                self.assertTrue(wp._cat_reads_stdin(argv))
        for argv in ([], ["cat", "--", "-n"], ["cat", "--", "--"], ["cat", "-n", "f"],
                     ["cat", "--", "f"], ["tac"]):
            with self.subTest(argv=argv):
                self.assertFalse(wp._cat_reads_stdin(argv))


class TestFixRound5(unittest.TestCase):
    """Re-review #3's R3-C1, R3-M1 and R3-M2(a) (rulings R-F15, R-F16) and R-F13's dead clause.
    R-F15: a holder whose command word is a `${X:-sh}` default (`shell_wrappers.Defaulted`) is not
    WRITTEN as the shell it spells -- `X` may hold another -- so its printers read both ways, as
    `_refused` already reads such a word. R-F16: the words after a `-c` string are `$0`, `$1`, ...,
    never options, so `runs_under`'s scan stops at the string, which it still weighs. `unprinted`
    asks `_PRINTERS` alone now. Truth columns are b5, b3, dash and gh (GitHub's default pairing),
    measured on this box, whose `cat` is BSD's."""

    GET = "curl -fsSLo tool https://example.test/tool\n"
    TAB = "<<'EOF'\necho 'sh\\ttool' | sh\nEOF\n"
    CHECK = "echo %s  tool | sha256sum -c -" % ("a" * 64)
    FETCH_EXEC = ("fetches https://example.test/tool -> tool and running it under `sh` with "
                  "nothing verifying what arrived")

    def command(self, script):
        """The argv `flattened` hands `runs_under`, from a real statement."""
        return shell_reader.command(shell_reader.statements(script)[0].stages[0].argv)

    def test_h15_a_default_command_word_reads_both_ways(self):
        # CLEAN under both keys at bc6f04c7, where main reported each: `_command_result` reads the
        # word as the shell it spells (#2337) and marks it `Defaulted`, which `runs_under`'s
        # plain-name branch ignored. h15 `X=dash; ${X:-bash} -s`, h15b its `-c "…"` twin, h15e with
        # no option and j05 `${X:=bash} -s` (FR x4: dash runs the body and decodes the tab); h15d
        # `X=sh` (F- FR FR FR); h15g `X=bash; ${X:-sh} -c "echo -e 'sh tool' | sh"` and h15h, its
        # `-s` heredoc (FR x4: bash reads `-e` as an option, where sh's row reads it as text).
        steps = {"h15": "X=dash\n${X:-bash} -s " + self.TAB,
                 "h15b": "X=dash\n${X:-bash} -c \"echo 'sh\\ttool' | sh\"\n",
                 "h15d": "X=sh\n${X:-bash} -s " + self.TAB,
                 "h15e": "X=dash\n${X:-bash} " + self.TAB,
                 "h15g": "X=bash\n${X:-sh} -c \"echo -e 'sh tool' | sh\"\n",
                 "h15h": "X=bash\n${X:-sh} -s <<'EOF'\necho -e 'sh tool' | sh\nEOF\n",
                 "j05": "X=dash\n${X:=bash} -s " + self.TAB}
        for step, holder in steps.items():
            for shell in (None, "sh"):
                with self.subTest(step=step, shell=shell):
                    found = defects(self.GET + holder, shell)
                    self.assertEqual(1, len(found), found)
                    self.assertIn(self.FETCH_EXEC, found[0][1])
        # h15g's sentence, main's own: "fetches https://example.test/tool -> tool and running it
        # under `sh` with nothing verifying what arrived -- verify it first: …".
        found = defects(self.GET + steps["h15g"])
        self.assertEqual(1, len(found), found)
        self.assertTrue(found[0][1].startswith(self.FETCH_EXEC + " -- verify it first: "), found)

    def test_h15c_h15f_an_unset_default_is_the_fail_closed_price(self):
        # h15c `${X:-bash} -s` and h15f `${X:-bash} -c "…"` with `X` unset: the default bash runs
        # the body, and its `echo` prints the tab literally (F- x4). D, read both ways because `X`
        # may hold another shell: the same fail-closed price as n04's and z02's value among the
        # holder's words. Main reports both too (`_Quiet`).
        for step, holder in (("h15c", "${X:-bash} -s " + self.TAB),
                             ("h15f", "${X:-bash} -c \"echo 'sh\\ttool' | sh\"\n")):
            for shell in (None, "sh"):
                with self.subTest(step=step, shell=shell):
                    found = defects(self.GET + holder, shell)
                    self.assertEqual(1, len(found), found)
                    self.assertIn(self.FETCH_EXEC, found[0][1])

    def test_a_written_holder_keeps_its_own_row(self):
        # The controls R-F15 must not touch, CLEAN at bc6f04c7 and now. n03 `bash <<'EOF'` and j04
        # `bash -s <<'EOF'`, h15's body under a WRITTEN bash (F- x4: its `echo` prints the tab
        # literally). j02 `sh -s <<'EOF'` with h15h's `echo -e 'sh tool' | sh`: a WRITTEN `sh` keeps
        # sh's row, where `-e` is text (b3, dash and gh F-, "-e: not found"; b5 FR only because this
        # box's b5 `sh` is bash 5, where GitHub's is dash). Under `shell: bash` and `shell: sh`.
        for step, holder in (("n03", "bash " + self.TAB), ("j04", "bash -s " + self.TAB),
                             ("j02", "sh -s <<'EOF'\necho -e 'sh tool' | sh\nEOF\n")):
            for shell in (None, "sh"):
                with self.subTest(step=step, shell=shell):
                    self.assertEqual([], defects(self.GET + holder, shell))

    def test_runs_under_reads_a_default_command_word_as_named(self):
        argv = self.command("${X:-sh} -s")
        self.assertIs(shell_wrappers.Defaulted, type(argv[0]))
        runner = forms.runs_under(argv, argv, "sh")
        self.assertIsInstance(runner, wp.Named)
        self.assertIs(wp.ANY, runner.runner)
        written = self.command("sh -s")
        self.assertIs(str, type(forms.runs_under(written, written, "sh")))

    def test_h14_h16_h16b_the_words_after_a_dash_c_string_are_parameters(self):
        # D under both keys at bc6f04c7: R-F12's scan weighed a `$` or `{}` word AFTER the string
        # as a possible option, so the holder was `Named`. h14 `xargs -I{} bash -c "…" {}` (`{}` a
        # `Rewritten` word) and h16 `bash -c "…" _ "$X"` (F- x4: bash runs the string and its
        # `echo` prints the tab literally). h16b `bash -c 'set -e; echo -e "<check>" | sh; sh tool'
        # _ "$X"` (F- x4: the check runs, fails and stops the step) was D where main is CLEAN: the
        # two readings `Named` gives differ, so neither counted the check. It counts again.
        steps = {"h14": "echo x | xargs -I{} bash -c \"echo 'sh\\ttool' | sh\" {}\n",
                 "h16": "bash -c \"echo 'sh\\ttool' | sh\" _ \"$X\"\n",
                 "h16b": "bash -c 'set -e; echo -e \"%s\" | sh; sh tool' _ \"$X\"\n" % self.CHECK}
        for step, script in steps.items():
            for shell in (None, "sh"):
                with self.subTest(step=step, shell=shell):
                    self.assertEqual([], defects(self.GET + script, shell))

    def test_z09_h10_h17_the_string_and_the_words_before_it_still_count(self):
        # z09 `S=sh; bash -s -c "$S"` (F- FR FR FR): the string itself stays in the scan, so a `$`
        # string that may name the reading shell keeps its catch: the download the body runs beside
        # the hand-off's `Idle` (#2703, fold 8: the `$S` string is a value stdin reader; before it,
        # `dynamic_program`'s `_Quiet` stood there). h10, z09 with `S` unset (F- x4: bash runs the
        # empty string, rc 0, and never reads the body), reads the same: z09's rule's price. h17
        # `X='-O xpg_echo'; bash $X -c "…"` (FR x4): the value stands BEFORE the string, so the
        # holder is still `Named`: the value's `Idle` and the download it runs, as before.
        handed = (("z09", "S=sh\nbash -s -c \"$S\" " + self.TAB),
                  ("h10", "bash -s -c \"$S\" " + self.TAB))
        for step, holder in handed:
            for shell in (None, "sh"):
                with self.subTest(step=step, shell=shell):
                    found = defects(self.GET + holder, shell)
                    self.assertEqual(2, len(found), found)
                    self.assertIs(forms.Idle, type(found[0][1]))
                    self.assertIn("to `$S`, a command word", found[0][1])
                    self.assertIn(self.FETCH_EXEC, found[1][1])
        h17 = "X='-O xpg_echo'\nbash $X -c \"echo 'sh\\ttool' | sh\"\n"
        for shell in (None, "sh"):
            with self.subTest(step="h17", shell=shell):
                found = defects(self.GET + h17, shell)
                self.assertEqual(2, len(found), found)
                self.assertIs(forms.Idle, type(found[0][1]))
                self.assertIn(self.FETCH_EXEC, found[1][1])

    def test_the_string_is_found_by_identity_only_where_its_object_is_unique(self):
        # CPython shares a one-character `str`: the `-c` string `+` after `-` IS the earlier `+`'s
        # object, so stopping at the FIRST word that `is` the string ends the scan at that `+`,
        # before `-$X`. j06 `X='c sh'; bash -s + -$X -c - +` (F- FR FR FR: bash reads `+` as an
        # option word and `-$X` as `-c sh`, so `sh` reads the body and decodes the tab) is CLEAN
        # with that line, where bc6f04c7 gave D and main `_Quiet`. Where the string's object recurs
        # in the argv, the scan reads on to `--`: j06 is D, and j01 (`$X` in place of `-$X`, the
        # same truth) keeps the value's `Idle` and its D. j03 `bash -s -c x "$X" x` is that
        # fallback's price (F- x4: bash runs `x` and never reads the body): D, as at bc6f04c7.
        steps = {"j06": "X='c sh'\nbash -s + -$X -c - + " + self.TAB,
                 "j01": "X='-c sh'\nbash -s + $X -c - + " + self.TAB,
                 "j03": "X='-c sh'\nbash -s -c x \"$X\" x " + self.TAB}
        for step, holder in steps.items():
            for shell in (None, "sh"):
                with self.subTest(step=step, shell=shell):
                    found = defects(self.GET + holder, shell)
                    self.assertEqual(2 if step == "j01" else 1, len(found), found)
                    self.assertIn(self.FETCH_EXEC, found[-1][1])
        argv = self.command("bash -s + -$X -c - +")
        self.assertIs(argv[2], argv[6])
        self.assertIsInstance(forms.runs_under(argv, argv, "bash"), wp.Named)
        # A string whose object is the argv's only one ends the scan there: a `$X` after it is a
        # parameter. A `$` string itself stays in the scan (z09's shape).
        for script in ("bash -c 'echo hi' _ \"$X\"", "bash -s -c 'echo hi' \"$X\""):
            with self.subTest(script=script):
                argv = self.command(script)
                self.assertIs(str, type(forms.runs_under(argv, argv, "bash")))
        argv = self.command("bash -s -c \"$S\"")
        self.assertIsInstance(forms.runs_under(argv, argv, "bash"), wp.Named)

    def test_h20_h21_cat_help_and_version_are_over_reported(self):
        # `cat --help` and `cat --version` read nothing: GNU prints its own usage or version text,
        # so the body never runs, and BSD's `cat` (this box) refuses them, "illegal option -- -":
        # truth -- x4 here. `_cat_reads_stdin` sees no operand there and reads the body as written:
        # D, an over-report, R-F14's price, named in its docstring.
        for option in ("--help", "--version"):
            for shell in (None, "sh"):
                with self.subTest(option=option, shell=shell):
                    found = defects("cat %s <<'EOF' | sh\n%s\nEOF\n" % (option, PIPE), shell)
                    self.assertEqual(1, len(found), found)
                    self.assertIn("i.sh straight to `sh`", found[0][1])

    def test_unprinted_asks_the_printers_table_alone(self):
        # R-F13's handed clause is gone: a heredoc-fed `cat` is never an unspelled printer.
        # `printed` spells a QUOTED body whole (an option word or not), and `_unread_stdin`
        # reports an EXPANDING one; `unprinted` gave `[]` for each at bc6f04c7 too, the clause
        # being dead (re-review #3: 29,055 instrumented calls, no changed answer).
        for script in ("cat <<'EOF' | sh\n%s\nEOF\n" % PIPE, "cat <<EOF | sh\n%s\nEOF\n" % PIPE,
                       "cat <<<'%s' | sh\n" % PIPE, "cat -n <<'EOF' | sh\n%s\nEOF\n" % PIPE):
            with self.subTest(script=script):
                stages = shell_reader.statements(script)[0].stages
                self.assertEqual([], forms.unprinted(shell_reader.command(stages[1].argv),
                                                     stages[1], stages[:1]))


class TestTheXpgEchoGapTheGuardDocuments(unittest.TestCase):
    """The gap list: "Open: `xpg_echo`;" -- `workflow_guard`'s module docstring."""

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
        self.assertEqual(("body text", False), wp.handed(stages[1], stages[:1]))

    def test_decoded_backslash_c_and_octal(self):
        self.assertEqual("a", wp._decoded("a\\cb"))
        self.assertEqual("A", wp._decoded("\\0101"))


class TestAPassThroughBetweenPrinterAndShell(unittest.TestCase):
    """#2478: a PASS-THROUGH stage between a printer and the shell it feeds -- `tee` writing plain
    files, a bare `cat` or `cat -` -- hands the printer's text on unchanged, so the printer behind
    it is read as if it stood right before the shell (`workflow_printers.producer`). Any other
    stage (`tr`, `base64 -d`, `cat -n`, `tee >(...)`, `xargs cat`, `tee /dev/stdout`) leaves the
    program UNREAD: the `_PRINTED` sentence naming the stage the shell reads from, never read as
    the printer's words (R-P4) -- LOUD where that stage's words or the printer's text fetch
    (review I-1), `_Quiet`, kept beside a reported download, where neither does. Every step below
    runs after GET unless it is named alone. Truth columns are b5, b3, dash and gh (GitHub's
    pairing: the step under bash 5.2.21 with `sh` = dash), measured on `t36-p-probes/steps/p2/`
    (c01-c12, p2n01-p2n32) and `steps/p2rv/` (the review's rv rows, fix round 1's fx rows, the
    re-review's rr rows); each step read CLEAN at the base (d44879b7) and on main unless said
    otherwise."""

    FETCH_EXEC = ("fetches https://example.test/tool -> tool and running it under `sh` with "
                  "nothing verifying what arrived -- verify it first: ")
    CHECKED = "fetches https://example.test/tool -> tool and running it under `sh`; the checksum "
    STREAM = "hands https://example.test/i.sh straight to `sh`"
    SUM = "echo '%s  tool' | sha256sum -c -" % ("a" * 64)

    @staticmethod
    def stages(script):
        return shell_reader.statements(script)[0].stages

    def assert_fetch_exec(self, script, shells=(None, "sh")):
        """GET + `script` is the fetch-and-run sentence alone, never `_PRINTED`."""
        for shell in shells:
            with self.subTest(script=script, shell=shell):
                found = defects(GET + script, shell)
                self.assertEqual(1, len(found), found)
                self.assertNotIsInstance(found[0][1], forms.Idle)
                self.assertTrue(found[0][1].startswith(self.FETCH_EXEC), found[0][1])

    def assert_unread(self, script, stage, shells=(None, "sh")):
        """GET + `script` is the unread answer alone, `_Quiet`, naming `stage`."""
        for shell in shells:
            with self.subTest(script=script, shell=shell):
                found = defects(GET + script, shell)
                self.assertEqual(1, len(found), found)
                self.assertIsInstance(found[0][1], forms._Quiet)
                self.assertTrue(found[0][1].startswith(
                    "pipes `sh` its program from `%s`, whose words this guard does not spell out"
                    % stage), found[0][1])

    def assert_loud(self, script, stage, runner="sh", shells=(None, "sh")):
        """`script` ALONE is the unread answer, LOUD, naming `stage` and the shell `runner`."""
        for shell in shells:
            with self.subTest(script=script, shell=shell):
                found = defects(script, shell)
                self.assertEqual(1, len(found), found)
                self.assertNotIsInstance(found[0][1], forms.Idle)
                self.assertTrue(found[0][1].startswith(
                    "pipes `%s` its program from `%s`, whose words this guard does not spell out"
                    % (runner, stage)), found[0][1])

    def test_c01_c04_c08_c11_c12_a_pass_through_hands_the_printer_on(self):
        # c01 `tee /dev/null`, c02 `tee log.txt`, c03 `cat`, c04 `cat -`, c08 `tee -a f`, c11
        # `tee /dev/null | cat` (two in a row), c12 `tee /dev/null 2>&1` (bash-truth b5/b3/dash/gh
        # FR FR FR FR each: the shell runs `sh tool`): the fetch-and-run sentence, as `echo 'sh
        # tool' | sh` gets it.
        for middle in ("tee /dev/null", "tee log.txt", "cat", "cat -", "tee -a f",
                       "tee /dev/null | cat", "tee /dev/null 2>&1"):
            self.assert_fetch_exec("echo 'sh tool' | %s | sh\n" % middle)

    def test_a_heredoc_cat_behind_a_pass_through(self):
        # p2n02 `cat <<'EOF' | tee log.txt | sh`, body PIPE (FR FR FR FR): the body's own pipeline
        # sentence, as `cat <<'EOF' | sh` (a01) gets it. p2n16 `cat <<'EOF' | cat | sh`, body
        # `sh tool` (FR FR FR FR): the fetch-and-run sentence.
        for shell in (None, "sh"):
            with self.subTest(shell=shell):
                found = defects(GET + "cat <<'EOF' | tee log.txt | sh\n%s\nEOF\n" % PIPE, shell)
                self.assertEqual(1, len(found), found)
                self.assertTrue(found[0][1].startswith(self.STREAM), found[0][1])
        self.assert_fetch_exec("cat <<'EOF' | cat | sh\nsh tool\nEOF\n")

    def test_an_expanding_heredoc_behind_a_pass_through_is_reported_loud(self):
        # p2n03 `cat <<EOF | tee log | sh`, body PIPE (FR FR FR FR): `_unread_stdin`'s EXPANDING
        # sentence, as `cat <<EOF | sh` (a02) gets it -- `handed` finds the body through the `tee`.
        for shell in (None, "sh"):
            with self.subTest(shell=shell):
                found = defects(GET + "cat <<EOF | tee log | sh\n%s\nEOF\n" % PIPE, shell)
                self.assertEqual(1, len(found), found)
                self.assertTrue(found[0][1].startswith("hands an EXPANDING heredoc body"),
                                found[0][1])

    def test_the_controls_stay_clean(self):
        # c05 `echo 'echo hi' | tee /dev/null | sh` (F- F- F- F-: it prints `hi`), c07 `echo 'sh
        # tool' | tee x.sh` (F- x4: no shell), p2n01 `echo 'sh tool' | tee x.sh | cat > y` (F- x4:
        # no shell either), p2n10 `echo 'sh tool' | sh 0</dev/null` (F- x4: the shell reads
        # /dev/null, the pipe is broken, and `producer` finds no source).
        for script in ("echo 'echo hi' | tee /dev/null | sh\n", "echo 'sh tool' | tee x.sh\n",
                       "echo 'sh tool' | tee x.sh | cat > y\n",
                       "echo 'sh tool' | sh 0</dev/null\n"):
            for shell in (None, "sh"):
                with self.subTest(script=script, shell=shell):
                    self.assertEqual([], defects(GET + script, shell))

    def test_c06_c09_c10_a_stage_that_rewrites_the_stream_leaves_it_unread(self):
        # c06 `base64 -d` and c09 `tr A-Z a-z` (FR FR FR FR: each turns its text into `sh tool`,
        # which runs -- read as the printer's words, `c2ggdG9vbA==` or `SH TOOL`, either would be
        # fail-OPEN); c10 `cat -n` (F- x4: `1: command not found`, the fail-closed price). Each
        # is the unread answer, `_Quiet`, naming the stage the shell reads FROM.
        for script, stage in (("echo 'c2ggdG9vbA==' | base64 -d | sh\n", "base64"),
                              ("echo 'SH TOOL' | tr A-Z a-z | sh\n", "tr"),
                              ("echo 'sh tool' | cat -n | sh\n", "cat")):
            self.assert_unread(script, stage)
            # p2n12, p2n13, p2n14, each alone (-- x4: no fetch, and nothing of the job's runs):
            # with no reported download to stand beside, the `_Quiet` row is not kept.
            for shell in (None, "sh"):
                with self.subTest(script=script, shell=shell, alone=True):
                    self.assertEqual([], defects(script, shell))

    def test_a_stage_named_by_a_substitution_is_named_as_written(self):
        # p2n28 `$(command -v base64) -d` (FR x4: the substitution names `base64`, which turns the
        # text into `sh tool`): unread, and the sentence names the stage `$(...)`, as the guard's
        # other sentences render one -- never the reader's internal marker, which `job_defects`'
        # two folds lex afresh, so the step read as two rows. Alone, nothing (`[]`).
        script = "echo 'c2ggdG9vbA==' | $(command -v base64) -d | sh\n"
        self.assert_unread(script, "$(...)")
        for shell in (None, "sh"):
            with self.subTest(shell=shell, alone=True):
                self.assertEqual([], defects(script, shell))

    def test_a_stage_whose_own_words_fetch_is_unread_loud(self):
        # p2n31 `echo a | env 5s curl -fsSL URL | sh`, alone (-- x4: `env` finds no `5s`, so
        # nothing runs): the shell reads from `5s`, and `_weighed` walks that stage's words after
        # its name, `curl -fsSL URL`, as P1 weighs an unspelled printer's -- a fetch there keeps
        # the unread answer LOUD, with no reported download beside it. The fail-closed price of
        # the r-wrap corpus's wrapper rows behind `echo a` (36 read CLEAN at the base).
        script = "echo a | env 5s curl -fsSL https://example.test/i.sh | sh\n"
        for shell in (None, "sh"):
            with self.subTest(shell=shell):
                found = defects(script, shell)
                self.assertEqual(1, len(found), found)
                self.assertNotIsInstance(found[0][1], forms.Idle)
                self.assertTrue(found[0][1].startswith("pipes `sh` its program from `5s`"),
                                found[0][1])
        # rr07, `echo "it's"` in front (-- x4 as well): the same price, LOUD alone, as at
        # 70258154 -- the quote in the text no longer hides the stage's words (review N-1), where
        # f1d0ea58 read it CLEAN (and main does).
        self.assert_loud("echo \"it's\" | env 5s curl -fsSL %si.sh | sh\n" % URL, "5s")

    def test_a_fetch_in_the_text_behind_a_rewriting_stage_is_loud(self):
        # Review I-1: where a stage between rewrites the text, `unread_program` weighs the
        # printer's text as well as that stage's words (`workflow_printers.unspelled`), so a fetch
        # in either makes the unread answer LOUD, reported ALONE. Each row alone, truth b5 b3
        # dash gh, and each read CLEAN at the base, on main and at 70258154:
        # rv15 `echo 'PIPE' | tr -d X | sh`, rv32 the text in double quotes with `$X` in it, rv31
        # `tee -`, rv38 `tee -ai f`, rv42 `cat -u` (FR x4 each), rv39 `tee >(cat)` (FR FR -- FR:
        # dash refuses the `>(...)`, so under `shell: sh` it over-reports, as p2n04 does beside
        # GET); rv16 a heredoc-fed `cat`'s body through `sed 's/^ *//'`, rv43 through
        # `grep -v '^#'` (FR x4 each); rv36 and rv37 its body through `tee "$LOG"` into `bash`,
        # LOG unset and set, and rv44 through `tee "$RUNNER_TEMP/install.sh"` (FR x4 each).
        for middle, stage in (("tr -d X", "tr"), ("tee -", "tee"), ("tee -ai f", "tee"),
                              ("tee >(cat)", "tee"), ("cat -u", "cat")):
            self.assert_loud("echo '%s' | %s | sh\n" % (PIPE, middle), stage)
        self.assert_loud('echo "%s $X" | tr -d X | sh\n' % PIPE, "tr")
        self.assert_loud("cat <<'EOF' | sed 's/^ *//' | sh\n  %s\nEOF\n" % PIPE, "sed")
        self.assert_loud("cat <<'EOF' | grep -v '^#' | sh\n# install\n%s\nEOF\n" % PIPE, "grep")
        for into in ('tee "$LOG"', 'tee "$RUNNER_TEMP/install.sh"'):
            self.assert_loud("cat <<'EOF' | %s | bash\n%s\nEOF\n" % (into, PIPE), "tee", "bash")
        self.assert_loud("LOG=install.log\ncat <<'EOF' | tee \"$LOG\" | bash\n%s\nEOF\n" % PIPE,
                         "tee", "bash")
        # rv34 `cat -n` (-- x4: the numbers spoil every line, so nothing runs) is LOUD too --
        # the over-report, p2n31's (F4's) price class: the guard does not model what `-n` does.
        self.assert_loud("echo '%s' | cat -n | sh\n" % PIPE, "cat")
        # fx02 `printf '%s\n' 'PIPE'` and fx03 `echo -n 'PIPE'` through `tr -d X` (FR x4 each):
        # the text weighed is what the printer PRINTS under each reading `spellings` gives, not
        # its words -- `%s\n` or `-n` in front would hide the fetch. fx01 `echo -e 'PIPE'` (FR FR
        # -- FR): bash's `echo` prints `PIPE` (LOUD under the default key and GitHub's pairing);
        # dash's prints `-e PIPE`, which runs nothing, so under `shell: sh` it is CLEAN.
        self.assert_loud("printf '%%s\\n' '%s' | tr -d X | sh\n" % PIPE, "tr")
        self.assert_loud("echo -n '%s' | tr -d X | sh\n" % PIPE, "tr")
        self.assert_loud("echo -e '%s' | tr -d X | sh\n" % PIPE, "tr", shells=(None,))
        self.assertEqual([], defects("echo -e '%s' | tr -d X | sh\n" % PIPE, "sh"))
        # fx04 `tr "'" x`, fx05 `sed "s/'//g"`, fx07 `tr '"' x` and fx06 `grep -v '<<X'` (FR x4
        # each: the text has no quote or `<<X` to touch, so it runs as printed): the stage's other
        # words are a text of their own, weighed apart from the printer's (review N-1), so a quote
        # or a heredoc operator among them cannot swallow the printer's text. fx08 `X=1` and fx09
        # `tr -d X | X=1` in front of the shell (-- x4: a stage with no command word prints
        # nothing) stay CLEAN, as at the base, on main and at 70258154.
        for middle, stage in (("tr \"'\" x", "tr"), ("sed \"s/'//g\"", "sed"),
                              ("tr '\"' x", "tr"), ("grep -v '<<X'", "grep")):
            self.assert_loud("echo '%s' | %s | sh\n" % (PIPE, middle), stage)
        for middle in ("X=1", "tr -d X | X=1"):
            for shell in (None, "sh"):
                with self.subTest(middle=middle, shell=shell):
                    self.assertEqual([], defects("echo '%s' | %s | sh\n" % (PIPE, middle), shell))

    def test_a_quote_in_one_text_cannot_hide_the_next(self):
        # Review N-1: `unread_program` walks each text `unspelled` gives on its own, so a quote or
        # an open `case` in the printer's text cannot swallow the stage's words after it. Each row
        # alone, the printer's text piped into `w`, a function running its words (FR x4 each: `w`
        # runs `curl`, `sh` runs the download, the text never reaches `sh`): rr09 `echo "it's"`,
        # rr42 `echo 'say "hi'`, rr43 `echo 'case x in'`, rr44 `printf "it's"` and rr46 a
        # heredoc-fed `cat`'s body `it's` -- CLEAN on main and at f1d0ea58 (one joined text, the
        # stage's words inside the open quote or `case`), LOUD at 70258154 and LOUD again now.
        fetch = "w curl -fsSL %si.sh | sh\n" % URL
        for front in ('echo "it\'s"', "echo 'say \"hi'", "echo 'case x in'", 'printf "it\'s"'):
            self.assert_loud('w() { "$@"; }\n%s | %s' % (front, fetch), "w")
        self.assert_loud("w() { \"$@\"; }\ncat <<'EOF' | %sit's\nEOF\n" % fetch, "w")
        # rr05 and rr06, an `eval` string piping `echo "it's \0047; curl -fsSL URL | sh"` through
        # `sed "s/Q'//"` or `tr -d Q` into `sh` (b5 --, b3 --, dash FR, gh --: dash's `echo`
        # decodes `\0047` and closes the quote, bash's prints it and `sh` meets an open quote).
        # A runner an `eval` string names is read both ways (#2476 R-F1), and the dash reading, a
        # text of its own now, fetches: LOUD under `shell: sh` and under the default key too,
        # where bash's reading runs nothing -- the `ANY`-reading price, #2476 R-F1. CLEAN on main
        # and at every round before (the bash reading's open quote hid the dash reading).
        text = r'''eval "echo \"it's \\0047; curl -fsSL https://example.test/i.sh | sh\" | '''
        for middle, stage in ((r'''sed \"s/Q'//\"''', "sed"), ("tr -d Q", "tr")):
            self.assert_loud(text + middle + ' | sh"\n', stage)
        # The gap the guard names: a quote or a space INSIDE one of the stage's words still hides
        # the fetch after it, the words joined, quotes removed, into the one text the walk reads.
        # fy01 `w env 'A=say "hi' curl -fsSL URL` and fy02 `w env "A=case x in" curl -fsSL URL`,
        # each behind `echo hi` and alone (FR x4 each), read CLEAN on main and at every round:
        # `[]` here is that gap, not a vacuous pin -- it fails if the gap ever closes.
        for word in ("'A=say \"hi'", '"A=case x in"'):
            for shell in (None, "sh"):
                with self.subTest(word=word, shell=shell, gap=True):
                    self.assertEqual([], defects('w() { "$@"; }\necho hi | w env %s curl -fsSL '
                                                 '%si.sh | sh\n' % (word, URL), shell))

    def test_xargs_or_the_pipe_itself_is_no_pass_through(self):
        # Review I-2: rv46 `echo 'x tool' | xargs cat | sh` (FR x4: `xargs` hands `cat` the words
        # `x` and `tool` as FILES, so `sh` runs the download's own text), CLEAN at the base, on
        # main and at 70258154: the unread answer beside GET. rv29 `echo 'tool' | xargs cat | sh`
        # (FR x4) stays reported: the unread answer and the sentence the base gave it, the
        # download piped into `sh`. rv21 `command cat` (FR x4) is a pass-through (fix round 1b):
        # `xargs` alone of the wrappers changes what the command reads, `command` only how it
        # runs, so the fetch-and-run sentence stands, as at 70258154 (round 1 read it unread).
        self.assert_unread("echo 'x tool' | xargs cat | sh\n", "cat")
        self.assert_fetch_exec("echo 'sh tool' | command cat | sh\n")
        for shell in (None, "sh"):
            with self.subTest(shell=shell, row="rv29"):
                whys = [why for _n, why in defects(GET + "echo 'tool' | xargs cat | sh\n", shell)]
                self.assertEqual(2, len(whys), whys)
                self.assertTrue(any(isinstance(why, forms._Quiet) and why.startswith(
                    "pipes `sh` its program from `cat`") for why in whys), whys)
                self.assertTrue(any(why.startswith(
                    "fetches https://example.test/tool -> tool and piping it into `sh`")
                    for why in whys), whys)
        # Review N-2: `env -S` SPLICES its string into words, so `xargs` can hide among as many
        # words as the stage has. rr16 `env -S 'xargs cat - -'` and rr28 `env -S'xargs cat -'`
        # (FR x4 each: `xargs` hands `cat` the files `x` and `tool`, the download among them),
        # CLEAN on main and at every round before: the unread answer beside GET, the answer rr17
        # `env -S 'xargs cat'` (FR x4, CLEAN on main and at 70258154) has had since fix round 1.
        for middle in ("env -S 'xargs cat - -'", "env -S'xargs cat -'", "env -S 'xargs cat'"):
            self.assert_unread("echo 'x tool' | %s | sh\n" % middle, "cat")
        # Review I-3a: rv40 `printf 'ool\nsh t' | tee /dev/stdout | sh` (FR x4: the two copies
        # meet as `ool\nsh tool\nsh t`), CLEAN at the base, on main and at 70258154: the unread
        # answer beside GET. rv17 `echo 'sh tool' | tee /dev/stdout | sh` (FR x4) and rv18
        # `printf 'tool\nsh ' | tee /dev/stdout | sh` (FR x4) were the fetch-and-run sentence at
        # 70258154 and are now the unread answer -- still reported, beside GET. rv41, rv40 with
        # `tee f` (F- x4: one copy, `ool` and `sh t` run nothing), stays CLEAN.
        self.assert_unread("printf 'ool\\nsh t' | tee /dev/stdout | sh\n", "tee")
        self.assert_unread("echo 'sh tool' | tee /dev/stdout | sh\n", "tee")
        self.assert_unread("printf 'tool\\nsh ' | tee /dev/stdout | sh\n", "tee")
        for shell in (None, "sh"):
            with self.subTest(shell=shell, row="rv41"):
                self.assertEqual([], defects(GET + "printf 'ool\\nsh t' | tee f | sh\n", shell))
        # rv48, a heredoc-fed `cat`'s PIPE body through `tee /dev/stdout`, alone (FR x4): the
        # body's stream sentence at 70258154, the LOUD unread answer now (the body fetches).
        self.assert_loud("cat <<'EOF' | tee /dev/stdout | sh\n%s\nEOF\n" % PIPE, "tee")

    def test_answers_the_pass_through_reaches_beyond_the_printer_rules(self):
        # Review I-4 (a): `_unread_stdin`'s other answers reach through a pass-through as well,
        # via `handed`: rv54 `cat <<EOF | tee f | $CMD` (F- x4) and rv28 `cat <<'EOF' | tee f |
        # python3`, body `print(1)` (F- x4), CLEAN at the base and on main, are one `Idle` row
        # each, the answer of the adjacent shape (rv55 `cat <<EOF | $CMD`, rv53 `cat <<'EOF' |
        # python3`) -- read as if adjacent.
        for script, twin, start in (
                ("cat <<EOF | tee f | $CMD\necho hi\nEOF\n", "cat <<EOF | $CMD\necho hi\nEOF\n",
                 "hands a heredoc body or here-string to `$CMD`, a command word"),
                ("cat <<'EOF' | tee f | python3\nprint(1)\nEOF\n",
                 "cat <<'EOF' | python3\nprint(1)\nEOF\n",
                 "hands a heredoc body or here-string to `python3` as the program to run")):
            for shell in (None, "sh"):
                with self.subTest(script=script, shell=shell):
                    found = defects(GET + script, shell)
                    self.assertEqual(1, len(found), found)
                    self.assertIsInstance(found[0][1], forms.Idle)
                    self.assertTrue(found[0][1].startswith(start), found[0][1])
                    self.assertEqual(defects(GET + twin, shell), found)
        # (b) rv13 `T=cat; echo 'sh tool' | $T | sh` (FR x4): `$T` may be a shell, so the text
        # it is handed is read (the fetch-and-run sentence, the base's one row), and the `sh`
        # after it reads a program from a `$` command word no table places: a second row, the
        # `_Quiet` unread answer from `$T` -- F5's price, a consumer feeding the shell. rv14, the
        # same with PIPE as the text, alone (FR x4): the stream sentence (the base's one row) and
        # the unread answer, LOUD now that the text it weighs fetches (I-1).
        for shell in (None, "sh"):
            with self.subTest(shell=shell, row="rv13"):
                whys = [why for _n, why in defects(GET + "T=cat\necho 'sh tool' | $T | sh\n",
                                                   shell)]
                self.assertEqual(2, len(whys), whys)
                self.assertTrue(any(why.startswith(self.FETCH_EXEC) for why in whys), whys)
                self.assertTrue(any(isinstance(why, forms._Quiet) and why.startswith(
                    "pipes `sh` its program from `$T`") for why in whys), whys)
            with self.subTest(shell=shell, row="rv14"):
                whys = [why for _n, why in defects("T=cat\necho '%s' | $T | sh\n" % PIPE, shell)]
                self.assertEqual(2, len(whys), whys)
                self.assertTrue(any(why.startswith(self.STREAM) for why in whys), whys)
                self.assertTrue(any(not isinstance(why, forms.Idle) and why.startswith(
                    "pipes `sh` its program from `$T`") for why in whys), whys)

    def test_a_word_that_is_no_plain_file_or_listed_option_is_no_pass_through(self):
        # p2n04 `tee >(cat)` (b5 FR, b3 FR, dash F- -- a syntax error after the fetch --, gh FR):
        # the `>(...)` operand's process may write into the stream too, so it is no plain file:
        # unread, from `tee`. p2n27 `tee "$LOG"` (FR x4, `LOG` unset: `tee` refuses the empty
        # name and still hands the text on) is a value, no plain file either. p2n20 `tee -ai f`
        # (FR x4): the options are read one to a word, as listed, so a cluster is unread too.
        # Beside GET each is the `_Quiet` answer -- the fail-closed price where the text, which
        # names no fetch, passes through; with a fetch in the text each is LOUD alone (rv31, rv38,
        # rv39 in `test_a_fetch_in_the_text_behind_a_rewriting_stage_is_loud`).
        self.assert_unread("echo 'sh tool' | tee >(cat) | sh\n", "tee")
        self.assert_unread("echo 'sh tool' | tee \"$LOG\" | sh\n", "tee")
        self.assert_unread("echo 'sh tool' | tee -ai f | sh\n", "tee")

    def test_a_shell_feeding_a_shell_rewrites_the_stream(self):
        # p2n26 `echo 'sh tool' | sh | sh` (FR x4): the first `sh` reads the printer's text and
        # runs the download, the fetch-and-run sentence; the second reads what the first PRINTS
        # -- what the download writes -- so its program is unread, from `sh` (R-P4). At the base
        # the first sentence stood alone.
        for shell in (None, "sh"):
            with self.subTest(shell=shell):
                whys = [why for _n, why in defects(GET + "echo 'sh tool' | sh | sh\n", shell)]
                self.assertEqual(2, len(whys), whys)
                self.assertTrue(any(why.startswith(self.FETCH_EXEC) for why in whys), whys)
                self.assertTrue(any(isinstance(why, forms._Quiet) and why.startswith(
                    "pipes `sh` its program from `sh`") for why in whys), whys)

    def test_an_unspelled_printer_behind_a_pass_through_is_unread_from_itself(self):
        # p2n05 `echo "$X" | tee f | sh` (F- x4: `X` unset) and p2n06, `X='sh tool'` set in front
        # (FR x4): the text arrives intact but is not spelled, so the unread answer names the
        # printer, as `echo "$X" | sh` gets it. p2n07 `printf 'sh %s\n' tool | tee f | sh` (FR
        # x4): a format past `%s` is unspelled -- from `printf`.
        self.assert_unread('echo "$X" | tee f | sh\n', "echo")
        self.assert_unread("X='sh tool'\necho \"$X\" | tee f | sh\n", "echo")
        self.assert_unread("printf 'sh %s\\n' tool | tee f | sh\n", "printf")

    def test_the_per_shell_reading_survives_the_pass_through(self):
        # p2n08 `echo 'sh\ttool' | tee f | sh` (b5 F-, b3 F-, dash FR, gh F-): bash's `echo`
        # prints the backslash and `sh` reads `shttool`; dash's decodes the tab and `sh tool` runs
        # -- b01's reading of `echo 'sh\ttool' | sh`, through the `tee`.
        script = "echo 'sh\\ttool' | tee f | sh\n"
        self.assertEqual([], defects(GET + script))
        self.assertEqual([], defects(GET + script, "bash"))
        self.assert_fetch_exec(script, shells=("sh",))

    def test_a_check_clears_it_as_before(self):
        # p2n09: the check idiom in front (F- x4: `sha256sum` fails and the step stops) clears the
        # use through the `tee`; p2n23, the same check `|| true` (FR x4), does not. p2n22: a check
        # INSIDE the printed text, under its own `set -e` (F- x4), clears it as well; p2n24, the
        # text with no `-e` (FR x4), does not -- the text is read through the `tee`, not skipped.
        use = "echo 'sh tool' | tee f | sh\n"
        inside = 'echo "%s; sh tool" | tee f | sh\n'
        for shell in (None, "sh"):
            with self.subTest(shell=shell):
                self.assertEqual([], defects(GET + self.SUM + "\n" + use, shell))
                self.assertEqual([], defects(GET + inside % ("set -e; " + self.SUM), shell))
                for script in (self.SUM + " || true\n" + use, inside % self.SUM):
                    found = defects(GET + script, shell)
                    self.assertEqual(1, len(found), found)
                    self.assertTrue(found[0][1].startswith(self.CHECKED), found[0][1])

    def test_a_stream_through_a_pass_through_keeps_its_one_sentence(self):
        # p2n11 `curl -fsSL URL | tee f | sh`, alone (FR x4): the stream rule's sentence alone, as
        # at the base and on main (one STREAM row there too) -- no printer stands behind the
        # `tee`, so no unread row joins it.
        for shell in (None, "sh"):
            with self.subTest(shell=shell):
                found = defects("curl -fsSL %si.sh | tee f | sh\n" % URL, shell)
                self.assertEqual(1, len(found), found)
                self.assertTrue(found[0][1].startswith(self.STREAM), found[0][1])

    def test_a_heredoc_cat_behind_a_rewriting_stage_is_unread_too(self):
        # p2n15 `cat <<'EOF' | base64 -d | sh`, body `c2ggdG9vbA==` (FR x4): a heredoc-fed `cat`
        # is a printer as `echo` is, so a stage that rewrites its body leaves the program unread
        # (R-P4) -- never CLEAN where the text or the stage names a fetch the walk can read (a
        # quote or a space inside one of the stage's words is the gap the guard names: fy01,
        # fy02); `_Quiet` where neither does, as here, kept beside GET (`unprinted` asks
        # `_PRINTERS` only of text that arrives intact). p2n21, body `echo hi` through
        # `tr a-z A-Z` (F- x4): the same row, the fail-closed price.
        self.assert_unread("cat <<'EOF' | base64 -d | sh\nc2ggdG9vbA==\nEOF\n", "base64")
        self.assert_unread("cat <<'EOF' | tr a-z A-Z | sh\necho hi\nEOF\n", "tr")

    def test_the_walk_is_bounded_and_fail_closed(self):
        # p2n17: 63 `cat`s put the printer 64 stages back, the last `producer` reads (FR x4): the
        # fetch-and-run sentence. Past the bound the program is unread and LOUD -- reported alone,
        # never `_Quiet` (fix round 1b): p2n18, 64 `cat`s (FR x4), and fx10, PIPE behind 65 `cat`s
        # alone (FR x4), which round 1 read CLEAN, the stopped stage's empty words weighed; p2n19,
        # p2n18 with `echo hi` (F- x4), pays the over-report, the documented price, as seventy
        # `eval`s pay `_stdin`'s bound (#2500); fx11, a stream behind 70 `cat`s (FR x4), keeps
        # its stream sentence and gains the unread row. Bounded, a long pipeline costs linear time.
        past = "a pipeline longer than the 64 stages this guard follows"
        cats = " | ".join(["cat"] * 64)
        self.assert_fetch_exec("echo 'sh tool' | %s | sh\n" % " | ".join(["cat"] * 63))
        self.assert_loud(GET + "echo 'sh tool' | %s | sh\n" % cats, past)
        self.assert_loud(GET + "echo 'echo hi' | %s | sh\n" % cats, past)
        self.assert_loud("echo '%s' | cat | %s | sh\n" % (PIPE, cats), past)
        for shell in (None, "sh"):
            with self.subTest(shell=shell, row="fx11"):
                whys = [why for _n, why in defects("curl -fsSL %si.sh | cat | cat | cat | cat | "
                                                   "cat | cat | %s | sh\n" % (URL, cats), shell)]
                self.assertEqual(2, len(whys), whys)
                self.assertTrue(any(why.startswith(self.STREAM) for why in whys), whys)
                self.assertTrue(any(not isinstance(why, forms.Idle) and why.startswith(
                    "pipes `sh` its program from `%s`" % past) for why in whys), whys)
        stages = self.stages("echo 'sh tool' | %s | sh\n" % " | ".join(["cat"] * 70))
        source, intact = wp.producer(stages[-1], stages[:-1])
        self.assertIs(stages[-1 - 65], source)          # the stage it stopped at, 65 back
        self.assertIsNone(intact)                       # unknown: neither intact nor rewritten

    def test_producer(self):
        def walk(script):
            stages = self.stages(script)
            return stages, wp.producer(stages[-1], stages[:-1])
        stages, (source, intact) = walk("echo 'sh tool' | tee f | sh\n")
        self.assertIs(stages[0], source)
        self.assertTrue(intact)
        stages, (source, intact) = walk("echo 'c2ggdG9vbA==' | base64 -d | sh\n")
        self.assertIs(stages[0], source)
        self.assertFalse(intact)
        stages, (source, intact) = walk("cat <<'EOF' | cat | sh\nsh tool\nEOF\n")
        self.assertIs(stages[0], source)
        self.assertTrue(intact)
        stages = self.stages("sh\n")
        self.assertEqual((None, False), wp.producer(stages[0], stages[:0]))
        self.assertEqual((None, False), wp.producer(stages[0], None))
        # `0</dev/null` takes the shell's descriptor 0 off the pipe (the reader's answer), so the
        # pipe is broken and there is no source.
        stages, answer = walk("echo x | sh 0</dev/null\n")
        self.assertFalse(stages[1].stdin_from_pipe)
        self.assertEqual((None, False), answer)

    def test_handed_and_unprinted_take_the_stages_in_front(self):
        stages = self.stages("cat <<'EOF' | tee log | sh\nbody\nEOF\n")
        self.assertEqual(("body", False), wp.handed(stages[2], stages[:2]))
        stages = self.stages("cat <<EOF | tee log | sh\nbody\nEOF\n")
        self.assertEqual(("body", True), wp.handed(stages[2], stages[:2]))     # EXPANDING kept
        stages = self.stages("cat <<'EOF' | tr a-z A-Z | sh\nbody\nEOF\n")
        self.assertIsNone(wp.handed(stages[2], stages[:2]))
        # `unprinted` gives a NAME, the one the sentence gives, then the TEXTS `unread_program`
        # walks, each on its own (review N-1). Where a stage between rewrites the text: the stage
        # the shell reads from, the text the printer put on the pipe, and LAST that stage's other
        # words as one text, so a fetch in either is weighed (review I-1) and a quote or an open
        # `case` in one cannot swallow the other: the base64 rows carry `echo`'s text, a
        # heredoc-fed `cat` its body, an unspelled `echo` its words. An `echo` with no words gives
        # the newline it prints, never an error; past `_DEPTH` the answer is `_PAST_DEPTH`, a
        # reason and one LOUD text, whatever the stage stopped at (fix round 1b); a stage with no
        # command word in front (`X=1`) prints nothing. An unspelled printer arriving intact gives
        # its name and its words as ONE text, as P1 weighs one right before the shell.
        deep = "echo 'sh tool' | %s | sh\n" % " | ".join(["cat"] * 70)
        for script, argv in (("echo 'c2ggdG9vbA==' | base64 -d | sh\n",
                              ["base64", "c2ggdG9vbA==\n", "-d"]),
                             ("echo x | base64 -d | tee f | sh\n", ["tee", "x\n", "f"]),
                             ("cat <<'EOF' | tr a-z A-Z | sh\nbody\nEOF\n",
                              ["tr", "body", "a-z A-Z"]),
                             ('echo "$X" | tr a b | sh\n', ["tr", "$X", "a b"]),
                             ("echo | tr a b | sh\n", ["tr", "\n", "a b"]),
                             (deep, list(wp._PAST_DEPTH)),
                             ("echo x | tr a b | X=1 | sh\n", []),
                             ('echo "$X" | tee f | sh\n', ["echo", "$X"]),
                             ("printf 'sh %s' \"$X\" | tee f | sh\n", ["printf", "sh %s $X"]),
                             ("echo 'sh tool' | tee f | sh\n", []),
                             ("cat <<EOF | tee f | sh\nbody\nEOF\n", [])):
            with self.subTest(script=script):
                stages = self.stages(script)
                self.assertEqual(argv, forms.unprinted(shell_reader.command(stages[-1].argv),
                                                       stages[-1], stages[:-1]))
        # Under a runner read both ways, each reading `spellings` gives is a text of its own.
        stages = self.stages("echo 'sh\\ttool' | tr a b | sh\n")
        self.assertEqual(["tr", "sh\\ttool\n", "sh\ttool\n", "a b"],
                         forms.unprinted(["sh"], stages[-1], stages[:-1], wp.ANY))

    def test_what_passes_through(self):
        # No stage behind `xargs` passes (review I-2), even where `env -S` splices it in and
        # `shell_reader.command` hands back as many words as the stage has (review N-2): it hands
        # `cat` or `tee` the piped words as operands, where every other wrapper the reader strips
        # changes only how the command runs, so `sudo tee f`, `nice cat`, `command cat`,
        # `time cat`, `stdbuf -oL tee f` and `env -S 'nice cat - -'` pass (fix round 1b; round 1
        # refused them all). No `tee` operand is the pipe itself (I-3a): `tee /dev/stdout`
        # doubles the text.
        for text, passes in (("tee f", True), ("tee", True), ("tee -a f", True), ("tee -p f", True),
                             ("tee -i f", True), ("tee --append f", True),
                             ("tee --output-error f", True), ("tee --output-error=warn f", True),
                             ("cat", True), ("cat -", True), ("cat -- -", True),
                             ("A=1 cat", True), ("sudo tee f", True), ("nice cat", True),
                             ("command cat", True), ("time cat", True), ("stdbuf -oL tee f", True),
                             ("env -S 'nice cat - -'", True), ("env -S 'xargs cat - -'", False),
                             ("xargs cat", False), ("xargs tee f", False),
                             ("sudo xargs cat", False), ("/usr/bin/xargs -n1 cat", False),
                             ("tee /dev/stdout", False), ("tee f /dev/fd/1", False),
                             ("tee >(cat)", False), ('tee "$F"', False),
                             ("tee -x f", False), ("tee -- f", False), ("tee -ai f", False),
                             ("tee *.log", False), ("cat -n", False), ("cat f", False),
                             ("cat - f", False), ("tr a b", False), ("base64 -d", False)):
            with self.subTest(text=text):
                stage = self.stages("echo x | %s | sh\n" % text)[1]
                self.assertIs(passes, wp._passes_through(shell_reader.command(stage.argv), stage))


def said(found, head, kind=None):
    """Whether a defect among `found` begins with `head` (and is a `kind`, where one is named)."""
    return any(why.startswith(head) and (kind is None or isinstance(why, kind))
               for _step, why in found)


class TestAPrinterThroughASubstitution(unittest.TestCase):
    """#2487, #2495: a printer reaching a shell through a substitution -- an `eval` or `-c` string
    holding a `$(...)` or backquote, a `<(...)` a shell or `source` reads as its FILE -- is read as
    the text the shell runs, where the substitution's script is ONE statement of ONE stage, an
    `echo`, a `printf` or a `cat` printing its quoted heredoc, every reading spells it alike
    (`workflow_printers.substituted`, R-P3) and its output reaches the substitution. Truth columns
    are b5 b3 dash gh (bash 5.2.21, bash 3.2.57 and dash under `-e`; gh = the step under bash
    5.2.21 with `sh` = dash), FR = fetched and ran, F- = fetched only, -- = neither, measured on
    `t36-p-probes/steps/p3/` (d01-d16) and `steps/p3b/` (e, u rows). Every step read CLEAN, or
    `Idle` beside its download, at the base (4ae90f4f) unless said otherwise. A `<(...)` is bash's:
    dash refuses it (rc 2), and a `shell: sh` step reads the same, fail-closed."""

    FETCH_EXEC = "fetches https://example.test/tool -> tool and running it under `sh` with nothing"
    STREAM = "hands https://example.test/i.sh straight to `sh`"
    EXPANDING = "hands an EXPANDING heredoc body or here-string to `%s` as the script to run"
    UNREAD = "runs `%s` on `$(...)`, a program this guard does not follow"
    PRINTED = "pipes `%s` its program from `echo`, whose words this guard does not spell out"
    CHECKED = ("fetches https://example.test/tool -> tool and running it under `sh`; the checksum "
               "that names tool is inside the script `%s` runs with what a `$(...)` prints")
    SUM = "echo %s  tool | sha256sum -c -" % ("a" * 64)
    QUOTED = "echo '%s  tool' | sha256sum -c -" % ("a" * 64)

    def test_d03_d04_d11_d12_a_printer_in_a_string_is_the_text_bash_runs(self):
        # d03 `eval "$(echo 'sh tool')"`, d04 `sh -c "$(echo 'sh tool')"`, d11 the MIXED string
        # `eval "echo hi; $(echo 'sh tool')"`, d12 `eval "sh $(echo tool)"` (b5 b3 dash gh: FR FR
        # FR FR each; base: `_DYNAMIC`'s `Idle`, d12 the value's, d11 CLEAN), and the backquote
        # e08, `printf`'s decoded tab e12 and the unquoted e15 (FR FR FR FR each): the fetch-and-run
        # sentence, under the default shell and `shell: sh` alike.
        for script in ("eval \"$(echo 'sh tool')\"\n", "sh -c \"$(echo 'sh tool')\"\n",
                       "eval \"echo hi; $(echo 'sh tool')\"\n", 'eval "sh $(echo tool)"\n',
                       "eval \"`echo 'sh tool'`\"\n", "sh -c \"$(printf 'sh\\ttool\\n')\"\n",
                       "eval $(echo 'sh tool')\n"):
            for shell in (None, "sh"):
                with self.subTest(script=script, shell=shell):
                    found = defects(GET + script, shell)
                    self.assertTrue(said(found, self.FETCH_EXEC), found)

    def test_d01_d02_d14_d16_a_printer_in_a_file_operand_is_the_program(self):
        # d01 `sh <(echo 'sh tool')`, d02 `bash <(echo "sh tool")`, d16 `sh <(printf 'sh tool\n')`
        # (b5 b3 dash gh: FR FR F- FR each -- dash refuses the `<(`), d14 `. <(echo 'sh tool')`
        # (FR F- F- FR: bash 3.2's `. <(…)` races, FR in 5 of 10 runs), e09 `source <(…)` (FR F-
        # F- FR: bash 3.2 reads it empty), e19 `bash -e <(…)` and e20 `bash -o pipefail <(…)` (FR
        # FR F- FR): each base CLEAN, now the fetch-and-run sentence.
        for script in ("sh <(echo 'sh tool')\n", 'bash <(echo "sh tool")\n',
                       "sh <(printf 'sh tool\\n')\n", ". <(echo 'sh tool')\n",
                       "source <(echo 'sh tool')\n", "bash -e <(echo 'sh tool')\n",
                       "bash -o pipefail <(echo 'sh tool')\n"):
            with self.subTest(script=script):
                found = defects(GET + script)
                self.assertTrue(said(found, self.FETCH_EXEC), found)

    def test_d07_d08_d09_a_heredoc_fed_cat_in_a_substitution_is_the_same_printer(self):
        # #2495. d07 `bash <(cat <<'EOF' … EOF)` (b5 b3 dash gh: FR FR -- FR), d08 `source <(cat
        # <<'EOF' … EOF)` (FR -- -- FR: bash 3.2 reads it empty) and d09 `eval "$(cat <<'EOF' …
        # EOF)"` (FR FR FR FR, R-P1: the gap the guard's list documented closes), the body
        # `curl … | sh`: the body's own STREAM sentence, each CLEAN at the base.
        for script in ("bash <(cat <<'EOF'\n%s\nEOF\n)\n" % PIPE,
                       "source <(cat <<'EOF'\n%s\nEOF\n)\n" % PIPE,
                       "eval \"$(cat <<'EOF'\n%s\nEOF\n)\"\n" % PIPE):
            for shell in (None, "sh"):
                with self.subTest(script=script, shell=shell):
                    self.assertTrue(said(defects(script, shell), self.STREAM), script)

    def test_e04_an_expanding_heredoc_in_a_file_operand_is_the_expanding_answer(self):
        # e04 `bash <(cat <<EOF … EOF)` (b5 b3 dash gh: FR FR -- FR) and e04b `source <(cat <<EOF
        # … EOF)` (FR -- -- FR), each CLEAN at the base: the EXPANDING answer `bash <<EOF` gets,
        # naming the shell. Its price is that answer's: e04c, a body `echo hi` (-- -- -- --), is
        # reported as `bash <<EOF` with that body is, fetch or no fetch.
        for script, runner in (("bash <(cat <<EOF\n%s\nEOF\n)\n" % PIPE, "bash"),
                               ("source <(cat <<EOF\n%s\nEOF\n)\n" % PIPE, "source"),
                               ("bash <(cat <<EOF\necho hi\nEOF\n)\n", "bash")):
            with self.subTest(script=script):
                self.assertTrue(said(defects(script), self.EXPANDING % runner), script)
        self.assertTrue(said(defects("bash <<EOF\necho hi\nEOF\n"), self.EXPANDING % "bash"))

    def test_the_controls_read_as_they_did(self):
        # d05 `sh <(echo 'echo hi')`, d06 `cat <(echo hi)` (b5 b3 dash gh: F- F- F- F-): CLEAN;
        # d10 `x=$(cat <<'EOF' … )` then `echo "$x"` (-- -- -- --): CLEAN, no shell runs it; e23
        # `bash <(cat <<'EOF' echo hi EOF)` (-- -- -- --): CLEAN; e13 `eval "$(echo 'echo hi')"`
        # (F- F- F- F-): CLEAN, where the base said `_DYNAMIC`'s `Idle` beside the download.
        for script in (GET + "sh <(echo 'echo hi')\n", GET + "cat <(echo hi)\n",
                       "x=$(cat <<'EOF'\n%s\nEOF\n)\necho \"$x\"\n" % PIPE,
                       "bash <(cat <<'EOF'\necho hi\nEOF\n)\n",
                       GET + "eval \"$(echo 'echo hi')\"\n"):
            for shell in (None, "sh"):
                with self.subTest(script=script, shell=shell):
                    self.assertEqual([], defects(script, shell))
        # e01 `sh <(curl …)` (FR FR -- FR): its one STREAM sentence, unchanged, no second row.
        found = defects("sh <(curl -fsSL %si.sh)\n" % URL)
        self.assertTrue(said(found, self.STREAM), found)
        self.assertFalse(said(found, self.PRINTED % "sh"), found)

    def test_e02_e10_a_file_operand_printer_no_reading_spells_is_the_pipe_twins(self):
        # e02 `sh <(echo "$X")` (b5 b3 dash gh: F- F- F- F-, `X` unset) and e10 `sh <(echo
        # 'sh\ttool')` (F- F- F- F-: bash prints the backslash) beside the download: `_PRINTED`'s
        # `_Quiet`, as `echo "$X" | sh` gets it -- that twin's over-report; e02c, `X='sh tool'`
        # (FR FR F- FR), is why. Alone, e02b (-- -- -- --), it reads CLEAN. Each base CLEAN.
        for script in ('sh <(echo "$X")\n', "sh <(echo 'sh\\ttool')\n",
                       "X='sh tool'\nsh <(echo \"$X\")\n"):
            with self.subTest(script=script):
                self.assertTrue(said(defects(GET + script), self.PRINTED % "sh", forms._Quiet))
        self.assertEqual([], defects('sh <(echo "$X")\n'))

    def test_e03_e06_e07_e14_what_is_not_one_printer_stays_unread(self):
        # The price of one printer of one stage: e06 two statements `eval "$(echo a; echo 'sh
        # tool')"` (b5 b3 dash gh: F- F- F- F-), e06b with `true` first (FR FR FR FR), e07 a
        # pipeline `eval "$(echo 'sh tool' | cat)"` (FR FR FR FR), e14/e14b a printer whose output
        # leaves the substitution `sh -c "$(echo 'sh tool' >&2)"` / `> /dev/null` (F- F- F- F-),
        # and e03 an operand `eval "$(cat prog.sh)"` (F- F- F- F-): `_DYNAMIC`'s `Idle` beside the
        # download, as at the base -- a fail-closed over-report where nothing runs it.
        for script, how in (("eval \"$(echo a; echo 'sh tool')\"\n", "eval"),
                            ("eval \"$(echo true; echo 'sh tool')\"\n", "eval"),
                            ("eval \"$(echo 'sh tool' | cat)\"\n", "eval"),
                            ("sh -c \"$(echo 'sh tool' >&2)\"\n", "sh -c"),
                            ("sh -c \"$(echo 'sh tool' > /dev/null)\"\n", "sh -c"),
                            ('eval "$(cat prog.sh)"\n', "eval")):
            with self.subTest(script=script):
                self.assertTrue(said(defects(GET + script), self.UNREAD % how, forms._Quiet))

    def test_d13_e11_the_r_p3_corner_where_the_readings_disagree(self):
        # d13 `sh -c "$(echo 'sh\ttool')"` and e11 `eval "$(echo 'sh\ttool')"` (b5 b3 dash gh: F-
        # F- FR F-: bash prints the backslash, dash decodes it, and only a `shell: sh` step runs
        # `sh tool`): no reading is chosen (R-P3), so the word stays all expansion -- `_DYNAMIC`'s
        # `Idle` beside the download under either key, as at the base, and CLEAN alone. The
        # fail-open corner the gap list names; d15 `sh -c "$(date)"` (F- F- F- F-), #2486's row.
        for script, how in (("sh -c \"$(echo 'sh\\ttool')\"\n", "sh -c"),
                            ("eval \"$(echo 'sh\\ttool')\"\n", "eval"),
                            ('sh -c "$(date)"\n', "sh -c")):
            for shell in (None, "sh"):
                with self.subTest(script=script, shell=shell):
                    found = defects(GET + script, shell)
                    self.assertTrue(said(found, self.UNREAD % how, forms._Quiet), found)
                    self.assertEqual([], defects(script, shell))

    def test_u01_u04_e16_e21_no_check_in_a_rendered_string_counts(self):
        # The string stays `Opaque` once its printer is read: the reader drops quotes, and bash
        # splits an UNQUOTED substitution into words. u01 `sh -c $(echo "<check>")` runs `echo`
        # alone and u03 `eval $(printf 'echo\nsha256sum -c f')` echoes the check, then `sh tool`
        # (b5 b3 dash gh: FR FR FR FR each) -- a plain text would credit the check and read CLEAN.
        # The price: their quoted twins u02 and u04, e16 `eval "$(echo "<check>")"` and e21
        # `eval "$(cat <<'EOF' <check> … EOF)"` stop at the failing check (F- F- F- F-, the check
        # run) and are reported all the same, as at the base (whose `Idle` row is gone).
        sums = 'echo "%s  tool" > tool.sha256\n' % ("a" * 64)
        for script, holder in (('sh -c $(echo "%s")\nsh tool\n' % self.SUM, "sh"),
                               ('sh -c "$(echo "%s")"\nsh tool\n' % self.SUM, "sh"),
                               (sums + "eval $(printf 'echo\\nsha256sum -c tool.sha256')\n"
                                "sh tool\n", "eval"),
                               (sums + "eval \"$(printf 'echo\\nsha256sum -c tool.sha256')\"\n"
                                "sh tool\n", "eval"),
                               ('eval "$(echo "%s")"\nsh tool\n' % self.SUM, "eval"),
                               ("eval \"$(cat <<'EOF'\n%s\nsh tool\nEOF\n)\"\n" % self.QUOTED,
                                "eval")):
            with self.subTest(script=script):
                self.assertTrue(said(defects(GET + script), self.CHECKED % holder), script)

    def test_e05_e17_e18_e22_e24_the_gaps_the_guard_documents(self):
        # The gap list's Open entries, CLEAN as at the base; each fails here if its gap closes.
        # e05 `sh -c <(echo 'sh tool')` (b5 b3 dash gh: F- F- F- F-: bash hands `-c` the pipe's
        # PATH, so nothing of the text runs) -- CLEAN is the truth there. The rest run the
        # download unread: e17 two statements `sh <(echo a; echo 'sh tool')` (FR FR F- FR), e18
        # `bash -- <(…)` and e24 `bash < <(…)` (FR FR F- FR each), e22 an EXPANDING heredoc a
        # `cat` prints for `eval` (FR FR FR FR, its body `curl … | sh`).
        for script in (GET + "sh -c <(echo 'sh tool')\n", GET + "sh <(echo a; echo 'sh tool')\n",
                       GET + "bash -- <(echo 'sh tool')\n", GET + "bash < <(echo 'sh tool')\n",
                       "eval \"$(cat <<EOF\n%s\nEOF\n)\"\n" % PIPE):
            with self.subTest(script=script):
                self.assertEqual([], defects(script))

    @staticmethod
    def word(script):
        return shell_reader.statements(script)[0].stages[0].argv[1]

    @staticmethod
    def argv(script):
        return shell_reader.command(shell_reader.statements(script)[0].stages[0].argv)

    def test_substituted_and_rendered(self):
        for script, text in (("eval \"$(echo 'sh tool')\"", "sh tool\n"),
                             ("eval \"`echo 'sh tool'`\"", "sh tool\n"),
                             ("eval \"$(printf 'sh\\ttool\\n')\"", "sh\ttool\n"),
                             ("eval \"$(echo -n x)\"", "x"),
                             ("eval \"$(cat <<'EOF'\nbody\nEOF\n)\"", "body"),
                             ("eval \"$(echo 'sh\\ttool')\"", None),
                             ("eval \"$(echo a; echo b)\"", None),
                             ("eval \"$(echo x | cat)\"", None),
                             ("eval \"$(echo x >&2)\"", None), ("eval \"$(cat f)\"", None),
                             ("eval \"$(cat <<EOF\nbody\nEOF\n)\"", None)):
            with self.subTest(script=script):
                word = self.word(script)
                value = next(v for kind, v in word.markers.values() if kind == "subst")
                self.assertEqual(text, wp.substituted(value))
                self.assertEqual("$(...)" if text is None else text.rstrip("\n"), wp.rendered(word))
        self.assertEqual("sh tool", wp.rendered(self.word('eval "sh $(echo tool)"')))
        self.assertEqual("sh $(...)", wp.rendered(self.word('eval "sh $(cat f)"')))
        self.assertEqual("$(...)", wp.rendered(self.word("sh <(echo 'sh tool')")))
        self.assertIsNone(wp.substituted(None))

    def test_file_operand_and_operand(self):
        for script, at in (("sh <(echo x)", 1), ("zsh <(echo x)", 1), ("bash -o pipefail f", 3),
                           ("bash -oe pipefail f", 3), ("bash -O extglob f", 3), ("bash -ex f", 2),
                           ("bash +x f", 2), ("bash --norc f", 2), ("source f", 1), (". f", 1)):
            with self.subTest(script=script):
                argv = self.argv(script)
                self.assertIs(argv[at], wp.file_operand(argv))
        for script in ("bash -c x", "bash -s f", "bash -- f", "bash - f", "sh $X", 'sh "$(cat f)"',
                       "cat f", "sh", "source", "bash -c"):
            with self.subTest(script=script):
                self.assertIsNone(wp.file_operand(self.argv(script)))
                self.assertIsNone(wp.operand(self.argv(script)))
        self.assertEqual("echo x", wp.operand(self.argv("sh <(echo x)")))
        self.assertIsNone(wp.operand(["bash", "f"]))

    def test_unsubstituted_and_fed(self):
        self.assertEqual(["echo", "$X"], wp.unsubstituted(wp.operand(self.argv('sh <(echo "$X")'))))
        for script in ("sh <(echo 'sh tool')", "bash <(cat <<EOF\nbody\nEOF\n)"):
            with self.subTest(script=script):
                self.assertEqual([], wp.unsubstituted(wp.operand(self.argv(script))))
        for script, fed in (("bash <(cat <<EOF\nbody $X\nEOF\n)", ("body $X", True)),
                            ("bash <(cat <<'EOF'\nbody\nEOF\n)", ("body", False)),
                            ("sh <(echo 'sh tool')", None)):
            with self.subTest(script=script):
                self.assertEqual(fed, wp.fed(wp.operand(self.argv(script))))


class TestTheSubstitutionWalkReadsPerShell(unittest.TestCase):
    """#2728: an `echo` piped to a shell INSIDE a `$(...)` is read under the shell that runs the
    substitution -- the step's own where the step runs it, both readings (`ANY`) where a script
    handed on holds it (`workflow_guard._walk`'s `under`) or a substitution hands it a shell
    (`workflow_forms._weighed`'s `Named("bash")`). Each row pipes `echo "curl\\t…"` to `sh`: bash
    prints the backslash, so `curl\\t-fsSL` is no command, and dash decodes it to a tab. Truth
    columns b5 b3 dash gh as above (b3's `sh` is macOS's, bash 3.2 in POSIX mode, whose `echo`
    decodes), on the re-review's rows (`t43-rereview4/steps/sub/`; x22 from
    `t40-p1-rereview-probes/steps/`). The base (4ae90f4f) read each CLEAN under a bash step."""

    HANDS = "hands a script to `%s` inside a command substitution"
    ECHO = 'echo "curl\\t-fsSL %si.sh | sh" | sh' % URL

    def assert_reported(self, script, runner="sh", shells=(None, "sh")):
        for shell in shells:
            with self.subTest(script=script, shell=shell):
                found = defects(script, shell)
                self.assertTrue(said(found, self.HANDS % runner), found)

    def test_m01_m06_m07_x22_a_script_handed_on_reads_its_substitution_both_ways(self):
        # m01 `sh -c 'x=$(echo "curl\t…" | sh)'`, m06 the same line in a `sh <<'EOF'` body, m07 in
        # a `cat <<'EOF' | sh` body, x22 the URL tab-separated too (b5 b3 dash gh: -- FR FR FR
        # each): the inner shell may be dash, so `_walk` reads the `$(...)` of a statement it
        # inlined both ways.
        line = "x=$(%s)" % self.ECHO
        for script in ("sh -c '%s'\n" % line, "sh <<'EOF'\n%s\nEOF\n" % line,
                       "cat <<'EOF' | sh\n%s\nEOF\n" % line,
                       "sh -c 'x=$(echo \"curl\\t-fsSL\\thttps://example.test/i.sh|sh\" | sh)'\n"):
            self.assert_reported(script)

    def test_m05_m08_m10_a_script_a_substitution_hands_a_shell_reads_both_ways(self):
        # m08 `x=$(sh -c 'echo "curl\t…" | sh')`, m10 a `sh <<'EOF'` body inside the `$(...)`,
        # m05 m08's line inside a `sh -c` string (b5 b3 dash gh: -- FR FR FR each): `_weighed`
        # flattens the handed script under `Named("bash")`, both readings.
        for script in ("x=$(sh -c '%s')\n" % self.ECHO,
                       "x=$(sh <<'EOF'\n%s\nEOF\n)\n" % self.ECHO,
                       "sh -c 'x=$(sh -c \"echo \\\"curl\\\\t-fsSL %si.sh | sh\\\" | sh\")'\n"
                       % URL):
            self.assert_reported(script)
        # m09 `x=$(eval 'echo "curl\t…" | sh')` (-- -- FR --): run by a `shell: sh` step, dash's
        # `eval` decodes it.
        self.assert_reported("x=$(eval '%s')\n" % self.ECHO, "eval", shells=("sh",))

    def test_m03_m09_m11_the_price(self):
        # Read both ways where only one shell runs it: m03 `eval 'x=$(echo "curl\t…" | sh)'` and
        # m09 under a bash step (b5 b3 dash gh: -- -- FR --, bash's `eval` prints the backslash),
        # m11 `x=$(bash -c 'echo "curl\t…" | sh')` (-- -- -- --): reported, fail-closed -- the
        # `eval`/unmeasured-runner class of #2723 and #2724.
        self.assert_reported("eval 'x=$(%s)'\n" % self.ECHO, shells=(None,))
        self.assert_reported("x=$(eval '%s')\n" % self.ECHO, "eval", shells=(None,))
        self.assert_reported("x=$(bash -c '%s')\n" % self.ECHO, "bash")

    def test_m12_the_steps_own_substitution_reads_per_the_steps_shell(self):
        # m12 `x=$(echo "curl\t…" | sh)` at the top (b5 b3 dash gh: -- -- FR --): the step's own
        # shell runs it, so a bash step reads CLEAN and a `shell: sh` step is reported, as at the
        # base.
        script = "x=$(%s)\n" % self.ECHO
        self.assertEqual([], defects(script))
        self.assert_reported(script, shells=("sh",))


if __name__ == "__main__":
    unittest.main()
