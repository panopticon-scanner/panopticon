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
        # unaffected by it -- a confirmed-correct control, not a new catch (measured, not predicted).
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
        texts = forms.stdin_scripts(argv, stages[1], stages[0], wp.Named("bash"))
        self.assertEqual(["echo \\x; sh\\ttool\n"], texts)
        self.assertIsNone(texts[0].reader)
        # One spelled reading alone keeps the real reader (bash's own table: `[spelled]`).
        texts = forms.stdin_scripts(argv, stages[1], stages[0], "bash")
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
        # shell reading the body too -- the dynamic program's `_Quiet` as before, and now the
        # download the body runs beside it (c3113439: the `_Quiet` alone).
        for shell in (None, "sh"):
            with self.subTest(step="z09", shell=shell):
                found = defects(self.GET + "S=sh\nbash -s -c \"$S\" " + body, shell)
                self.assertEqual(2, len(found), found)
                self.assertIsInstance(found[0][1], forms._Quiet)
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
