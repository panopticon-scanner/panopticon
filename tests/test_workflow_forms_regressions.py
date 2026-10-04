"""P35: bounded workflow execution forms, with verified and non-use controls."""
import inspect
import unittest

import shell_reader
import workflow_fetch as fetches
import workflow_forms as forms
import workflow_guard as guard
import workflow_printers
import workflow_programs

URL = 'https://example.test/tool'
CHECK = "echo '" + 'a' * 64 + "  tool' | sha256sum -c -"
PREFIXES = (
    'sudo -u root', 'sudo -uroot', 'sudo --user=root', 'sudo --user root --',
    'sudo --preserve-env=PATH -u root', 'sudo -nEu root', 'timeout -k 5 300', 'timeout -k5 300',
    'timeout --kill-after=5 --signal TERM -- 300', 'nice -n 10',
    'nice -n10', 'nice --adjustment=10 --', 'env -u VAR', 'env -uVAR',
    'env --unset=VAR --', 'env -i -u VAR FLAG=yes',
    'sudo -u root timeout -k 5 300 nice -n 10 env -u VAR',
)


class TestWrapperExecution(unittest.TestCase):
    def test_wrapped_fetch_and_executor(self):
        for prefix in PREFIXES:
            for script in (f'{prefix} curl {URL} | sh',
                           f'curl {URL} | {prefix} sh',
                           f'curl -o tool {URL}; {prefix} sh tool'):
                with self.subTest(script=script):
                    self.assertTrue(guard.fetch_exec_defects(script))
            verified = f'curl -o tool {URL}; {CHECK} && {prefix} sh tool'
            self.assertEqual([], guard.fetch_exec_defects(verified), prefix)
            self.assertEqual([], guard.fetch_exec_defects(
                f'{prefix} curl -o tool {URL}; cat tool'), prefix)

    def test_wrapper_operands_are_not_arbitrary_command_search(self):
        for prefix in PREFIXES:
            script = f'{prefix} ordinary curl {URL} | sh'
            self.assertEqual([], guard.fetch_exec_defects(script), script)
        for script in ('command -v curl', 'sudo --list curl'):
            self.assertEqual([], guard.fetches(script), script)
        self.assertEqual(1, len(guard.fetches('env -S "curl URL"')))

    def test_wrapper_resolution_reaches_guard(self):
        for prefix in ('sudo --preserve-groups', 'env --default-signal',
                       'env --default-signal=PIPE,TERM',
                       'env --ignore-signal=PIPE', 'env --block-signal'):
            script = f'{prefix} curl -fsSL {URL} | sh'
            with self.subTest(script=script):
                self.assertTrue(guard.fetch_exec_defects(script))
                self.assertEqual([], guard.fetch_exec_defects(
                    f'{prefix} ordinary curl {URL} | sh'))
        for prefix in ('sudo --unknown-flag', 'sudo -K',
                       'sudo --remove-timestamp', 'env --unknown-flag'):
            defect = guard.fetch_exec_defect(f'{prefix} curl -fsSL {URL} | sh')
            self.assertIsNotNone(defect, prefix)
            self.assertIn('wrapper', defect)
        self.assertEqual([], guard.fetch_exec_defects('sudo -K'))
        self.assertEqual([], guard.fetch_exec_defects('sudo --remove-timestamp'))
        self.assertTrue(guard.fetch_exec_defects('env -S "curl -fsSL ' + URL + '" | sh'))
        self.assertIn('wrapper', guard.fetch_exec_defect(
            'env -S "${FETCHER} -fsSL ' + URL + '" | sh'))
        self.assertIn('wrapper', guard.fetch_exec_defect(
            'echo "$(sudo --unknown-flag curl ' + URL + ')"'))

    def test_sudo_host_taking_forms_keep_wrapped_fetch_visible(self):
        for prefix in ('sudo -h localhost', 'sudo -hlocalhost',
                       'sudo --host=localhost'):
            script = f'{prefix} curl -fsSL {URL} | sh'
            with self.subTest(script=script):
                self.assertEqual(1, len(guard.fetches(script)))
                self.assertIn('hands', guard.fetch_exec_defect(script))
        for script in ('sudo -h', 'sudo --help'):
            self.assertEqual([], guard.fetches(script))
            self.assertEqual([], guard.fetch_exec_defects(script))


class TestSymbolicChmod(unittest.TestCase):
    def test_execute_setting_modes(self):
        for mode in ('a+x', 'u+x', 'ugo+x', 'u=rx,g+x', '+x', 'a+X',
                     'u=rX,g-w', 'u+r+x', '755', '0750'):
            with self.subTest(mode=mode):
                tail = f'chmod {mode} tool'
                self.assertTrue(guard.fetch_exec_defects(f'curl -o tool {URL}; {tail}'))
                self.assertEqual([], guard.fetch_exec_defects(
                    f'curl -o tool {URL}; {CHECK} && {tail}'))
                self.assertEqual([], guard.fetch_exec_defects(
                    f'curl -o tool {URL}; chmod {mode} other'))

    def test_mode_is_an_operand_and_removal_is_not_execution(self):
        for command in ('chmod a-x tool', 'chmod u=rw,g+r tool', 'chmod 644 tool',
                        'chmod u-X,g-x tool', 'chmod 644 tool u+x',
                        'chmod --reference=u+x tool', 'chmod --reference u+x tool'):
            self.assertEqual([], guard.fetch_exec_defects(f'curl -o tool {URL}; {command}'))
        for command in ('chmod -R u+x .', 'chmod -- u+x tool', 'chmod -v a+x tool',
                        'find . -exec chmod u+x {} \\;', 'echo tool | xargs chmod u+x'):
            self.assertTrue(guard.fetch_exec_defects(f'curl -o tool {URL}; {command}'))


class TestCurlTransfers(unittest.TestCase):
    def one(self, arguments):
        found = guard.fetches('curl ' + arguments)
        self.assertEqual(1, len(found), arguments)
        return found[0]

    def test_remote_names_and_default_overrides(self):
        for flags, dest in (
            ('-O', 'tool'), ('--remote-name', 'tool'), ('--remote-name-all', 'tool'),
            ('--remote-name-all --no-remote-name-all', None),
            ('--no-remote-name-all --remote-name-all', 'tool'),
            ('--remote-name-all --no-remote-name', None),
            ('--no-remote-name --remote-name-all', 'tool'),
            ('--remote-name-all -o saved', 'saved'),
            ('-o saved --remote-name-all', 'saved'),
            ('--remote-name-all -o -', None),
            ('--remote-name --output-dir downloads', 'downloads/tool'),
            ('--remote-name-all --output-dir=downloads -o saved', 'downloads/saved'),
        ):
            with self.subTest(flags=flags):
                self.assertEqual(dest, self.one(f'{flags} {URL}').dest)
                if dest:
                    self.assertTrue(guard.fetch_exec_defects(f'curl {flags} {URL}; sh {dest}'))
        for flag in ('-O', '--remote-name', '--remote-name-all'):
            self.assertEqual([], guard.fetch_exec_defects(f'curl {flag} {URL}; {CHECK} && sh tool'))
            self.assertEqual([], guard.fetch_exec_defects(f'curl {flag} {URL}; cat tool'))

    def test_url_option_and_url_valued_non_transfer_options(self):
        for args in (f'--url {URL}', f'--url={URL}',
                     f'-H https://header.test/x {URL}',
                     f'--referer https://referer.test/x --url={URL}',
                     f'--proxy=https://proxy.test --url {URL}',
                     f'--doh-url https://resolver.test --url {URL}',
                     f'--location-trusted {URL}'):
            with self.subTest(args=args):
                self.assertEqual(URL, self.one(args).url)
                self.assertTrue(guard.fetch_exec_defects('curl ' + args + ' | sh'))
        self.assertEqual('--help', self.one('--url=--help').url)

    def test_multiple_transfers_and_unresolved_fanout_are_unread(self):
        for args in (
            f'--remote-name-all {URL} https://example.test/second',
            f'-O {URL} --url https://example.test/second',
            f'--url={URL} --url=https://example.test/second',
            f'-o tool {URL} --next -o second https://example.test/second',
            f'-o tool {URL} -: -o second https://example.test/second',
            f'-K config {URL}', f'--config=config {URL}',
            '--remote-name-all https://example.test/{tool,second}',
            '--remote-name https://example.test/[1-2]', f'-OJ {URL}',
            f'--remote-name --remote-header-name {URL}',
            f'-o tool -o second {URL}',
            f'-O -o second {URL}', f'--remote-name --no-remote-name {URL}',
            f'{URL} --remote-name-all', f'--remote-name-all {URL} --no-remote-name-all',
        ):
            with self.subTest(args=args):
                self.assertEqual(forms.Fetch('curl', None, None, None), self.one(args))
                self.assertTrue(guard.fetch_exec_defects(
                    'curl ' + args + f'; {CHECK} && sh second'))
                self.assertIn('single-download', guard.fetch_exec_defect('curl ' + args))
        args = f'--remote-name-all {URL} https://example.test/second'
        for script in (f'eval "$(curl {args})"', f'sh <(curl {args})',
                       f'echo "$(curl {args})"', f"sh -c 'curl {args}; sh second'"):
            self.assertTrue(guard.fetch_exec_defects(script), script)
        self.assertTrue(guard.job_defects([
            guard.Step('download', 'curl ' + args),
            guard.Step('verify first', CHECK), guard.Step('run second', 'sh second')]))

    def test_deterministic_glob_and_header_disabling(self):
        for args in ('--globoff --remote-name https://example.test/[1-2]',
                     '-gO https://example.test/{a,b}',
                     f'-OJ --no-remote-header-name {URL}'):
            self.assertIsNotNone(self.one(args).url)
        self.assertIsNone(self.one('-g --no-globoff https://example.test/{a,b}').url)

    def test_informational_fetchers(self):
        for script in ('curl --help', 'curl --help all', 'curl --version', 'curl -V',
                       'curl --manual', 'wget --help', 'wget --version'):
            self.assertEqual([], guard.fetches(script), script)
            self.assertEqual([], guard.fetch_exec_defects(script), script)


class TestCombinedPipeline(unittest.TestCase):
    def test_stream_order_and_disconnected_controls(self):
        for redirects, streaming in (('', True), ('2>err', True), ('>saved', False),
                                     ('2>&1 >saved', False), ('3>&1 >saved 1>&3', True),
                                     ('2>&-', True)):
            with self.subTest(redirects=redirects):
                script = f'curl {URL} {redirects} |& sh'
                self.assertEqual(streaming, bool(guard.fetch_exec_defects(script)))
                self.assertEqual([], guard.fetch_exec_defects(script + ' <local'))
                self.assertEqual([], guard.fetch_exec_defects(
                    f'curl {URL} {redirects} |& cat'))
        self.assertTrue(guard.fetch_exec_defects(f'curl {URL} |& tee tool | sh'))
        self.assertTrue(guard.fetch_exec_defects(f'curl {URL} >saved |& sh; sh saved'))
        self.assertEqual([], guard.fetch_exec_defects(
            f'curl {URL} >tool |& cat; {CHECK} && sh tool'))

    def test_a_value_command_word_is_a_stream_consumer(self):
        # #2602: the first word may name a shell even though no executor table
        # can place it. The same walk must cross a pass-through `tee` stage.
        for tail, word in (("$CMD", "$CMD"), ("${CMD}", "${CMD}"),
                           ("$(echo sh)", "$(...)"), ("tee saved | $SUDO sh", "$SUDO")):
            with self.subTest(tail=tail):
                stages = shell_reader.statements(f"curl {URL} | {tail}")[0].stages
                consumer = forms.stream_consumer(stages[1:], guard.EXECUTORS)
                self.assertEqual(word, shell_reader.readable(consumer[0]))


class TestFetchCompatibility(unittest.TestCase):
    def test_single_owner_and_legacy_shapes(self):
        self.assertEqual(12, len(shell_reader.Stage._fields))
        legacy = shell_reader.Stage([], [], [], None, [], [])
        self.assertEqual((0, 0, True, True, ("0",), None), tuple(legacy)[6:])
        self.assertEqual(("tool", "url", "dest", "piped_to"), forms.Fetch._fields)
        for name in ("Fetch", "FETCHERS", "STDOUT", "parse_fetch", "streamed_fetch"):
            self.assertIs(getattr(forms, name), getattr(fetches, name))
        self.assertIs(guard.parse_fetch, fetches.parse_fetch)
        self.assertIs(guard.streamed_fetch, fetches.streamed_fetch)
        self.assertEqual(('tool', 'args', 'stage', 'piped_to'),
                         tuple(inspect.signature(forms.parse_fetch).parameters))
        self.assertEqual(('tool', 'args', 'stage', 'following', 'executors'),
                         tuple(inspect.signature(forms.streamed_fetch).parameters))

    def test_unread_transfer_never_supplies_a_stream(self):
        parsed = shell_reader.statements(f'curl {URL} --url {URL}/second | sh')[0]
        first, last = parsed.stages
        self.assertEqual(forms.Fetch('curl', None, None, None), forms.parse_fetch(
            'curl', first.argv[1:], first, tuple(last.argv)))
        self.assertIsNone(forms.streamed_fetch(
            'curl', first.argv[1:], first, [last], guard.EXECUTORS))

    def test_url_and_directory_derivations_retain_provenance(self):
        for options in ('--url="$(echo URL)" -o tool',
                        '--url "$(echo URL)" --remote-name',
                        '--output-dir="$(echo directory)" --remote-name ' + URL):
            fetch = guard.fetches('curl ' + options)[0]
            self.assertTrue(shell_reader.has_substitution(fetch.url)
                            or shell_reader.has_substitution(fetch.dest))
        self.assertEqual([], guard.fetch_exec_defects(
            'curl -H "$(echo unused)" --remote-name ' + URL + '; ' + CHECK + ' && sh tool'))


class TestReviewRoundOne(unittest.TestCase):
    def test_sudo_shell_and_login_execute_supplied_commands(self):
        for prefix in ('sudo -s', 'sudo -i', 'sudo --shell', 'sudo --login',
                       'sudo -ns -u root', 'sudo --login --user=root --'):
            for script in (f'{prefix} curl {URL} | sh',
                           f'curl {URL} | {prefix} sh',
                           f'curl -o tool {URL}; {prefix} sh tool'):
                with self.subTest(script=script):
                    self.assertTrue(guard.fetch_exec_defects(script))
            self.assertEqual([], guard.fetch_exec_defects(
                f'{prefix} curl -o tool {URL}; {CHECK} && {prefix} sh tool'))
            self.assertEqual([], guard.fetch_exec_defects(
                f'{prefix} curl -o tool {URL}; cat tool'))
        argv = ['sudo', '--unknown', 'ordinary', 'curl', URL]
        self.assertEqual(argv, shell_reader.command(argv))

    def test_chmod_mode_is_not_a_target_filename(self):
        for mode in ('u+x', 'a+x', 'u=rx,g+x', '+x', '755'):
            for prefix in ('chmod', 'chmod -v', 'chmod --'):
                with self.subTest(mode=mode, prefix=prefix):
                    download = f'curl -o {mode} {URL}; '
                    self.assertEqual([], guard.fetch_exec_defects(
                        download + f'{prefix} {mode} other'))
                    self.assertTrue(guard.fetch_exec_defects(
                        download + f'{prefix} {mode} ./{mode}'))
                    check = "echo '" + 'a' * 64 + f"  {mode}' | sha256sum -c -"
                    self.assertEqual([], guard.fetch_exec_defects(
                        download + check + f' && {prefix} {mode} ./{mode}'))
        for command in ('chmod -R u+x .', 'find . -exec chmod u+x {} \\;',
                        'echo u+x | xargs chmod u+x', 'chmod u+x u+?'):
            self.assertTrue(guard.fetch_exec_defects(f'curl -o u+x {URL}; {command}'))
        for command in ('find other -exec chmod u+x {} \\;',
                        'echo other | xargs chmod u+x', 'chmod -R u+x other'):
            self.assertEqual([], guard.fetch_exec_defects(f'curl -o u+x {URL}; {command}'))


class TestTheProgramAfterDashC(unittest.TestCase):
    """#2332: a shell reads on past the option words after `-c` to its program.

    Bash 3.2.57 and 5.2.21 run `P` in every spelling below, and so does dash,
    but for the `-o`/`-O` ones: it has no `pipefail` or `extglob`, and refuses
    them with nothing run. A `--long` word after `-c` all three refuse.
    """

    @staticmethod
    def program(script):
        stmts = shell_reader.statements(script)
        assert len(stmts) == 1 and len(stmts[0].stages) == 1, stmts
        return forms.scripts(stmts[0].stages[0].argv)

    def test_the_option_words_after_dash_c_are_skipped(self):
        for spelling in ("sh -c -e", "bash -c -x", "sh -c +x", "sh -c --", "sh -c -",
                         "bash -c -e --", "bash -ec --", "bash -c -o pipefail",
                         "bash -c -O extglob", "bash -co pipefail", "bash -oc pipefail",
                         "bash -c -ex +o pipefail --", "bash -c -s"):
            with self.subTest(spelling=spelling):
                self.assertEqual(["P"], self.program(spelling + " P x"))

    def test_an_option_letter_no_shell_takes_hands_over_no_program(self):
        # #2475: `sh -c -K P` and `sh -cK P` are refused outright -- bash
        # 3.2.57, 5.2.21 and dash all exit before they read `P` -- so the
        # step runs nothing and no program is handed over. The letters are
        # bash's (`workflow_programs.SHELL_OPTIONS`), which is the union:
        # dash takes fewer, and a letter dash alone refuses still runs.
        for spelling in ("sh -c -K", "sh -cK", "bash -c -Z -e", "bash -c -e -Z",
                         "bash -c -o pipefail -K", "sh -c -ex +Z"):
            with self.subTest(spelling=spelling):
                self.assertEqual([], self.program(spelling + " P x"))
        pipe = f'curl -fsSL {URL} | sh'
        for script in (f"sh -c -K '{pipe}'", f"sh -cK '{pipe}'", f"bash -c -e -Z '{pipe}'"):
            with self.subTest(script=script):
                self.assertEqual([], guard.fetch_exec_defects(script))
        # A word that is not all LETTERS is read ON, as it was and fail-closed:
        # bash, dash and ksh refuse `-1`, `-I{}` and `-nw5`, but zsh RUNS `-1`
        # (review NIT 5), and all five shells run the program after
        # `sh -c -u$X P` wherever `X` is empty.
        for spelling in ("sh -c -1", "sh -c -I{}", "sh -c -nw5", "sh -c -u$X"):
            with self.subTest(spelling=spelling):
                self.assertEqual(["P"], self.program(spelling + " P x"))
        # The controls: a letter both shells take reads on to the program as
        # it did, `-O` is one bash takes WITH a value, and a value where the
        # shell reads its options is unfollowed still (#2344).
        for script in (f"sh -c -e '{pipe}'", f"bash -c -o pipefail '{pipe}'",
                       f"bash -c -O extglob '{pipe}'", f"X=-K\nsh $X -c '{pipe}'"):
            with self.subTest(script=script):
                self.assertTrue(guard.fetch_exec_defects(script), script)

    def test_the_refusal_is_the_measured_familys_and_nobody_elses(self):
        # Review BLOCKER 1 and MAJOR 2: this walk is reached for every name in
        # `_SHELL_STRING`, and zsh 5.9 RUNS twenty of the letters bash refuses
        # -- `zsh -c -K 'curl … | sh'` is rc 0, fetches AND runs the download,
        # and so are `-F`, `-S`, `-d`, `-g`, `-w`, `-y`; ksh 93u+ runs `-G`.
        # So an unknown letter is a refusal only for the shells whose table is
        # measured (`sh`, `bash`, `dash`); for zsh, ksh, the unmeasured `ash`
        # and a command word this module cannot identify, the word is read ON
        # exactly as it was.
        pipe = f'curl -fsSL {URL} | sh'
        for spelling in ("zsh -c -K", "zsh -cK", "zsh -c +K", "ksh -c -G", "ash -c -K"):
            with self.subTest(spelling=spelling):
                self.assertEqual(["P"], self.program(spelling + " P x"))
                self.assertTrue(guard.fetch_exec_defects(f"{spelling} '{pipe}'"))
        # A `$` command word keeps #2344's own sentence: a letter table for a
        # command this guard does not follow cannot overrule it, and `X=zsh`
        # fetches and runs. A `${X:-sh}` reads as its default here too.
        # `X` is a `$(...)` no table sees: since #2468 a literal one reads as its command.
        for script in (f"X=$(echo sh)\n$X -cK '{pipe}'\n", f"X=$(echo sh)\n$X -c -K '{pipe}'\n"):
            with self.subTest(script=script):
                self.assertIn("a command word this guard does not follow",
                              guard.fetch_exec_defect(script))
        self.assertIn("straight to `sh`", guard.fetch_exec_defect(f"${{X:-sh}} -cK '{pipe}'"))
        # Beside them, the measured family reads the refusal (#2475).
        for shell in ("sh", "bash", "dash"):
            with self.subTest(shell=shell):
                self.assertEqual([], self.program(f"{shell} -c -K P x"))
                self.assertEqual([], guard.fetch_exec_defects(f"{shell} -c -K '{pipe}'"))

    def test_an_option_name_no_shell_takes_hands_over_no_program(self):
        # #2560 on the COMMAND LINE: an `-o` value outside the names the
        # measured shells take is one the shell refuses, and it exits before
        # it reads `P`.
        # bash 3.2.57: `bash -c -o foo P` and `bash -co foo P` are `foo:
        #   invalid option name`, rc 2, with `P` never run.
        # bash 5.2.21: the same, rc 2 both.
        # dash: `Illegal option -o foo`, rc 2 -- and it refuses `pipefail`
        #   itself, which bash takes, so the table is the UNION.
        pipe = f'curl -fsSL {URL} | sh'
        for spelling in ("sh -c -o foo", "sh -co foo", "bash -c -o foo -e",
                         "bash -c -ex +o foo", "bash -co foo -O extglob"):
            with self.subTest(spelling=spelling):
                self.assertEqual([], self.program(spelling + " P x"))
                self.assertEqual([], guard.fetch_exec_defects(f"{spelling} '{pipe}'"))
        # The controls: a name bash takes reads on to the program as it did
        # (`bash -co pipefail P` and `bash -c -o pipefail P` print `RAN`, rc
        # 0 on both bashes), and so does a value this guard cannot read as a
        # name at all -- `sh -c -o $X P` runs `P` wherever `X` is `pipefail`,
        # exactly as `sh -c -u$X P` does (#2475).
        for spelling in ("bash -co pipefail", "bash -c -o pipefail", "sh -c -o $X",
                         "bash -c -o ${X:-pipefail}", "bash -c -o pipefail -O extglob"):
            with self.subTest(spelling=spelling):
                self.assertEqual(["P"], self.program(spelling + " P x"))
                self.assertTrue(guard.fetch_exec_defects(f"{spelling} '{pipe}'"))
        # dash takes three names bash refuses -- `dash -o stdin -c 'echo RAN
        # $-'` is `RAN s`, rc 0, and so are `-o interactive` and `-o debug`,
        # where bash answers `stdin: invalid option name`, rc 2 -- so the
        # union reads the program on for all three. zsh, ksh and the
        # unmeasured `ash` are read on whatever the name is.
        for spelling in ("bash -c -o stdin", "sh -co interactive", "dash -c -o debug",
                         "zsh -c -o foo", "ksh -co foo", "ash -c -o foo"):
            with self.subTest(spelling=spelling):
                self.assertEqual(["P"], self.program(spelling + " P x"))

    def test_the_first_operand_is_the_program_as_it_was(self):
        self.assertEqual(["P"], self.program("sh -c P x"))
        self.assertEqual(["P"], self.program("bash -euc P"))
        # A dynamic program reads as `sh -c "$P"` does; after `--` a word
        # that begins with `-` is the program; with none, there is none.
        self.assertEqual(["$P"], self.program('sh -c -x "$P"'))
        self.assertEqual(["-P"], self.program("sh -c -- -P"))
        self.assertEqual([], self.program("sh -c -x"))
        self.assertEqual([], self.program("bash -c --norc P"))

    def test_a_substitution_among_the_strings_text_is_read_opaque(self):
        # #2486: the string is a script, the substitution written as the
        # reader renders it and the script marked `Opaque`, so no marker of
        # this parse reaches the next -- two parses give one text. A word
        # that is one lone `$(...)` is still none: `dynamic_program` names it.
        # Since #2487 a `$(...)` that is one printer is written as the text it
        # prints (`workflow_printers.rendered`), the script still `Opaque`, and
        # a lone one so written is a script, no dynamic program.
        for script, text in (('sh -c "sh $(cat f)" x', "sh $(...)"),
                             ('eval "sh $(cat f)"', "sh $(...)"),
                             ('sh -c "sh $(echo tool)" x', "sh tool"),
                             ('eval "sh $(echo tool)"', "sh tool"),
                             ('sh -c "$(echo tool)" x', "tool")):
            with self.subTest(script=script):
                found = self.program(script)
                self.assertEqual([text], found)
                self.assertIsInstance(found[0], workflow_programs.Opaque)
                self.assertEqual(found, self.program(script))
        self.assertEqual([], self.program('sh -c "$(cat f)" x'))
        # A text so rendered that the reader refuses is none, as before:
        # `cat <<$(...)` names no line to end the body at. Nothing reaches a
        # re-parse that would refuse the whole step. A printer's `E` is a
        # delimiter like any other (#2487).
        for script in ('eval "cat <<$(a b)\nit\'s\n$(a b)\n"', 'sh -c "cat <<$(cat d)\nE\nsh x"'):
            with self.subTest(script=script):
                self.assertEqual([], self.program(script))
                self.assertEqual([], guard.fetch_exec_defects(script))
        self.assertEqual(["cat <<E\nE\nsh x"], self.program('sh -c "cat <<$(echo E)\nE\nsh x"'))

    def test_a_word_that_is_all_substitution_is_the_dynamic_programs(self):
        # #2486: it spells no command, so `scripts` hands on no text for it
        # and `dynamic_program` names it; one with text of its own is not.
        for script, how, word in (('sh -c "$(cat x)"', "sh -c", "$(...)"),
                                  ('eval "$(cat x)"', "eval", "$(...)"),
                                  ('sh -c "$P$(cat x)"', "sh -c", "$P$(...)")):
            with self.subTest(script=script):
                argv = shell_reader.statements(script)[0].stages[0].argv
                found = workflow_programs.dynamic_program(argv)
                self.assertEqual((how, word), (found[0], shell_reader.readable(found[1])))
                self.assertEqual([], self.program(script))
        for script in ('sh -c "echo $(date)"', 'sh -c "$(curl %s) x"' % URL):
            with self.subTest(script=script):
                argv = shell_reader.statements(script)[0].stages[0].argv
                self.assertEqual((None, None), workflow_programs.dynamic_program(argv))

    def test_a_process_substitution_is_neither_an_opaque_script_nor_a_dynamic_program(self):
        # `shell_reader.yields_words`: a `<(...)` hands a file, not words. A
        # string holding one beside a `$(...)` is no script at all, where its
        # twin with the `$(...)` alone is read opaque (#2486), the one
        # printer's text written in (#2487) ...
        for script in ('sh -c "sh $(echo tool) <(echo x)" x', 'eval "sh $(echo tool) <(echo x)"'):
            with self.subTest(script=script):
                self.assertEqual([], self.program(script))
        found = self.program('sh -c "sh $(echo tool)" x')
        self.assertEqual(["sh tool"], found)
        self.assertIsInstance(found[0], workflow_programs.Opaque)
        # ... and a program word that is all `<(...)` is not `dynamic_program`'s,
        # where its `$(...)` twin is.
        for script in ('sh -c "<(cat tool)"', 'eval "<(cat tool)"'):
            with self.subTest(script=script):
                argv = shell_reader.statements(script)[0].stages[0].argv
                self.assertEqual((None, None), workflow_programs.dynamic_program(argv))
        argv = shell_reader.statements('sh -c "$(cat tool)"')[0].stages[0].argv
        found = workflow_programs.dynamic_program(argv)
        self.assertEqual(("sh -c", "$(...)"), (found[0], shell_reader.readable(found[1])))


class TestAValueWhereAShellReadsItsOptions(unittest.TestCase):
    """#2344: a value bash expands where a shell reads its options may be
    `-c` -- `X=-c; sh $X P`, `sh $(echo -c) P`, `xargs -I{} sh {} P` run `P`
    under bash 3.2.57 and 5.2.21 -- so a word after it may be the program.
    The guard does not follow the value; `candidates` hands on the words
    after it to the first operand, a dynamic one too, for `unread_program`
    (review N2 of #2331), and none past it, a positional parameter (#2484),
    until a later word that may expand to an option word re-opens the rest:
    the operand may have been an option's own value (`--rcfile FILE`)."""

    @staticmethod
    def argv(script):
        stmts = shell_reader.statements(script)
        assert len(stmts) == 1, stmts
        return shell_reader.command(stmts[0].stages[-1].argv)

    def test_the_words_to_the_first_operand_after_the_value_are_candidates(self):
        for script, value in (("sh $X P", "$X"), ('sh "${X:--c}" P', "${X:--c}"),
                              ("sh $(echo -c) P", "$(...)"), ("bash -e $X -o pipefail P", "$X"),
                              ("echo -c | xargs -I{} sh {} P", "{}"), ("sh ${X}c P", "${X}c")):
            with self.subTest(script=script):
                found, words = forms.candidates(self.argv(script))
                self.assertEqual((value, ["P"]), (shell_reader.readable(found), words[-1:]))
        # Bare words and `$` words may be an option's value, or vanish, so the
        # walk reads past them: with no operand, every word after the value.
        self.assertEqual(["P", "$Y", "Q"], forms.candidates(self.argv('sh $X P "$Y" Q'))[1])
        # The first word that can be none of an option, an option's value (a
        # bare word) or anything once expanded is the first operand, the last
        # candidate; the option words before it stay (#2484), and a later word
        # of literal text, `--` among them, re-opens nothing.
        for script, words in (("sh $X P \"$Y\" 'echo Q' R", ["P", "$Y", "echo Q"]),
                              ("sh $X -e -o pipefail 'echo P' Q", ["-e", "-o", "pipefail", "echo P"]),
                              ("bash $X extglob 'echo P' Q", ["extglob", "echo P"]),
                              ("sh $X x$Y 'echo P' Q", ["x$Y", "echo P"]), ("sh $X -e", ["-e"]),
                              ("sh $X 'echo P' x$Y Q", ["echo P"]),
                              ("bash $X /dev/null -- P", ["/dev/null"])):
            with self.subTest(script=script):
                self.assertEqual(words, forms.candidates(self.argv(script))[1])
        # That operand may be an option's own value (`--rcfile FILE`), so the
        # first later word that may expand to an option word re-opens every
        # word after it -- never itself, which with `X=-c` is a parameter and
        # with `--rcfile` an option word or a file name. The fourth row was
        # `['echo P']` under #2484 alone: the rule's price.
        for script, words in (("bash $X /dev/null $Y 'echo P' Q", ["/dev/null", "echo P", "Q"]),
                              ("bash $X /dev/null -$Y P", ["/dev/null", "P"]),
                              ("sh $X 'echo P' \"$Y\"", ["echo P"]),
                              ("sh $X 'echo P' \"$Y\" Q", ["echo P", "Q"]),
                              ("sh $X 'echo P' \"$Y\" Q R", ["echo P", "Q", "R"])):
            with self.subTest(script=script):
                self.assertEqual(words, forms.candidates(self.argv(script))[1])

    def test_none_where_the_options_end_first(self):
        # At a program, a `-c` (whose string `scripts` reads), a `--`, a word
        # the value only begins (`$X/x.sh` is no option), or a value an `-o`
        # takes; and a pattern is `leads`'s to read (#2294).
        for script in ("sh $X", "sh x.sh $X P", "sh -c $X P", "sh -- $X P", "bash $X/x.sh P",
                       "bash -o $X P", "bash [-]c P", "python3 $X P", "sh -e P"):
            with self.subTest(script=script):
                self.assertEqual([], forms.candidates(self.argv(script))[1])

    def test_every_o_before_a_stdin_program_takes_a_value(self):
        # `bash -oe pipefail <<'EOF'` reads its program from the heredoc.
        for argv in (["bash", "-oe", "pipefail"], ["bash", "-eo", "pipefail", "-s"],
                     ["bash", "-oo", "errexit", "pipefail"]):
            with self.subTest(argv=argv):
                self.assertEqual(forms.SHELL_PROGRAM, forms.stdin_program(argv))
        self.assertIsNone(forms.stdin_program(["bash", "-oe", "pipefail", "x.sh"]))

    def test_2605_a_file_after_a_value_option_keeps_stdin_possible(self):
        # The value may be `-s`, making every following word a parameter, or
        # `--rcfile`, making the first literal word that option's value.
        rows = (("sh $X file.sh", forms.SHELL_PROGRAM),
                ("bash $X x.sh arg", forms.SHELL_PROGRAM),
                ("bash $X /dev/null", forms.SHELL_PROGRAM),
                ("bash $X /dev/null -s arg", forms.SHELL_PROGRAM),
                ("$CMD $X file.sh", workflow_programs.VALUE_PROGRAM))
        for script, expected in rows:
            with self.subTest(script=script):
                self.assertEqual(expected, forms.stdin_program(self.argv(script)))
        # A literal file, an ended option list and a literal `-c` remain files
        # or strings. The literal `-s` must-trip remains a stdin program.
        for script in ("sh file.sh", "sh -- $X file.sh", "sh $X -c 'cat' file.sh"):
            with self.subTest(script=script):
                self.assertIsNone(forms.stdin_program(self.argv(script)))
        self.assertEqual(forms.SHELL_PROGRAM,
                         forms.stdin_program(self.argv("sh -s file.sh")))

    def test_a_stdin_reading_shell_behind_eval_or_dash_c_is_the_enclosings_answer(self):
        # #2500: `eval 'bash -s' <<'EOF'` and `bash -c 'sh' <<'EOF'` run the
        # heredoc in bash 3.2.57 and 5.2.21 alike -- the program string is one
        # statement whose own command (`bash -s`, `sh`) already answers
        # SHELL_PROGRAM, so the command handing it to `eval`/`-c` does too,
        # and its own heredoc/here-string/pipe is read as that inner shell's.
        for argv in (["eval", "bash -s"], ["bash", "-c", "sh"], ["eval", "sh"],
                     ["sh", "-c", "bash -s"]):
            with self.subTest(argv=argv):
                self.assertEqual(forms.SHELL_PROGRAM, forms.stdin_program(argv))
        # `echo hi` and `cat` do not read their own program from stdin, so
        # nothing is inherited: it is the HEREDOC that stays `eval`'s or
        # `-c`'s DATA, as one behind a literal filename does too.
        for argv in (["eval", "echo hi"], ["bash", "-c", "cat"], ["eval", "sh x.sh"]):
            with self.subTest(argv=argv):
                self.assertIsNone(forms.stdin_program(argv))
        # r0's N-4 (d13): `eval`'s own several words join into the ONE
        # string bash runs before this check, never read one at a time --
        # `eval bash script.sh` is `bash script.sh`, a FILE (bash runs the
        # file, not the heredoc), not bare `bash` alone reading stdin, and
        # `eval set -- "$ARGS"` is not `set` alone either.
        for argv in (["eval", "bash", "script.sh"], ["eval", "set", "--", "$ARGS"]):
            with self.subTest(argv=argv):
                self.assertIsNone(forms.stdin_program(argv))
        # `stdin_program` answers the unquoted and quoted spellings of the
        # same joined string alike.
        for argv in (["eval", "bash", "-s"], ["eval", "bash -s"]):
            with self.subTest(argv=argv):
                self.assertEqual(forms.SHELL_PROGRAM, forms.stdin_program(argv))

    def test_a_stdin_reading_value_behind_eval_or_dash_c_is_inherited_and_named(self):
        # #2599: the enclosing command inherits VALUE_PROGRAM too, while the
        # naming seam retains the inner word that may name the stdin reader.
        for argv, word in ((["eval", "$CMD"], "$CMD"),
                           (["bash", "-c", "$CMD"], "$CMD"),
                           (["sh", "-c", "$P"], "$P")):
            with self.subTest(argv=argv):
                self.assertEqual(workflow_programs.VALUE_PROGRAM,
                                 forms.stdin_program(argv))
                self.assertEqual(word, workflow_programs.stdin_command(argv)[0])

    def test_a_value_or_a_word_that_may_vanish_does_not_end_a_shells_walk(self):
        # #2485: `X=-s; sh $X <<'EOF'` runs the heredoc in bash 3.2.57,
        # 5.2.21 and dash, as `bash $(true)` does -- the value form
        # (`_value`) in the operand slot does not end the walk at a FILE,
        # so it reads on to the heredoc exactly as `sh -s` does. Quoting is
        # already lost by the time a word reaches here (`sh "$X"` and
        # `sh $X` give the same argv), so `stdin_program` answers the quoted
        # spelling alike -- true of the reader's parse, not a claim that
        # bash runs every quoted value exactly as the unquoted one.
        for script in ("sh $X", "bash $(true)", "bash $X"):
            with self.subTest(script=script):
                self.assertEqual(forms.SHELL_PROGRAM, forms.stdin_program(self.argv(script)))
        # Limited to shells: a FOREIGN interpreter's file operand is unaffected.
        self.assertIsNone(forms.stdin_program(self.argv("python3 $S")))
        # A literal word still ends the walk at a file, value-form or not.
        self.assertIsNone(forms.stdin_program(self.argv("sh x.sh")))
        # A `<(...)` is `_value`-shaped too (every substitution reads back as
        # `$(...)`), but it never vanishes: a process substitution always
        # substitutes a real path, so it stays a FILE, as `$(true)` (whose
        # OUTPUT may vanish) does not. Found via the 11-corpus differential
        # (i-sub row 106): `echo "$X" | bash <(curl ...)` gained a spurious
        # "pipes `bash` its program from `echo`" report until this was
        # excluded -- review I-3: a LITERAL `echo hi` would not have tripped
        # it (`printed()` spells a literal out; `unprinted()`, the path this
        # exclusion protects, is never reached for one).
        self.assertIsNone(forms.stdin_program(self.argv("bash <(curl https://example.test/i.sh)")))
        # The same exclusion on the COMMAND WORD half (commit 4 touched
        # both): a `<(...)` there is `_value`-shaped too, but it is a FILE
        # path, not a name any table carries -- unaffected, None, not a
        # spurious SHELL or FOREIGN guess.
        self.assertIsNone(forms.stdin_program(self.argv("<(echo sh)")))

    def test_a_dollar_command_word_with_stdin_on_it_is_a_value_program(self):
        # #2473: `CMD=sh; $CMD <<'EOF'` runs the heredoc in bash 3.2.57,
        # 5.2.21 and dash, but a value-form COMMAND word gives the walk no
        # NAME to key its tables on -- it may hold a shell, `python3` or
        # `true`. It answers VALUE_PROGRAM, not SHELL -- under which
        # `$PYTHON -` was never reported, even beside a fetch (review I-2) --
        # nor FOREIGN, whose body goes unread: `Idle` under #2499, so the
        # issue's own `curl ... | sh` body read CLEAN beside no other fetch.
        for script in ("$CMD", '"$CMD"', "${CMD}", "$(echo sh)", "$PYTHON -"):
            with self.subTest(script=script):
                self.assertEqual(workflow_programs.VALUE_PROGRAM,
                                 forms.stdin_program(self.argv(script)))
        # A literal name keeps its table's answer, and a literal path is not a
        # value form: unaffected, as they always were.
        self.assertEqual(workflow_programs.FOREIGN_PROGRAM,
                         forms.stdin_program(self.argv("python3 -")))
        self.assertEqual(forms.SHELL_PROGRAM, forms.stdin_program(self.argv("sh")))
        self.assertIsNone(forms.stdin_program(self.argv("$HOME/bin/tool")))
        # Its body is read as shell, as a shell's quoted body is; an
        # expanding body's substitutions become values, and FOREIGN is unread.

        def handed(script):
            stage = shell_reader.statements(script)[0].stages[-1]
            return forms.stdin_scripts(shell_reader.command(stage.argv), stage)
        self.assertEqual(["sh tool"], handed("$CMD <<'EOF'\nsh tool\nEOF"))
        self.assertEqual(["sh tool"], handed("$CMD <<EOF\nsh tool\nEOF"))
        self.assertEqual(['echo "$VALUE"'], handed(
            '$CMD <<EOF\necho "$(curl -fsSL https://example.test/i.sh)"\nEOF'))
        self.assertEqual([], handed("python3 - <<'EOF'\nsh tool\nEOF"))

    def test_a_stdin_scripts_reader_is_the_literal_shell_an_empty_tuple_or_none(self):
        # A stdin script's `reader` (`workflow_programs.Stdin`) is of three kinds, tabled below;
        # `stdin_program`'s answer is unchanged for each.
        def read(step):
            stage = shell_reader.statements(step + " <<'EOF'\necho hi\nEOF")[0].stages[-1]
            argv = shell_reader.command(stage.argv)
            return argv, forms.stdin_program(argv), forms.stdin_scripts(argv, stage)[0].reader

        # The argv of a literal shell at the step's own level, whatever its options, a `-c` string
        # among them that names no shell reading stdin too.
        for step in ("bash -s", "bash -e -s", "sudo bash -s", "bash -n -s", "bash -s -c 'echo hi'"):
            with self.subTest(step=step):
                argv, program, reader = read(step)
                self.assertIs(argv, reader)
                self.assertEqual(forms.SHELL_PROGRAM, program)
        # `()` behind a `-c` string naming a stdin shell, where the holder's own options read stdin.
        for step in ("bash -s -c 'sh'", "bash -e -s -c 'sh'", "sh -s -c 'bash -s'"):
            with self.subTest(step=step):
                self.assertEqual((forms.SHELL_PROGRAM, ()), read(step)[1:])
        # None where no shell is sure to read it: behind an `eval` or `-c` string that names the
        # shell reading it, past a word that may vanish, under a `$` command word.
        for step in ("eval 'bash -s'", "bash -c 'sh'", "bash -ec 'sh -e'", "bash $X -s -c 'sh'",
                     "$CMD -s -c 'sh'", "sh $X", "$CMD", "eval '! bash -s'", "eval 'bash -s &'",
                     "eval 'bash -s < /dev/null'", "eval 'bash -n -s'", "bash -nc 'sh'",
                     "eval 'bash -s' $(printf %s -n)", "eval " * 65 + "bash -s",
                     "sudo bash -c 'sh'"):
            with self.subTest(step=step):
                program = (workflow_programs.VALUE_PROGRAM if step.startswith("$CMD")
                           else forms.SHELL_PROGRAM)
                self.assertEqual((program, None), read(step)[1:])
        # A shell read behind a string is no reader at any depth, whatever its
        # options: `_stdin` names one only at the step's own level.
        for depth in (1, 64):
            with self.subTest(depth=depth):
                self.assertEqual((forms.SHELL_PROGRAM, None),
                                 workflow_programs._stdin(["bash", "-e", "-s"], depth))

    def test_flattened_marks_each_statement_no_shell_is_sure_to_read(self):
        # `workflow_forms.Unsure`: a statement of a body no shell is sure to read, or of a body
        # inside one, whatever reads that; a body the holder's own options read stays `Inlined`.
        def kinds(text):
            return [(type(statement), " ".join(shell_reader.command(statement.stages[0].argv)))
                    for statement in forms.flattened(shell_reader.statements(text))]
        unsure, inlined, top = forms.Unsure, forms.Inlined, shell_reader.Statement
        # A literal `bash -s` inside a `$CMD` body: its own body is `Unsure` too, and so is that of
        # a holder whose own options read stdin.
        self.assertEqual(
            [(unsure, "echo inner"), (unsure, "bash -s"), (unsure, "echo outer"), (top, "$CMD")],
            kinds("$CMD <<'EOF'\nbash -s <<'IN'\necho inner\nIN\necho outer\nEOF"))
        self.assertEqual(
            [(unsure, "sh"), (unsure, "echo inner"), (unsure, "bash -s -c sh"), (top, "$CMD")],
            kinds("$CMD <<'EOF'\nbash -s -c 'sh' <<'IN'\necho inner\nIN\nEOF"))
        # A `$CMD` body inside a literal one is `Unsure`; the literal body's own statements are not.
        self.assertEqual(
            [(unsure, "echo inner"), (inlined, "$CMD"), (inlined, "echo outer"), (top, "bash -s")],
            kinds("bash -s <<'EOF'\n$CMD <<'IN'\necho inner\nIN\necho outer\nEOF"))
        # `bash -s -c 'sh'`: the body is the step's own, `Inlined`, but no check in it counts.
        found = forms.flattened(shell_reader.statements("bash -s -c 'sh' <<'EOF'\necho hi\nEOF"))
        self.assertEqual([inlined, inlined, top], [type(statement) for statement in found])
        self.assertEqual((forms._UNGATED % "bash",) * 2, found[1].credit)


class TestADynamicCommandWordHandedDashC(unittest.TestCase):
    """#2337: any other dynamic command word handed a `-c` cluster may be a
    shell (`CMD=sh; $CMD -c P` runs `P`), so the program after the options
    is a candidate, read as #2344's are; with no `-c` it is the value gap
    `$CMD --flag` has."""

    @staticmethod
    def argv(script):
        stmts = shell_reader.statements(script)
        assert len(stmts) == 1 and len(stmts[0].stages) == 1, stmts
        return shell_reader.command(stmts[0].stages[0].argv)

    def test_the_program_after_dash_c_is_a_candidate(self):
        for script, value in (("$CMD -c P", "$CMD"), ('"$PYTHON" -c P', "$PYTHON"),
                              ("$(which sh) -ec -- P", "$(...)"), ("${X:-true} -c -x P", "${X:-true}")):
            with self.subTest(script=script):
                found, words = forms.candidates(self.argv(script))
                self.assertEqual((value, ["P"]), (shell_reader.readable(found), words))
        # A dynamic program is a candidate too (review N2 of #2331).
        self.assertEqual(["$P"], forms.candidates(self.argv('$CMD -c "$P"'))[1])

    def test_none_without_a_dash_c(self):
        for script in ("$CMD --flag", "$CMD -x P", "$CMD", "$HOME/bin/tool -c P"):
            with self.subTest(script=script):
                self.assertEqual([], forms.candidates(self.argv(script))[1])


class TestAProgramAPrinterPipesIntoAShell(unittest.TestCase):
    """#2333: a shell that reads its program on standard input from an `echo`
    or `printf` in front of it runs the text they print -- bash 3.2.57 and
    5.2.21 run `sh tool` in `echo 'sh tool' | sh` -- so where their words spell
    that text out it is the shell's program, read as a quoted heredoc's is."""

    @staticmethod
    def handed(script, piped=True):
        stmts = shell_reader.statements(script)
        assert len(stmts) == 1, stmts
        stages = stmts[0].stages
        before = stages[:-1] if piped else None
        return forms.stdin_scripts(shell_reader.command(stages[-1].argv), stages[-1], before)

    def test_the_text_a_printer_spells_out_is_the_program(self):
        for script, text in (("echo 'sh tool' | sh", "sh tool\n"), ("echo sh tool | bash -s", "sh tool\n"),
                             ("echo -n 'sh tool' | sh -", "sh tool"),
                             ("printf '%s\\n' 'sh tool' | bash", "sh tool\n"),
                             ("printf %s 'sh tool' | sh", "sh tool"), ("printf %b 'sh tool' | sh", "sh tool"),
                             ("printf 'sh tool\\nsh x\\n' | sh", "sh tool\nsh x\n"),
                             ("printf -- 'sh tool' a | sudo sh", "sh tool"),
                             ('echo "x=\\$(curl -fsSL u)" | sh', "x=$(curl -fsSL u)\n"),
                             ("echo 'sh tool' | $CMD", "sh tool\n")):     # #2473
            with self.subTest(script=script):
                self.assertEqual([text], self.handed(script))

    def test_text_it_does_not_spell_out_is_no_program_here(self):
        # A `$`, an escape outside `_decoded`'s table (#2476 -- `echo -e` forces bash's decoder on
        # and `printf` always decodes, so a plain `\t` would decode cleanly there; `\x` is outside
        # that table and is what stays unspelled instead), a format other than `%s`, `%s\n` and `%b`
        # with one word, or an option: `unprinted` has these.
        for script in ('echo "$X" | sh', 'echo "sh $X" | sh', "echo -e 'a\\xb' | sh",
                       "printf '%s %s\\n' sh tool | sh", "printf '%s\\n' sh tool | sh",
                       'printf "$F" | sh', "printf -v x %s y | sh", "printf '%d\\n' 1 | sh",
                       "printf 'a\\xb' | sh", "echo `echo sh tool` | sh"):
            with self.subTest(script=script):
                self.assertEqual([], self.handed(script))
                self.assertTrue(forms.unprinted(*self.parts(script)))
        # Behind a `$` command word (#2473) `unprinted` has no printer either:
        # it weighs a shell's only, so `echo "$X" | $CMD` is unread -- the gap
        # the guard's list files under #2331.
        self.assertEqual([], self.handed('echo "$X" | $CMD'))
        self.assertEqual([], forms.unprinted(*self.parts('echo "$X" | $CMD')))

    def test_no_program_where_the_shell_reads_none_from_the_printer(self):
        # A `-c` string or a script file makes stdin data; a printer writing
        # elsewhere pipes nothing; only a printer is read, and only when the
        # stages in front of the shell are given (`flattened`, `_walk`).
        for script in ("echo 'sh tool' | sh -c 'echo hi'", "echo y | sh install.sh",
                       "echo 'sh tool' > f | sh", "cat notes.txt | sh", "echo 'sh tool' | python3"):
            with self.subTest(script=script):
                self.assertEqual([], self.handed(script))
                self.assertEqual([], forms.unprinted(*self.parts(script)))
        self.assertEqual([], self.handed("echo 'sh tool' | sh", piped=False))
        self.assertEqual(["echo hi"], self.handed("echo 'sh tool' | sh <<'EOF'\necho hi\nEOF"))

    @staticmethod
    def parts(script):
        stages = shell_reader.statements(script)[0].stages
        return shell_reader.command(stages[-1].argv), stages[-1], stages[:-1]


class TestThePrinterRulesLiveInWorkflowPrinters(unittest.TestCase):
    """#2331: `printed`, `_piped` and `_PRINTERS` moved out of `workflow_programs` into
    `workflow_printers`, byte for byte; `workflow_programs` re-exports them so `stdin_scripts`,
    `unprinted` and every caller read the one definition, and no stale copy can linger."""

    def test_the_seam_is_one_object(self):
        for name in ("printed", "_piped", "_PRINTERS", "handed", "producer", "unspelled"):
            with self.subTest(name=name):
                self.assertIs(getattr(workflow_programs, name), getattr(workflow_printers, name))
        self.assertIs(forms.unprinted, workflow_programs.unprinted)
        self.assertIs(forms.stdin_scripts, workflow_programs.stdin_scripts)

    def test_the_moved_text_reads_as_before(self):
        # The printer's text, the pipe and the table answer as they did in `workflow_programs`.
        self.assertEqual("sh tool\n", workflow_printers.printed(["echo", "sh", "tool"]))
        # #2476 FLIPS this: bash's `echo` (the default, no `shell` given) prints a backslash it does
        # not decode literally, rather than leaving the whole text unspelled -- `printed` now hands
        # that literal text on, for the next reader to read as `statements("sh\\ttool")` does.
        self.assertEqual("sh\\ttool\n", workflow_printers.printed(["echo", "sh\\ttool"]))
        self.assertEqual(("echo", "printf"), workflow_printers._PRINTERS)
        stages = shell_reader.statements("echo 'sh tool' | sh")[0].stages
        self.assertTrue(workflow_printers._piped(stages[1], stages[0]))
        self.assertFalse(workflow_printers._piped(stages[0], None))
