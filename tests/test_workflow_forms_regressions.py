"""P35: bounded workflow execution forms, with verified and non-use controls."""
import inspect
import unittest

import shell_reader
import workflow_fetch as fetches
import workflow_forms as forms
import workflow_guard as guard

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

    def test_the_first_operand_is_the_program_as_it_was(self):
        self.assertEqual(["P"], self.program("sh -c P x"))
        self.assertEqual(["P"], self.program("bash -euc P"))
        # A dynamic program reads as `sh -c "$P"` does; after `--` a word
        # that begins with `-` is the program; with none, there is none.
        self.assertEqual(["$P"], self.program('sh -c -x "$P"'))
        self.assertEqual(["-P"], self.program("sh -c -- -P"))
        self.assertEqual([], self.program("sh -c -x"))
        self.assertEqual([], self.program("bash -c --norc P"))


class TestAValueWhereAShellReadsItsOptions(unittest.TestCase):
    """#2344: a value bash expands where a shell reads its options may be
    `-c` -- `X=-c; sh $X P`, `sh $(echo -c) P`, `xargs -I{} sh {} P` run `P`
    under bash 3.2.57 and 5.2.21 -- so each word after it may be the
    program. The guard does not follow the value; `candidates` hands on every
    word after it, a dynamic one too, for `unread_program` (review N2 of #2331)."""

    @staticmethod
    def argv(script):
        stmts = shell_reader.statements(script)
        assert len(stmts) == 1, stmts
        return shell_reader.command(stmts[0].stages[-1].argv)

    def test_each_word_after_the_value_is_a_candidate(self):
        for script, value in (("sh $X P", "$X"), ('sh "${X:--c}" P', "${X:--c}"),
                              ("sh $(echo -c) P", "$(...)"), ("bash -e $X -o pipefail P", "$X"),
                              ("echo -c | xargs -I{} sh {} P", "{}"), ("sh ${X}c P", "${X}c")):
            with self.subTest(script=script):
                found, words = forms.candidates(self.argv(script))
                self.assertEqual((value, ["P"]), (shell_reader.readable(found), words[-1:]))
        self.assertEqual(["P", "$Y", "Q"], forms.candidates(self.argv('sh $X P "$Y" Q'))[1])

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
        # nothing is inherited: the string stays `eval`'s or `-c`'s DATA, as
        # a literal filename behind `eval` does too.
        for argv in (["eval", "echo hi"], ["bash", "-c", "cat"], ["eval", "sh x.sh"]):
            with self.subTest(argv=argv):
                self.assertIsNone(forms.stdin_program(argv))


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
        before = stages[-2] if piped and len(stages) > 1 else None
        return forms.stdin_scripts(shell_reader.command(stages[-1].argv), stages[-1], before)

    def test_the_text_a_printer_spells_out_is_the_program(self):
        for script, text in (("echo 'sh tool' | sh", "sh tool\n"), ("echo sh tool | bash -s", "sh tool\n"),
                             ("echo -n 'sh tool' | sh -", "sh tool"),
                             ("printf '%s\\n' 'sh tool' | bash", "sh tool\n"),
                             ("printf %s 'sh tool' | sh", "sh tool"), ("printf %b 'sh tool' | sh", "sh tool"),
                             ("printf 'sh tool\\nsh x\\n' | sh", "sh tool\nsh x\n"),
                             ("printf -- 'sh tool' a | sudo sh", "sh tool"),
                             ('echo "x=\\$(curl -fsSL u)" | sh', "x=$(curl -fsSL u)\n")):
            with self.subTest(script=script):
                self.assertEqual([text], self.handed(script))

    def test_text_it_does_not_spell_out_is_no_program_here(self):
        # A `$`, a backslash a printer may read as an escape (dash's `echo`
        # does), a format other than `%s`, `%s\n` and `%b` with one word, or
        # an option: `unprinted` has these.
        for script in ('echo "$X" | sh', 'echo "sh $X" | sh', "echo 'a\\tb' | sh",
                       "printf '%s %s\\n' sh tool | sh", "printf '%s\\n' sh tool | sh",
                       'printf "$F" | sh', "printf -v x %s y | sh", "printf '%d\\n' 1 | sh",
                       "printf 'a\\tb' | sh", "echo `echo sh tool` | sh"):
            with self.subTest(script=script):
                self.assertEqual([], self.handed(script))
                self.assertTrue(forms.unprinted(*self.parts(script)))

    def test_no_program_where_the_shell_reads_none_from_the_printer(self):
        # A `-c` string or a script file makes stdin data; a printer writing
        # elsewhere pipes nothing; only a printer is read, and only when the
        # stage in front of the shell is given (`flattened`, `_walk`).
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
        return shell_reader.command(stages[-1].argv), stages[-1], stages[-2]
