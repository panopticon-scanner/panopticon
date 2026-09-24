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
        for script in ('command -v curl', 'sudo --list curl', 'env -S "curl URL"'):
            self.assertEqual([], guard.fetches(script), script)


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
        self.assertEqual(11, len(shell_reader.Stage._fields))
        legacy = shell_reader.Stage([], [], [], None, [], [])
        self.assertEqual((0, 0, True, True, ("0",)), tuple(legacy)[6:])
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
