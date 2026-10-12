"""A downloaded file whose bytes become a shell program is a use of that file (#2428)."""
import unittest

import workflow_guard as guard


URL = "https://example.test/tool"
GET = "curl -fsSLo tool %s\n" % URL
CHECK = "echo '%s  tool' | sha256sum -c -\n" % ("a" * 64)


def defects(script):
    return [why for _step, why in guard.job_defects([("step", script)])]


class TestDownloadedFileReaderHandoffs(unittest.TestCase):
    def assert_bound(self, use, kind="command substitution"):
        found = defects(GET + use + "\n")
        self.assertEqual(1, len(found), found)
        self.assertIn("running it", found[0])
        self.assertIn("through a %s" % kind, found[0])

    def test_the_filed_command_substitution_forms_bind_the_reader_to_the_download(self):
        for use in (
                'eval "$(cat tool)"',
                'sh -c "$(cat tool)"',
                'echo "$(cat tool)" | sh'):
            with self.subTest(use=use):
                self.assert_bound(use)

    def test_each_filed_reader_spelling_binds_its_input_file(self):
        for use in (
                'eval "$(cat < tool)"',
                'eval "$(< tool)"',
                'eval "$(head -n 20 tool)"',
                'eval "$(tail -n +1 tool)"',
                "eval \"$(sed -n '1,20p' tool)\"",
                'eval "$(tr A-Z a-z < tool)"'):
            with self.subTest(use=use):
                self.assert_bound(use)

    def test_a_process_substitution_file_operand_binds_the_reader(self):
        for use in ('bash <(cat tool)', 'source <(head -n 20 tool)'):
            with self.subTest(use=use):
                self.assert_bound(use, "process substitution")

    def test_an_output_process_substitution_does_not_hand_the_reader_to_the_shell(self):
        self.assertEqual([], defects(GET + 'bash >(cat tool)\n'))

    def test_the_reader_path_uses_its_command_substitutions_working_directory(self):
        get = "curl -fsSLo a/tool %s\n" % URL
        found = defects(get + 'eval "$(cd a; cat tool)"\n')
        self.assertEqual(1, len(found), found)
        self.assertIn("running it through a command substitution", found[0])

    def test_a_check_of_that_file_before_the_handoff_clears_it(self):
        for use in (
                'eval "$(cat tool)"',
                'sh -c "$(head -n 20 tool)"',
                'echo "$(sed -n 1p tool)" | sh',
                'bash <(cat tool)'):
            with self.subTest(use=use):
                self.assertEqual([], defects(GET + CHECK + use + "\n"))

    def test_a_check_after_the_handoff_is_too_late(self):
        found = defects(GET + 'eval "$(cat tool)"\n' + CHECK)
        self.assertEqual(1, len(found), found)
        self.assertIn("only AFTER running it through a command substitution", found[0])

    def test_an_unrelated_file_and_a_job_with_no_download_are_clean(self):
        for script in (
                GET + 'eval "$(cat other.sh)"\n',
                GET + 'eval "$(head -n 20 other.sh)"\n',
                GET + 'eval "$(tail -n +1 other.sh)"\n',
                GET + "eval \"$(sed -n '1,20p' other.sh)\"\n",
                GET + 'eval "$(tr A-Z a-z < other.sh)"\n',
                GET + 'bash <(cat other.sh)\n',
                'eval "$(cat tool)"\n',
                'bash <(cat tool)\n'):
            with self.subTest(script=script):
                self.assertEqual([], defects(script))

    def test_reader_arguments_and_discarded_output_keep_the_generic_fail_safe(self):
        for use in (
                'eval "$(sed tool)"',
                'eval "$(tr tool A-Z)"',
                'eval "$(cat tool >/dev/null; echo true)"'):
            with self.subTest(use=use):
                found = defects(GET + use + "\n")
                self.assertEqual(1, len(found), found)
                self.assertTrue(found[0].startswith("runs `eval` on `$(...)`"), found)
                self.assertNotIn("running it through", found[0])

    def test_option_values_and_sed_or_tr_program_arguments_are_not_input_files(self):
        for use in (
                'eval "$(head -n tool other.sh)"',
                'eval "$(tail -n tool other.sh)"',
                'eval "$(sed tool other.sh)"',
                'eval "$(sed -e tool other.sh)"',
                'eval "$(tr tool A-Z < other.sh)"',
                'eval "$(cat < tool other.sh)"',
                'eval "$(head -n 1 other.sh < tool)"',
                "eval \"$(sed -n '1p' other.sh < tool)\""):
            with self.subTest(use=use):
                self.assertEqual([], defects(GET + use + "\n"))

    def test_unbounded_reader_forms_keep_the_generic_fail_safe(self):
        for use in ('eval "$(cat 3<tool)"', 'eval "$(cat <<< tool)"',
                    'eval "$(cat $F)"', 'eval "$(sed -i tool)"'):
            with self.subTest(use=use):
                found = defects(GET + use + "\n")
                self.assertTrue(any(why.startswith("runs `eval` on `$(...)`")
                                    for why in found), found)
                self.assertFalse(any("running it through" in why for why in found), found)

    def test_a_reader_path_resolved_from_a_static_value_binds_the_download(self):
        # The as-written dynamic-path catch-all remains beside the resolved, source-bound reading.
        found = defects(GET + 'F=tool\neval "$(cat $F)"\n')
        bound = [why for why in found if "running it through a command substitution" in why]
        self.assertEqual(1, len(bound), found)

    def test_a_generated_reader_file_keeps_the_generic_fail_safe(self):
        script = GET + 'echo tool | tee f >/dev/null\neval "$(cat f)"\n'
        found = defects(script)
        self.assertTrue(any(why.startswith("runs `eval` on `$(...)`")
                            for why in found), found)

    def test_a_reader_among_other_output_still_hands_the_download_on(self):
        for use in (
                'eval "$(printf true; cat tool)"',
                'eval "$(cat tool; printf true)"',
                'eval "$(cat other.sh tool)"',
                'sh -c "$(cat other.sh) $(cat tool)"'):
            with self.subTest(use=use):
                self.assert_bound(use)


if __name__ == "__main__":
    unittest.main()
