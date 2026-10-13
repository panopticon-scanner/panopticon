"""#2829: named download programs use bounded, tool-specific adapters."""
import unittest

import shell_reader
import workflow_annotate
import workflow_fetch
import workflow_guard as guard


URL = "https://example.test/tool"
HEX = "a" * 64


class TestNamedDownloadAdapters(unittest.TestCase):
    def one(self, script):
        found = guard.fetches(script)
        self.assertEqual(1, len(found), (script, found))
        return found[0]

    def test_each_adapter_binds_the_file_that_the_tool_writes(self):
        cases = (
            ("aria2c --dir out --out tool " + URL, "out/tool"),
            ("axel --output=tool " + URL, "tool"),
            ("fetch -o tool " + URL, "tool"),
            ("http --download --output tool " + URL, "tool"),
            ("https -do tool " + URL, "tool"),
            ("gh release download v1.2.3 --repo owner/repo --output tool", "tool"),
            ("git clone --depth 1 https://example.test/repo.git source", "source"),
            ("pip3 download --no-deps --dest out " + URL + ".whl", "out/tool.whl"),
        )
        for fetch, dest in cases:
            with self.subTest(fetch=fetch):
                parsed = self.one(fetch)
                self.assertEqual(dest, parsed.dest)
                use = "sh %s/install.sh" % dest if fetch.startswith("git ") else "sh " + dest
                self.assertIsNotNone(guard.fetch_exec_defect(fetch + "\n" + use))

    def test_file_checks_clear_the_exact_file_adapters(self):
        cases = (
            ("aria2c -o tool " + URL, "tool"),
            ("axel -o tool " + URL, "tool"),
            ("fetch -o tool " + URL, "tool"),
            ("http -do tool " + URL, "tool"),
            ("gh release download -R owner/repo -p tool -D out", "out/tool"),
            ("pip download --no-deps -d out " + URL + ".whl", "out/tool.whl"),
        )
        for fetch, dest in cases:
            with self.subTest(fetch=fetch):
                script = "%s\necho '%s  %s' | sha256sum -c -\nsh %s" % (
                    fetch, HEX, dest, dest,
                )
                self.assertEqual([], guard.fetch_exec_defects(script))
                self.assertTrue(guard.fetch_exec_defects(script.replace(
                    "  %s'" % dest, "  other'",
                )))

    def test_stream_capable_adapters_bind_a_shell_consumer(self):
        cases = (
            "fetch -o - " + URL + " | sh",
            "http --body " + URL + " | bash",
            "https " + URL + " | sh",
            "gh release download v1 -R owner/repo -O - | bash",
        )
        for script in cases:
            with self.subTest(script=script):
                fetch = self.one(script)
                self.assertIsNone(fetch.dest)
                self.assertIn(fetch.piped_to[0], ("sh", "bash"))
                self.assertIn("straight", guard.fetch_exec_defect(script))

    def test_option_values_are_not_mistaken_for_the_download_operand(self):
        cases = (
            "aria2c --load-cookies https://example.test/cookies -o tool " + URL,
            "axel --header https://example.test/header -o tool " + URL,
            "fetch -N https://example.test/netrc -o tool " + URL,
            "http --proxy https:https://example.test/proxy -o tool " + URL,
            "git clone --reference https://example.test/reference "
            "https://example.test/repo.git source",
            "pip download --index-url https://example.test/simple --no-deps -d out "
            + URL + ".whl",
        )
        for script in cases:
            with self.subTest(script=script):
                self.assertEqual(URL if not script.endswith(".git source") and "pip " not in script
                                 else (URL + ".whl" if "pip " in script
                                       else "https://example.test/repo.git"),
                                 self.one(script).url)

    def test_only_the_named_subcommands_and_network_clone_are_fetches(self):
        controls = (
            "aria2c --version",
            "axel --help",
            "fetch -s " + URL,
            "http --offline " + URL + " | sh",
            "gh release view v1",
            "gh release download --help",
            "git status",
            "git clone ./local source && sh source/install.sh",
            "git clone file:///tmp/local source && sh source/install.sh",
            "pip list",
            "pip3 install package",
            "pip download --help",
        )
        for script in controls:
            with self.subTest(script=script):
                self.assertEqual([], guard.fetches(script))
                self.assertEqual([], guard.fetch_exec_defects(script))

    def test_adapters_are_read_inside_a_fed_shell_body(self):
        for fetch in (
                "aria2c -o tool " + URL,
                "gh release download -R owner/repo -O tool",
                "git clone https://example.test/repo.git source",
        ):
            use = "sh source/install.sh" if fetch.startswith("git ") else "sh tool"
            script = "bash <<'EOF'\n%s\n%s\nEOF" % (fetch, use)
            with self.subTest(fetch=fetch):
                self.assertIsNotNone(guard.fetch_exec_defect(script))

    def test_a_clone_into_dot_covers_only_relative_children(self):
        clone = "git clone https://example.test/repo.git ."
        self.assertIsNotNone(guard.fetch_exec_defect(clone + "\nsh scripts/install.sh"))
        self.assertIsNone(guard.fetch_exec_defect(clone + "\n/bin/sh /tmp/install.sh"))

    def test_a_checksum_of_one_clone_child_does_not_bless_the_tree(self):
        clone = "git clone https://example.test/repo.git source"
        script = (clone + "\necho '%s  source/other.sh' | sha256sum -c -\n"
                  "sh source/install.sh" % HEX)
        self.assertIsNotNone(guard.fetch_exec_defect(script))

    def test_fetcher_vocabulary_stays_mirrored_by_the_shell_reader(self):
        expected = {
            "curl", "wget", "aria2c", "axel", "fetch", "http", "https",
            "gh", "git", "pip", "pip3",
        }
        self.assertEqual(expected, set(workflow_fetch.FETCHERS))
        self.assertEqual(expected, set(shell_reader._FETCHERS))

    def test_an_https_url_is_not_itself_an_httpie_command_word(self):
        self.assertIsNone(workflow_annotate._FETCH_WORD.search(URL))
        self.assertIsNotNone(workflow_annotate._FETCH_WORD.search("https " + URL))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
