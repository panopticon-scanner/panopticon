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
            "http --download --quiet " + URL + " | sh",
            "gh release download v1 -R owner/repo -O - | bash",
        )
        for script in cases:
            with self.subTest(script=script):
                fetch = self.one(script)
                self.assertIsNone(fetch.dest)
                self.assertIn(fetch.piped_to[0], ("sh", "bash"))
                self.assertIn("straight", guard.fetch_exec_defect(script))

    def test_quiet_httpie_and_literal_dash_outputs_do_not_invent_a_stream(self):
        self.assertEqual([], guard.fetch_exec_defects("http --quiet " + URL + " | sh"))
        self.assertEqual([], guard.fetch_exec_defects(
            "http --quiet " + URL + " | tee tool\nsh tool",
        ))
        for tool in ("aria2c", "axel"):
            script = "%s -o - %s | sh" % (tool, URL)
            with self.subTest(tool=tool):
                fetched = self.one(script)
                self.assertEqual("-", fetched.dest)
                self.assertEqual([], guard.fetch_exec_defects(script))
                self.assertIsNotNone(guard.fetch_exec_defect(
                    "%s -o - %s\nsh ./-" % (tool, URL),
                ))

    def test_adapter_stdout_follows_descriptor_aliases_and_an_adjacent_tee(self):
        cases = (
            "aria2c -o //dev/stdout " + URL + " | sh",
            "axel -o /dev/fd/3 " + URL + " 3>&1 | sh",
            "http --body " + URL + " | tee tool\nsh tool",
            "gh release download v1 -R owner/repo -O - | tee tool\nsh tool",
        )
        for script in cases:
            with self.subTest(script=script):
                self.assertIsNotNone(guard.fetch_exec_defect(script))

    def test_shell_redirects_of_an_adapter_stream_keep_their_own_path_semantics(self):
        self.assertIsNotNone(guard.fetch_exec_defect(
            "http --body %s > -\nsh ./-" % URL,
        ))
        for redirect in ("/dev/null", "/dev/stderr"):
            script = "http --body %s > %s | tee tool\nsh tool" % (URL, redirect)
            with self.subTest(redirect=redirect):
                self.assertEqual([], guard.fetch_exec_defects(script))

    def test_option_values_are_not_mistaken_for_the_download_operand(self):
        cases = (
            "aria2c --load-cookies https://example.test/cookies -o tool " + URL,
            "axel --header https://example.test/header -o tool " + URL,
            "fetch -N https://example.test/netrc -o tool " + URL,
            "fetch -i https://example.test/stamp -o tool " + URL,
            "http --proxy https:https://example.test/proxy -o tool " + URL,
            "http --raw https://example.test/request-body -I -o tool " + URL,
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

    def test_the_last_output_alias_on_the_command_line_wins(self):
        cases = (
            ("aria2c --out first -o second " + URL, "second"),
            ("axel -o first --output second " + URL, "second"),
            ("http --output first -o second " + URL, "second"),
            ("gh release download v1 -O first --output second", "second"),
            ("pip download --no-deps --dest first -d second " + URL + ".whl",
             "second/tool.whl"),
        )
        for script, dest in cases:
            with self.subTest(script=script):
                self.assertEqual(dest, self.one(script).dest)

    def test_directory_outputs_append_the_remote_basename(self):
        cases = (
            ("axel --output=out/ " + URL, "out/tool"),
            ("fetch -o . " + URL, "tool"),
            ("fetch --quiet --user-agent agent --output=out/ " + URL, "out/tool"),
        )
        for script, dest in cases:
            with self.subTest(script=script):
                self.assertEqual(dest, self.one(script).dest)

    def test_bounded_root_options_still_reach_the_download_subcommand(self):
        cases = (
            ("gh -R owner/repo release download v1 -O tool", "tool"),
            ("gh release --repo owner/repo download v1 -O tool", "tool"),
            ("git --no-pager -c protocol.version=2 clone "
             "https://example.test/repo.git source", "source"),
            ("pip --disable-pip-version-check --timeout 5 download --no-deps -d out "
             + URL + ".whl", "out/tool.whl"),
        )
        for script, dest in cases:
            with self.subTest(script=script):
                self.assertEqual(dest, self.one(script).dest)

    def test_unknown_root_options_before_a_download_subcommand_fail_closed(self):
        for script in (
                "gh --mystery release download v1 -O tool",
                "git --mystery clone https://example.test/repo.git source",
                "pip --mystery download " + URL + ".whl",
        ):
            with self.subTest(script=script):
                self.assertIn("unresolved transfers", guard.fetch_exec_defect(script))

    def test_an_inferred_clone_directory_uses_gits_humanish_name(self):
        for repository in (
                "https://example.test/owner/repo.git",
                "git@example.test:repo.git",
                "git@example.test:owner/repo.git",
        ):
            with self.subTest(repository=repository):
                self.assertEqual("repo", self.one("git clone " + repository).dest)

    def test_a_deferred_checkout_still_carries_the_network_clone(self):
        clone = "git clone --no-checkout https://example.test/repo.git source"
        script = clone + "\ngit -C source checkout HEAD -- install.sh\nsh source/install.sh"
        self.assertIsNotNone(guard.fetch_exec_defect(script))

    def test_explicit_network_enablers_make_a_local_clone_fail_closed(self):
        for script in (
                "git clone --bundle-uri=https://example.test/repo.bundle ./local source",
                "git clone --recurse-submodules ./local source",
                "git -c url.https://example.test/.insteadOf=local clone local source",
                "git --config-env=url.https://example.test/.insteadOf=REWRITE clone ./local source",
        ):
            with self.subTest(script=script):
                self.assertIn("unresolved transfers", guard.fetch_exec_defect(script))

    def test_only_the_named_subcommands_and_network_clone_are_fetches(self):
        controls = (
            "aria2c --version",
            "axel --help",
            "fetch -s " + URL,
            "http --offline " + URL + " | sh",
            "http --manual",
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

    def test_unknown_options_fail_closed_in_each_adapter(self):
        cases = (
            "aria2c --mystery " + URL,
            "axel --mystery " + URL,
            "fetch --mystery " + URL,
            "http --mystery " + URL,
            "gh release download --mystery",
            "git clone --mystery https://example.test/repo.git source",
            "pip download --mystery " + URL + ".whl",
        )
        for script in cases:
            with self.subTest(script=script):
                found = guard.fetch_exec_defects(script)
                self.assertEqual(1, len(found), found)
                self.assertIn("unresolved transfers", found[0])

    def test_axel_mirror_lists_fail_closed_instead_of_naming_one_source(self):
        script = "axel %s https://example.test/other" % URL
        self.assertIn("unresolved transfers", guard.fetch_exec_defect(script))

    def test_a_server_chosen_httpie_download_name_is_unresolved_unless_shell_captured(self):
        self.assertIn("without a bindable output filename", guard.fetch_exec_defect(
            "http --download " + URL,
        ))
        redirected = "http --download %s > tool\nsh tool" % URL
        self.assertEqual("tool", self.one(redirected).dest)
        self.assertIsNotNone(guard.fetch_exec_defect(redirected))
        for discard in ("/dev/null", "/dev/stderr"):
            with self.subTest(discard=discard):
                self.assertEqual([], guard.fetch_exec_defects(
                    "http --download %s > %s" % (URL, discard),
                ))
        self.assertEqual([], guard.fetch_exec_defects(
            "http --download %s | wc -c" % URL,
        ))

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
        for control in ("echo hello", "printf hi", "git status", "ls scripts", "touch file"):
            with self.subTest(control=control):
                self.assertIsNone(guard.fetch_exec_defect(clone + "\n" + control))

    def test_a_file_checksum_cannot_bless_a_cloned_tree(self):
        clone = "git clone https://example.test/repo.git source"
        for checked in ("source", "source/other.sh", "source/install.sh"):
            with self.subTest(checked=checked):
                script = (clone + "\necho '%s  %s' | sha256sum -c -\n"
                          "sh source/install.sh" % (HEX, checked))
                defect = guard.fetch_exec_defect(script)
                self.assertIsNotNone(defect)
                self.assertIn("pinned source archive", defect)

    def test_conditional_capital_x_does_not_make_tree_files_executable(self):
        clone = "git clone https://example.test/repo.git source"
        self.assertIsNone(guard.fetch_exec_defect(clone + "\nchmod -R a+rX source"))
        for chmod in ("chmod -R a+rx source", "chmod 755 source/install.sh"):
            with self.subTest(chmod=chmod):
                self.assertIsNotNone(guard.fetch_exec_defect(clone + "\n" + chmod))

    def test_a_copied_or_moved_clone_remains_a_fetched_tree(self):
        for command, dest in (("cp -R source copy", "copy"), ("mv source moved", "moved")):
            script = ("git clone https://example.test/repo.git source\n%s\n"
                      "sh %s/install.sh" % (command, dest))
            with self.subTest(command=command):
                self.assertIsNotNone(guard.fetch_exec_defect(script))

    def test_a_copied_clone_descendant_keeps_its_fetched_provenance(self):
        clone = "git clone https://example.test/repo.git source"
        for copy, use in (
                ("cp source/install.sh tool", "sh tool"),
                ("mv source/scripts moved", "sh moved/install.sh"),
                ("cat source/install.sh > tool", "sh tool"),
        ):
            with self.subTest(copy=copy):
                self.assertIsNotNone(guard.fetch_exec_defect("\n".join((clone, copy, use))))

    def test_pip_needs_no_deps_to_bind_one_direct_archive(self):
        script = "pip download -d out %s.whl\nsh out/tool.whl" % URL
        self.assertIn("unresolved transfers", guard.fetch_exec_defect(script))
        unnamed = "pip download --no-deps -d out %s\nsh out/tool" % URL
        self.assertIn("unresolved transfers", guard.fetch_exec_defect(unnamed))
        bounded = "pip download --no-deps -d out %s.whl\nsh out/tool.whl" % URL
        self.assertNotIn("unresolved transfers", guard.fetch_exec_defect(bounded))

    def test_fetcher_vocabulary_stays_mirrored_by_the_shell_reader(self):
        expected = {
            "curl", "wget", "aria2c", "axel", "fetch", "http", "https",
            "gh", "git", "pip", "pip3",
        }
        self.assertEqual(expected, set(workflow_fetch.FETCHERS))
        self.assertEqual(expected, set(shell_reader._FETCHERS))

    def test_an_https_url_is_not_itself_an_httpie_command_word(self):
        self.assertIsNone(workflow_annotate._FETCH_WORD.search(URL))
        self.assertIsNone(workflow_annotate._FETCH_WORD.search("http+unix://socket/path"))
        self.assertIsNone(workflow_annotate._FETCH_WORD.search("git+https://example.test/repo"))
        self.assertIsNotNone(workflow_annotate._FETCH_WORD.search("https " + URL))
        # #2829's URL boundary may not narrow the legacy curl/wget arm.
        self.assertIsNotNone(workflow_annotate._FETCH_WORD.search("curl:payload"))
        self.assertIsNotNone(workflow_annotate._FETCH_WORD.search("wget+payload"))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
