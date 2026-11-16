"""#3623 Ruby: Gemfile.lock PATH gems, under owner rulings R1 (literal only) and R2.

A gem under a Gemfile.lock `PATH` source is first-party when the source is inside the
review root and its one gemspec proves the exact name and version with plain string
literals, and the gem is publishable (R2: a literal `allowed_push_host` other than
rubygems.org is private-only, except for the review root itself). Everything else --
`Foo::VERSION`, a GEM or GIT copy, an outside source, a malformed lock -- stays on the
ordinary advisor path. bundler-audit and gems.locked are out. Fixtures only.
"""

import json
import os
import tempfile
import unittest
from unittest import mock

import scripts.evidence as evidence
import scripts.first_party_advisory as first_party_advisory
import scripts.ingest_tools as ingest_tools


ROOT = ("acme-app", "0.3.0")
MEMBER = ("acme-lib", "1.2.0")
REGISTRY = ("rack", "2.2.3")


def _write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)


def _gemspec(name, version, extra="", var="s"):
    return ('Gem::Specification.new do |%s|\n'
            '  %s.name = "%s"\n'
            '  %s.version = "%s"\n'
            '  %s.summary = "a gem"\n'
            '  %s.required_ruby_version = ">= 3.0"\n'
            '%s'
            'end\n' % (var, var, name, var, version, var, var, extra))


def _lock(*, member_remote="gems/acme-lib", member_options="", extra_sections="",
          extra_gem_specs=""):
    return ("PATH\n"
            "  remote: .\n"
            "  specs:\n"
            "    acme-app (0.3.0)\n"
            "      rack (~> 2.2)\n"
            "\n"
            "PATH\n"
            "  remote: %s\n"
            "%s"
            "  specs:\n"
            "    acme-lib (1.2.0)\n"
            "\n"
            "GEM\n"
            "  remote: https://rubygems.org/\n"
            "  specs:\n"
            "    nokogiri (1.16.0-x86_64-linux)\n"
            "    rack (2.2.3)\n"
            "%s"
            "\n"
            "%s"
            "PLATFORMS\n"
            "  ruby\n"
            "\n"
            "DEPENDENCIES\n"
            "  acme-app!\n"
            "  acme-lib!\n"
            "\n"
            "CHECKSUMS\n"
            "  rack (2.2.3) sha256=abc\n"
            "\n"
            "BUNDLED WITH\n"
            "   2.5.6\n"
            % (member_remote, member_options, extra_gem_specs, extra_sections))


def _tree(root, *, lock=None, member=None, top=None, lock_name="Gemfile.lock"):
    _write(os.path.join(root, "acme-app.gemspec"), top if top is not None else _gemspec(*ROOT))
    if member is not False:
        _write(os.path.join(root, "gems", "acme-lib", "acme-lib.gemspec"),
               member if member is not None else _gemspec(*MEMBER))
    _write(os.path.join(root, lock_name), lock if lock is not None else _lock())


def _finding(package, *, path="Gemfile.lock", source="tool:osv-scanner"):
    return {
        "id": "OS-001",
        "title": "%s %s: GHSA-xxxx-yyyy-zzzz" % package,
        "source": source,
        "location": {"file": path, "line_start": 1},
        "tool_evidence": {"rule_id": "GHSA-xxxx-yyyy-zzzz", "package_name": package[0],
                          "vulnerable_versions": package[1]},
    }


class _RubyCase(unittest.TestCase):
    def setUp(self):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        self.root = os.path.realpath(d.name)

    def _mark(self, package, *, cache=None, **kw):
        finding = _finding(package, **kw)
        first_party_advisory.mark([finding], self.root,
                                  cache or first_party_advisory.IngestCache())
        return finding

    def _origin(self, package, **kw):
        return self._mark(package, **kw)["tool_evidence"].get("package_origin")


class TestRubyFirstPartyAdvisory(_RubyCase):

    def test_a_path_member_and_the_root_are_reframed_but_the_registry_gem_is_not(self):
        _tree(self.root)
        member = self._mark(MEMBER)
        self.assertTrue(evidence.is_first_party_advisory(member))
        self.assertIn("acme-lib 1.2.0 Ruby package", member["impact"])
        self.assertIn("path gem", member["remediation"])
        self.assertEqual("first_party", self._origin(ROOT))
        registry = self._mark(REGISTRY)
        self.assertFalse(evidence.is_first_party_advisory(registry))
        self.assertNotIn("package_origin", registry["tool_evidence"])
        self.assertIsNone(self._origin(("nokogiri", "1.16.0-x86_64-linux")))

    def test_osv_and_trivy_ingest_classify_the_same_way(self):
        _tree(self.root)

        def package(name, version, advisory):
            return {"package": {"name": name, "version": version, "ecosystem": "RubyGems"},
                    "vulnerabilities": [{"id": advisory, "summary": "affected gem",
                                         "database_specific": {"severity": "HIGH"}}],
                    "groups": []}
        osv = {"results": [{"source": {"path": "/src/Gemfile.lock"}, "packages": [
            package(*MEMBER, "GHSA-aaaa-bbbb-cccc"), package(*REGISTRY, "GHSA-dddd-eeee-ffff")]}]}
        findings = self._ingest("osv-scanner.json", osv)
        by_package = {f["tool_evidence"]["package_name"]: f for f in findings}
        self.assertTrue(evidence.is_first_party_advisory(by_package[MEMBER[0]]))
        self.assertFalse(evidence.is_first_party_advisory(by_package[REGISTRY[0]]))
        advisory = "CVE-2099-34567"
        trivy = {"runs": [{
            "tool": {"driver": {"name": "trivy", "rules": [{
                "id": advisory, "properties": {"security-severity": "8.1",
                                               "tags": ["vulnerability", "HIGH"]}}]}},
            "results": [{"ruleId": advisory, "level": "error",
                         "message": {"text": "Package: %s\nInstalled Version: %s\n"
                                             "Vulnerability %s\nSeverity: HIGH"
                                             % (MEMBER + (advisory,))},
                         "locations": [{"physicalLocation": {
                             "artifactLocation": {"uri": "Gemfile.lock"},
                             "region": {"startLine": 1}}}]}]}]}
        marked = self._ingest("trivy.sarif", trivy)[0]
        self.assertTrue(evidence.is_first_party_advisory(marked))
        self.assertEqual({"name": MEMBER[0], "version": MEMBER[1]},
                         marked["tool_evidence"]["advisory_package"])

    def _ingest(self, name, document):
        tools = tempfile.mkdtemp(prefix="tools-out-", dir=self.root)
        with open(os.path.join(tools, name), "w", encoding="utf-8") as fh:
            json.dump(document, fh)
        return ingest_tools.ingest_dir(tools, "g1", target_root=self.root)

    def test_bundler_audit_is_never_classified(self):
        # Owner ruling R2: bundler-audit stays out.
        _tree(self.root)
        self.assertIsNone(self._origin(MEMBER, source="tool:bundler-audit"))
        self.assertEqual("first_party", self._origin(MEMBER, source="tool:trivy"))

    def test_only_the_review_roots_own_gemfile_lock_is_read(self):
        _tree(os.path.join(self.root, "vendor", "y"))
        _tree(self.root)
        self.assertIsNone(self._origin(MEMBER, path="vendor/y/Gemfile.lock"))
        for path in ("gems.locked", "Gemfile", "../Gemfile.lock", "/Gemfile.lock"):
            with self.subTest(path=path):
                _write(os.path.join(self.root, "gems.locked"), _lock())
                self.assertIsNone(self._origin(MEMBER, path=path))
        self.assertEqual("first_party", self._origin(MEMBER))


class TestTheGemspecIsReadAsLiteralsOnly(_RubyCase):
    """Owner ruling R1 = (a): exactly one `x.name = "lit"` and one `x.version = "lit"`."""

    def test_literal_forms_prove_the_identity(self):
        for label, member in (
                ("double quotes", _gemspec(*MEMBER)),
                ("single quotes", "Gem::Specification.new do |spec|\n  spec.name = 'acme-lib'\n"
                                  "  spec.version = '1.2.0'  \nend\n"),
                ("brace block", "Gem::Specification.new { |g|\n  g.name    =   \"acme-lib\"\n"
                                "  g.version = \"1.2.0\"\n}\n")):
            with self.subTest(form=label):
                _tree(self.root, member=member)
                self.assertEqual("first_party", self._origin(MEMBER))

    def test_every_other_form_fails_closed(self):
        name, version = '  s.name = "acme-lib"\n', '  s.version = "1.2.0"\n'
        head, tail = "Gem::Specification.new do |s|\n", "end\n"
        for label, body in (
                ("a constant", name + "  s.version = Acme::VERSION\n"),
                ("interpolation", name + '  s.version = "#{base}.0"\n'),
                ("a frozen literal", name + '  s.version = "1.2.0".freeze\n'),
                ("percent literal", name + "  s.version = %q{1.2.0}\n"),
                ("a second assignment", name + version + '  s.version = "1.3.0"\n'),
                ("a commented second assignment", name + version + '  # s.version = "9"\n'),
                ("no version", name),
                ("no name", version),
                ("another variable", name + '  spec.version = "1.2.0"\n'),
                ("an empty literal", name + '  s.version = ""\n'),
                ("an escape", '  s.name = "acme\\-lib"\n' + version)):
            with self.subTest(form=label):
                _tree(self.root, member=head + body + tail)
                self.assertIsNone(self._origin(MEMBER))
        for label, member in (
                ("no block", 'Gem::Specification.new("acme-lib", "1.2.0")\n'),
                ("two specs", _gemspec(*MEMBER) + _gemspec(*MEMBER)),
                ("name and version split over two blocks",
                 'Gem::Specification.new do |s|\n  s.name = "acme-lib"\nend\n'
                 'Gem::Specification.new do |s|\n  s.version = "1.2.0"\nend\n'),
                ("another Gem::Specification mention",
                 _gemspec(*MEMBER) + 'Gem::Specification.load("other.gemspec")\n'),
                ("not utf-8", None)):
            with self.subTest(form=label):
                _tree(self.root, member=member if member is not None else "")
                if member is None:
                    with open(os.path.join(self.root, "gems", "acme-lib", "acme-lib.gemspec"),
                              "wb") as fh:
                        fh.write(b'Gem::Specification.new do |s|\n  s.name = "\xff"\nend\n')
                self.assertIsNone(self._origin(MEMBER))

    def test_the_directory_must_hold_exactly_one_gemspec(self):
        _tree(self.root)
        _write(os.path.join(self.root, "gems", "acme-lib", "acme-lib-ext.gemspec"),
               _gemspec(*MEMBER))
        self.assertIsNone(self._origin(MEMBER))
        _tree(self.root, member=False)
        os.remove(os.path.join(self.root, "gems", "acme-lib", "acme-lib.gemspec"))
        os.remove(os.path.join(self.root, "gems", "acme-lib", "acme-lib-ext.gemspec"))
        self.assertIsNone(self._origin(MEMBER))
        self.assertEqual("first_party", self._origin(ROOT))

    def test_a_version_mismatch_stays_on_the_advisor_path(self):
        _tree(self.root, member=_gemspec(MEMBER[0], "1.2.1"))
        self.assertIsNone(self._origin(MEMBER))
        self.assertIsNone(self._origin((MEMBER[0], "1.2.1")))
        _tree(self.root)
        self.assertIsNone(self._origin((MEMBER[0], "1.2")))
        self.assertIsNone(self._origin(("Acme-Lib", MEMBER[1])))     # gem names are exact


class TestAllowedPushHost(_RubyCase):
    """Owner ruling R2: a non-rubygems `allowed_push_host` is private-only; a non-literal
    value or any other mention fails closed; the review root is exempt, members are not."""

    def _host(self, line):
        return _gemspec(*MEMBER, extra=line)

    def test_rubygems_is_publishable(self):
        for host in ("https://rubygems.org", "https://rubygems.org/"):
            with self.subTest(host=host):
                _tree(self.root, member=self._host('  s.metadata["allowed_push_host"] = "%s"\n'
                                                   % host))
                self.assertEqual("first_party", self._origin(MEMBER))
        _tree(self.root, member=self._host("  s.metadata['allowed_push_host'] = "
                                           "'https://rubygems.org'\n"))
        self.assertEqual("first_party", self._origin(MEMBER))

    def test_another_host_is_private_only_for_a_member(self):
        for host in ("https://gems.example.internal", "https://rubygems.org.evil.example"):
            with self.subTest(host=host):
                _tree(self.root, member=self._host('  s.metadata["allowed_push_host"] = "%s"\n'
                                                   % host))
                self.assertIsNone(self._origin(MEMBER))

    def test_the_review_root_is_exempt(self):
        _tree(self.root, top=_gemspec(*ROOT, extra='  s.metadata["allowed_push_host"] = '
                                                   '"https://gems.example.internal"\n'))
        self.assertEqual("first_party", self._origin(ROOT))

    def test_any_other_mention_fails_closed(self):
        for line in ('  s.metadata["allowed_push_host"] = HOST\n',
                     '  s.metadata = { "allowed_push_host" => "https://rubygems.org" }\n',
                     '  s.metadata["allowed_push_host"] = "https://rubygems.org"\n'
                     '  s.metadata["allowed_push_host"] = "https://rubygems.org"\n',
                     '  other.metadata["allowed_push_host"] = "https://rubygems.org"\n'):
            with self.subTest(line=line):
                _tree(self.root, member=self._host(line))
                self.assertIsNone(self._origin(MEMBER))


class TestTheGemfileLockFailsClosed(_RubyCase):

    def test_a_registry_or_git_copy_of_the_same_identity_is_ambiguous(self):
        _tree(self.root, lock=_lock(extra_gem_specs="    acme-lib (1.2.0)\n"))
        self.assertIsNone(self._origin(MEMBER))
        git = ("GIT\n  remote: https://example.invalid/acme-lib.git\n  revision: abc\n"
               "  specs:\n    acme-lib (1.2.0)\n\n")
        _tree(self.root, lock=_lock(extra_sections=git))
        self.assertIsNone(self._origin(MEMBER))
        self.assertEqual("first_party", self._origin(ROOT))

    def test_a_source_outside_the_tree_stays_on_the_advisor_path(self):
        outside = tempfile.TemporaryDirectory()
        self.addCleanup(outside.cleanup)
        _write(os.path.join(outside.name, "acme-lib.gemspec"), _gemspec(*MEMBER))
        for remote in (os.path.relpath(outside.name, self.root), outside.name,
                       "file:gems/acme-lib", "https://example.invalid/gems"):
            with self.subTest(remote=remote):
                _tree(self.root, lock=_lock(member_remote=remote))
                self.assertIsNone(self._origin(MEMBER))
        # An in-tree path that is a symlink out of the tree.
        os.symlink(outside.name, os.path.join(self.root, "gems", "linked"))
        _tree(self.root, lock=_lock(member_remote="gems/linked"))
        self.assertIsNone(self._origin(MEMBER))

    def test_the_gemspec_and_its_directory_must_both_resolve_in_tree(self):
        outside = tempfile.TemporaryDirectory()
        self.addCleanup(outside.cleanup)
        # An absolute remote is refused even when it names an in-tree directory.
        _tree(self.root, lock=_lock(member_remote=os.path.join(self.root, "gems", "acme-lib")))
        self.assertIsNone(self._origin(MEMBER))
        os.remove(os.path.join(self.root, "gems", "acme-lib", "acme-lib.gemspec"))
        # A gemspec symlinked out of the tree.
        _write(os.path.join(outside.name, "acme-lib.gemspec"), _gemspec(*MEMBER))
        _tree(self.root, member=False)
        os.makedirs(os.path.join(self.root, "gems", "acme-lib"), exist_ok=True)
        os.symlink(os.path.join(outside.name, "acme-lib.gemspec"),
                   os.path.join(self.root, "gems", "acme-lib", "acme-lib.gemspec"))
        self.assertIsNone(self._origin(MEMBER))
        # An outside directory whose gemspec links back into the tree.
        _write(os.path.join(self.root, "inside", "acme-lib.gemspec"), _gemspec(*MEMBER))
        away = os.path.join(outside.name, "away")
        os.makedirs(away)
        os.symlink(os.path.join(self.root, "inside", "acme-lib.gemspec"),
                   os.path.join(away, "acme-lib.gemspec"))
        _tree(self.root, member=False, lock=_lock(member_remote=os.path.relpath(away, self.root)))
        self.assertIsNone(self._origin(MEMBER))
        os.remove(os.path.join(self.root, "gems", "acme-lib", "acme-lib.gemspec"))
        _tree(self.root)
        self.assertEqual("first_party", self._origin(MEMBER))

    def test_a_path_source_with_any_other_option_stays_on_the_advisor_path(self):
        _tree(self.root, lock=_lock(member_options="  glob: **/*.gemspec\n"))
        self.assertIsNone(self._origin(MEMBER))
        self.assertEqual("first_party", self._origin(ROOT))

    def test_a_malformed_lock_classifies_nothing(self):
        good = _lock()
        for label, lock in (
                ("bad spec line", good.replace("    acme-lib (1.2.0)", "    acme-lib 1.2.0")),
                ("trailing text", good.replace("    acme-lib (1.2.0)", "    acme-lib (1.2.0) x")),
                ("a space in the version", good.replace("    acme-lib (1.2.0)",
                                                        "    acme-lib (1.2.0 x)")),
                ("an odd indent", good.replace("      rack (~> 2.2)", "     rack (~> 2.2)")),
                ("spec outside specs", good.replace("  specs:\n    acme-lib",
                                                    "    acme-lib (9.9.9)\n  specs:\n    acme-lib")),
                ("dependency outside specs", good.replace(
                    "  remote: gems/acme-lib\n", "  remote: gems/acme-lib\n      rack\n")),
                ("two remotes", good.replace("  remote: gems/acme-lib\n",
                                             "  remote: gems/acme-lib\n  remote: .\n")),
                ("empty remote", good.replace("  remote: gems/acme-lib", "  remote:")),
                ("bad option", good.replace("  remote: gems/acme-lib", "  Remote gems/acme-lib")),
                ("not utf-8", None)):
            with self.subTest(lock=label):
                _tree(self.root, lock=lock if lock is not None else "")
                if lock is None:
                    with open(os.path.join(self.root, "Gemfile.lock"), "wb") as fh:
                        fh.write(good.encode() + b"\xff\n")
                self.assertIsNone(self._origin(MEMBER))
                self.assertIsNone(self._origin(ROOT))

    def test_the_entry_and_local_caps_are_exact(self):
        with mock.patch.object(first_party_advisory, "MAX_CARGO_MANIFESTS", 2):
            # 2 local + 2 registry = 4 specs; fill to 128, then one more.
            for count, expected in ((124, "first_party"), (125, None)):
                with self.subTest(specs=count + 4):
                    filler = "".join("    f%d (1.0.0)\n" % i for i in range(count))
                    _tree(self.root, lock=_lock(extra_gem_specs=filler))
                    self.assertEqual(expected, self._origin(MEMBER))
            third = "PATH\n  remote: gems/util\n  specs:\n    acme-util (0.1.0)\n\n"
            _write(os.path.join(self.root, "gems", "util", "acme-util.gemspec"),
                   _gemspec("acme-util", "0.1.0"))
            _tree(self.root, lock=_lock(extra_sections=third))
            self.assertIsNone(self._origin(MEMBER))           # 3 local gems > 2

    def test_lock_and_gemspec_bytes_spend_the_shared_budget_once(self):
        _tree(self.root)
        cache = first_party_advisory.IngestCache()
        self.assertEqual("first_party", self._origin(MEMBER, cache=cache))
        self.assertEqual("first_party", self._origin(ROOT, cache=cache))
        spent = sum(os.path.getsize(os.path.join(self.root, p)) for p in (
            "Gemfile.lock", "acme-app.gemspec", "gems/acme-lib/acme-lib.gemspec"))
        self.assertEqual(first_party_advisory.MAX_CARGO_MANIFEST_INGEST_BYTES - spent,
                         cache.manifest_bytes_remaining)
        lock_size = os.path.getsize(os.path.join(self.root, "Gemfile.lock"))
        with mock.patch.object(first_party_advisory, "MAX_CARGO_MANIFEST_INGEST_BYTES",
                               lock_size):
            cache = first_party_advisory.IngestCache()
            self.assertIsNone(self._origin(MEMBER, cache=cache))
        self.assertTrue(cache.manifest_budget_exhausted)

    def test_one_directory_serving_two_specs_reads_its_gemspec_once(self):
        lock = _lock().replace("    acme-app (0.3.0)\n", "    acme-app (0.3.0)\n    acme-extra (0.3.0)\n")
        _tree(self.root, lock=lock)
        cache = first_party_advisory.IngestCache()
        self.assertEqual("first_party", self._origin(ROOT, cache=cache))
        self.assertIsNone(self._origin(("acme-extra", "0.3.0"), cache=cache))
        spent = sum(os.path.getsize(os.path.join(self.root, p)) for p in (
            "Gemfile.lock", "acme-app.gemspec", "gems/acme-lib/acme-lib.gemspec"))
        self.assertEqual(first_party_advisory.MAX_CARGO_MANIFEST_INGEST_BYTES - spent,
                         cache.manifest_bytes_remaining)

    def test_an_oversized_lock_or_gemspec_classifies_nothing(self):
        _tree(self.root)
        lock_size = os.path.getsize(os.path.join(self.root, "Gemfile.lock"))
        for limit, expected in ((lock_size, "first_party"), (lock_size - 1, None)):
            with self.subTest(lock_limit=limit), \
                    mock.patch.object(first_party_advisory, "MAX_RUBY_LOCK_BYTES", limit):
                self.assertEqual(expected, self._origin(MEMBER))
        spec_size = os.path.getsize(os.path.join(self.root, "gems", "acme-lib",
                                                 "acme-lib.gemspec"))
        with mock.patch.object(first_party_advisory, "MAX_GEMSPEC_BYTES", spec_size - 1):
            self.assertIsNone(self._origin(MEMBER))


if __name__ == "__main__":
    unittest.main()
