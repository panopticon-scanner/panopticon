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


class TestTheReviewProbes(_RubyCase):
    """#3692 review H1, H2, M1, M2 and L2: every probe the review seat ran returned
    first_party before; each must fail closed, beside an honest control."""

    PATH = "PATH\n  remote: gems/foo\n  specs:\n    foo (1.0)\n\n"
    FOO = ("foo", "1.0")

    @staticmethod
    def _gem(body):
        return "GEM\n  remote: https://rubygems.org/\n  specs:\n" + body

    @staticmethod
    def _spec(body):
        return 'Gem::Specification.new do |s|\n' + body + 'end\n'

    def _probe(self, lock, gemspec=None, package=None):
        _write(os.path.join(self.root, "app.gemspec"), _gemspec("app", "0.1"))
        _write(os.path.join(self.root, "gems", "foo", "foo.gemspec"),
               gemspec if gemspec is not None else _gemspec(*self.FOO))
        with open(os.path.join(self.root, "Gemfile.lock"), "w", encoding="utf-8",
                  newline="") as fh:
            fh.write(lock)
        return self._origin(package or self.FOO)

    def test_the_controls(self):
        self.assertEqual("first_party", self._probe(self.PATH + self._gem("    rack (2.0)\n")))
        self.assertIsNone(self._probe(self.PATH + self._gem("    foo (1.0)\n")))
        # Every skipped header, exactly as Bundler writes it, still parses.
        skipped = ("PLATFORMS\n  ruby\n\nDEPENDENCIES\n  foo!\n\nCHECKSUMS\n  foo (1.0)\n\n"
                   "RUBY VERSION\n   ruby 3.3.0p0\n\nBUNDLED WITH\n   2.5.6\n")
        self.assertEqual("first_party", self._probe(self.PATH + skipped))

    def test_a_platform_suffixed_copy_shares_the_release(self):
        # H1: Bundler reads `foo (1.0-x86_64-linux)` as foo 1.0 on that platform.
        for copy in ("1.0-x86_64-linux", "1.0-java", "1.0-x86_64-linux-musl"):
            with self.subTest(copy=copy):
                self.assertIsNone(self._probe(self.PATH + self._gem("    foo (%s)\n" % copy)))
        self.assertEqual("first_party",
                         self._probe(self.PATH + self._gem("    foo (1.1-java)\n")))
        # The platform copy is itself external under both spellings.
        self.assertIsNone(self._probe(self.PATH + self._gem("    rack (2.0-java)\n"),
                                      package=("rack", "2.0")))
        # A local spec with a platform never proves its release.
        lock = self.PATH.replace("foo (1.0)", "foo (1.0-java)")
        # A second, platform-suffixed local spec of the same release is ambiguous too.
        other = "PATH\n  remote: gems/foo-java\n  specs:\n    foo (1.0-java)\n\n"
        _write(os.path.join(self.root, "gems", "foo-java", "foo.gemspec"),
               _gemspec("foo", "1.0-java"))
        self.assertIsNone(self._probe(self.PATH + other))
        for version in ("1.0", "1.0-java"):
            with self.subTest(local_platform=version):
                gemspec = _gemspec("foo", version)
                self.assertIsNone(self._probe(lock, gemspec=gemspec))
                self.assertIsNone(self._probe(lock, gemspec=gemspec,
                                              package=("foo", "1.0-java")))

    def test_whitespace_bundler_reads_differently_fails_the_lock(self):
        # H2: each of these hid the GEM copy below it from the old parser.
        for label, line in (("tab", "\tjunk\n"), ("form feed", "\x0c\n"),
                            ("form feed text", "\x0cx\n"), ("cr-led", "\r    bar (2)\n"),
                            ("u2028", "\u2028x\n"), ("nel", "\x85x\n"), ("vt", "\x0bx\n"),
                            ("nbsp", "\u00a0x\n"), ("u2029", "\u2029x\n"),
                            ("spaces only", "   \n")):
            with self.subTest(line=label):
                self.assertIsNone(self._probe(self.PATH + self._gem(line + "    foo (1.0)\n")))
        # Anywhere in the lock, not just inside a source.
        for label, lock in (
                ("bom", "\ufeff" + self._gem("    foo (1.0)\n") + "\n" + self.PATH),
                ("crlf", (self.PATH + self._gem("    rack (2.0)\n")).replace("\n", "\r\n")),
                ("tab in a skipped section", self.PATH + "PLATFORMS\n\truby\n"),
                ("trailing tab on a header", self.PATH.replace("PATH\n", "PATH\t\n"))):
            with self.subTest(lock=label):
                self.assertIsNone(self._probe(lock))

    def test_only_known_headers_are_read_or_skipped(self):
        # H2: exact header match; anything else fails the lock.
        gem = self._gem("    foo (1.0)\n")
        for label, lock in (
                ("GEM with a trailing space", self.PATH + gem.replace("GEM\n", "GEM \n")),
                ("PATH with a trailing space",
                 self.PATH.replace("PATH\n", "PATH \n") + self._gem("    rack (2.0)\n")),
                ("lower-case header", self.PATH + "platforms\n  ruby\n"),
                ("skipped header with a trailing space", self.PATH + "PLATFORMS \n  ruby\n"),
                ("unknown header", self.PATH + "SOMETHING NEW\n  x\n"),
                ("indented line before any header", "  remote: x\n" + self.PATH)):
            with self.subTest(lock=label):
                self.assertIsNone(self._probe(lock))
        # A second GEM section is still read.
        self.assertIsNone(self._probe(self.PATH + self._gem("    rack (1)\n") + "\n" + gem))
        self.assertIsNone(self._probe(self.PATH + "PLATFORMS\n  ruby\n" + gem))

    def test_spec_lines_bundler_reads_differently_fail_the_lock(self):
        for label, body in (("pinned bang", "    foo (1.0)!\n"),
                            ("two-space spec", "  foo (1.0)\n")):
            with self.subTest(spec=label):
                self.assertIsNone(self._probe(self.PATH + self._gem(body)))

    def test_a_gemfile_lock_symlinked_to_another_name_is_refused(self):
        # #3692 review L3, on #3686's F1 guard: the parser follows the resolved name,
        # so a Gemfile.lock must resolve to a file called Gemfile.lock.
        lock = self.PATH + self._gem("    rack (2.0)\n")
        self.assertEqual("first_party", self._probe(lock))             # the control
        for target in ("gems.locked", "Gemfile.lock.real", "Cargo.lock"):
            with self.subTest(target=target):
                os.remove(os.path.join(self.root, "Gemfile.lock"))
                with open(os.path.join(self.root, target), "w", encoding="utf-8") as fh:
                    fh.write(lock)
                os.symlink(target, os.path.join(self.root, "Gemfile.lock"))
                self.assertIsNone(self._origin(self.FOO))
                # The real file under its own name is not a lock this marker reads.
                self.assertIsNone(self._origin(self.FOO, path=target))
        # The other direction is the dangerous one: another ecosystem's lock resolving
        # to a Gemfile.lock would have its advisory matched against the gems.
        for stale in ("Gemfile.lock", "gems.locked", "Gemfile.lock.real", "Cargo.lock"):
            os.remove(os.path.join(self.root, stale))
        with open(os.path.join(self.root, "Gemfile.lock"), "w", encoding="utf-8") as fh:
            fh.write(lock)
        for name in ("poetry.lock", "uv.lock", "pdm.lock", "package-lock.json", "Cargo.lock"):
            with self.subTest(link=name):
                os.symlink("Gemfile.lock", os.path.join(self.root, name))
                self.assertIsNone(self._origin(self.FOO, path=name))
        self.assertEqual("first_party", self._origin(self.FOO))
        # A symlink to a Gemfile.lock elsewhere keeps the name but is not the root's own.
        os.remove(os.path.join(self.root, "Gemfile.lock"))
        _write(os.path.join(self.root, "nested", "Gemfile.lock"), lock)
        os.symlink(os.path.join("nested", "Gemfile.lock"),
                   os.path.join(self.root, "Gemfile.lock"))
        self.assertIsNone(self._origin(self.FOO))

    def test_an_option_after_specs_fails_the_lock(self):
        # L2: Bundler builds the source at `specs:`.
        self.assertIsNone(self._probe("PATH\n  specs:\n    foo (1.0)\n  remote: gems/foo\n\n"))
        self.assertIsNone(self._probe(self.PATH.replace("    foo (1.0)\n",
                                                        "    foo (1.0)\n  glob: x\n")))
        self.assertIsNone(self._probe(self.PATH.replace("    foo (1.0)\n",
                                                        "    foo (1.0)\n  specs:\n")))

    def test_ruby_the_reader_cannot_follow_fails_the_gemspec(self):
        # M1: each was evaluated by ruby and overrides or hides the proven literals.
        lit = '  s.name = "foo"\n  s.version = "1.0"\n'
        hidden = 'Gem::Specification.new do |s|\n  s.send(:name=, "bar")\n' \
                 '  s.send(:version=, "9.9")\nend\n'
        for label, gemspec in (
                ("send", self._spec(lit + '  s.send(:version=, "9.9")\n')),
                ("colon colon", self._spec(lit + '  s::version = "9.9"\n')),
                ("backslash continuation", self._spec(lit + '  s.version \\\n= "9.9"\n')),
                ("dot continuation", self._spec(lit + '  s.\n  version = "9.9"\n')),
                ("leading dot", self._spec(lit + '  s\n  .version = "9.9"\n')),
                ("name replace", self._spec(lit + '  s.name.replace("bar")\n')),
                ("name append", self._spec(lit + '  s.name << "x"\n')),
                ("multiple assignment", self._spec(lit + '  s.name, _x = "bar", 1\n')),
                ("ivar set", self._spec(
                    lit + '  s.instance_variable_set(:@version, Gem::Version.new("9.9"))\n')),
                ("instance eval", self._spec(lit + '  s.instance_eval { @name = "bar" }\n')),
                ("__END__", hidden + "__END__\n" + lit),
                ("=begin", "=begin\n" + lit + "=end\n" + hidden),
                ("heredoc", "X = <<-R\n" + lit + "R\n" + hidden),
                ("aliased Gem", self._spec(lit) + 'G = Gem\nG::Specification.new { |t| '
                                                  't.send(:name=, "bar") }\n'),
                ("semicolon", self._spec('  s.name = "foo"\n  s.version = "1.0"; '
                                         's.send(:version=, "9.9")\n')),
                ("public_send", self._spec(lit + '  s.public_send(:version=, "9.9")\n')),
                ("__send__", self._spec(lit + '  s.__send__(:version=, "9.9")\n')),
                ("method object", self._spec(lit + '  s.method(:version=).call("9.9")\n')),
                ("symbol to proc", self._spec(lit + '  [s].each(&:"version=")\n')),
                ("class eval", self._spec(lit) + 'Gem::Specification.class_eval { }\n'),
                ("reopened method", self._spec(lit + '  def s.version; "9.9"; end\n')),
                ("eval", self._spec(lit + '  eval("s.version = 9")\n')),
                ("define_method", self._spec(lit + '  define_method(:x) { }\n')),
                ("ObjectSpace", self._spec(lit) + "ObjectSpace.each_object { }\n"),
                ("binding", self._spec(lit + "  binding.local_variable_get(:s)\n")),
                ("Gem semicolon", "Gem;" + self._spec(lit)),
                ("assigned spec", "x = " + self._spec(lit) + 'x.version = "9.9"\n'),
                ("chained end", self._spec(lit).replace("end\n", "end.tap { }\n")),
                ("code after the opener",
                 self._spec(lit).replace("|s|\n", '|s|; s.name.replace("bar")\n')),
                ("mention after a nested block's end",
                 "module Foo\n  Gem::Specification.new do |s|\n    s.name = \"foo\"\n"
                 "    s.version = \"1.0\"\n  end\n  s.summary = 1\nend\n"),
                ("comparison", self._spec(lit + '  s.summary == "x"\n')),
                ("match", self._spec(lit + "  s.summary =~ /x/\n")),
                ("unknown add_ method", self._spec(lit + '  s.add_signing_key("x")\n')),
                ("setter symbol", self._spec(lit + "  x = :version=\n")),
                ("name setter symbol", self._spec(lit + "  x = :name=\n")),
                ("name outside the block", self._spec('  s.version = "1.0"\n')
                 + '  s.name = "foo"\n'),
                ("mention outside the block", self._spec(lit) + "s.summary = 1\n"),
                ("mention mid-line", self._spec(lit + '  x = s\n')),
                ("getter on the rhs", self._spec(lit + '  s.summary = s.name.replace("y")\n')),
                ("interpolated mention",
                 self._spec(lit + '  s.summary = "#{s.name.replace(%q(y))}"\n')),
                ("or-assign", self._spec(lit + '  s.version ||= "9.9"\n')),
                ("safe navigation", self._spec(lit + '  s&.version = "9.9"\n')),
                ("block var in a nested block", self._spec(lit + '  [1].each { s }\n')),
                ("two Specifications", self._spec(lit) + "# Gem::Specification\n"),
                ("unclosed block", self._spec(lit).replace("end\n", "  end\n")),
                ("tab whitespace", self._spec(lit.replace("  s.name", "\ts.name"))),
                ("u2028", self._spec(lit + "  s.summary = 1\u2028\n"))):
            with self.subTest(gemspec=label):
                self.assertIsNone(self._probe(self.PATH, gemspec=gemspec))

    def test_each_refused_form_fails_the_gemspec_alone(self):
        # M1's refusal list, one at a time, each in a line no other rule objects to.
        lit = '  s.name = "foo"\n  s.version = "1.0"\n'
        calls = ("send", "public_send", "__send__", "instance_variable_set",
                 "instance_variable_get", "instance_eval", "instance_exec", "class_eval",
                 "class_exec", "module_eval", "module_exec", "define_method",
                 "define_singleton_method", "eval", "method", "binding")
        cases = [(call, self._spec(lit + "  x = Object.%s(:y)\n" % call)) for call in calls]
        cases += [
            ("def", self._spec(lit + "  def y; end\n")),
            ("alias", self._spec(lit + "  alias y z\n")),
            ("alias_method", self._spec(lit + "  alias_method :y, :z\n")),
            ("undef", self._spec(lit + "  undef y\n")),
            ("ObjectSpace", self._spec(lit + "  x = ObjectSpace\n")),
            ("__END__", self._spec(lit) + "__END__\n"),
            ("=begin", "=begin\n=end\n" + self._spec(lit)),
            ("<<", self._spec(lit + "  x = [] << 1\n")),
            ("&:", self._spec(lit + "  x = [1].map(&:to_s)\n")),
            ("bare Gem", self._spec(lit + "  x = Gem\n")),
            ("trailing backslash", self._spec(lit + "  x = 1 \\\n  + 2\n")),
            ("trailing dot", self._spec(lit + "  x = 1.\n  to_s\n")),
            ("leading dot", self._spec(lit + "  x = 1\n  .to_s\n")),
            ("leading safe navigation", self._spec(lit + "  x = 1\n  &.to_s\n"))]
        for label, gemspec in cases:
            with self.subTest(refused=label):
                self.assertIsNone(self._probe(self.PATH, gemspec=gemspec))
        self.assertEqual("first_party", self._probe(
            self.PATH, gemspec=self._spec(lit + "  x = Object.sender(:y)\n")))

    def test_metadata_must_be_literal_lines(self):
        # M2: an escaped or computed key, or a whole-hash assignment, may set a host.
        lit = '  s.name = "foo"\n  s.version = "1.0"\n'
        for label, line in (
                ("escaped key", '  s.metadata["allowed\\x5fpush_host"] = "https://gems.corp"\n'),
                ("unicode-escaped key",
                 '  s.metadata["allowed\\u005fpush_host"] = "https://gems.corp"\n'),
                ("concatenated key",
                 '  s.metadata["allowed_" + "push_host"] = "https://gems.corp"\n'),
                ("constant metadata", "  s.metadata = Foo::METADATA\n"),
                ("merged metadata", '  s.metadata.merge!("a" => "b")\n'),
                ("literal private host",
                 '  s.metadata["allowed_push_host"] = "https://gems.corp"\n'),
                ("constant value", '  s.metadata["homepage_uri"] = HOME\n'),
                ("interpolated value", '  s.metadata["homepage_uri"] = "#{x}"\n'),
                ("host named elsewhere", '  s.summary = "allowed_push_host"\n'),
                ("host inside a longer key",
                 '  s.metadata["allowed_push_host_note"] = "https://rubygems.org"\n'),
                ("two hosts", '  s.metadata["allowed_push_host"] = "https://rubygems.org"\n'
                              '  s.metadata["allowed_push_host"] = "https://gems.corp"\n')):
            with self.subTest(metadata=label):
                self.assertIsNone(self._probe(self.PATH, gemspec=self._spec(lit + line)))

    def test_honest_gemspecs_still_prove_their_identity(self):
        lit = '  s.name = "foo"\n  s.version = "1.0"\n'
        for label, gemspec in (
                ("plain", self._spec(lit)),
                ("crlf", self._spec(lit).replace("\n", "\r\n")),
                ("dependencies", self._spec(lit + '  s.add_dependency "rack", "~> 2.2"\n'
                                                  '  s.add_runtime_dependency("rake")\n'
                                                  '  s.add_development_dependency "rspec"\n')),
                ("literal metadata", self._spec(
                    lit + '  s.metadata["homepage_uri"] = "https://example.invalid"\n'
                          "  s.metadata['allowed_push_host'] = 'https://rubygems.org'\n")),
                ("prose mentioning the variable", self._spec(
                    lit + '  s.description = "s is a gem\'s spec; it == s"\n')),
                ("other fields", self._spec(lit + '  s.files = Dir["lib/**/*.rb"]\n'
                                                  '  s.required_ruby_version = ">= 3.0"\n')),
                ("nested in a module", "module Foo\n  Gem::Specification.new do |s|\n"
                                       "    s.name = \"foo\"\n    s.version = \"1.0\"\n"
                                       "  end\nend\n"),
                ("brace block", "Gem::Specification.new { |s|\n" + lit + "}\n"),
                ("other receivers named like the variable", self._spec(
                    lit + '  s.require_paths = [Foo::s, @s, $s, :s, x.s, s!, s?, "s#{1}"]\n')),
                ("comparisons naming the fields", self._spec(
                    lit + '  s.summary = "a" if version == "1" || name =~ /x/\n'))):
            with self.subTest(gemspec=label):
                self.assertEqual("first_party", self._probe(self.PATH, gemspec=gemspec))


if __name__ == "__main__":
    unittest.main()
