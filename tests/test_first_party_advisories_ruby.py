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
import shutil
import tempfile
import unittest
from unittest import mock

import scripts.evidence as evidence
import scripts.first_party_advisory as first_party_advisory
import scripts.ingest_tools as ingest_tools
import scripts.tools as tools


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
                # Not text beside an assignment: `x # s.version = "9"` is a second
                # statement shape, refused. A whole-line comment is inert (below).
                ("an assignment with a trailing comment",
                 name + '  s.version = "1.2.0" # s.version = "9"\n'),
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
                ("two Specifications",
                 self._spec(lit) + "Gem::Specification.new do |t|\nend\n"),
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
                ("other fields", self._spec(lit + '  s.required_ruby_version = ">= 3.0"\n')),
                ("brace block", "Gem::Specification.new { |s|\n" + lit + "}\n")):
            with self.subTest(gemspec=label):
                self.assertEqual("first_party", self._probe(self.PATH, gemspec=gemspec))


class TestTheSecondReview(TestTheReviewProbes):
    """#3692 review at 98993a71: the gemspec reader allowlists EVERY line, not only the
    lines that mention the block variable; the lock parser holds exact indents, the exact
    `specs:` marker and RubyGems-valid versions; and the path, the gemspec set and the
    version equality are Bundler's and RubyGems' own."""

    LIT = '  s.name = "foo"\n  s.version = "1.0"\n'

    # Not inherited: the parent's cases stay the parent's.
    for _name in [n for n in dir(TestTheReviewProbes) if n.startswith("test_")]:
        locals()[_name] = None
    del _name

    def test_every_line_of_a_gemspec_is_on_the_allowlist(self):
        lit = self.LIT
        hidden = 'Gem::Specification.new do |s|\n  s.name = "foo"\n  s.version = "1.0"\nend\n'
        for label, gemspec in (
                # Item 1's demonstrations.
                ("version in a conditional",
                 self._spec('  s.name = "foo"\n  if false\n    s.version = "1.0"\n  end\n')),
                ("version after unless",
                 self._spec('  s.name = "foo"\n  unless true\n  s.version = "1.0"\n  end\n')),
                ("a second specification from split strings",
                 hidden + 'Object.const_get("G" "em")::const_get("Spec" "ification")'
                          '.new { |t| t.send("ver" "sion=", "9.9") }\n'),
                ("a hidden second mention in a percent literal",
                 self._spec(lit + "  y = %q(\n  s.name = 1\n)\n")),
                ("a character literal", self._spec(lit + '  y = ?"\n')),
                ("load on the right-hand side", self._spec(lit + '  s.files = load("x.rb")\n')),
                ("require on the right-hand side",
                 self._spec(lit + '  s.summary = require("x")\n')),
                ("a require line before the block", 'require "x"\n' + hidden),
                ("a require_relative line", 'require_relative "lib/foo/version"\n' + hidden),
                ("the whole block in a conditional", "if false\n" + hidden + "end\n"),
                ("the block in a module", "module Foo\n" + hidden + "end\n"),
                ("code after the block", hidden + "puts 1\n"),
                ("newdo", hidden.replace(".new do |s|", ".newdo |s|")),
                ("a numeric block variable", hidden.replace("|s|", "|1|").replace("s.", "1.")),
                ("an upper-case block variable",
                 hidden.replace("|s|", "|S|").replace("  s.", "  S.")),
                ("a keyword block variable",
                 hidden.replace("|s|", "|if|").replace("  s.", "  if.")),
                # Every line inside is a literal assignment, a dependency or metadata.
                ("a bare call inside", self._spec(lit + "  puts 1\n")),
                ("a local assignment inside", self._spec(lit + "  x = 1\n")),
                ("a glob", self._spec(lit + '  s.files = Dir["lib/**/*.rb"]\n')),
                ("a constant", self._spec(lit + "  s.platform = Gem::Platform::RUBY\n")),
                ("a method call", self._spec(lit + '  s.summary = "a".upcase\n')),
                ("frozen", self._spec(lit + '  s.summary = "a".freeze\n')),
                ("a trailing comment", self._spec(lit + '  s.summary = "a" # note\n')),
                ("a trailing modifier", self._spec(lit + '  s.summary = "a" if true\n')),
                ("two statements", self._spec(lit + '  s.summary = "a"; s.license = "MIT"\n')),
                ("an array holding code", self._spec(lit + '  s.files = ["a", x]\n')),
                ("an unclosed array", self._spec(lit + '  s.files = ["a",\n')),
                ("a hash", self._spec(lit + '  s.summary = {"a" => "b"}\n')),
                ("a symbol", self._spec(lit + "  s.summary = :a\n")),
                ("a float", self._spec(lit + "  s.summary = 1.5\n")),
                ("an array for the version",
                 self._spec('  s.name = "foo"\n  s.version = ["1.0"]\n')),
                ("a number for the version", self._spec('  s.name = "foo"\n  s.version = 1\n')),
                ("the version twice", self._spec(lit + '  s.version = "1.0"\n')),
                ("the name twice", self._spec(lit + '  s.name = "foo"\n')),
                ("metadata assigned whole", self._spec(lit + '  s.metadata = "x"\n')),
                ("a setter with a capital", self._spec(lit + '  s.Summary = "a"\n')),
                ("a dependency with a variable",
                 self._spec(lit + '  s.add_dependency "rack", constraint\n')),
                ("a dependency with nothing", self._spec(lit + "  s.add_dependency\n")),
                ("a dependency with an unclosed paren",
                 self._spec(lit + '  s.add_dependency("rack"\n')),
                ("another add_ method", self._spec(lit + '  s.add_bindir "x"\n')),
                ("an encoding the reader does not read as",
                 "# encoding: Shift_JIS\n" + hidden),
                ("an encoding comment inside", self._spec("  # coding: big5\n" + lit)),
                ("a block comment", "=begin\n=end\n" + hidden),
                ("an opener with trailing code", hidden.replace("|s|\n", "|s| # x\n")),
                # Survivors of the first mutation pass.
                ("a block that never closes", hidden.replace("end\n", "")),
                ("adjacent literals", self._spec(lit + '  s.summary = "a" "b"\n')),
                ("adjacent literals in an array", self._spec(lit + '  s.files = ["a" "b"]\n')),
                ("adjacent literals in a dependency",
                 self._spec(lit + '  s.add_dependency "rack" "~> 2"\n')),
                ("a trailing comma, so the statement continues",
                 self._spec(lit + '  s.add_dependency "rack",\n')),
                ("a trailing comma in an array", self._spec(lit + '  s.files = ["a",]\n')),
                ("two strings for one field",
                 self._spec('  s.name = "foo"\n  s.version = "1.0", "9"\n')),
                ("a dependency with only a space", self._spec(lit + "  s.add_dependency \n")),
                ("a dependency with empty parens", self._spec(lit + "  s.add_dependency()\n")),
                ("an integer", self._spec(lit + "  s.rubygems_version = 4\n")),
                ("an integer with a leading zero",
                 self._spec(lit + "  s.specification_version = 08\n")),
                ("non-ASCII digits", self._spec(lit + "  s.specification_version = %s\n"
                                                % (chr(0x661) + chr(0x662)))),
                ("true", self._spec(lit + "  s.has_rdoc = true\n")),
                ("nil", self._spec(lit + "  s.cert_chain = nil\n")),
                ("a metadata value that is not a string",
                 self._spec(lit + '  s.metadata["homepage_uri"] = 1\n')),
                ("a metadata value that is an array",
                 self._spec(lit + '  s.metadata["homepage_uri"] = ["x"]\n')),
                ("two metadata keys", self._spec(lit + '  s.metadata["a", "b"] = "x"\n'))):
            with self.subTest(gemspec=label):
                self.assertIsNone(self._probe(self.PATH, gemspec=gemspec))

    def test_the_allowlisted_shapes_still_prove_the_identity(self):
        lit = self.LIT
        for label, gemspec in (
                # A whole-line comment is inert, whatever it says (earlier rounds
                # refused these because only some lines were on the allowlist).
                ("a commented second assignment", self._spec(lit + '  # s.version = "9"\n')),
                ("a comment naming the constant", self._spec(lit) + "# Gem::Specification\n"),
                ("plain", self._spec(lit)),
                ("crlf", self._spec(lit).replace("\n", "\r\n")),
                ("comments and blank lines everywhere",
                 "#!/usr/bin/env ruby\n# frozen_string_literal: true\n\n   \n"
                 "# a gem's spec: s.version = 9, Gem::Specification.new, if false\n"
                 + self._spec("  # s.summary = 1\n\n" + lit) + "\n# the end\n"),
                ("a utf-8 encoding comment", "# -*- encoding: utf-8 -*-\n" + self._spec(lit)),
                ("a UTF-8 coding comment", "# coding: UTF-8\n" + self._spec(lit)),
                ("literal fields", self._spec(
                    lit + '  s.summary = "s is a gem\'s spec; it == s if false"\n'
                          "  s.description = 'say \"hi\"; # not a comment'\n"
                          '  s.authors = ["A", \'B\']\n  s.files = []\n'
                          '  s.require_paths = [ "lib" ]\n  s.bindir = "exe"\n'
                          "  s.email = 'a@example.invalid'\n  s.email = ['a@example.invalid']\n"
                          '  s.homepage = "https://example.invalid"\n  s.license = "MIT"\n'
                          "  s.licenses = ['MIT']\n  s.executables = ['foo']\n"
                          "  s.required_ruby_version = \">= 3.0\"\n"
                          "  s.required_ruby_version = ['>= 3.0', '< 4']\n"
                          "  s.required_rubygems_version = '~>3.2.0.rc1'\n"
                          "  s.required_ruby_version = '3'\n")),
                ("dependencies", self._spec(lit + '  s.add_dependency "rack", "~> 2.2"\n'
                                                  '  s.add_runtime_dependency("rake")\n'
                                                  '  s.add_development_dependency "rspec", '
                                                  '">= 3", "< 4"\n'
                                                  "  s.add_dependency( 'json' , '>= 1' )\n")),
                ("literal metadata", self._spec(
                    lit + '  s.metadata["homepage_uri"] = "https://example.invalid"\n'
                          "  s.metadata['allowed_push_host'] = 'https://rubygems.org'\n")),
                ("brace block", "Gem::Specification.new { |s|\n" + lit + "}\n"),
                ("brace block, tight", "Gem::Specification.new{|s|\n" + lit + "}\n"),
                ("do with no space before the pipe",
                 "Gem::Specification.new do|spec_1|\n" + lit.replace("s.", "spec_1.") + "end\n"),
                ("an indented block",
                 "  Gem::Specification.new do |s|\n" + lit + "  end\n"),
                ("an underscore variable",
                 "Gem::Specification.new do |_s|\n" + lit.replace("s.", "_s.") + "end\n")):
            with self.subTest(gemspec=label):
                self.assertEqual("first_party", self._probe(self.PATH, gemspec=gemspec))

    def test_only_fields_the_reader_knows_with_the_kind_each_takes(self):
        # #3692 round 2, items 1 and 2: `x.<anything> = <literal>` let through gemspecs
        # Ruby cannot load (`Gem::Specification.load` returns nil), and a platform.
        lit = self.LIT
        for label, line in (
                ("platform", '  s.platform = "java"\n'),
                ("original_platform", '  s.original_platform = "java"\n'),
                ("a field that does not exist", '  s.bogus = "x"\n'),
                ("class", '  s.class = "x"\n'),
                ("freeze", '  s.freeze = "x"\n'),
                ("a junk ruby requirement", '  s.required_ruby_version = "junk"\n'),
                ("an empty requirement", '  s.required_ruby_version = ""\n'),
                ("a requirement with a bad operator", '  s.required_ruby_version = "=> 3"\n'),
                ("a requirement with two versions", '  s.required_ruby_version = ">= 3 4"\n'),
                ("a requirement with a non-ASCII digit",
                 '  s.required_ruby_version = ">= %s"\n' % chr(0x663)),
                ("a requirement list holding junk",
                 '  s.required_rubygems_version = [">= 3", "junk"]\n'),
                ("an empty requirement list", "  s.required_ruby_version = []\n"),
                ("a date", '  s.date = "2026-11-21"\n'),
                ("a junk date", '  s.date = "junk"\n'),
                ("a dependency with a junk requirement", '  s.add_dependency "a", "junk req"\n'),
                ("a dependency with an empty name", '  s.add_dependency ""\n'),
                ("a dependency with a spaced name", '  s.add_dependency "a b"\n'),
                ("a development dependency with a junk requirement",
                 '  s.add_development_dependency("a", ">= 1", "x")\n'),
                ("an array for a string field", '  s.summary = ["a"]\n'),
                ("a string for an array field", '  s.files = "a.rb"\n'),
                ("an array for the author", '  s.author = ["A"]\n'),
                ("a string for the authors", '  s.authors = "A"\n'),
                ("an array for the name", '  s.name = ["foo"]\n'),
                ("signing_key", '  s.signing_key = "key.pem"\n'),
                ("rubygems_version", '  s.rubygems_version = "3.5.0"\n'),
                ("specification_version", "  s.specification_version = 4\n")):
            with self.subTest(field=label):
                body = line if "s.name" in line else lit + line
                if "s.name" in line:
                    body = line + '  s.version = "1.0"\n'
                self.assertIsNone(self._probe(self.PATH, gemspec=self._spec(body)))
        # The table itself: every field, and the kind it takes.
        self.assertEqual(
            {"name": "string", "version": "string", "summary": "string",
             "description": "string", "homepage": "string", "license": "string",
             "author": "string", "bindir": "string", "post_install_message": "string",
             "email": "string or array", "authors": "array", "licenses": "array",
             "files": "array", "test_files": "array", "executables": "array",
             "extensions": "array", "extra_rdoc_files": "array", "rdoc_options": "array",
             "require_paths": "array", "requirements": "array",
             "required_ruby_version": "requirement",
             "required_rubygems_version": "requirement"},
            first_party_advisory.GEMSPEC_FIELDS)
        for field, kind in first_party_advisory.GEMSPEC_FIELDS.items():
            if field in ("name", "version"):
                continue
            values = {"string": ('"a"',), "array": ('["a"]', "[]"),
                      "string or array": ('"a"', '["a"]'),
                      "requirement": ('">= 1"', '[">= 1", "< 2"]')}[kind]
            wrong = {"string": '["a"]', "array": '"a"', "string or array": "1",
                     "requirement": '"a"'}[kind]
            for value in values:
                with self.subTest(field=field, value=value):
                    self.assertEqual("first_party", self._probe(
                        self.PATH, gemspec=self._spec(lit + "  s.%s = %s\n" % (field, value))))
            with self.subTest(field=field, wrong=wrong):
                self.assertIsNone(self._probe(
                    self.PATH, gemspec=self._spec(lit + "  s.%s = %s\n" % (field, wrong))))

    def test_a_requirement_is_one_rubygems_can_parse(self):
        ok = first_party_advisory._gem_requirement_ok
        for text in ("1", "1.0", ">= 1", ">=1", "~> 2.2", "~>2.2.0.rc1", "= 1.a", "!= 1.0",
                     "> 0", "< 4", "<= 4.0.0", "  >= 1  ", "1.0.0.pre"):
            with self.subTest(valid=text):
                self.assertTrue(ok(text))
        for text in ("", " ", "junk", "junk req", ">=", "=> 1", ">= 1 2", ">> 1", "~ 1",
                     ">= .1", ">= 1.", ">= 1..2", ">= v1", ">= 1-rc", ">= 1,", "1 >=",
                     ">= " + chr(0x663), ">= 1." + chr(0xE9), ">=\t1"):
            with self.subTest(invalid=text):
                self.assertFalse(ok(text))

    def test_a_coding_comment_must_be_exactly_utf_8(self):
        # Item 3: Ruby's magic comment allows spaces round the separator.
        lit = self.LIT
        for comment in ("#  coding   :   bogus", "# coding  = bogus-enc",
                        "# -*- encoding : utf-16 -*-", "# coding : us-ascii",
                        "# coding: utf-8x", "# coding: utf-8.old", "# coding: utf8",
                        "# vim: set fileencoding=latin-1 :", "# CODING: SHIFT_JIS",
                        "# coding", "# coding utf-8", "#coding:ascii-8bit",
                        "# coding: utf-8 coding: big5", "# decoding notes"):
            for where in ("before", "inside", "after"):
                with self.subTest(comment=comment, where=where):
                    gemspec = {"before": comment + "\n" + self._spec(lit),
                               "inside": self._spec("  " + comment + "\n" + lit),
                               "after": self._spec(lit) + comment + "\n"}[where]
                    self.assertIsNone(self._probe(self.PATH, gemspec=gemspec))
        for comment in ("# coding: utf-8", "# encoding: UTF-8", "#coding:utf-8",
                        "# -*- coding : utf-8 -*-", "# encoding  =  Utf-8",
                        "# vim: set fileencoding=utf-8 :", "# coding: utf-8 encoding: utf-8",
                        "# nothing about it"):
            with self.subTest(utf8=comment):
                self.assertEqual("first_party", self._probe(
                    self.PATH, gemspec=comment + "\n" + self._spec(lit)))

    def test_a_numbered_parameter_is_not_a_block_variable(self):
        # Item 7: Ruby 3 reserves _1 to _9.
        for var, expected in (("_1", None), ("_9", None), ("_0", "first_party"),
                              ("_10", "first_party"), ("_a", "first_party"),
                              ("_", "first_party")):
            with self.subTest(var=var):
                gemspec = ("Gem::Specification.new do |%s|\n" % var
                           + self.LIT.replace("s.", var + ".") + "end\n")
                self.assertEqual(expected, self._probe(self.PATH, gemspec=gemspec))

    def test_an_escape_is_never_read_as_its_own_text(self):
        # A lock name may hold a backslash; `"fo\x6f"` is `foo` to Ruby, not that text.
        name = "fo\\x6f"
        lock = self.PATH.replace("foo (1.0)", name + " (1.0)")
        for quote in ('"', "'"):
            with self.subTest(quote=quote):
                gemspec = self._spec("  s.name = %s%s%s\n  s.version = \"1.0\"\n"
                                     % (quote, name, quote))
                self.assertIsNone(self._probe(lock, gemspec=gemspec, package=(name, "1.0")))

    def test_a_version_that_is_not_a_string_proves_nothing(self):
        lock = self.PATH.replace("foo (1.0)", "foo (1)")
        self.assertEqual("first_party", self._probe(
            lock, gemspec=_gemspec("foo", "1"), package=("foo", "1")))
        for version in ("1", '["1"]', "true"):
            with self.subTest(version=version):
                gemspec = self._spec('  s.name = "foo"\n  s.version = %s\n' % version)
                self.assertIsNone(self._probe(lock, gemspec=gemspec, package=("foo", "1")))
                self.assertIsNone(self._probe(
                    self.PATH.replace("foo (1.0)", "foo (true)"), gemspec=gemspec,
                    package=("foo", "true")))

    def test_the_gemspec_listing_is_bounded(self):
        base = os.path.join(self.root, "gems", "foo")
        for extra in range(3):
            _write(os.path.join(base, "lib", "f%d.rb" % extra), "x")
        self._probe(self.PATH)
        # gems/foo holds foo.gemspec and lib/ (2), and lib/ holds 3 files: 5 entries.
        for cap, expected in ((5, "first_party"), (4, None), (2, None)):
            with self.subTest(cap=cap), \
                    mock.patch.object(first_party_advisory, "MAX_GEMSPEC_SCAN_ENTRIES", cap):
                self.assertEqual(expected, self._origin(self.FOO))
        self.assertEqual(65536, first_party_advisory.MAX_GEMSPEC_SCAN_ENTRIES)
        # The cap holds for a flat directory too, with no subdirectory to count in.
        shutil.rmtree(os.path.join(base, "lib"))
        for extra in range(3):
            _write(os.path.join(base, "f%d.rb" % extra), "x")
        for cap, expected in ((4, "first_party"), (3, None)):
            with self.subTest(flat_cap=cap), \
                    mock.patch.object(first_party_advisory, "MAX_GEMSPEC_SCAN_ENTRIES", cap):
                self.assertEqual(expected, self._origin(self.FOO))

    def test_the_lock_holds_exact_indents_markers_and_versions(self):
        good = ("PATH\n  remote: gems/foo\n  specs:\n    foo (1.0)\n      rack (~> 2.2)\n"
                "      json\n\n" + self._gem("    rack (2.2.3)\n      webrick\n    json (2.0)\n"))
        self.assertEqual("first_party", self._probe(good))
        for label, lock in (
                ("a seven-space dependency",
                 good.replace("      webrick\n", "       webrick\n")),
                ("a seven-space spec hiding a copy",
                 good.replace("      webrick\n", "       foo (1.0)\n")),
                ("an eight-space line", good.replace("      json\n", "        json\n")),
                ("a five-space line", good.replace("      json\n", "     json\n")),
                ("a three-space line", good.replace("  specs:\n    foo", "   specs:\n    foo")),
                ("a dependency with trailing text",
                 good.replace("      rack (~> 2.2)\n", "      rack (~> 2.2) x\n")),
                ("a dependency with two names",
                 good.replace("      json\n\n", "      json rpc\n\n")),
                ("an unclosed dependency constraint",
                 good.replace("      rack (~> 2.2)\n", "      rack (~> 2.2\n")),
                ("specs with a value", good.replace("  specs:\n    foo", "  specs: junk\n    foo")),
                ("specs with a trailing space",
                 good.replace("  specs:\n    foo", "  specs: \n    foo")),
                ("a GEM specs with a value",
                 good.replace("  specs:\n    rack", "  specs: x\n    rack")),
                ("a valued specs with nothing under it",
                 good + "\nGIT\n  remote: https://example.invalid/x.git\n  specs: junk\n"),
                # Item 6: Bundler raises on a source with no remote, or a spaced one.
                ("a second PATH with no remote", good + "\nPATH\n  specs:\n    bar (1.0)\n"),
                ("a GIT with no remote", good + "\nGIT\n  revision: abc\n  specs:\n"),
                ("a spaced GEM remote",
                 good.replace("remote: https://rubygems.org/", "remote: https://rubygems.org/ junk")),
                ("a spaced PATH remote", good.replace("remote: gems/foo", "remote: gems/foo x")),
                ("a dependency before any spec",
                 good + "\nGIT\n  remote: https://example.invalid/x.git\n  specs:\n"
                        "      rack\n")):
            with self.subTest(lock=label):
                self.assertNotEqual(good, lock)
                self.assertIsNone(self._probe(lock))
        # A version RubyGems rejects, on an unrelated spec, fails the whole lock.
        # Item 5: digits and letters are ASCII, as RubyGems' pattern is.
        for version in ("x", ".1", "1.", "1..0", "a.1", "1.0!", "1.0_1", "1.0-", "-java",
                        "1.0-x86 64", "v1.0", "1.0+1", "1,0", chr(0x661) + ".2",
                        "1." + chr(0xE9), "1." + chr(0x662), "1.0-jav" + chr(0xE9),
                        chr(0xB2), "1." + chr(0xB2)):
            with self.subTest(version=version):
                self.assertIsNone(self._probe(
                    good.replace("    json (2.0)\n", "    json (%s)\n" % version)))
        for version in ("0", "2", "1.0.0.pre.1", "1.0a", "1.0.0.rc1", "1.0-java",
                        "1.0-x86_64-linux-musl", "1.0.0.beta-arm64-darwin-23",
                        "1.0-x64-mingw-ucrt"):
            with self.subTest(valid=version):
                self.assertEqual("first_party", self._probe(
                    good.replace("    json (2.0)\n", "    json (%s)\n" % version)))

    def test_a_copy_rubygems_reads_as_the_same_version_is_ambiguous(self):
        # Item 3: RubyGems satisfies `= 1.2.0` with 1.2, so they are one release.
        path = "PATH\n  remote: gems/foo\n  specs:\n    foo (1.2.0)\n\n"
        gemspec = _gemspec("foo", "1.2.0")
        package = ("foo", "1.2.0")
        for copy, expected in (("1.2", None), ("1.2.0.0", None), ("1.2.0", None),
                               ("1.2.0-java", None), ("1.2-java", None),
                               ("1.2.0.0-x86_64-linux", None),
                               ("1.2.1", "first_party"), ("1.20", "first_party"),
                               ("1.2.0.1", "first_party"), ("1.2.0.pre", "first_party"),
                               ("1.2.a", "first_party"), ("10.2.0", "first_party")):
            with self.subTest(copy=copy):
                self.assertEqual(expected, self._probe(
                    path + self._gem("    foo (%s)\n" % copy), gemspec=gemspec,
                    package=package))
        # Prerelease twins: 1.2.0.pre is 1.2.pre, and 1.0.a.0 is 1.0.a.
        for local, copy in (("1.2.0.pre", "1.2.pre"), ("1.0.a", "1.0.a.0"),
                            ("1.0.0.rc1", "1.rc1")):
            with self.subTest(local=local, copy=copy):
                lock = path.replace("foo (1.2.0)", "foo (%s)" % local)
                self.assertEqual("first_party", self._probe(
                    lock + self._gem("    rack (2.0)\n"), gemspec=_gemspec("foo", local),
                    package=("foo", local)))
                self.assertIsNone(self._probe(
                    lock + self._gem("    foo (%s)\n" % copy), gemspec=_gemspec("foo", local),
                    package=("foo", local)))
        # A second local spelling of the release is ambiguous too.
        twin = "PATH\n  remote: gems/twin\n  specs:\n    foo (1.2)\n\n"
        _write(os.path.join(self.root, "gems", "twin", "foo.gemspec"), _gemspec("foo", "1.2"))
        self.assertIsNone(self._probe(path + twin, gemspec=gemspec, package=package))
        self.assertIsNone(self._probe(path + twin, gemspec=gemspec, package=("foo", "1.2")))

    def test_a_remote_bundler_expands_elsewhere_is_refused(self):
        # Item 4: Bundler expands the remote, so `~` is $HOME and `..` is lexical. A
        # literal `~` directory in the tree, or a path through `..`, is not what it reads.
        for remote in ("~/gems/foo", "~", "~root/gems/foo", "gems/../gems/foo", "./../x/gems/foo",
                       "gems/foo/..", "..", "gems/foo/../foo"):
            with self.subTest(remote=remote):
                target = os.path.normpath(os.path.join(self.root, remote))
                if target.startswith(self.root + os.sep):
                    _write(os.path.join(target, "foo.gemspec"), _gemspec(*self.FOO))
                _write(os.path.join(self.root, "~", "gems", "foo", "foo.gemspec"),
                       _gemspec(*self.FOO))
                lock = self.PATH.replace("remote: gems/foo", "remote: " + remote)
                self.assertIsNone(self._probe(lock))
        self.assertEqual("first_party", self._probe(
            self.PATH.replace("remote: gems/foo", "remote: ./gems/foo")))

    def test_the_gemspec_set_is_bundlers_glob(self):
        # Item 5: Bundler globs `{,*,*/*}.gemspec` with no dot-matching.
        base = os.path.join(self.root, "gems", "foo")
        private = _gemspec(*self.FOO, extra='  s.metadata["allowed_push_host"] = '
                                            '"https://gems.example.internal"\n')

        def reset(**files):
            shutil.rmtree(base, ignore_errors=True)
            for rel, text in files.items():
                _write(os.path.join(base, rel), text)
            with open(os.path.join(self.root, "Gemfile.lock"), "w", encoding="utf-8") as fh:
                fh.write(self.PATH)
            _write(os.path.join(self.root, "app.gemspec"), _gemspec("app", "0.1"))
            return self._origin(self.FOO)

        good = _gemspec(*self.FOO)
        self.assertEqual("first_party", reset(**{"foo.gemspec": good}))
        # One level down is in the glob: a second manifest there is ambiguous.
        self.assertIsNone(reset(**{"foo.gemspec": good, "real/foo.gemspec": private}))
        self.assertIsNone(reset(**{"foo.gemspec": good, "real/other.gemspec": good}))
        # ...and a sole one there is the manifest Bundler uses.
        self.assertEqual("first_party", reset(**{"real/foo.gemspec": good}))
        self.assertIsNone(reset(**{"real/foo.gemspec": private}))
        # Two levels down is not in the glob.
        self.assertEqual("first_party",
                         reset(**{"foo.gemspec": good, "a/b/foo.gemspec": private}))
        self.assertIsNone(reset(**{"a/b/foo.gemspec": good}))
        # Dot-prefixed names and directories are not matched...
        self.assertEqual("first_party",
                         reset(**{"foo.gemspec": good, ".hidden.gemspec": private,
                                  ".git/foo.gemspec": private, "real/.x.gemspec": private}))
        self.assertIsNone(reset(**{".hidden.gemspec": good}))
        self.assertIsNone(reset(**{".git/foo.gemspec": good}))
        # ...except the literal `.gemspec`, which the glob's empty alternative names.
        self.assertIsNone(reset(**{"foo.gemspec": good, ".gemspec": private}))
        self.assertEqual("first_party", reset(**{".gemspec": good}))
        # Item 4: on a case-insensitive filesystem Ruby's glob matches any case.
        for other in ("X.GEMSPEC", "x.Gemspec", "real/B.GemSpec", ".GEMSPEC"):
            with self.subTest(other=other):
                self.assertIsNone(reset(**{"foo.gemspec": good, other: private}))
        self.assertEqual("first_party", reset(**{"FOO.GEMSPEC": good}))
        self.assertEqual("first_party", reset(**{"real/Foo.Gemspec": good}))
        # ...and only here: one level down the glob is `*/*.gemspec`.
        self.assertEqual("first_party",
                         reset(**{"foo.gemspec": good, "real/.gemspec": private}))
        # A file that only ends like one is not matched; a DIRECTORY named like one is
        # (the glob does not ask what it matched), so Bundler would fail on it.
        self.assertEqual("first_party",
                         reset(**{"foo.gemspec": good, "foo.gemspec.bak": private,
                                  "real/foo.gemspecs": private}))
        self.assertIsNone(reset(**{"foo.gemspec": good, "x.gemspec/readme": "x"}))
        self.assertIsNone(reset(**{"foo.gemspec": good, "real/x.gemspec/readme": "x"}))
        # A subdirectory that resolves out of the tree is never listed.
        outside = tempfile.mkdtemp(prefix="outside-")
        self.addCleanup(shutil.rmtree, outside, ignore_errors=True)
        _write(os.path.join(outside, "x.txt"), "x")
        reset(**{"foo.gemspec": good})
        os.symlink(outside, os.path.join(base, "linked"))
        self.assertIsNone(self._origin(self.FOO))

    def test_one_trailing_slash_and_no_more(self):
        # Item 8.
        for host, expected in (("https://rubygems.org", "first_party"),
                               ("https://rubygems.org/", "first_party"),
                               ("https://rubygems.org//", None),
                               ("https://rubygems.org///", None),
                               ("https://rubygems.org/ ", None),
                               ("/https://rubygems.org", None)):
            with self.subTest(host=host):
                gemspec = self._spec(self.LIT + '  s.metadata["allowed_push_host"] = "%s"\n'
                                     % host)
                self.assertEqual(expected, self._probe(self.PATH, gemspec=gemspec))

    def test_only_osv_scanner_and_trivy_classify(self):
        # Item 9: the whole adapter set, not one member of it.
        self._probe(self.PATH)
        marking = {name for name in sorted(tools.ADVISORY_ADAPTERS | {"trivy"})
                   if self._origin(self.FOO, source="tool:" + name) == "first_party"}
        self.assertEqual({"osv-scanner", "trivy"}, marking)

    def test_a_url_remote_is_not_a_directory_of_that_name(self):
        # Item 9: `https://x/gems/foo` normalises to an in-tree `https:/x/gems/foo`.
        for remote in ("https://example.invalid/gems/foo", "https:/example.invalid/gems/foo",
                       "file:gems/foo", "git+ssh://example.invalid/foo"):
            with self.subTest(remote=remote):
                _write(os.path.join(self.root, os.path.normpath(remote), "foo.gemspec"),
                       _gemspec(*self.FOO))
                self.assertIsNone(self._probe(
                    self.PATH.replace("remote: gems/foo", "remote: " + remote)))

    def test_odd_whitespace_fails_the_lock_wherever_it_sits(self):
        # Item 9: in a section the parser otherwise skips, where no header or spec
        # rule could be what refuses it.
        skipped = "PLATFORMS\n  ruby%s\n\nDEPENDENCIES\n  foo!\n"
        self.assertEqual("first_party", self._probe(self.PATH + skipped % ""))
        for label, char in (("tab", "\t"), ("bom", chr(0xFEFF)), ("form feed", "\x0c"),
                            ("carriage return", "\r"), ("nbsp", chr(0xA0)),
                            ("line separator", chr(0x2028))):
            with self.subTest(char=label):
                self.assertIsNone(self._probe(self.PATH + skipped % (char + "x")))
                self.assertIsNone(self._probe(self.PATH + skipped % char))

    def test_a_plugin_source_copy_is_external(self):
        # Item 9: PLUGIN SOURCE is never local, even with a relative in-tree remote.
        plugin = "PLUGIN SOURCE\n  remote: gems/foo\n  type: path\n  specs:\n    foo (1.0)\n\n"
        self.assertIsNone(self._probe(self.PATH + plugin))
        self.assertIsNone(self._probe(plugin))
        # Even shaped exactly like a PATH source: no option but `remote`.
        self.assertIsNone(self._probe(plugin.replace("  type: path\n", "")))
        self.assertEqual("first_party", self._probe(
            self.PATH + plugin.replace("foo (1.0)", "bar (1.0)")))

    def test_the_confirmation_names_ruby_not_cargo(self):
        # Item 6: the exported reasoning named Cargo for every ecosystem.
        self._probe(self.PATH)
        for source in ("tool:osv-scanner", "tool:trivy"):
            with self.subTest(source=source):
                finding = self._mark(self.FOO, source=source)
                self.assertTrue(evidence.is_first_party_advisory(finding))
                reasoning = evidence.derive_evidence(finding)["reasoning"]
                self.assertIn("in-tree publishable Ruby path gem", reasoning)
                self.assertNotIn("Cargo", reasoning)


if __name__ == "__main__":
    unittest.main()
