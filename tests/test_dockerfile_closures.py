"""#1734 (SEC-E2A): the package-manager installs pin the WHOLE closure.

Split out of `test_dockerfile.py`, which these rules pushed past the 700-line
ceiling. They travel together and away from the rest: everything here reads the
Dockerfile as a SHELL SCRIPT -- folding continuations and dropping prose --
where its sibling reads the same file as a sequence of instructions and
asserts on literals. One reader, one subject, one file.
"""
import json
import os
import re
import unittest

from test_dockerfile import ROOT, _logical_lines, _read_dockerfile


def dockerfile_commands(text):
    """Every instruction in a Dockerfile as one string, prose removed.

    Docker drops a whole `#` line even inside a `\\`-continuation -- which is
    how the gosec-verify block explains itself mid-command -- so those lines go
    BEFORE continuations are folded here, and the fold sees what the builder
    sees. The file documents its own registry policy in prose that names the
    exact commands the rules below forbid, so a reader that kept the comments
    would fire on the fix rather than on a regression.
    """
    body = "\n".join(ln for ln in text.splitlines()
                      if not ln.lstrip().startswith("#"))
    return [joined for _n, joined in _logical_lines(body) if joined]


_PIP_INSTALL = re.compile(r"\bpip\d?\s+(?:-\S+\s+)*install\b")
_GEM_INSTALL = re.compile(r"\bgem\s+install\b")
_NPM_INSTALL = re.compile(r"\bnpm\s+(?:\S+\s+)*install\b")
_NPM_CI = re.compile(r"\bnpm\s+(?:\S+\s+)*ci\b")



class TestRegistryClosuresArePinned(unittest.TestCase):
    """#1734 (SEC-E2A): the package-manager installs pin the WHOLE closure.

    The release-binary fetches in this file have been checksum-gated for a
    year; `pip install semgrep==X`, `gem install brakeman:X` and `npm install
    -g eslint@X` were not. Each pinned only the NAMED distribution, so every
    transitive dependency resolved fresh from PyPI/RubyGems/npm at build time,
    as root, into an image that is published publicly, rebuilt daily, and used
    as the trust root of every scan this project runs against somebody else's
    code. A single compromised transitive release executes its install-time
    code in that build and is then baked into what downstream repos pull.

    Each rule below is the enforced half of a sentence in the Dockerfile's
    registry-policy comment; they are written as rules rather than as literal
    assertions because the defect they exist to catch is a NEW install arriving
    in the weaker shape, not an edit to the three lines that were fixed.
    """

    def setUp(self):
        self.text = _read_dockerfile()
        self.commands = dockerfile_commands(self.text)

    # --- the readers say no before they are believed when they say yes ------

    def test_the_readers_see_the_shapes_they_forbid(self):
        hostile = ("RUN pip install --no-cache-dir semgrep==1.0.0\n"
                   "RUN gem install --no-document brakeman:8.0.6\n"
                   "RUN npm install --fetch-timeout=600000 -g eslint@10.9.0\n")
        found = dockerfile_commands(hostile)
        self.assertEqual(3, len(found), found)
        self.assertTrue(_PIP_INSTALL.search(found[0]), found[0])
        self.assertTrue(_GEM_INSTALL.search(found[1]), found[1])
        self.assertTrue(_NPM_INSTALL.search(found[2]), found[2])

    def test_prose_naming_a_forbidden_command_is_not_a_command(self):
        # The policy comment quotes `pip install`, `gem install` and `npm
        # install -g` to say what is no longer allowed; so does the semgrep
        # outage note. Reading those as installs would make every rule here
        # fire on its own documentation -- and a contributor would "fix" it by
        # deleting the explanation.
        prose = ("# the old line was `pip install semgrep==1.0.0`\n"
                 "RUN echo ok \\\n"
                 "    # and `npm install -g eslint` before that\n"
                 "    && echo done\n")
        found = dockerfile_commands(prose)
        self.assertEqual(["RUN echo ok && echo done"], found)

    # --- pip ----------------------------------------------------------------

    def test_every_pip_install_requires_hashes(self):
        installs = [c for c in self.commands if _PIP_INSTALL.search(c)]
        self.assertTrue(installs, "no pip install found in the Dockerfile; the "
                                  "reader is broken, not the file")
        for cmd in installs:
            self.assertIn(
                "--require-hashes", cmd,
                "a pip install that does not pass --require-hashes resolves "
                "its transitive closure fresh from PyPI as root:\n  %s" % cmd)

    def test_the_pip_closure_is_the_complete_list_not_a_starting_point(self):
        installs = [c for c in self.commands if _PIP_INSTALL.search(c)]
        for cmd in installs:
            self.assertIn(
                "--no-deps", cmd,
                "--require-hashes without --no-deps still lets pip WIDEN the "
                "set; the file has to be the whole list:\n  %s" % cmd)
            self.assertRegex(cmd, r"-r\s+/tmp/requirements-tools\.txt",
                             "pip installs from something other than the "
                             "committed closure:\n  %s" % cmd)
        self.assertIn("COPY requirements-tools.txt /tmp/requirements-tools.txt",
                      self.text,
                      "the closure is installed from a path the repo does not "
                      "COPY into the image")

    def test_the_declared_pip_versions_match_the_pinned_closure(self):
        # The ARGs stay because a version belongs beside the tool it names, but
        # an ARG nothing checks is a second source of truth: bumping
        # SEMGREP_VERSION alone would leave the image installing the old
        # semgrep while the file claims the new one.
        with open(os.path.join(ROOT, "requirements-tools.txt"),
                  encoding="utf-8") as fh:
            pinned = dict(re.findall(r"^([A-Za-z0-9._-]+)==(\S+?)\s*\\?$",
                                     fh.read(), re.M))
        for arg, name in (("SEMGREP_VERSION", "semgrep"),
                          ("BANDIT_VERSION", "bandit"),
                          ("BANDIT_SARIF_FORMATTER_VERSION",
                           "bandit-sarif-formatter"),
                          ("PIP_AUDIT_VERSION", "pip-audit")):
            m = re.search(r"^ARG %s=(\S+)\s*$" % arg, self.text, re.M)
            self.assertIsNotNone(m, "no ARG %s" % arg)
            self.assertEqual(
                pinned.get(name), m.group(1),
                "ARG %s says %s but requirements-tools.txt pins %s==%s; bump "
                "both, and re-run `python3 scripts/bump_pins.py requirements "
                "--file requirements-tools.txt --write`"
                % (arg, m.group(1), name, pinned.get(name)))

    # --- gem ----------------------------------------------------------------

    def test_every_gem_install_is_a_verified_local_file(self):
        installs = [c for c in self.commands if _GEM_INSTALL.search(c)]
        self.assertTrue(installs, "no gem install found in the Dockerfile")
        for cmd in installs:
            self.assertIn("--local", cmd,
                          "a gem install without --local reaches RubyGems and "
                          "resolves whatever it likes:\n  %s" % cmd)
            self.assertIn("--ignore-dependencies", cmd,
                          "without --ignore-dependencies the resolver runs "
                          "anyway for anything the .gem requires:\n  %s" % cmd)
            self.assertNotRegex(
                cmd, r"gem install[^&|]*\s[A-Za-z0-9_-]+:[0-9]",
                "the `name:version` form is a REGISTRY install; pass a "
                "downloaded, checksum-verified .gem file:\n  %s" % cmd)

    def test_every_gem_download_is_checksum_verified(self):
        # Same shape as the release binaries above: an ARG holding the digest
        # upstream published (and bump_pins re-verified), and a `sha256sum -c`
        # the build dies on. .gem files are platform-independent, so one digest
        # covers both published architectures.
        args = dict(re.findall(r"^ARG ([A-Z0-9_]+_GEM_SHA256)=(\S+)\s*$",
                               self.text, re.M))
        self.assertTrue(args, "no gem digest is pinned at all")
        for arg, value in sorted(args.items()):
            self.assertRegex(value, r"^[0-9a-f]{64}$",
                             "%s is not a sha256" % arg)
        fetched = set(re.findall(r"-o\s+(/tmp/[\w.-]+\.gem)", self.text))
        self.assertTrue(fetched, "no .gem is downloaded to a file to verify")
        self.assertEqual(
            len(fetched), len(args),
            "%d .gem download(s) but %d pinned digest(s): %s vs %s"
            % (len(fetched), len(args), sorted(fetched), sorted(args)))
        for path in sorted(fetched):
            self.assertRegex(
                self.text, re.escape(path) + r'"\s*\|\s*sha256sum -c',
                "%s is downloaded but never sha256sum-verified" % path)

    # --- npm ----------------------------------------------------------------

    def test_node_packages_come_from_npm_ci_not_npm_install(self):
        offenders = [c for c in self.commands if _NPM_INSTALL.search(c)]
        self.assertEqual(
            [], offenders,
            "`npm install` resolves and may WRITE a lockfile; only `npm ci` "
            "installs exactly what the committed package-lock.json "
            "says:\n  %s" % "\n  ".join(offenders))
        ci = [c for c in self.commands if _NPM_CI.search(c)]
        self.assertTrue(ci, "the image installs no node packages at all")
        for cmd in ci:
            self.assertIn(
                "--ignore-scripts", cmd,
                "npm ci without --ignore-scripts runs install-time code from "
                "every package in the tree, as root:\n  %s" % cmd)

    def test_the_node_closure_is_copied_from_the_repo(self):
        self.assertIn("COPY tools-image/node/package.json "
                      "tools-image/node/package-lock.json "
                      "/opt/panopticon-node/", self.text,
                      "npm ci needs BOTH files from the repo; a lockfile "
                      "generated in the image is not a reviewed one")
        self.assertIn('ENV PATH="/opt/panopticon-node/node_modules/.bin:'
                      '${PATH}"', self.text,
                      "eslint is installed where nothing can find it")

    def test_the_declared_node_versions_match_the_lockfile(self):
        with open(os.path.join(ROOT, "tools-image", "node", "package.json"),
                  encoding="utf-8") as fh:
            deps = json.load(fh)["dependencies"]
        for arg, name in (("ESLINT_VERSION", "eslint"),
                          ("ESLINT_PLUGIN_SECURITY_VERSION",
                           "eslint-plugin-security"),
                          ("ESLINT_FORMATTER_SARIF_VERSION",
                           "@microsoft/eslint-formatter-sarif")):
            m = re.search(r"^ARG %s=(\S+)\s*$" % arg, self.text, re.M)
            self.assertIsNotNone(m, "no ARG %s" % arg)
            self.assertEqual(
                deps.get(name), m.group(1),
                "ARG %s says %s but tools-image/node/package.json asks for %s; "
                "bump both and re-run `npm install --package-lock-only "
                "--ignore-scripts`" % (arg, m.group(1), deps.get(name)))

    def test_the_lockfile_pins_every_package_by_integrity(self):
        with open(os.path.join(ROOT, "tools-image", "node",
                               "package-lock.json"), encoding="utf-8") as fh:
            lock = json.load(fh)
        packages = lock.get("packages") or {}
        # "" is the project itself, which has no artifact to hash.
        missing = sorted(name for name, entry in packages.items()
                         if name and not entry.get("integrity"))
        self.assertEqual([], missing,
                         "package(s) the lockfile does not pin by digest: %s"
                         % ", ".join(missing))
        self.assertGreater(len(packages), 10,
                           "the lockfile lists almost nothing; it was "
                           "regenerated against an empty package.json")


if __name__ == "__main__":
    unittest.main()
