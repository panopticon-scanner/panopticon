"""#1774 (ARC-261650949): one tested reader for the Dockerfile's pinned ARGs.

Two workflow steps re-derived the dependency-check pins from the Dockerfile,
each with its own `grep -E '^ARG ...=' Dockerfile | head -1 | cut -d= -f2` and
its own inline shape check: `.github/workflows/nvd-cache.yml`'s "Read
dependency-check version from the Dockerfile" step (the version AND the SHA256
the release zip is checked against) and `.github/workflows/docker-publish.yml`'s
"Resolve NVD data image digest (content-pin the cache)" step (the version, to
name the `dc-<version>` cache tag it pins). Both now call
`scripts/dockerfile_args.py`.

The inline shape check is a security control, not tidiness -- nvd-cache.yml
spelled it "constrain to expected shapes so a tampered ARG can't inject
downstream" -- so consolidating the READ without the CHECK would have deleted a
guard. The check moved into the module, and this file is where it is tested.

The module is at least as strict as the two inline checks it replaces, and on
the version STRICTER: inline `^[0-9][0-9.]*$` also accepted `10.0.3.` and
`1..2`, and `cut -d= -f2` truncated a value carrying a second `=` to the part
before it (so `1.2.3=evil` passed the inline check as `1.2.3`, which is not what
the Dockerfile's ARG default says). Both differences are pinned below.
"""
import os
import subprocess
import sys
import tempfile
import unittest

import yaml

import dockerfile_args as da
from tests._test_helpers import REPO_ROOT

MODULE = os.path.join(REPO_ROOT, "scripts", "dockerfile_args.py")
WORKFLOWS = os.path.join(REPO_ROOT, ".github", "workflows")
SHA = "5263fbafb15010823364274b83e9a2219b654d00a557d92941c37736d4076ba4"


def _text(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def _dockerfile(version="10.0.3", sha=SHA, extra=""):
    return ("FROM scratch\n"
            "ARG DEPENDENCY_CHECK_VERSION=%s\n"
            "ARG DEPENDENCY_CHECK_SHA256=%s\n%s" % (version, sha, extra))


def _cli(arguments, cwd=REPO_ROOT):
    return subprocess.run(  # nosec B603
        [sys.executable, MODULE] + arguments,
        capture_output=True, text=True, timeout=60, cwd=cwd)


class ReadArgTest(unittest.TestCase):

    def test_a_registered_arg_reads_its_value(self):
        text = _dockerfile()
        self.assertEqual(da.read_arg(text, "DEPENDENCY_CHECK_VERSION"), "10.0.3")
        self.assertEqual(da.read_arg(text, "DEPENDENCY_CHECK_SHA256"), SHA)

    def test_the_first_matching_line_wins(self):
        # `head -1`'s reading, and the Dockerfile's own: the first ARG default
        # is the one a later stage inherits unless it redeclares it.
        text = _dockerfile() + "ARG DEPENDENCY_CHECK_VERSION=9.9.9\n"
        self.assertEqual(da.read_arg(text, "DEPENDENCY_CHECK_VERSION"), "10.0.3")

    def test_an_absent_arg_is_refused_and_named(self):
        with self.assertRaises(ValueError) as caught:
            da.read_arg("FROM scratch\n", "DEPENDENCY_CHECK_VERSION")
        self.assertIn("DEPENDENCY_CHECK_VERSION", str(caught.exception))

    def test_a_line_that_is_not_an_arg_declaration_is_not_read(self):
        # `^ARG <NAME>=` is the whole pattern, as it was in the grep: a comment,
        # an indented line, and a longer name that merely starts the same way
        # are all invisible to it.
        for line in ("# ARG DEPENDENCY_CHECK_VERSION=9.9.9\n",
                     "  ARG DEPENDENCY_CHECK_VERSION=9.9.9\n",
                     "ARG DEPENDENCY_CHECK_VERSION_NEXT=9.9.9\n",
                     "ENV DEPENDENCY_CHECK_VERSION=9.9.9\n"):
            with self.subTest(line=line):
                with self.assertRaises(ValueError):
                    da.read_arg("FROM scratch\n" + line,
                                "DEPENDENCY_CHECK_VERSION")

    def test_a_tampered_version_is_refused(self):
        for value in ("1.2.3; curl evil", "1.2.3 && rm -rf /", "$(id)",
                      "../../etc/passwd", "1.2.3\t", "1.2.3 ", "",
                      "latest", "1.2.3-SNAPSHOT"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError) as caught:
                    da.read_arg(_dockerfile(version=value),
                                "DEPENDENCY_CHECK_VERSION")
                self.assertIn("DEPENDENCY_CHECK_VERSION", str(caught.exception))

    def test_the_version_shape_is_stricter_than_the_inline_grep(self):
        # Inline `^[0-9][0-9.]*$` accepted these; the module does not. Neither
        # is a version, and the value goes on to name an image tag.
        for value in ("10.0.3.", "1..2", "10.0.3.."):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    da.read_arg(_dockerfile(version=value),
                                "DEPENDENCY_CHECK_VERSION")

    def test_a_value_carrying_a_second_equals_sign_is_refused_not_truncated(self):
        # `cut -d= -f2` handed the inline check `1.2.3` here and it passed,
        # while the Dockerfile's ARG default is the whole `1.2.3=evil`.
        with self.assertRaises(ValueError):
            da.read_arg(_dockerfile(version="1.2.3=evil"),
                        "DEPENDENCY_CHECK_VERSION")

    def test_a_sha256_that_is_not_64_lowercase_hex_is_refused(self):
        for value in (SHA[:63], SHA + "a", SHA.upper(), "z" * 64,
                      SHA[:63] + " ", ""):
            with self.subTest(value=value):
                with self.assertRaises(ValueError) as caught:
                    da.read_arg(_dockerfile(sha=value),
                                "DEPENDENCY_CHECK_SHA256")
                self.assertIn("DEPENDENCY_CHECK_SHA256", str(caught.exception))

    def test_an_unregistered_arg_is_refused_even_though_the_line_is_there(self):
        # Fail closed: the module exists to constrain values, so a name with no
        # shape is not a value it will hand back.
        text = _dockerfile(extra="ARG GO_VERSION=1.25.14\n")
        with self.assertRaises(ValueError) as caught:
            da.read_arg(text, "GO_VERSION")
        self.assertIn("GO_VERSION", str(caught.exception))
        self.assertNotIn("1.25.14", str(caught.exception))

    def test_every_registered_shape_is_anchored(self):
        # `read_arg` enforces with `fullmatch`, so an unanchored pattern would
        # still be checked end to end; the anchors keep the map readable as the
        # statement it is, and a future entry that drops them is a fail-open
        # shape the moment anyone reaches for `match`.
        for name, shape in sorted(da.SHAPES.items()):
            with self.subTest(arg=name):
                self.assertTrue(shape.pattern.startswith("^"), shape.pattern)
                self.assertTrue(shape.pattern.endswith("$"), shape.pattern)

    def test_the_refusal_message_is_one_line_and_cannot_start_a_log_command(self):
        # A tampered value reaches a runner log. One line, and never at the
        # start of it, so it cannot forge a `::error::` workflow command.
        with self.assertRaises(ValueError) as caught:
            da.read_arg(_dockerfile(version="::error::forged"),
                        "DEPENDENCY_CHECK_VERSION")
        message = str(caught.exception)
        self.assertEqual(len(message.splitlines()), 1, message)
        self.assertFalse(message.startswith("::"), message)


class RealDockerfileTest(unittest.TestCase):
    """The committed pins must satisfy the shapes CI reads them through, or the
    two workflows fail at their first step. This is that check, before CI."""

    def test_both_registered_args_pass_their_shapes_in_the_committed_dockerfile(self):
        text = _text(os.path.join(REPO_ROOT, "Dockerfile"))
        for name in sorted(da.SHAPES):
            with self.subTest(arg=name):
                self.assertRegex(da.read_arg(text, name),
                                 da.SHAPES[name].pattern)


class CommandLineTest(unittest.TestCase):

    def test_stdout_is_the_bare_value(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "Dockerfile")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(_dockerfile())
            result = _cli(["read-arg", "DEPENDENCY_CHECK_SHA256",
                           "--dockerfile", path])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, SHA + "\n")

    def test_a_refusal_exits_2_with_nothing_on_stdout(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "Dockerfile")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(_dockerfile(version="1.2.3; curl evil"))
            result = _cli(["read-arg", "DEPENDENCY_CHECK_VERSION",
                           "--dockerfile", path])
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertEqual(len(result.stderr.strip().splitlines()), 1,
                         result.stderr)
        self.assertIn("DEPENDENCY_CHECK_VERSION", result.stderr)

    def test_a_dockerfile_that_cannot_be_read_exits_2(self):
        with tempfile.TemporaryDirectory() as directory:
            result = _cli(["read-arg", "DEPENDENCY_CHECK_VERSION",
                           "--dockerfile",
                           os.path.join(directory, "absent")])
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")

    def test_the_default_dockerfile_is_the_working_directory_s(self):
        # The shape both workflow steps use: no `--dockerfile`, run from the
        # checkout root, which is where `grep ... Dockerfile` read it too.
        with tempfile.TemporaryDirectory() as directory:
            with open(os.path.join(directory, "Dockerfile"), "w",
                      encoding="utf-8") as fh:
                fh.write(_dockerfile(version="1.2.3"))
            result = _cli(["read-arg", "DEPENDENCY_CHECK_VERSION"],
                          cwd=directory)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "1.2.3\n")

    def test_the_committed_dockerfile_reads_through_the_cli_from_the_repo_root(self):
        result = _cli(["read-arg", "DEPENDENCY_CHECK_VERSION"])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            result.stdout.strip(),
            da.read_arg(_text(os.path.join(REPO_ROOT, "Dockerfile")),
                        "DEPENDENCY_CHECK_VERSION"))

    def test_an_unknown_mode_is_refused(self):
        result = _cli(["write-arg", "DEPENDENCY_CHECK_VERSION"])
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")


class WorkflowCallersTest(unittest.TestCase):
    """Both callers read the pins through the module, and a refusal still stops
    the step: the consolidation is only real while nothing greps the Dockerfile
    for an ARG again, and only safe while the reader's exit 2 fails the job."""

    CALLERS = (
        ("docker-publish.yml", "build",
         "Resolve NVD data image digest (content-pin the cache)",
         ("DEPENDENCY_CHECK_VERSION",)),
        ("nvd-cache.yml", "refresh",
         "Read dependency-check version from the Dockerfile",
         ("DEPENDENCY_CHECK_VERSION", "DEPENDENCY_CHECK_SHA256")),
    )

    def _step(self, workflow, job, name):
        with open(os.path.join(WORKFLOWS, workflow), encoding="utf-8") as fh:
            parsed = yaml.safe_load(fh)
        step = next((s for s in parsed["jobs"][job]["steps"]
                     if s.get("name") == name), None)
        self.assertIsNotNone(step, "%s has no %r step" % (workflow, name))
        return step

    def test_each_caller_reads_its_pins_through_the_module(self):
        for workflow, job, name, args in self.CALLERS:
            run = self._step(workflow, job, name)["run"]
            for arg in args:
                with self.subTest(workflow=workflow, arg=arg):
                    self.assertIn(
                        "python3 scripts/dockerfile_args.py read-arg %s" % arg,
                        run)

    def test_a_refusal_fails_the_step(self):
        # The reader exits 2; `set -e` is what turns that into a failed job, and
        # a failed command substitution in an assignment carries its status.
        for workflow, job, name, _args in self.CALLERS:
            with self.subTest(workflow=workflow):
                self.assertIn("set -euo pipefail",
                              self._step(workflow, job, name)["run"])

    def test_neither_caller_greps_the_dockerfile_for_an_arg_any_more(self):
        # Whole file, not just the step: a second reader anywhere in it is the
        # duplication coming back. The offending lines are the message.
        for workflow, _job, _name, _args in self.CALLERS:
            with self.subTest(workflow=workflow):
                offenders = [line.strip() for line
                             in _text(os.path.join(WORKFLOWS, workflow)).splitlines()
                             if "^ARG " in line or "cut -d=" in line]
                self.assertEqual(
                    offenders, [],
                    "%s re-derives a Dockerfile ARG in shell; read it through "
                    "scripts/dockerfile_args.py, which shape-checks it:\n  %s"
                    % (workflow, "\n  ".join(offenders)))


if __name__ == "__main__":
    unittest.main()
