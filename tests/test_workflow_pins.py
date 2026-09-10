"""ARC-F2A (#1517): SHA-pinning every GitHub Actions reference is this repo's
compensating control for the mutable-tag supply-chain risk, and it had a scope
blind spot -- 29 of 30 `uses:` lines were pinned, and the unpinned one sat in
the job carrying the widest write scope in the fleet (pin-freshness.yml:
`contents: write` + `pull-requests: write`, and it pushes branches and opens
PRs).

The convention was unwritten and unanimous, which is exactly the shape that
drifts: nothing failed when the thirtieth reference was added without a pin.
This module writes the convention down as a test, so the control's scope is the
whole directory rather than whichever lines someone remembered.
"""
import os
import re
import unittest

import yaml

from conftest import REPO_ROOT

WORKFLOW_DIR = os.path.join(REPO_ROOT, ".github", "workflows")

# A step's `uses:` with its trailing version comment kept. YAML drops the
# comment, so the raw line is the only place it can be read -- and the comment
# is what makes a 40-hex pin bumpable by a human or by Dependabot.
_USES_LINE = re.compile(
    r"^\s*(?:-\s+)?uses:\s*(?P<ref>\S+)(?:\s+#\s*(?P<comment>.*?))?\s*$")

_SHA_PINNED = re.compile(r"^[^@\s]+@[0-9a-f]{40}$")
_DIGEST_PINNED = re.compile(r"^docker://[^@\s]+@sha256:[0-9a-f]{64}$")


def pin_defect(ref, comment):
    """Why this `uses:` reference is unpinned, or None if it is fine.

    Three accepted shapes: a repo-local action (`./...`, no supply chain to
    pin), a container reference pinned by digest, and the usual
    `owner/repo[/path]@<40-hex sha>` carrying a version comment.
    """
    if ref.startswith("./"):
        return None
    if ref.startswith("docker://"):
        if not _DIGEST_PINNED.match(ref):
            return "container reference is not pinned to an @sha256: digest"
        return None
    if "@" not in ref:
        return "no version reference at all"
    if not _SHA_PINNED.match(ref):
        return ("pinned to the mutable tag %r, not a 40-hex commit SHA"
                % ref.split("@", 1)[1])
    if not comment:
        return ("pinned to a SHA with no `# vX.Y.Z` comment, so nobody can "
                "tell what version it is or when to bump it")
    return None


def scan_uses(text):
    """[(lineno, ref, comment)] for every `uses:` key in a workflow's text."""
    found = []
    for n, line in enumerate(text.splitlines(), 1):
        m = _USES_LINE.match(line)
        if m:
            found.append((n, m.group("ref"), m.group("comment")))
    return found


def _yaml_uses(doc):
    """Every `uses:` value the YAML parser sees, from the two places one can
    appear: a job's steps, and a job that calls a reusable workflow."""
    refs = []
    for job in (doc.get("jobs") or {}).values():
        if not isinstance(job, dict):
            continue
        if isinstance(job.get("uses"), str):
            refs.append(job["uses"])
        for step in job.get("steps") or []:
            if isinstance(step, dict) and isinstance(step.get("uses"), str):
                refs.append(step["uses"])
    return refs


def _workflow_files():
    return sorted(
        os.path.join(WORKFLOW_DIR, n) for n in os.listdir(WORKFLOW_DIR)
        if n.endswith((".yml", ".yaml")))


class TestPinDefectRule(unittest.TestCase):
    """The rule itself, exercised on both answers. A guard that only ever runs
    over a clean tree cannot fail, so it proves nothing until something proves
    it can say no."""

    def test_floating_tag_is_a_defect(self):
        self.assertIn("mutable tag", pin_defect("actions/checkout@v7", None))

    def test_bare_action_with_no_ref_is_a_defect(self):
        self.assertIn("no version reference",
                      pin_defect("actions/checkout", None))

    def test_sha_without_a_version_comment_is_a_defect(self):
        self.assertIn("no `# vX.Y.Z` comment",
                      pin_defect("actions/checkout@" + "3" * 40, None))

    def test_sha_with_a_version_comment_is_accepted(self):
        self.assertIsNone(pin_defect("actions/checkout@" + "3" * 40, "v7.0.1"))

    def test_repo_local_action_is_exempt(self):
        self.assertIsNone(pin_defect("./.github/actions/setup", None))

    def test_container_reference_must_carry_a_digest(self):
        self.assertIn("digest", pin_defect("docker://alpine:3.20", None))
        self.assertIsNone(
            pin_defect("docker://alpine@sha256:" + "a" * 64, None))


class TestEveryActionReferenceIsPinned(unittest.TestCase):
    def test_no_unpinned_uses_in_any_workflow(self):
        defects = []
        for path in _workflow_files():
            with open(path, encoding="utf-8") as fh:
                text = fh.read()
            for lineno, ref, comment in scan_uses(text):
                why = pin_defect(ref, comment)
                if why:
                    defects.append("%s:%d %s -- %s"
                                   % (os.path.basename(path), lineno, ref, why))
        self.assertEqual([], defects, "unpinned action references:\n" +
                         "\n".join(defects))

    def test_the_fleet_is_actually_being_scanned(self):
        # Guards the guard: a regex that silently matched nothing would let
        # every workflow through while reporting a clean pass.
        total = sum(len(scan_uses(open(p, encoding="utf-8").read()))
                    for p in _workflow_files())
        self.assertGreater(total, 25, "workflow scan found almost no `uses:` "
                                      "lines; the scanner is broken, not the tree")

    def test_raw_scan_sees_every_uses_the_yaml_parser_does(self):
        # The pin rule reads raw lines (only there is the version comment
        # visible), so it can only be trusted while the raw scan and the parsed
        # document agree on which references exist.
        for path in _workflow_files():
            with open(path, encoding="utf-8") as fh:
                text = fh.read()
            doc = yaml.safe_load(text) or {}
            self.assertEqual(
                sorted(_yaml_uses(doc)),
                sorted(ref for _, ref, _ in scan_uses(text)),
                "raw `uses:` scan disagrees with the parsed workflow in %s"
                % os.path.basename(path))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
