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
import ast
import copy
import importlib.metadata
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import yaml

from scripts import scanner_config
from tests._test_helpers import REPO_ROOT
from workflow_guard import UNNAMED, Step, fetches, job_defects, run_jobs
# #1641's comment-stripper, now `scripts/shell_reader.py`'s: half this repo's
# workflow and Dockerfile prose QUOTES the commands it explains -- including
# the two the install rule was written for -- and a guard that reads a comment
# as an act flags the explanation. One definition, two rules.
# `tests/test_security_workflow.py` imports this name from this module.
from shell_reader import without_comments as _without_comments
# #1697: the continuation-joiner and the statement split came from there too,
# rather than being hand-rolled a second time in this file.
from shell_reader import join_continuations
from shell_reader import statements as _statements
# #1655: the same parse, asked what a `docker run` line's FLAGS are --
# `_shell_command` is what makes `sudo docker run` read as `docker run`.
from shell_reader import command as _shell_command

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


# --- #1529 / #1647: fetch-and-exec inside a `run:` step ----------------------
# A workflow can reach outside the supply chain the pin rule above governs, by
# curling a binary and running it. The Dockerfile was hardened for exactly this
# (10 artifact fetches, all `sha256sum -c`'d) and `tests/test_dockerfile.py`
# guards it; nothing guarded the workflows, where the same act is written in
# shell instead of Dockerfile syntax.
#
# The RULE now lives in `scripts/workflow_guard.py`, and its unit spec in
# `tests/test_workflow_guard.py`. #1647 moved it: what stood here were two
# regexes that could not see `curl ... | sh` or `--output` as downloads at all,
# and accepted any `sha256sum -c` anywhere in the step as verification of every
# download in it -- both failing open, over every workflow in the fleet. What
# remains here is the fleet APPLICATION of that rule, beside the two sibling
# supply-chain rules (`uses:` pins above, `pip install` below) it shares a
# workflow reader and a posture check with. Applied per JOB, not per step:
# steps in a job share the workspace and /tmp, so `curl -o /tmp/x` in one step
# and `chmod +x /tmp/x; /tmp/x` in the next is one fetch-and-exec that no
# per-step reading can see -- and a checksum in a later step is a real check
# of an earlier step's download.
#
# (workflow, step name, why it may fetch and execute unverified) -- the step
# name is the one the DEFECT is reported against, which is the step that
# fetched (or, for an unparseable shell, the step that runs it). EMPTY, and
# the shape is here so it cannot be filled in silently: an exemption is a named
# step carrying a written reason, and it is checked in both directions below --
# one that stops firing is stale and fails, and a workflow that has become
# privileged may not hold one.
EXEMPT_FETCHES = ()


def fetch_exemption(workflow, step_name, entries=EXEMPT_FETCHES):
    """The entry excusing this step from the fetch rule, or None."""
    return next((e for e in entries if e[0] == workflow and e[1] == step_name),
                None)


def _run_jobs_in_repo():
    """[(workflow basename, job id, [Step, ...])] for the whole fleet."""
    jobs = []
    for path in _workflow_files():
        with open(path, encoding="utf-8") as fh:
            doc = yaml.safe_load(fh.read()) or {}
        for job, steps in run_jobs(doc):
            jobs.append((os.path.basename(path), job, steps))
    return jobs


def _fetch_defects_in_repo():
    """[(workflow, step name, why)] -- the rule, per JOB, across the fleet.

    Per job because that is the rule's scope (steps share the workspace, so a
    fetch in one step and its execution in another is one act); the defect is
    still reported against the step that fetched.
    """
    defects = []
    for workflow, _job, steps in _run_jobs_in_repo():
        for name, why in job_defects(steps):
            defects.append((workflow, name, why))
    return defects


class TestNoWorkflowFetchesAndExecutesUnverified(unittest.TestCase):
    def test_every_run_step_verifies_what_it_executes(self):
        defects = ["%s / %s -- %s" % (workflow, name, why)
                   for workflow, name, why in _fetch_defects_in_repo()
                   if not fetch_exemption(workflow, name)]
        self.assertEqual([], defects, "unverified fetch-and-exec:\n" +
                         "\n".join(defects))

    def test_the_fetch_scan_is_actually_seeing_the_downloads(self):
        # Guards the guard, and it is the #1647 defect itself: a parser that
        # returns an EMPTY fetch set reports a clean pass over every workflow
        # in the fleet. "No defects" is evidence only while the scan still
        # sees the two artifact downloads this repo has (hadolint in
        # docker-build-pr.yml, the DependencyCheck release in nvd-cache.yml).
        # `fetches` raises on a step the reader refuses, which has no answer
        # in its shape -- none is "no downloads" -- so `job_defects`, which
        # names such a step, is asked first (#2286).
        refused = ["%s / %s -- %s" % defect for defect in _fetch_defects_in_repo()
                   if defect[2].startswith("cannot read this step: ")]
        self.assertEqual([], refused, "the fetch scan cannot read these steps:\n" +
                         "\n".join(refused))
        found = [(w, f) for w, _j, steps in _run_jobs_in_repo()
                 for step in steps for f in fetches(step.script)]
        self.assertGreaterEqual(
            len(found), 2, "workflow fetch scan found almost nothing; the "
                           "scanner is broken, not the tree")
        self.assertTrue(all(f.url for _w, f in found),
                        "a fetch was seen with no URL parsed out of it: %s" % found)

    def test_a_step_the_reader_refuses_fails_the_scan_by_name(self):
        # The scan above ERRORED on such a step with a `shell_lex.Unreadable`
        # traceback that named no step, beside the gate test's named failure.
        steps = [Step("fetch", "curl -fsSL -o t https://example.test/t\n"),
                 Step("refused", "cat <<$(a b)\nit's\n$(a b)\n")]
        with mock.patch.dict(globals(), {"_run_jobs_in_repo": lambda: [("x.yml", "j", steps)]}):
            with self.assertRaises(AssertionError) as raised:
                self.test_the_fetch_scan_is_actually_seeing_the_downloads()
        self.assertIn("x.yml / refused -- cannot read this step: ", str(raised.exception))

    def test_no_fetch_exemption_outlives_the_step_it_was_written_for(self):
        fired = set()
        for workflow, name, _why in _fetch_defects_in_repo():
            if fetch_exemption(workflow, name):
                fired.add((workflow, name))
        stale = [e[:2] for e in EXEMPT_FETCHES if e[:2] not in fired]
        self.assertEqual([], stale, "fetch exemptions that no longer excuse "
                                    "anything; delete them:\n%s" % stale)

    def test_no_exempted_workflow_has_become_privileged(self):
        # Same posture rule the install exemptions are held to
        # (`privilege_defect`, exercised on both answers in
        # TestExemptionPosture): an exemption is written against an
        # unprivileged trigger and a read-only token, and neither is assumed.
        defects = []
        for name in sorted({e[0] for e in EXEMPT_FETCHES}):
            with open(os.path.join(WORKFLOW_DIR, name), encoding="utf-8") as fh:
                doc = yaml.safe_load(fh.read()) or {}
            why = privilege_defect(doc)
            if why:
                defects.append("%s -- %s" % (name, why))
        self.assertEqual([], defects, "a workflow carrying a fetch exemption "
                         "has become privileged:\n" + "\n".join(defects))

    def test_the_exemption_matcher_answers_on_both_sides(self):
        # EXEMPT_FETCHES is empty, so the three checks above pass vacuously
        # today; the matcher they depend on is proved here instead, on scratch
        # entries, so an exemption added later lands on tested machinery.
        entries = (("ci.yml", "fetch the thing", "a reason"),)
        self.assertIsNotNone(fetch_exemption("ci.yml", "fetch the thing", entries))
        self.assertIsNone(fetch_exemption("ci.yml", "another step", entries))
        self.assertIsNone(fetch_exemption("other.yml", "fetch the thing", entries))


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
        total = 0
        for path in _workflow_files():
            with open(path, encoding="utf-8") as fh:
                total += len(scan_uses(fh.read()))
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


# --- #1641 (SEC-E2A): what a privileged build INSTALLS ------------------------
# The two rules above govern what a workflow RUNS (`uses:`) and what it FETCHES
# (curl-and-exec). The third door into the same supply chain is what it
# INSTALLS. Run-13 found it open in the two most privileged build contexts the
# repo has: the `pull_request_target` security gate upgraded pip from whatever
# the index served while holding `security-events: write`, and the fixture image
# installed pytest as root at image build. Pinning the gate's pyyaml/jsonschema
# on the very next line did not cover it -- the UNPINNED tool is the one that
# then installs the pinned things.
#
# So the rule: every `pip install` in a workflow or a Dockerfile either resolves
# to artifacts this repo has hash-pinned (`--require-hashes -r <file>`), or it is
# on EXEMPT_INSTALLS below with a reason. The exemption list is checked in both
# directions -- an entry that stops matching anything is a stale exemption and
# fails, so the list cannot outlive the line it was written for.
# `pip -q install`, `pip --disable-pip-version-check install`: an option between
# the binary and the verb is still an install, and the two shapes above are the
# ones a CI author reaches for first.
_PIP_INSTALL = re.compile(
    r"(?:\bpython3?\s+-m\s+)?\bpip3?\s+(?:-\S+\s+)*install\b")
_REQ_FILE = re.compile(r"(?:^|\s)(?:-r|--requirement)[\s=]+(\S+)")
_HASH_OPT = re.compile(r"--hash=sha256:([0-9a-f]{64})\b")
_PIN_LINE = re.compile(r"^(?P<name>[A-Za-z0-9._-]+)==(?P<version>[^\s;]+)")

# The pip a fresh runner already has. The pin exists to move pip FORWARD onto an
# audited artifact, so it may never resolve to something OLDER than what the
# runner shipped with -- a "pin" that downgrades pip is a supply-chain
# regression wearing a pin's clothes. Recorded 2026-09-16 from
# `ensurepip.version()` on the CPython line this repo develops against (3.14.5:
# 26.1.1); raise it deliberately when that baseline moves.
RUNNER_PIP_FLOOR = (26, 1, 1)

# (file basename, fragment of the command, why it may install unpinned).
EXEMPT_INSTALLS = (
    ("ci.yml", "pip install --upgrade pip",
     "CI is the unprivileged surface: it runs on `pull_request` (never "
     "`pull_request_target`), with the default read-only token, and publishes "
     "nothing. It installs the project itself from the checkout, so a lockfile "
     "here would pin the dependency set the matrix exists to test across four "
     "Python versions."),
    # Quotes are shell syntax and the scan reports the parsed argv, so the
    # fragment is the command as `pip_install_commands` spells it.
    ("ci.yml", "pip install -e .[dev]",
     "installs THIS repo from THIS checkout; its dependency floors are "
     "pyproject.toml's and Dependabot bumps them."),
    ("ci.yml", "pip install -e .[test]",
     "same, for the test matrix."),
)
# #1734 retired the two Dockerfile exemptions that used to sit here. Their
# reasoning -- that the image digest fixes what the gate runs -- was true and
# beside the point: it pins the image, not the 88 transitive packages the build
# resolved from PyPI as root to MAKE that image. Both lines now install from
# `requirements-tools.txt` under --require-hashes --no-deps and need no
# exemption. The remaining entries are all ci.yml's, the unprivileged surface.


def _write_scopes(permissions):
    """The write grants in a `permissions:` block, in either spelling.

    An absent block holds no write grant, which is all this answers. Whether a
    job may HAVE no block is a different question, and `privilege_defect` asks
    it: the answer depends on the workflow-level block, which is not in scope
    here.
    """
    if permissions is None:
        return []
    if isinstance(permissions, str):            # `permissions: write-all`
        return [permissions] if "write" in permissions else []
    return sorted("%s: %s" % (scope, level)
                  for scope, level in permissions.items()
                  if isinstance(level, str) and level == "write")


def privilege_defect(doc):
    """Why this workflow is too privileged to carry an install exemption, or None.

    Every exemption below is written against a POSTURE -- unprivileged trigger,
    read-only token -- and keyed by filename, which is the part that cannot
    change. The posture can: adding `pull_request_target` or one `write` grant to
    `ci.yml` would silently keep four unpinned installs exempt in a workflow that
    had just become reachable from a fork PR. So the posture is asserted, not
    assumed.

    Which is why an UNDECLARED token is a defect too (#1784, ARC-3955973987): a
    job with no `permissions:` of its own and no workflow-level block to inherit
    takes its scopes from the repository's `GITHUB_TOKEN` default -- a setting
    outside this tree, invisible to a PR, and read-write on repositories created
    before GitHub changed that default. "Read-only" has to be written down here
    to be asserted at all.
    """
    on = doc.get(True, doc.get("on")) or {}
    if isinstance(on, dict):
        triggers = list(on.keys())
    elif isinstance(on, list):
        triggers = on
    else:
        triggers = [on]
    if "pull_request_target" in triggers:
        return "runs on pull_request_target, so a fork PR reaches it"
    workflow_block = doc.get("permissions")
    grants = [("workflow", _write_scopes(workflow_block))]
    undeclared = []
    for name, job in (doc.get("jobs") or {}).items():
        if isinstance(job, dict):
            block = job.get("permissions")   # one value, two questions below
            grants.append(("job %s" % name, _write_scopes(block)))
            if workflow_block is None and block is None:
                undeclared.append(name)
    defects = ["%s holds %s" % (where, ", ".join(scopes))
               for where, scopes in grants if scopes]
    defects += ["job %s declares no `permissions:` block, so the token's scopes "
                "come from the repository default" % name
                for name in sorted(undeclared)]
    if defects:
        return "; ".join(defects)
    return None


def install_pin_defect(command):
    """Why this `pip install` installs an unconstrained artifact, or None.

    One accepted shape: an install from a requirements file under
    `--require-hashes`, which makes pip refuse anything whose digest is not
    written down in this repo. A bare `pip install <name>` -- with or without a
    version -- is not it: a version constrains WHICH release, never WHAT bytes.
    """
    if "--require-hashes" not in command:
        return "installs without --require-hashes: %s" % command
    if not _REQ_FILE.search(command):
        return ("passes --require-hashes but installs no requirements file, so "
                "it pins nothing: %s" % command)
    return None


def pip_install_commands(script):
    """Every `pip install` command in a shell script, one per shell command.

    On `shell_reader.statements()` -- the reader the fetch-and-exec rule next
    door already uses -- rather than a private `re.split` over the text. The
    split cut on every `&&`, `||`, `;` and newline it could SEE, including the
    ones inside quotes, and a PEP 508 environment marker puts a `;` inside the
    requirement exactly where it has to be quoted: `pip install "black;
    python_version>='3.9'" --require-hashes -r reqs.txt` arrived as
    `pip install "black`, its own pin sheared off, reported as an unpinned
    install of a package called `"black`. Continuations, whole-line comments
    and quoting are one reader's job, and this file had a second copy of two
    of the three (#1641 already shared the comment-stripper).

    The command is the ARGV, joined: quoting is shell syntax that says where a
    word ends, and what this rule reads -- `--require-hashes`, `-r <file>` --
    are words. `EXEMPT_INSTALLS` matches against the same spelling.

    The reader lifts `$(...)`, backticks and heredoc bodies into side tables
    and leaves a marker in the argv, so they are walked back in here: reading
    the argv alone would have let `X=$(pip install evil)` and a `cat <<EOF`
    installer script past a gate whose standing requirement is to fail CLOSED.

    So is a heredoc body consumed INSIDE a substitution -- `eval "$(cat <<'EOF'
    … pip install … EOF)"` -- which was the one shape narrower than the text
    split this replaced: the outer parse held that body in a table the inner
    re-read could not reach, until the reader handed it over with the
    substitution's text (#2336).
    """
    out = []
    for statement in _statements(script):
        for stage in statement.stages:
            command = " ".join(stage.argv)
            if _PIP_INSTALL.search(command):
                out.append(command)
            for inner in stage.substitutions:
                out.extend(pip_install_commands(inner))
            if stage.heredoc:
                out.extend(pip_install_commands(stage.heredoc))
    return out


def _dockerfiles():
    return sorted(os.path.join(REPO_ROOT, n) for n in os.listdir(REPO_ROOT)
                  if n == "Dockerfile" or n.startswith("Dockerfile."))


def _installs_in_repo():
    """[(basename, command)] for every pip install in a workflow or Dockerfile."""
    found = []
    for path in _workflow_files():
        with open(path, encoding="utf-8") as fh:
            doc = yaml.safe_load(fh.read()) or {}
        for job in (doc.get("jobs") or {}).values():
            if not isinstance(job, dict):
                continue
            for step in job.get("steps") or []:
                if isinstance(step, dict) and step.get("run"):
                    for cmd in pip_install_commands(step["run"]):
                        found.append((os.path.basename(path), cmd))
    for path in _dockerfiles():
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
        for cmd in pip_install_commands(text):
            found.append((os.path.basename(path), cmd))
    return found


def _resolve_requirements(ref):
    """The in-repo path of a requirements file an install names, or None.

    The reference is written for the machine that runs it -- the gate names
    `controller/.github/...` (its trusted checkout) and the fixture image names
    a path inside the image -- so resolution is by basename against the two
    places this repo keeps them.
    """
    base = os.path.basename(ref)
    for candidate in (os.path.join(REPO_ROOT, base),
                      os.path.join(REPO_ROOT, ".github", base)):
        if os.path.isfile(candidate):
            return candidate
    return None


def requirements_defects(text):
    """Why this requirements file does not pin what it installs, or []."""
    defects = []
    for line in join_continuations(text).splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if "TODO-hash" in stripped:
            defects.append("placeholder digest left in: %s" % stripped)
            continue
        m = _PIN_LINE.match(stripped)
        if not m:
            defects.append("not a `name==version` pin: %s" % stripped)
            continue
        if not _HASH_OPT.search(stripped):
            defects.append("%s is pinned by version but not by hash"
                           % m.group("name"))
    return defects


class TestInstallPinRule(unittest.TestCase):
    """The rule on both answers, using the two lines it was written for."""

    def test_the_gates_unpinned_pip_upgrade_is_a_defect(self):
        self.assertIn("without --require-hashes",
                      install_pin_defect("python -m pip install --upgrade pip"))

    def test_the_fixture_images_unpinned_pytest_is_a_defect(self):
        self.assertIn("without --require-hashes",
                      install_pin_defect("pip install --no-cache-dir pytest"))

    def test_a_version_pin_alone_is_still_a_defect(self):
        # A version says WHICH release; only a hash says WHAT bytes.
        self.assertIsNotNone(install_pin_defect("pip install pytest==9.1.1"))

    def test_require_hashes_without_a_file_pins_nothing(self):
        self.assertIn("pins nothing",
                      install_pin_defect("pip install --require-hashes pytest"))

    def test_an_install_from_a_hashed_requirements_file_is_accepted(self):
        self.assertIsNone(install_pin_defect(
            "python -m pip install --require-hashes --no-deps "
            "-r controller/.github/requirements-gate.txt"))

    def test_continuations_and_multi_command_lines_are_seen(self):
        script = ("apt-get update \\\n    && pip install \\\n"
                  "        --no-cache-dir pytest\n")
        self.assertEqual(["pip install --no-cache-dir pytest"],
                         pip_install_commands(script))

    def test_an_option_between_pip_and_install_is_still_an_install(self):
        for script in ("pip -q install pytest\n",
                       "pip --disable-pip-version-check install pytest\n"):
            self.assertEqual(1, len(pip_install_commands(script)), script)
            self.assertIsNotNone(
                install_pin_defect(pip_install_commands(script)[0]), script)

    def test_a_comment_about_an_install_is_not_an_install(self):
        # The prose explaining this very fix quotes both offending commands; so
        # does the Dockerfile's note about semgrep. Reading those as installs
        # would make the guard fire on its own documentation.
        script = ("# the old line here was `pip install --upgrade pip`\n"
                  "python -m pip install --require-hashes -r reqs.txt\n")
        self.assertEqual(["python -m pip install --require-hashes -r reqs.txt"],
                         pip_install_commands(script))

    def test_an_install_inside_a_command_substitution_is_seen(self):
        # #1697 review F6: the reader lifts `$(...)`, backticks and heredoc
        # bodies into side tables and leaves a marker in the argv, so moving
        # off the raw text silently narrowed a supply-chain gate. A rule whose
        # standing requirement is to fail CLOSED does not get to lose scope
        # quietly.
        for script in ("X=$(pip install evil)\n", "X=`pip install evil`\n"):
            found = pip_install_commands(script)
            self.assertEqual(1, len(found), script)
            self.assertIsNotNone(install_pin_defect(found[0]), script)

    def test_an_install_inside_a_heredoc_body_is_seen(self):
        script = "cat <<EOF > setup.sh\npip install evil\nEOF\n"
        found = pip_install_commands(script)
        self.assertEqual(1, len(found), found)
        self.assertIsNotNone(install_pin_defect(found[0]))

    def test_an_install_inside_a_quoted_heredoc_body_is_seen(self):
        script = "cat <<'EOF' > setup.sh\npip install evil\nEOF\n"
        self.assertEqual(1, len(pip_install_commands(script)))

    def test_an_install_inside_a_heredoc_inside_a_substitution_is_seen(self):
        # The one shape that was narrower than the raw-text split this
        # replaced: the body lived in the OUTER parse's table, which the
        # re-read of the substitution's text could not reach before #2336.
        for script in ('eval "$(cat <<\'EOF\'\npip install evil\nEOF\n)"\n',
                       'X="$(cat <<\'EOF\'\npip install evil\nEOF\n)"\n'):
            self.assertEqual(["pip install evil"], pip_install_commands(script), script)

    def test_a_script_with_no_install_is_left_alone(self):
        self.assertEqual([], pip_install_commands("python -m pytest tests/ -q\n"))

    def test_an_environment_marker_does_not_split_the_command(self):
        # #1697: a PEP 508 marker puts a `;` INSIDE the requirement, where it
        # must be quoted -- and the private `re.split(r"&&|\|\||;|\n", ...)`
        # this rule used cut on every `;` in the TEXT. The install arrived as
        # `pip install "black`, with its own `--require-hashes -r` sheared off
        # and reported as an unpinned install of a package named `"black`.
        script = ('pip install "black; python_version>=\'3.9\'" '
                  "--require-hashes -r reqs.txt\n")
        found = pip_install_commands(script)
        self.assertEqual(1, len(found), found)
        self.assertIn("--require-hashes", found[0])
        self.assertIsNone(install_pin_defect(found[0]))

    def test_a_separator_inside_quotes_is_not_a_separator(self):
        script = 'echo "one && two"\npip install --require-hashes -r reqs.txt\n'
        self.assertEqual(["pip install --require-hashes -r reqs.txt"],
                         pip_install_commands(script))


class TestRequirementsRule(unittest.TestCase):
    def test_an_unhashed_pin_is_a_defect(self):
        self.assertIn("not by hash", requirements_defects("pytest==9.1.1\n")[0])

    def test_a_placeholder_digest_is_refused(self):
        self.assertIn("placeholder", requirements_defects(
            "pytest==9.1.1 --hash=sha256:TODO-hash\n")[0])

    def test_an_unpinned_name_is_a_defect(self):
        self.assertIn("not a `name==version` pin",
                      requirements_defects("pytest\n")[0])

    def test_a_hashed_pin_over_continuations_is_accepted(self):
        self.assertEqual([], requirements_defects(
            "# a comment\npytest==9.1.1 \\\n    --hash=sha256:%s\n" % ("a" * 64)))


class TestEveryPrivilegedInstallIsPinned(unittest.TestCase):
    def test_no_unpinned_pip_install_in_a_workflow_or_dockerfile(self):
        defects, fired = [], set()
        for name, cmd in _installs_in_repo():
            exemption = next(
                (e for e in EXEMPT_INSTALLS if e[0] == name and e[1] in cmd),
                None)
            if exemption:
                fired.add(exemption[:2])
                continue
            why = install_pin_defect(cmd)
            if why:
                defects.append("%s -- %s" % (name, why))
        self.assertEqual([], defects, "unpinned dependency install:\n" +
                         "\n".join(defects))

    def test_no_exemption_outlives_the_line_it_was_written_for(self):
        fired = set()
        for name, cmd in _installs_in_repo():
            for entry in EXEMPT_INSTALLS:
                if entry[0] == name and entry[1] in cmd:
                    fired.add(entry[:2])
        stale = [e[:2] for e in EXEMPT_INSTALLS if e[:2] not in fired]
        self.assertEqual([], stale, "exemptions that no longer match any "
                                    "install line; delete them:\n%s" % stale)

    def test_no_exempted_workflow_has_become_privileged(self):
        defects = []
        for name in sorted({e[0] for e in EXEMPT_INSTALLS
                            if e[0].endswith((".yml", ".yaml"))}):
            with open(os.path.join(WORKFLOW_DIR, name), encoding="utf-8") as fh:
                doc = yaml.safe_load(fh.read()) or {}
            why = privilege_defect(doc)
            if why:
                defects.append("%s -- %s" % (name, why))
        self.assertEqual([], defects, "a workflow carrying an install exemption "
                         "has become privileged; pin its installs or justify "
                         "them again:\n" + "\n".join(defects))

    def test_the_scan_is_actually_finding_installs(self):
        # Guards the guard: a regex that matched nothing would report a clean
        # pass over a tree full of unpinned installs.
        self.assertGreater(len(_installs_in_repo()), 4,
                           "install scan found almost nothing; the scanner is "
                           "broken, not the tree")


class TestExemptionPosture(unittest.TestCase):
    """The posture rule on both answers, on scratch documents."""

    READ_ONLY = {True: {"pull_request": {"branches": ["main"]}},
                 "permissions": {"contents": "read"},
                 "jobs": {"test": {"steps": []}}}
    # The same document with no `permissions:` block at all -- the posture the
    # rule used to read as unprivileged (#1784, ARC-3955973987).
    NO_BLOCK = {True: {"pull_request": {"branches": ["main"]}},
                "jobs": {"test": {"steps": []}}}

    def test_an_unprivileged_pull_request_workflow_may_be_exempt(self):
        self.assertIsNone(privilege_defect(self.READ_ONLY))

    def test_pull_request_target_disqualifies_it(self):
        # PyYAML 1.1 parses the unquoted `on:` key as the boolean True, which is
        # why the rule reads both spellings and why this fixture uses that one.
        doc = dict(self.READ_ONLY)
        doc[True] = {"pull_request": None, "pull_request_target": None}
        self.assertIn("pull_request_target", privilege_defect(doc))

    def test_a_workflow_level_write_grant_disqualifies_it(self):
        doc = dict(self.READ_ONLY, permissions={"contents": "read",
                                                "security-events": "write"})
        self.assertIn("security-events: write", privilege_defect(doc))

    def test_a_job_level_write_grant_disqualifies_it(self):
        doc = dict(self.READ_ONLY,
                   jobs={"test": {"permissions": {"contents": "write"},
                                  "steps": []}})
        self.assertIn("job test holds contents: write", privilege_defect(doc))

    def test_write_all_disqualifies_it(self):
        self.assertIn("write-all",
                      privilege_defect(dict(self.READ_ONLY, permissions="write-all")))

    # --- ARC-3955973987 (#1784): an UNDECLARED posture is not a read-only one --
    # An absent block grants no write scope, so the rule read it as clean and the
    # exemptions' "default read-only token" was the repository's `GITHUB_TOKEN`
    # setting -- which is not in this tree, cannot be reviewed in a PR, and flips
    # every one of these workflows to a write token the day someone changes it.
    # An undeclared effective posture is now the defect; a block at EITHER level
    # is the assertion that satisfies it.

    def test_no_permissions_block_at_any_level_is_a_defect(self):
        why = privilege_defect(self.NO_BLOCK)
        self.assertIsNotNone(why, "a workflow declaring no `permissions:` at any "
                                  "level read as unprivileged")
        self.assertIn("job test declares no `permissions:` block", why)
        self.assertIn("repository default", why)

    def test_a_workflow_level_block_covers_every_job(self):
        self.assertIsNone(privilege_defect(
            dict(self.NO_BLOCK, permissions={"contents": "read"})))

    def test_an_explicit_empty_block_is_declared_not_missing(self):
        # `permissions: {}` grants nothing, a stronger statement than
        # `contents: read`; only an ABSENT block reads as undeclared.
        self.assertIsNone(privilege_defect(dict(self.NO_BLOCK, permissions={})))

    def test_a_job_level_block_on_every_job_is_enough(self):
        # `codeql.yml`, `nvd-cache.yml`, `security.yml` and `docker-publish.yml`
        # are this shape: no workflow-level block, one per job.
        self.assertIsNone(privilege_defect(dict(self.NO_BLOCK, jobs={
            "lint": {"permissions": {"contents": "read"}, "steps": []},
            "test": {"permissions": {"contents": "read"}, "steps": []}})))

    def test_only_the_job_that_declares_nothing_is_named(self):
        why = privilege_defect(dict(self.NO_BLOCK, jobs={
            "lint": {"permissions": {"contents": "read"}, "steps": []},
            "test": {"steps": []}}))
        self.assertIsNotNone(why, "a job inheriting nothing read as unprivileged")
        self.assertIn("job test declares no `permissions:` block", why)
        self.assertNotIn("job lint", why)

    def test_a_write_grant_is_still_named_when_no_workflow_block_exists(self):
        self.assertIn("job test holds contents: write", privilege_defect(
            dict(self.NO_BLOCK,
                 jobs={"test": {"permissions": {"contents": "write"},
                                "steps": []}})))


class TestEveryPinnedRequirementsFileIsHashed(unittest.TestCase):
    def test_every_requirements_file_an_install_names_is_fully_hashed(self):
        seen, defects = [], []
        for name, cmd in _installs_in_repo():
            if "--require-hashes" not in cmd:
                continue
            for ref in _REQ_FILE.findall(cmd):
                path = _resolve_requirements(ref)
                if path is None:
                    defects.append("%s installs from %s, which is not in this "
                                   "repo" % (name, ref))
                    continue
                seen.append(path)
                with open(path, encoding="utf-8") as fh:
                    for why in requirements_defects(fh.read()):
                        defects.append("%s -- %s" % (os.path.basename(path), why))
        self.assertEqual([], defects, "\n".join(defects))
        self.assertTrue(seen, "no hash-pinned requirements file is installed "
                              "anywhere; the pin was removed, not satisfied")

    def test_the_fixture_image_copies_the_repos_requirements_file(self):
        # `_resolve_requirements` maps `/tmp/requirements-fixtures.txt` back to
        # the repo by BASENAME, which proves the digests in this repo are
        # hashed -- not that the image installs them. The COPY is what ties the
        # path inside the image to the file this guard reads.
        with open(os.path.join(REPO_ROOT, "Dockerfile.fixtures"),
                  encoding="utf-8") as fh:
            text = fh.read()
        self.assertIn("COPY requirements-fixtures.txt", text)

    def test_the_gate_never_downgrades_pip(self):
        path = os.path.join(REPO_ROOT, ".github", "requirements-gate.txt")
        with open(path, encoding="utf-8") as fh:
            m = re.search(r"^pip==(\S+)", join_continuations(fh.read()), re.M)
        self.assertIsNotNone(m, "the gate's requirements file pins no pip; the "
                                "unpinned `--upgrade pip` it replaced is back")
        pinned = tuple(int(p) for p in m.group(1).split(".") if p.isdigit())
        self.assertGreaterEqual(
            pinned, RUNNER_PIP_FLOOR,
            "pinned pip %s is older than the %s the runner already ships"
            % (m.group(1), ".".join(str(n) for n in RUNNER_PIP_FLOOR)))


# --- #2369: what the driver's and the gate's import chains actually reach -----
# Two properties over one reading of the same files.
#
# WHERE an import sits decides whether `driver readiness` can diagnose a thin
# install at all: the `dependencies` row names an absent runtime package with
# its `pip install`, and it only gets to print if the process reached a row. A
# third-party import at MODULE level on the driver's path is a
# ModuleNotFoundError traceback out of `import scripts.driver` instead (#2369).
#
# WHICH package an import names decides whether the security gate can start:
# installed with `--require-hashes --no-deps`, `.github/requirements-gate.txt`
# IS that environment, so every third-party module either chain imports -- at
# module level or nested inside a function -- has to be in the closure.
#
# Both read the AST. A text guard cannot tell `import yaml` at the top of a file
# from one inside a function, and that distinction is the whole first property
# (`text-guards-must-read-the-AST`).

SKILL_SCRIPTS = os.path.join(REPO_ROOT, "skill", "scripts")


def _is_local_module(name):
    """Is `name` one of this repo's own modules rather than a package?

    `scripts` itself, or a module `skill/scripts/` ships under its BARE name:
    `discovery.py` reaches `diff_map` that way, off the flat import root it
    puts on `sys.path` itself, and a checker that did not know that would
    report the repo's own files as third-party.
    """
    return (name == "scripts"
            or os.path.isfile(os.path.join(SKILL_SCRIPTS, name + ".py"))
            or os.path.isdir(os.path.join(SKILL_SCRIPTS, name)))


def third_party_names(node):
    """The non-stdlib, non-local top-level module names one import statement
    names. A relative `from . import x` is local by construction."""
    if isinstance(node, ast.ImportFrom):
        if node.level:
            return []
        names = [(node.module or "").split(".")[0]]
    else:
        names = [alias.name.split(".")[0] for alias in node.names]
    return [name for name in names
            if name and name not in sys.stdlib_module_names
            and not _is_local_module(name)]


#: The only statements whose body is NOT executed as part of importing the
#: module: a function body is the one place an import is deferred to call time.
#: `Lambda` is named for completeness and can never match: it is an expression,
#: and an import is a statement, so no import can sit inside one.
_FUNCTION_SCOPES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)


def _module_level_import_nodes(body):
    """Every import statement that MAY run when the module is imported.

    Written as a REFUSAL rather than as a list of shapes worth descending into:
    everything not inside a function body may run at import (a `try:` arm, an
    `if:` arm, an `except` arm that never fires), so the guard refuses all of
    it: the walk follows every child statement -- `try`/`except`/`except*`/
    `finally`, `if`/`else`, `with`, `for`, `while`, `match`/`case`, `class` --
    and stops only at `def` and `async def`.

    The first version descended into `try:` and `if:` alone, and six other
    shapes read as clean: `with contextlib.suppress(ImportError):`, which is the
    first thing a developer reaches for when this guard reds on them, `except*`
    (whose node is `ast.TryStar`, not an `ast.Try`), a class body, a `for`/
    `while` body and a `match` case. A guard that enumerates the shapes it knows
    is a guard the next shape walks past -- text-guards-must-read-the-AST, and
    `TestNoThirdPartyImportAtModuleLevelOnTheDriverPath.MODULE_LEVEL_SHAPES`
    holds all nine as a table.
    """
    for node in body:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            yield node
        elif not isinstance(node, _FUNCTION_SCOPES):
            for child in ast.iter_child_nodes(node):
                # `iter_child_nodes` hands back expressions too (a `with`'s
                # context manager, an `if`'s test); only statement bodies can
                # hold an import, and the two nodes that HOLD a body without
                # being statements themselves are an except arm and a `case`.
                if isinstance(child, ast.stmt):
                    yield from _module_level_import_nodes([child])
                elif isinstance(child, (ast.ExceptHandler, ast.match_case)):
                    yield from _module_level_import_nodes(child.body)


def module_level_third_party(source, filename="<source>"):
    """[(line, module)] for every third-party import at MODULE level."""
    tree = ast.parse(source, filename=filename)
    return [(node.lineno, name)
            for node in _module_level_import_nodes(tree.body)
            for name in third_party_names(node)]


def every_third_party(source, filename="<source>"):
    """[(line, module)] for every third-party import ANYWHERE in the file.

    Nested imports included, because since #2369 they are the norm on these
    paths -- and the gate still has to install what they name.
    """
    tree = ast.parse(source, filename=filename)
    return [(node.lineno, name) for node in ast.walk(tree)
            if isinstance(node, (ast.Import, ast.ImportFrom))
            for name in third_party_names(node)]


# The census program, run in a CHILD rather than read off this process's
# `sys.modules`: a full-suite run has already imported whatever every other
# test module imports, and two of those are on neither chain under test --
# `scripts.capture_goldens` (defusedxml at module level) and
# `scripts.smoke_adapters` (a nested `bandit`). Reading this suite's own
# `sys.modules` would make both guards depend on test ORDER.
#
# Selected by FILE and not by module NAME. `skill/scripts/` holds no
# `__init__.py` and is itself on `sys.path` in several live paths, so a module
# there has two reachable names (`tests/test_module_identity.py` is the guard
# for that), and the flat one is how several are actually reached:
# `grouping_engine.py` does a bare `import tests_axis`, and a census keyed
# on `scripts.` missed `setup_proposal.py`'s own module-level `import yaml`
# entirely. The file is on the path however it was spelled.
_CENSUS = """
import json, os, sys
scripts_dir = sys.argv[1]
for name in sys.argv[2:]:
    __import__(name)
print(json.dumps(sorted({
    os.path.abspath(module.__file__)
    for module in list(sys.modules.values())
    if getattr(module, "__file__", None)
    and os.path.abspath(module.__file__).startswith(scripts_dir + os.sep)})))
"""


def files_reached_by(*roots):
    """Every `skill/scripts` FILE that importing `roots` loads, sorted.

    A fresh interpreter with only `skill/` on the path and a cwd elsewhere --
    the driver-shaped process `tests/test_module_identity.py` measures its own
    census in, for the same reason: the import graph under test must be the
    product's, not this suite's.

    The environment is STATED, not inherited, the way the sibling child-process
    case in `tests/phases/test_readiness_verb.py` states its own: an empty PATH
    and a HOME with nothing under them, `PYTHONPATH` exactly `skill/`, the user
    site-packages excluded on purpose (`PYTHONNOUSERSITE=1`, not merely by the
    relocated HOME), and no other `PYTHON*` variable the developer happens to
    have set. Nothing here
    launches a binary -- it only imports -- but a census of what the product
    imports must not be a reading of whoever ran it.
    """
    with tempfile.TemporaryDirectory() as elsewhere:
        env = {"PATH": os.path.join(elsewhere, "empty-path"),
               "HOME": os.path.join(elsewhere, "home"),
               "PYTHONPATH": os.path.join(REPO_ROOT, "skill"),
               "PYTHONNOUSERSITE": "1",
               "PYTHONDONTWRITEBYTECODE": "1"}
        for path in (env["PATH"], env["HOME"]):
            os.makedirs(path, exist_ok=True)
        proc = subprocess.run(  # nosec B603
            [sys.executable, "-c", _CENSUS, SKILL_SCRIPTS, *roots],
            cwd=elsewhere, env=env, capture_output=True, text=True,
            timeout=180)
    if proc.returncode != 0:
        raise AssertionError("importing %s failed, so neither import-chain "
                             "guard can read anything:\n%s"
                             % (", ".join(roots), proc.stdout + proc.stderr))
    return json.loads(proc.stdout)


def third_party_imports_under(files):
    """{module: ["<file>:<line>", ...]} for every third-party import, nested
    included, in `files`."""
    found = {}
    for path in files:
        with open(path, encoding="utf-8") as fh:
            source = fh.read()
        for line, module in every_third_party(source, path):
            found.setdefault(module, []).append(
                "%s:%d" % (os.path.relpath(path, REPO_ROOT), line))
    return found


class TestGateClosureCoversRuntimePackages(unittest.TestCase):
    """#2363: installed with `--no-deps`, the gate's requirements file IS the
    environment, so a runtime package the gate's import chain reaches has to be
    listed in it or the gate cannot start.

    Both commands that run repository code in that environment
    (`skill/scripts/run_tools.py` and `skill/scripts/security_gate.py`) reach
    `scripts.tools`, whose package body builds `ADAPTERS` by importing every
    adapter, and an adapter is free to import a declared runtime dependency --
    since #2369 inside the function that needs it, which changes nothing about
    what has to be installed. The existing guards in this file assert the
    install COMMAND (`--require-hashes`, a pinned file) and that every pinned
    line carries a digest; none of them asks whether the closure covers what
    the gate imports. That gap red-lined the `scan` and `fork-scan` checks the
    moment `tools/spotbugs.py` stopped falling back to the stdlib XML parser.

    Two guards, because they fail differently, and NEITHER is redundant. The
    first reads `readiness_checks.RUNTIME_PACKAGES` -- a declared LIST, and a
    proxy: an adapter that grows a dependency the list does not name would red
    the `scan` job with it green. The second reads the IMPORTS, which is the
    property that actually broke.

    What each one covers is not the same set, so read this before retiring
    either. The gate's chain imports `jsonschema` (through `security_gate` into
    `synth/validate_schema.py`) and `defusedxml` (through `scripts.tools` into
    the spotbugs adapter's `parse`), and it does NOT import `yaml` at all -- the
    modules that do are on the DRIVER's chain, not the gate's. So the
    import-reading guard covers jsonschema and defusedxml, and the
    `RUNTIME_PACKAGES` proxy is the only thing keeping `pyyaml` in the closure:
    retiring it would silently drop pyyaml from a file installed with
    `--require-hashes --no-deps`.
    """

    GATE = os.path.join(REPO_ROOT, ".github", "requirements-gate.txt")

    @staticmethod
    def _normalised(name):
        """PEP 503 normalisation, in full: pip treats `rpds-py`, `rpds_py` and
        `rpds.py` as one project, and so must a guard reading two files. The
        dot matters now that the second guard below compares requirement lines
        against `importlib.metadata` distribution names, which are free to
        carry any of the three separators (and any case -- `PyYAML`).
        """
        return re.sub(r"[-_.]+", "-", name).lower()

    def _pinned_names(self):
        with open(self.GATE, encoding="utf-8") as fh:
            text = join_continuations(fh.read())
        names = set()
        for line in text.splitlines():
            m = _PIN_LINE.match(line.strip())
            if m:
                names.add(self._normalised(m.group("name")))
        return names

    def test_every_runtime_package_is_in_the_gate_closure(self):
        import scripts.phases.readiness_checks as readiness_checks
        pinned = self._pinned_names()
        self.assertTrue(pinned, "the gate's requirements file pins nothing; "
                                "this guard is reading the wrong file")
        self.assertTrue(readiness_checks.RUNTIME_PACKAGES, "no packages to check")
        for _module, pip_name in readiness_checks.RUNTIME_PACKAGES:
            with self.subTest(package=pip_name):
                self.assertIn(
                    self._normalised(pip_name), pinned,
                    "%s is in readiness_checks.RUNTIME_PACKAGES, so the gate's "
                    "import chain reaches it, but %s does not pin it -- and "
                    "that file is installed with --require-hashes --no-deps, "
                    "so it is the whole environment. The gate would fail at "
                    "import, not degrade."
                    % (pip_name, os.path.relpath(self.GATE, REPO_ROOT)))

    def test_every_third_party_import_on_the_gate_path_is_pinned(self):
        pinned = self._pinned_names()
        self.assertTrue(pinned, "the gate's requirements file pins nothing; "
                                "this guard is reading the wrong file")
        reached = files_reached_by("scripts.run_tools", "scripts.security_gate")
        self.assertIn(os.path.join(SKILL_SCRIPTS, "run_tools.py"), reached,
                      "the census imported no gate module; this guard is vacuous")
        imports = third_party_imports_under(reached)
        self.assertTrue(imports, "the gate's import chain reads as having no "
                                 "third-party import at all, which it does "
                                 "(defusedxml and jsonschema, at least); this "
                                 "guard is reading the wrong files")
        # `packages_distributions()` rather than a hand-written import-name ->
        # distribution map: the mapping is a fact about what is installed
        # (`yaml` comes from `PyYAML`), and a restated one goes stale silently.
        provided_by = importlib.metadata.packages_distributions()
        gate = os.path.relpath(self.GATE, REPO_ROOT)
        for module, sites in sorted(imports.items()):
            with self.subTest(module=module):
                distributions = provided_by.get(module) or []
                self.assertTrue(
                    distributions,
                    "`import %s` (%s) and no installed distribution provides "
                    "that module, so this guard cannot say whether the gate's "
                    "closure covers it -- an import the environment cannot "
                    "explain. Install it (`pip install -e \".[dev]\"`) or drop "
                    "the import." % (module, ", ".join(sites)))
                # ANY of them: several distributions may provide one import
                # name, and installing one of those is enough for the import to
                # resolve. The message names them all so an unpinned one is
                # obvious either way.
                self.assertTrue(
                    any(self._normalised(d) in pinned for d in distributions),
                    "`import %s` (%s) is provided by %s, and %s pins none of "
                    "them -- that file is installed with --require-hashes "
                    "--no-deps, so it IS the gate's environment. The gate would "
                    "fail at import, not degrade."
                    % (module, ", ".join(sites),
                       ", ".join(sorted(distributions)), gate))


class TestNoThirdPartyImportAtModuleLevelOnTheDriverPath(unittest.TestCase):
    """#2369: `driver readiness`'s `dependencies` row is only reachable if
    importing the driver imports no third-party package.

    The row names an absent runtime package with its `pip install`, before the
    first paid dispatch. It printed for `jsonschema` -- imported lazily by the
    artifact validation -- and for neither of the other two, because four
    modules on the driver's own import path imported a third-party package at
    MODULE level: `tools/spotbugs.py` (defusedxml, reached twice over through
    `scripts.tools`'s package body, which imports every adapter) and
    `setup_flow.py`, `discovery.py` and `setup_proposal.py` (yaml). A thin
    install therefore got a ModuleNotFoundError traceback out of
    `import scripts.driver` and no document at all -- loud, and it named the
    package, but it was not the preflight.

    The fourth was found by this guard and not by the issue: `setup_proposal.py`
    is reached as flat `setup_proposal`, so the first draft of the census, keyed
    on `sys.modules` names beginning `scripts.`, could not see it. Hence the
    file-keyed census above.

    So the property is about WHERE an import sits: on this path every
    third-party import belongs inside the function that needs it. The design
    ruling was lazy IMPORTS and not a lazy `ADAPTERS` registry -- that dict is
    `mock.patch.dict`-ed by three test modules and enumerated by
    `capture_goldens.py`, so it stays a plain dict.

    `tests/phases/test_readiness_verb.py` asserts the row from the other side,
    in a child interpreter where the package is genuinely gone. This guard is
    what stops the next module-level import from putting it back.
    """

    #: `run_tools` and `security_gate` join the driver here because they are the
    #: two commands the security gate runs, and the class above asks a different
    #: question about the same two chains.
    ROOTS = ("scripts.driver", "scripts.phases.readiness", "scripts.run_tools",
             "scripts.security_gate")

    def test_no_module_on_the_driver_path_imports_a_third_party_at_module_level(self):
        reached = files_reached_by(*self.ROOTS)
        self.assertIn(os.path.join(SKILL_SCRIPTS, "driver.py"), reached,
                      "the census imported no driver module; this guard is vacuous")
        offenders = []
        for path in reached:
            with open(path, encoding="utf-8") as fh:
                source = fh.read()
            offenders += ["%s:%d %s" % (os.path.relpath(path, REPO_ROOT), line, module)
                          for line, module in module_level_third_party(source, path)]
        self.assertEqual(
            [], offenders,
            "these imports are attempted when the driver is imported, so an "
            "install without one of them is a traceback (or a silently swallowed "
            "one) instead of the `dependencies` row that names its "
            "`pip install` (#2369):\n  %s\nMove each into the function that "
            "uses it. Not into a module-level `try:` / `except ImportError:` -- "
            "or a `with contextlib.suppress(ImportError):`, which is the same "
            "statement in fewer words: an except arm that rebinds the name is the "
            "fallback #2363 forbids, one that passes leaves the name unbound "
            "for a NameError at first use, and an unguarded one takes the row "
            "down. The function body is the only place that is none of those."
            % "\n  ".join(offenders))

    #: Every shape that puts an import at MODULE level, with the line it sits
    #: on. All of them RUN when the module is imported, so all of them must
    #: trip -- text-guards-must-read-the-AST, and this is the table that says
    #: what "read the AST" has to mean here.
    #:
    #: Note what the rule is NOT resting on. A module-level
    #: `try: import x / except ImportError: pass` does NOT need the package at
    #: import time -- suppressing the error is exactly what it does, and the
    #: readiness row prints fine with one in place (measured). It is refused for
    #: two other reasons: an except arm that rebinds the name is the fallback
    #: #2363 forbids, and one that passes leaves the name unbound for a
    #: NameError at first use. An UNGUARDED module-level import is the one that
    #: takes the row down. All three belong in the function instead.
    #:
    #: Six of the nine read as CLEAN
    #: while the walk descended into `try:`/`if:` only (#2369 re-review):
    #: `contextlib.suppress(ImportError)` is the first shape a developer
    #: reaches for when this guard reds on them, and `except*` builds an
    #: `ast.TryStar`, which is not an `ast.Try` subclass.
    MODULE_LEVEL_SHAPES = (
        ("a bare import", 1, "import defusedxml\n"),
        ("an `if` arm", 2, "if True:\n    import defusedxml\n"),
        ("a `try` body", 2, ("try:\n    import defusedxml\n"
                             "except ImportError:\n    pass\n")),
        ("an `except*` body (ast.TryStar)", 2,
         "try:\n    import defusedxml\nexcept* ImportError:\n    pass\n"),
        ("a `with contextlib.suppress(ImportError)` body", 2,
         "with contextlib.suppress(ImportError):\n    import defusedxml\n"),
        ("a class body", 2, "class A:\n    import defusedxml\n"),
        ("a `for` body", 2, "for _ in range(1):\n    import defusedxml\n"),
        ("a `while` body", 2,
         "while True:\n    import defusedxml\n    break\n"),
        ("a `match` case body", 3,
         "match 1:\n    case 1:\n        import defusedxml\n"),
    )

    def test_every_module_level_shape_trips_the_checker(self):
        for label, line, source in self.MODULE_LEVEL_SHAPES:
            with self.subTest(shape=label):
                self.assertEqual(
                    [(line, "defusedxml")], module_level_third_party(source),
                    "%s puts the import at module level, so it runs when the "
                    "module is imported, so the checker has to see it" % label)

    def test_an_import_inside_a_function_is_not_a_module_level_import(self):
        source = ("def parse(raw):\n"
                  "    import defusedxml.ElementTree as ET\n"
                  "    return ET.fromstring(raw)\n")
        self.assertEqual([], module_level_third_party(source))
        # ...and the nested reading DOES see it, which is what the gate-closure
        # guard above is built on: moving an import does not un-require it.
        self.assertEqual([(2, "defusedxml")], every_third_party(source))

    def test_this_repos_own_modules_are_not_third_party(self):
        source = ("import json\n"
                  "import scripts.hosts\n"
                  "from scripts.tools import egress\n"
                  "import diff_map\n")
        self.assertEqual([], module_level_third_party(source))

    def test_a_relative_import_is_local_by_construction(self):
        self.assertEqual([], module_level_third_party("from . import base\n"))
        self.assertEqual([], module_level_third_party("from .base import run_tool\n"))


# --- #1652: the scheduled adapter job's test selector ------------------------
# `adapter-integration.yml` is the only job that runs the real adapter probes
# against the real fixtures, and it selects them with a whole-tree
# `pytest tests/tools/`. Nothing asserted that argv: a narrowing edit to a
# passing subset would leave the daily job GREEN while the probes it exists to
# run no longer execute. `tests/test_integration_strictness.py` asserts the
# SUBSTRING "tests/tools/", which `pytest tests/tools/test_brakeman.py` also
# contains -- so the convention needed pinning as an argv, not as a fragment.
#
# Here rather than there because this module is where the fleet's unwritten
# workflow conventions are written down as tests, beside the `uses:` pin and
# the install pin, sharing one workflow reader.
ADAPTER_WORKFLOW = "adapter-integration.yml"
ADAPTER_JOB = "integration"
# #1655's lane, in the same workflow. Its selector is ONE file on purpose:
# it is the job that executes attacker-shaped build logic, and it runs only
# the test written to be run that way. Pinned for the same reason as its
# sibling -- a selector that drifted would leave a scheduled green tick over
# a probe that no longer runs.
CONTAINMENT_JOB = "containment"
CONTAINMENT_SELECTOR = ("python3", "-m", "pytest",
                        "tests/tools/test_hostile_csproj.py", "-q", "-rs",
                        "-p", "no:cacheprovider")
# Both of this workflow's jobs, so a THIRD is an explicit decision rather than
# a silent one: the selector pins are per-job, so a new job would arrive with
# no selector pinned at all, and this is the workflow where a job means
# "something runs adapters, or hostile build logic, on a schedule".
EXPECTED_ADAPTER_JOBS = ("containment", "integration")

# The exact argv, in order. `tests/tools/` and not a `*_integration.py` glob:
# the railsgoat probe that caught the stale brakeman CWE map lives in
# test_brakeman.py, so a glob would scope around the class of defect this job
# exists to catch. `-rs` prints the skip reasons, which is how a strict-mode
# run is read at all.
ADAPTER_SELECTOR = ("python3", "-m", "pytest", "tests/tools/", "-q", "-rs",
                    "-p", "no:cacheprovider")

_PYTHON = re.compile(r"python3?$")


def _is_pytest(argv):
    """`pytest ...` or `python3 -m pytest ...` as the command's OWN argv.

    Not a substring test: the `docker run ... -c "python3 -m pytest ..."` line
    CONTAINS the word, and reading the outer command as the pytest invocation
    would pin `docker`'s flags instead of the selector.
    """
    if argv[:1] == ["pytest"]:
        return True
    return (len(argv) >= 3 and _PYTHON.match(argv[0]) and argv[1] == "-m"
            and argv[2] == "pytest")


def pytest_argvs(script):
    """Every pytest invocation in a shell script, as argv lists.

    Reads INSIDE `sh -c "<command>"`: the adapter job runs its tests in a
    container, so the selector is a quoted argument of `docker run`, and a
    reader that stopped at the outer command would see no pytest at all.
    """
    found, pending = [], [script]
    while pending:
        text = join_continuations(_without_comments(pending.pop(0)))
        for segment in re.split(r"&&|\|\||;|\n", text):
            seg = " ".join(segment.split())
            if not seg:
                continue
            try:
                argv = shlex.split(seg)
            except ValueError:                  # an unbalanced quote
                continue
            if not argv:
                continue
            if _is_pytest(argv):
                found.append(argv)
                continue
            # A quoted sub-command (`-c "..."`) arrives as ONE token holding
            # whitespace; anything else cannot be a command.
            pending.extend(t for t in argv
                           if "pytest" in t and len(t.split()) > 1)
    return found


def selector_defect(argvs, expected=ADAPTER_SELECTOR):
    """Why this job's pytest selector is not the pinned one, or None."""
    if not argvs:
        return ("no pytest command in the step that runs the adapter tests -- "
                "the job that exists to execute the real adapter probes runs "
                "none")
    if len(argvs) > 1:
        return ("%d pytest commands in one step; the pin describes one: %s"
                % (len(argvs), " | ".join(" ".join(a) for a in argvs)))
    if tuple(argvs[0]) != tuple(expected):
        return ("selector is `%s`; the pin is `%s`. A narrowed selector leaves "
                "the scheduled job green while the adapter probes it exists to "
                "run no longer execute (#1652)"
                % (" ".join(argvs[0]), " ".join(expected)))
    return None


def _adapter_doc():
    path = os.path.join(WORKFLOW_DIR, ADAPTER_WORKFLOW)
    with open(path, encoding="utf-8") as fh:
        return yaml.safe_load(fh.read()) or {}


def _adapter_run_steps(job=ADAPTER_JOB):
    """One JOB's `run:` steps. #1655 added a second job to this workflow with
    a selector of its own (one file, deliberately), so a reader that pooled
    every step in the file would see two pytest commands where the pin
    describes one -- and would stop being able to say which job narrowed."""
    return [step for name, steps in run_jobs(_adapter_doc()) if name == job
            for step in steps]


class TestAdapterSelectorRule(unittest.TestCase):
    """The rule, on scratch scripts -- both answers."""

    SHIPPED = ('docker run --rm \\\n  -v "$PWD:/work:ro" -w /work \\\n'
               '  -e PANOPTICON_REQUIRE_INTEGRATION=1 \\\n'
               '  --entrypoint sh panopticon-fixtures:latest \\\n'
               '  -c "python3 -m pytest tests/tools/ -q -rs -p no:cacheprovider"\n')

    def test_the_shipped_shape_reads_as_the_pinned_selector(self):
        self.assertEqual([list(ADAPTER_SELECTOR)], pytest_argvs(self.SHIPPED))
        self.assertIsNone(selector_defect(pytest_argvs(self.SHIPPED)))

    def test_a_narrowed_selector_is_a_defect(self):
        narrowed = self.SHIPPED.replace("tests/tools/ ",
                                        "tests/tools/test_brakeman.py ")
        why = selector_defect(pytest_argvs(narrowed))
        self.assertIsNotNone(why, "a narrowed selector passed the pin")
        self.assertIn("test_brakeman.py", why)
        # ...and the reason this pin had to be an argv: the substring check
        # that already existed cannot see the narrowing at all.
        self.assertIn("tests/tools/", narrowed)

    def test_a_k_filter_is_a_defect(self):
        narrowed = self.SHIPPED.replace("-q -rs", "-k parse -q -rs")
        self.assertIsNotNone(selector_defect(pytest_argvs(narrowed)))

    def test_a_step_that_runs_no_pytest_is_a_defect(self):
        why = selector_defect(pytest_argvs("docker build -t x .\n"))
        self.assertIsNotNone(why)
        self.assertIn("no pytest command", why)

    def test_the_outer_docker_command_is_not_mistaken_for_the_selector(self):
        argvs = pytest_argvs(self.SHIPPED)
        self.assertEqual(1, len(argvs))
        self.assertNotIn("docker", argvs[0])


class TestTheAdapterJobsSelectorIsPinned(unittest.TestCase):
    def test_the_scheduled_job_still_runs_the_whole_tools_tree(self):
        steps = _adapter_run_steps()
        argvs = [a for step in steps for a in pytest_argvs(step.script)]
        self.assertIsNone(selector_defect(argvs),
                          selector_defect(argvs) or "")

    def test_the_containment_job_runs_the_hostile_build_test(self):
        steps = _adapter_run_steps(CONTAINMENT_JOB)
        argvs = [a for step in steps for a in pytest_argvs(step.script)]
        why = selector_defect(argvs, expected=CONTAINMENT_SELECTOR)
        self.assertIsNone(why, why or "")

    def test_the_workflow_carries_exactly_the_two_pinned_jobs(self):
        self.assertEqual(
            EXPECTED_ADAPTER_JOBS, tuple(sorted(_adapter_doc().get("jobs") or {})),
            "%s gained or lost a job. Each job here has its own pinned pytest "
            "selector, so a new one is unpinned until it is named: add it to "
            "EXPECTED_ADAPTER_JOBS and pin what it runs (#1655)."
            % ADAPTER_WORKFLOW)

    def test_the_reader_actually_found_the_workflow(self):
        # Guards the guard: an unreadable workflow would produce no argvs and
        # the assertion above would report a defect rather than a silent pass,
        # but a reader that found no STEPS at all is broken, not the fleet.
        self.assertTrue(_adapter_run_steps(), "no run: steps in " + ADAPTER_WORKFLOW)
        self.assertTrue(_adapter_run_steps(CONTAINMENT_JOB),
                        "no run: steps in %s / %s" % (ADAPTER_WORKFLOW,
                                                      CONTAINMENT_JOB))


# --- #1655: which CI lane, if any, opts the hostile build in -----------------
# `tests/tools/test_hostile_csproj.py` is the only test that invokes an adapter
# on a hostile project, and it sits behind four guards -- the
# PANOPTICON_CONTAINMENT_PROBE opt-in, the fixture, adapter applicability, and
# `dotnet`. The opt-in exists because the test EXECUTES evil.csproj's hostile
# MSBuild target, which must only happen inside a no-egress container.
#
# The runtime half of the guard lives beside that test (it has to observe the
# other three preconditions where they are evaluated, and tests/tools/ runs
# inside the fixtures image, which carries no PyYAML). This half reads the
# fleet and pins the answer to "which lane is supposed to run it", so the skip
# reason over there cannot quietly stop being true.
CONTAINMENT_PROBE_ENV = "PANOPTICON_CONTAINMENT_PROBE"

# (workflow, job, step name) that set it to "1". ONE lane, per the owner
# ruling of 2026-09-22: `adapter-integration.yml`'s `containment` job, on the
# same daily schedule as its `integration` sibling, running the hostile build
# inside the fixtures image with the network switched off. Adding or removing
# a lane is a decision about where hostile MSBuild logic may execute, not a
# test edit: change this AND the skip reason in
# tests/tools/test_hostile_csproj.py, which names the same lane.
EXPECTED_CONTAINMENT_LANES = (
    ("adapter-integration.yml", "containment",
     "Run the hostile-build containment probe offline"),)

# `docker run` env flags, in every spelling docker accepts: `-e VAR=VALUE`,
# `-eVAR=VALUE`, `--env VAR=VALUE`, `--env=VAR=VALUE`. A step's env is not only
# its `env:` block -- this job passes the flags into the container on the
# command line, so a reader that looked only at `env:` would find nothing.
#
# R1 Minor 6: this matched `-e VAR=VALUE` alone. A lane added in any of the
# other three spellings would have left `EXPECTED_CONTAINMENT_LANES = ()`
# passing while a lane HAD opted in -- the false-negative direction the pin
# exists to close. The leading `(?:^|\s)` is what keeps `--entrypoint` and
# `--env-file` out: neither has whitespace immediately before its `-e`/`--env`,
# and `--env-file` is followed by `-`, which is neither a space nor `=`.
_DOCKER_ENV = re.compile(
    r"(?:^|\s)(?:-e\s*|--env[\s=])([A-Za-z_][A-Za-z0-9_]*)=(\S+)")


def step_env(doc, job, step_name, script):
    """Every variable this step's command ends up seeing.

    Workflow `env:`, then the job's, then the step's, then anything the step
    passes into a container with `-e`/`--env`, in any of docker's four
    spellings. Later wins, which is the order Actions and docker apply them in.
    """
    env = {}
    for block in ((doc.get("env") or {}),
                  ((doc.get("jobs") or {}).get(job) or {}).get("env") or {}):
        env.update({k: str(v) for k, v in block.items()})
    for step in ((doc.get("jobs") or {}).get(job) or {}).get("steps") or []:
        if isinstance(step, dict) and (step.get("name") or UNNAMED) == step_name:
            env.update({k: str(v) for k, v in (step.get("env") or {}).items()})
    env.update(dict(_DOCKER_ENV.findall(join_continuations(_without_comments(script)))))
    return env


def _run_steps_with_env():
    """[(workflow, job, step name, {VAR: value}, script)] for the whole fleet.

    The script travels with the env because #1655's second half asks a
    question ABOUT the command line the first half read the env out of: is the
    `docker run` that carries the opt-in offline.
    """
    rows = []
    for path in _workflow_files():
        with open(path, encoding="utf-8") as fh:
            doc = yaml.safe_load(fh.read()) or {}
        for job, steps in run_jobs(doc):
            for step in steps:
                rows.append((os.path.basename(path), job, step.name,
                             step_env(doc, job, step.name, step.script),
                             step.script))
    return rows


def _run_step_envs():
    """[(workflow, job, step name, {VAR: value})] for the whole fleet."""
    return [row[:4] for row in _run_steps_with_env()]


def containment_lanes(rows=None):
    """(workflow, job, step) for every lane that opts the hostile build in."""
    return tuple((wf, job, name) for wf, job, name, env
                 in (rows if rows is not None else _run_step_envs())
                 if env.get(CONTAINMENT_PROBE_ENV) == "1")


class TestContainmentLaneRule(unittest.TestCase):
    """The reader, on scratch documents -- both answers."""

    DOC = {"jobs": {"integration": {"steps": [
        {"name": "Run", "run": 'docker run -e PANOPTICON_REQUIRE_INTEGRATION=1 '
                               'sh -c "pytest tests/tools/"'}]}}}

    def _rows(self, doc):
        return [("scratch.yml", job, step.name,
                 step_env(doc, job, step.name, step.script))
                for job, steps in run_jobs(doc) for step in steps]

    def test_a_lane_that_opts_in_is_found(self):
        doc = {"jobs": {"integration": {"steps": [
            {"name": "Run", "run": 'docker run -e %s=1 sh -c "pytest x"'
                                   % CONTAINMENT_PROBE_ENV}]}}}
        self.assertEqual((("scratch.yml", "integration", "Run"),),
                         containment_lanes(self._rows(doc)))

    def test_a_job_level_env_block_counts_too(self):
        doc = {"jobs": {"integration": {"env": {CONTAINMENT_PROBE_ENV: 1},
                                        "steps": [{"name": "Run", "run": "pytest x"}]}}}
        self.assertEqual((("scratch.yml", "integration", "Run"),),
                         containment_lanes(self._rows(doc)))

    # R1 Minor 6. All four are valid docker; the reader saw only the first, so
    # a lane added in any of the other three would leave
    # EXPECTED_CONTAINMENT_LANES = () passing while a lane HAD opted in -- the
    # false-negative direction this pin exists to close -- and the `_NO_LANE`
    # skip reason beside the containment test would silently stop being true.
    # `test_the_env_reader_actually_reads_the_fleet` cannot catch it: it only
    # proves the reader finds PANOPTICON_REQUIRE_INTEGRATION=1, which the
    # current fleet happens to spell `-e VAR=VALUE`.
    SPELLINGS = ("-e %s=1", "--env %s=1", "--env=%s=1", "-e%s=1")

    def test_every_docker_spelling_of_the_opt_in_is_found(self):
        for spelling in self.SPELLINGS:
            with self.subTest(spelling=spelling):
                run = ('docker run --rm --entrypoint sh %s image -c "pytest x"'
                       % (spelling % CONTAINMENT_PROBE_ENV))
                doc = {"jobs": {"j": {"steps": [{"name": "R", "run": run}]}}}
                self.assertEqual((("scratch.yml", "j", "R"),),
                                 containment_lanes(self._rows(doc)), run)

    def test_neighbouring_docker_flags_are_not_read_as_env(self):
        # The other direction: `--entrypoint` and `--env-file` must not be
        # mistaken for `-e`/`--env`, or the reader invents lanes.
        doc = {"jobs": {"j": {"steps": [{"name": "R", "run":
               "docker run --entrypoint sh --env-file ci.env image"}]}}}
        self.assertEqual({}, self._rows(doc)[0][3])

    def test_a_lane_that_does_not_opt_in_is_not_found(self):
        self.assertEqual((), containment_lanes(self._rows(self.DOC)))

    def test_any_other_value_does_not_count_as_opting_in(self):
        for value in ("0", "true", "", "2"):
            with self.subTest(value=value):
                doc = {"jobs": {"j": {"env": {CONTAINMENT_PROBE_ENV: value},
                                      "steps": [{"name": "R", "run": "pytest x"}]}}}
                self.assertEqual((), containment_lanes(self._rows(doc)))


class TestTheFleetsContainmentLanesArePinned(unittest.TestCase):
    def test_the_set_of_lanes_that_opt_in_is_the_recorded_one(self):
        self.assertEqual(
            EXPECTED_CONTAINMENT_LANES, containment_lanes(),
            "a CI lane's %s setting changed. That is a decision about where "
            "hostile MSBuild logic may execute: update "
            "EXPECTED_CONTAINMENT_LANES here AND the skip reason in "
            "tests/tools/test_hostile_csproj.py, which names the same fact "
            "(#1655)." % CONTAINMENT_PROBE_ENV)

    def test_the_env_reader_actually_reads_the_fleet(self):
        # Guards the guard. An empty answer above is only meaningful if the
        # reader can find an env var it is NOT looking for: a parser that
        # returned {} for every step would pin "no lane" forever, and the
        # runtime guard beside the containment test would skip in silence.
        rows = _run_step_envs()
        self.assertTrue(
            any(env.get("PANOPTICON_REQUIRE_INTEGRATION") == "1"
                for _wf, _job, _step, env in rows),
            "the workflow env reader found no integration lane at all; it is "
            "broken, not the fleet")


# --- #1655 ruling: the opt-in and `--network none`, together -----------------
# The owner ruling (2026-09-22) is that a scheduled lane DOES run the hostile
# build. Two controls make that safe and neither is sufficient alone:
# `PANOPTICON_CONTAINMENT_PROBE=1` is the opt-in, and `--network none` on the
# same `docker run` is what makes the opt-in true -- evil.csproj's hostile
# MSBuild target attempts a live `curl`, and the probe beside the test
# (`_UNCONTAINED_MSG`) refuses an opted-in run whose egress is reachable. A
# lane that set only the env var would be opted in on a network-enabled
# runner, which is the one outcome the opt-in exists to prevent.
#
# So the pin above ("which lanes opt in") is only half an answer. This half
# reads the `docker run` those lanes actually execute and requires the network
# to be off on the same invocation that carries the flag.


def docker_run_argvs(script):
    """Every `docker run` invocation in a step's script, as argv lists.

    Through `shell_reader`, not a regex: the flags are written across six
    continued lines, and the container's own command is a quoted argument of
    the same invocation. `_shell_command` strips `sudo`/`env`-style wrappers,
    so `sudo docker run ...` reads as the same act.
    """
    found = []
    for statement in _statements(script):
        for stage in statement.stages:
            argv = _shell_command(stage.argv)
            if not argv or os.path.basename(argv[0]) != "docker":
                continue
            if [t for t in argv[1:] if not t.startswith("-")][:1] == ["run"]:
                found.append(argv)
    return found


# `--net` is docker's older spelling of `--network` and still works, so a lane
# written with it is contained and must not read as a defect.
_NETWORK_FLAGS = ("--network", "--net")

# `docker run [FLAGS] IMAGE [COMMAND...]`. Only the tokens BEFORE the image are
# docker's: `--network none` after it is an argument handed to the container's
# entrypoint, and `-e VAR=1` after it never becomes an environment variable at
# all. Both mis-writings break the step loudly at run time -- but a guard that
# called either one contained would be asserting the opposite of what docker
# does, so the reader stops at the image operand.
#
# Finding it means knowing which flags consume the next token. The table is
# what this fleet writes plus its common neighbours; an UNKNOWN flag is not
# assumed to be either kind, because guessing wrong moves the boundary and
# silently changes every answer past it. Unknown means UNREAD, which is a
# defect, not a pass.
_DOCKER_VALUE_FLAGS = frozenset((
    "-v", "--volume", "-e", "--env", "--env-file", "-w", "--workdir",
    "--entrypoint", "--network", "--net", "--name", "-u", "--user",
    "-p", "--publish", "--expose", "--mount", "--tmpfs", "-l", "--label",
    "--add-host", "--device", "--cap-add", "--cap-drop", "--security-opt",
    "--platform", "--pull", "--memory", "-m", "--cpus", "-h", "--hostname",
    "--ulimit", "--log-driver", "--restart", "--shm-size", "--dns", "--gpus",
    "--link", "--pid", "--ipc", "--userns", "--stop-signal", "--health-cmd",
))
_DOCKER_BOOL_FLAGS = frozenset((
    "--rm", "-d", "--detach", "-i", "--interactive", "-t", "--tty", "-it",
    "-ti", "-itd", "--init", "--privileged", "--read-only", "--sig-proxy",
    "--no-healthcheck", "-q", "--quiet", "--disable-content-trust",
))


def docker_image_index(argv):
    """(index of the image operand, None), or (None, why it cannot be found).

    An `=`-attached flag (`--network=none`, `-eVAR=1`) consumes nothing
    further, which is why the check is on the token rather than on the name.
    """
    index = argv.index("run") + 1
    while index < len(argv):
        token = argv[index]
        if not token.startswith("-"):
            return index, None
        if "=" in token or token in _DOCKER_BOOL_FLAGS:
            index += 1
        elif token in _DOCKER_VALUE_FLAGS:
            index += 2
        else:
            return None, (
                "`docker run` carries %r, which this guard's flag table does "
                "not know, so it cannot say where the image operand starts -- "
                "and everything after the image belongs to the container, not "
                "to docker. Add it to _DOCKER_VALUE_FLAGS or "
                "_DOCKER_BOOL_FLAGS (#1655)" % token)
    return None, "`docker run` names no image at all"


def _flag_value(argv, names):
    """The value of `--name value` / `--name=value`, or None if absent."""
    for index, token in enumerate(argv):
        for name in names:
            if token == name:
                return argv[index + 1] if index + 1 < len(argv) else ""
            if token.startswith(name + "="):
                return token.split("=", 1)[1]
    return None


def _carries_opt_in(argv):
    """True if this `docker run` hands the container the opt-in itself."""
    return dict(_DOCKER_ENV.findall(" ".join(argv))).get(
        CONTAINMENT_PROBE_ENV) == "1"


def containment_defect(script):
    """Why an opted-in step would execute the hostile build uncontained, or None.

    The rule is about the ONE invocation that carries the opt-in, and about the
    part of it docker reads: a sibling `docker run --network none` elsewhere in
    the step contains nothing, a flag written past the image operand is the
    container's argument rather than docker's, and a step that opts in with no
    container at all runs evil.csproj's `curl` on the runner. All of them are
    the same defect as the missing flag.
    """
    opted = 0
    for argv in docker_run_argvs(script):
        if not _carries_opt_in(argv):
            continue            # not this invocation's business, either way
        index, why = docker_image_index(argv)
        if why is not None:
            return why
        flags = argv[:index]
        if not _carries_opt_in(flags):
            return ("%s=1 is written after the image operand, where docker "
                    "hands it to the container's own command instead of "
                    "setting it -- the probe would never be opted in (#1655)"
                    % CONTAINMENT_PROBE_ENV)
        opted += 1
        network = _flag_value(flags, _NETWORK_FLAGS)
        if network is None:
            return ("the `docker run` that sets %s=1 carries no `--network "
                    "none` among its flags, so the hostile build's live curl "
                    "reaches the network from a CI runner (#1655)"
                    % CONTAINMENT_PROBE_ENV)
        if network != "none":
            return ("the `docker run` that sets %s=1 runs on network %r, not "
                    "`none` (#1655)" % (CONTAINMENT_PROBE_ENV, network))
    if not opted:
        return ("no `docker run` in this step hands %s=1 to a container -- a "
                "job- or step-level `env:` block does not reach one -- so "
                "whatever is opted in either executes the hostile MSBuild "
                "target on the runner itself or never runs the probe at all "
                "(#1655)" % CONTAINMENT_PROBE_ENV)
    return None


class TestTheOfflineRule(unittest.TestCase):
    """The reader and the rule, on scratch scripts -- both answers."""

    CONTAINED = ('docker run --rm \\\n  -v "$PWD:/work:ro" -w /work \\\n'
                 '  --network none \\\n'
                 '  -e PANOPTICON_CONTAINMENT_PROBE=1 \\\n'
                 '  --entrypoint sh panopticon-fixtures:latest \\\n'
                 '  -c "python3 -m pytest tests/tools/test_hostile_csproj.py -q"\n')

    def test_the_shipped_shape_reads_as_one_docker_run(self):
        argvs = docker_run_argvs(self.CONTAINED)
        self.assertEqual(1, len(argvs), argvs)
        self.assertEqual(["docker", "run"], argvs[0][:2])

    def test_a_contained_lane_is_not_a_defect(self):
        self.assertIsNone(containment_defect(self.CONTAINED))

    def test_dropping_the_flag_is_a_defect(self):
        why = containment_defect(self.CONTAINED.replace(
            "  --network none \\\n", ""))
        self.assertIsNotNone(why, "an opted-in lane with no --network passed")
        self.assertIn("--network none", why)

    def test_another_network_is_a_defect(self):
        why = containment_defect(self.CONTAINED.replace("--network none",
                                                        "--network host"))
        self.assertIsNotNone(why)
        self.assertIn("host", why)

    def test_both_spellings_of_the_flag_are_read(self):
        for spelling in ("--network none", "--network=none", "--net none",
                         "--net=none"):
            with self.subTest(spelling=spelling):
                self.assertIsNone(containment_defect(
                    self.CONTAINED.replace("--network none", spelling)))

    def test_opting_in_with_no_container_at_all_is_a_defect(self):
        why = containment_defect('PANOPTICON_CONTAINMENT_PROBE=1 pytest x\n')
        self.assertIsNotNone(why)
        self.assertIn("on the runner itself", why)

    def test_a_contained_sibling_does_not_vouch_for_the_opted_in_run(self):
        # The flag has to be on the invocation that carries the opt-in; a
        # second, offline `docker run` in the same step contains nothing.
        script = ('docker run --rm --network none alpine true\n'
                  'docker run --rm -e PANOPTICON_CONTAINMENT_PROBE=1 image sh\n')
        why = containment_defect(script)
        self.assertIsNotNone(why, "a sibling --network none vouched for it")
        self.assertIn("--network none", why)

    # --- the image operand is the boundary, and it is not decoration --------

    def test_the_image_operand_is_found_past_the_value_taking_flags(self):
        argv = docker_run_argvs(self.CONTAINED)[0]
        index, why = docker_image_index(argv)
        self.assertIsNone(why, why or "")
        self.assertEqual("panopticon-fixtures:latest", argv[index])

    def test_the_network_flag_after_the_image_is_not_dockers(self):
        # docker hands everything after the image to the container's command,
        # so `--network none` there is an argument to `sh`, not containment.
        script = ('docker run --rm -v "$PWD:/work:ro" -w /work \\\n'
                  '  -e PANOPTICON_CONTAINMENT_PROBE=1 \\\n'
                  '  --entrypoint sh panopticon-fixtures:latest \\\n'
                  '  --network none -c "python3 -m pytest x"\n')
        why = containment_defect(script)
        self.assertIsNotNone(why, "a flag written after the image read as "
                                  "containment")
        self.assertIn("--network none", why)

    def test_the_opt_in_after_the_image_never_reaches_the_container(self):
        script = ('docker run --rm --network none \\\n'
                  '  --entrypoint sh panopticon-fixtures:latest \\\n'
                  '  -e PANOPTICON_CONTAINMENT_PROBE=1 -c "pytest x"\n')
        why = containment_defect(script)
        self.assertIsNotNone(why, "an opt-in written after the image read as "
                                  "opted in")
        self.assertIn("after the image", why)

    def test_an_unknown_flag_is_refused_rather_than_guessed(self):
        # Where the image starts depends on which flags take a value. Guessing
        # moves the boundary and silently changes every answer after it, so an
        # unknown flag is UNREAD, not clean.
        script = ('docker run --rm --frobnicate 3 \\\n'
                  '  --network none -e PANOPTICON_CONTAINMENT_PROBE=1 \\\n'
                  '  --entrypoint sh image -c "pytest x"\n')
        why = containment_defect(script)
        self.assertIsNotNone(why)
        self.assertIn("--frobnicate", why)

    def test_an_unknown_flag_elsewhere_in_the_step_is_not_this_rules_business(self):
        # Only the invocation carrying the opt-in needs its boundary resolved.
        script = ('docker run --frobnicate 3 alpine true\n' + self.CONTAINED)
        self.assertIsNone(containment_defect(script))

    def test_a_step_that_never_opts_in_is_never_asked(self):
        # The rule is only applied to lanes `containment_lanes()` found, but
        # the reader must still be able to tell them apart.
        self.assertFalse(_carries_opt_in(
            ["docker", "run", "-e", "PANOPTICON_REQUIRE_INTEGRATION=1", "i"]))
        self.assertTrue(_carries_opt_in(
            ["docker", "run", "-e", "PANOPTICON_CONTAINMENT_PROBE=1", "i"]))


def uncontained_lanes(rows=None):
    """(workflow, job, step, why) for every opted-in lane that is not offline.

    The two controls are read together on purpose: a lane is only found by
    `containment_lanes()` because something hands it the opt-in, and this asks
    that same step whether the container it hands it to has a network.
    """
    rows = _run_steps_with_env() if rows is None else rows
    found = []
    for wf, job, name, env, script in rows:
        if env.get(CONTAINMENT_PROBE_ENV) != "1":
            continue
        why = containment_defect(script)
        if why is not None:
            found.append((wf, job, name, why))
    return tuple(found)


# The containment job pulls the nightly image from GHCR, so it needs `packages:
# read` on top of the workflow's `contents: read` -- and nothing else. It is
# the job in this repo that deliberately executes attacker-shaped build logic,
# so any write grant on it is a grant to that build.
CONTAINMENT_PERMISSIONS = {"contents": "read", "packages": "read"}


def permissions_defect(doc, job, expected=CONTAINMENT_PERMISSIONS):
    """Why this job's `permissions:` are not the pinned read-only pair, or None.

    A job with no block of its own INHERITS the workflow's, which is the drift
    this pin exists to catch: `contents: read` at the top would silently stop
    being the whole story the day the workflow needs a write scope for
    something else.
    """
    block = ((doc.get("jobs") or {}).get(job) or {}).get("permissions")
    if block is None:
        return ("job %r declares no `permissions:` of its own, so it inherits "
                "the workflow's -- the job that executes hostile build logic "
                "must state its own least privilege (#1655)" % job)
    if not isinstance(block, dict):
        return "job %r sets `permissions: %r`, not a scope map" % (job, block)
    got = {k: str(v) for k, v in block.items()}
    if got != expected:
        return ("job %r has permissions %r; the pin is %r (#1655)"
                % (job, got, expected))
    return None


def _containment_docs():
    """{(workflow, job)} -> parsed workflow, for every recorded lane."""
    docs = {}
    for workflow, job, _step in EXPECTED_CONTAINMENT_LANES:
        path = os.path.join(WORKFLOW_DIR, workflow)
        with open(path, encoding="utf-8") as fh:
            docs[(workflow, job)] = yaml.safe_load(fh.read()) or {}
    return docs


class TestTheLanePermissionsRule(unittest.TestCase):
    """The permissions rule, on scratch documents -- both answers."""

    def _doc(self, permissions):
        return {"permissions": {"contents": "read"},
                "jobs": {"containment": dict(
                    {"steps": []},
                    **({} if permissions is None
                       else {"permissions": permissions}))}}

    def test_the_pinned_pair_is_not_a_defect(self):
        self.assertIsNone(permissions_defect(
            self._doc({"contents": "read", "packages": "read"}), "containment"))

    def test_inheriting_the_workflows_block_is_a_defect(self):
        why = permissions_defect(self._doc(None), "containment")
        self.assertIsNotNone(why)
        self.assertIn("inherits", why)

    def test_a_write_grant_is_a_defect(self):
        why = permissions_defect(self._doc({"contents": "read",
                                            "packages": "write"}), "containment")
        self.assertIsNotNone(why)
        self.assertIn("write", why)

    def test_an_extra_scope_is_a_defect(self):
        why = permissions_defect(self._doc({"contents": "read",
                                            "packages": "read",
                                            "id-token": "write"}), "containment")
        self.assertIsNotNone(why)
        self.assertIn("id-token", why)

    def test_write_all_is_a_defect(self):
        why = permissions_defect(self._doc("write-all"), "containment")
        self.assertIsNotNone(why)
        self.assertIn("scope map", why)


class TestTheFleetsContainmentLaneIsOffline(unittest.TestCase):
    def test_no_lane_runs_the_hostile_build_with_a_network(self):
        offenders = uncontained_lanes()
        self.assertEqual(
            (), offenders,
            "a lane opts the hostile build in without containing it. The "
            "opt-in and `--network none` are one control, not two (#1655):\n"
            + "\n".join("%s %s / %s: %s" % row for row in offenders))

    def test_there_is_a_lane_to_ask(self):
        # Guards the guard: an empty answer above is only meaningful while a
        # lane exists. `EXPECTED_CONTAINMENT_LANES` pins which one.
        self.assertTrue(EXPECTED_CONTAINMENT_LANES)
        self.assertEqual(EXPECTED_CONTAINMENT_LANES, containment_lanes())

    def test_the_rule_is_applied_to_the_recorded_lane(self):
        # ...and that the rule would speak if that lane lost the flag: the
        # same step, read with `--network none` deleted, is a defect.
        rows = [row for row in _run_steps_with_env()
                if (row[0], row[1], row[2]) in EXPECTED_CONTAINMENT_LANES]
        self.assertEqual(len(EXPECTED_CONTAINMENT_LANES), len(rows), rows)
        for wf, job, name, env, script in rows:
            with self.subTest(step=name):
                stripped = script.replace("--network none", "")
                self.assertIsNotNone(
                    containment_defect(stripped),
                    "deleting `--network none` from %s / %s left the lane "
                    "passing; the pin reads something else" % (wf, job))


# The third control in the lane's own comment ("scheduled and manual only"),
# and the only one that was argued in prose and pinned by nothing. `on:` is
# read as `True` because YAML 1.1 parses the bare key as a boolean.
EXPECTED_CONTAINMENT_TRIGGERS = {"schedule", "workflow_dispatch"}


class TestTheContainmentLaneIsLeastPrivilege(unittest.TestCase):
    def test_the_lane_grants_itself_read_and_nothing_more(self):
        for (workflow, job), doc in _containment_docs().items():
            with self.subTest(job=job):
                self.assertIsNone(permissions_defect(doc, job),
                                  permissions_defect(doc, job) or workflow)

    def test_the_lane_is_never_reachable_from_a_pull_request(self):
        # A `push:`/`pull_request:` trigger on this workflow would run the
        # hostile MSBuild target on whatever a PR proposed -- the one edit the
        # job's comment rules out and nothing else in the suite refuses.
        # `privilege_defect` only fires on `pull_request_target`, and
        # tests/test_integration_strictness.py asserts the two triggers are
        # PRESENT, never that they are all there is.
        for (workflow, _job), doc in _containment_docs().items():
            with self.subTest(workflow=workflow):
                triggers = set(doc.get(True, doc.get("on")) or {})
                self.assertEqual(
                    EXPECTED_CONTAINMENT_TRIGGERS, triggers,
                    "%s carries a lane that executes attacker-shaped build "
                    "logic; its trigger surface is scheduled and manual only "
                    "(#1655). Adding one is a decision about whose code runs, "
                    "not a workflow edit." % workflow)


# --- ARC-2930403871 (#1771): both adapter lanes run as production's user ------
# `Dockerfile.fixtures` ends on `USER root`, correctly, for its BUILD: it
# installs language toolchains and writes build artifacts. Nothing dropped that
# privilege at run time and this workflow passed no `--user`, so the ONE gate
# where the adapters meet real tools and real fixtures exercised them as uid 0
# while every production scan runs the tools image as `scanner` (the
# `Dockerfile`'s `useradd -m -u 1000 scanner` and its closing `USER scanner`).
# A root-only adapter regression -- the #1877 class, a tool refusing
# its input under the real uid -- passed the only gate that could catch it.
#
# The posture has two halves and both are pinned. STATIC: every `docker run` of
# the fixtures image carries `--user` naming production's user, read through the
# workflow's own `env:` block so the pin follows the VALUE rather than the
# spelling. RUNTIME: each job asks the CONTAINER what it is before it runs
# anything else, which is the half that catches a `--user` docker could not
# honour (an image whose passwd stopped carrying the user) -- otherwise that is
# a green tick over probes run as root, which is the finding itself.
#
# By name rather than `1000:1000`: the Dockerfile states the uid and says
# nothing about the gid, so the name is the only spelling that takes
# production's own primary group instead of a guessed one. The uid is pinned all
# the same -- it travels into the container as `EXPECTED_UID`, which is what the
# assertion compares `id -u` against. And the number is not hand-copied: it is
# READ out of the `Dockerfile`'s `useradd` line below and compared to both this
# constant and the workflow's `env:` value, so the PR that changes the uid goes
# red rather than the daily job one PR later.
FIXTURES_IMAGE = "panopticon-fixtures:latest"
EXPECTED_SCANNER_USER = "scanner"        # the tools image's closing `USER scanner`
EXPECTED_SCANNER_UID = "1000"            # its `useradd -m -u 1000 scanner`
UID_ASSERTION_ENV = "EXPECTED_UID"
# Every spelling of the user flag docker accepts, for the readers AND for the
# mutations that take it away: one pattern, so a meta-test cannot drift from the
# rule it is exercising (R2-2).
_USER_FLAG = re.compile(r"(?:--user|-u)(?:=\S+|\s+\S+)")
# The account the tools image creates, as the `Dockerfile` writes it. Anchored on
# the flags rather than on a line number: this is the one fact three files repeat
# (the workflow's `env:`, the constant above, the image's own `USER`), so it is
# read from the source of it.
_USERADD = re.compile(r"useradd\s+-m\s+-u\s+(\d+)\s+%s\b" % EXPECTED_SCANNER_USER)

_VAR = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)")


def dockerfile_scanner_uid(text=None):
    """The uid the tools image's `useradd` creates `scanner` with, or None."""
    if text is None:
        with open(os.path.join(REPO_ROOT, "Dockerfile"), encoding="utf-8") as fh:
            text = fh.read()
    match = _USERADD.search(text)
    return match.group(1) if match else None


def resolve_env(value, env):
    """Every `$VAR` / `${VAR}` in *value* through a step's env; the rest as written.

    The workflow writes `--user "$SCANNER_USER"` and keeps the value in the
    job's `env:` block beside the `Dockerfile` command it comes from, so a reader
    that stopped at the token would pin the spelling and never see the user. A
    name the env does not carry is left as written (`$PWD` stays `$PWD`), which
    is what lets two texts written with different spellings be compared.
    """
    if not value:
        return value
    return _VAR.sub(
        lambda m: env.get(m.group(1) or m.group(2), m.group(0)), value)


def fixtures_runs(script):
    """[(flags, argv, why unreadable)] for each run of the fixtures image.

    `flags` is the part of the invocation docker reads -- everything before the
    image operand -- because a `--user` written after it is an argument handed
    to the container's own command and sets no uid at all.
    """
    found = []
    for argv in docker_run_argvs(script):
        index, why = docker_image_index(argv)
        if why is not None:
            found.append((None, argv, why))
        elif argv[index] == FIXTURES_IMAGE:
            found.append((argv[:index], argv, None))
    return found


def user_defect(script, env):
    """Why a step's run of the fixtures image is not production's user, or None.

    Silent about a step that runs no container: which steps must be asked is
    `fixtures_runs`' answer, and the fleet test below guards that there is one.
    """
    for flags, _argv, why in fixtures_runs(script):
        if why is not None:
            return why
        # docker applies the LAST `--user`, and `_flag_value` returns the
        # first, so a second one would be read as clean while the container ran
        # as whatever it names. An ambiguity is a defect here, the way an
        # unknown flag is above: the sibling reader in
        # `tests/test_integration_strictness.py` fails closed on duplicates too.
        written = [token for token in flags if token in ("--user", "-u")
                   or token.startswith(("--user=", "-u="))]
        if len(written) > 1:
            return ("this `docker run %s` carries %d `--user` flags; docker "
                    "honours the LAST one, so which uid the probes get depends "
                    "on flag order (ARC-2930403871, #1771)"
                    % (FIXTURES_IMAGE, len(written)))
        value = _flag_value(flags, ("--user", "-u"))
        if value is None:
            return ("this `docker run %s` carries no `--user` among its flags, "
                    "so the adapter probes run as uid 0 while every production "
                    "scan runs the tools image as %r (ARC-2930403871, #1771)"
                    % (FIXTURES_IMAGE, EXPECTED_SCANNER_USER))
        resolved = resolve_env(value, env)
        if resolved.split(":")[0] not in (EXPECTED_SCANNER_USER,
                                          EXPECTED_SCANNER_UID):
            return ("this `docker run %s` runs as %r; production runs the tools "
                    "image as %r, uid %s (its `useradd -m -u 1000 scanner` and "
                    "its closing `USER scanner`) "
                    "-- a root-only adapter regression passes a harness that "
                    "runs as root (ARC-2930403871, #1771)"
                    % (FIXTURES_IMAGE, resolved, EXPECTED_SCANNER_USER,
                       EXPECTED_SCANNER_UID))
    return None


def _flag_values(argv, name):
    """Every value written for *name* on *argv*, in both spellings docker takes.

    `_flag_value` above answers "what did the FIRST one say", which is the right
    question for a flag docker resolves by taking one of them (`--user`). These
    are flags docker ACCUMULATES, so the question is which values are present.
    """
    values = []
    for index, token in enumerate(argv):
        if token == name and index + 1 < len(argv):
            values.append(argv[index + 1])
        elif token.startswith(name + "="):
            values.append(token.split("=", 1)[1])
    return values


# #2150 (ARC-A3A): the privilege drop these lanes carry, read from the module
# that OWNS it rather than restated here. A workflow cannot call a Python
# function, so the flags are spelled out in the YAML -- which is a COPY, and this
# pin is the reason the copy is safe: a flag added to
# `scanner_config.privilege_drop_flags` reds every lane until it carries that
# flag too. The resource CEILINGS are deliberately NOT asked for: a lane runs
# EVERY adapter's real scanner in one container over corpora the fixtures image
# already holds, which is not the one-scanner-against-one-target footprint those
# ceilings tune, and the corpus build itself is a `docker build` these flags never
# reach. The workflow states that exemption above its first lane.
def privilege_drop_defect(script):
    """Why a step's run of the fixtures image is not the owner's privilege drop,
    or None.

    Read by flag NAME, and every value the owner writes for that name has to be
    present -- both `--cap-drop` and `--security-opt` are flags docker
    accumulates, so a `name: value` expectation would keep only the last of a
    repeated name and then red a correct lane naming the wrong flag (fix round 1
    nit 4). Either spelling is credited, the way `user_defect` reads `--user`.

    What this does NOT claim: it says the owner's flags are THERE with the
    owner's values. That they are still in FORCE is the sibling rule below.
    """
    expected = {}
    for token in scanner_config.privilege_drop_flags():
        name, sep, value = token.partition("=")
        if not sep:
            return ("`scanner_config.privilege_drop_flags` returned %r, which "
                    "carries no `=`; this pin compares flag VALUES and cannot "
                    "read that shape -- teach it the new shape rather than "
                    "leaving the lanes unpinned (#2150)" % token)
        expected.setdefault(name, []).append(value)
    for flags, _argv, why in fixtures_runs(script):
        if why is not None:
            return why
        for name, values in sorted(expected.items()):
            missing = sorted(set(values) - set(_flag_values(flags, name)))
            if missing:
                return ("this `docker run %s` does not carry `%s` with %s; "
                        "every other panopticon container gets the privilege "
                        "drop from `scanner_config.privilege_drop_flags`, and "
                        "these lanes run the hostile fixture corpus (#2150, "
                        "#1767)" % (FIXTURES_IMAGE, name,
                                    ", ".join(repr(v) for v in missing)))
    return None


# Fix round 1 (review finding 2): the drop above is only in FORCE if nothing on
# the same argv hands the capability straight back. docker applies `--cap-add`
# AFTER `--cap-drop`, and `--privileged` overrides both, so either one turns the
# lane's privilege drop into decoration that the presence pin still credits. A
# SECOND `--security-opt` is the same shape one flag over: `no-new-privileges`
# stays written while a security option nobody reviewed rides in beside it.
_WIDENING_FLAGS = ("--privileged", "--cap-add")


def widened_privileges_defect(script):
    """Why a step's run of the fixtures image gives back what it dropped, or None.

    The `--security-opt` count is DERIVED from the owner's own list rather than
    pinned at one, so the day the owner writes a second one the lanes are
    required to carry two instead of being refused for it.
    """
    allowed = len([token for token in scanner_config.privilege_drop_flags()
                   if token.partition("=")[0] == "--security-opt"])
    for flags, _argv, why in fixtures_runs(script):
        if why is not None:
            return why
        for name in _WIDENING_FLAGS:
            written = [token for token in flags
                       if token == name or token.startswith(name + "=")]
            if written:
                return ("this `docker run %s` carries %s beside the privilege "
                        "drop; docker applies `--cap-add` after `--cap-drop` "
                        "and `--privileged` overrides both, so the drop on the "
                        "line above it is decoration (#2150, #1767)"
                        % (FIXTURES_IMAGE, ", ".join(repr(t) for t in written)))
        options = [token for token in flags if token == "--security-opt"
                   or token.startswith("--security-opt=")]
        if len(options) != allowed:
            return ("this `docker run %s` carries %d `--security-opt` flags; "
                    "`scanner_config.privilege_drop_flags` writes %d, and an "
                    "extra one is a security option nobody reviewed riding in "
                    "beside `no-new-privileges` (#2150)"
                    % (FIXTURES_IMAGE, len(options), allowed))
    return None


# A shell test expression: `[ ... ]` or `test ...`, up to the `;`/`&&`/`||` that
# ends it. The COMPARISON is the subject, not the command: the shipped payload
# names `EXPECTED_UID` twice -- once where it is compared and once in the
# `::error::` sentence -- so a rule that searched the whole command was satisfied
# by the MESSAGE while the comparison drifted to a literal. That is the exact
# drift this half was written to catch, so it is read where it happens.
_TEST_EXPR = re.compile(r"(?:\[|\btest\b)[^;&|]*")


def uid_comparisons(command):
    """Every `[ ... ]` / `test ...` expression in a command that reads `id -u`."""
    return [m.group(0) for m in _TEST_EXPR.finditer(command)
            if "id -u" in m.group(0)]


def asserts_the_uid(script, env):
    """True if this step asks the CONTAINER its uid and fails on a mismatch.

    Not `--user` read a second time: this is the runtime half, and what makes
    it an assertion rather than a log line is the failure arm. The uid it
    compares against travels in as `EXPECTED_UID`, and it has to be the thing
    `id -u` is COMPARED WITH -- a literal there pins a number nothing else in
    the file agrees with, however often the message repeats the variable.
    """
    for flags, argv, why in fixtures_runs(script):
        if why is not None:
            continue
        passed = dict(_DOCKER_ENV.findall(" ".join(flags))).get(UID_ASSERTION_ENV)
        if resolve_env(passed, env) != EXPECTED_SCANNER_UID:
            continue
        command = " ".join(argv[len(flags):])
        compared = uid_comparisons(command)
        if not any(UID_ASSERTION_ENV in expression for expression in compared):
            continue
        # The failure arm may live outside the expression (`else ... exit 1`),
        # so it is the command that must carry it.
        if "exit 1" in command:
            return True
    return False


class TestTheScannerUserRule(unittest.TestCase):
    """The static half, on scratch scripts -- both answers."""

    ENV = {"SCANNER_USER": "scanner", "SCANNER_UID": "1000",
           "SCANNER_HOME": "/home/scanner"}
    SHIPPED = ('docker run --rm \\\n'
               '  --user "$SCANNER_USER" \\\n'
               '  -v "$PWD:/work:ro" -w /work \\\n'
               '  -e HOME="$SCANNER_HOME" \\\n'
               '  --entrypoint sh panopticon-fixtures:latest \\\n'
               '  -c "python3 -m pytest tests/tools/ -q -rs -p no:cacheprovider"\n')

    def test_the_shipped_shape_is_not_a_defect(self):
        self.assertIsNone(user_defect(self.SHIPPED, self.ENV))

    def test_dropping_the_flag_is_a_defect(self):
        why = user_defect(
            self.SHIPPED.replace('  --user "$SCANNER_USER" \\\n', ""), self.ENV)
        self.assertIsNotNone(why, "a root run of the fixtures image passed")
        self.assertIn("--user", why)

    def test_running_as_root_is_a_defect(self):
        for spelling in ("--user root", "--user 0:0", "-u 0", "--user=root"):
            with self.subTest(spelling=spelling):
                why = user_defect(
                    self.SHIPPED.replace('--user "$SCANNER_USER"', spelling),
                    self.ENV)
                self.assertIsNotNone(why, "%s passed" % spelling)

    def test_the_value_is_read_through_the_jobs_env_block(self):
        # The pin follows the VALUE: an `env:` block that points the flag at
        # root is the same defect as writing root on the command line, and a
        # reader that stopped at `$SCANNER_USER` could not tell them apart.
        why = user_defect(self.SHIPPED, dict(self.ENV, SCANNER_USER="root"))
        self.assertIsNotNone(why, "the pin read the spelling, not the value")
        self.assertIn("root", why)

    def test_the_numeric_spelling_of_the_same_user_is_accepted(self):
        for spelling in ("1000", "1000:1000"):
            with self.subTest(spelling=spelling):
                self.assertIsNone(user_defect(
                    self.SHIPPED.replace('"$SCANNER_USER"', spelling), self.ENV))

    def test_a_second_user_flag_is_a_defect(self):
        # docker honours the LAST `--user`; a reader that returns the first
        # would call this clean while the container ran as root.
        for second in ("--user root", "-u 0", "--user=root",
                       '--user "$SCANNER_USER"'):
            with self.subTest(second=second):
                script = self.SHIPPED.replace(
                    '  --user "$SCANNER_USER" \\\n',
                    '  --user "$SCANNER_USER" %s \\\n' % second)
                why = user_defect(script, self.ENV)
                self.assertIsNotNone(why, "two --user flags passed")
                self.assertIn("honours the LAST one", why)

    def test_a_flag_written_after_the_image_is_not_dockers(self):
        # docker hands everything past the image to the container's command, so
        # `--user` there sets no uid -- the same defect as its absence.
        script = ('docker run --rm -v "$PWD:/work:ro" -w /work \\\n'
                  '  --entrypoint sh panopticon-fixtures:latest \\\n'
                  '  --user scanner -c "python3 -m pytest tests/tools/"\n')
        why = user_defect(script, self.ENV)
        self.assertIsNotNone(why, "a --user past the image read as a uid")
        self.assertIn("--user", why)

    def test_another_images_run_is_not_this_rules_business(self):
        self.assertIsNone(user_defect("docker run --rm alpine true\n", self.ENV))

    def test_an_unknown_flag_is_refused_rather_than_guessed(self):
        # Where the image starts decides which `--user` docker reads, so an
        # unknown flag means UNREAD, not clean.
        why = user_defect(
            self.SHIPPED.replace("docker run --rm",
                                 "docker run --rm --frobnicate 3"), self.ENV)
        self.assertIsNotNone(why)
        self.assertIn("--frobnicate", why)


class TestTheUidAssertionRule(unittest.TestCase):
    """The runtime half, on scratch scripts -- both answers."""

    ENV = TestTheScannerUserRule.ENV
    ASSERTION = ('docker run --rm \\\n'
                 '  --user "$SCANNER_USER" \\\n'
                 '  -e EXPECTED_UID="$SCANNER_UID" \\\n'
                 '  --entrypoint sh panopticon-fixtures:latest \\\n'
                 '  -c \'if [ "$(id -u)" = "$EXPECTED_UID" ]; then echo ok; '
                 'else echo "::error::not the scanner uid $EXPECTED_UID"; '
                 'exit 1; fi\'\n')

    def test_the_shipped_assertion_is_found(self):
        self.assertTrue(asserts_the_uid(self.ASSERTION, self.ENV))

    def test_an_assertion_with_no_failure_arm_is_a_log_line(self):
        self.assertFalse(asserts_the_uid(
            self.ASSERTION.replace("exit 1", "true"), self.ENV))

    def test_an_assertion_that_never_asks_the_container_is_not_one(self):
        self.assertFalse(asserts_the_uid(
            self.ASSERTION.replace("id -u", "echo 1000"), self.ENV))

    def test_the_uid_it_compares_against_must_be_the_pinned_one(self):
        self.assertFalse(asserts_the_uid(self.ASSERTION,
                                         dict(self.ENV, SCANNER_UID="0")))

    def test_a_hardcoded_uid_in_the_comparison_is_not_an_assertion(self):
        # The env var is what ties the runtime half to the pin, and it is the
        # COMPARISON that has to carry it. This mutation leaves the variable in
        # the `::error::` sentence -- as the shipped payload does -- so a rule
        # that searched the whole command would be satisfied by the message
        # while the number actually pinned became nobody's.
        drifted = self.ASSERTION.replace('= "$EXPECTED_UID" ]', '= "999" ]')
        self.assertIn(UID_ASSERTION_ENV, drifted,
                      "the mutation removed every mention; it would pass the "
                      "old command-wide rule too and prove nothing")
        self.assertFalse(asserts_the_uid(drifted, self.ENV))

    def test_the_comparison_reader_finds_both_shell_spellings(self):
        for spelling in ('[ "$(id -u)" = "$EXPECTED_UID" ]',
                         'test "$(id -u)" = "$EXPECTED_UID"'):
            with self.subTest(spelling=spelling):
                found = uid_comparisons("sh -c if %s; then echo ok; fi" % spelling)
                self.assertEqual(1, len(found), found)
                self.assertIn(UID_ASSERTION_ENV, found[0])

    def test_the_comparison_reader_stops_at_the_end_of_the_expression(self):
        # ...so the `::error::` sentence after the `;` is never read as part of
        # what `id -u` was compared with.
        found = uid_comparisons(
            'sh -c if [ "$(id -u)" = "1000" ]; then echo ok; '
            'else echo "::error::not $EXPECTED_UID"; exit 1; fi')
        self.assertEqual(1, len(found), found)
        self.assertNotIn(UID_ASSERTION_ENV, found[0])

    def test_an_expected_uid_past_the_image_never_reaches_the_container(self):
        script = ('docker run --rm --user scanner \\\n'
                  '  --entrypoint sh panopticon-fixtures:latest \\\n'
                  '  -e EXPECTED_UID=1000 -c \'[ "$(id -u)" = 1000 ] || exit 1\'\n')
        self.assertFalse(asserts_the_uid(script, self.ENV))

    def test_the_pytest_step_is_not_mistaken_for_the_assertion(self):
        self.assertFalse(asserts_the_uid(TestTheScannerUserRule.SHIPPED,
                                         self.ENV))


class TestThePinnedUidIsTheDockerfilesOwn(unittest.TestCase):
    """#1771 F7. Three files repeat one number -- this constant, the workflow's
    `env:`, and the image's own account -- and only the `Dockerfile` decides it.
    Read it there, so the PR that changes the uid reddens instead of the daily
    job one PR later."""

    def test_the_tools_image_still_creates_the_account_at_the_pinned_uid(self):
        found = dockerfile_scanner_uid()
        self.assertIsNotNone(
            found, "no `useradd -m -u <uid> scanner` in the Dockerfile; the "
                   "account this workflow names by user is gone, or written in "
                   "a shape this reader cannot see")
        self.assertEqual(
            EXPECTED_SCANNER_UID, found,
            "the Dockerfile creates `scanner` with uid %s; this module pins %s. "
            "The uid is repeated in the workflow's `env:` and asserted inside "
            "the container, so change all three together (#1771)."
            % (found, EXPECTED_SCANNER_UID))

    def test_both_jobs_env_blocks_carry_the_dockerfiles_uid(self):
        jobs = (_adapter_doc().get("jobs") or {})
        for job in EXPECTED_ADAPTER_JOBS:
            with self.subTest(job=job):
                value = str(((jobs.get(job) or {}).get("env") or {})
                            .get("SCANNER_UID", ""))
                self.assertEqual(
                    dockerfile_scanner_uid(), value,
                    "%s / %s pins SCANNER_UID=%r; the Dockerfile's `useradd` "
                    "says %r" % (ADAPTER_WORKFLOW, job, value,
                                 dockerfile_scanner_uid()))

    def test_the_reader_reads_the_account_and_not_any_useradd(self):
        # Guards the guard, both answers, on scratch text.
        self.assertEqual("1234", dockerfile_scanner_uid(
            "RUN useradd -m -u 1234 scanner \\\n    && chown scanner /x\n"))
        self.assertIsNone(dockerfile_scanner_uid(
            "RUN useradd -m -u 1234 builder\n"))
        self.assertIsNone(dockerfile_scanner_uid("USER scanner\n"))


class TestBothAdapterLanesRunAsProductionsUser(unittest.TestCase):
    """The fleet. Both jobs, because both run the fixtures image."""

    def _rows(self, job):
        doc = _adapter_doc()
        return [(step.name, step.script,
                 step_env(doc, job, step.name, step.script))
                for step in _adapter_run_steps(job)]

    def test_every_run_of_the_fixtures_image_names_the_scanner_user(self):
        for job in EXPECTED_ADAPTER_JOBS:
            for name, script, env in self._rows(job):
                with self.subTest(job=job, step=name):
                    why = user_defect(script, env)
                    self.assertIsNone(why, "%s / %s: %s" % (job, name, why or ""))

    def test_there_is_a_run_to_ask(self):
        # Guards the guard: `user_defect` is silent about a step that runs no
        # container, so the answer above only means something while both jobs
        # actually run the fixtures image.
        for job in EXPECTED_ADAPTER_JOBS:
            with self.subTest(job=job):
                self.assertTrue(
                    [run for _name, script, _env in self._rows(job)
                     for run in fixtures_runs(script)],
                    "no `docker run %s` in %s / %s" % (FIXTURES_IMAGE,
                                                       ADAPTER_WORKFLOW, job))

    def test_every_run_of_the_fixtures_image_carries_the_privilege_drop(self):
        # #2150 (ARC-A3A): the same four lanes, asked about the OTHER half of
        # the launch posture. `_rows` and `fixtures_runs` are shared with the
        # `--user` pin above, so a fifth lane is covered by both the moment it
        # lands.
        for job in EXPECTED_ADAPTER_JOBS:
            for name, script, _env in self._rows(job):
                with self.subTest(job=job, step=name):
                    why = privilege_drop_defect(script)
                    self.assertIsNone(why, "%s / %s: %s" % (job, name, why or ""))

    def test_the_privilege_drop_rule_would_speak_if_a_lane_lost_a_flag(self):
        # Non-vacuity, on this workflow's own steps: the answer above asserts
        # None, which a reader that sees no lane also returns.
        for job in EXPECTED_ADAPTER_JOBS:
            for name, script, _env in self._rows(job):
                if not fixtures_runs(script):
                    continue
                for flag in scanner_config.privilege_drop_flags():
                    with self.subTest(job=job, step=name, flag=flag):
                        self.assertIsNotNone(
                            privilege_drop_defect(script.replace(flag + " ", "")),
                            "%s / %s stayed clean without %s" % (job, name, flag))

    def test_no_run_of_the_fixtures_image_widens_what_it_dropped(self):
        # Fix round 1 (finding 2): the other half of ruling 4's posture. The
        # presence pin above credits a lane that writes `--cap-drop=ALL` and
        # then hands the capabilities back on the next line; this one does not.
        for job in EXPECTED_ADAPTER_JOBS:
            for name, script, _env in self._rows(job):
                with self.subTest(job=job, step=name):
                    why = widened_privileges_defect(script)
                    self.assertIsNone(why, "%s / %s: %s" % (job, name, why or ""))

    def test_the_widening_rule_speaks_for_every_way_back_in(self):
        # Red first is by MUTATION here, not by history: the shipped lanes carry
        # none of these flags, so the rule above could never have been red on
        # this tree. Each widening is inserted into each shipped lane, beside
        # the drop it undoes, and has to be refused BY NAME.
        for job in EXPECTED_ADAPTER_JOBS:
            for name, script, _env in self._rows(job):
                if not fixtures_runs(script):
                    continue
                for widening in ("--privileged", "--cap-add=SYS_ADMIN",
                                 "--security-opt=seccomp=unconfined"):
                    with self.subTest(job=job, step=name, widening=widening):
                        why = widened_privileges_defect(script.replace(
                            "--cap-drop=ALL", "--cap-drop=ALL " + widening))
                        self.assertIsNotNone(
                            why, "%s / %s stayed clean with %s"
                            % (job, name, widening))
                        self.assertIn(widening.partition("=")[0], why)

    def test_the_rule_would_speak_if_a_lane_lost_the_flag(self):
        # ...and that it is this workflow the rule is reading: the same steps,
        # with the flag deleted, are defects. Every spelling docker accepts and
        # `user_defect` reads, `=` forms included: a mutation that only knew
        # `--user` would delete nothing from a lane written `-u`, and then
        # assert a defect that cannot appear on a file that is correct.
        for job in EXPECTED_ADAPTER_JOBS:
            for name, script, env in self._rows(job):
                if not fixtures_runs(script):
                    continue
                with self.subTest(job=job, step=name):
                    stripped = _USER_FLAG.sub("", script)
                    self.assertIsNotNone(
                        user_defect(stripped, env),
                        "deleting the user flag from %s / %s left the lane "
                        "passing; the pin reads something else" % (job, name))

    def test_either_spelling_is_legal_on_the_shipped_lanes(self):
        # `-u` and `--user` are one flag to docker, to `user_defect` and to the
        # strict contract in tests/test_integration_strictness.py. A lane
        # written the short way is correct, so it must be green here -- and the
        # mutation above must still be able to take it away.
        for job in EXPECTED_ADAPTER_JOBS:
            for name, script, env in self._rows(job):
                if not fixtures_runs(script):
                    continue
                with self.subTest(job=job, step=name):
                    short = script.replace('--user "$SCANNER_USER"',
                                           '-u "$SCANNER_USER"')
                    self.assertIsNone(user_defect(short, env))
                    self.assertIsNotNone(user_defect(_USER_FLAG.sub("", short),
                                                     env))

    def test_each_job_asserts_the_uid_before_it_runs_a_probe(self):
        for job in EXPECTED_ADAPTER_JOBS:
            rows = self._rows(job)
            asserted = [i for i, (_n, script, env) in enumerate(rows)
                        if asserts_the_uid(script, env)]
            selected = [i for i, (_n, script, _e) in enumerate(rows)
                        if pytest_argvs(script)]
            with self.subTest(job=job):
                self.assertTrue(
                    asserted,
                    "%s / %s runs the adapter probes without ever asking the "
                    "container which uid it got. `--user` is the intent; `id "
                    "-u` inside the container is the proof (ARC-2930403871, "
                    "#1771)." % (ADAPTER_WORKFLOW, job))
                self.assertTrue(selected, "no pytest step in %s" % job)
                self.assertLess(
                    asserted[0], selected[0],
                    "%s / %s asserts its uid AFTER running the probes, so a "
                    "root run reports its findings first" % (ADAPTER_WORKFLOW,
                                                            job))


# --- ARC-2930403871 (#1771) F10: the hand-run recipe DEVELOPMENT.md publishes --
# `DEVELOPMENT.md` prints the containment lane's `docker run` and says it IS the
# job's own line, so a developer reproducing the lane by hand reproduces the
# lane. This PR falsified that sentence for one edit cycle -- the two new flags
# landed in the workflow and not in the doc -- and only a human reading both
# noticed. The same command is pinned twice from this suite; the PUBLISHED copy
# had no pin at all.
#
# Found by the SENTENCE that claims it rather than by position: the claim is what
# turns a code block into a promise about the workflow, so a block that drifted
# away from its claim is the same defect as one that drifted from the job. The
# job's `env:` is substituted into BOTH sides (`step_env` + `resolve_env`), which
# is what lets the doc write `--user scanner` where the workflow writes
# `--user "$SCANNER_USER"` and still be the same command -- and what makes a
# changed VALUE a defect rather than a spelling difference.
HAND_RUN_DOC = "DEVELOPMENT.md"
HAND_RUN_CLAIM = "the job's `run:` line"
HAND_RUN_STEP = "Run the hostile-build containment probe offline"


def _hand_run_doc_text():
    with open(os.path.join(REPO_ROOT, HAND_RUN_DOC), encoding="utf-8") as fh:
        return fh.read()


def published_hand_run(text):
    """(the block published as the lane's own command, None), or (None, why not).

    Unterminated or unfound is UNREAD, which is a defect rather than a pass --
    the same stance the flag-table reader takes on an unknown docker flag.
    """
    index = text.find(HAND_RUN_CLAIM)
    if index < 0:
        return None, ("%s no longer says the command it publishes is %s, so "
                      "nothing there promises to match the lane (#1771)"
                      % (HAND_RUN_DOC, HAND_RUN_CLAIM))
    fence = text.find("\n```", index)
    if fence < 0:
        return None, ("no fenced block follows the sentence in %s that claims "
                      "to publish %s" % (HAND_RUN_DOC, HAND_RUN_CLAIM))
    start = text.find("\n", fence + 1)
    end = text.find("\n```", start + 1) if start >= 0 else -1
    if start < 0 or end < 0:
        return None, ("the fenced block after that sentence in %s is "
                      "unterminated" % HAND_RUN_DOC)
    return text[start + 1:end], None


def hand_run_defect(text):
    """Why the published hand-run command is not the lane's own, or None."""
    published, why = published_hand_run(text)
    if why is not None:
        return why
    steps = [step for step in _adapter_run_steps(CONTAINMENT_JOB)
             if step.name == HAND_RUN_STEP]
    if len(steps) != 1:
        return ("%s / %s has no step named %r, so the command %s publishes "
                "matches nothing" % (ADAPTER_WORKFLOW, CONTAINMENT_JOB,
                                     HAND_RUN_STEP, HAND_RUN_DOC))
    step = steps[0]
    env = step_env(_adapter_doc(), CONTAINMENT_JOB, step.name, step.script)
    shipped = docker_run_argvs(step.script)
    printed = docker_run_argvs(published)
    if len(shipped) != 1:
        return ("the %r step runs %d containers; this pin describes one"
                % (HAND_RUN_STEP, len(shipped)))
    if len(printed) != 1:
        return ("the block %s publishes as %s carries %d `docker run` commands; "
                "the step runs one" % (HAND_RUN_DOC, HAND_RUN_CLAIM,
                                       len(printed)))
    lane = [resolve_env(token, env) for token in shipped[0]]
    doc = [resolve_env(token, env) for token in printed[0]]
    if lane != doc:
        return ("%s publishes a command that is not the one %s / %s runs, while "
                "saying it is %s -- so a developer reproducing the lane by hand "
                "reproduces something else (#1771).\n  published: %s\n  lane:    "
                "  %s" % (HAND_RUN_DOC, ADAPTER_WORKFLOW, CONTAINMENT_JOB,
                          HAND_RUN_CLAIM, " ".join(doc), " ".join(lane)))
    return None


class TestTheHandRunRecipeRule(unittest.TestCase):
    """The rule, on copies of the doc -- both answers. Never on the file."""

    @staticmethod
    def _doc_with(mutate):
        """The doc with its PUBLISHED BLOCK mutated, and nothing else.

        Mutating the raw text is what these tests did first, and two of them
        went green against a defect: `--user scanner` and the hostile-csproj
        selector both appear in the PROSE above the block (the sentence that
        explains the two flags, and the paragraph naming the file the lane
        runs), so a first-occurrence replace edited the explanation and left the
        command alone. The block is the subject; edit it, not the page.
        """
        text = _hand_run_doc_text()
        block, why = published_hand_run(text)
        assert why is None, why
        return text.replace(block, mutate(block), 1)

    def test_the_shipped_doc_publishes_the_lanes_command(self):
        self.assertIsNone(hand_run_defect(_hand_run_doc_text()))

    def test_a_flag_dropped_from_the_published_copy_is_a_defect(self):
        # Through `_USER_FLAG`, not a literal: `-u` is a legal spelling of the
        # same flag, and a mutation that only knew `--user` would delete nothing
        # from a doc that used the short one and then assert a defect that
        # cannot appear (R2-2, the same trap one module over).
        why = hand_run_defect(self._doc_with(
            lambda block: _USER_FLAG.sub("", block, count=1)))
        self.assertIsNotNone(why, "a published command missing `--user` passed")
        self.assertIn("published", why)

    def test_a_value_changed_in_the_published_copy_is_a_defect(self):
        # The doc writes literals where the workflow writes `$SCANNER_USER`, so
        # the comparison has to substitute -- and still notice `root`.
        why = hand_run_defect(self._doc_with(
            lambda block: _USER_FLAG.sub("--user root", block, count=1)))
        self.assertIsNotNone(why, "a published `--user root` passed")

    def test_a_changed_selector_in_the_published_copy_is_a_defect(self):
        self.assertIsNotNone(hand_run_defect(self._doc_with(
            lambda block: block.replace("tests/tools/test_hostile_csproj.py",
                                        "tests/tools/"))))

    def test_the_home_the_doc_writes_out_is_compared_by_value(self):
        # The one that would have caught this PR's own drift: the doc spells the
        # HOME as a literal, the workflow as `$SCANNER_HOME`.
        self.assertIsNotNone(hand_run_defect(self._doc_with(
            lambda block: block.replace("-e HOME=/home/scanner",
                                        "-e HOME=/root"))))

    def test_losing_the_claim_is_a_defect(self):
        why = hand_run_defect(_hand_run_doc_text().replace(
            HAND_RUN_CLAIM, "one way to run it", 1))
        self.assertIsNotNone(why, "a doc that stopped claiming anything passed")
        self.assertIn("promises", why)

    def test_an_unterminated_block_is_refused_rather_than_guessed(self):
        text = _hand_run_doc_text()
        fence = text.find("\n```", text.find(HAND_RUN_CLAIM))
        why = hand_run_defect(text[:fence + 4])
        self.assertIsNotNone(why)
        self.assertIn("unterminated", why)


class TestThePublishedHandRunIsTheLanesOwnCommand(unittest.TestCase):
    def test_the_doc_publishes_the_command_the_lane_actually_runs(self):
        why = hand_run_defect(_hand_run_doc_text())
        self.assertIsNone(why, why or "")

    def test_the_reader_actually_found_a_command(self):
        # Guards the guard: an empty answer above is only meaningful while the
        # doc still publishes a runnable command under that sentence.
        published, why = published_hand_run(_hand_run_doc_text())
        self.assertIsNone(why, why or "")
        self.assertEqual(1, len(docker_run_argvs(published)), published)


class TestVerifiedPinFreshnessJobs(unittest.TestCase):
    def _defects(self, job, family):
        steps = job.get("steps", [])
        check = next((step for step in steps if step.get("id") == "check"), {})
        apply = next((step for step in steps if
                      "python3 scripts/bump_pins.py " + family + " --write" in
                      step.get("run", "")), {})
        opening = next((step for step in steps if
                        "scripts/open_pin_pr.py" in step.get("run", "")), {})
        defects = []
        if job.get("permissions") != {"contents": "write", "pull-requests": "write"}:
            defects.append("job permissions")
        if not check.get("run", "").startswith("set -euo pipefail\n"):
            defects.append("check shell fail-closed")
        if "python3 scripts/bump_pins.py " + family + " | tee " not in check.get("run", ""):
            defects.append("check command")
        write = "python3 scripts/bump_pins.py " + family + " --write"
        if apply.get("run", "").strip() not in (write, "set -euo pipefail\n" + write):
            defects.append("write command/failure propagation")
        if apply.get("if") != "steps.check.outputs.stale == 'true'":
            defects.append("write condition")
        if opening.get("if") != "steps.check.outputs.stale == 'true'":
            defects.append("PR condition")
        # This is a single command: Actions propagates its exit code. Exact
        # family binding guards against another pin family opening this PR;
        # the helper tests cover branch naming and explicit PR metadata.
        if opening.get("run") != "python3 scripts/open_pin_pr.py " + family:
            defects.append("PR helper/failure propagation")
        if opening.get("env") != {"GH_TOKEN": "${{ github.token }}"}:
            defects.append("PR authentication")
        if not any(re.fullmatch(r"actions/checkout@[0-9a-f]{40}", step.get("uses", ""))
                   for step in steps):
            defects.append("pinned checkout")
        return defects

    def test_verified_pin_jobs_are_scoped_and_fail_closed(self):
        with open(os.path.join(WORKFLOW_DIR, "pin-freshness.yml"), encoding="utf-8") as fh:
            doc = yaml.safe_load(fh)
        self.assertEqual(doc["permissions"], {"contents": "read"})
        for family in ("rustup", "trivy", "rust-toolchain"):
            with self.subTest(family=family):
                self.assertEqual(self._defects(doc["jobs"][family], family), [])

    def test_unsafe_shell_or_permission_changes_are_detected(self):
        with open(os.path.join(WORKFLOW_DIR, "pin-freshness.yml"), encoding="utf-8") as fh:
            doc = yaml.safe_load(fh)
        job = doc["jobs"]["trivy"]
        job["steps"][1]["run"] = job["steps"][1]["run"].replace("set -euo pipefail\n", "")
        job["permissions"] = {"contents": "read"}
        self.assertIn("check shell fail-closed", self._defects(job, "trivy"))
        self.assertIn("job permissions", self._defects(job, "trivy"))

    def test_helper_boundary_negative_controls(self):
        with open(os.path.join(WORKFLOW_DIR, "pin-freshness.yml"), encoding="utf-8") as fh:
            original = yaml.safe_load(fh)["jobs"]["rustup"]
        cases = (
            (lambda job: job["steps"][3].update(run="python3 scripts/open_pin_pr.py trivy"),
             "PR helper/failure propagation"),
            (lambda job: job["steps"][3].update(run="python3 scripts/open_pin_pr.py rustup || true"),
             "PR helper/failure propagation"),
            (lambda job: job["steps"][3].pop("if"), "PR condition"),
            (lambda job: job["steps"][3].pop("env"), "PR authentication"),
            (lambda job: job["steps"][0].update(uses="actions/checkout@v7"),
             "pinned checkout"),
            (lambda job: job["steps"][2].update(run="python3 scripts/bump_pins.py rustup --write || true"),
             "write command/failure propagation"),
        )
        for mutate, expected in cases:
            with self.subTest(expected=expected):
                job = copy.deepcopy(original)
                mutate(job)
                self.assertIn(expected, self._defects(job, "rustup"))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
