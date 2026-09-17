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
from workflow_guard import fetches, job_defects, run_jobs
# #1641's comment-stripper, now `scripts/shell_reader.py`'s: half this repo's
# workflow and Dockerfile prose QUOTES the commands it explains -- including
# the two the install rule was written for -- and a guard that reads a comment
# as an act flags the explanation. One definition, two rules.
# `tests/test_security_workflow.py` imports this name from this module.
from shell_reader import without_comments as _without_comments

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
        found = [(w, f) for w, _j, steps in _run_jobs_in_repo()
                 for step in steps for f in fetches(step.script)]
        self.assertGreaterEqual(
            len(found), 2, "workflow fetch scan found almost nothing; the "
                           "scanner is broken, not the tree")
        self.assertTrue(all(f.url for _w, f in found),
                        "a fetch was seen with no URL parsed out of it: %s" % found)

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
    ("ci.yml", 'pip install -e ".[dev]"',
     "installs THIS repo from THIS checkout; its dependency floors are "
     "pyproject.toml's and Dependabot bumps them."),
    ("ci.yml", 'pip install -e ".[test]"',
     "same, for the test matrix."),
    ("Dockerfile", "semgrep==${SEMGREP_VERSION}",
     "version-pinned by ARG in the same file and rebuilt from a digest-pinned "
     "base; the scanner image is built from main, published to GHCR and pulled "
     "by digest, so the artifact the gate runs is fixed by the image digest "
     "rather than by this line."),
    ("Dockerfile", "pip-audit==${PIP_AUDIT_VERSION}",
     "same: ARG-pinned version inside the digest-pinned scanner image."),
)


def _write_scopes(permissions):
    """The write grants in a `permissions:` block, in either spelling."""
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
    grants = [("workflow", _write_scopes(doc.get("permissions")))]
    for name, job in (doc.get("jobs") or {}).items():
        if isinstance(job, dict):
            grants.append(("job %s" % name, _write_scopes(job.get("permissions"))))
    held = ["%s holds %s" % (where, ", ".join(scopes))
            for where, scopes in grants if scopes]
    if held:
        return "; ".join(held)
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


def _join_lines(script):
    """`\\`-continuations folded in, so an install written across five lines
    reads as the one command it is."""
    return re.sub(r"\\\s*\n\s*", " ", script)


def pip_install_commands(script):
    """Every `pip install` command in a shell script, one per shell command."""
    out = []
    for segment in re.split(r"&&|\|\||;|\n", _join_lines(_without_comments(script))):
        seg = " ".join(segment.split())
        if _PIP_INSTALL.search(seg):
            out.append(seg)
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
    for line in _join_lines(text).splitlines():
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

    def test_a_script_with_no_install_is_left_alone(self):
        self.assertEqual([], pip_install_commands("python -m pytest tests/ -q\n"))


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
            m = re.search(r"^pip==(\S+)", _join_lines(fh.read()), re.M)
        self.assertIsNotNone(m, "the gate's requirements file pins no pip; the "
                                "unpinned `--upgrade pip` it replaced is back")
        pinned = tuple(int(p) for p in m.group(1).split(".") if p.isdigit())
        self.assertGreaterEqual(
            pinned, RUNNER_PIP_FLOOR,
            "pinned pip %s is older than the %s the runner already ships"
            % (m.group(1), ".".join(str(n) for n in RUNNER_PIP_FLOOR)))
