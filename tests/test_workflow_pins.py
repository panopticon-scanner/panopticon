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
import shlex
import unittest

import yaml

from conftest import REPO_ROOT
from workflow_guard import UNNAMED, fetches, job_defects, run_jobs
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

    One exception, and it is narrower than the text split this replaced: a
    heredoc body consumed INSIDE a substitution -- `eval "$(cat <<'EOF' … pip
    install … EOF)"`. The outer parse holds that body in a table the inner
    re-read cannot reach, so what the `eval` runs is unread. Reaching it means
    handing one parse's tables to another, which is the same gap the
    fetch-and-exec guard records for the same shape (see its docstring). Not
    reachable today -- no `cat <<EOF` in any workflow or Dockerfile -- and
    pinned below, so the day it starts being seen this paragraph is edited
    with it.
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

    def test_an_install_inside_a_heredoc_inside_a_substitution_is_unread(self):
        # The one shape narrower than the raw-text split this replaced, and
        # the twin of the fetch guard's own documented gap: the body lives in
        # the OUTER parse's table, which the re-read of the substitution's
        # text cannot reach.
        for script in ('eval "$(cat <<\'EOF\'\npip install evil\nEOF\n)"\n',
                       'X="$(cat <<\'EOF\'\npip install evil\nEOF\n)"\n'):
            self.assertEqual([], pip_install_commands(script), script)

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
            m = re.search(r"^pip==(\S+)", join_continuations(fh.read()), re.M)
        self.assertIsNotNone(m, "the gate's requirements file pins no pip; the "
                                "unpinned `--upgrade pip` it replaced is back")
        pinned = tuple(int(p) for p in m.group(1).split(".") if p.isdigit())
        self.assertGreaterEqual(
            pinned, RUNNER_PIP_FLOOR,
            "pinned pip %s is older than the %s the runner already ships"
            % (m.group(1), ".".join(str(n) for n in RUNNER_PIP_FLOOR)))


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
            rest = [t for t in argv[1:] if not t.startswith("-")]
            if argv and os.path.basename(argv[0]) == "docker" and rest[:1] == ["run"]:
                found.append(argv)
    return found


# `--net` is docker's older spelling of `--network` and still works, so a lane
# written with it is contained and must not read as a defect.
_NETWORK_FLAGS = ("--network", "--net")


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

    The rule is about the ONE invocation that carries the opt-in: a sibling
    `docker run --network none` elsewhere in the step contains nothing, and a
    step that opts in with no container at all runs evil.csproj's `curl` on the
    runner. Both are the same defect as the missing flag.
    """
    opted = [argv for argv in docker_run_argvs(script) if _carries_opt_in(argv)]
    if not opted:
        return ("no `docker run` in this step carries %s=1, so whatever opted "
                "this lane in executes the hostile MSBuild target outside the "
                "no-egress container -- on the runner itself (#1655)"
                % CONTAINMENT_PROBE_ENV)
    for argv in opted:
        network = _flag_value(argv, _NETWORK_FLAGS)
        if network is None:
            return ("the `docker run` that sets %s=1 carries no `--network "
                    "none`, so the hostile build's live curl reaches the "
                    "network from a CI runner (#1655)" % CONTAINMENT_PROBE_ENV)
        if network != "none":
            return ("the `docker run` that sets %s=1 runs on network %r, not "
                    "`none` (#1655)" % (CONTAINMENT_PROBE_ENV, network))
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
