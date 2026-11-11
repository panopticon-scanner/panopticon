"""Non-shell product and supply-chain pins for the repository fleet.

These checks intentionally read YAML, Python ASTs, requirements files, and the
Dockerfile directly.  They do not interpret workflow ``run:`` shell.
"""

import ast
import copy
import importlib.metadata
import json
import os
import re
import sys
import tempfile
import unittest

import yaml

from tests._test_helpers import REPO_ROOT


WORKFLOW_DIR = os.path.join(REPO_ROOT, ".github", "workflows")
SKILL_SCRIPTS = os.path.join(REPO_ROOT, "skill", "scripts")
ADAPTER_WORKFLOW = "adapter-integration.yml"
EXPECTED_ADAPTER_JOBS = ("containment", "integration")
CONTAINMENT_LANES = ((ADAPTER_WORKFLOW, "containment"),)
CONTAINMENT_PERMISSIONS = {"contents": "read", "packages": "read"}
CONTAINMENT_TRIGGERS = {"schedule", "workflow_dispatch"}
EXPECTED_SCANNER_UID = "1000"
RUNNER_PIP_FLOOR = (26, 1, 1)

_PIN_LINE = re.compile(r"^(?P<name>[A-Za-z0-9._-]+)==(?P<version>[^\s;]+)")
_USERADD = re.compile(r"useradd\s+-m\s+-u\s+(\d+)\s+scanner\b")


def _join_continuations(text):
    """Fold a backslash-newline and its indentation into one space."""
    return re.sub(r"\\\n\s*", " ", text)


def _workflow_document(filename):
    with open(os.path.join(WORKFLOW_DIR, filename), encoding="utf-8") as fh:
        return yaml.safe_load(fh.read()) or {}


def _adapter_doc():
    return _workflow_document(ADAPTER_WORKFLOW)


def permissions_defect(document, job_name, expected=CONTAINMENT_PERMISSIONS):
    """Why ``job_name`` does not state the exact read-only scope pair."""
    job = ((document.get("jobs") or {}).get(job_name) or {})
    permissions = job.get("permissions")
    if permissions is None:
        return (
            f"job {job_name!r} declares no `permissions:` of its own, so it "
            "inherits the workflow's"
        )
    if not isinstance(permissions, dict):
        return f"job {job_name!r} sets `permissions: {permissions!r}`, not a scope map"
    got = {key: str(value) for key, value in permissions.items()}
    if got != expected:
        return f"job {job_name!r} has permissions {got!r}; the pin is {expected!r}"
    return None


def dockerfile_scanner_uid(text=None):
    """The uid assigned to the Dockerfile's ``scanner`` account, or None."""
    if text is None:
        with open(os.path.join(REPO_ROOT, "Dockerfile"), encoding="utf-8") as fh:
            text = fh.read()
    match = _USERADD.search(text)
    return match.group(1) if match else None


class TestEveryPinnedRequirementsFileIsHashed(unittest.TestCase):
    """The two non-hash contracts formerly housed beside the shell guard."""

    def test_the_fixture_image_copies_the_repos_requirements_file(self):
        with open(
            os.path.join(REPO_ROOT, "Dockerfile.fixtures"), encoding="utf-8"
        ) as fh:
            text = fh.read()
        self.assertIn("COPY requirements-fixtures.txt", text)

    def test_the_gate_never_downgrades_pip(self):
        path = os.path.join(REPO_ROOT, ".github", "requirements-gate.txt")
        with open(path, encoding="utf-8") as fh:
            match = re.search(
                r"^pip==(\S+)", _join_continuations(fh.read()), re.MULTILINE
            )
        self.assertIsNotNone(match, "the gate requirements pin no pip")
        pinned = tuple(int(part) for part in match.group(1).split(".") if part.isdigit())
        self.assertGreaterEqual(
            pinned,
            RUNNER_PIP_FLOOR,
            "pinned pip %s is older than the runner floor %s"
            % (match.group(1), ".".join(str(part) for part in RUNNER_PIP_FLOOR)),
        )


def _is_local_module(name):
    return (
        name == "scripts"
        or os.path.isfile(os.path.join(SKILL_SCRIPTS, name + ".py"))
        or os.path.isdir(os.path.join(SKILL_SCRIPTS, name))
    )


def third_party_names(node):
    """Non-stdlib, non-repository top-level names in one import node."""
    if isinstance(node, ast.ImportFrom):
        if node.level:
            return []
        names = [(node.module or "").split(".")[0]]
    else:
        names = [alias.name.split(".")[0] for alias in node.names]
    return [
        name
        for name in names
        if name and name not in sys.stdlib_module_names and not _is_local_module(name)
    ]


_FUNCTION_SCOPES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)


def _module_level_import_nodes(body):
    """Imports that may execute while their module is imported."""
    for node in body:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            yield node
        elif not isinstance(node, _FUNCTION_SCOPES):
            for child in ast.iter_child_nodes(node):
                if isinstance(child, ast.stmt):
                    yield from _module_level_import_nodes([child])
                elif isinstance(child, (ast.ExceptHandler, ast.match_case)):
                    yield from _module_level_import_nodes(child.body)


def module_level_third_party(source, filename="<source>"):
    tree = ast.parse(source, filename=filename)
    return [
        (node.lineno, name)
        for node in _module_level_import_nodes(tree.body)
        for name in third_party_names(node)
    ]


def every_third_party(source, filename="<source>"):
    tree = ast.parse(source, filename=filename)
    return [
        (node.lineno, name)
        for node in ast.walk(tree)
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for name in third_party_names(node)
    ]


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
    """Every ``skill/scripts`` file loaded by importing ``roots``."""
    from scripts.tools.exec import run_tool

    with tempfile.TemporaryDirectory() as elsewhere:
        env = {
            "PATH": os.path.join(elsewhere, "empty-path"),
            "HOME": os.path.join(elsewhere, "home"),
            "PYTHONPATH": os.path.join(REPO_ROOT, "skill"),
            "PYTHONNOUSERSITE": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
        }
        for path in (env["PATH"], env["HOME"]):
            os.makedirs(path, exist_ok=True)
        stdout, stderr, returncode = run_tool(
            [sys.executable, "-c", _CENSUS, SKILL_SCRIPTS, *roots],
            timeout=180,
            ok_codes=(0,),
            capture_stderr=True,
            cwd=elsewhere,
            env=env,
        )
    if returncode != 0:
        raise AssertionError(
            "importing %s failed, so the import-chain guards read nothing:\n%s"
            % (
                ", ".join(roots),
                (stdout + stderr).decode("utf-8", errors="replace"),
            )
        )
    return json.loads(stdout.decode("utf-8"))


def third_party_imports_under(files):
    found = {}
    for path in files:
        with open(path, encoding="utf-8") as fh:
            source = fh.read()
        for line, module in every_third_party(source, path):
            found.setdefault(module, []).append(
                "%s:%d" % (os.path.relpath(path, REPO_ROOT), line)
            )
    return found


class TestGateClosureCoversRuntimePackages(unittest.TestCase):
    GATE = os.path.join(REPO_ROOT, ".github", "requirements-gate.txt")

    @staticmethod
    def _normalised(name):
        return re.sub(r"[-_.]+", "-", name).lower()

    def _pinned_names(self):
        with open(self.GATE, encoding="utf-8") as fh:
            text = _join_continuations(fh.read())
        return {
            self._normalised(match.group("name"))
            for line in text.splitlines()
            if (match := _PIN_LINE.match(line.strip()))
        }

    def test_every_runtime_package_is_in_the_gate_closure(self):
        import scripts.phases.readiness_checks as readiness_checks

        pinned = self._pinned_names()
        self.assertTrue(pinned, "the gate requirements pin nothing")
        self.assertTrue(readiness_checks.RUNTIME_PACKAGES, "no packages to check")
        for _module, pip_name in readiness_checks.RUNTIME_PACKAGES:
            with self.subTest(package=pip_name):
                self.assertIn(self._normalised(pip_name), pinned)

    def test_every_third_party_import_on_the_gate_path_is_pinned(self):
        pinned = self._pinned_names()
        reached = files_reached_by("scripts.run_tools", "scripts.security_gate")
        self.assertIn(os.path.join(SKILL_SCRIPTS, "run_tools.py"), reached)
        imports = third_party_imports_under(reached)
        self.assertTrue(imports, "the gate import chain has no third-party imports")
        provided_by = importlib.metadata.packages_distributions()
        for module, sites in sorted(imports.items()):
            with self.subTest(module=module):
                distributions = provided_by.get(module) or []
                self.assertTrue(
                    distributions,
                    "import %s (%s) has no providing distribution"
                    % (module, ", ".join(sites)),
                )
                self.assertTrue(
                    any(self._normalised(name) in pinned for name in distributions),
                    "import %s (%s) is provided by %s, none pinned in %s"
                    % (
                        module,
                        ", ".join(sites),
                        ", ".join(sorted(distributions)),
                        os.path.relpath(self.GATE, REPO_ROOT),
                    ),
                )


class TestNoThirdPartyImportAtModuleLevelOnTheDriverPath(unittest.TestCase):
    ROOTS = (
        "scripts.driver",
        "scripts.phases.readiness",
        "scripts.run_tools",
        "scripts.security_gate",
    )
    MODULE_LEVEL_SHAPES = (
        ("bare", 1, "import defusedxml\n"),
        ("if", 2, "if True:\n    import defusedxml\n"),
        (
            "try",
            2,
            "try:\n    import defusedxml\nexcept ImportError:\n    pass\n",
        ),
        (
            "except-star",
            2,
            "try:\n    import defusedxml\nexcept* ImportError:\n    pass\n",
        ),
        (
            "suppress",
            2,
            "with contextlib.suppress(ImportError):\n    import defusedxml\n",
        ),
        ("class", 2, "class A:\n    import defusedxml\n"),
        ("for", 2, "for _ in range(1):\n    import defusedxml\n"),
        ("while", 2, "while True:\n    import defusedxml\n    break\n"),
        ("match", 3, "match 1:\n    case 1:\n        import defusedxml\n"),
    )

    def test_no_module_on_the_driver_path_imports_a_third_party_at_module_level(self):
        reached = files_reached_by(*self.ROOTS)
        self.assertIn(os.path.join(SKILL_SCRIPTS, "driver.py"), reached)
        offenders = []
        for path in reached:
            with open(path, encoding="utf-8") as fh:
                source = fh.read()
            offenders.extend(
                "%s:%d %s" % (os.path.relpath(path, REPO_ROOT), line, module)
                for line, module in module_level_third_party(source, path)
            )
        self.assertEqual(
            [],
            offenders,
            "module-level third-party imports bypass readiness:\n  "
            + "\n  ".join(offenders),
        )

    def test_every_module_level_shape_trips_the_checker(self):
        for label, line, source in self.MODULE_LEVEL_SHAPES:
            with self.subTest(shape=label):
                self.assertEqual([(line, "defusedxml")], module_level_third_party(source))

    def test_an_import_inside_a_function_is_not_a_module_level_import(self):
        source = (
            "def parse(raw):\n"
            "    import defusedxml.ElementTree as ET\n"
            "    return ET.fromstring(raw)\n"
        )
        self.assertEqual([], module_level_third_party(source))
        self.assertEqual([(2, "defusedxml")], every_third_party(source))

    def test_this_repos_own_modules_are_not_third_party(self):
        source = (
            "import json\n"
            "import scripts.hosts\n"
            "from scripts.tools import egress\n"
            "import diff_map\n"
        )
        self.assertEqual([], module_level_third_party(source))

    def test_a_relative_import_is_local_by_construction(self):
        self.assertEqual([], module_level_third_party("from . import base\n"))
        self.assertEqual([], module_level_third_party("from .exec import run_tool\n"))


class TestTheLanePermissionsRule(unittest.TestCase):
    @staticmethod
    def _doc(permissions):
        job = {"steps": []}
        if permissions is not None:
            job["permissions"] = permissions
        return {"permissions": {"contents": "read"}, "jobs": {"containment": job}}

    def test_the_pinned_pair_is_not_a_defect(self):
        self.assertIsNone(
            permissions_defect(
                self._doc({"contents": "read", "packages": "read"}), "containment"
            )
        )

    def test_inheriting_the_workflows_block_is_a_defect(self):
        self.assertIn("inherits", permissions_defect(self._doc(None), "containment"))

    def test_a_write_grant_is_a_defect(self):
        why = permissions_defect(
            self._doc({"contents": "read", "packages": "write"}), "containment"
        )
        self.assertIn("write", why)

    def test_an_extra_scope_is_a_defect(self):
        why = permissions_defect(
            self._doc(
                {"contents": "read", "packages": "read", "id-token": "write"}
            ),
            "containment",
        )
        self.assertIn("id-token", why)

    def test_write_all_is_a_defect(self):
        self.assertIn(
            "scope map", permissions_defect(self._doc("write-all"), "containment")
        )


class TestTheContainmentLaneIsLeastPrivilege(unittest.TestCase):
    def test_the_lane_grants_itself_read_and_nothing_more(self):
        for workflow, job in CONTAINMENT_LANES:
            with self.subTest(job=job):
                document = _workflow_document(workflow)
                self.assertIsNone(
                    permissions_defect(document, job),
                    permissions_defect(document, job) or workflow,
                )

    def test_the_lane_is_never_reachable_from_a_pull_request(self):
        for workflow, _job in CONTAINMENT_LANES:
            with self.subTest(workflow=workflow):
                document = _workflow_document(workflow)
                triggers = set(document.get(True, document.get("on")) or {})
                self.assertEqual(CONTAINMENT_TRIGGERS, triggers)


class TestThePinnedUidIsTheDockerfilesOwn(unittest.TestCase):
    def test_the_tools_image_still_creates_the_account_at_the_pinned_uid(self):
        found = dockerfile_scanner_uid()
        self.assertIsNotNone(found, "the Dockerfile creates no pinned scanner uid")
        self.assertEqual(EXPECTED_SCANNER_UID, found)

    def test_both_jobs_env_blocks_carry_the_dockerfiles_uid(self):
        jobs = _adapter_doc().get("jobs") or {}
        for job in EXPECTED_ADAPTER_JOBS:
            with self.subTest(job=job):
                value = str(((jobs.get(job) or {}).get("env") or {}).get("SCANNER_UID", ""))
                self.assertEqual(dockerfile_scanner_uid(), value)

    def test_the_reader_reads_the_account_and_not_any_useradd(self):
        self.assertEqual(
            "1234",
            dockerfile_scanner_uid(
                "RUN useradd -m -u 1234 scanner \\\n    && chown scanner /x\n"
            ),
        )
        self.assertIsNone(dockerfile_scanner_uid("RUN useradd -m -u 1234 builder\n"))
        self.assertIsNone(dockerfile_scanner_uid("USER scanner\n"))


class TestVerifiedPinFreshnessJobs(unittest.TestCase):
    """#3420: each family verifies and reports through one issue; no push, no PR."""

    FAMILIES = ("tinyproxy", "rustup", "trivy", "rust-toolchain")

    @staticmethod
    def _defects(job, family):
        steps = job.get("steps", [])
        report = [step for step in steps
                  if "devtools/report_pin_bump.py" in step.get("run", "")]
        checkout = next((step for step in steps
                         if str(step.get("uses", "")).startswith("actions/checkout@")), {})
        defects = []
        if job.get("permissions") != {"contents": "read", "issues": "write"}:
            defects.append("job permissions")
        if not re.fullmatch(r"actions/checkout@[0-9a-f]{40}", checkout.get("uses", "")):
            defects.append("pinned checkout")
        if (checkout.get("with") or {}).get("persist-credentials") is not False:
            defects.append("checkout credentials")
        if len(report) != 1 or report[0].get("run") != (
                "python3 devtools/report_pin_bump.py " + family):
            defects.append("report helper/failure propagation")
        elif report[0].get("env") != {"GH_TOKEN": "${{ github.token }}"}:
            defects.append("report authentication")
        elif "if" in report[0]:
            defects.append("report condition")
        if any("--write" in step.get("run", "") or "git push" in step.get("run", "")
               or "open_pin_pr" in step.get("run", "") for step in steps):
            defects.append("writes or pushes")
        # #3557 review: the token is step-scoped, on the report step only.
        if "env" in job:
            defects.append("job-level env")
        if any("GH_TOKEN" in (step.get("env") or {}) for step in steps
               if step not in report):
            defects.append("token outside the report step")
        return defects

    def test_verified_pin_jobs_are_scoped_and_fail_closed(self):
        document = _workflow_document("pin-freshness.yml")
        self.assertEqual({"contents": "read"}, document["permissions"])
        self.assertEqual(set(self.FAMILIES), set(document["jobs"]))
        for family in self.FAMILIES:
            with self.subTest(family=family):
                self.assertEqual([], self._defects(document["jobs"][family], family))

    def test_helper_boundary_negative_controls(self):
        original = _workflow_document("pin-freshness.yml")["jobs"]["rustup"]
        cases = (
            (lambda job: job.update(permissions={"contents": "write", "issues": "write"}),
             "job permissions"),
            (lambda job: job.update(permissions={"contents": "read", "issues": "write",
                                                 "pull-requests": "write"}),
             "job permissions"),
            (lambda job: job["steps"][0].update(uses="actions/checkout@v7"), "pinned checkout"),
            (lambda job: job["steps"][0].update({"with": {"persist-credentials": True}}),
             "checkout credentials"),
            (lambda job: job["steps"][0].pop("with"), "checkout credentials"),
            (lambda job: job["steps"][1].update(run="python3 devtools/report_pin_bump.py trivy"),
             "report helper/failure propagation"),
            (lambda job: job["steps"][1].update(
                run="python3 devtools/report_pin_bump.py rustup || true"),
             "report helper/failure propagation"),
            (lambda job: job["steps"][1].pop("env"), "report authentication"),
            (lambda job: job["steps"][1].update({"if": "always()"}), "report condition"),
            (lambda job: job["steps"].append(
                {"run": "python3 devtools/bump_pins.py rustup --write"}), "writes or pushes"),
            (lambda job: job["steps"].append({"run": "git push origin HEAD"}),
             "writes or pushes"),
            (lambda job: job.update(env={"GH_TOKEN": "${{ github.token }}"}), "job-level env"),
            (lambda job: job.update(env={"OTHER": "x"}), "job-level env"),
            (lambda job: job["steps"].insert(1, {"run": "true",
                                                 "env": {"GH_TOKEN": "${{ github.token }}"}}),
             "token outside the report step"),
            (lambda job: job["steps"][0].update(env={"GH_TOKEN": "${{ github.token }}"}),
             "token outside the report step"),
        )
        for mutate, expected in cases:
            with self.subTest(expected=expected):
                job = copy.deepcopy(original)
                mutate(job)
                self.assertIn(expected, self._defects(job, "rustup"))


class TestThePrBuildFreesDiskAndReportsHeadroom(unittest.TestCase):
    """#3441: docker-build-pr's `load: true` import ran the runner out of disk, so the
    job removes preinstalled toolchains it never uses before the build, and logs the
    margin and the image's layers after it."""

    FREED = ("/usr/local/lib/android", "/usr/share/dotnet", "/opt/ghc", "/usr/local/.ghcup",
             "/opt/hostedtoolcache")
    FOR_LOOP = re.compile(r"^\s*for dir in (?P<dirs>[^;]+); do$", re.MULTILINE)
    # The one setup-* action this job may use: it installs Buildx, not a toolchain.
    SETUP_ALLOWED = ("docker/setup-buildx-action",)

    @staticmethod
    def _index(steps, predicate):
        return next((i for i, step in enumerate(steps) if predicate(step)), None)

    @classmethod
    def _defects(cls, job):
        steps = job.get("steps", [])

        def run(step):
            return str(step.get("run", ""))

        def uses(step):
            return str(step.get("uses", ""))

        free = cls._index(steps, lambda st: st.get("name") == "Free runner disk")
        buildx = cls._index(steps, lambda st: uses(st).startswith("docker/setup-buildx-action@"))
        build = cls._index(steps, lambda st: st.get("name") == "Build Dockerfile")
        fixtures = cls._index(steps, lambda st: st.get("name") == "Build Dockerfile.fixtures")
        defects = []
        if free is None:
            return ["no free step"]
        if buildx is None or build is None or not free < buildx < build:
            defects.append("free step order")
        body = run(steps[free])
        loops = cls.FOR_LOOP.findall(body)
        if "uses" in steps[free]:
            defects.append("free step uses an action")
        if not body.lstrip().startswith("set -euo pipefail"):
            defects.append("free step strictness")
        if "|| true" in body or "|| :" in body:
            defects.append("free step swallows failures")
        if len(loops) != 1 or tuple(loops[0].split()) != cls.FREED:
            defects.append("freed directories")
        if [line.strip() for line in body.splitlines() if "rm " in line] != [
                'sudo rm -rf "$dir"']:
            defects.append("free step removes something else")
        if body.count("df -h /") != 2:
            defects.append("free step headroom")
        for step in steps:
            name = uses(step).split("@", 1)[0]
            if "/setup-" in name and name not in cls.SETUP_ALLOWED:
                defects.append("toolchain installer: " + name)
        after_build = [st for st in steps[(build or 0) + 1:(fixtures or len(steps))]
                       if "df -h /" in run(st)]
        if not after_build or ("docker image inspect panopticon-tools:latest" not in
                               run(after_build[0]) or ".RootFS.Layers" not in run(after_build[0])
                               or "{{.Id}}" not in run(after_build[0])):
            defects.append("headroom and layers after the tools image")
        if fixtures is None or not any("df -h /" in run(st) for st in steps[fixtures + 1:]):
            defects.append("headroom after the fixtures image")
        return defects

    def _job(self):
        return _workflow_document("docker-build-pr.yml")["jobs"]["build"]

    def test_the_build_job_frees_disk_and_reports_headroom(self):
        self.assertEqual([], self._defects(self._job()))

    def test_negative_controls(self):
        def step(job, name):
            return next(st for st in job["steps"] if st.get("name") == name)

        def edit_free(old, new):
            def mutate(job):
                free = step(job, "Free runner disk")
                free["run"] = free["run"].replace(old, new)
            return mutate

        def move_free_after_build(job):
            free = step(job, "Free runner disk")
            job["steps"].remove(free)
            job["steps"].insert(job["steps"].index(step(job, "Build Dockerfile")) + 1, free)

        def drop(name):
            return lambda job: job["steps"].remove(step(job, name))

        cases = (
            (drop("Free runner disk"), "no free step"),
            (move_free_after_build, "free step order"),
            (lambda job: step(job, "Free runner disk").update(uses="x/free@" + "0" * 40),
             "free step uses an action"),
            (edit_free("set -euo pipefail", "set -e"), "free step strictness"),
            (edit_free('sudo du -sh "$dir"', 'sudo du -sh "$dir" || true'),
             "free step swallows failures"),
            (edit_free(" /opt/hostedtoolcache;", ";"), "freed directories"),
            (edit_free("/usr/share/dotnet", "/usr/share"), "freed directories"),
            (edit_free(" /opt/hostedtoolcache;", " /opt/hostedtoolcache /var/lib/docker;"),
             "freed directories"),
            (edit_free('sudo rm -rf "$dir"', 'sudo rm -rf "$dir" /tmp/x'),
             "free step removes something else"),
            (edit_free("done\n", "done\nsudo rm -rf /usr/lib/jvm\n"),
             "free step removes something else"),
            (edit_free("df -h /\n", ""), "free step headroom"),
            (edit_free("done\ndf -h /\n", "done\n"), "free step headroom"),
            (lambda job: job["steps"].insert(1, {"uses": "actions/setup-go@" + "0" * 40}),
             "toolchain installer: actions/setup-go"),
            (lambda job: job["steps"].insert(1, {"uses": "astral-sh/setup-uv@" + "0" * 40}),
             "toolchain installer: astral-sh/setup-uv"),
            (drop("Report disk headroom after the tools image"),
             "headroom and layers after the tools image"),
            (lambda job: step(job, "Report disk headroom after the tools image").update(
                run="set -euo pipefail\ndf -h /\n"),
             "headroom and layers after the tools image"),
            (lambda job: step(job, "Report disk headroom after the tools image").update(
                run=step(job, "Report disk headroom after the tools image")["run"].replace(
                    "{{.Id}} ", "")),
             "headroom and layers after the tools image"),
            (drop("Report disk headroom after the fixtures image"),
             "headroom after the fixtures image"),
        )
        for mutate, expected in cases:
            with self.subTest(expected=expected):
                job = copy.deepcopy(self._job())
                mutate(job)
                self.assertIn(expected, self._defects(job))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
