#!/usr/bin/env python3
"""Build and run the panopticon-fixtures image to vet scanner adapters."""
from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

# The container-launch policy these two containers run under is read from the
# modules that OWN it rather than copied weakly into here (#1767,
# ARC-3859414366): the resource ceilings from `run_tools`, whose env constants
# tune them, and the privilege drop from `scanner_config`, the one owner every
# panopticon container shares since #2150 (ARC-A3A).
# skill/ is not on sys.path when this file runs as a script, so put it there
# first: the same bootstrap run_tools.py itself uses. Acyclic and stdlib-only
# (run_tools imports no part of this module), so a module-level import costs a
# few tens of milliseconds and keeps the coupling visible.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from scripts import run_tools            # noqa: E402  (needs the path above)
from scripts import scanner_config       # noqa: E402  (needs the path above)

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
DOCKERFILE = REPO_ROOT / "Dockerfile.fixtures"
MANIFEST = REPO_ROOT / "tests" / "fixtures" / "manifest.json"
DEFAULT_IMAGE = "panopticon-fixtures:latest"

# Hard bounds so a wedged docker daemon, a stalled image build (e.g. a network
# fetch stuck inside Dockerfile.fixtures), or a hung scanner cannot block the
# fixture-test pipeline indefinitely (#1113, #1114).
PROBE_TIMEOUT = 30     # docker version / image inspect probes
BUILD_TIMEOUT = 1800   # docker build (image build can be slow)
TEST_TIMEOUT = 1800    # dockerized pytest suite

# The image operand is still in Docker's option-parsing region for some
# commands, so list argv alone does not make a leading-dash value safe. Keep
# this grammar aligned with github.com/distribution/reference: repository path
# components are lowercase, registry hosts may carry a port or bracketed IPv6,
# tags may contain uppercase characters, and digests are not limited to sha256.
_PATH_COMPONENT = r"[a-z0-9]+(?:(?:[._]|__|[-]+)[a-z0-9]+)*"
_DOMAIN_COMPONENT = r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?"
_HOST = rf"(?:{_DOMAIN_COMPONENT}(?:\.{_DOMAIN_COMPONENT})*|\[[A-Fa-f0-9:]+\])"
_NAME = rf"(?P<name>(?:{_HOST}(?::[0-9]+)?/)?{_PATH_COMPONENT}(?:/{_PATH_COMPONENT})*)"
_TAG = r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}"
_DIGEST_ALGORITHM = r"[A-Za-z][A-Za-z0-9]*(?:[-_+.][A-Za-z][A-Za-z0-9]*)*"
_DIGEST = rf"{_DIGEST_ALGORITHM}:[A-Fa-f0-9]{{32,}}"
_IMAGE_REFERENCE = re.compile(rf"{_NAME}(?::{_TAG})?(?:@{_DIGEST})?", re.ASCII)
_MAX_REPOSITORY_NAME_LENGTH = 255


def validate_image_reference(reference: str) -> str:
    """Return a valid Docker image reference, or raise ``ValueError``.

    Docker-facing public helpers call this before resolving or invoking Docker,
    so direct callers receive the same pre-subprocess safety boundary as the
    CLI. The accepted syntax follows the Distribution reference grammar rather
    than treating a reference as an arbitrary command-line string.
    """
    if not isinstance(reference, str):
        raise ValueError("invalid Docker image reference")
    match = _IMAGE_REFERENCE.fullmatch(reference)
    if match is None or len(match.group("name")) > _MAX_REPOSITORY_NAME_LENGTH:
        raise ValueError("invalid Docker image reference")
    return reference


def run(cmd: list[str], **kwargs) -> subprocess.CompletedProcess:
    print("+", " ".join(cmd), flush=True)
    return subprocess.run(cmd, check=True, **kwargs)  # nosec B603


def _docker_bin() -> str:
    return shutil.which("docker") or "docker"


def docker_available() -> bool:
    try:
        result = subprocess.run(  # nosec B603
            [_docker_bin(), "version"],
            capture_output=True,
            timeout=PROBE_TIMEOUT,
        )
        return result.returncode == 0
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
        return False


def image_exists(tag: str) -> bool:
    validate_image_reference(tag)
    try:
        result = subprocess.run(  # nosec B603
            [_docker_bin(), "image", "inspect", tag],
            capture_output=True,
            timeout=PROBE_TIMEOUT,
        )
        return result.returncode == 0
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
        return False


def build_image(tag: str) -> None:
    validate_image_reference(tag)
    run([
        _docker_bin(), "build",
        "-f", str(DOCKERFILE),
        "-t", tag,
        str(REPO_ROOT),
    ], timeout=BUILD_TIMEOUT)


def check_fixtures(tag: str, fixtures: list[dict]) -> tuple[list[str], list[str]]:
    """Return (present, missing) fixture names.

    Most fixtures are baked into the fixtures image (Dockerfile.fixtures COPYs
    them under an absolute /opt/panopticon-fixtures/... path); those are
    checked by asking the built image whether the path exists inside it.

    Fixtures marked "baked": false are committed to the repo instead and never
    copied into the image, by design (see the manifest entry's "note") —
    checking them inside the image would always report MISSING regardless of
    whether the fixture is actually present. Those are checked directly against
    the host checkout (REPO_ROOT / path) instead. Nothing is marked that way
    today: hostile-csproj was, until #1655 needed its NuGet restore output,
    which only an image build can produce.
    """
    validate_image_reference(tag)
    baked = [f for f in fixtures if f.get("baked", True) and f.get("path")]
    local = [f for f in fixtures if not f.get("baked", True) and f.get("path")]

    present = []
    missing = []

    for f in local:
        if (REPO_ROOT / f["path"]).is_dir():
            present.append(f["name"])
        else:
            missing.append(f["name"])

    paths = [f["path"] for f in baked]
    if not paths:
        return present, missing
    # Pass the paths as positional ARGUMENTS to sh, never interpolated into the
    # script text (#664). The old f-string built the script by splicing each
    # manifest path into `sh -c`, so a path like `"; rm -rf / #` executed as
    # shell. Here the script is a fixed constant that reads its inputs from
    # "$@", so a path is data — a shell metacharacter in it can do nothing.
    # ($0 is set to "sh" so the paths start at $1 and "$@" covers them all.)
    test_script = (
        'for p in "$@"; do '
        'if [ -d "$p" ]; then printf "PRESENT:%s\n" "$p"; else printf "MISSING:%s\n" "$p"; fi; '
        'done'
    )
    # The probe stats baked paths only, but it launches under the same policy as
    # every other container here: the same flags in the same order as the tool
    # runner's own dispatch, and a network it cannot use.
    cmd = [_docker_bin(), "run", "--rm",
           *run_tools.resource_limit_flags(),
           *scanner_config.privilege_drop_flags(),
           "--network", "none",
           tag, "sh", "-c", test_script, "sh", *paths]
    # Bound the docker call so a hung container can't wedge the fixture run
    # (consistent with run_tools.py's timeouts; run-4 self-scan C15).
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)  # nosec B603
    except (subprocess.SubprocessError, OSError) as e:
        # #run7 OPS-E1A: a crashed/timed-out docker probe was silently treated
        # as "all fixtures absent" -- give the operator a signal so a broken
        # daemon isn't mistaken for genuinely-missing baked fixtures.
        print("check_fixtures: docker probe failed (%s); treating all baked "
              "fixtures as missing" % e, file=sys.stderr)
        result = None
    present_paths = []
    missing_paths = set()
    if result and result.returncode == 0:
        for line in result.stdout.splitlines():
            if line.startswith("PRESENT:"):
                present_paths.append(line.split(":", 1)[1])
            elif line.startswith("MISSING:"):
                missing_paths.add(line.split(":", 1)[1])
    else:
        if result is not None:   # ran but rc != 0 -> also worth an operator note
            # A ceiling the daemon REFUSES exits here too (`--cpus` above the
            # host's CPU count is the concrete case), so quote docker's own
            # sentence, flattened and bounded -- without it a refused flag reads
            # as every baked fixture having gone missing.
            why = " ".join((result.stderr or "").split())[:300]
            print("check_fixtures: docker probe exited %s%s; treating all baked "
                  "fixtures as missing"
                  % (result.returncode, ": " + why if why else ""),
                  file=sys.stderr)
        missing_paths.update(paths)
    path_to_name = {f["path"]: f["name"] for f in baked}
    present += [path_to_name[p] for p in present_paths if p in path_to_name]
    missing += [path_to_name[p] for p in missing_paths if p in path_to_name]
    return present, missing


def run_tests(tag: str, test: str | None = None) -> int:
    validate_image_reference(tag)
    repo = str(REPO_ROOT)
    test_paths = ["/opt/panopticon/tests/tools"]
    pytest_args = ["python", "-m", "pytest", "-v"]
    if test:
        pytest_args.extend(["-k", f"test_{test}_integration"])
    pytest_args.extend(test_paths)
    cmd = [
        _docker_bin(), "run", "--rm",
        # This container runs the whole adapter suite on a developer machine:
        # the REAL scanners over live attacker-shaped inputs (a planted
        # eslint.config.js and a shadow node_modules plugin eslint must refuse
        # to load, a planted .gitleaks.toml rule set and a GITLEAKS_CONFIG
        # hijack gitleaks must ignore) plus the dotnet/MSBuild and JVM
        # toolchains over the baked goat trees. The hostile-csproj corpus is
        # baked into the image as well, but its BUILD is opt-in
        # (PANOPTICON_CONTAINMENT_PROBE=1, set only by the containment lane of
        # .github/workflows/adapter-integration.yml), so evil.csproj's curl
        # target does not fire here -- that test skips. All of that launched
        # with no cap-drop, no no-new-privileges and no memory/CPU/pids ceiling until
        # #1767 (ARC-3859414366). Each flag set comes from the module that owns it.
        *run_tools.resource_limit_flags(),
        *scanner_config.privilege_drop_flags(),
        # #calibration-6: scans run with NO NETWORK, so the fixture suite must
        # too -- otherwise it certifies scanners in an environment that does not
        # exist. Three broken adapters passed here for exactly that reason:
        # gosec read zero files (#1457), roslyn compiled nothing (#1469), and
        # spotbugs emitted log4j DNS noise ahead of its XML, which only happens
        # when there is no DNS. Every one looked healthy against a networked
        # fixture. Measured: with this flag, 254 pass and precisely the two
        # genuinely-broken Java scanners fail.
        "--network", "none",
        "-e", "FIXTURE_ROOT=/opt/panopticon-fixtures",
        "-v", f"{repo}/skill:/opt/panopticon/skill:ro",
        # ...AND over the image's baked-in copy. The image does
        # `COPY skill/scripts /opt/panopticon/scripts`, so `scripts.tools`
        # resolved to the BAKED adapters and a local fix was invisible here --
        # the suite silently tested whatever the image was built with.
        # run_tools.py already mounts this way for the same reason
        # ("fixed adapters silently kept failing because the image carried the
        # stale code"); the fixture runner did not.
        "-v", f"{repo}/skill/scripts:/opt/panopticon/scripts:ro",
        "-v", f"{repo}/tests:/opt/panopticon/tests:ro",
        tag,
        *pytest_args,
    ]
    try:
        result = subprocess.run(cmd, timeout=TEST_TIMEOUT)  # nosec B603
    except subprocess.TimeoutExpired:
        # `--cpus` only throttles, but it throttles against a pre-existing
        # wall-clock bound, so a run that used to fit can now cross it.
        # PANOPTICON_TOOL_CPUS retunes that ceiling or drops it.
        msg = "fixture test run timed out after %ds; aborting (exit 124)." % TEST_TIMEOUT
        if run_tools.CONTAINER_CPUS:
            msg += (" If the CPU ceiling is what slowed it, retune or drop it with "
                    "PANOPTICON_TOOL_CPUS.")
        print(msg, file=sys.stderr, flush=True)
        return 124
    if result.returncode == 137 and run_tools.CONTAINER_MEMORY:
        # 128+SIGKILL. --memory-swap is pinned equal to --memory, so an
        # over-ceiling allocation is killed rather than swapped: at a live
        # ceiling this is the envelope, not an adapter regression.
        print("fixture test run exited 137 (SIGKILL): at the --memory %s "
              "ceiling that is the OOM killer, not an adapter failure. "
              "Retune or drop it with PANOPTICON_TOOL_MEMORY."
              % run_tools.CONTAINER_MEMORY, file=sys.stderr, flush=True)
    return result.returncode


def load_manifest() -> dict:
    if not MANIFEST.exists():
        print(f"manifest not found: {MANIFEST}", file=sys.stderr)
        sys.exit(1)
    try:
        return json.loads(MANIFEST.read_text())
    except json.JSONDecodeError as exc:
        print(f"manifest is not valid JSON: {exc}", file=sys.stderr)
        sys.exit(1)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run panopticon scanner fixture tests.")
    parser.add_argument("--tag", default=DEFAULT_IMAGE, help="Docker image tag to use.")
    parser.add_argument("--rebuild", action="store_true", help="Force a fresh image build.")
    parser.add_argument("--test", default=None, help="Run only one language/test target (e.g., rust).")
    args = parser.parse_args(argv)

    try:
        validate_image_reference(args.tag)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if not docker_available():
        print("error: docker is not available or not running", file=sys.stderr)
        return 1

    manifest = load_manifest()
    fixtures = manifest.get("fixtures", [])
    print("Fixtures in manifest:")
    for fixture in fixtures:
        print(f"  - {fixture['name']} ({fixture['language']})")

    if args.rebuild or not image_exists(args.tag):
        build_image(args.tag)
    else:
        print(f"Using existing image {args.tag}")

    print("\nChecking fixture presence inside image...")
    present, missing = check_fixtures(args.tag, fixtures)
    for name in present:
        print(f"  [FOUND]   {name}")
    for name in missing:
        print(f"  [MISSING] {name}")

    print("\nRunning integration tests...")
    rc = run_tests(args.tag, args.test)

    print("\nSummary:")
    print(f"  Fixtures present: {len(present)}")
    print(f"  Fixtures missing: {len(missing)}")
    print(f"  pytest exit code: {rc}")
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
