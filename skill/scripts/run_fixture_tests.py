#!/usr/bin/env python3
"""Build and run the panopticon-fixtures image to vet scanner adapters."""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
DOCKERFILE = REPO_ROOT / "Dockerfile.fixtures"
MANIFEST = REPO_ROOT / "tests" / "fixtures" / "manifest.json"
DEFAULT_IMAGE = "panopticon-fixtures:latest"


def run(cmd: list[str], **kwargs) -> subprocess.CompletedProcess:
    print("+", " ".join(cmd), flush=True)
    return subprocess.run(cmd, check=True, **kwargs)


def _docker_bin() -> str:
    return shutil.which("docker") or "docker"


def docker_available() -> bool:
    try:
        result = subprocess.run(
            [_docker_bin(), "version"],
            capture_output=True,
        )
        return result.returncode == 0
    except (FileNotFoundError, OSError):
        return False


def image_exists(tag: str) -> bool:
    try:
        result = subprocess.run(
            [_docker_bin(), "image", "inspect", tag],
            capture_output=True,
        )
        return result.returncode == 0
    except (FileNotFoundError, OSError):
        return False


def build_image(tag: str) -> None:
    run([
        _docker_bin(), "build",
        "-f", str(DOCKERFILE),
        "-t", tag,
        str(REPO_ROOT),
    ])


def check_fixtures(tag: str, fixtures: list[dict]) -> tuple[list[str], list[str]]:
    """Return (present, missing) fixture names.

    Most fixtures are baked into the fixtures image (Dockerfile.fixtures COPYs
    them under an absolute /opt/panopticon-fixtures/... path); those are
    checked by asking the built image whether the path exists inside it.

    Fixtures marked "baked": false (e.g. hostile-csproj) are committed to the
    repo instead and never copied into the image, by design (see the manifest
    entry's "note") — checking them inside the image would always report
    MISSING regardless of whether the fixture is actually present. Those are
    checked directly against the host checkout (REPO_ROOT / path) instead.
    """
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
    cmd = [_docker_bin(), "run", "--rm", tag, "sh", "-c", test_script, "sh", *paths]
    # Bound the docker call so a hung container can't wedge the fixture run
    # (consistent with run_tools.py's timeouts; run-4 self-scan C15).
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    except (subprocess.SubprocessError, OSError):
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
        missing_paths.update(paths)
    path_to_name = {f["path"]: f["name"] for f in baked}
    present += [path_to_name[p] for p in present_paths if p in path_to_name]
    missing += [path_to_name[p] for p in missing_paths if p in path_to_name]
    return present, missing


def run_tests(tag: str, test: str | None = None) -> int:
    repo = str(REPO_ROOT)
    test_paths = ["/opt/panopticon/tests/tools"]
    pytest_args = ["python", "-m", "pytest", "-v"]
    if test:
        pytest_args.extend(["-k", f"test_{test}_integration"])
    pytest_args.extend(test_paths)
    cmd = [
        _docker_bin(), "run", "--rm",
        "-e", "FIXTURE_ROOT=/opt/panopticon-fixtures",
        "-v", f"{repo}/skill:/opt/panopticon/skill:ro",
        "-v", f"{repo}/tests:/opt/panopticon/tests:ro",
        tag,
        *pytest_args,
    ]
    result = subprocess.run(cmd)
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
