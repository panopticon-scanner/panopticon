"""Policy checks shared by requirements pin write and check modes (#2877).

This stays stdlib-only so the privileged requirements gate can inspect its own
hashes before installing the packages those hashes authorize.
"""
from __future__ import annotations

import os
import re
import sys

from pin_requirements import parse_requirement_options, parse_requirements


# What `--require-hashes` needs is one `--hash=sha256:` line per artifact pip
# could legitimately choose for the target platform. Writing those by hand is
# how a digest gets invented; this reads each one from PyPI's JSON API and
# recomputes it from the downloaded wheel, exactly as the rustup family does.

# The machine architectures the builds these pins protect actually run on.
# ubuntu-latest (the gate) is amd64 only, but docker-publish.yml builds the
# tools image -- and with it the fixtures image FROM it -- for linux/amd64 AND
# linux/arm64, so an x86_64-only hash block fails `--require-hashes` on the
# arm64 leg alone (#1734). Both are kept for every file: pip only needs ONE
# `--hash` on a line to match the artifact it actually fetched, so the digests
# an amd64 build never uses cost it nothing.
LINUX_ARCHES = ("x86_64", "aarch64")

# #2877 narrows the gate file to its real x86_64 runner while retaining both
# image architectures for the files docker-publish installs.
REQUIREMENTS_POLICIES = {
    ".github/requirements-gate.txt": ("x86_64",),
    "requirements-fixtures.txt": LINUX_ARCHES,
    "requirements-tools.txt": LINUX_ARCHES,
}
REQUIREMENTS_FILES = tuple(REQUIREMENTS_POLICIES)
_SHA256_OPTION = re.compile(r"--hash(?:=|\s+)sha256:([0-9a-f]{64})\Z")


def requirements_arches(path: str) -> tuple[str, ...]:
    """Architectures authorized by the canonical requirements file at `path`."""
    normalized = os.path.normpath(path).replace("\\", "/")
    for filename, arches in REQUIREMENTS_POLICIES.items():
        if normalized == filename or normalized.endswith("/" + filename):
            return arches
    raise RuntimeError("no requirements check policy for %s" % path)


def wheel_is_installable(filename: str, arches=LINUX_ARCHES) -> bool:
    """Could the linux builds this repo pins for select this wheel?

    The surfaces are ubuntu-latest for the gate and the `python:3.12-slim`
    images for the fixtures and the tools -- so the answer is the pure-Python
    wheels plus the linux binary ones for either architecture in
    `LINUX_ARCHES`. Every CPython ABI is kept rather than just today's: the
    gate's `python-version` is a pin of its own and moving it must not silently
    leave pip with nothing it may install.

    `"linux" in tag` is load-bearing next to the arch suffix, not decoration:
    `macosx_11_0_arm64` also ends in an arm64 spelling, and `aarch64` is the
    one manylinux uses, so the two tests together are what keep a macOS wheel
    out of a linux build's hash block.
    """
    if not filename.endswith(".whl"):
        return False
    platform_tag = filename[:-len(".whl")].rsplit("-", 1)[-1]
    for tag in platform_tag.split("."):
        if tag == "any":
            return True
        if "linux" in tag and tag.endswith(arches):
            return True
    return False


def requirement_hash_errors(
        path: str, text: str,
        releases: dict[tuple[str, str], list[dict]],
) -> list[str]:
    """Policy errors in one file, in source/digest/PyPI filename order."""
    arches = requirements_arches(path)
    pins, unsupported = parse_requirement_options(text)
    errors = ["%s:%d: unsupported requirements line: %s" % (path, line, value)
              for line, value in unsupported]
    for name, version, options in pins:
        pin = (name, version)
        prefix = "%s: %s==%s" % (path, name, version)
        digests = []
        for option in options:
            match = _SHA256_OPTION.fullmatch(option)
            if match:
                digests.append(match.group(1))
            else:
                errors.append(
                    "%s: %s: requires lowercase sha256 with 64 lowercase "
                    "hexadecimal digits" % (prefix, option))
        if pin not in releases:  # its fetch failed; the runner reports that separately
            continue
        host_installable = False
        files = releases[pin]
        for digest in digests:
            matches = sorted(
                (entry for entry in files
                 if (entry.get("digests") or {}).get("sha256") == digest),
                key=lambda entry: str(entry.get("filename") or ""))
            if not matches:
                errors.append("%s: %s: not published for this release"
                              % (prefix, digest))
                continue
            for entry in matches:
                filename = str(entry.get("filename") or "")
                if not filename.endswith(".whl"):
                    reason = "sdist"
                elif not wheel_is_installable(filename, arches):
                    reason = "off-policy wheel"
                else:
                    host_installable |= wheel_is_installable(
                        filename, ("x86_64",))
                    continue
                errors.append("%s: %s: %s: %s"
                              % (prefix, digest, filename, reason))
        if not host_installable:
            errors.append("%s: no installable x86_64-or-any digest" % prefix)
    return errors


def check_requirements(paths: list[str], fetch_release) -> int:
    """Check every file without writing; return policy 1 or unavailable 2."""
    documents = []
    pins = set()
    errors = []
    for path in paths:
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
        try:
            requirements_arches(path)
        except RuntimeError as exc:
            errors.append(str(exc))
            continue
        documents.append((path, text))
        pins.update(parse_requirements(text))
    releases = {}
    unavailable = []
    for pin in sorted(pins):
        try:
            releases[pin] = fetch_release(*pin)
        except RuntimeError as exc:
            unavailable.append("could not verify %s==%s: %s" % (*pin, exc))
            break
    for path, text in documents:
        errors.extend(requirement_hash_errors(path, text, releases))
    for error in errors + unavailable:
        print("bump-pins: " + error, file=sys.stderr)
    return 2 if unavailable else (1 if errors else 0)
