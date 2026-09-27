#!/usr/bin/env python3
"""#1774 (ARC-261650949): read ONE pinned `ARG` out of the Dockerfile, shape-checked.

Two workflow steps used to re-derive the dependency-check pins with their own
`grep -E '^ARG ...=' Dockerfile | head -1 | cut -d= -f2` and their own inline
shape check:

  * `.github/workflows/nvd-cache.yml`, step "Read dependency-check version from
    the Dockerfile": `DEPENDENCY_CHECK_VERSION` (which keys the `dc-<version>`
    data-image tag) and `DEPENDENCY_CHECK_SHA256` (what the downloaded release
    zip is checked against); and
  * `.github/workflows/docker-publish.yml`, step "Resolve NVD data image digest
    (content-pin the cache)": the version, to name the cache tag it then pins
    by digest.

The shape check is a security control rather than tidiness -- nvd-cache.yml
spelled it "constrain to expected shapes so a tampered ARG can't inject
downstream", because the value goes on to name an image tag and a download URL
-- so this reader keeps the check and REFUSES instead of returning. An ARG with
no registered shape is refused too: a shared reader that hands back arbitrary
values is the thing neither caller was allowed to have.

`SHAPES` is that closed map, every pattern anchored and enforced with
`fullmatch`. Where `head -1` silently took the first of two `ARG <NAME>=` lines,
`read_arg` REFUSES the duplicate: the tag the workflows prime and the default the
image builds from must never disagree (`bump_pins._single_arg` draws the same
line). Nothing is stripped, so trailing whitespace fails the shape
exactly as it did when the inline `echo "$ver" | grep -Eq` saw it. Refusals are
one line and always start with this module's name, so a tampered value cannot
begin a line in the runner log and forge a `::error::` workflow command.

Stdlib only and no subprocess: CI runs it as `python3 scripts/dockerfile_args.py
read-arg <NAME>` from the checkout root right after `actions/checkout`, with no
setup step, the way `pin-freshness.yml` already runs `scripts/bump_pins.py`.
`bump_pins.py` owns the pins it WRITES (rustup, trivy, rust-toolchain,
requirements, gems, tinyproxy); this owns the two the workflows READ.
Tests: `tests/test_dockerfile_args.py`.
"""
from __future__ import annotations

import argparse
import re
import sys

# ARG name -> the shape its value must have. Closed: a name that is not here is
# refused. Both entries are at least as strict as the inline `grep -Eq` they
# replace, and the version one is deliberately STRICTER -- inline
# `^[0-9][0-9.]*$` also accepted `10.0.3.` and `1..2`, which are not versions.
SHAPES: dict[str, re.Pattern[str]] = {
    "DEPENDENCY_CHECK_VERSION": re.compile(r"^[0-9]+(\.[0-9]+)*$"),
    "DEPENDENCY_CHECK_SHA256": re.compile(r"^[0-9a-f]{64}$"),
}

DEFAULT_DOCKERFILE = "Dockerfile"


def _brief(value: str, limit: int = 60) -> str:
    """The value as a bounded `repr`, so a refusal stays one readable line."""
    return repr(value if len(value) <= limit else value[:limit] + "...")


def read_arg(dockerfile_text: str, name: str) -> str:
    """The single `ARG <name>=<value>` line's value, shape-checked.

    Raises `ValueError` naming the ARG when it has no registered shape, when no
    `ARG <name>=` line declares it, when more than one line does, or when the
    declared value fails that shape. Pure: no I/O, so the callers' file reading
    stays in `main`.
    """
    shape = SHAPES.get(name)
    if shape is None:
        raise ValueError(
            "ARG %s has no registered shape: add one to SHAPES in "
            "scripts/dockerfile_args.py, or read that value somewhere else"
            % name)
    values = re.findall(r"^ARG " + re.escape(name) + r"=(.*)$",
                        dockerfile_text, re.M)
    if not values:
        raise ValueError("no `ARG %s=` line in the Dockerfile" % name)
    if len(values) > 1:
        raise ValueError("ARG %s is declared %d times in the Dockerfile; "
                         "expected exactly one line" % (name, len(values)))
    value = values[0]
    if not shape.fullmatch(value):
        raise ValueError("ARG %s is not of the form %s: %s"
                         % (name, shape.pattern, _brief(value)))
    return value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Read one shape-checked pin out of the Dockerfile.")
    modes = parser.add_subparsers(dest="mode", required=True)
    read = modes.add_parser(
        "read-arg", help="print one ARG's value on stdout, or refuse")
    read.add_argument("name", help="ARG name, e.g. DEPENDENCY_CHECK_VERSION")
    read.add_argument(
        "--dockerfile", default=DEFAULT_DOCKERFILE,
        help="file to read (default: %(default)s, relative to the working "
             "directory, which in CI is the checkout root)")
    args = parser.parse_args(argv)
    try:
        with open(args.dockerfile, encoding="utf-8") as handle:
            value = read_arg(handle.read(), args.name)
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        # One line, prefixed: nothing a tampered value carries can start it.
        print("dockerfile_args: %s" % exc, file=sys.stderr)
        return 2
    print(value)
    return 0


if __name__ == "__main__":
    sys.exit(main())
