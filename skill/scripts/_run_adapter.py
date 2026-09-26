#!/usr/bin/env python3
"""Run a single adapter by name and print raw output to stdout."""
import os
import sys
import traceback
from typing import Any

# When executed inside the panopticon-tools container the target repo is mounted
# at /src; on a developer host it is the project root. Adding the project root to
# sys.path lets us import ``tools`` both ways.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scripts.tools import ADAPTERS
from scripts.tools.base import (SECURITY_FLAG, SECURITY_MODES,  # noqa: F401
                                STANDARD)


# #1051 / SEC-G2B: every failure path exits NON-ZERO. A crash, an emit failure,
# or an unregistered adapter previously returned 0, which the caller
# (run_tools._capture_run) read as a clean run -- a silent crash reported as
# success. Fail closed instead: FAIL_RC forces _capture_run's rc-check to skip
# the tool, so the coverage manifest lands it in `missing` (-> INCONCLUSIVE).
FAIL_RC = 2


def _split_security_mode(argv):
    """`(argv without the `--security <mode>` pair, mode)`, or `(argv, None)`
    when the pair is present but unusable (#1839).

    The pair is stripped BEFORE the positional read below, or a dispatch that
    named the mode would hand the scan root the string `--security`. An
    unrecognised token yields None, which the caller turns into FAIL_RC: this
    argv is machine-generated, so a spelling nobody registered is a bug in the
    dispatcher, and the fail-OPEN reading of one -- treat it as `standard` --
    is a redteam run that silently honours the target's suppression comments.
    """
    kept, mode = [], STANDARD
    rest = list(argv)
    while rest:
        arg = rest.pop(0)
        if arg != SECURITY_FLAG:
            kept.append(arg)
            continue
        if not rest or rest[0] not in SECURITY_MODES:
            return argv, None
        mode = rest.pop(0)
    return kept, mode


def main(argv):
    argv, security_mode = _split_security_mode(argv)
    if security_mode is None:
        print("adapter dispatch named an unknown security mode; failing closed "
              "(expected one of %s)" % ", ".join(SECURITY_MODES), file=sys.stderr)
        return FAIL_RC
    name = argv[1]
    # ABSOLUTE, once, here (#1877 M4). Every adapter now runs its scanner from
    # an empty scratch cwd, and several pass `target` through to argv verbatim
    # (npm-audit's `--prefix`, osv-scanner, brakeman, spotbugs,
    # dependency-check, legacy_sarif), so a RELATIVE target would resolve
    # against a directory that by construction contains nothing. In the
    # container the default is already absolute; this is for every other
    # caller. `tools.base.scratch_cwd` names this as its precondition.
    target = os.path.abspath(argv[2] if len(argv) > 2 else "/src")
    try:
        adapter = ADAPTERS[name]
    except KeyError:
        print(f"adapter {name} is not registered; failing closed", file=sys.stderr)
        return FAIL_RC
    # Only the adapters that DECLARE they read it are given the keyword: every
    # other `invoke` takes one argument, and passing it to all of them would be
    # a TypeError -- the whole tool axis lost to a plumbing change.
    # `tests/test_run_adapter.py` holds the pin the other way round: an
    # `invoke` that TAKES the keyword must declare the attribute, so a new
    # mode-aware adapter cannot silently be handed `standard` for ever.
    call: Any = adapter.invoke
    try:
        if getattr(adapter, "reads_security_mode", False):
            stdout, rc = call(target, security_mode=security_mode)
        else:
            stdout, rc = call(target)
    except Exception as exc:  # noqa: BLE001
        print(f"adapter {name} crashed: {exc}; failing closed", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        return FAIL_RC
    try:
        sys.stdout.buffer.write(stdout)
    except Exception as exc:  # noqa: BLE001
        print(f"adapter {name} failed to emit output: {exc}; failing closed",
              file=sys.stderr)
        return FAIL_RC
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv))
