#!/usr/bin/env python3
"""Run a single adapter by name and print raw output to stdout."""
import os
import sys
import traceback

# When executed inside the panopticon-tools container the target repo is mounted
# at /src; on a developer host it is the project root. Adding the project root to
# sys.path lets us import ``tools`` both ways.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scripts.tools import ADAPTERS


# #1051 / SEC-G2B: every failure path exits NON-ZERO. A crash, an emit failure,
# or an unregistered adapter previously returned 0, which the caller
# (run_tools._capture_run) read as a clean run -- a silent crash reported as
# success. Fail closed instead: FAIL_RC forces _capture_run's rc-check to skip
# the tool, so the coverage manifest lands it in `missing` (-> INCONCLUSIVE).
FAIL_RC = 2


def main(argv):
    name = argv[1]
    target = argv[2] if len(argv) > 2 else "/src"
    try:
        adapter = ADAPTERS[name]
    except KeyError:
        print(f"adapter {name} is not registered; failing closed", file=sys.stderr)
        return FAIL_RC
    try:
        stdout, rc = adapter.invoke(target)
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
