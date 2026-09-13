"""The orchestrator on rails: `driver loop` and `driver persist` (spec 4)."""
import os
import sys

import scripts.phases.persist as persist
import scripts.phases.runio as runio


def persist_cli(args):
    """`driver persist ENTRY_ID [--file PATH] [--setup] [target]` -> exit code."""
    review_root, _wt, _pr = runio.resolve_review_root(args.target)
    entry = persist.find_entry(review_root, args.entry_id,
                               namespace="setup" if args.setup else None)
    if entry is None:
        print("driver persist: no entry %r in the current dispatch request"
              % args.entry_id, file=sys.stderr)
        return 1
    if args.file:
        with open(args.file, encoding="utf-8") as fh:
            text = fh.read()
    else:
        text = sys.stdin.read()
    ok, reason = persist.write_reply(entry, text)
    if not ok:
        print("driver persist: %s" % reason, file=sys.stderr)
        return 1
    print(os.path.abspath(entry["out_file"]))
    return 0


def main_verb(args):
    if args.verb == "persist":
        return persist_cli(args)
    raise SystemExit("driver loop lands in a later task")
