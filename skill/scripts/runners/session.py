"""Session mode (spec 4.4): print the batch, return None; the loop then exits
`dispatch` and the session runs the agents and calls `driver persist`."""
import json
import sys

import scripts.runners.base as base


class SessionRunner(base.HostRunner):
    mode = "session"
    default_concurrency = 1
    # Handed over by the loop before the first batch (C2/M4, final review).
    # `dispatch_request` is the ABSOLUTE path of the request these entries came
    # from -- per-run (`runs/<tag>/dispatch-request.json`) for a review, a
    # top-level `setup-dispatch-request.json` under `--setup` (#1507) -- so the
    # host can cross-reference the printed ids against the file instead of
    # guessing a path. `namespace` is "setup" there and None otherwise, and is
    # what puts `--setup` in the two commands below: without it `driver
    # persist` and the next `driver loop` both read the review namespace and
    # find no entry. `runners/` may not import `phases` (layout rule 3), so the
    # loop -- which owns both facts -- sets them rather than this module
    # resolving them.
    dispatch_request = None
    namespace = None

    def run_entry(self, entry, env):
        raise NotImplementedError("session mode never runs an entry itself")

    def run_batch(self, entries, concurrency, env_for):
        entries = list(entries)
        ids = [e.get("id") for e in entries]
        rp = [e.get("id") for e in entries if e.get("delivery") == "return_json"]
        setup = " --setup" if self.namespace == "setup" else ""
        sys.stdout.write(json.dumps({
            "status": "dispatch",
            "pending": ids,
            "return_persist": rp,
            "dispatch_request": self.dispatch_request,
            "prompt_files": {e.get("id"): e.get("prompt_file") for e in entries},
            "persist": "driver persist <id>%s --file <reply.txt>   "
                       "# once per return-persist id, e.g. `driver persist %s%s`"
                       % (setup, rp[0] if rp else "<id>", setup),
            "then": "driver loop%s --mode session <target> [same flags]" % setup,
        }) + "\n")
        sys.stdout.flush()
        return None
