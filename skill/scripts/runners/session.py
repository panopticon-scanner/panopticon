"""Session mode (spec 4.4): print the batch, return None; the loop then exits
`dispatch` and the session runs the agents and calls `driver persist`."""
import json
import sys

import scripts.runners.base as base


class SessionRunner(base.HostRunner):
    mode = "session"
    default_concurrency = 1

    def run_entry(self, entry, env):
        raise NotImplementedError("session mode never runs an entry itself")

    def run_batch(self, entries, concurrency, env_for):
        entries = list(entries)
        ids = [e.get("id") for e in entries]
        rp = [e.get("id") for e in entries if e.get("delivery") == "return_json"]
        sys.stdout.write(json.dumps({
            "status": "dispatch",
            "pending": ids,
            "return_persist": rp,
            "prompt_files": {e.get("id"): e.get("prompt_file") for e in entries},
            "persist": "driver persist <id> --file <reply.txt>   "
                       "# once per return-persist id, e.g. `driver persist %s`" % (rp[0] if rp else "<id>"),
            "then": "driver loop --mode session <target> [same flags]",
        }) + "\n")
        sys.stdout.flush()
        return None
