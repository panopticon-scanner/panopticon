"""The loop's host-outage verdict (#1623): whose failure was that, and what the
run does about a batch of them.

Its own module, not part of the runner seam in `base.py`: `base` is the
contract a FAMILY implements, while everything here is what the LOOP decides
once a family has answered. The two are wired one way only -- `base.RunResult`
asks this module to classify a failure nobody classified -- so there is no
cycle, and `runners/*` still imports no `phases` (layout rule 3).
"""
import re
import shlex


# #1623: the two classes a failed launch can belong to. `host` is the run's
# problem, not this entry's -- auth, quota, a rate limit, the provider down --
# and the loop refuses to charge an entry's attempt budget for one.
HOST_FAILURE = "host"
ENTRY_FAILURE = "entry"
# The provider-side symptoms, read case-insensitively out of the failure TEXT,
# which is where all three shipped families put the host's own words: claude
# composes "claude -p exited %s: %s" and "claude -p reported is_error: %s" from
# the envelope, kimi "kimi -p exited %s: %s" from stdout-or-stderr, and codex
# takes its `turn.failed`/`error` event's message verbatim. One host-agnostic
# reader therefore covers the shipped text, and a family that knows better
# passes `failure_class` at its own RunResult construction instead of teaching
# this list a fourth dialect.
_HOST_FAILURE_TEXT = (
    # the credential is refused
    "unauthorized", "unauthorised", "forbidden", "authentication",
    "invalid api key", "api key not", "no api key", "token expired",
    "expired token", "oauth", "please log in", "please login", "not logged in",
    "/login",
    # there is no money or allowance left
    "quota", "insufficient_quota", "billing", "payment required",
    "out of credits", "credit balance", "usage limit",
    # too fast
    "rate limit", "rate_limit", "ratelimit", "too many requests", "overloaded",
    # the provider itself
    "service unavailable", "bad gateway", "gateway timeout", "upstream",
    "temporarily unavailable", "internal server error",
)
# ...and the statuses they arrive as. Bounded on BOTH sides so that a duration
# ("kimi -p timed out after 403s"), a version, a path and a line number are not
# read as an HTTP status: no word character, dot, dash or slash before it, and
# no word character after.
_HOST_FAILURE_STATUS = re.compile(r"(?<![\w./-])(401|402|403|429|502|503|504|529)(?!\w)")


def classify_failure(error):
    """`HOST_FAILURE` when this failure was the HOST's rather than this entry's
    -- auth, quota, a rate limit, or the provider being down -- else
    `ENTRY_FAILURE` (#1623).

    Deliberately asymmetric. An unrecognised failure stays the entry's, which
    is what every failure was before this existed, so nothing a family already
    returns changes meaning. A false negative costs exactly what #1623 cost; a
    false positive stops a run that could have retried -- and the loop acts on
    it only when EVERY failure in a batch says the same thing, so one
    misread line in a mixed batch changes nothing at all.
    """
    text = ("" if error is None else str(error)).lower()
    if not text:
        return ENTRY_FAILURE
    if _HOST_FAILURE_STATUS.search(text) or any(m in text for m in _HOST_FAILURE_TEXT):
        return HOST_FAILURE
    return ENTRY_FAILURE


# #1623: the sentence a host-wide outage ends a run with. Two constants, the
# way the interrupt's are, because `docs/PANOPTICON.md` quotes the clause back
# and the guide test reads it off here rather than re-typing it.
HOST_OUTAGE_CLAUSE = ("no entry's attempt budget was charged and nothing was written, so "
                      "re-running the loop resumes this run where it stopped")
HOST_OUTAGE = ("paused: the %s host failed %d of this batch's %d launches with a %s-class "
               "failure (auth, quota, a rate limit, or the provider itself) rather than an "
               "entry-class one; last: %s; " + HOST_OUTAGE_CLAUSE + ", with the same flags, "
               "once the host is back: `%s`")


class FailureTally:
    """The loop's failure bookkeeping for one INVOCATION: which entries are
    stuck, and whether a batch was really the host going down (#1623).

    Consecutive failed launches per entry id, and that entry's last failure
    message (fix round 2). A launch the runner failed and a reply persist
    refused both count: neither advanced the entry, and neither gets likelier
    on the fortieth attempt. A clean, accepted launch clears the streak -- this
    bounds an entry that is STUCK, not one that is merely flaky.

    In memory, and per INVOCATION. In session mode that means a re-entry starts
    every entry at zero, deliberately: nothing there advances except a human
    persisting a reply that passes the phase's own done predicate, so the
    disk-evidence gate already bounds it -- there is no runaway to cap, and a
    streak that survived across invocations would refuse an operator their
    fourth honest attempt at a cell.

    Nothing is charged as it lands, though: "whose failure was that" is not
    answerable one result at a time. 243 of the 247 failed launches in the Kimi
    evidence run were a single 403, and charging each of them the moment it
    arrived is what spent every pending cell's budget on an outage and ended
    the run `complete` with an empty review axis. So a batch is charged when it
    CLOSES (`settle`), by which time the loop knows whether every failure in it
    said the same thing.

    It lives beside the classifier rather than in orchestrate.py so that the
    classification and every decision read off it have one owner -- and because
    orchestrate.py is an entry script at its line ceiling, where this would
    have gone in as forty more lines of loop body.
    """

    def __init__(self, host, args=None):
        self.host = host
        # The loop's own `args`, read ONLY through getattr and only to compose
        # the resume line: an operator told "re-run it" has to be told with
        # what. Nothing here imports argparse or requires a Namespace.
        self.args = args
        self.streaks = {}        # entry id -> consecutive CHARGED failures
        self.last_error = {}     # entry id -> that entry's last failure message
        self._batch = []         # (entry id, message, class or None) for the open batch

    def record(self, entry_id, result, refusal=None):
        """One landed entry: `result` as the runner returned it, and `refusal`
        the loop's own persist refusal -- which is panopticon's verdict on a
        launch that DID come back, so it is always the entry's own failure
        whatever the host would have said about it."""
        if refusal is not None:
            self._batch.append((entry_id, refusal, ENTRY_FAILURE))
        elif getattr(result, "ok", False):
            self._batch.append((entry_id, None, None))
        else:
            self._batch.append((entry_id, getattr(result, "error", None),
                                getattr(result, "failure_class", None) or ENTRY_FAILURE))

    def settle(self):
        """Close the batch: charge what it really proved, and return the
        operator's `paused` message when the whole of it was the host (else
        None). Called once per batch, whatever the outcome -- it is the charge,
        not just the verdict."""
        batch, self._batch = self._batch, []
        failures = [(eid, err, cls) for eid, err, cls in batch if cls is not None]
        for eid, err, cls in batch:
            if cls is None:
                self.streaks.pop(eid, None)          # a clean launch clears the streak
                continue
            self.last_error[eid] = err
            if cls == ENTRY_FAILURE:
                self.streaks[eid] = self.streaks.get(eid, 0) + 1
        if not failures or any(cls != HOST_FAILURE for _eid, _err, cls in failures):
            return None
        return HOST_OUTAGE % (self.host, len(failures), len(batch), HOST_FAILURE,
                              failures[-1][1], self.resume_command())

    def exhausted(self, pending, cap):
        """The `error` message for the first pending entry that has spent `cap`
        consecutive charged launches, or None. An entry the HOST failed never
        reaches it, because a host-class failure is never charged."""
        for entry in pending or ():
            eid = entry.get("id") if isinstance(entry, dict) else None
            if self.streaks.get(eid, 0) >= cap:
                return ("driver loop: entry %s failed %d consecutive launches; last: %s"
                        % (eid, self.streaks[eid], self.last_error.get(eid)))
        return None

    def resume_command(self):
        """The command that resumes this run once the host is back.

        The flags that RESOLVE the run, and no others: the review root
        (`target`, plus `--pr`/`--base`, whose worktree is the review root),
        the namespace, and the host and mode the loop settled on. Everything
        else the operator passed has to be passed again too -- the engine
        refuses a changed flag as run drift -- which is what "with the same
        flags" in the message says.
        """
        target = getattr(self.args, "target", None) or "."
        cmd = ["python3 skill/scripts/driver.py loop", shlex.quote(str(target))]
        if getattr(self.args, "pr", None):
            cmd += ["--pr", str(self.args.pr)]
        elif getattr(self.args, "base", None):
            cmd += ["--base", shlex.quote(str(self.args.base))]
        if getattr(self.args, "setup", False):
            cmd.append("--setup")
        cmd += ["--host", str(self.host),
                "--mode", str(getattr(self.args, "mode", None) or "headless")]
        return " ".join(cmd)
