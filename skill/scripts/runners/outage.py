"""The loop's host-outage verdict (#1623): whose failure was that, and what the
run does about a batch of them.

Its own module, not part of the runner seam in `base.py`: `base` is the
contract a FAMILY implements, while everything here is what the LOOP decides
once a family has answered. The two are wired one way only -- `base.RunResult`
asks this module to classify a failure nobody classified -- so there is no
cycle, and `runners/*` still imports no `phases` (layout rule 3).
"""
import json
import re

import scripts.redact as redact
import scripts.runners.resume as resume


# #1623: the two classes a failed launch can belong to. `host` is the run's
# problem, not this entry's -- auth, quota, a rate limit, the provider down --
# and the loop refuses to charge an entry's attempt budget for one.
HOST_FAILURE = "host"
ENTRY_FAILURE = "entry"
# What is classified is the HOST's own error surface (`RunResult.host_error`),
# never the composed `RunResult.error`: on two of the three shipped families
# that message is built out of up to 200 characters of the AGENT's reply
# (`claude -p exited %s: %s` % (rc, text[:200]); kimi's `detail` prefers the
# assistant's content over stderr), so a cell reviewing `src/billing/quota.py`
# would report its own findings as a quota outage. Every family fills
# `host_error` from the place it ALREADY parses the host's error and from
# nowhere else; a family that recorded none said nothing about the host.
#
# The match is anchored on both sides of that, as defence in depth:
#
# * a KIND -- the error key or reason phrase a provider names its own failures
#   with (`authentication_error`, `insufficient_quota`, `RESOURCE_EXHAUSTED`).
#   Phrase-shaped, never a bare word: `quota` alone is a directory name,
#   `quota exceeded` is an outage. Separators are `[\s_.-]` so the wire form
#   (`rate_limit_error`) and the prose form (`rate limit error`) are one entry.
# * a STATUS that sits NEXT TO its reason (`403 Forbidden`, `429 Too Many
#   Requests`, `auth_error: 403`, `API Error: 401`). A bare status is not
#   enough: `line 403`, `got 503 in tests/test_gateway.py` and `429 python
#   files` are all things a failing entry really says.
_S = r"[\s_.-]"                      # how a provider spells a compound reason
_KINDS = (
    r"auth(?:entication|orization)?{s}?error",   # auth_error, provider.auth_error
    r"invalid{s}api{s}key",
    r"(?:missing|no){s}api{s}key",
    r"api{s}key{s}(?:not{s}found|expired|is{s}invalid)",
    r"please{s}run{s}/login",
    r"(?:not{s}authenticated|unauthenticated)",
    # N2: the WIRE key only (Google's canonical 403 name), never the
    # space-separated English. kimi and codex hand their whole stderr over as
    # the host surface, and `Permission denied` there is the OS talking about
    # a local file -- an EACCES on a temp directory read as a provider outage
    # tells the operator to wait and re-run, which reproduces it for ever.
    # The provider's own 403 still arrives as a status beside its reason, or
    # as `permission_error` below.
    r"permission_denied",
    r"permission_error",              # Anthropic's own type for the same refusal
    r"insufficient{s}quota",
    r"quota{s}(?:exceeded|exhausted)",
    r"exceeded{s}your{s}current{s}quota",
    r"resource{s}exhausted",
    r"credit{s}balance{s}is{s}too{s}low",
    r"payment{s}required",
    r"billing{s}hard{s}limit",
    r"rate_limit",                               # the wire key, underscore only
    r"rate{s}limit(?:ed|{s}(?:error|exceeded|reached))",
    r"exceeded{s}(?:your{s})?rate{s}limit",
    # #1729: Claude's own subscription-limit line, printed with NO `error`
    # object -- run 14's 225 wasted launches were entirely this
    # (`You've hit your session limit \u00b7 resets 10:10am (America/Chicago)`,
    # and the same shape for a usage, weekly/7-day, daily, monthly, plan or
    # N-hour limit). Phrase-shaped like the neighbours: never a bare `limit`,
    # and never a bare `usage limit`/`session limit` on their own -- an
    # agent's finding can say "the per-user usage limit is never enforced"
    # and a tool's stderr can say "session limit".
    #
    # Coordinator review round 1 found two defects in the first cut of these:
    #
    # Critical 1 (ReDoS): the filler between "your"/"the" and the limit name
    # was `(?:\S+{s}){0,3}?` -- and `{s}` is `[\s_.-]`, which OVERLAPS `\S` on
    # `_`/`.`/`-`. A long separator-free run then has cubically many ways to
    # split itself between the filler's `\S+` and its own trailing
    # separator, so a hostile or merely unlucky agent reply (or a claude
    # `result` opening `API Error: 500 exceeded the a-a-a-a-...`, since
    # `_HOST_HEAD` embeds this whole tuple into `_CLI_ERROR` too) cost
    # seconds at 1-2 KB and tens of seconds at 3 KB. Fixed by making the
    # filler's own separator whitespace-only (plain `\s`, spelled out rather
    # than `{s}`): disjoint from `\S`, so there is no character either side
    # can claim and nothing left to backtrack over.
    #
    # Critical 2 (false positives on ordinary code): the SAME `{s}` overlap
    # meant a Python identifier (`hit_your_plan_limit()`) or a pytest node id
    # (`test_usage_limit_reached`) read as this KIND, because `_` stood in
    # for a space. Every separator in both patterns below is now a literal
    # `\s`, never `{s}` -- these two patterns are about an English sentence
    # the CLI or an agent wrote, never an identifier.
    #
    # Both patterns also refuse to run on into ordinary prose ("...limit
    # handling is wrong in src/quota.py", "...limit reached counter is reset
    # nightly") OR into a directly-attached quote (`'weekly limit reached'`,
    # no space before the closing quote -- a bare `[a-z]`-only guard let this
    # through, since a quote is not a letter) by requiring that nothing but a
    # genuine delimiter follows: either no continuing word/quote at all, or
    # -- Important 3 -- up to 40 characters of ANYTHING (a model name, "for
    # Claude Opus 4.5") and then the real `\u00b7 resets` delimiter. The 40-char
    # cap keeps that second option just as immune to backtracking blowup as
    # the first: it is a bounded quantifier, not an unbounded one.
    r"(?:hit|reached|exceeded)\s+(?:your|the)\s+(?:\S+\s){{0,3}}?"
    r"(?:session|usage|weekly|daily|monthly|plan|\d+-hour)\s+limit"
    r"(?:(?!\s*[a-z'])|.{{0,40}}?\u00b7\s*resets\b)",
    r"(?:session|usage|weekly|daily|monthly|plan|\d+-hour)\s+limit\s+"
    r"(?:reached|exceeded|hit)(?:(?!\s*[a-z'])|.{{0,40}}?\u00b7\s*resets\b)",
    # The older API form of the same class: a bare phrase followed by a pipe
    # and an epoch integer (`Claude AI usage limit reached|1758400000`), or
    # end of line. Same guard as the two above -- a continuation into an
    # ordinary word ("...reached is shown as a toast") is a finding, not a
    # line the CLI printed.
    r"claude\s+ai\s+usage\s+limit\s+reached(?!\s*[a-z'])",
    r"too{s}many{s}requests",
    r"overloaded(?:{s}error)?",
    r"(?:service|api){s}unavailable",
    r"temporarily{s}unavailable",
    r"upstream{s}connect{s}error",
    r"bad{s}gateway",
    r"gateway{s}time-?out",
    r"internal{s}server{s}error",
)
# The reason phrases a status is allowed to sit beside. Short on purpose: this
# half only qualifies a status that is already there. The KEY NAMES are in here
# too (N3) -- `code`, `status`, `http_status`, `error_code` -- because a
# provider error object is flattened to `key: value` pairs and `code: 403` has
# to qualify its own number: `message` is always last, so a status under `code`
# and its reason in `message` are never adjacent, which is what the rule needs.
_REASONS = (r"forbidden", r"unauthori[sz]ed", r"unauthenticated", r"too{s}many{s}requests",
            r"payment{s}required", r"service{s}unavailable", r"bad{s}gateway",
            r"gateway{s}time-?out", r"internal{s}server{s}error", r"quota",
            r"rate{s}limit", r"overloaded", r"error", r"(?:resource{s})?exhausted",
            r"(?:http{s})?status(?:{s}?code)?")     # status, status_code, statusCode
# The provider's error OBJECT may qualify a status by its own key name
# (`code: 403`) and may carry 500 for the `api_error` shape. Free text may
# not (R2 re-review N6): kimi and codex hand their whole stderr over, where
# `code` is the commonest word a tool says about the code under review and
# `500 errors` is what mypy prints -- ten realistic tool lines read as the
# provider when these two were shared.
_OBJECT_REASONS = _REASONS + (r"(?:error{s})?code",)
_STATUS = r"(?:401|402|403|429|502|503|504|529)"
_OBJECT_STATUS = r"(?:401|402|403|429|500|502|503|504|529)"


def _alt(patterns):
    return "|".join(p.format(s=_S) for p in patterns)


# A kind never starts mid-word: `/billing/quota.py` and `myquota exceeded` are
# not the provider talking. `_` and `.` are separators, not word characters.
_HOST_ERROR_KIND = re.compile(r"(?:^|[^0-9a-z])(?:%s)" % _alt(_KINDS), re.I)
# A status, bounded on both sides so a duration ("403s"), a version, a path and
# a line number are not one -- and required to touch its reason.
# The separator class admits JSON quoting (R2 re-review N7): the same
# envelope printed raw on a family's stderr -- `{"status":403,"message":
# "Forbidden"}` -- must read the way the flattened object does.
def _status_rule(status, reasons):
    return re.compile(
        r"(?<![\w./-])%(st)s(?!\w)[\s:,;=()\"'-]*(?:%(rs)s)"
        r"|(?:%(rs)s)[\s:,;=()\"'-]*(?<![\w./-])%(st)s(?!\w)"
        % {"st": status, "rs": _alt(reasons)}, re.I)


_HOST_ERROR_STATUS = _status_rule(_STATUS, _REASONS)
_HOST_ERROR_STATUS_OBJECT = _status_rule(_OBJECT_STATUS, _OBJECT_REASONS)
# A CLI's own error FRAMING at the start of a text field. How a family tells
# the host's words from the agent's when both can arrive in one field -- and
# anchoring at the start is not enough on its own, because half of these are
# also ordinary English sentence openings: "Rate limit exceeded responses are
# not handled" and "Authentication error handling is missing in src/login.py"
# are findings, not outages, and a gate that accepted them let the whole reply
# through to the classifier (N1).
#
# So the prefix must be followed by the DELIMITER the CLI puts there -- a
# colon, a middot, a dash, or the end of the line -- and the two prefixes that
# are pure prose without one ("rate limit", "authentication error", "credit
# balance") are gone: the renderings they were meant to catch are "Rate limit
# reached ..." and "Your credit balance is too low", which never started with
# them anyway, and both carry a status the classifier reads for itself.
#
# And the delimiter is necessary but not sufficient (R2 re-review N5): `Error:
# 401 handling is missing in src/auth/view.py` and `Overloaded: the scheduler
# drops tasks` clear a delimiter and are findings. So the status must be
# followed by its reason, a JSON or parenthetical body, another delimiter or
# the end of the line; and a bare prefix by the end of the line, or by a
# delimiter and then a KIND or a REASON -- host-shaped content, not prose.
#
# #1729 adds a fifth, sixth and seventh: `You've hit your session limit
# \u00b7 resets 10:10am (America/Chicago)` (and the usage/weekly/daily/
# monthly/plan/N-hour siblings of it), `Claude AI usage limit
# reached|1758400000` (the older API form), and `5-hour limit reached
# \u00b7 resets 3pm` -- all printed with NO `error` object at all, so this
# gate is the ONLY place that surfaces them. Same discipline again --
# "You've hit your session limit handling is wrong in src/quota.py" is a
# finding, not an outage -- so each opening is only CLI framing when it is
# followed by the delimiter that rendering actually uses, or the end of the
# line; never by more prose.
#
# Coordinator review round 1, Important 3: the first cut required the middot
# to sit IMMEDIATELY after "limit", so "You've reached your usage limit FOR
# CLAUDE OPUS 4.5 \u00b7 resets 3:10pm" -- a real rendering with a model name
# between the two -- failed the gate before the \u00b7 was ever looked at.
# The lookahead now also accepts up to 40 characters of anything (bounded,
# so this stays as immune to backtracking blowup as a fixed-width check) and
# then the real `\u00b7 resets` delimiter.
_HOST_HEAD = r"(?:%s|%s)" % (_alt(_KINDS), _alt(_REASONS))
_CLI_ERROR = re.compile(
    r"^(?:(?:api\s+)?error\s*:\s*[45]\d\d(?!\w)(?=\s*(?:$|[{(\[\u00b7,;-]|" + _HOST_HEAD + r"))"
    r"|(?:api\s+error|invalid\s+api\s+key|overloaded)"
    r"(?=\s*(?:$|[:\u00b7,-]\s*(?:[{\[]|" + _HOST_HEAD + r")))"
    # Item 4: the CLI may print a curly apostrophe (U+2019) instead of a
    # straight one.
    r"|you['\u2019]?ve\s+(?:hit|reached)\s+(?:your|the)\s+(?:\S+\s+){0,3}?"
    r"(?:session|usage|weekly|daily|monthly|plan|\d+-hour)\s+limit"
    r"(?=\s*(?:$|.{0,40}?\u00b7\s*(?:resets\b|$)))"
    r"|claude\s+ai\s+usage\s+limit\s+reached(?=$|\|\d+)"
    r"|\d+-hour\s+limit\s+reached(?=\s*(?:$|\u00b7\s*resets\b)))", re.I)


# The keys a provider error object carries its own verdict in, across the
# spellings the vendors use (N3). A fixed list, not "every key": an error
# payload can also carry the request that produced it, and reading that back
# would be the C1 door again in a different shape.
_SURFACE_KEYS = ("type", "kind", "code", "error_code", "errorCode", "status",
                 "status_code", "statusCode", "http_status", "httpStatus",
                 "reason", "error", "message")


def _surface(host_error):
    """The text to match, out of whatever shape a family recorded.

    A provider error arrives either as a line (`provider.auth_error: 403`) or
    as the error OBJECT the API returned. The object is flattened key by key,
    so `{"code": 403}` reads as `code: 403` -- a status beside its own key,
    which is what the anchoring rule needs, because `message` is always last
    and a reason there would never touch the number. A nested `{"error": {...}}`
    envelope is followed one level at a time.
    """
    if isinstance(host_error, dict):
        parts = []
        for key in _SURFACE_KEYS:
            value = host_error.get(key)
            if isinstance(value, dict):
                parts.append(_surface(value))
            elif value not in (None, "", []):
                parts.append("%s: %s" % (key, value))
        return " ".join(parts)
    return "" if host_error is None else str(host_error)


def _as_object(host_error):
    """A provider error object that a family printed as raw JSON on its
    stderr, read back as the object (R2 re-review N7); anything else as it
    came. Whole text first, then line by line, so an envelope printed after
    other stderr is still found. Only a JSON OBJECT qualifies -- a list, a
    number or a string is not an error envelope.
    """
    if not isinstance(host_error, str):
        return host_error
    candidates = [host_error.strip()]
    candidates += [line.strip() for line in host_error.splitlines()]
    for candidate in candidates:
        if not candidate.startswith("{") or not candidate.endswith("}"):
            continue
        try:
            parsed = json.loads(candidate)
        except ValueError:
            continue
        if isinstance(parsed, dict):
            return parsed
    return host_error


def classify_failure(host_error):
    """`HOST_FAILURE` when THIS failure was the host's rather than the entry's
    -- auth, quota, a rate limit, or the provider being down -- else
    `ENTRY_FAILURE` (#1623).

    `host_error` is the host's own error surface and nothing else: the CLI's
    error line, or the provider error object it printed. Absent -- the normal
    case, because most failures are the entry's -- is `ENTRY_FAILURE`, which
    is what every failure was before this existed.

    Deliberately asymmetric in the same direction. A false negative costs what
    #1623 cost: an outage charged to the cells. A false positive stops a run
    that could have retried AND takes the per-entry cap off that entry, which
    is why the surface is narrowed at the family, anchored here, and acted on
    by the loop only when a batch ENDS in a run of them (#1721) -- one of
    these on its own, with a later launch answering cleanly, decides nothing.
    """
    host_error = _as_object(host_error)
    text = _surface(host_error)
    if not text:
        return ENTRY_FAILURE
    # The object rule is for the provider's own error object (N3): only there
    # may a key name qualify a status, and only there is 500 a host failure.
    status_rule = _HOST_ERROR_STATUS_OBJECT if isinstance(host_error, dict) else _HOST_ERROR_STATUS
    if _HOST_ERROR_KIND.search(text) or status_rule.search(text):
        return HOST_FAILURE
    return ENTRY_FAILURE


def cli_error(text):
    """`text` when it IS a CLI's own error rendering rather than the agent's
    reply, else None (#1623).

    For the one place a family cannot keep the two apart by structure: the
    Claude envelope's `result` string, which carries the agent's final message
    on a good turn and the CLI's `API Error: ...` line on a refused one. The
    envelope's own `error` OBJECT is preferred wherever the CLI emits one; this
    is the fallback, and it is deliberately the narrowest thing that still
    recognises the seven renderings the CLI really prints.

    Matched at the START of the stripped text AND up to the delimiter that
    follows it, so neither a findings body that quotes an error message inside
    it nor one that OPENS with the same words is mistaken for the host (N1).
    """
    return text if _CLI_ERROR.match((text or "").strip()) else None


# #1623: the sentence a host-wide outage ends a run with. Two constants, the
# way the interrupt's are, because `docs/PANOPTICON.md` quotes the clause back
# and the guide test reads it off here rather than re-typing it.
#
# The clause says what is TRUE of the batch, which is not "nothing was
# written": the pause fires when every FAILURE was the host's, and a batch can
# reach that with successful entries in it whose findings are persisted, whose
# ledger rows are written and whose spend is in usage.json. What the pause
# guarantees is narrower and is the part that matters -- no attempt budget was
# charged, and the launches that FAILED left nothing behind to take back.
HOST_OUTAGE_CLAUSE = ("no entry's attempt budget was charged and the failed launches left "
                      "nothing behind, so every reply that did land is kept and re-running "
                      "the loop resumes this run where it stopped")
HOST_OUTAGE = ("paused: the %s host failed %d of this batch's %d launches with a %s-class "
               "failure (auth, quota, a plan or session limit, a rate limit, or the provider "
               "itself) rather than an "
               "entry-class one, and %d of its entries were never launched; last: %s; "
               + HOST_OUTAGE_CLAUSE + ", with the same flags, once the host is back: `%s`")

# How fast a launch has to fail to count as "before any entry did its work"
# (#1732). Run 14's 103 refused launches each took ~120 ms -- the CLI parsing
# its own argv, finding it invalid and exiting. Two seconds is an order of
# magnitude above that and an order of magnitude below the cheapest real
# entry, so a batch that clears it is not a batch of entries failing.
UNIFORM_FAST_MS = 2000
# #1732: the sibling of HOST_OUTAGE, for the OTHER thing a whole batch of
# failures can mean. Its own constant rather than a clause of that one,
# because the two name different causes and different remedies: HOST_OUTAGE
# says wait for the host, this says fix the launch. Both end the run `paused`
# and both give every attempt back.
#
# The message is composed ONCE, as the paused status -- never per entry. Run
# 14 printed its 103 identical failures 103 times per checkpoint and three
# checkpoints deep, which is how a defect that two results had already proved
# stayed unreadable.
UNIFORM_FAILURE = (
    "paused: the first %d launches of this batch all failed in under %d ms with the same "
    "entry-class message, which is the launch refusing before any entry did its work -- the "
    "argv or the configuration, not %d different entries and not the host; %d of the batch's "
    "entries were never launched; message: %s; no entry's attempt budget was charged and the "
    "failed launches left nothing behind, so fix the cause and re-run the loop to resume this "
    "run where it stopped: `%s`")
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
    CLOSES (`settle`), by which time the loop knows what the batch as a whole
    said.

    #1721 replaced the all-or-nothing reading of that with a TRAILING RUN.
    "Every failure was the host's" made one entry-class failure anywhere in a
    batch -- a masked 403, a schema refusal, a timeout -- cancel a real outage
    outright: no pause, no attempt given back, all 78 cells charged. So what is
    tracked instead is the run of host-class failures the batch is CURRENTLY
    in, by LAUNCH ORDER (`seq`, the entry's index in the batch's pending list;
    the pool is FIFO):

    * a host-class failure opens the run if none is open, and extends it;
    * a success LAUNCHED AFTER the run opened says the host is back and closes
      it -- but one launched before it merely landed late, and decides nothing;
    * an entry-class failure neither opens, extends nor closes it. During an
      outage it is still the entry's own failure, and is still charged.

    Two readings come off that run. `outage(width)` is the live one the loop
    passes to `iter_batch` as its `stop`: enough corroboration to stop
    LAUNCHING, which is two failures or a whole pool round, whichever is
    larger. `settle` is the terminal one: the batch ended inside a run, so the
    run pauses.

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
        # #1732: the open batch's results in ARRIVAL order -- (class, redacted
        # message, launched-and-came-back, duration_ms) -- for `uniform`. By
        # arrival rather than by `seq` because the question is "what did the
        # first answers say", and the first answers are the only evidence
        # available while the rest of the batch is still queued.
        self._arrived = []
        # #1721, per batch: the launch order (`seq`) of the first host-class
        # failure of the run the batch is currently in, None when no run is
        # open, and how many host-class failures that run holds.
        self._outage_seq, self._trailing = None, 0
        # The batch's host-class entry ids, as of the last `settle`: the loop
        # gives each of them its per-dispatch attempt marker back.
        self.uncharged = []
        # How many host-class failures the run held when `outage` first said
        # stop, or None. Read by the loop's "stopped launching after N" line,
        # and NOT the same as `_trailing` by then: a success drained after the
        # stop can have closed the run and reset it to zero.
        self.stopped_at = None
        # #1732: the same, for the OTHER stop rule -- how many identical
        # instant failures `uniform` had seen when it first said stop, or
        # None. A separate attribute rather than a discriminator on
        # `stopped_at` so the loop's line can say which rule fired without
        # unpacking a tuple, and so a reader of either one cannot mistake the
        # two counts for each other.
        self.stopped_uniform = None

    def record(self, entry_id, result, refusal=None, seq=None, duration_ms=None):
        """One landed entry: `result` as the runner returned it, `refusal` the
        loop's own persist refusal -- which is panopticon's verdict on a launch
        that DID come back, so it is always the entry's own failure whatever
        the host would have said about it -- and `seq` this entry's LAUNCH
        order in the batch (#1721), which is what tells a success that proves
        the host is back from one that was merely in flight when it went
        down.

        `duration_ms` (#1732) is the runner's own measurement for this entry
        (`iter_batch`'s `timing`), which is what `uniform` reads: a whole
        batch failing identically in a tenth of a second is the launch being
        refused, and the same batch failing identically after five minutes
        each is not."""
        if refusal is not None:
            failure = (entry_id, refusal, ENTRY_FAILURE)
        elif getattr(result, "ok", False):
            failure = (entry_id, None, None)
        else:
            failure = (entry_id, getattr(result, "error", None),
                       getattr(result, "failure_class", None) or ENTRY_FAILURE)
        self._batch.append(failure)
        # #1732: `refusal is not None` is recorded as its own fact rather than
        # inferred from the class. A persist refusal IS an entry-class failure
        # -- but of a launch that came back, which is the one thing a uniform
        # LAUNCH failure says did not happen, so the two must stay
        # distinguishable here.
        self._arrived.append((failure[2], redact.redact(failure[1]),
                              refusal is not None, duration_ms))
        self._track(failure[2], seq)

    def _track(self, cls, seq):
        """Open, extend or close the trailing run of host-class failures.

        A run is open while `_trailing` is non-zero; `_outage_seq` may still be
        None there (a caller that passes no `seq` at all), and a success can
        then prove nothing about ordering, so it is ignored exactly as one from
        before the run is.
        """
        if cls == HOST_FAILURE:
            if not self._trailing:
                self._outage_seq = seq
            self._trailing += 1
        elif (cls is None and self._trailing and seq is not None
                and self._outage_seq is not None and seq > self._outage_seq):
            self._outage_seq, self._trailing = None, 0      # the host is back

    def outage(self, width=1):
        """Whether the batch is far enough into a run of host-class failures to
        stop LAUNCHING -- the predicate the loop hands `iter_batch` as its
        `stop` (#1721).

        Two, or a whole pool round when the pool is wider. Two because one
        host-class failure is a classification, not a verdict, and the cost of
        being wrong is a run stopped that could have carried on; a full round
        because at width `w` the first `w` results are all from launches that
        overlapped, so anything less would fire on a single moment's worth of
        evidence however wide the pool.

        The count at the FIRST yes is kept in `stopped_at` for the loop's own
        line: by the time the batch has drained, a later success may have
        closed the run, and "stopped launching after 0" says nothing.
        """
        if self._trailing < max(2, int(width or 1)):
            return False
        if self.stopped_at is None:
            self.stopped_at = self._trailing
        return True

    def uniform(self, width=1):
        """Whether the first `K = max(2, width)` results of this batch are one
        launch failure repeated -- the loop's SECOND stop rule (#1732).

        Run 14's tool-verify checkpoint launched 103 entries and every one of
        them exited non-zero in ~120 ms with `claude -p printed no JSON
        envelope (exit 1)`, because one argv token was wrong. Nothing here
        could tell that from 103 entries each failing on its own account: the
        per-entry cap needs three rounds to fire, so the loop launched all 103
        three times -- 309 launches, ~35 minutes -- for a defect its first two
        results had already proved.

        Four conditions, and every one of them is a way for the batch to be
        about the ENTRIES instead:

        * K results have ARRIVED. The same `max(2, width)` `outage` uses, and
          for the same reason: at width `w` the first `w` results are from
          launches that overlapped, so anything less fires on one moment's
          worth of evidence however wide the pool.
        * every one is an entry-class LAUNCH failure. A success says the argv
          is fine. A persist refusal says the launch came back, which is the
          one thing this rule claims did not happen. A host-class failure is
          the host's, and `outage` is the rule that governs it -- so the
          precedence between the two rules needs no arbitration: a host-class
          result simply is not uniform.
        * each took less than `UNIFORM_FAST_MS`. An unmeasured duration counts
          as not fast: a rule that stops a run may not fire on a fact nobody
          measured.
        * their REDACTED messages are byte-identical. Redacted because that is
          also what the pause prints, and because a per-launch request id or
          key inside an otherwise identical refusal would otherwise read as
          two different failures.

        The count at the FIRST yes is kept in `stopped_uniform`, exactly as
        `outage` keeps `stopped_at`, for the loop's own "stopped launching"
        line.
        """
        k = max(2, int(width or 1))
        first = self._arrived[:k]
        if len(first) < k:
            return False
        messages = set()
        for cls, message, refused, duration_ms in first:
            if refused or cls != ENTRY_FAILURE or not message:
                return False
            if duration_ms is None or duration_ms >= UNIFORM_FAST_MS:
                return False
            messages.add(message)
        if len(messages) != 1:
            return False
        if self.stopped_uniform is None:
            self.stopped_uniform = k
        return True

    def settle(self, unlaunched=0, width=1):
        """Close the batch: charge what it really proved, and return the
        operator's `paused` message when the batch ENDED inside a run of
        host-class failures (else None). Called once per batch, whatever the
        outcome -- it is the charge, not just the verdict. `unlaunched` is how
        many of the batch's entries the short-circuit never launched, which the
        message names because they are neither done nor charged.

        #1732 adds the second verdict, read FIRST because it is the narrower
        one: a batch whose first `max(2, width)` results were one launch
        failure repeated charges nobody at all, since what failed was the
        launch rather than any entry. `width` is the pool width, so this asks
        exactly the question the live `uniform` stop asked; a caller that
        passes none gets the floor of two, which is what a batch narrower than
        its pool was measured against anyway. The two verdicts cannot both
        describe the same K results -- a host-class failure among them is not
        uniform -- so there is no precedence to arbitrate."""
        was_uniform = self.stopped_uniform is not None or self.uniform(width)
        batch, self._batch = self._batch, []
        self._arrived = []
        trailing, self._trailing, self._outage_seq = self._trailing, 0, None
        self.stopped_at = None
        uniform_count, self.stopped_uniform = self.stopped_uniform, None
        if was_uniform:
            failed = [(eid, err) for eid, err, cls in batch if cls is not None]
            self.uncharged = [eid for eid, _err in failed]
            for eid, err, cls in batch:
                if cls is None:
                    self.streaks.pop(eid, None)
                    continue
                # Recorded, never CHARGED: the streak is what bounds an entry
                # that is stuck, and none of these entries was given a turn.
                self.last_error[eid] = err
            k = uniform_count or max(2, int(width or 1))
            return UNIFORM_FAILURE % (
                k, UNIFORM_FAST_MS, k, unlaunched,
                # Already redacted on arrival; redacted again on the way out
                # for the same reason every other pause message is -- the
                # composition is the guarantee, not the storage.
                redact.redact(failed[-1][1] if failed else None),
                self.resume_command())
        host = [(eid, err) for eid, err, cls in batch if cls == HOST_FAILURE]
        self.uncharged = [eid for eid, _err in host]
        for eid, err, cls in batch:
            if cls is None:
                self.streaks.pop(eid, None)          # a clean launch clears the streak
                continue
            self.last_error[eid] = err
            if cls == ENTRY_FAILURE:
                self.streaks[eid] = self.streaks.get(eid, 0) + 1
        if not trailing:
            return None
        # M3/item 24: the host's own words reach an operator's terminal and
        # whatever collects it, and the one message whose PURPOSE is to surface
        # an auth failure is the likeliest of all of them to be carrying a
        # credential ("Incorrect API key provided: sk-ant-...").
        return HOST_OUTAGE % (self.host, len(host), len(batch), HOST_FAILURE,
                              unlaunched, redact.redact(host[-1][1]), self.resume_command())

    def exhausted(self, pending, cap):
        """The `error` message for the first pending entry that has spent `cap`
        consecutive charged launches, or None. An entry the HOST failed never
        reaches it, because a host-class failure is never charged."""
        for entry in pending or ():
            eid = entry.get("id") if isinstance(entry, dict) else None
            if self.streaks.get(eid, 0) >= cap:
                # Redacted for the same reason the pause message is: this one
                # quotes a failure the HOST composed too, and it predates the
                # rule rather than being exempt from it.
                return ("driver loop: entry %s failed %d consecutive launches; last: %s"
                        % (eid, self.streaks[eid], redact.redact(self.last_error.get(eid))))
        return None

    def resume_command(self):
        """The command that resumes this run, composed by `runners/resume.py`
        -- which is where the flag table and the `sys.argv[0]` reading live
        since #1732 took this module past the package ceiling. Kept as a
        method because this object is what holds both inputs (the RESOLVED
        host, and the loop's own `args`) and because both pause messages above
        already call it."""
        return resume.command(self.host, self.args)
