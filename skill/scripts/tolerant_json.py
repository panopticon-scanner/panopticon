"""Bounded JSON-object extraction from markdown or prose-wrapped agent output."""

import json
import re


_SCAN_CANDIDATES = 256
# A short reply can spend a length-scaled budget on prose braces before reaching
# its verdict. This constant floor covers those wrappers; large inputs retain
# the linear multipliers below.
_SCAN_BUDGET_FLOOR = 64 * 1024
# #2959: the deepest an agent's or a scanner's JSON may nest. Every recursive
# walker downstream (redact_tree, the codec itself, schema repair) ran out of
# stack somewhere between 900 levels (3.11) and 100,000 (3.14), ending the run
# in a traceback; the deepest document this tree carries nests 13.
MAX_JSON_DEPTH = 64
_TOO_DEEP = "nested deeper than %d levels" % MAX_JSON_DEPTH
# A whole string (to its first unescaped quote), one bracket, or a LONE quote: a
# string that never closes. Without that last arm `finditer` stepped one
# character past an unterminated quote and every later `\"` opened a "string"
# that rescanned to the end -- quadratic on a truncated reply (#2959 review).
_DEPTH_TOKENS = re.compile(r'"[^"\\]*(?:\\.[^"\\]*)*"|[][{}"]', re.DOTALL)
_DEPTH_TOKENS_BYTES = re.compile(rb'"[^"\\]*(?:\\.[^"\\]*)*"|[][{}"]', re.DOTALL)


class TooDeep(json.JSONDecodeError):
    """The depth bound's refusal: a JSONDecodeError, which every reader already
    treats as a malformed document."""


def depth_checked(text):
    """`text` (str or bytes) itself, or `json.JSONDecodeError` when a bracket
    opens deeper than MAX_JSON_DEPTH -- counted outside strings, a string ending
    only at an unescaped quote. Iterative and linear, so it runs BEFORE any
    parse; the error is the one every caller already treats as malformed."""
    depth = 0
    tokens = (_DEPTH_TOKENS_BYTES if isinstance(text, bytes) else _DEPTH_TOKENS).finditer(text)
    for token in tokens:
        char = text[token.start():token.start() + 1]
        if char in ('"', b'"') and token.end() - token.start() == 1:
            break                  # unterminated: the rest is inside that string
        if char in ("[", "{", b"[", b"{"):
            depth += 1
            if depth > MAX_JSON_DEPTH:
                raise TooDeep(_TOO_DEEP, _as_text(text), token.start())
        elif char in ("]", "}", b"]", b"}"):
            depth = max(0, depth - 1)
    return text


def _as_text(text):
    """JSONDecodeError's document is a str, whatever the caller handed in."""
    return text.decode("utf-8", "replace") if isinstance(text, bytes) else text


def unparsed_reason(text):
    """Why `loads` could not read `text`, for a refusal line: the depth bound by
    name when it is the cause (#2959), else the two tolerant tries."""
    try:
        depth_checked(text)
    except TooDeep as exc:
        return exc.msg
    return "fence- and prose-wrapped both tried"


def first_balanced_object(body):
    """Return the first embedded object with bounded time and auxiliary memory.

    The single-pass fast path remembers a fixed number of spans. A globally
    budgeted replay preserves the tolerant pre-#2531 answer when prose quotes,
    many small spans, or nested non-JSON braces obscure the real object. Pure;
    never raises.
    """
    starts, spans = list[int](), list[tuple[int, int]]()
    in_str = esc = False
    overflow = 0
    for pos, char in enumerate(body):
        if in_str:
            if esc:
                esc = False
            elif char == "\\":
                esc = True
            elif char == '"':
                in_str = False
        elif char == '"':
            in_str = True
        elif char == "{":
            if overflow or len(starts) >= _SCAN_CANDIDATES:
                overflow += 1
            else:
                starts.append(pos)
        elif char == "}" and overflow:
            overflow -= 1
        elif char == "}" and starts:
            start = starts.pop()
            # A span that closes encloses every span recorded since it opened
            # -- a contiguous suffix, because spans land in closing order --
            # and a parent that parses supersedes its children, so they yield
            # their slots to it. Without this the OUTERMOST object, which
            # closes last, was the one the candidate cap dropped on any
            # document nesting more than _SCAN_CANDIDATES objects, and a
            # prose-wrapped setup proposal read as its first inner group
            # (tests/test_tolerant_json_outer_object.py).
            while spans and spans[-1][0] > start:
                spans.pop()
            if len(spans) < _SCAN_CANDIDATES:
                spans.append((start, pos + 1))
    budget = max(_SCAN_BUDGET_FLOOR, 2 * len(body))
    deep_until = 0      # #2959: no shallow object is dug out of a too-deep one
    for start, end in sorted(spans):
        size = end - start
        if size > budget or start < deep_until:
            continue
        budget -= size
        try:
            return json.loads(depth_checked(body[start:end]))
        except TooDeep:
            deep_until = end
        except (json.JSONDecodeError, RecursionError, MemoryError):
            pass
    # The replay also pays once for locating candidate starts. Keep that linear
    # pass and fixed candidate bookkeeping outside the 64 KiB scan floor.
    replay_budget, cursor, length = (
        max(_SCAN_BUDGET_FLOOR, 4 * len(body))
        + len(body) + 4 * _SCAN_CANDIDATES, 0, len(body))
    while replay_budget > 0:
        start = body.find("{", cursor)
        if start < 0:
            return None
        replay_budget -= start - cursor + 1
        depth, in_str, esc = 0, False, False
        for end in range(start, length):
            replay_budget -= 1
            if replay_budget < 0:
                return None
            char = body[end]
            if in_str:
                if esc:
                    esc = False
                elif char == "\\":
                    esc = True
                elif char == '"':
                    in_str = False
            elif char == '"':
                in_str = True
            elif char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(depth_checked(body[start:end + 1]))
                    except TooDeep:
                        cursor = end            # #2959: resume past it, never inside
                        break
                    except (json.JSONDecodeError, RecursionError, MemoryError):
                        break
        cursor = max(cursor, start) + 1
    return None


def loads(body):
    """Parse JSON after stripping fences and searching prose for an object."""
    body = body.strip()
    if body.startswith("```"):
        body = re.sub(r"^```[a-zA-Z]*\s*", "", body)
        body = re.sub(r"\s*```\s*$", "", body).strip()
    try:
        return json.loads(depth_checked(body))
    except json.JSONDecodeError as first_err:
        # #1058: narrative wrapping lost 8/79 advisor verdicts in run-5; three
        # repeated on retry, so it was prompt-induced rather than noise. The
        # bounded scanner accepts the first object despite prose braces at
        # either end. The greedy regex remains a last resort; a total miss is
        # still `unloadable` (#938).
        obj = first_balanced_object(body)
        if obj is not None:
            return obj
        match = re.search(r"(\{.*\})", body, re.DOTALL)
        if match:
            try:
                return json.loads(depth_checked(match.group(1)))
            except (json.JSONDecodeError, RecursionError, MemoryError):
                pass
        raise first_err
