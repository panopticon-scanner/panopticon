"""Bounded JSON-object extraction from markdown or prose-wrapped agent output."""

import json
import re


_SCAN_CANDIDATES = 256
# A short reply can spend a length-scaled budget on prose braces before reaching
# its verdict. This constant floor covers those wrappers; large inputs retain
# the linear multipliers below.
_SCAN_BUDGET_FLOOR = 64 * 1024


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
            if len(spans) < _SCAN_CANDIDATES:
                spans.append((start, pos + 1))
    budget = max(_SCAN_BUDGET_FLOOR, 2 * len(body))
    for start, end in sorted(spans):
        size = end - start
        if size > budget:
            continue
        budget -= size
        try:
            return json.loads(body[start:end])
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
                        return json.loads(body[start:end + 1])
                    except (json.JSONDecodeError, RecursionError, MemoryError):
                        break
        cursor = start + 1
    return None


def loads(body):
    """Parse JSON after stripping fences and searching prose for an object."""
    body = body.strip()
    if body.startswith("```"):
        body = re.sub(r"^```[a-zA-Z]*\s*", "", body)
        body = re.sub(r"\s*```\s*$", "", body).strip()
    try:
        return json.loads(body)
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
                return json.loads(match.group(1))
            except (json.JSONDecodeError, RecursionError, MemoryError):
                pass
        raise first_err
