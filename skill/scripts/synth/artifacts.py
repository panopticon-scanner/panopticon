"""Bound untrusted run-metadata reads before JSON decoding or field repair.

The default is 16 MiB per artifact; callers may retain a smaller existing cap.
Only regular files are read. The final path component cannot be a symlink;
parent aliases such as macOS /var are allowed. This is not directory confinement.
Callers still own absent/corrupt distinctions, shape validation and gate policy.
"""
import json
import os
import stat
import sys
from typing import Any

import scripts.evidence as evidence_mod

MAX_JSON_BYTES = 16 * 1024 * 1024


def _read_json(path, limit, tolerant):
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError("not a regular file")
        with os.fdopen(fd, "rb") as stream:
            fd = -1  # the stream owns the descriptor from here
            raw = stream.read(limit + 1)
    finally:
        if fd >= 0:
            os.close(fd)
    # Bound the actual read, never trust a preliminary stat size.
    if len(raw) > limit:
        raise ValueError("over the %d-byte read limit; skipped unparsed" % limit)
    text = raw.decode("utf-8")
    return evidence_mod.load_json_tolerant(text) if tolerant else json.loads(text)


def read_json(path, *, limit=None, tolerant=False, announce=False) -> Any:
    """Read JSON or raise OSError/ValueError, including parser resource errors.

    Strict JSON remains the default. Only existing agent-envelope readers opt
    into markdown/prose tolerance. With announce=True, rejected present inputs
    get one stderr diagnostic; an optional missing file remains quiet. Callers
    already publishing a reason keep announce=False to avoid duplicate messages.
    """
    if limit is None:
        limit = MAX_JSON_BYTES
    if type(limit) is not int or limit <= 0:
        raise ValueError("artifact read limit must be a positive integer")
    try:
        return _read_json(path, limit, tolerant)
    except (OSError, ValueError, RecursionError, MemoryError) as exc:
        error = exc
        if isinstance(exc, (RecursionError, MemoryError)):
            error = ValueError("%s: %s" % (type(exc).__name__, str(exc) or "cannot parse artifact"))
        if announce and not isinstance(exc, FileNotFoundError):
            print("synthesize: artifact %r could not be read (%s); ignoring"
                  % (os.fspath(path), error), file=sys.stderr)
        if error is exc:
            raise
        raise error from exc
