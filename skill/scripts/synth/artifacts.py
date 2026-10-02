"""Bound untrusted run-metadata reads before JSON decoding or field repair.

The 16 MiB default is the broadest read class: run metadata can aggregate many
rows, while one advisor verdict is capped at 8 MiB and one source or digest read
at 4 MiB. Callers may retain a smaller cap. Only regular files are read. The
final path component cannot be a symlink; parent aliases such as macOS /var are
allowed. This is not directory confinement. Callers still own absent/corrupt
distinctions, shape validation and gate policy.
"""
import json
import os
import sys
from typing import Any

import scripts.evidence as evidence_mod
import scripts.safe_write as safe_write

MAX_JSON_BYTES = 16 * 1024 * 1024


def _read_json(path, limit, tolerant):
    text = safe_write.read_regular_bytes(path, limit).decode("utf-8")
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


read_failure_reason = safe_write.read_failure_reason
