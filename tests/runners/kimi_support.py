import contextlib
import json
import os
import tempfile
from unittest import mock

from tests._test_helpers import kimi_entry

STREAM = "\n".join([
    json.dumps({"role": "meta", "type": "system.version", "version": "0.42.0"}),
    json.dumps({"role": "assistant", "content": "intermediate thought"}),
    json.dumps({"role": "tool", "tool_call_id": "t1", "content": "file contents"}),
    json.dumps({"role": "assistant", "content": "the final reply"}),
    json.dumps({"role": "meta", "type": "session.resume_hint",
                "session_id": "session_test-1", "command": "kimi -r session_test-1"}),
])
CONFIGURED = frozenset({"kimi-code/k3", "kimi-code/kimi-for-coding"})


def _entry(enforced, model="secondary"):
    return kimi_entry(enforced, model=model)


@contextlib.contextmanager
def _narrowed_temp_root():
    """Yield (root, outside): a directory the runner will treat as THE temp
    root, and a sibling that is therefore outside it.

    Both are real temp directories -- tests write nowhere else -- but the
    runner's idea of the root is narrowed to the first, so a path can be
    prefix-matching and still outside the root. That combination is what the
    root half of `is_temp_home` exists for, and there is no other way to build
    it without writing outside the temp directory the test owns.
    """
    with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as outside:
        with mock.patch.object(tempfile, "gettempdir", return_value=root), \
             mock.patch.dict(os.environ):
            os.environ.pop("XDG_RUNTIME_DIR", None)
            yield root, outside
