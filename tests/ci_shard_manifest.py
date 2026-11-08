"""pytest plugin: record which tests one CI job collected and ran (#2933 phase 2).

Loaded only by CI, as `-p tests.ci_shard_manifest --shard-manifest PATH`.
Nothing else loads it, and without `--shard-manifest` every hook returns
before touching anything, so the local suite and the forge legs are unaffected
(tests/test_ci_shards.py pins both).

The manifest it writes is a JSON object:
- `python`: the interpreter's "major.minor";
- `args`: the pytest arguments, so a failing check can name the job;
- `collected`: every node id BEFORE any deselection, recorded first thing in
  `pytest_collection_modifyitems`, ahead of the `-m` filter and pytest-split;
- `selected`: what the job then ran, `session.items` at collection finish.

`devtools/ci_shards.py check` reads every job's manifest and proves each
collected test ran exactly once per version.

Under xdist the controller collects nothing and every worker collects the same
items (xdist refuses to run otherwise), so only worker `gw0` writes.
"""
import json
import sys

import pytest

_COLLECTED = "_ci_shard_manifest_collected"


def pytest_addoption(parser):
    parser.getgroup("ci-shards").addoption(
        "--shard-manifest", default=None, metavar="PATH",
        help="CI only (#2933): write this job's collected and selected node ids to PATH")


def _manifest_path(config):
    """Where this process writes, or None when it must not."""
    path = config.getoption("shard_manifest", default=None)
    if not path:
        return None
    worker = getattr(config, "workerinput", None)
    if worker is not None:
        return path if worker.get("workerid") == "gw0" else None
    if config.pluginmanager.has_plugin("dsession"):
        return None   # the xdist controller: its workers hold the items
    return path


@pytest.hookimpl(tryfirst=True)
def pytest_collection_modifyitems(session, config, items):
    if _manifest_path(config):
        setattr(config, _COLLECTED, [item.nodeid for item in items])


def pytest_collection_finish(session):
    path = _manifest_path(session.config)
    if not path:
        return
    manifest = {
        "python": "%d.%d" % sys.version_info[:2],
        "args": [str(a) for a in session.config.invocation_params.args],
        "collected": getattr(session.config, _COLLECTED, []),
        "selected": [item.nodeid for item in session.items],
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh)
