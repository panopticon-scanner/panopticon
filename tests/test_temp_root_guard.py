"""A checkout-backed temporary directory must be refused before collection."""
import os
import shlex
import subprocess
import sys
import tomllib

import pytest

from tests._test_helpers import REPO_ROOT


def _child_import_roots():
    with open(os.path.join(REPO_ROOT, "pyproject.toml"), "rb") as stream:
        roots = tomllib.load(stream)["tool"]["pytest"]["ini_options"]["pythonpath"]
    return os.pathsep.join(os.path.join(REPO_ROOT, root) for root in roots)


def _run_startup_fixture(tmp_path, metadata, option, alias, unsafe=True,
                         forbid_home_allocation=False):
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    if metadata == "directory":
        (checkout / ".git").mkdir()
    else:
        (checkout / ".git").write_text("gitdir: /unused/worktree/metadata\n")
    selected = checkout / "temporary" if unsafe else tmp_path / "external-temporary"
    selected.mkdir()
    if alias:
        link = tmp_path / "alias"
        link.symlink_to(selected, target_is_directory=True)
        selected = link
    suite = tmp_path / "suite"
    suite.mkdir()
    sentinel = suite / "body-executed"
    collected = suite / "collection-executed"
    (suite / "test_sentinel.py").write_text(
        "from pathlib import Path\nPath(%r).write_text('collected')\n"
        "def test_body():\n    Path(%r).write_text('ran')\n" % (str(collected), str(sentinel)))
    env = dict(os.environ)
    env.pop("PYTEST_ADDOPTS", None)
    # -c replaces the repository config, and -p loads before collection.
    env["PYTHONPATH"] = _child_import_roots()
    env["TMPDIR"] = str(tmp_path)
    env["TEMP"] = env["TMP"] = str(tmp_path)
    arguments = ["-p", "tests.conftest", "-q", str(suite)]
    if option == "TMPDIR":
        env["TMPDIR"] = str(selected)
    elif option in ("--basetemp", "programmatic"):
        arguments.extend(["--basetemp", str(selected)])
    elif option == "--basetemp=":
        arguments.append("--basetemp=" + str(selected))
    elif option == "config-file":
        config = suite / "pytest.ini"
        config.write_text("[pytest]\naddopts = --basetemp=" + shlex.quote(str(selected)) + "\n")
        arguments.extend(["-c", str(config)])
    else:
        env["PYTEST_ADDOPTS"] = "--basetemp=" + shlex.quote(str(selected))
    if forbid_home_allocation:
        # The import-time TMPDIR check must run before any plugin HOME setup.
        # Parsed basetemp refusal is a later pytest_configure contract.
        assert unsafe and option == "TMPDIR"
        env.pop("PANOPTICON_TEST_HOME", None)
        prelude = ("import tempfile\n"
                   "def forbidden(*args, **kwargs):\n"
                   "    raise AssertionError('HOME allocation preceded temp-root refusal')\n"
                   "tempfile.mkdtemp = forbidden\n")
        command = [sys.executable, "-c", prelude +
                   "import pytest; raise SystemExit(pytest.main(%r))" % arguments]
    elif option == "programmatic":
        # No basetemp option is directly present in sys.argv or PYTEST_ADDOPTS.
        command = [sys.executable, "-c",
                   "import pytest; raise SystemExit(pytest.main(%r))" % arguments]
    else:
        command = [sys.executable, "-m", "pytest", *arguments]
    result = subprocess.run(command, cwd=suite, env=env, capture_output=True, text=True, timeout=30)
    return result, collected, sentinel


@pytest.mark.parametrize("metadata", ["directory", "gitfile"])
@pytest.mark.parametrize("option", ["TMPDIR", "--basetemp", "--basetemp=", "addopts", "config-file", "programmatic"])
@pytest.mark.parametrize("alias", [False, True])
def test_startup_refuses_checkout_temp_before_sentinel(tmp_path, metadata, option, alias):
    result, collected, sentinel = _run_startup_fixture(tmp_path, metadata, option, alias)
    assert result.returncode != 0
    assert "Use an external temp directory" in result.stdout + result.stderr
    assert not collected.exists()
    assert not sentinel.exists()


@pytest.mark.parametrize("option", ["TMPDIR", "--basetemp", "config-file", "programmatic"])
def test_external_temp_root_runs_real_conftest_and_sentinel(tmp_path, option):
    result, collected, sentinel = _run_startup_fixture(tmp_path, "directory", option, False, unsafe=False)
    assert result.returncode == 0, result.stdout + result.stderr
    assert collected.read_text() == "collected"
    assert sentinel.read_text() == "ran"


def test_unsafe_tmpdir_refusal_precedes_home_allocation(tmp_path):
    result, collected, sentinel = _run_startup_fixture(
        tmp_path, "directory", "TMPDIR", False, forbid_home_allocation=True)
    assert result.returncode != 0
    output = result.stdout + result.stderr
    assert "Use an external temp directory" in output
    assert "HOME allocation preceded temp-root refusal" not in output
    assert not collected.exists()
    assert not sentinel.exists()
