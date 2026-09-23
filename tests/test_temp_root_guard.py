"""A checkout-backed temporary directory must be refused before test execution."""
import os
import subprocess
import sys

import pytest

from conftest import REPO_ROOT, _refuse_repository_temp_root


@pytest.mark.parametrize("metadata", ["directory", "gitfile"])
@pytest.mark.parametrize("option", ["TMPDIR", "--basetemp", "--basetemp=", "addopts"])
@pytest.mark.parametrize("alias", [False, True])
def test_startup_refuses_checkout_temp_before_sentinel(tmp_path, metadata, option, alias):
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    if metadata == "directory":
        (checkout / ".git").mkdir()
    else:
        (checkout / ".git").write_text("gitdir: /unused/worktree/metadata\n")
    nested = checkout / "temporary"
    nested.mkdir()
    selected = nested
    if alias:
        selected = tmp_path / "alias"
        selected.symlink_to(nested, target_is_directory=True)
    suite = tmp_path / "suite"
    suite.mkdir()
    sentinel = suite / "body-executed"
    (suite / "test_sentinel.py").write_text(
        "from pathlib import Path\ndef test_body():\n    Path(%r).write_text('ran')\n" % str(sentinel))
    env = dict(os.environ)
    env.pop("PYTEST_ADDOPTS", None)
    env["TMPDIR"] = str(tmp_path)
    env["TEMP"] = env["TMP"] = str(tmp_path)
    command = [sys.executable, "-m", "pytest", "-p", "tests.conftest", "-q", str(suite)]
    if option == "TMPDIR":
        env["TMPDIR"] = str(selected)
    elif option == "--basetemp":
        command.extend(["--basetemp", str(selected)])
    elif option == "--basetemp=":
        command.append("--basetemp=" + str(selected))
    else:
        import shlex
        env["PYTEST_ADDOPTS"] = "--basetemp=" + shlex.quote(str(selected))
    result = subprocess.run(command, cwd=REPO_ROOT, env=env, capture_output=True, text=True, timeout=30)
    assert result.returncode != 0
    assert "Use an external temp directory" in result.stdout + result.stderr
    assert not sentinel.exists()


def test_external_temp_root_is_permitted(tmp_path):
    _refuse_repository_temp_root(tmp_path / "not-created-yet", "fixture")
