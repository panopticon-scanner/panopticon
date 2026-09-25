"""Local-only pin PR lifecycle tests; gh is an injected inert runner."""
import json
from pathlib import Path
import subprocess
from types import SimpleNamespace

import pytest

from scripts import open_pin_pr as pin


BASE = """FROM scratch
ARG RUSTUP_VERSION=1.0.0
ARG RUSTUP_INIT_SHA256_AMD64={zero}
ARG RUSTUP_INIT_SHA256_ARM64={zero}
ARG TRIVY_VERSION=1.0.0
ARG TRIVY_SHA256_AMD64={zero}
ARG TRIVY_SHA256_ARM64={zero}
ARG RUST_TOOLCHAIN_VERSION=1.0.0
""".format(zero="0" * 64)


def git(cwd, *args):
    return subprocess.run(["git", *args], cwd=cwd, text=True, capture_output=True,
                          check=True).stdout


class FakeGh:
    def __init__(self):
        self.prs = []
        self.calls = []
        self.fail_create = False
        self.fail_lookup = False
        self.bad_response = False

    def __call__(self, command, cwd):
        self.calls.append(command)
        if command[:2] == ["gh", "api"]:
            if self.fail_lookup:
                return subprocess.CompletedProcess(command, 1, "", "lookup unavailable")
            return subprocess.CompletedProcess(command, 0,
                                               "{}" if self.bad_response else json.dumps(self.prs), "")
        assert command[:3] == ["gh", "pr", "create"]
        if self.fail_create:
            return subprocess.CompletedProcess(command, 1, "", "create unavailable")
        branch = command[command.index("--head") + 1]
        self.prs.append({"number": len(self.prs) + 1, "state": "open",
                         "head": {"ref": branch, "repo": {"full_name": "owner/repo"}},
                         "base": {"ref": "main", "repo": {"full_name": "owner/repo"}}})
        return subprocess.CompletedProcess(command, 0, "created", "")


def generated(family):
    version_arg, digest_args, _title, _body = pin.FAMILIES[family]
    text = BASE.replace("ARG %s=1.0.0" % version_arg,
                        "ARG %s=2.0.0" % version_arg)
    for name in digest_args:
        text = text.replace("ARG %s=%s" % (name, "0" * 64),
                            "ARG %s=%s" % (name, "a" * 64))
    return text


@pytest.fixture
def repo(tmp_path):
    remote = tmp_path / "remote.git"
    work = tmp_path / "work"
    git(tmp_path, "init", "--bare", str(remote))
    git(tmp_path, "init", "-b", "main", str(work))
    (work / "Dockerfile").write_text(BASE)
    git(work, "add", "Dockerfile")
    git(work, "-c", "user.name=fixture", "-c", "user.email=fixture@example.com",
        "commit", "-m", "base")
    git(work, "remote", "add", "origin", str(remote))
    git(work, "push", "origin", "main")
    return work


def test_failed_create_rerun_recovers_orphan_and_open_is_noop(repo):
    gh = FakeGh()
    (repo / "Dockerfile").write_text(generated("rustup"))
    gh.fail_create = True
    with pytest.raises(RuntimeError, match="PR creation failed"):
        pin.open_pin_pr("rustup", "owner/repo", cwd=repo, gh_runner=gh)
    assert git(repo, "ls-remote", "--heads", "origin", "refs/heads/chore/bump-rustup-2.0.0")
    assert not gh.prs

    git(repo, "checkout", "main")
    (repo / "Dockerfile").write_text(generated("rustup"))
    gh.fail_create = False
    assert pin.open_pin_pr("rustup", "owner/repo", cwd=repo, gh_runner=gh) == "created PR"
    assert len(gh.prs) == 1
    assert pin.open_pin_pr("rustup", "owner/repo", cwd=repo, gh_runner=gh) == "open PR already exists"
    assert len([c for c in gh.calls if c[:3] == ["gh", "pr", "create"]]) == 2


@pytest.mark.parametrize("family", list(pin.FAMILIES))
def test_each_family_metadata_and_workflow_wiring(repo, family):
    gh = FakeGh()
    (repo / "Dockerfile").write_text(generated(family))
    assert pin.open_pin_pr(family, "owner/repo", cwd=repo, gh_runner=gh) == "created PR"
    create = [c for c in gh.calls if c[:3] == ["gh", "pr", "create"]][0]
    assert create[create.index("--head") + 1] == "chore/bump-%s-2.0.0" % family
    assert create[create.index("--base") + 1] == "main"
    assert create[create.index("--repo") + 1] == "owner/repo"
    assert create[create.index("--label") + 1] == "dependencies"
    assert "2.0.0" in create[create.index("--title") + 1]
    assert "Review" in create[create.index("--body") + 1]
    workflow = (Path(__file__).parents[1] / ".github/workflows/pin-freshness.yml").read_text()
    assert "python3 scripts/open_pin_pr.py " + family in workflow
    matrix = (Path(__file__).parents[1] / "panopticon.yml").read_text()
    assert "- scripts/open_pin_pr.py" in matrix
    assert "- tests/test_pin_pr.py" in matrix


@pytest.mark.parametrize("failure", ["lookup", "response", "remote"])
def test_lookup_failure_is_not_absence(repo, failure):
    gh = FakeGh()
    (repo / "Dockerfile").write_text(generated("trivy"))
    if failure == "lookup":
        gh.fail_lookup = True
    elif failure == "response":
        gh.bad_response = True
    else:
        def fail_remote(command, cwd):
            if command[:2] == ["git", "ls-remote"]:
                return subprocess.CompletedProcess(command, 128, "", "network unavailable")
            return pin._run(command, cwd)
        with pytest.raises(RuntimeError, match="git failed"):
            pin.open_pin_pr("trivy", "owner/repo", cwd=repo, gh_runner=gh,
                            git_runner=fail_remote)
        return
    with pytest.raises(RuntimeError, match="gh failed|invalid PR lookup"):
        pin.open_pin_pr("trivy", "owner/repo", cwd=repo, gh_runner=gh)
    assert not git(repo, "ls-remote", "--heads", "origin", "refs/heads/chore/bump-trivy-2.0.0")


def test_orphan_with_unrelated_change_is_rejected(repo):
    gh = FakeGh()
    (repo / "Dockerfile").write_text(generated("trivy"))
    (repo / "unexpected").write_text("unrelated")
    git(repo, "checkout", "-b", "chore/bump-trivy-2.0.0")
    git(repo, "add", "Dockerfile", "unexpected")
    git(repo, "-c", "user.name=fixture", "-c", "user.email=fixture@example.com",
        "commit", "-m", "bad branch")
    git(repo, "push", "origin", "HEAD")
    git(repo, "checkout", "main")
    (repo / "Dockerfile").write_text(generated("trivy"))
    with pytest.raises(RuntimeError, match="orphan branch differs"):
        pin.open_pin_pr("trivy", "owner/repo", cwd=repo, gh_runner=gh)


def test_orphan_with_divergent_dockerfile_is_rejected(repo):
    gh = FakeGh()
    (repo / "Dockerfile").write_text(generated("rustup").replace("a" * 64, "b" * 64))
    git(repo, "checkout", "-b", "chore/bump-rustup-2.0.0")
    git(repo, "add", "Dockerfile")
    git(repo, "-c", "user.name=fixture", "-c", "user.email=fixture@example.com",
        "commit", "-m", "different digest")
    git(repo, "push", "origin", "HEAD")
    git(repo, "checkout", "main")
    (repo / "Dockerfile").write_text(generated("rustup"))
    with pytest.raises(RuntimeError, match="orphan branch differs"):
        pin.open_pin_pr("rustup", "owner/repo", cwd=repo, gh_runner=gh)


def test_create_race_accepts_only_exact_open_pr(repo):
    class RacingGh(FakeGh):
        def __call__(self, command, cwd):
            if command[:3] == ["gh", "pr", "create"]:
                self.prs.append({"number": 9, "state": "open",
                                 "head": {"ref": "chore/bump-trivy-2.0.0",
                                          "repo": {"full_name": "owner/repo"}},
                                 "base": {"ref": "main", "repo": {"full_name": "owner/repo"}}})
                self.calls.append(command)
                return subprocess.CompletedProcess(command, 1, "", "already exists")
            return super().__call__(command, cwd)

    gh = RacingGh()
    (repo / "Dockerfile").write_text(generated("trivy"))
    assert pin.open_pin_pr("trivy", "owner/repo", cwd=repo, gh_runner=gh) == "open PR appeared during creation"
    assert len(gh.prs) == 1


def _make_orphan_then_advance_main(repo, family, *, dockerfile_drift=False):
    (repo / "Dockerfile").write_text(generated(family))
    git(repo, "checkout", "-b", "chore/bump-%s-2.0.0" % family)
    git(repo, "add", "Dockerfile")
    git(repo, "-c", "user.name=fixture", "-c", "user.email=fixture@example.com",
        "commit", "-m", "pin bump")
    git(repo, "push", "origin", "HEAD")
    git(repo, "checkout", "main")
    (repo / "notes.txt").write_text("new unrelated main change\n")
    if dockerfile_drift:
        (repo / "Dockerfile").write_text(BASE + "# later Dockerfile change\n")
    git(repo, "add", ".")
    git(repo, "-c", "user.name=fixture", "-c", "user.email=fixture@example.com",
        "commit", "-m", "advance main")
    git(repo, "push", "origin", "main")
    (repo / "Dockerfile").write_text(generated(family)
                                    + ("# later Dockerfile change\n" if dockerfile_drift else ""))


def test_orphan_recovers_after_unrelated_main_advance(repo):
    _make_orphan_then_advance_main(repo, "rust-toolchain")
    assert pin.open_pin_pr("rust-toolchain", "owner/repo", cwd=repo,
                           gh_runner=FakeGh()) == "created PR"


def test_orphan_refuses_after_dockerfile_drift_on_main(repo):
    _make_orphan_then_advance_main(repo, "rust-toolchain", dockerfile_drift=True)
    with pytest.raises(RuntimeError, match="orphan branch differs"):
        pin.open_pin_pr("rust-toolchain", "owner/repo", cwd=repo,
                        gh_runner=FakeGh())


def test_depth_one_checkout_recovers_after_unrelated_main_advance(repo, tmp_path):
    _make_orphan_then_advance_main(repo, "rust-toolchain")
    remote = git(repo, "remote", "get-url", "origin").strip()
    shallow = tmp_path / "shallow"
    git(tmp_path, "clone", "--depth", "1", "--branch", "main",
        Path(remote).as_uri(), str(shallow))
    assert git(shallow, "rev-parse", "--is-shallow-repository").strip() == "true"
    (shallow / "Dockerfile").write_text(generated("rust-toolchain"))
    gh = FakeGh()
    assert pin.open_pin_pr("rust-toolchain", "owner/repo", cwd=shallow,
                           gh_runner=gh) == "created PR"
    assert len(gh.prs) == 1


@pytest.mark.parametrize("unsafe", ["dockerfile-drift", "unrelated-branch-file"])
def test_depth_one_checkout_refuses_unsafe_orphan(repo, tmp_path, unsafe):
    if unsafe == "dockerfile-drift":
        _make_orphan_then_advance_main(repo, "rust-toolchain", dockerfile_drift=True)
    else:
        (repo / "Dockerfile").write_text(generated("rust-toolchain"))
        (repo / "unexpected.txt").write_text("unrelated branch edit\n")
        git(repo, "checkout", "-b", "chore/bump-rust-toolchain-2.0.0")
        git(repo, "add", "Dockerfile", "unexpected.txt")
        git(repo, "-c", "user.name=fixture", "-c", "user.email=fixture@example.com",
            "commit", "-m", "bad pin branch")
        git(repo, "push", "origin", "HEAD")
        git(repo, "checkout", "main")
        (repo / "notes.txt").write_text("later main edit\n")
        git(repo, "add", "notes.txt")
        git(repo, "-c", "user.name=fixture", "-c", "user.email=fixture@example.com",
            "commit", "-m", "advance main")
        git(repo, "push", "origin", "main")
    remote = git(repo, "remote", "get-url", "origin").strip()
    shallow = tmp_path / "shallow"
    git(tmp_path, "clone", "--depth", "1", "--branch", "main",
        Path(remote).as_uri(), str(shallow))
    (shallow / "Dockerfile").write_text(generated("rust-toolchain")
                                     + ("# later Dockerfile change\n"
                                        if unsafe == "dockerfile-drift" else ""))
    gh = FakeGh()
    before = git(shallow, "ls-remote", "--heads", "origin",
                 "refs/heads/chore/bump-rust-toolchain-2.0.0")
    with pytest.raises(RuntimeError, match="orphan branch differs"):
        pin.open_pin_pr("rust-toolchain", "owner/repo", cwd=shallow, gh_runner=gh)
    assert git(shallow, "ls-remote", "--heads", "origin",
               "refs/heads/chore/bump-rust-toolchain-2.0.0") == before
    assert not gh.prs


def test_feature_checkout_cannot_publish_unrelated_commit(repo):
    git(repo, "checkout", "-b", "feature")
    (repo / "unrelated.txt").write_text("feature change\n")
    git(repo, "add", "unrelated.txt")
    git(repo, "-c", "user.name=fixture", "-c", "user.email=fixture@example.com",
        "commit", "-m", "unrelated change")
    (repo / "Dockerfile").write_text(generated("trivy"))
    gh = FakeGh()
    with pytest.raises(RuntimeError, match="current main"):
        pin.open_pin_pr("trivy", "owner/repo", cwd=repo, gh_runner=gh)
    assert not git(repo, "ls-remote", "--heads", "origin", "refs/heads/chore/bump-trivy-2.0.0")
    assert not gh.prs


def test_feature_based_orphan_is_neither_adopted_nor_rewritten(repo):
    git(repo, "checkout", "-b", "feature")
    (repo / "unrelated.txt").write_text("feature change\n")
    git(repo, "add", "unrelated.txt")
    git(repo, "-c", "user.name=fixture", "-c", "user.email=fixture@example.com",
        "commit", "-m", "unrelated change")
    (repo / "Dockerfile").write_text(generated("trivy"))
    git(repo, "checkout", "-b", "chore/bump-trivy-2.0.0")
    git(repo, "add", "Dockerfile")
    git(repo, "-c", "user.name=fixture", "-c", "user.email=fixture@example.com",
        "commit", "-m", "feature based pin")
    git(repo, "push", "origin", "HEAD")
    before = git(repo, "ls-remote", "--heads", "origin", "refs/heads/chore/bump-trivy-2.0.0")
    git(repo, "checkout", "main")
    (repo / "Dockerfile").write_text(generated("trivy"))
    gh = FakeGh()
    with pytest.raises(RuntimeError, match="ancestor of current main"):
        pin.open_pin_pr("trivy", "owner/repo", cwd=repo, gh_runner=gh)
    assert git(repo, "ls-remote", "--heads", "origin", "refs/heads/chore/bump-trivy-2.0.0") == before
    assert not gh.prs


def test_closed_pr_requires_manual_recovery(repo):
    gh = FakeGh()
    (repo / "Dockerfile").write_text(generated("rust-toolchain"))
    gh.prs.append({"number": 4, "state": "closed",
                   "head": {"ref": "chore/bump-rust-toolchain-2.0.0",
                            "repo": {"full_name": "owner/repo"}},
                   "base": {"ref": "main", "repo": {"full_name": "owner/repo"}}})
    with pytest.raises(RuntimeError, match="closed or merged"):
        pin.open_pin_pr("rust-toolchain", "owner/repo", cwd=repo, gh_runner=gh)


def test_malformed_pr_entry_fails_closed(repo):
    gh = FakeGh()
    (repo / "Dockerfile").write_text(generated("rustup"))
    gh.prs.append({"number": 3, "state": "open",
                   "head": {"ref": "chore/bump-rustup-2.0.0", "repo": None},
                   "base": {"ref": "main", "repo": {"full_name": "owner/repo"}}})
    with pytest.raises(RuntimeError, match="invalid PR lookup response"):
        pin.open_pin_pr("rustup", "owner/repo", cwd=repo, gh_runner=gh)


@pytest.mark.parametrize("extra", ["RUN echo surprise\n", "ARG RUSTUP_VERSION=bad\n"])
def test_invalid_generated_change_is_rejected(repo, extra):
    (repo / "Dockerfile").write_text(generated("rustup") + extra)
    with pytest.raises(RuntimeError, match="generated Dockerfile|invalid or duplicate"):
        pin.open_pin_pr("rustup", "owner/repo", cwd=repo, gh_runner=FakeGh())


def test_default_runner_ignores_repository_path_and_bounds_git(repo, monkeypatch):
    hostile = repo / "git"
    hostile.write_text("#!/bin/sh\nexit 99\n")
    hostile.chmod(0o755)
    monkeypatch.setenv("PATH", str(repo) + ":/usr/bin:/bin")
    monkeypatch.setenv("PYTHONPATH", str(repo))
    monkeypatch.setenv("LD_PRELOAD", str(hostile))
    seen = []

    def fake_run(argv, **kwargs):
        seen.append((argv, kwargs))
        return subprocess.CompletedProcess(argv, 0, "safe", "")

    monkeypatch.setattr(pin.subprocess, "run", fake_run)
    assert pin._run(["git", "status", "--porcelain", "--untracked-files=normal"], repo).stdout == "safe"
    argv, kwargs = seen[0]
    assert argv[0] != str(hostile)
    assert Path(argv[0]).is_absolute()
    assert str(repo) not in kwargs["env"]["PATH"]
    assert "PYTHONPATH" not in kwargs["env"]
    assert "LD_PRELOAD" not in kwargs["env"]
    assert kwargs["timeout"] == pin.PROCESS_TIMEOUT
    assert kwargs["cwd"] == repo


def test_default_runner_keeps_gh_token_with_trusted_binary(repo, monkeypatch):
    monkeypatch.setenv("GH_TOKEN", "inert-test-token")
    monkeypatch.setenv("GH_CONFIG_DIR", str(repo / "wrong-account"))
    monkeypatch.setattr(pin, "resolve", lambda program, cwd, path: SimpleNamespace(
        path="/usr/bin/gh", path_env="/usr/bin:/bin"))
    seen = []

    def fake_run(argv, **kwargs):
        seen.append((argv, kwargs))
        return subprocess.CompletedProcess(argv, 0, "[]", "")

    monkeypatch.setattr(pin.subprocess, "run", fake_run)
    query = "repos/owner/repo/pulls?state=all&base=main&head=owner%3Achore%2Fbump-trivy-2.0.0&per_page=100"
    result = pin._run(["gh", "api", query], repo)
    assert result.stdout == "[]"
    argv, kwargs = seen[0]
    assert argv == ["/usr/bin/gh", "api", query]
    assert kwargs["env"]["GH_TOKEN"] == "inert-test-token"
    assert "GH_CONFIG_DIR" not in kwargs["env"]
    assert kwargs["timeout"] == pin.PROCESS_TIMEOUT


@pytest.mark.parametrize("command", [
    ["sh", "-c", "evil"], ["git", "-c", "core.hooksPath=evil", "status"],
    ["gh", "pr", "merge", "1"], ["gh", "auth", "login"],
])
def test_default_runner_rejects_unexpected_executable_or_verb(repo, monkeypatch, command):
    monkeypatch.setattr(pin, "resolve", lambda *_args, **_kwargs: pytest.fail(
        "unexpected command reached executable resolution"))
    with pytest.raises(RuntimeError, match="unexpected"):
        pin._run(command, repo)


def test_default_runner_timeout_is_a_named_failure(repo, monkeypatch):
    monkeypatch.setattr(pin, "resolve", lambda program, cwd, path: SimpleNamespace(
        path="/usr/bin/git", path_env="/usr/bin:/bin"))

    def expire(argv, **kwargs):
        raise subprocess.TimeoutExpired(argv, kwargs["timeout"])

    monkeypatch.setattr(pin.subprocess, "run", expire)
    with pytest.raises(RuntimeError, match="git timed out"):
        pin._run(["git", "status", "--porcelain", "--untracked-files=normal"], repo)
