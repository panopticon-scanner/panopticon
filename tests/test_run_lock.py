"""#3779 part 1: one driver at a time on a review root."""
import contextlib
import errno
import fcntl
import json
import os
import signal
import socket
import sys
import threading
from unittest import mock

import pytest

import scripts.driver as driver
import scripts.orchestrate as orchestrate
import scripts.run_lock as run_lock
import scripts.run_manifest as run_manifest
from scripts.phases import child, engine, runio, setup
from tests._test_helpers import adopt_panopticon, dead_pid, our_manifest
from tests.tools.git_repo import make_git_repo

SKILL = os.path.dirname(os.path.dirname(os.path.abspath(run_lock.__file__)))
BOOTSTRAP = os.path.join(SKILL, "scripts", "_bootstrap.py")
REFUSAL = "review root"          # every refusal names what is held


def _record(**fields):
    return dict({"pid": os.getpid(), "verb": "loop", "since": "2026-11-23T04:00:12Z",
                 "host": run_lock.socket.gethostname()}, **fields)


@contextlib.contextmanager
def _another_driver(root, record=None, text=None):
    """What a second process holding `root` is on disk: its own open of the lock
    file, locked, with whatever it wrote there."""
    path = run_lock.lock_path(root)
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        os.ftruncate(fd, 0)
        if text is None:
            text = json.dumps(_record() if record is None else record)
        os.pwrite(fd, text if isinstance(text, bytes) else text.encode(), 0)
        yield fd
    finally:
        os.close(fd)


def _free(root):
    """Whether a process that is not this driver could take `root` now."""
    try:
        with _another_driver(root):
            return True
    except BlockingIOError:
        return False


def _tree(root):
    """Every path under `root` with its bytes or link target: what a refused verb may
    not change."""
    seen = {}
    for folder, dirs, files in os.walk(root):
        dirs[:] = [name for name in dirs if name != ".git"]
        for name in dirs + files:
            path = os.path.join(folder, name)
            if os.path.islink(path):
                seen[path] = "-> " + os.readlink(path)
            elif os.path.isfile(path):
                with open(path, "rb") as fh:
                    seen[path] = fh.read()
            else:
                seen[path] = None
    return seen


@pytest.fixture
def root(tmp_path, monkeypatch):
    path = make_git_repo(tmp_path=tmp_path / "target")
    monkeypatch.chdir(path)
    monkeypatch.setattr(driver, "_establish_host_posture", lambda *args: None)
    return path


def _a_run_in_flight(root):
    """A run of ours with a run folder and a durable report: what `--reset` deletes."""
    adopt_panopticon(root)
    manifest = run_manifest.build_manifest(
        target=root, review_root=root, host="codex", security_mode="standard",
        flags={"tools": False}, scope={"mode": "repo", "target": None})
    run_manifest.write_manifest(root, our_manifest(root, manifest))
    for path, text in ((runio._pano(root, "groups.json"), '{"mode": "repo", "groups": []}'),
                       (runio._report_out(root), '{"summary": {"gate": "PASS"}}')):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
    return manifest


def _run(root, *flags, phases=()):
    args = driver.parse_cli(["run", root, "--host", "codex", "--no-tools", *flags])
    return driver.run(args, phases=phases)


def _says(root):
    with open(run_lock.lock_path(root), encoding="utf-8") as fh:
        return json.load(fh)["verb"]


def _held_inside(root, seen):
    """A phase that records whether the root was free while it ran, and for which verb."""
    def execute(review_root, manifest):
        seen.append((_free(root), _says(root)))
        return engine.PhaseResult(kind="advanced", message="looked")
    return engine.Phase("look", "deterministic", lambda *_: bool(seen), execute)


# ---- the lock itself ---------------------------------------------------------------

def test_a_root_is_held_until_the_holder_lets_go(root):
    assert _free(root)
    with run_lock.hold(root, "run"):
        assert not _free(root)
    assert _free(root)


def test_a_root_is_let_go_when_the_holder_fails(root):
    with pytest.raises(RuntimeError):
        with run_lock.hold(root, "run"):
            raise RuntimeError("the verb died")
    assert _free(root)


def test_a_second_hold_in_one_process_passes_and_the_first_still_holds(root):
    with run_lock.hold(root, "loop"):
        with run_lock.hold(root, "run"):
            assert not _free(root)
        assert not _free(root)            # the inner exit did not let the root go
    assert _free(root)


def test_a_held_root_refuses_the_next_driver_and_says_who_holds_it(root):
    with _another_driver(root, _record(pid=os.getpid(), verb="loop")):
        with pytest.raises(run_lock.Refused) as refused:
            with run_lock.hold(root, "run"):
                pytest.fail("the root was held twice")
    assert str(refused.value) == (
        "another driver is running on this review root (pid %d, `driver loop`, since "
        "2026-11-23T04:00:12Z): wait for it to finish, or stop it, then run again" % os.getpid())
    assert _free(root)                    # a refusal holds nothing


def test_each_root_has_its_own_lock_and_a_link_to_a_root_shares_it(root, tmp_path):
    other = make_git_repo(tmp_path=tmp_path / "other")
    link = tmp_path / "link"
    link.symlink_to(root)
    assert run_lock.lock_path(other) != run_lock.lock_path(root)
    assert run_lock.lock_path(str(link)) == run_lock.lock_path(root)
    with run_lock.hold(root, "run"):
        assert _free(other)
        assert not _free(str(link))
        with run_lock.hold(other, "run"):
            assert not _free(other)
        assert _free(other)
        assert not _free(root)
    with run_lock.hold(str(link), "run"):
        assert not _free(root)


def test_the_lock_is_named_for_the_directory_itself_not_for_a_spelling_of_it(root):
    """Device and inode: one directory has one lock, however its path is typed."""
    info = os.stat(root)
    assert os.path.basename(run_lock.lock_path(root)) == "%x-%x.lock" % (info.st_dev, info.st_ino)
    assert run_lock.lock_path(root + os.sep + ".") == run_lock.lock_path(root)
    assert run_lock.lock_path(os.path.join(root, os.pardir, os.path.basename(root))) == \
        run_lock.lock_path(root)


def test_a_root_typed_in_another_case_is_the_same_root(tmp_path, monkeypatch):
    """A non-git root on a case-insensitive volume: `nongit/Proj` and `NONGIT/proj` are
    one `.panopticon/`, and were two lock names by path (seat review of #3782)."""
    typed = tmp_path / "nongit" / "Proj"
    typed.mkdir(parents=True)
    other = str(tmp_path / "NONGIT" / "proj")
    if not os.path.isdir(other):
        pytest.skip("this volume tells the two spellings apart")
    assert os.path.realpath(other) != os.path.realpath(str(typed))    # resolving keeps the case
    assert run_lock.lock_path(other) == run_lock.lock_path(str(typed))
    monkeypatch.setattr(driver, "_establish_host_posture", lambda *args: None)
    with _another_driver(str(typed)):
        assert not _free(other)
        status = _run(other)
    assert status["status"] == "error"
    assert status["message"].startswith("another driver is running on this review root (pid ")
    assert not os.path.lexists(os.path.join(other, ".panopticon"))


def test_a_root_that_cannot_be_looked_at_is_refused_and_no_child_is_handed_anything(tmp_path):
    gone = str(tmp_path / "no-such-root")
    with pytest.raises(run_lock.Refused) as refused:
        with run_lock.hold(gone, "run"):
            pytest.fail("held a root that is not there")
    assert str(refused.value).startswith(
        "the review root cannot be locked: %s: No such file or directory" % gone)
    assert run_lock.descriptor(gone) is None
    run_lock.note_child(gone, 4242, "tools")          # says nothing, raises nothing


def test_the_lock_is_kept_in_the_state_directory_and_not_in_the_tree(root):
    before = _tree(root)
    with run_lock.hold(root, "run"):
        assert _tree(root) == before
    path = run_lock.lock_path(root)
    assert os.path.dirname(path) == os.path.join(run_lock.run_stamp.state_dir(), "locks")
    assert not os.path.commonpath([path, os.path.realpath(root)]) == os.path.realpath(root)
    assert os.stat(os.path.dirname(path)).st_mode & 0o777 == 0o700
    assert os.stat(path).st_mode & 0o777 == 0o600


def test_the_holder_says_who_it_is_while_it_holds_and_nothing_afterwards(root):
    with run_lock.hold(root, "setup"):
        with open(run_lock.lock_path(root), encoding="utf-8") as fh:
            said = json.load(fh)
        assert said["pid"] == os.getpid()
        assert said["verb"] == "setup"
        assert said["host"] == run_lock.socket.gethostname()
        assert run_lock._SINCE.fullmatch(said["since"])
        assert sorted(said) == ["host", "pid", "since", "verb"]       # no path: nothing reads one
    assert os.path.getsize(run_lock.lock_path(root)) == 0


def test_the_record_is_one_write_of_one_size_so_a_reader_never_sees_part_of_one(root):
    """The next driver may read while the holder writes. A record replaced by truncating
    and then writing showed it an empty file, and so the fallback wording."""
    sizes = []
    with run_lock.hold(root, "loop"):
        with mock.patch.object(run_lock.os, "ftruncate") as truncate, \
                mock.patch.object(run_lock.os, "pwrite", wraps=os.pwrite) as write:
            for pid, phase in ((4242, "synthesize"), (None, None), (7, "tools"), (None, None)):
                run_lock.note_child(root, pid, phase)
                sizes.append(os.path.getsize(run_lock.lock_path(root)))
                with open(run_lock.lock_path(root), encoding="utf-8") as fh:
                    assert json.load(fh).get("child") == (
                        {"pid": pid, "phase": phase} if pid else None)
        assert not truncate.called
        assert [len(call.args[1]) for call in write.call_args_list] == [run_lock._RECORD_SIZE] * 4
        assert all(call.args[2] == 0 for call in write.call_args_list)
    assert sizes == [run_lock._RECORD_SIZE] * 4
    assert run_lock._RECORD_SIZE <= run_lock._RECORD_MAX


def _host_filling(room):
    """A machine name whose record is `room` bytes longer than one with no name."""
    return "\u00e9" * (room // 6) + "h" * (room % 6)      # JSON spells the first as six bytes


def test_a_record_of_exactly_its_size_is_written_and_one_byte_more_says_nothing(root):
    empty = len(json.dumps({"host": "", "pid": os.getpid(), "since": "2026-11-23T04:00:12Z",
                            "verb": "run"}, sort_keys=True))
    for extra, written in ((0, True), (1, False)):
        host = _host_filling(run_lock._RECORD_SIZE - empty + extra)
        with mock.patch.object(run_lock.socket, "gethostname", return_value=host):
            with run_lock.hold(root, "run"):
                assert os.path.getsize(run_lock.lock_path(root)) == run_lock._RECORD_SIZE
                with open(run_lock.lock_path(root), "rb") as fh:
                    said = fh.read()
                assert not _free(root)                # held, whatever the record says
        assert _free(root)
        if written:
            assert said == said.strip() and json.loads(said)["host"] == host
        else:
            assert said.strip() == b""


def test_the_longest_record_a_holder_can_write_fits_and_is_read_back(root):
    longest = "h" * 255                                # a hostname's limit
    with mock.patch.object(run_lock.socket, "gethostname", return_value=longest):
        with run_lock.hold(root, "setup"):
            run_lock.note_child(root, 2 ** 31 - 1, "x" * 20)
            assert os.path.getsize(run_lock.lock_path(root)) == run_lock._RECORD_SIZE
            with open(run_lock.lock_path(root), encoding="utf-8") as fh:
                assert json.load(fh)["host"] == longest


def test_the_drivers_own_descriptor_is_not_inherited_by_what_it_starts(root):
    """A reviewer agent, a probe, `git`: started by the driver without being handed the
    descriptor, none holds the root. Close-on-exec is the kernel's, whatever starts them."""
    assert run_lock.descriptor(root) is None
    with run_lock.hold(root, "loop"):
        fd = run_lock.descriptor(root)
        assert not os.get_inheritable(fd)
        assert fcntl.fcntl(fd, fcntl.F_GETFD) & fcntl.FD_CLOEXEC
    assert run_lock.descriptor(root) is None


# ---- what the refusal says ---------------------------------------------------------

def _refusal(root):
    with pytest.raises(run_lock.Refused) as refused:
        with run_lock.hold(root, "run"):
            pytest.fail("the root was held twice")
    return str(refused.value)


def test_a_child_left_by_a_driver_that_is_gone_is_named_with_what_to_do(root):
    gone = dead_pid()
    record = _record(pid=gone, verb="run", child={"pid": os.getpid(), "phase": "synthesize"})
    with _another_driver(root, record):
        message = _refusal(root)
    assert message == (
        "a synthesize child (pid %d) left by a driver that is no longer running (pid %d, "
        "`driver run`, since 2026-11-23T04:00:12Z) still holds this review root: wait for it "
        "to exit, or stop it (`kill %d`), then run again" % (os.getpid(), gone, os.getpid()))


def test_a_running_driver_with_a_child_is_named_as_the_driver(root):
    record = _record(child={"pid": 4242, "phase": "tools"})
    with _another_driver(root, record):
        message = _refusal(root)
    assert "another driver is running on this review root (pid %d" % os.getpid() in message
    assert "4242" not in message


def test_a_holder_left_by_a_gone_driver_with_no_child_named_points_at_the_lock_file(root):
    gone = dead_pid()
    with _another_driver(root, _record(pid=gone, verb="loop")):
        message = _refusal(root)
    assert message == (
        "a process left by a driver that is no longer running (pid %d, `driver loop`, since "
        "2026-11-23T04:00:12Z) still holds this review root: `lsof %s` names it; wait for it "
        "to exit, or stop it, then run again" % (gone, run_lock.lock_path(root)))


def test_a_driver_on_another_machine_is_named_with_its_machine_and_not_probed(root):
    gone = dead_pid()                    # a pid from over there means nothing here
    with _another_driver(root, _record(pid=gone, host="elsewhere.example")):
        message = _refusal(root)
    assert message == (
        "another driver is running on this review root (pid %d on elsewhere.example, "
        "`driver loop`, since 2026-11-23T04:00:12Z): wait for it to finish, or stop it, then "
        "run again" % gone)


def _said(**fields):
    """A complete record of a driver on another machine, with `fields` changed."""
    record = {"pid": 7, "verb": "run", "since": "2026-11-23T04:00:12Z", "host": "h.example"}
    record.update(fields)
    return json.dumps({key: value for key, value in record.items() if value is not None})


@pytest.mark.parametrize("text", [
    "", "not json", "[]", "{}", b"\xff\xfe",
    _said(pid=True), _said(pid=-3), _said(pid=0), _said(pid="7"), _said(pid=7.0),
    _said(pid=None), '{"pid": 1e400, "verb": "run", "since": "2026-11-23T04:00:12Z", "host": "h"}',
    _said(verb="\x1b[2Jrun"), _said(verb="persist"), _said(verb=None),
    _said(since="yesterday"), _said(since="2026-11-23T04:00:12Z\nstatus: complete"),
    _said(since=None), _said(since=20261123),
    _said(host="a\x1b[2Jb"), _said(host="h.example\nstatus: complete"), _said(host=7),
    _said(host=None), _said(host=""),
], ids=["empty", "not-json", "a-list", "no-fields", "not-utf8",
        "pid-true", "pid-negative", "pid-zero", "pid-text", "pid-float", "pid-absent",
        "pid-infinite", "verb-escape", "verb-unknown", "verb-absent",
        "since-words", "since-then-a-line", "since-absent", "since-number",
        "host-escape", "host-then-a-line", "host-number", "host-absent", "host-empty"])
def test_a_lock_file_that_says_nothing_usable_still_refuses_and_prints_none_of_it(root, text):
    with _another_driver(root, text=text):
        message = _refusal(root)
    assert message == (
        "another process holds this review root, and its lock file says nothing readable "
        "about it: `lsof %s` names it; wait for it to finish, or stop it, then run again"
        % run_lock.lock_path(root))


def test_a_lock_file_that_cannot_be_read_still_refuses(root):
    with _another_driver(root), mock.patch.object(
            run_lock.os, "pread", side_effect=OSError(errno.EIO, "Input/output error")):
        assert "says nothing readable" in _refusal(root)


def test_a_record_longer_than_a_record_is_not_read_whole(root):
    with _another_driver(root, text=_said(padding="x" * 5000)):
        assert "says nothing readable" in _refusal(root)


@pytest.mark.skipif(os.getuid() == 0, reason="root may signal any process")
def test_a_driver_this_user_may_not_signal_is_named_as_running(root):
    with _another_driver(root, _record(pid=1)):       # pid 1 is always there, and not ours
        assert "another driver is running on this review root (pid 1," in _refusal(root)


def test_a_pid_no_system_holds_does_not_stop_the_refusal(root):
    with _another_driver(root, _record(pid=2 ** 80)):
        assert "review root (pid %d," % 2 ** 80 in _refusal(root)


def test_a_child_whose_record_is_unusable_is_not_named(root):
    gone = dead_pid()
    for bad in ({"pid": "12", "phase": "synthesize"}, {"pid": 12, "phase": "\x1b[2J"},
                {"pid": 12, "phase": "tools\x1b[2J"}, {"pid": 12, "phase": 7}, {"pid": 12},
                {"pid": 0, "phase": "synthesize"}, ["12"], {"pid": True, "phase": "tools"}):
        with _another_driver(root, _record(pid=gone, child=bad)):
            message = _refusal(root)
        assert "lsof %s" % run_lock.lock_path(root) in message, bad
        assert "child (pid" not in message and "\x1b" not in message, bad


# ---- a lock that cannot be used ----------------------------------------------------

@pytest.mark.parametrize("reason", [errno.ENOLCK, errno.EOPNOTSUPP, errno.EINVAL, errno.EBADF])
def test_a_filesystem_that_refuses_the_lock_stops_the_driver_with_the_reason(root, reason):
    before = _tree(root)
    with mock.patch.object(run_lock.fcntl, "flock",
                           side_effect=OSError(reason, os.strerror(reason))) as flock:
        status = _run(root)
    flock.assert_called_once()
    assert status["status"] == "error"
    assert "refused the lock (%s)" % os.strerror(reason) in status["message"]
    assert run_lock.lock_path(root) in status["message"]
    assert "PANOPTICON_STATE_DIR" in status["message"]
    assert "another driver" not in status["message"]
    assert _tree(root) == before          # no `.panopticon/`, nothing begun
    assert run_lock.descriptor(root) is None


def test_a_refused_lock_leaves_no_descriptor_open(root):
    opened = []
    real_open = os.open

    def watch(path, *args, **kwargs):
        fd = real_open(path, *args, **kwargs)
        if path == run_lock.lock_path(root):
            opened.append(fd)
        return fd

    with mock.patch.object(run_lock.os, "open", side_effect=watch), \
            mock.patch.object(run_lock.fcntl, "flock",
                              side_effect=OSError(errno.ENOLCK, "No locks available")):
        with pytest.raises(run_lock.Refused):
            with run_lock.hold(root, "run"):
                pytest.fail("held without a lock")
    assert len(opened) == 1
    with pytest.raises(OSError):
        os.fstat(opened[0])
    with _another_driver(root):
        with mock.patch.object(run_lock.os, "open", side_effect=watch):
            with pytest.raises(run_lock.Refused):
                with run_lock.hold(root, "run"):
                    pytest.fail("the root was held twice")
    assert len(opened) == 2
    with pytest.raises(OSError):
        os.fstat(opened[1])


def _state(monkeypatch, tmp_path):
    state = tmp_path / "state"
    monkeypatch.setenv("PANOPTICON_STATE_DIR", str(state))
    return state


def test_a_state_directory_that_is_a_file_stops_the_driver(root, monkeypatch, tmp_path):
    _state(monkeypatch, tmp_path).write_text("not a directory")
    status = _run(root)
    assert status["status"] == "error"
    assert status["message"].startswith(
        "the run lock cannot be used: %s: File exists. " % tmp_path.joinpath("state"))
    assert status["message"].endswith(
        "point PANOPTICON_STATE_DIR at a directory you own and can write, on a local filesystem")
    assert not os.path.lexists(os.path.join(root, ".panopticon"))


@pytest.mark.skipif(os.getuid() == 0, reason="root writes anywhere")
def test_a_state_directory_that_cannot_be_written_stops_the_driver(root, monkeypatch, tmp_path):
    """The stamp key can be read from a read-only state directory. The lock cannot be
    made in one, so `run`, `loop` and `setup` need it writable (seat review of #3782)."""
    state = _state(monkeypatch, tmp_path)
    state.mkdir(mode=0o700)
    state.chmod(0o500)
    try:
        status = _run(root)
    finally:
        state.chmod(0o700)
    assert status["status"] == "error"
    assert status["message"].startswith(
        "the run lock cannot be used: %s: Permission denied. " % (state / "locks"))
    assert "a directory you own and can write" in status["message"]
    assert not os.path.lexists(os.path.join(root, ".panopticon"))


def test_a_locks_directory_that_is_a_link_is_not_followed(root, monkeypatch, tmp_path):
    state = _state(monkeypatch, tmp_path)
    state.mkdir(mode=0o700)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (state / "locks").symlink_to(elsewhere)
    with pytest.raises(run_lock.Refused) as refused:
        with run_lock.hold(root, "run"):
            pytest.fail("held through a link")
    assert str(refused.value).startswith(
        "the run lock cannot be used: %s is not a real directory. " % (state / "locks"))
    assert list(elsewhere.iterdir()) == []


@pytest.mark.parametrize("planted", ["link", "directory", "fifo"])
def test_a_lock_file_that_is_not_a_plain_file_is_refused(root, monkeypatch, tmp_path, planted):
    _state(monkeypatch, tmp_path)
    path = run_lock.lock_path(root)
    os.makedirs(os.path.dirname(path), mode=0o700)
    target = tmp_path / "target-of-link"
    if planted == "link":
        target.write_text("someone else's file")
        os.symlink(target, path)
    elif planted == "directory":
        os.mkdir(path)
    else:
        os.mkfifo(path)
    with pytest.raises(run_lock.Refused) as refused:
        with run_lock.hold(root, "run"):
            pytest.fail("held on something that is not a lock file")
    assert str(refused.value).startswith("the run lock cannot be used: %s" % path)
    if planted == "fifo":
        assert "%s is not a regular file. " % path in str(refused.value)
    if planted == "link":
        assert target.read_text() == "someone else's file"


def test_a_lock_file_owned_by_another_user_is_refused(root):
    real = os.fstat

    def theirs(fd):
        info = list(real(fd))
        info[4] += 1                      # st_uid
        return os.stat_result(info)

    with mock.patch.object(run_lock.os, "fstat", side_effect=theirs):
        with pytest.raises(run_lock.Refused) as refused:
            with run_lock.hold(root, "run"):
                pytest.fail("held on another user's file")
    assert str(refused.value).startswith("the run lock cannot be used: %s is owned by "
                                         "another user. " % run_lock.lock_path(root))
    assert _free(root)


def test_a_holder_record_that_cannot_be_written_does_not_stop_the_holder(root):
    """What the file says is for the next driver's message. The lock is the decision."""
    with mock.patch.object(run_lock.os, "pwrite", side_effect=OSError(errno.ENOSPC, "full")):
        with run_lock.hold(root, "run"):
            assert not _free(root)
    assert _free(root)


# ---- the verbs ---------------------------------------------------------------------

def test_a_run_holds_its_root_while_its_phases_run_and_lets_go_after(root):
    seen = []
    status = _run(root, phases=(_held_inside(root, seen),))
    assert seen == [(False, "run")]
    assert REFUSAL not in str(status.get("message"))
    assert _free(root)


@pytest.mark.parametrize("flags", [(), ("--reset",)], ids=["resume", "reset"])
def test_a_run_on_a_held_root_is_refused_before_it_touches_the_tree(root, flags):
    """The issue's case: a second driver's `--reset` deleted the run folder under the
    first. Refused here, it reads and writes nothing under `.panopticon/`."""
    _a_run_in_flight(root)
    before = _tree(root)
    seen = []
    with _another_driver(root), mock.patch.object(driver.first_contact, "assess") as assess:
        status = _run(root, *flags, phases=(_held_inside(root, seen),))
    assert status["status"] == "error"
    assert status["message"].startswith("another driver is running on this review root (pid ")
    assert seen == []
    assert not assess.called              # refused before first contact
    assert _tree(root) == before


def test_a_run_refused_on_a_pr_worktree_leaves_the_worktree_to_its_holder(root):
    """The worktree is the running driver's: a refusal does not release it. (`--pr` is
    withdrawn at the command line, #3735; `driver.run` still takes it from a caller.)"""
    args = driver.build_parser().parse_args(
        ["run", root, "--host", "codex", "--no-tools", "--pr", "7"])
    with _another_driver(root), \
            mock.patch.object(driver.diff_map, "release_worktree") as release:
        status = driver.run(args, phases=(), resolved=(root, root, "main"))
    assert status["status"] == "error"
    assert status["message"].startswith("another driver is running")
    release.assert_not_called()


def test_the_loop_holds_its_root_across_every_run_and_lets_go_after(root):
    seen = []

    def run(args, resolved=None):
        first = not seen
        seen.append((_free(root), _says(root)))
        with run_lock.hold(root, "run"):          # `driver.run`'s own hold passes
            seen.append((_free(root), _says(root)))
        seen.append((_free(root), _says(root)))   # and its exit does not let go
        return orchestrate._status("checkpoint" if first else "complete", "done",
                                   phase="review", checkpoint="review")

    def between(review_root):                     # after the first run, with work remaining
        seen.append((_free(root), _says(root)))
        return True

    class Pause(orchestrate.loop_setup.PauseRequest):
        def restore(self):                        # the loop's last step, after the root is let go
            seen.append(_free(root))
            super().restore()

    args = driver.parse_cli(["loop", root, "--host", "codex", "--mode", "session", "--no-tools"])
    with mock.patch.object(orchestrate.driver, "run", side_effect=run), \
            mock.patch.object(orchestrate, "_after_first_run", side_effect=between):
        status = orchestrate.loop(args, pause=Pause())
    assert status["status"] == "complete", status
    assert seen == [(False, "loop")] * 7 + [True]
    assert _free(root)


@pytest.mark.parametrize("flags", [(), ("--reset",), ("--setup",)],
                         ids=["resume", "reset", "setup"])
def test_a_loop_on_a_held_root_is_refused_before_it_touches_the_tree(root, flags):
    _a_run_in_flight(root)
    before = _tree(root)
    args = driver.parse_cli(["loop", root, "--host", "codex", "--mode", "session",
                             "--no-tools", *flags])
    with _another_driver(root), mock.patch.object(orchestrate.driver, "run") as run, \
            mock.patch.object(setup, "run_setup_flow") as flow, \
            mock.patch.object(orchestrate.loop_setup.first_contact, "assess_loop") as assess:
        status = orchestrate.loop(args)
    assert status["status"] == "error"
    assert status["message"].startswith("another driver is running on this review root (pid ")
    run.assert_not_called()
    flow.assert_not_called()
    assert not assess.called              # refused before first contact
    assert _tree(root) == before
    assert _free(root)


def test_a_loop_that_fails_lets_its_root_go(root):
    args = driver.parse_cli(["loop", root, "--host", "codex", "--mode", "session", "--no-tools"])
    with mock.patch.object(orchestrate.driver, "run", side_effect=KeyboardInterrupt):
        with contextlib.suppress(KeyboardInterrupt):
            orchestrate.loop(args)
    assert _free(root)


def test_setup_holds_its_root_and_a_held_root_refuses_it(root):
    args = driver.parse_cli(["setup", root, "--host", "codex"])
    seen = []

    def look(review_root, manifest_name, **kwargs):
        seen.append((_free(root), _says(root)))
        raise setup.first_contact.FirstContactHalt("stop here")

    with mock.patch.object(setup.first_contact, "assess", side_effect=look):
        setup.run_setup_flow(args)
    assert seen == [(False, "setup")]
    assert _free(root)
    worked = []                                   # past first contact, while work remains
    status = setup.run_setup_flow(args, phases=(_held_inside(root, worked),))
    assert worked == [(False, "setup")], status
    assert _free(root)
    before = _tree(root)
    with _another_driver(root), mock.patch.object(setup.first_contact, "assess") as assess:
        status = setup.run_setup_flow(args)
    assert status["status"] == "error"
    assert status["message"].startswith(
        "another driver is running on this review root (pid %d, `driver loop`" % os.getpid())
    assert _tree(root) == before
    assert not assess.called


def test_persist_and_readiness_take_no_lock(root, capsys):
    """A session host persists several replies at once, and `readiness` only reads."""
    _a_run_in_flight(root)
    with _another_driver(root), mock.patch.object(run_lock, "hold") as hold:
        code = driver.main(["persist", "no-such-entry", root])
        said = capsys.readouterr()
        assert code != 0 and "another driver" not in said.err + said.out
        with mock.patch.object(driver.readiness, "emit_preflight", return_value=0) as preflight:
            assert driver.main(["readiness", root, "--host", "codex"]) == 0
        preflight.assert_called_once()
    hold.assert_not_called()


# ---- the phase child ---------------------------------------------------------------

_CHILD = """\
import json, os, runpy, subprocess, sys
handed = os.environ.get({env!r})
runpy.run_path({bootstrap!r})
probe = ("import os\\ntry:\\n    os.fstat(%s)\\n    print('open')\\n"
         "except OSError:\\n    print('closed')\\n" % handed)
def mine():
    try:
        os.fstat(int(handed))
    except (OSError, TypeError, ValueError):
        return False
    return True
print(json.dumps({{
    "handed": handed,
    "open here": mine(),
    "variable after start": os.environ.get({env!r}),
    "started with close_fds=False": subprocess.run(
        [sys.executable, "-c", probe], close_fds=False, capture_output=True,
        text=True).stdout.strip() if handed else None,
    "started by fork and exec": os.spawnv(os.P_WAIT, sys.executable, [
        sys.executable, "-c", "import os\\ntry:\\n    os.fstat(%s)\\n"
        "except OSError:\\n    os._exit(0)\\nos._exit(7)\\n" % handed]) if handed else None,
}}))
"""


def _phase_child(tmp_path):
    script = tmp_path / "phase_child.py"
    script.write_text(_CHILD.format(env=run_lock.FD_ENV, bootstrap=BOOTSTRAP), encoding="utf-8")
    return [sys.executable, str(script)]


@pytest.mark.parametrize("phase", ["discovery", "tools", "usage", "synthesize"])
def test_a_phase_child_is_handed_the_lock_and_what_it_starts_is_not(root, tmp_path, phase):
    with run_lock.hold(root, "run"):
        fd = run_lock.descriptor(root)
        proc = child._run_child(_phase_child(tmp_path), review_root=root, phase=phase)
    said = json.loads(proc.stdout)
    assert said == {"handed": str(fd), "open here": True, "variable after start": None,
                    "started with close_fds=False": "closed", "started by fork and exec": 0}


def test_a_phase_child_started_outside_a_held_root_is_handed_nothing(root, tmp_path, monkeypatch):
    monkeypatch.setenv(run_lock.FD_ENV, "0")      # a stale value from the environment
    proc = child._run_child(_phase_child(tmp_path), review_root=root, phase="synthesize")
    assert json.loads(proc.stdout)["handed"] is None


@pytest.mark.parametrize("value", ["", "x", "987", "-1", "9" * 30, "3.5"])
def test_a_variable_that_names_no_descriptor_does_not_stop_a_script(value, tmp_path):
    script = tmp_path / "starts.py"
    script.write_text("import os, runpy\nrunpy.run_path(%r)\nprint(os.environ.get(%r))\n"
                      % (BOOTSTRAP, run_lock.FD_ENV), encoding="utf-8")
    env = dict(child._child_env(), **{run_lock.FD_ENV: value})
    with mock.patch.object(child, "_child_env", return_value=env):
        started = child._run_child([sys.executable, str(script)], review_root=str(tmp_path),
                                   phase="synthesize")
    assert (started.returncode, started.stdout.strip(), started.stderr) == (0, "None", "")


_STARTS = """\
import json, os, runpy, sys
kind, bootstrap, name, path = sys.argv[1:5]
if kind == "pipe":
    fd = os.pipe()[1]
elif kind == "directory":
    fd = os.open(os.path.dirname(path), os.O_RDONLY)
else:
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)     # descriptor 3: the first one free
report = os.fdopen(os.dup(1), "w")    # the output this was started with, whatever follows
if kind.startswith("standard"):
    os.dup2(fd, int(kind[-1]))        # a regular file as standard input, output or error
    fd = int(kind[-1])
os.set_inheritable(fd, True)
os.environ[name] = str(fd)
runpy.run_path(bootstrap)
print(json.dumps({"inherited by what it starts": os.get_inheritable(fd), "descriptor": fd,
                  "variable": os.environ.get(name)}), file=report)
"""


@pytest.mark.parametrize("kind, descriptor, inherited", [
    ("file", 3, False),               # what a driver hands a phase child, at the lowest number
    ("pipe", 4, True), ("directory", 3, True),
    ("standard-0", 0, True), ("standard-1", 1, True), ("standard-2", 2, True),
])
def test_the_bootstrap_closes_a_regular_file_past_the_standard_three_and_nothing_else(
        tmp_path, kind, descriptor, inherited):
    """`PANOPTICON_RUN_LOCK_FD=1` beside a script run by hand took its standard output
    from everything that script started (seat review of #3782)."""
    script = tmp_path / "starts.py"
    script.write_text(_STARTS, encoding="utf-8")
    started = child._run_child(
        [sys.executable, str(script), kind, BOOTSTRAP, run_lock.FD_ENV, str(tmp_path / "a-file")],
        review_root=str(tmp_path), phase="synthesize")
    assert started.returncode == 0, started.stderr
    assert json.loads(started.stdout) == {
        "inherited by what it starts": inherited, "descriptor": descriptor, "variable": None}


def test_the_lock_file_names_the_phase_child_while_it_runs(root, tmp_path):
    script = tmp_path / "reads_lock.py"
    script.write_text(      # the driver names the child just after it starts it: wait for that
        "import json, sys, time\nfor _ in range(2000):\n    said = open(sys.argv[1]).read()\n"
        "    if 'child' in json.loads(said or '{}'):\n        break\n    time.sleep(0.01)\n"
        "print(said)\n", encoding="utf-8")
    with run_lock.hold(root, "loop"):
        proc = child._run_child([sys.executable, str(script), run_lock.lock_path(root)],
                                review_root=root, phase="tools")
        with open(run_lock.lock_path(root), encoding="utf-8") as fh:
            after = json.load(fh)
    during = json.loads(proc.stdout)
    assert during["pid"] == os.getpid() and during["verb"] == "loop"
    assert during["child"]["phase"] == "tools"
    assert isinstance(during["child"]["pid"], int) and during["child"]["pid"] != os.getpid()
    assert "child" not in after


def test_a_phase_child_that_fails_to_start_or_times_out_leaves_no_child_named(root, tmp_path):
    slow = tmp_path / "slow.py"
    slow.write_text("import time\ntime.sleep(60)\n", encoding="utf-8")
    with run_lock.hold(root, "run"):
        with pytest.raises(runio.DriverError, match="could not spawn"):
            child._run_child([str(tmp_path / "no-such-interpreter"), "x"],
                             review_root=root, phase="synthesize")
        with pytest.raises(runio.DriverError, match="timed out"):
            child._run_child([sys.executable, str(slow)], review_root=root,
                             phase="synthesize", timeout=0.2)
        with open(run_lock.lock_path(root), encoding="utf-8") as fh:
            assert "child" not in json.load(fh)
        assert not _free(root)
    assert _free(root)                    # the killed child held nothing back


_DRIVER = """\
import os, sys
import scripts.run_lock as run_lock
from scripts.phases import child
root, script, port = sys.argv[1:4]
with run_lock.hold(root, "run"):
    child._run_child([sys.executable, script, port, str(os.getpid()), run_lock.lock_path(root)],
                     review_root=root, phase="synthesize")
"""

# Ready only once the driver has named it in the lock file: the driver writes that just
# after it starts the child, and a driver killed in between leaves no child named.
_LINGERS = """\
import json, os, socket, sys, time
def named():
    try:
        with open(sys.argv[3]) as fh:
            return json.load(fh)["child"]["pid"] == os.getpid()
    except (OSError, ValueError, KeyError):
        return False
for _ in range(2000):                 # about twenty seconds, then it reports as it is
    if named():
        break
    time.sleep(0.01)
with socket.create_connection(("127.0.0.1", int(sys.argv[1]))) as said:
    said.sendall(("%s %d\\n" % (sys.argv[2], os.getpid())).encode())
time.sleep(120)
"""

_HOLDER = """\
import os, socket, sys, time
import scripts.run_lock as run_lock
with run_lock.hold(sys.argv[1], "loop"):
    with socket.create_connection(("127.0.0.1", int(sys.argv[2]))) as said:
        said.sendall(("%d\\n" % os.getpid()).encode())
    time.sleep(120)
"""


class _Started:
    """A real process, started the way the driver starts one (`child._run_child`), on a
    thread, and the line it sends once it is ready."""

    def __init__(self, tmp_path, name, text, *args, cwd):
        self.server = socket.socket()
        self.server.bind(("127.0.0.1", 0))
        self.server.listen()
        self.server.settimeout(30)
        script = tmp_path / name
        script.write_text(text, encoding="utf-8")
        cmd = [sys.executable, str(script), *args, str(self.server.getsockname()[1])]
        self.thread = threading.Thread(
            target=child._run_child, args=(cmd,),
            kwargs={"review_root": cwd, "phase": "tools", "timeout": 120}, daemon=True)
        self.thread.start()

    def said(self):
        with self.server.accept()[0] as ready:
            ready.settimeout(30)
            return [int(word) for word in ready.makefile().readline().split()]

    def running(self):
        return self.thread.is_alive()

    def ended(self):
        self.thread.join(30)
        self.server.close()
        return not self.thread.is_alive()


def _stop(*pids):
    for pid in pids:
        with contextlib.suppress(OSError):
            os.kill(pid, signal.SIGKILL)


def _until_free(root):
    """Block until `root` is free, as a waiting process would: no polling."""
    fd = os.open(run_lock.lock_path(root), os.O_RDWR)
    waiting = threading.Thread(target=fcntl.flock, args=(fd, fcntl.LOCK_EX), daemon=True)
    waiting.start()
    waiting.join(30)
    try:
        assert not waiting.is_alive(), "the root was not let go"
    finally:
        os.close(fd)


def test_a_child_that_outlives_its_killed_driver_holds_the_root_until_it_exits(root, tmp_path):
    """The orphaned synthesis child of the issue: a retry cannot start beside it."""
    lingers = tmp_path / "lingers.py"
    lingers.write_text(_LINGERS, encoding="utf-8")
    first = _Started(tmp_path, "driver.py", _DRIVER, root, str(lingers), cwd=root)
    pids = []
    try:
        pids = driver_pid, orphan = first.said()
        _stop(driver_pid)
        assert first.ended()
        status = _run(root)
        assert status["status"] == "error"
        assert ("a synthesize child (pid %d) left by a driver that is no longer running "
                "(pid %d, `driver run`" % (orphan, driver_pid)) in status["message"]
        assert "`kill %d`" % orphan in status["message"]
        _stop(orphan)
        _until_free(root)
        assert REFUSAL not in str(_run(root).get("message"))
    finally:
        _stop(*pids)


def test_a_second_driver_process_is_refused_and_the_first_is_not_disturbed(root, tmp_path):
    """Two real processes, the second through the command line."""
    first = _Started(tmp_path, "holder.py", _HOLDER, root, cwd=root)
    pids = []
    try:
        pids = first.said()
        second = child._run_child(
            [sys.executable, os.path.join(SKILL, "scripts", "driver.py"), "run", root,
             "--host", "codex", "--no-tools"], review_root=root, phase="tools")
        assert second.returncode != 0
        assert ("another driver is running on this review root (pid %d, `driver loop`"
                % pids[0]) in second.stdout
        assert not os.path.lexists(os.path.join(root, ".panopticon"))
        assert first.running()
    finally:
        _stop(*pids)
    assert first.ended()
    assert _free(root)                    # a killed holder leaves nothing to clear


# ---- five gates at 712b36ee --------------------------------------------------------

_STREAM_CLOSED = """\
import json, os, sys
closed, root, probe, out = int(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4]
os.close(closed)                      # as a scheduler or a service starts a driver
import scripts.run_lock as run_lock
from scripts.phases import child
said = {}
with run_lock.hold(root, "run"):
    fd = run_lock.descriptor(root)
    info = os.fstat(fd)
    said.update(fd=fd, lock=[info.st_dev, info.st_ino], inheritable=os.get_inheritable(fd))
    done = child._run_child([sys.executable, probe, out + ".child"], review_root=root,
                            phase="synthesize")
    said["child status"] = done.returncode
with open(out, "w") as fh:
    json.dump(said, fh)
"""

_HANDED = """\
import json, os, runpy, sys
handed = int(os.environ[{env!r}])
info = os.fstat(handed)
runpy.run_path({bootstrap!r})
with open(sys.argv[1], "w") as fh:
    json.dump({{"fd": handed, "lock": [info.st_dev, info.st_ino],
               "inherited by what it starts": os.get_inheritable(handed)}}, fh)
"""


@pytest.mark.parametrize("closed", [0, 1, 2])
def test_a_driver_started_with_a_standard_stream_closed_holds_the_lock_above_them(
        root, tmp_path, closed):
    """`os.open` returns the lowest free number. At 1 or 2 the child's output redirection
    replaced the lock with a pipe, and a retry ran beside the orphan; at 0 the bootstrap
    left it open to everything the child started."""
    driver_script, probe, out = tmp_path / "driver.py", tmp_path / "probe.py", tmp_path / "out"
    driver_script.write_text(_STREAM_CLOSED, encoding="utf-8")
    probe.write_text(_HANDED.format(env=run_lock.FD_ENV, bootstrap=BOOTSTRAP), encoding="utf-8")
    child._run_child([sys.executable, str(driver_script), str(closed), root, str(probe), str(out)],
                     review_root=root, phase="tools")
    info = os.stat(run_lock.lock_path(root))
    lock = [info.st_dev, info.st_ino]
    held = json.loads(out.read_text(encoding="utf-8"))
    handed = json.loads((tmp_path / "out.child").read_text(encoding="utf-8"))
    assert held["fd"] > 2 and handed["fd"] == held["fd"]
    assert (held["lock"], handed["lock"]) == (lock, lock)     # the lock file, in both
    assert held["inheritable"] is False
    assert handed["inherited by what it starts"] is False
    assert held["child status"] == 0
    assert _free(root)


def test_a_lock_opened_above_the_standard_three_is_kept_where_it_is(root):
    opened = []
    real = os.open

    def watch(path, *args, **kwargs):
        opened.append(real(path, *args, **kwargs))
        return opened[-1]

    with mock.patch.object(run_lock.os, "open", side_effect=watch):
        with run_lock.hold(root, "run"):
            assert run_lock.descriptor(root) == opened[0] > 2


def test_the_hand_off_does_not_look_at_the_root_again(root, tmp_path):
    """A failed look read as "this process holds nothing", and the child was started
    without the lock its driver held."""
    script = tmp_path / "handed.py"
    script.write_text("import os\nprint(os.environ.get(%r))\n" % run_lock.FD_ENV, encoding="utf-8")
    with run_lock.hold(root, "run"):
        fd = run_lock.descriptor(root)
        with mock.patch.object(run_lock.os, "stat", side_effect=OSError(errno.EIO, "I/O error")):
            assert run_lock.descriptor(root) == fd
            assert run_lock.descriptor(root + os.sep) == fd
            proc = child._run_child([sys.executable, str(script)], review_root=root,
                                    phase="synthesize")
            run_lock.note_child(root, 4242, "tools")
        assert proc.stdout.strip() == str(fd)
        with open(run_lock.lock_path(root), encoding="utf-8") as fh:
            assert json.load(fh)["child"] == {"pid": 4242, "phase": "tools"}


def test_a_root_that_cannot_be_matched_to_a_held_lock_stops_the_launch(root, tmp_path):
    """Another spelling of a root, while this process holds a lock and the look fails:
    it may be the held one. No child is started without knowing."""
    link = tmp_path / "link"
    link.symlink_to(root)
    with run_lock.hold(root, "run"):
        assert run_lock.descriptor(str(link)) == run_lock.descriptor(root)    # looked at: the same
        with mock.patch.object(run_lock.os, "stat", side_effect=OSError(errno.EIO, "I/O error")), \
                mock.patch.object(child.subprocess, "Popen") as started:
            with pytest.raises(runio.DriverError) as stopped:
                child._run_child([sys.executable, "-c", "pass"], review_root=str(link),
                                 phase="synthesize")
            run_lock.note_child(str(link), 4242, "tools")     # best-effort: says nothing
        assert not started.called
        assert str(stopped.value) == (
            "synthesize: not started: the run lock for %s could not be checked: I/O error" % link)
        with open(run_lock.lock_path(root), encoding="utf-8") as fh:
            assert "child" not in json.load(fh)


def test_a_process_that_holds_nothing_starts_a_child_without_looking(tmp_path):
    with mock.patch.object(run_lock.os, "stat", side_effect=OSError(errno.EIO, "I/O error")) as look:
        assert run_lock.descriptor(str(tmp_path)) is None
        proc = child._run_child([sys.executable, "-c", "print('ran')"], review_root=str(tmp_path),
                                phase="synthesize")
    assert proc.stdout.strip() == "ran"
    assert not look.called


def _refused_on_another_thread(root):
    said = []

    def contend():
        try:
            with run_lock.hold(root, "run"):
                said.append("held")
        except run_lock.Refused as exc:
            said.append(str(exc))

    thread = threading.Thread(target=contend)
    thread.start()
    thread.join(30)
    return said


def test_a_hold_on_another_thread_is_another_driver(root):
    """The loop's nested `driver.run` is on the loop's own thread. A second `driver.run`
    on any other thread was taken for it and let in."""
    with run_lock.hold(root, "loop"):
        said = _refused_on_another_thread(root)
        assert len(said) == 1 and said[0].startswith(
            "another driver is running on this review root (pid %d, `driver loop`" % os.getpid())
        with run_lock.hold(root, "run"):          # the same thread: still the nested call
            assert not _free(root)
        assert not _free(root)                    # the refusal let nothing go
    assert _free(root)
    assert _refused_on_another_thread(root) == ["held"]
    assert _free(root)


def test_a_hold_in_a_process_that_inherited_the_table_is_another_driver(root):
    """A forked process has its parent's table and its parent's descriptor."""
    with run_lock.hold(root, "loop"):
        with mock.patch.object(run_lock.os, "getpid", return_value=os.getpid() + 1):
            with pytest.raises(run_lock.Refused, match="another driver is running"):
                with run_lock.hold(root, "run"):
                    pytest.fail("the inherited table let a second process in")
        assert not _free(root)
    assert _free(root)


_SLEEPS = "import time\ntime.sleep(120)\n"


def test_an_interrupt_while_the_child_is_being_named_stops_the_child(root, tmp_path):
    """The record was written before the cleanup was in place: a Ctrl-C there left the
    child running, with the root, after its driver had gone."""
    script = tmp_path / "sleeps.py"
    script.write_text(_SLEEPS, encoding="utf-8")
    named = []

    def interrupted(review_root, pid=None, phase=None):
        if pid is not None:
            named.append(pid)
            raise KeyboardInterrupt

    with run_lock.hold(root, "run"):
        with mock.patch.object(child.run_lock, "note_child", side_effect=interrupted):
            with pytest.raises(KeyboardInterrupt):
                child._run_child([sys.executable, str(script)], review_root=root, phase="tools")
    assert len(named) == 1
    with pytest.raises(ProcessLookupError):       # stopped and reaped, not left with the root
        os.kill(named[0], 0)
    _until_free(root)


def test_time_spent_naming_the_child_is_charged_to_the_phase(root, tmp_path):
    """A 0.2 s cap ran 1.4 s and published: the clock started after the record write."""
    script = tmp_path / "sleeps.py"
    script.write_text(_SLEEPS, encoding="utf-8")
    clock = iter([100.0, 104.5])                  # started; then 4.5 s later, the wait
    with run_lock.hold(root, "run"):
        with mock.patch.object(child, "_clock", side_effect=lambda: next(clock)), \
                mock.patch.object(child.loop_progress, "wait",
                                  wraps=child.loop_progress.wait) as waited:
            with pytest.raises(runio.DriverError, match="timed out after 5s"):
                child._run_child([sys.executable, str(script)], review_root=root,
                                 phase="tools", timeout=5)
    assert waited.call_args.args[1] == 0.5        # what was left of the cap
    clock = iter([100.0, 199.0])
    with mock.patch.object(child, "_clock", side_effect=lambda: next(clock)), \
            mock.patch.object(child.loop_progress, "wait",
                              wraps=child.loop_progress.wait) as waited:
        with pytest.raises(runio.DriverError, match="timed out after 5s"):
            child._run_child([sys.executable, str(script)], review_root=root,
                             phase="tools", timeout=5)
    assert waited.call_args.args[1] == 0          # never a negative wait


def test_a_lock_that_cannot_be_closed_does_not_fail_a_finished_run(root):
    real, kept = os.close, []

    def fails(fd):
        if kept and fd == kept[0]:
            raise OSError(errno.EIO, "Input/output error")
        real(fd)

    def watch(review_root, manifest):
        kept.append(run_lock.descriptor(root))
        return engine.PhaseResult(kind="advanced", message="looked")

    phase = engine.Phase("look", "deterministic", lambda *_: bool(kept), watch)
    try:
        with mock.patch.object(run_lock.os, "close", side_effect=fails):
            status = _run(root, phases=(phase,))
        assert (run_lock._HELD, run_lock._GIVEN) == ({}, {})  # nothing of the hold is left
    finally:
        for fd in kept:                           # the descriptor the failed close left open
            real(fd)
    assert REFUSAL not in str(status.get("message")) and status["status"] != "error", status
    assert len(kept) == 1 and _free(root)


def test_a_child_that_is_not_running_is_not_named_as_the_one_to_stop(root):
    """A record update that failed leaves the last child's pid in the file. `kill <pid>`
    of a process that is gone, or of whatever has its number now, is the wrong advice."""
    gone = dead_pid()
    record = _record(pid=gone, verb="run", child={"pid": dead_pid(), "phase": "synthesize"})
    with _another_driver(root, record):
        message = _refusal(root)
    assert message == (
        "a process left by a driver that is no longer running (pid %d, `driver run`, since "
        "2026-11-23T04:00:12Z) still holds this review root: `lsof %s` names it; wait for it "
        "to exit, or stop it, then run again" % (gone, run_lock.lock_path(root)))
