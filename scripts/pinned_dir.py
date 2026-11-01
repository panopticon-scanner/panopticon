"""Open a directory by walking from `/`, one pinned component at a time, never through a symlink.

`reconcile_apply._exclusive_path` locks and writes beside a path through the descriptor this
returns, so no component can be swapped for a symlink between the check and the write: each step
is opened `O_DIRECTORY | O_NOFOLLOW` relative to the previous step's descriptor, and a symlink
component fails (ELOOP / ENOTDIR) as `NotADirectoryError("unsafe directory component: ...")`.

#2841 (#2839's root cause, on this surface): opening a directory O_RDONLY needs READ on it, and
passing through one needs only SEARCH, so a walk opening every ancestor read-only refused a path
under a `--x` directory the kernel lets us traverse. O_PATH (Linux) and O_SEARCH (macOS, exposed
by CPython from 3.13) open a directory for traversal alone; the ancestors are opened with it and
the final directory -- the one the caller locks and writes in -- still O_RDONLY. Where neither
flag exists the walk stays read-only and such a path fails closed, as before.
"""
import errno
import os

# Read at call time, so a test can stand in the flagless branch on every platform.
TRAVERSAL_FLAG = getattr(os, "O_PATH", getattr(os, "O_SEARCH", None))


def open_directory(directory, create=False):
    """A descriptor for absolute `directory`, walked from `/`; the caller closes it. `create`
    makes each missing component on the way (mkdir through the parent's descriptor)."""
    parts = [c for c in directory.split("/") if c]
    passing = TRAVERSAL_FLAG if TRAVERSAL_FLAG is not None else os.O_RDONLY
    fd = os.open("/", (passing if parts else os.O_RDONLY) | os.O_DIRECTORY)
    try:
        for index, component in enumerate(parts):
            if create:
                try:
                    os.mkdir(component, dir_fd=fd)
                except FileExistsError:
                    pass
            mode = passing if index < len(parts) - 1 else os.O_RDONLY
            try:
                child = os.open(component, mode | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            except OSError as exc:
                if exc.errno in (errno.ELOOP, errno.ENOTDIR):
                    raise NotADirectoryError(errno.ENOTDIR,
                                             "unsafe directory component: " + component) from exc
                raise
            os.close(fd)
            fd = child
    except BaseException:
        os.close(fd)
        raise
    return fd
