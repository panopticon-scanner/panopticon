"""Delta-review support (#449): turn a base ref + working tree into a per-file
changed-line-range map, and classify findings against it. Stdlib only; pure
functions plus thin git/gh subprocess wrappers.
"""
import hashlib
import json as _json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import uuid

# This repo has two directories named `scripts` with no __init__.py (repo-root
# scripts/ and skill/scripts/). When imported flat (skill/scripts on
# sys.path -- the standalone-script shape, e.g. discovery.py's own bootstrap),
# the try arm raises ModuleNotFoundError. When `scripts` resolves as a
# namespace package (pytest via conftest.py, or driver.py's own bootstrap
# importing this module as `scripts.diff_map`), it succeeds and binds the
# SAME module object every other caller sees -- see host_disclosure.py for the
# same fallback on the same seam.
try:
    import scripts.repo_config as repo_config
except ImportError:
    import repo_config

class DiffMapError(Exception):
    """A delta-map computation failed in a way that must NOT silently degrade to
    an empty (and therefore vacuous-PASS) hunk map — the caller fails loud
    instead of scoping the on-diff gate to nothing (#5.0-08)."""


_NEWFILE_RE = re.compile(r"^\+\+\+ (.*)$")
_HUNK_RE = re.compile(r"^@@ -\d+(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
_FILE_HEADER = "diff --git "
_RENAME_TO = "rename to "
_COMBINED_HEADERS = ("diff --cc ", "diff --combined ")


_C_ESCAPES = {"a": 0x07, "b": 0x08, "f": 0x0C, "n": 0x0A, "r": 0x0D,
              "t": 0x09, "v": 0x0B, '"': 0x22, "\\": 0x5C}


def _unquote_git_path(s):
    r"""Decode ONE C-quoted git path, or return *s* unchanged.

    #1739 (COD-C2D / SEC-G2B). git prints a path in double quotes, with the
    escapes below, whenever it carries a byte >= 0x80 (under the default
    core.quotepath) or a `"`, `\` or control character (whatever quotepath
    says) -- observed against real git in a temp repo:

        diff --git "a/caf\303\251.py" "b/caf\303\251.py"
        +++ "b/we\"ird.py"
        rename to "ta\tb.py"

    Left undecoded, that spelling keys the hunk map under a name that matches
    no other surface -- discovery lists the real name -- so the file's hunks
    are unreachable and the on-diff gate silently scopes past a changed file
    that a PR author picked the name of.

    The escapes are git's `quote_c_style` set: \a \b \f \n \r \t \v, \" and
    \\ verbatim, and \NNN for any other byte (up to three OCTAL digits). The
    escapes reconstitute BYTES, so the result is decoded UTF-8 with
    `surrogateescape` -- the same spelling `os.fsdecode` gives discovery for
    the same name, which is what keeps the two sets comparable.

    Anything that is not exactly a C-quoted string -- unquoted, unterminated,
    a trailing backslash, an unknown escape, an octal value above 0xFF -- is
    returned VERBATIM. git emits none of those; inventing a different path
    from a malformed one would be a worse failure than keying the literal.
    """
    if len(s) < 2 or not (s.startswith('"') and s.endswith('"')):
        return s
    body = s[1:-1]
    out = bytearray()
    i, n = 0, len(body)
    while i < n:
        ch = body[i]
        if ch != "\\":
            out.extend(ch.encode("utf-8", "surrogateescape"))
            i += 1
            continue
        i += 1
        if i >= n:
            return s                                  # trailing backslash
        esc = body[i]
        if esc in _C_ESCAPES:
            out.append(_C_ESCAPES[esc])
            i += 1
            continue
        if esc not in "01234567":
            return s                                  # unknown escape
        j = i
        while j < n and j - i < 3 and body[j] in "01234567":
            j += 1
        val = int(body[i:j], 8)
        if val > 0xFF:
            return s                                  # not a byte git wrote
        out.append(val)
        i = j
    return out.decode("utf-8", "surrogateescape")


def _plus_header_path(rem):
    r"""The path named by a `+++ ` line's remainder, or None for /dev/null.

    git terminates the ---/+++ name with a TAB when it contains a space (and
    it does so for a quoted name too: `+++ "b/sp ace\"q.py"\t`), then strips
    the `b/` prefix here. A quoted name is unquoted first (#1739), because
    the `b/` prefix lives INSIDE the quotes. Exactly one terminator tab is
    peeled -- never a trailing-whitespace strip, which would silently rename
    a file whose own name ends in a space.
    """
    if rem.endswith("\t"):
        rem = rem[:-1]               # EXACTLY the terminator: a name may itself
                                     # end in a space, and stripping all
                                     # trailing whitespace keyed `endsp .py`
                                     # while discovery listed `endsp .py `
                                     # (#1739). A name ending in a tab is
                                     # always quoted, so this can't eat one.
    p = _unquote_git_path(rem)
    if p == "/dev/null":
        return None
    return p[2:] if p.startswith("b/") else p


def _git_header_path(line):
    r"""The new-side path of a `diff --git a/<p> b/<p>` line, or None.

    Only the SAME-path form is decoded, by halving the remainder: a path may
    contain spaces, so `a/<x> b/<y>` with x != y is genuinely ambiguous. When
    the path needs C-quoting git quotes BOTH halves identically, so the
    quoted form halves just as cleanly and is decoded here too (#1739). A
    MIXED line -- `a/ren.py "b/re\"n.py"`, which is what a rename to a quoted
    name actually emits -- stays ambiguous and falls through to the
    `rename to` / `+++` lines, which are unambiguous. This line is therefore
    only ever the FALLBACK key (see parse_unified_diff).
    """
    rem = line[len(_FILE_HEADER):]
    if rem.startswith('"'):
        half, odd = divmod(len(rem) - 1, 2)      # '"a/p"' + " " + '"b/p"'
        if odd or half <= 0 or rem[half] != " ":
            return None
        left = _unquote_git_path(rem[:half])
        right = _unquote_git_path(rem[half + 1:])
        if not left.startswith("a/") or not right.startswith("b/"):
            return None                          # undecodable, or not a pair
        p = right[2:]
        return p if p and left[2:] == p else None
    half, odd = divmod(len(rem) - 5, 2)          # "a/" + p + " b/" + p
    if odd or half <= 0 or rem[:2] != "a/" or rem[2 + half:5 + half] != " b/":
        return None
    p = rem[2:2 + half]
    return p if rem[5 + half:] == p else None


def parse_unified_diff(text):
    r"""{path: [(start, end), ...]} of changed NEW-side line ranges.

    #1738 (COD-C2A/DAT-E1D): this is a STATE MACHINE, not a line scanner,
    because the diff it parses is attacker-authored content. Under
    `--unified=0` (the flags `hunk_map` pins) an ADDED line carries a single
    '+', so a source line whose text begins with "++ " arrives as
    `+++ <text>` -- byte-identical to a file header. A flat scanner read it as
    one and re-keyed (`++ b/other`), erased (`++ /dev/null`) or invented
    (`++ x;`) map entries, dropping the PR's own later hunks off the on-diff
    gate.

    The frame: `diff --git` opens a file block; `---`/`+++` head it;
    `@@ -a,b +c,d @@` opens a hunk whose payload under --unified=0 is EXACTLY
    b removed + d added lines (a missing `,n` means 1), plus
    `\ No newline at end of file` markers, which pay no budget. So while that
    budget is unspent every line is PAYLOAD whatever it looks like, and
    framing is recognized ONLY between hunks -- where a payload line can
    never stand.

    Keys: the `+++ b/<path>` header is authoritative (unambiguous even for a
    name with spaces, which git tab-terminates); `+++ /dev/null` marks a
    deletion and takes no key. A block with NO `+++` header at all (binary,
    mode-only, a 100%-similarity rename) still changed a file, so it keeps a
    key with no ranges -- classify()'s documented fail-open -- under the path
    from its `rename to` line or, failing that, from the `diff --git` line.
    `@@ -a,b +c,d @@` gives new-side range (c, c+d-1); d==0 (pure deletion)
    adds no range.

    RAISES DiffMapError on a diff the budget cannot reconcile -- text that
    ends inside a hunk, a hunk before any file header, or a COMBINED (merge)
    diff, whose `@@@` payload cannot be budgeted at all and whose two-column
    markers forge a header from content beginning with "+ " (defence-in-depth
    for a direct caller: hunk_map's own `git diff <base_sha>` never emits
    one, see the guard). Same contract as
    hunk_map's other guards (#5.0-08, #1256): half a map scopes the on-diff
    gate to half the change and passes vacuously for the rest, so it is never
    returned.
    """
    result = {}
    path = None        # key of the open block, None = no new side (deletion)
    pending = None     # fallback key, live until this block's `+++` header
    opened = False     # a file block has been framed at all
    budget = 0         # payload lines the open hunk still owes
    # split("\n"), NOT splitlines(): git frames a diff on "\n" and nothing
    # else, while splitlines() also breaks on \r, \x0b, \x0c, \x1c-\x1e,
    # \x85 and \u2028/\u2029. Any of those inside an ADDED source line would
    # split it in two, over-spend the hunk budget, and hand the fragment after
    # it to the framing branch -- the #1738 bypass again, through a character
    # class instead of a prefix. The trailing "" of the final newline is
    # dropped; it is not a payload line and must not spend budget.
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    for line in lines:
        if budget > 0:                                   # inside a hunk
            if not line.startswith("\\"):                # no-newline marker
                budget -= 1
            continue
        if line.startswith(_FILE_HEADER):
            if pending is not None:                      # hunkless block
                result.setdefault(pending, [])
            path, pending, opened = None, _git_header_path(line), True
            continue
        if line.startswith(_COMBINED_HEADERS) or line.startswith("@@@"):
            # Defence-in-depth, and believed unreachable from hunk_map: only an
            # ARGUMENT-LESS `git diff` emits combined format for unmerged
            # paths. `git diff <base_sha>` -- the only diff this module runs --
            # returns an ordinary two-way `diff --git` even with `UU` entries
            # in the index (probed on a real conflicted merge). Kept for any
            # other caller of this parser: a combined hunk's `@@@` header does
            # not describe a payload that can be counted, and its two-column
            # markers let content beginning with "+ " forge a header exactly as
            # "++ " does here -- so refusing beats mis-parsing.
            raise DiffMapError(
                "combined (merge) diff format cannot be parsed here: %r. Its "
                "payload cannot be line-budgeted, so content would be read as "
                "framing (#1738). This parser takes two-way diffs only." % line[:80])
        if line.startswith(_RENAME_TO):
            # #1739: a rename TO a C-quoted name used to be skipped outright,
            # and the `diff --git` line of such a rename is mixed-quoting and
            # undecodable -- so a 100%-similarity rename to e.g. `re"n.py`
            # got no key at all and the changed file vanished from the map.
            # No terminator on this line at all (observed: `rename to new sp
            # .py `), so it is taken verbatim -- rstrip() renamed a file whose
            # name ends in a space.
            pending = _unquote_git_path(line[len(_RENAME_TO):]) or pending
            continue
        m = _NEWFILE_RE.match(line)
        if m:
            path, pending = _plus_header_path(m.group(1)), None
            opened = True
            if path is not None:
                result.setdefault(path, [])
            continue
        h = _HUNK_RE.match(line)
        if h:
            if not opened:
                raise DiffMapError(
                    "hunk header before any file header: %r. The diff is "
                    "malformed and the ranges cannot be attributed to a file; "
                    "an unattributed hunk map would scope the on-diff gate to "
                    "nothing and pass vacuously (#5.0-08)." % line[:80])
            removed = int(h.group(1)) if h.group(1) is not None else 1
            start = int(h.group(2))
            count = int(h.group(3)) if h.group(3) is not None else 1
            budget = removed + count
            if path is not None and count > 0:
                result.setdefault(path, []).append((start, start + count - 1))
    if budget > 0:
        raise DiffMapError(
            "the diff ended inside a hunk: its @@ header still owes %d payload "
            "line(s). The map read so far covers only part of the change, and "
            "the rest would come back off-diff -- the same vacuous pass the "
            "diff/merge-base guards refuse (#5.0-08)." % budget)
    if pending is not None:
        result.setdefault(pending, [])
    return result


def _run_git(repo, args, timeout=60, text=True):
    r"""Run git in `repo`. `text=False` returns BYTES.

    #1738 fix round 1: text mode is universal-newline mode -- it rewrites a
    lone `\r` (and `\r\n`) to `\n` on the way out of the pipe, which invents
    diff lines that git never emitted and hands parse_unified_diff a forged
    file header inside an added line. The diff is therefore read as bytes and
    decoded by its caller; every other call here reads a ref or a file list,
    where the translation is harmless.
    """
    git_bin = shutil.which("git") or "git"
    return subprocess.run([git_bin, "-C", repo, *args],  # nosec B603
                          capture_output=True, text=text, timeout=timeout,
                          env={"PATH": os.environ.get("PATH", "")})


def _decode_git(raw, lossy=False):
    """UTF-8-decode what `_run_git(..., text=False)` returned.

    Strict by default so undecodable diff output fails loud at the call site
    rather than quietly losing a path; `lossy` is for stderr, which is only
    ever quoted back to the operator in a message.
    """
    return (raw or b"").decode("utf-8", "replace" if lossy else "strict")


def _merge_base_cause(repo, base):
    """Why `git merge-base HEAD <base>` failed, in the operator's terms.

    Only ever called on the failure path, so the extra git call is free."""
    try:
        rp = _run_git(repo, ["rev-parse", "--verify", "-q", "%s^{commit}" % base])
        resolves = rp.returncode == 0 and bool(rp.stdout.strip())
    except Exception:
        return "the base could not be checked (git rev-parse itself failed)"
    if not resolves:
        return ("%r does not resolve to a commit -- check the ref name, or fetch "
                "it if it is a remote branch this clone does not have" % base)
    return ("%r resolves, but shares no common ancestor with HEAD. If this is a "
            "shallow clone, deepen it (git fetch --unshallow, or fetch-depth: 0 "
            "in CI); otherwise it is the wrong base" % base)


def hunk_map(repo, base, exclude=()):
    """Changed new-side line ranges per file (merge-base vs working tree),
    including untracked non-ignored files as whole-file ranges.

    RAISES DiffMapError when the base cannot be resolved, when HEAD and the base
    share no common ancestor, when the diff itself fails, or when the diff text
    does not reconcile against its own hunk budget (#1738) — none of these may
    fall through to an empty or partial map that passes the delta gate
    vacuously (#5.0-08, #1256).

    `exclude`: repo-root-relative paths (exact match, no directory component)
    dropped from the map before it is returned. Only the `--pr` worktree
    caller passes anything here -- `_sync_config` overwrites the worktree's
    root config with the OPERATOR's own file after the worktree is built, so
    without this the on-diff gate would attribute that overwrite to the PR
    (#1681). A plain non-PR delta review passes none, so a real change to
    the root config there is classified exactly like any other file."""
    try:
        mb = _run_git(repo, ["merge-base", "HEAD", base])
    except Exception as e:
        # #run7 OPS-E1A: an INFRA failure here (git missing, timeout) must fail
        # LOUD like the diff/ls-files steps below -- not silently return {} and
        # let the delta gate pass vacuously (#5.0-08), the exact hazard one call
        # later.
        raise DiffMapError("git merge-base HEAD..%s failed: %s" % (base, e))
    if mb.returncode != 0 or not mb.stdout.strip():
        # #1256 (COD-B2C): this used to return {} on the documented assumption
        # that "an upstream loud-fail already guards this". That guard is
        # discovery.resolve_base_or_die, and it verifies the base ref RESOLVES
        # TO A COMMIT -- a different question from whether HEAD and that commit
        # share an ancestor. merge-base also fails, with a perfectly valid base,
        # when they do not; the everyday way to reach that is a SHALLOW CLONE,
        # since CI checkouts default to depth 1 and the fork point is simply not
        # in the local history. Either way an empty hunk map scopes the on-diff
        # gate to nothing and passes vacuously -- the exact hazard the diff and
        # ls-files steps below already raise on -- so both fail loud here.
        # Which one it was changes the operator's remedy, so say which.
        raise DiffMapError(
            "git merge-base HEAD..%s failed (exit %s): %s. The delta cannot be "
            "computed, and an empty diff would pass the on-diff gate vacuously."
            % (base, mb.returncode, _merge_base_cause(repo, base)))
    base_sha = mb.stdout.strip()
    # Pin diff formatting so a user's gitconfig (diff.mnemonicPrefix=true, a
    # diff.external driver, quotepath escaping) can't reshape the `+++ b/<path>`
    # headers parse_unified_diff keys on — which would yield an empty map and a
    # vacuous PASS (#5.0-08).
    try:
        # text=False (#1738 fix round 1): universal-newline translation would
        # rewrite a lone `\r` inside an added line to `\n`, splitting one
        # payload line into two before the parser can budget them.
        diff = _run_git(repo, ["-c", "diff.mnemonicPrefix=false",
                               "-c", "core.quotepath=false", "diff",
                               "--unified=0", "--no-color", "--find-renames",
                               "--src-prefix=a/", "--dst-prefix=b/", base_sha],
                        text=False)
    except Exception as e:
        raise DiffMapError("git diff against %s failed: %s" % (base_sha, e))
    if diff.returncode != 0:
        raise DiffMapError("git diff against %s failed (rc=%s): %s"
                           % (base_sha, diff.returncode,
                              _decode_git(diff.stderr, lossy=True).strip()))
    try:
        # Pinned to UTF-8, not the operator's locale: git hands back path and
        # content bytes as they are, and every other surface this map meets
        # (the findings' location.file, diff-hunks.json) is UTF-8. Undecodable
        # output stays a loud DiffMapError -- exactly what strict text-mode
        # decoding already raised here -- never a silently empty map (#5.0-08).
        diff_text = _decode_git(diff.stdout)
    except UnicodeDecodeError as e:
        raise DiffMapError(
            "git diff against %s produced output that is not UTF-8 (%s). The "
            "delta cannot be computed, and an empty diff would pass the "
            "on-diff gate vacuously." % (base_sha, e))
    result = parse_unified_diff(diff_text)
    # `git diff` omits untracked files; add them as whole-file ranges.
    try:
        # Include new untracked files, matching discovery.collect_changed_files.
        others = _run_git(repo, ["ls-files", "--others", "--exclude-standard"])
    except Exception as e:
        raise RuntimeError(f"git ls-files failed: {e}")
    if others is not None:
        if others.returncode != 0:
            raise RuntimeError(f"git ls-files failed: {others.stderr}")
        for rel in others.stdout.splitlines():
            rel = rel.strip()
            if not rel:
                continue
            full = os.path.join(repo, rel)
            if os.path.islink(full):
                continue
            # #1260: resolve symlinks (including intermediate directory symlinks)
            # and refuse to count any path that escapes the repository.
            real_full = os.path.realpath(full)
            real_repo = os.path.realpath(repo)
            try:
                if os.path.commonpath([real_full, real_repo]) != real_repo:
                    continue
            except ValueError:
                continue
            try:
                # #1083: count newlines in bounded chunks so an untracked file
                # with few/no newlines (a huge blob) can't be buffered wholesale.
                # Matches `sum(1 for _ in fh)`: a final newline-less line counts.
                with open(real_full, "rb") as fh:
                    n = 0
                    last = b""
                    while True:
                        chunk = fh.read(65536)
                        if not chunk:
                            break
                        n += chunk.count(b"\n")
                        last = chunk
                    if last and not last.endswith(b"\n"):
                        n += 1
            except OSError:
                continue
            result[rel] = [(1, max(n, 1))]
    for name in exclude:
        result.pop(name, None)
    return result


def diff_anchors(repo, base):
    """Resolve the three commit anchors the delta artifact records.

    {base_commit, delta_start, delta_end}: the base ref's tip, the
    merge-base(base, HEAD) fork point, and HEAD. Any field is None if git can't
    resolve it (in practice the orchestrator has already refused an unresolvable
    base, so all three are populated).
    """
    def _rev(ref):
        try:
            r = _run_git(repo, ["rev-parse", "--verify", "-q", ref])
        except Exception:
            return None
        return r.stdout.strip() if r.returncode == 0 and r.stdout.strip() else None
    delta_start = None
    if base:
        try:
            mb = _run_git(repo, ["merge-base", "HEAD", base])
            if mb.returncode == 0 and mb.stdout.strip():
                delta_start = mb.stdout.strip()
        except Exception:
            delta_start = None
    return {"base_commit": _rev(base + "^{commit}") if base else None,
            "delta_start": delta_start,
            "delta_end": _rev("HEAD")}


def _distance_to_range(ls, le, s, e):
    """Minimum distance from finding [ls, le] to range [s, e] (0 if overlapping)."""
    if ls <= e and le >= s:
        return 0
    return min(abs(ls - s), abs(ls - e), abs(le - s), abs(le - e))


def norm_key(path, repo_root=None):
    """Normalize a location.file / hunk key to the repo-relative spelling the
    hunk map is keyed by: backslash->/, strip leading './', and (when repo_root
    is given) relativize an absolute path that lives under it. Without this a
    finding whose location.file is absolute (e.g. the worktree-absolute paths
    panels are handed on a --pr run, #1007) or './'-prefixed never matches the
    git-relative hunk keys, silently dropping off the on-diff gate -> vacuous
    PASS (#5.0-06)."""
    p = str(path or "").replace("\\", "/")
    while p.startswith("./"):
        p = p[2:]
    if repo_root and os.path.isabs(p):
        try:
            rel = os.path.relpath(p, repo_root).replace("\\", "/")
        except ValueError:
            rel = p
        if not rel.startswith("../"):   # only relativize paths inside the repo
            p = rel
    return p


def classify(finding, hmap, tolerance=5, repo_root=None):
    """{on_diff, hunk, distance} for a finding vs the hunk map (see module docstring).

    Both the finding's location.file and the hunk keys are normalized via
    norm_key so absolute/'./'/backslash spellings still match (#5.0-06)."""
    loc = finding.get("location") or {}
    path = norm_key(loc.get("file"), repo_root)
    nmap = {norm_key(k, repo_root): v for k, v in hmap.items()}
    if path not in nmap:
        return {"on_diff": False, "hunk": None, "distance": None}
    ranges = nmap[path]
    ls = loc.get("line_start")
    if ls is None:
        return {"on_diff": True, "hunk": None, "distance": None}   # fail-open
    le = loc.get("line_end") or ls
    best = None
    for (s, e) in ranges:
        if le >= s - tolerance and ls <= e + tolerance:            # within window or overlap
            dist = _distance_to_range(ls, le, s, e)
            if best is None or dist < best[1]:
                best = ((s, e), dist)
    if best is not None:
        return {"on_diff": True, "hunk": [best[0][0], best[0][1]], "distance": best[1]}
    if not ranges:
        return {"on_diff": True, "hunk": None, "distance": None}   # changed file, no ranges, lined finding: fail-open
    nearest = min(_distance_to_range(ls, le, s, e) for (s, e) in ranges)
    return {"on_diff": False, "hunk": None, "distance": nearest}


def _worktree_dir(repo, pr_number):
    """Deterministic per-(repo, PR) worktree path (owner steer: deterministic
    wherever possible) so acquire_pr is idempotent and a driver --pr run is
    resumable — re-acquisition returns the SAME tree, never leaks a fresh one.
    Under the system temp dir, keyed by the repo's physical path + PR number.

    realpath (#947 FIXME-1): on macOS mkdtemp/tempdir roots live under
    /var/folders/..., a symlink into /private/var/...; record the physical
    path so every consumer (guard allowlist, reconcile, cwd-derived paths)
    agrees.

    #run8 COD-X0X: resolve only the tempdir ROOT, never the deterministic leaf.
    The leaf name (`panopticon-pr-<n>-<hash>`) is fully derivable by anyone with
    write access to the shared temp dir, so realpath-ing the whole path would
    silently FOLLOW an attacker-planted symlink at the leaf and hand back its
    resolved target -- defeating acquire_pr's `os.path.islink(wt)` guard, which
    would then only ever inspect the (non-symlink) destination. Keeping the leaf
    unresolved lets that guard see the real, possibly hostile, leaf.
    """
    key = hashlib.sha256(os.path.realpath(repo).encode("utf-8")).hexdigest()[:12]
    root = os.path.realpath(tempfile.gettempdir())
    return os.path.join(root, "panopticon-pr-%d-%s" % (pr_number, key))


# Hard bound on the --pr worktree git/gh calls so a hung fetch/API/teardown
# (network partition, stalled TLS, a held git lock) cannot block the run
# indefinitely (#1081, #1082). Generous -- a shallow PR fetch is the slowest.
_PR_TIMEOUT = 180


def _write_operator_config(path, data):
    """Create `path` holding `data`, following nothing and overwriting nothing.

    #1681 fix round 3 M1. The destination sits in a worktree full of
    attacker-controlled PR content, and `shutil.copy2` opened the name a
    SECOND time after `_sync_config` had unlinked it -- a window in which a
    link planted at that name is followed, carrying the operator's config (and
    the source file's mode) onto whatever it points at. The same CWE-59 the
    lstat+unlink loop above exists to close, one call later.

    O_EXCL|O_CREAT|O_NOFOLLOW refuses anything that is already there, link or
    file, so a destination that came back is a loud RuntimeError in the voice
    of this module's other refusals rather than a silent write-through.
    `_sync_config` only ever calls this on a name it has just removed or never
    found, so EEXIST means exactly that race.
    """
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags, 0o644)
    except OSError as exc:
        raise RuntimeError(
            "panopticon --pr: refusing to write %s in the worktree -- the path "
            "reappeared after it was removed (%s)" % (path, exc)) from exc
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)


def _sync_config(repo, wt_path):
    """Copy the OPERATOR's root config into the PR worktree so the review runs
    against the operator's grouping, never the PR's (#1681; was `_sync_groups`).

    #run8 SEC-D1C: the worktree holds ATTACKER-CONTROLLED checked-out PR
    content. Its root is symlink-checked in acquire_pr and again here; a
    PR-shipped copy of the root config (file OR symlink) under either
    recognized config name at the worktree root is REMOVED with lstat+unlink
    -- never opened, never followed (CWE-59) -- before the operator's file is
    copied in under the operator's own name. Overwriting is the point (the
    old copy-if-absent let the PR's file govern its own review); every
    removal, refresh, and overwrite is returned as a disclosure line for the
    caller to print.

    #1681 fix round 2 item 5 (controller ruling R18): the removal loop runs
    UNCONDITIONALLY, even when the operator has no config (or a refused one)
    -- a PR-shipped file at either name must never govern its own review just
    because the operator's own repo has none. Only the final copy is
    conditional on `res.path`. `res.disclosures` (an operator-side symlink
    refusal, or a "both present" note) is always prepended to the returned
    notes -- fix round 1 item 2 and fix round 2 item 4 -- so neither branch
    goes silent on the caller, who prints exactly this list.

    An existing regular file at the destination whose bytes already match the
    operator's copy (the reuse/resume call site: a PREVIOUS `_sync_config`
    already wrote it) is left alone -- not removed, and not rewritten either:
    the final write is skipped for it -- and disclosed as "refreshed", never
    "removed". Three guards on that fast path (fix round 2 items 1-2):
    the size from the already-done `lstat` must match before anything is
    opened at all (a large PR-planted file at the config name is never read
    just to prove it differs); reading what does match sizes uses O_NOFOLLOW
    so the compare can't be tricked into opening through a same-named symlink
    an attacker raced in after the `lstat`; and the fast path only ever
    applies to the destination name that matches the operator's OWN file
    (`os.path.basename(res.path)`) -- a fluke-identical file under the
    OTHER name is still removed, so the worktree never ends up with both
    names present (which would raise its own "both present" disclosure the
    next time something reads config from the worktree).

    Fix round 3, M1/M3. The copy is `_write_operator_config`, an EXCLUSIVE
    O_NOFOLLOW create of bytes already in hand, not a second `shutil.copy2`
    open of the same name: removal and copy were a TOCTOU pair in a directory
    full of attacker-controlled PR content, and copy2 follows whatever is at
    the path when it opens it. And the operator's file is read under
    `repo_config.MAX_CONFIG_BYTES` like every other reader -- an over-cap file
    is refused there, so it is disclosed and not copied here rather than
    shipped into the worktree for `read_document` to refuse again.
    """
    res = repo_config.resolve(repo)
    if os.path.islink(wt_path):
        raise RuntimeError(
            "panopticon --pr: refusing to sync into a symlinked worktree (%s)" % wt_path)
    if not os.path.isdir(wt_path):
        raise RuntimeError(
            "panopticon --pr: refusing to sync into a missing worktree (%s)" % wt_path)
    notes = []
    src, operator_bytes = res.path, None
    if src is not None:
        with open(src, "rb") as fh:
            operator_bytes = fh.read(repo_config.MAX_CONFIG_BYTES + 1)
        if len(operator_bytes) > repo_config.MAX_CONFIG_BYTES:
            # M3: the resolver's own cap, read-then-check, never partially
            # copied. A refused operator config is exactly like NO operator
            # config from here on (R18): the removal loop still runs.
            notes.append("%s exceeds %d bytes; refused -- not copied into the "
                         "worktree" % (src, repo_config.MAX_CONFIG_BYTES))
            src, operator_bytes = None, None
    removed, refreshed = set(), set()
    for name in repo_config.CONFIG_NAMES:
        dst = os.path.join(wt_path, name)
        try:
            st = os.lstat(dst)
        except FileNotFoundError:
            continue
        existing = None
        if (operator_bytes is not None
                and name == os.path.basename(src)
                and stat.S_ISREG(st.st_mode)
                and st.st_size == len(operator_bytes)):
            try:
                fd = os.open(dst, os.O_RDONLY | os.O_NOFOLLOW)
            except OSError:
                fd = None
            if fd is not None:
                try:
                    with os.fdopen(fd, "rb") as fh:
                        existing = fh.read()
                except OSError:
                    existing = None
        if existing is not None and existing == operator_bytes:
            refreshed.add(name)
            notes.append("refreshed the operator's %s in the worktree (unchanged)" % name)
            continue
        if stat.S_ISDIR(st.st_mode):
            shutil.rmtree(dst)
        else:
            os.unlink(dst)
        removed.add(name)
        notes.append("removed the PR's %s from the worktree "
                     "(target content must not govern its own review)" % name)
    if src is not None:
        name = os.path.basename(src)
        if name not in refreshed:           # M2: identical == left alone, truly
            _write_operator_config(os.path.join(wt_path, name), operator_bytes)
            if name in removed:
                notes.append("overwrote %s in the worktree with the operator's copy"
                             % name)
    elif removed:
        notes.append("no operator config; PR-shipped config removed, "
                     "reviewing with defaults")
    return list(res.disclosures) + notes


def acquire_pr(pr_number, repo=".", runner=subprocess.run):
    """Fetch a PR head into a DETERMINISTIC throwaway worktree and return its
    base branch. Idempotent: if the deterministic worktree already exists and
    is registered (per `git worktree list`), REUSE it (no re-fetch, stays at
    its pinned head) so a driver --pr run resumes in the same tree; else
    fetch the PR head + create it.

    Never mutates the caller's checkout — all work lands in the worktree (the
    blast radius). Raises RuntimeError (loud) on any step's failure.
    """
    def _run(argv):
        try:
            r = runner(argv, capture_output=True, text=True, timeout=_PR_TIMEOUT)
        except subprocess.TimeoutExpired:
            raise RuntimeError("panopticon --pr: `%s` timed out after %ss"
                               % (" ".join(argv), _PR_TIMEOUT))
        if r.returncode != 0:
            raise RuntimeError("panopticon --pr: `%s` failed: %s"
                               % (" ".join(argv), (r.stderr or "").strip()))
        return r.stdout

    view = _run(["gh", "pr", "view", str(pr_number), "--json", "baseRefName"])
    try:
        pr_info = _json.loads(view)
    except ValueError as exc:
        raise RuntimeError("panopticon --pr: `gh pr view` returned invalid JSON for PR %d: %s"
                           % (pr_number, exc)) from exc
    if not isinstance(pr_info, dict) or not isinstance(pr_info.get("baseRefName"), str) \
            or not pr_info["baseRefName"]:
        raise RuntimeError("panopticon --pr: `gh pr view` output missing baseRefName for PR %d"
                           % pr_number)
    base = pr_info["baseRefName"]

    wt = _worktree_dir(repo, pr_number)
    if os.path.islink(wt):
        raise RuntimeError("panopticon --pr: insecure symlink detected at worktree path %s" % wt)
    # `git worktree list` (no --porcelain) prints one line per worktree:
    # "<path>  <sha> [<branch>]" or "<path>  <sha> (detached HEAD)" — column
    # widths vary with the longest path, so match on the first whitespace-
    # split token rather than a fixed-width slice (verified against real
    # `git worktree list` output, not assumed from the porcelain format).
    # #run7 QAL-C2D: route through _run so a stalled `git worktree list` raises
    # RuntimeError (which driver.run's #5.0-14 handler catches) instead of leaking
    # a raw TimeoutExpired as an uncaught traceback, and so a non-zero listing
    # fails loud rather than silently falling through to the create path.
    listing_out = _run(["git", "-C", repo, "worktree", "list"])
    if any(line.split()[:1] == [wt]
           for line in listing_out.splitlines() if line.strip()):
        head_sha = _run(["git", "-C", wt, "rev-parse", "HEAD"]).strip()
        for line in _sync_config(repo, wt):
            print("panopticon --pr: %s" % line, file=sys.stderr)
        return {"worktree": wt, "base": base, "head_sha": head_sha}   # reuse (resume)

    fetch_ref = "refs/panopticon/pr-%d-%s" % (pr_number, uuid.uuid4().hex)
    _run(["git", "-C", repo, "fetch", "--no-write-fetch-head", "origin",
          "refs/pull/%d/head:%s" % (pr_number, fetch_ref)])
    head_sha = _run(["git", "-C", repo, "rev-parse", fetch_ref]).strip()
    try:
        _run(["git", "-C", repo, "worktree", "add", "--detach", wt, head_sha])
    finally:
        try:
            _run(["git", "-C", repo, "update-ref", "-d", fetch_ref])
        except RuntimeError:
            pass
    for line in _sync_config(repo, wt):
        print("panopticon --pr: %s" % line, file=sys.stderr)
    return {"worktree": wt, "base": base, "head_sha": head_sha}


def release_worktree(path, repo=".", runner=subprocess.run):
    """Remove a worktree; tolerant if it is already gone."""
    try:
        runner(["git", "-C", repo, "worktree", "remove", "--force", path],
               capture_output=True, text=True, timeout=_PR_TIMEOUT)
    except Exception:      # incl. TimeoutExpired -> a hung teardown is tolerated (#1082)
        pass
