# tests/test_diff_map.py
import contextlib, io, json, os, shlex, unittest, subprocess, tempfile, shutil
from unittest import mock

import scripts.diff_map as diff_map
from tools.git_repo import make_git_repo


def _git(d, *a):
    subprocess.run(["git", "-C", d, *a], check=True, capture_output=True)


def _git_bytes(d, *args, input_bytes=None):
    return subprocess.run(
        [b"git", b"-C", os.fsencode(d), *args], input=input_bytes,
        check=True, capture_output=True, timeout=30,
    ).stdout

DIFF = """diff --git a/app/db.py b/app/db.py
index 111..222 100644
--- a/app/db.py
+++ b/app/db.py
@@ -10,0 +11,3 @@ def q():
+a
+b
+c
@@ -40,2 +43,1 @@ def r():
-old1
-old2
+new
diff --git a/gone.py b/gone.py
deleted file mode 100644
--- a/gone.py
+++ /dev/null
@@ -1,2 +0,0 @@
-x
-y
diff --git a/new.py b/new.py
new file mode 100644
--- /dev/null
+++ b/new.py
@@ -0,0 +1,4 @@
+1
+2
+3
+4
"""

class TestParse(unittest.TestCase):
    def test_new_side_ranges_and_deletions(self):
        m = diff_map.parse_unified_diff(DIFF)
        self.assertEqual(m["app/db.py"], [(11, 13), (43, 43)])  # d==0 hunk omitted, single-line count defaults to 1
        self.assertEqual(m["new.py"], [(1, 4)])                 # whole new file
        self.assertNotIn("gone.py", m)                          # deleted -> not a new-side key

    def test_single_line_hunk_without_count(self):
        d = "--- a/x.py\n+++ b/x.py\n@@ -5 +7 @@\n-old\n+new\n"
        self.assertEqual(diff_map.parse_unified_diff(d), {"x.py": [(7, 7)]})

    def test_empty_and_garbage_tolerated(self):
        self.assertEqual(diff_map.parse_unified_diff(""), {})
        self.assertEqual(diff_map.parse_unified_diff("not a diff\nrandom\n"), {})


# #1738 (COD-C2A / DAT-E1D). `git diff --unified=0` marks an ADDED line with a
# single '+', so an added source line whose text begins with "++ " reaches the
# parser as "+++ <text>" -- byte-identical to a `+++ b/<path>` file header.
# Every fixture below is a real shape git emits under the flags hunk_map pins
# (--unified=0 --no-color --find-renames --src-prefix=a/ --dst-prefix=b/),
# checked against live `git diff` output rather than hand-imagined.
FORGED = """diff --git a/app/db.py b/app/db.py
index f696b4b..e9a07cf 100644
--- a/app/db.py
+++ b/app/db.py
@@ -3 +3 @@ def q():
%s
%s
@@ -40,0 +41,2 @@ def r():
+real1
+real2
"""

NO_NEWLINE = """diff --git a/a.txt b/a.txt
index ce01362..14be0d4 100644
--- a/a.txt
+++ b/a.txt
@@ -1 +1 @@
-old
\\ No newline at end of file
+++ x;
@@ -5,0 +6 @@
+tail
"""

RENAME_AND_DELETE = """diff --git a/old.py b/new.py
similarity index 80%
rename from old.py
rename to new.py
index 1111111..2222222 100644
--- a/old.py
+++ b/new.py
@@ -2 +2 @@
-b
+B
diff --git a/gone.py b/gone.py
deleted file mode 100644
index 3333333..0000000
--- a/gone.py
+++ /dev/null
@@ -1,2 +0,0 @@
-x
-y
"""

HUNKLESS = """diff --git a/bin.dat b/bin.dat
index c866266..5663091 100644
Binary files a/bin.dat and b/bin.dat differ
diff --git a/sh.sh b/sh.sh
old mode 100644
new mode 100755
diff --git a/moved.py b/renamed.py
similarity index 100%
rename from moved.py
rename to renamed.py
"""


class TestParseHunkState(unittest.TestCase):
    """#1738: framing is recognized only BETWEEN hunks, so a PR's own added
    content can never re-key, erase, or invent an entry in the hunk map."""

    REAL = {"app/db.py": [(3, 3), (41, 42)]}

    def _forged(self, added="+plain", removed="-line3"):
        """The two payload lines of the first hunk, exactly as git prefixes them."""
        return FORGED % (removed, added)

    def test_the_fixture_is_a_faithful_two_hunk_diff(self):
        # positive control: with innocent payload the map is the REAL one, so
        # every failure below is about the forged line and nothing else.
        self.assertEqual(diff_map.parse_unified_diff(self._forged()), self.REAL)

    def test_added_line_forging_a_file_header_is_payload(self):      # (a)
        # source line `++ x;` -> diff line `+++ x;`
        self.assertEqual(diff_map.parse_unified_diff(self._forged(added="+++ x;")),
                         self.REAL)

    def test_added_line_forging_dev_null_does_not_drop_later_hunks(self):   # (b)
        # source line `++ /dev/null` -> `+++ /dev/null`: used to set path=None,
        # discarding every later hunk of the real file.
        self.assertEqual(diff_map.parse_unified_diff(self._forged(added="+++ /dev/null")),
                         self.REAL)

    def test_added_line_forging_another_path_does_not_rekey(self):   # (c)
        # source line `++ b/other/file` -> `+++ b/other/file`: used to re-key
        # the later hunks onto a path of the author's choosing AND mint a key
        # for a file the diff never touched.
        m = diff_map.parse_unified_diff(self._forged(added="+++ b/other/file"))
        self.assertEqual(m, self.REAL)

    def test_added_line_starting_with_three_pluses_is_payload(self):  # (d)
        # source line `+++ b/x` -> diff line `++++ b/x`: never matched the old
        # header regex (it wants a space in position 4) -- pinned so the fix
        # cannot widen the regex and make it match.
        self.assertEqual(diff_map.parse_unified_diff(self._forged(added="++++ b/x")),
                         self.REAL)

    def test_removed_line_looking_like_an_old_file_header_does_nothing(self):  # (e)
        # source line `-- a/x` -> diff line `--- a/x`
        self.assertEqual(diff_map.parse_unified_diff(self._forged(removed="--- a/x")),
                         self.REAL)

    def test_no_newline_marker_consumes_no_budget(self):             # (f)
        # `\ No newline at end of file` sits INSIDE the hunk and pays no line
        # budget; if it did, the forged header after it would land at budget 0
        # and be read as framing again.
        self.assertEqual(diff_map.parse_unified_diff(NO_NEWLINE),
                         {"a.txt": [(1, 1), (6, 6)]})

    def test_rename_and_deletion_parse_as_before(self):               # (g)
        # a rename WITH hunks keys on the new side; a deletion is not a
        # new-side key at all. Unchanged by #1738.
        self.assertEqual(diff_map.parse_unified_diff(RENAME_AND_DELETE),
                         {"new.py": [(2, 2)]})

    def test_hunkless_changes_keep_a_key_with_no_ranges(self):
        # Binary, mode-only and 100%-similarity renames carry no `+++` header
        # and no hunks. They ARE changed files, so they keep a key with no
        # ranges -- classify()'s documented fail-open for a lineless (or
        # lined-but-rangeless) finding on a changed file.
        self.assertEqual(diff_map.parse_unified_diff(HUNKLESS),
                         {"bin.dat": [], "sh.sh": [], "renamed.py": []})

    def test_a_path_containing_spaces_keys_on_the_real_name(self):
        # git tab-terminates the ---/+++ names when they contain a space, and
        # the `diff --git a/<p> b/<p>` line is only decodable because both
        # halves are the same path.
        text = ("diff --git a/my file.txt b/my file.txt\n"
                "index ce01362..14be0d4 100644\n"
                "--- a/my file.txt\t\n"
                "+++ b/my file.txt\t\n"
                "@@ -1 +1 @@\n-hello\n+hello2\n"
                "diff --git a/my bin.dat b/my bin.dat\n"
                "index c866266..5663091 100644\n"
                "Binary files a/my bin.dat and b/my bin.dat differ\n")
        self.assertEqual(diff_map.parse_unified_diff(text),
                         {"my file.txt": [(1, 1)], "my bin.dat": []})

    # #1738 fix round 1 (Critical). git frames a diff on "\n" and nothing else,
    # but str.splitlines() also breaks on a lone \r, \x0b, \x0c, \x1c-\x1e,
    # \x85 (NEL) and \u2028/\u2029 -- so one of those INSIDE an added source
    # line split it into two fragments, over-spent the hunk budget, and handed
    # the fragment after it to the framing branch. The original bypass through
    # a second door.
    SPLITTERS = [("CR", "\r"), ("VT", "\x0b"), ("FF", "\x0c"), ("FS", "\x1c"),
                 ("GS", "\x1d"), ("RS", "\x1e"), ("NEL", "\x85"),
                 ("LS", "\u2028"), ("PS", "\u2029")]

    def test_only_a_newline_frames_a_line(self):
        for name, ch in self.SPLITTERS:
            with self.subTest(name):
                m = diff_map.parse_unified_diff(
                    self._forged(added="+payload%s+++ b/other/file" % ch))
                self.assertEqual(m, self.REAL)

    def test_an_embedded_hunk_header_neither_forges_nor_stalls_the_parse(self):
        # the denial-of-service face of the same bug: the fragment after the
        # split was read as a `@@` header, opening a 198-line budget that ate
        # the rest of the diff and ended in a (loud, run-killing) DiffMapError.
        for name, ch in self.SPLITTERS:
            with self.subTest(name):
                m = diff_map.parse_unified_diff(
                    self._forged(added="+x=1%s@@ -1,99 +1,99 @@" % ch))
                self.assertEqual(m, self.REAL)

    def test_classify_still_sees_a_hunk_after_a_forged_header(self):  # (i)
        # The whole point: a finding at line 41 (second hunk) used to come back
        # on_diff False -- the PR's own content had scoped the gate away from it.
        m = diff_map.parse_unified_diff(self._forged(added="+++ b/other/file"))
        verdict = diff_map.classify(
            {"location": {"file": "app/db.py", "line_start": 41}}, m)
        self.assertTrue(verdict["on_diff"])
        self.assertEqual(verdict["hunk"], [41, 42])


class TestGitPathQuoting(unittest.TestCase):
    r"""#1739 (COD-C2D / SEC-G2B). git C-quotes a path whose name carries a
    byte >= 0x80 (under the default core.quotepath), or a `"`, `\`, tab or
    newline (whatever quotepath says). Observed against real git 2.x in a
    temp repo:

        diff --git "a/caf\303\251.py" "b/caf\303\251.py"
        +++ "b/we\"ird.py"
        rename to "re\\n.py"

    An un-decoded quoted spelling keys the map under a name no other surface
    uses, so the file's hunks are unreachable and the on-diff gate scopes
    past it -- the silent drop this issue is about.
    """

    def test_unquote_plain_string_is_returned_unchanged(self):
        for s in ("app/db.py", "my file.txt", "", '"', 'x"y'):
            self.assertEqual(diff_map._unquote_git_path(s), s)

    def test_unquote_octal_escapes_decode_as_utf8(self):
        # real git output for a file named café.py
        self.assertEqual(diff_map._unquote_git_path(r'"caf\303\251.py"'),
                         "café.py")

    def test_unquote_named_escapes(self):
        self.assertEqual(diff_map._unquote_git_path(r'"we\"ird.py"'), 'we"ird.py')
        self.assertEqual(diff_map._unquote_git_path(r'"back\\slash.py"'),
                         "back\\slash.py")
        self.assertEqual(diff_map._unquote_git_path(r'"ta\tb.py"'), "ta\tb.py")
        self.assertEqual(diff_map._unquote_git_path(r'"new\nline.py"'), "new\nline.py")
        self.assertEqual(diff_map._unquote_git_path(r'"a\a\b\f\r\v.py"'),
                         "a\a\b\f\r\v.py")

    def test_unquote_undecodable_bytes_use_surrogateescape_like_os_fsdecode(self):
        # the SAME spelling discovery's os.fsdecode produces, so the hunk-map
        # key and the reviewed-file-set entry are equal strings.
        self.assertEqual(diff_map._unquote_git_path(r'"\377.py"'),
                         os.fsdecode(b"\xff.py"))

    def test_unquote_refuses_to_invent_a_path_from_invalid_quoting(self):
        # git never emits these; if one arrives, keep the literal rather than
        # guess a different file.
        for bad in (r'"bad\q.py"', r'"\777.py"', '"dangling\\"', '"unterminated'):
            self.assertEqual(diff_map._unquote_git_path(bad), bad)

    def test_plus_header_with_a_quoted_path_keys_the_real_name(self):
        text = ('diff --git "a/caf\\303\\251.py" "b/caf\\303\\251.py"\n'
                'index 111..222 100644\n'
                '--- "a/caf\\303\\251.py"\n'
                '+++ "b/caf\\303\\251.py"\n'
                '@@ -1 +1 @@\n-old\n+new\n')
        self.assertEqual(diff_map.parse_unified_diff(text),
                         {"café.py": [(1, 1)]})

    def test_plus_header_quoted_name_with_a_space_is_tab_terminated(self):
        # observed: git appends a tab to the ---/+++ names when the path
        # contains a space, INCLUDING when the name is also quoted.
        text = ('diff --git "a/sp ace\\"q.py" "b/sp ace\\"q.py"\n'
                '--- "a/sp ace\\"q.py"\t\n'
                '+++ "b/sp ace\\"q.py"\t\n'
                '@@ -1 +1 @@\n-old\n+new\n')
        self.assertEqual(diff_map.parse_unified_diff(text),
                         {'sp ace"q.py': [(1, 1)]})

    def test_a_trailing_space_in_the_name_survives_the_tab_terminator(self):
        # `+++ b/endsp .py \t` (observed): stripping ALL trailing whitespace
        # keyed "endsp .py" while discovery listed "endsp .py " -- the same
        # name-chosen divergence, without any quoting at all.
        text = ("diff --git a/endsp .py  b/endsp .py \n"
                "--- a/endsp .py \t\n"
                "+++ b/endsp .py \t\n"
                "@@ -1 +1 @@\n-old\n+new\n")
        self.assertEqual(diff_map.parse_unified_diff(text),
                         {"endsp .py ": [(1, 1)]})
        # `rename to new sp .py ` (observed) carries no terminator at all, so
        # rstrip() ate the trailing space there too.
        ren = ('diff --git a/old.py b/new sp .py \n'
               'similarity index 100%\n'
               'rename from old.py\n'
               'rename to new sp .py \n')
        self.assertEqual(diff_map.parse_unified_diff(ren), {"new sp .py ": []})

    def test_hunkless_block_keys_on_the_quoted_diff_git_line(self):
        # a binary/mode-only change has no `+++` header at all, so the
        # `diff --git "a/<p>" "b/<p>"` line is the only key available.
        text = ('diff --git "a/caf\\303\\251.dat" "b/caf\\303\\251.dat"\n'
                'index c866266..5663091 100644\n'
                'Binary files a/x and b/x differ\n')
        self.assertEqual(diff_map.parse_unified_diff(text),
                         {"café.dat": []})

    def test_hundred_percent_rename_to_a_quoted_name_keeps_a_key(self):
        # observed for `git mv ren.py 're"n.py'`: the diff --git line is MIXED
        # (`a/ren.py "b/re\"n.py"`), so only `rename to` names the new path.
        text = ('diff --git a/ren.py "b/re\\"n.py"\n'
                'similarity index 100%\n'
                'rename from ren.py\n'
                'rename to "re\\"n.py"\n')
        self.assertEqual(diff_map.parse_unified_diff(text), {'re"n.py': []})

    def test_dev_null_is_still_a_deletion_not_a_key(self):
        text = ("diff --git a/gone.py b/gone.py\n"
                "deleted file mode 100644\n"
                "--- a/gone.py\n"
                "+++ /dev/null\n"
                "@@ -1,2 +0,0 @@\n-x\n-y\n")
        self.assertEqual(diff_map.parse_unified_diff(text), {})

    def test_a_quoted_header_forged_inside_a_hunk_is_still_payload(self):
        # #1738 must not regress: unquoting happens only where framing is
        # recognized, between hunks.
        text = ('diff --git a/app/db.py b/app/db.py\n'
                '--- a/app/db.py\n'
                '+++ b/app/db.py\n'
                '@@ -1,0 +1,1 @@\n'
                '+++ "b/caf\\303\\251.py"\n')
        self.assertEqual(diff_map.parse_unified_diff(text),
                         {"app/db.py": [(1, 1)]})


def _make_repo(test_case):
    return make_git_repo(
        test_case=test_case,
        files={"a.py": "\n".join("line%d" % i for i in range(1, 11)) + "\n"},
        branch="main",
        user_email="t@e.com",
        user_name="T",
        realpath=False,
    )


class TestHunkMap(unittest.TestCase):
    def _repo(self):
        return _make_repo(self)

    def test_committed_and_uncommitted_changes(self):
        d = self._repo()
        _git(d, "checkout", "-q", "-b", "feat")
        p = os.path.join(d, "a.py")
        with open(p, encoding="utf-8") as fh:
            lines = fh.read().splitlines()
        lines[2] = "CHANGED3"
        with open(p, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
        _git(d, "commit", "-qam", "c")
        # uncommitted new file (untracked) -> whole-file range
        with open(os.path.join(d, "b.py"), "w", encoding="utf-8") as fh:
            fh.write("x\ny\n")
        m = diff_map.hunk_map(d, "main")
        self.assertIn("a.py", m)
        self.assertTrue(any(s <= 3 <= e for (s, e) in m["a.py"]))
        self.assertEqual(m["b.py"], [(1, 2)])
        # #1083: a no-trailing-newline untracked file still counts its last line
        # (the chunked newline count matches `sum(1 for _ in fh)`).
        with open(os.path.join(d, "c.py"), "w", encoding="utf-8") as fh:
            fh.write("x\ny\nz")   # 3 lines, no trailing newline
        m2 = diff_map.hunk_map(d, "main")
        self.assertEqual(m2["c.py"], [(1, 3)])

    def test_a_forged_header_in_the_content_cannot_scope_the_gate(self):
        # #1738 end-to-end through the REAL pinned `git diff --unified=0`: a
        # branch whose own added line reads "++ /dev/null" is emitted as
        # "+++ /dev/null" and used to erase every LATER hunk of the same file
        # from the map -- so a finding at line 9 came back off-diff.
        d = self._repo()
        _git(d, "checkout", "-q", "-b", "feat")
        p = os.path.join(d, "a.py")
        with open(p, encoding="utf-8") as fh:
            lines = fh.read().splitlines()
        lines[1] = "++ /dev/null"      # the forged header, first hunk
        lines[8] = "CHANGED9"          # the real change, a later hunk
        with open(p, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
        _git(d, "commit", "-qam", "c")
        m = diff_map.hunk_map(d, "main")
        self.assertEqual(sorted(m), ["a.py"])          # no forged/erased keys
        self.assertTrue(any(s <= 2 <= e for (s, e) in m["a.py"]), m)
        self.assertTrue(any(s <= 9 <= e for (s, e) in m["a.py"]), m)
        self.assertTrue(diff_map.classify(
            {"location": {"file": "a.py", "line_start": 9}}, m)["on_diff"])

    def test_a_carriage_return_inside_a_line_cannot_split_it(self):
        # #1738 fix round 1 (Critical), end-to-end through REAL git: a lone \r
        # inside an added line used to be turned into a line break TWICE --
        # once by the universal-newline translation in _run_git's text-mode
        # pipe (which rewrites \r to \n before the parser sees a thing) and
        # once by str.splitlines() -- so `+++ b/other/file` after it was read
        # as a file header and the later hunk was re-keyed off the real file.
        d = self._repo()
        _git(d, "checkout", "-q", "-b", "feat")
        lines = ["line%d" % i for i in range(1, 11)]
        lines[1] = "payload\r+++ b/other/file"   # forged header behind a CR
        lines[8] = "CHANGED9"                    # the real change, later hunk
        # newline="" so nothing on the way out of Python rewrites the \r (or
        # the \n) -- the bytes git sees are the bytes written here.
        with open(os.path.join(d, "a.py"), "w", encoding="utf-8", newline="") as fh:
            fh.write("\n".join(lines) + "\n")
        _git(d, "commit", "-qam", "c")
        m = diff_map.hunk_map(d, "main")
        self.assertEqual(sorted(m), ["a.py"], m)      # no forged key
        self.assertTrue(any(s <= 2 <= e for (s, e) in m["a.py"]), m)
        self.assertTrue(any(s <= 9 <= e for (s, e) in m["a.py"]), m)
        self.assertTrue(diff_map.classify(
            {"location": {"file": "a.py", "line_start": 9}}, m)["on_diff"], m)

    def test_non_utf8_payload_keeps_ranges_and_serializable_utf8_keys(self):
        for label, payload in (("latin-1", "café".encode("latin-1")),
                               ("shift-jis", "表".encode("shift_jis"))):
            with self.subTest(encoding=label):
                name = "café.py"
                d = make_git_repo(
                    test_case=self,
                    files={name: "".join("line%d\n" % i for i in range(1, 11))},
                    branch="main", realpath=False,
                )
                _git(d, "checkout", "-q", "-b", "feat")
                lines = [("line%d\n" % i).encode("ascii") for i in range(1, 11)]
                lines[1] = b"value = '" + payload + b"'\n"
                lines[8] = b"CHANGED9\n"
                with open(os.path.join(d, name), "wb") as fh:
                    fh.writelines(lines)
                _git(d, "commit", "-qam", label)
                m = diff_map.hunk_map(d, "main")
                self.assertEqual(m, {name: [(2, 2), (9, 9)]})
                serialized = json.dumps(m, ensure_ascii=False).encode("utf-8")
                self.assertEqual(json.loads(serialized), {name: [[2, 2], [9, 9]]})
                for key in m:
                    key.encode("utf-8", "strict")

    def test_non_utf8_filename_fails_loud(self):
        # An undecodable path in the diff must never become a JSON map key.
        def fake(repo, args, timeout=60, text=True):
            r = mock.Mock()
            if args[0] == "merge-base":
                r.returncode, r.stdout, r.stderr = 0, "deadbeef\n", ""
            elif args[0] == "-c":
                r.returncode, r.stdout, r.stderr = 0, (
                    b"diff --git a/bad_\xff.py b/bad_\xff.py\n"
                    b"--- /dev/null\n+++ b/bad_\xff.py\n"
                    b"@@ -0,0 +1 @@\n+fixture\n"), b""
            else:
                r.returncode, r.stdout, r.stderr = 0, "", ""
            return r
        with mock.patch.object(diff_map, "_run_git", side_effect=fake):
            with self.assertRaises(diff_map.DiffMapError) as ctx:
                diff_map.hunk_map(".", "main")
        self.assertIn("UTF-8", str(ctx.exception))

    def test_unresolvable_base_raises_instead_of_returning_empty(self):
        # #1256: this used to return {}. An empty map scopes the on-diff gate to
        # nothing, so a typo'd or unfetched base would PASS vacuously.
        with self.assertRaises(diff_map.DiffMapError) as caught:
            diff_map.hunk_map(self._repo(), "no-such-ref")
        self.assertIn("does not resolve to a commit", str(caught.exception))

    def _fake_git(self, seen, diff_rc=0, diff_err=""):
        def fake(repo, args, timeout=60, text=True):
            r = mock.Mock()
            if args[0] == "merge-base":
                r.returncode, r.stdout, r.stderr = 0, "deadbeef\n", ""
            elif args[0] == "-c":                 # the pinned `git -c ... diff`
                seen["diff"] = args
                seen["text"] = text
                # bytes, because #1738 reads the diff with text=False -- the
                # universal-newline translation of text mode forges diff lines.
                r.returncode = diff_rc
                r.stdout, r.stderr = b"", diff_err.encode("utf-8")
            else:                                  # ls-files --others -z
                # bytes: #1739 reads the untracked listing with -z/text=False.
                r.returncode, r.stdout, r.stderr = 0, b"", b""
            return r
        return fake

    def test_diff_command_failure_raises_not_empty(self):
        # #5.0-08: merge-base OK but the diff itself fails -> DiffMapError, so
        # the run fails loud instead of returning {} and passing the gate vacuously.
        seen = {}
        with mock.patch.object(diff_map, "_run_git",
                               side_effect=self._fake_git(seen, diff_rc=128, diff_err="boom")):
            with self.assertRaises(diff_map.DiffMapError):
                diff_map.hunk_map(".", "main")

    def test_merge_base_infra_failure_raises_not_empty(self):
        # #run7 OPS-E1A: an INFRA failure on merge-base (git missing/timeout) must
        # raise DiffMapError like the diff step, not silently return {} and pass
        # the delta gate vacuously. (A genuinely unresolvable base still -> {}.)
        def raising(repo, args, timeout=60, text=True):
            if args[0] == "merge-base":
                raise FileNotFoundError("git not found")
            # Mirror production: only the diff call reads bytes (text=False);
            # merge-base / ls-files stay in text mode.
            empty = b"" if not text else ""
            return mock.Mock(returncode=0, stdout=empty, stderr=empty)
        with mock.patch.object(diff_map, "_run_git", side_effect=raising):
            with self.assertRaises(diff_map.DiffMapError):
                diff_map.hunk_map(".", "main")

    def test_exclude_drops_named_paths_from_the_map(self):
        # #1681 fix round 1 item 3: the --pr worktree caller (write_diff_hunks)
        # excludes the root config names so the operator's post-acquire
        # overwrite is never attributed to the PR in diff-hunks.json. A plain
        # (non-PR) caller passes none and sees a real change normally.
        d = self._repo()
        _git(d, "checkout", "-q", "-b", "feat")
        with open(os.path.join(d, "panopticon.yml"), "w", encoding="utf-8") as fh:
            fh.write("version: 1\ngroups: {}\n")
        _git(d, "add", "panopticon.yml")
        _git(d, "commit", "-qm", "add root config")
        m = diff_map.hunk_map(d, "main")
        self.assertIn("panopticon.yml", m)
        m2 = diff_map.hunk_map(d, "main", exclude=("panopticon.yml", ".panopticon.yml"))
        self.assertNotIn("panopticon.yml", m2)
        # untracked-others path: same exclusion applies to an uncommitted file
        with open(os.path.join(d, ".panopticon.yml"), "w", encoding="utf-8") as fh:
            fh.write("version: 1\ngroups: {}\n")
        # positive control (fix round 2 item 6): without exclude, the untracked
        # file IS in the map -- proves the assertion below is actually testing
        # the exclusion, not an untracked-others path that never picks it up.
        m3_control = diff_map.hunk_map(d, "main")
        self.assertIn(".panopticon.yml", m3_control)
        m3 = diff_map.hunk_map(d, "main", exclude=("panopticon.yml", ".panopticon.yml"))
        self.assertNotIn(".panopticon.yml", m3)

    def test_diff_flags_are_pinned(self):
        # #5.0-08: pin mnemonicPrefix/quotepath/prefixes so a user's gitconfig
        # can't reshape the `+++ b/<path>` headers parse_unified_diff keys on.
        seen = {}
        with mock.patch.object(diff_map, "_run_git", side_effect=self._fake_git(seen)):
            diff_map.hunk_map(".", "main")
        argv = seen["diff"]
        self.assertIn("diff.mnemonicPrefix=false", argv)
        self.assertIn("core.quotepath=false", argv)
        self.assertIn("--unified=0", argv)
        self.assertIn("--no-color", argv)
        self.assertIn("--find-renames", argv)
        self.assertIn("--src-prefix=a/", argv)
        self.assertIn("--dst-prefix=b/", argv)
        # #1738 fix round 1: and the diff is read as BYTES, because text mode
        # rewrites a lone \r to \n and forges a diff line out of payload.
        self.assertFalse(seen["text"])


class TestNonUtf8GitPaths(unittest.TestCase):
    """Real Git index entries exercise paths this macOS filesystem refuses."""

    def _repo_with_bad_index_path(self, rename):
        d = _make_repo(self)
        path = b"bad_\xe9.py"
        if rename:
            blob = _git_bytes(d, b"rev-parse", b"HEAD:a.py").strip()
            _git_bytes(d, b"update-index", b"--force-remove", b"a.py")
        else:
            blob = _git_bytes(d, b"hash-object", b"-w", b"--stdin",
                              input_bytes=b"fixture\n").strip()
        _git_bytes(d, b"update-index", b"--add", b"--cacheinfo",
                   b"100644," + blob + b"," + path)
        return d

    def test_real_git_rejects_quoted_and_unquoted_bad_filename(self):
        for quote_path in (b"true", b"false"):
            with self.subTest(quote_path=quote_path):
                d = self._repo_with_bad_index_path(rename=False)
                raw = _git_bytes(d, b"-c", b"core.quotePath=" + quote_path,
                                 b"diff", b"--cached", b"--unified=0",
                                 b"--src-prefix=a/", b"--dst-prefix=b/", b"HEAD")
                self.assertIn(b"\\351" if quote_path == b"true" else b"\xe9", raw)
                with self.assertRaisesRegex(diff_map.DiffMapError, "UTF-8"):
                    diff_map.parse_unified_diff(raw.decode("utf-8", "surrogateescape"))

    def test_real_git_rejects_bad_filename_in_pure_rename(self):
        for quote_path in (b"true", b"false"):
            with self.subTest(quote_path=quote_path):
                d = self._repo_with_bad_index_path(rename=True)
                raw = _git_bytes(d, b"-c", b"core.quotePath=" + quote_path,
                                 b"diff", b"--cached", b"--find-renames",
                                 b"--unified=0", b"--src-prefix=a/",
                                 b"--dst-prefix=b/", b"HEAD")
                self.assertIn(b"similarity index 100%", raw)
                self.assertIn(
                    b'rename to "bad_\\351.py"' if quote_path == b"true"
                    else b"rename to bad_\xe9.py", raw,
                )
                with self.assertRaisesRegex(diff_map.DiffMapError, "UTF-8"):
                    diff_map.parse_unified_diff(raw.decode("utf-8", "surrogateescape"))


class TestHunkMapUntrackedQuotedPaths(unittest.TestCase):
    r"""#1739: `git ls-files --others` C-quotes the same names, and the
    quoted spelling then failed `open()` with FileNotFoundError -- an OSError
    the loop swallowed with a bare `continue`. The untracked file was in
    neither the hunk map nor any warning.
    """

    def _repo(self):
        return _make_repo(self)

    def test_untracked_files_with_quoted_names_are_keyed_by_their_real_name(self):
        d = self._repo()
        _git(d, "checkout", "-q", "-b", "feat")
        names = ["naïve.txt", 'we"ird.txt', "back\\slash.txt"]
        for name in names:
            with open(os.path.join(d, name), "w", encoding="utf-8") as fh:
                fh.write("x\ny\n")
        m = diff_map.hunk_map(d, "main")
        for name in names:
            self.assertIn(name, m)
            self.assertEqual(m[name], [(1, 2)])

    def test_a_newline_in_an_untracked_name_does_not_fragment_the_listing(self):
        # -z frames on NUL; splitlines() would have split this one name into
        # two bogus entries (and str.splitlines() splits on \r, \x0c, \x85 and
        # U+2028 as well -- #1738's lesson, applied to the file list).
        d = self._repo()
        _git(d, "checkout", "-q", "-b", "feat")
        name = "two\nlines.txt"
        try:
            with open(os.path.join(d, name), "w", encoding="utf-8") as fh:
                fh.write("x\n")
        except OSError:
            self.skipTest("filesystem refuses a newline in a filename")
        m = diff_map.hunk_map(d, "main")
        self.assertEqual(sorted(m), [name])

    def test_an_unreadable_untracked_file_is_reported_not_swallowed(self):
        d = self._repo()
        _git(d, "checkout", "-q", "-b", "feat")
        p = os.path.join(d, "locked.txt")
        with open(p, "w", encoding="utf-8") as fh:
            fh.write("x\n")
        os.chmod(p, 0)
        self.addCleanup(os.chmod, p, 0o644)
        try:
            with open(p, "rb"):
                self.skipTest("this user can read a mode-000 file (root?)")
        except OSError:
            pass
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            m = diff_map.hunk_map(d, "main")
        self.assertNotIn("locked.txt", m)
        self.assertIn("locked.txt", err.getvalue())


class TestClassify(unittest.TestCase):
    HM = {"a.py": [(10, 12)], "empty.py": []}
    def _f(self, path, ls=None, le=None):
        loc = {"file": path}
        if ls is not None: loc["line_start"] = ls
        if le is not None: loc["line_end"] = le
        return {"location": loc}

    def test_inside_hunk_is_on_diff_distance_zero(self):
        d = diff_map.classify(self._f("a.py", 11), self.HM)
        self.assertEqual((d["on_diff"], d["hunk"], d["distance"]), (True, [10, 12], 0))

    def test_within_tolerance_boundary_on_at_5_off_at_6(self):
        self.assertTrue(diff_map.classify(self._f("a.py", 17), self.HM, 5)["on_diff"])   # 17 vs end 12 = 5
        off = diff_map.classify(self._f("a.py", 18), self.HM, 5)                          # = 6
        self.assertFalse(off["on_diff"]); self.assertEqual(off["distance"], 6)

    def test_range_overlap_counts(self):
        self.assertTrue(diff_map.classify(self._f("a.py", 1, 50), self.HM)["on_diff"])

    def test_lineless_on_changed_file_fails_open(self):
        self.assertTrue(diff_map.classify(self._f("empty.py"), self.HM)["on_diff"])

    def test_file_not_in_map_is_pre_existing(self):
        d = diff_map.classify(self._f("other.py", 3), self.HM)
        self.assertEqual((d["on_diff"], d["distance"]), (False, None))

    def test_multiline_off_diff_uses_four_corners(self):
        # finding [1, 3] vs range (10, 12): nearest gap is le=3 to s=10 = 7
        d = diff_map.classify(self._f("a.py", 1, 3), self.HM, 5)
        self.assertFalse(d["on_diff"])
        self.assertEqual(d["distance"], 7)

    def test_dotslash_prefix_still_matches(self):
        # #5.0-06: './a.py' must still match the git-relative key 'a.py'.
        self.assertTrue(diff_map.classify(self._f("./a.py", 11), self.HM)["on_diff"])

    def test_absolute_path_relativizes_against_repo_root(self):
        # #5.0-06: a worktree-absolute location.file (what --pr panels emit)
        # must match the git-relative hunk key once relativized against the root.
        d = diff_map.classify(self._f("/repo/a.py", 11), self.HM, repo_root="/repo")
        self.assertTrue(d["on_diff"])
        # and without a repo_root it (correctly) cannot relativize -> pre-existing,
        # which is exactly the silent-drop the fix closes when repo_root IS passed.
        self.assertFalse(diff_map.classify(self._f("/repo/a.py", 11), self.HM)["on_diff"])

    def test_norm_key(self):
        self.assertEqual(diff_map.norm_key("a\\b.py"), "a/b.py")
        self.assertEqual(diff_map.norm_key("./a.py"), "a.py")
        self.assertEqual(diff_map.norm_key("/repo/sub/a.py", "/repo"), "sub/a.py")
        self.assertEqual(diff_map.norm_key("/outside/a.py", "/repo"), "/outside/a.py")


class TestDiffAnchors(unittest.TestCase):
    def _repo(self):
        return _make_repo(self)

    def test_anchors_resolve_base_fork_and_head(self):
        d = self._repo()
        base_sha = subprocess.run(["git", "-C", d, "rev-parse", "main"],
                                  capture_output=True, text=True, check=True).stdout.strip()
        _git(d, "checkout", "-q", "-b", "feat")
        with open(os.path.join(d, "a.py"), "a") as fh:
            fh.write("line2\n")
        _git(d, "commit", "-qam", "c")
        head_sha = subprocess.run(["git", "-C", d, "rev-parse", "HEAD"],
                                  capture_output=True, text=True, check=True).stdout.strip()
        anchors = diff_map.diff_anchors(d, "main")
        self.assertEqual(anchors["base_commit"], base_sha)
        self.assertEqual(anchors["delta_start"], base_sha)  # merge-base(HEAD, main)
        self.assertEqual(anchors["delta_end"], head_sha)

    def test_anchors_unresolvable_base_returns_none_fields(self):
        d = self._repo()
        anchors = diff_map.diff_anchors(d, "no-such-ref")
        self.assertIsNone(anchors["base_commit"])
        self.assertIsNone(anchors["delta_start"])
        self.assertIsNotNone(anchors["delta_end"])   # HEAD always resolves

    def test_anchors_no_base_returns_none_for_base_and_start(self):
        d = self._repo()
        anchors = diff_map.diff_anchors(d, None)
        self.assertIsNone(anchors["base_commit"])
        self.assertIsNone(anchors["delta_start"])
        self.assertIsNotNone(anchors["delta_end"])


class TestPrWorktree(unittest.TestCase):
    def test_acquire_reads_base_and_adds_worktree(self):
        # `acquire_pr` calls `_sync_config` on BOTH paths (#1681), and that
        # refuses a worktree directory that is not there -- so a fake `git
        # worktree add` has to leave a real directory behind the way git does.
        # Pinned as a temp dir created here and removed after: with a
        # hard-coded `/tmp/wt-pr7` this passed only while a stale one from an
        # earlier run happened to still exist, and failed on a clean machine.
        wt = tempfile.mkdtemp(prefix="panopticon-test-wt-")
        self.addCleanup(shutil.rmtree, wt, ignore_errors=True)
        calls = []
        fetched_ref = []
        def runner(argv, **kw):
            calls.append(argv)
            out = ""
            if argv[:3] == ["gh", "pr", "view"]:
                out = '{"baseRefName": "main"}'
            elif "fetch" in argv:
                fetched_ref.append(argv[-1].split(":", 1)[1])
            elif "rev-parse" in argv:
                out = "deadbeef\n"
            class R: returncode = 0; stdout = out; stderr = ""
            return R()
        with mock.patch.object(diff_map, "_worktree_dir", return_value=wt):
            info = diff_map.acquire_pr(7, repo=".", runner=runner)
        self.assertEqual(info["base"], "main")
        self.assertEqual(info["worktree"], wt)
        worktree = next(a for a in calls if "worktree" in a and "add" in a)
        self.assertEqual(worktree[-1], "deadbeef")
        self.assertNotIn("FETCH_HEAD", " ".join(" ".join(a) for a in calls))
        self.assertTrue(any("--no-write-fetch-head" in a for a in calls))
        self.assertTrue(any("update-ref" in a and fetched_ref[0] in a for a in calls))
        self.assertTrue(any("refs/pull/7/head" in " ".join(a) for a in calls))

    def test_acquire_is_idempotent_deterministic_path(self):
        repo = "."
        # M9: a temp dir with `_worktree_dir` stubbed at it, like this test's
        # three siblings -- this used to compute the REAL deterministic
        # `panopticon-pr-7-<hash>` path and rmtree it on cleanup, which is a
        # live --pr worktree on any machine that happens to have one open.
        # The path's own determinism is pinned by
        # test_worktree_dir_does_not_resolve_leaf_symlink, against a stubbed
        # tempdir; what THIS test is about is create-once/reuse-after.
        wt = tempfile.mkdtemp(prefix="panopticon-test-wt-")
        self.addCleanup(shutil.rmtree, wt, ignore_errors=True)
        calls = {"fetch": 0, "wtadd": 0}
        def runner(argv, **kw):
            out = ""
            if argv[:3] == ["gh", "pr", "view"]:
                out = '{"baseRefName": "main"}'
            elif "worktree" in argv and "list" in argv:
                # Real `git worktree list` (no --porcelain) format:
                # "<path>  <sha> [<branch>]" / "(detached HEAD)". Only
                # registered (i.e. after the worktree add) on later calls.
                out = "%s  deadbeef [detached HEAD]\n" % wt if calls["wtadd"] > 0 else ""
            elif "worktree" in argv and "add" in argv:
                calls["wtadd"] += 1
                os.makedirs(wt, exist_ok=True)
            elif "fetch" in argv:
                calls["fetch"] += 1
            elif "rev-parse" in argv:
                out = "deadbeef\n"
            class R: returncode = 0; stdout = out; stderr = ""
            return R()
        with mock.patch.object(diff_map, "_worktree_dir", return_value=wt):
            a = diff_map.acquire_pr(7, repo=repo, runner=runner)
            b = diff_map.acquire_pr(7, repo=repo, runner=runner)
        self.assertEqual(a["worktree"], b["worktree"])
        self.assertEqual(a["worktree"], wt)
        self.assertEqual(a["base"], "main")
        self.assertEqual(a["head_sha"], "deadbeef")
        self.assertEqual(b["head_sha"], "deadbeef")
        self.assertEqual(calls["wtadd"], 1)   # created once, reused second time
        self.assertEqual(calls["fetch"], 1)   # no re-fetch on reuse

    def test_acquire_raises_loudly_on_gh_failure(self):
        def runner(argv, **kw):
            class R: returncode = 1; stdout = ""; stderr = "gh: no PR 999"
            return R()
        with self.assertRaises(RuntimeError):
            diff_map.acquire_pr(999, repo=".", runner=runner)

    def test_acquire_raises_loudly_on_invalid_gh_json(self):
        def runner(argv, **kw):
            class R: returncode = 0; stdout = "not json"; stderr = ""
            return R()
        with self.assertRaisesRegex(RuntimeError, "invalid JSON"):
            diff_map.acquire_pr(7, repo=".", runner=runner)

    def test_acquire_raises_loudly_on_missing_baseRefName(self):
        def runner(argv, **kw):
            class R: returncode = 0; stdout = '{"number": 7}'; stderr = ""
            return R()
        with self.assertRaisesRegex(RuntimeError, "missing baseRefName"):
            diff_map.acquire_pr(7, repo=".", runner=runner)

    def test_acquire_rejects_symlink_worktree(self):
        def runner(argv, **kw):
            if argv[:3] == ["gh", "pr", "view"]:
                return mock.Mock(returncode=0, stdout='{"baseRefName": "main"}', stderr="")
            return mock.Mock(returncode=0, stdout="", stderr="")

        with tempfile.TemporaryDirectory() as d:
            target_dir = os.path.join(d, "target")
            os.makedirs(target_dir)
            symlink_path = os.path.join(d, "symlink_wt")
            os.symlink(target_dir, symlink_path)
            with mock.patch.object(diff_map, "_worktree_dir", return_value=symlink_path):
                with self.assertRaisesRegex(RuntimeError, "insecure symlink detected"):
                    diff_map.acquire_pr(7, repo=".", runner=runner)

    def test_worktree_dir_does_not_resolve_leaf_symlink(self):
        # #run8 COD-X0X: _worktree_dir must NOT realpath its deterministic leaf.
        # If it did, an attacker-planted symlink at the leaf would be silently
        # followed and acquire_pr's islink guard (which inspects the returned
        # path) would only ever see the resolved, non-symlink target.
        with tempfile.TemporaryDirectory() as d:
            with mock.patch.object(diff_map.tempfile, "gettempdir", return_value=d):
                wt = diff_map._worktree_dir(".", 7)
            self.assertEqual(os.path.dirname(wt), os.path.realpath(d))
            target = os.path.join(d, "attacker")
            os.makedirs(target)
            os.symlink(target, wt)                 # plant symlink AT the leaf
            with mock.patch.object(diff_map.tempfile, "gettempdir", return_value=d):
                wt_again = diff_map._worktree_dir(".", 7)
            # deterministic + unresolved: same leaf path, and it IS seen as a link
            self.assertEqual(wt_again, wt)
            self.assertTrue(os.path.islink(wt_again))

    def test_acquire_rejects_symlink_worktree_via_real_worktree_dir(self):
        # #run8 COD-X0X: exercise the REAL _worktree_dir (not a monkeypatched
        # stub) with an attacker-planted symlink at the deterministic leaf, to
        # prove acquire_pr's islink guard actually fires on the true code path.
        def runner(argv, **kw):
            if argv[:3] == ["gh", "pr", "view"]:
                return mock.Mock(returncode=0, stdout='{"baseRefName": "main"}', stderr="")
            return mock.Mock(returncode=0, stdout="", stderr="")
        with tempfile.TemporaryDirectory() as d:
            with mock.patch.object(diff_map.tempfile, "gettempdir", return_value=d):
                wt = diff_map._worktree_dir(".", 7)
                target = os.path.join(d, "attacker")
                os.makedirs(target)
                os.symlink(target, wt)             # pre-plant the hostile leaf
                with self.assertRaisesRegex(RuntimeError, "insecure symlink detected"):
                    diff_map.acquire_pr(7, repo=".", runner=runner)

    def test_release_is_tolerant(self):
        def runner(argv, **kw):
            class R: returncode = 1; stdout = ""; stderr = "not a worktree"
            return R()
        diff_map.release_worktree("/tmp/gone", runner=runner)  # must not raise

    def test_acquire_pr_calls_carry_timeout(self):
        # #1081: every git/gh call in acquire_pr is time-bounded.
        # Real temp worktree for the same reason as the two tests above: the
        # create path ends in `_sync_config`, which refuses a missing tree.
        #
        # #2012: `_PR_TIMEOUT` is now the bound on a safe_git call rather than
        # the timeout of each launch inside it -- the probe spends ONE deadline
        # across its preflight and its command, so a confined call's launches
        # carry the REMAINING budget. That is still "every call is bounded by
        # _PR_TIMEOUT", which is what #1081 asked for, and a regression that
        # dropped the bound (None, or a larger number) fails either branch.
        wt = tempfile.mkdtemp(prefix="panopticon-test-wt-")
        self.addCleanup(shutil.rmtree, wt, ignore_errors=True)
        seen = []
        def runner(argv, **kw):
            seen.append((list(argv), kw.get("timeout")))
            out = ""
            if argv[:3] == ["gh", "pr", "view"]:
                out = '{"baseRefName": "main"}'
            elif "rev-parse" in argv:
                out = "deadbeef\n"
            class R: returncode = 0; stdout = out; stderr = ""
            return R()
        with mock.patch.object(diff_map, "_worktree_dir", return_value=wt):
            diff_map.acquire_pr(7, repo=".", runner=runner)
        self.assertTrue(seen)
        for argv, timeout in seen:
            self.assertIsNotNone(timeout, argv)
            self.assertGreater(timeout, 0, argv)
            self.assertLessEqual(timeout, diff_map._PR_TIMEOUT, argv)
        # The two calls that keep the operator's environment are a single launch
        # each, so they carry the whole bound exactly.
        operator = [t for argv, t in seen
                    if argv[:3] == ["gh", "pr", "view"] or "fetch" in argv]
        self.assertEqual(len(operator), 2, seen)
        self.assertTrue(all(t == diff_map._PR_TIMEOUT for t in operator), operator)

    def test_acquire_pr_timeout_raises_runtimeerror(self):
        def runner(argv, **kw):
            raise subprocess.TimeoutExpired(argv, kw.get("timeout"))
        with self.assertRaises(RuntimeError):
            diff_map.acquire_pr(7, repo=".", runner=runner)   # bounded, loud

    def test_worktree_list_timeout_raises_runtimeerror(self):
        # #run7 QAL-C2D: a stalled `git worktree list` must raise RuntimeError
        # (which driver.run's #5.0-14 handler catches), not leak a raw
        # TimeoutExpired as an uncaught traceback.
        def runner(argv, **kw):
            if argv[:2] == ["gh", "pr"]:
                return mock.Mock(returncode=0, stdout='{"baseRefName": "main"}',
                                 stderr="")
            if "worktree" in argv and "list" in argv:
                raise subprocess.TimeoutExpired(argv, kw.get("timeout"))
            return mock.Mock(returncode=0, stdout="", stderr="")
        with self.assertRaises(RuntimeError):
            diff_map.acquire_pr(7, repo=".", runner=runner)

    def test_release_passes_timeout_and_tolerates_hang(self):
        # #1082: release_worktree bounds the git call and a hung teardown is
        # tolerated. #2012 routes it through `safe_git.mutate`, so the FIRST
        # launch is the preflight's config read and it carries the shared
        # deadline rather than the flat bound -- one launch, one bound, and the
        # hang still swallowed.
        seen = []
        def runner(argv, **kw):
            seen.append(kw.get("timeout"))
            raise subprocess.TimeoutExpired(argv, kw.get("timeout"))
        diff_map.release_worktree("/tmp/x", runner=runner)   # must not raise
        self.assertEqual(len(seen), 1, seen)
        self.assertGreater(seen[0], 0)
        self.assertLessEqual(seen[0], diff_map._PR_TIMEOUT)

    def test_release_is_confined_and_still_tolerates_a_refusal(self):
        # #2012: the teardown was the second written exemption from the
        # target-git guard. It is a `safe_git.mutate` call now, and the tolerance
        # that justified the exemption is unchanged -- a REFUSED teardown (the
        # one case #2013 kept) leaks a temp directory rather than raising.
        seen = []
        def runner(argv, **kw):
            seen.append(list(argv))
            raise AssertionError("no launch expected after the refusal")
        with mock.patch.object(diff_map.safe_git, "mutate",
                               side_effect=diff_map.safe_git.RepositoryRefused("nope")):
            diff_map.release_worktree("/tmp/x", runner=runner)   # must not raise
        self.assertEqual(seen, [])

    def test_release_goes_through_the_mutating_entry_point(self):
        # The argv the confined teardown runs, and that it is `mutate` (which
        # refuses every other write) rather than `probe`.
        calls = []
        def mutate(root, args, **kw):
            calls.append((root, list(args), kw.get("timeout")))
            return mock.Mock(returncode=0, stdout="", stderr="")
        with mock.patch.object(diff_map.safe_git, "mutate", mutate):
            diff_map.release_worktree("/tmp/x", repo="/repo")
        self.assertEqual(calls, [("/repo", ["worktree", "remove", "--force", "/tmp/x"],
                                 diff_map._PR_TIMEOUT)])

    def test_acquire_pr_prints_sync_notes_with_the_pr_prefix(self):
        # minor 7: acquire_pr's own print (not _sync_config's return value) must
        # carry the "panopticon --pr: " prefix for whatever _sync_config reports.
        with tempfile.TemporaryDirectory() as d:
            repo = os.path.join(d, "repo"); os.makedirs(repo)
            with open(os.path.join(repo, "panopticon.yml"), "w", encoding="utf-8") as fh:
                fh.write("version: 1\ngroups: {}\n")
            wt = os.path.join(d, "wt"); os.makedirs(wt)
            with open(os.path.join(wt, "panopticon.yml"), "w", encoding="utf-8") as fh:
                fh.write("version: 1\ngroups:\n  Evil:\n    match: ['**']\n")

            def runner(argv, **kw):
                out = ""
                if argv[:3] == ["gh", "pr", "view"]:
                    out = '{"baseRefName": "main"}'
                elif "rev-parse" in argv:
                    out = "deadbeef\n"
                class R: returncode = 0; stdout = out; stderr = ""
                return R()

            buf = io.StringIO()
            with mock.patch.object(diff_map, "_worktree_dir", return_value=wt):
                with contextlib.redirect_stderr(buf):
                    diff_map.acquire_pr(7, repo=repo, runner=runner)
            self.assertIn("panopticon --pr: ", buf.getvalue())
            self.assertIn("overwrote", buf.getvalue())


class TestPrAcquisitionIsConfined(unittest.TestCase):
    """#2012: `--pr` acquisition must run no command the TARGET authored.

    The end-to-end exercise the issue asked for, on real repositories: a bare
    "origin", an operator clone configured the way a repository's own
    CONTRIBUTING file asks people to configure it (`git config core.hooksPath
    .githooks`, plus a content filter), and a PR head fetched into a throwaway
    worktree. Nothing here is a mock: `acquire_pr` runs its real steps, and the
    only call the injected runner answers itself is `gh pr view`, which needs a
    GitHub API.

    Three planted vectors, three mechanisms, each measured on git 2.50 and each
    proved LIVE with plain git before its absence is asserted -- an absent
    marker is also what an inert fixture produces:

      - `reference-transaction` fires on the acquisition's FETCH (the one call
        that keeps the operator's environment, for the credential helper, and
        so carries the hooks pin by hand);
      - `post-checkout` fires on `worktree add`, from the repository's own
        `.githooks/` directory;
      - `filter.evil.smudge` runs on `worktree add` and its output REPLACES the
        committed bytes, so `payload.txt` reads `SMUDGED` rather than what the
        PR actually committed. A review of the replaced bytes reviews the
        filter's output, not the PR.

    A fourth vector is the fetch's own, and it is REFUSED rather than confined
    (#2041, owner ruling "refuse with remedy"): the fetch keeps the operator's
    environment, so a repo-local `core.sshCommand` or `remote.<name>.uploadpack`
    still runs on it under both of the pins it carries (measured in #2012's
    review). Acquisition reads the checkout's LOCAL config immediately before
    the fetch and refuses, naming the key and the remedy -- move the setting to
    the global config, which the fetch still honours.
    """

    MARKERS = ("hook-ran", "ref-hook-ran", "smudge-ran")
    PAYLOAD = b"COMMITTED PAYLOAD\n"

    def _marker_script(self, base, marker):
        return "#!/bin/sh\nprintf hit > %s\nexit 0\n" % shlex.quote(
            os.path.join(base, marker))

    def _write(self, path, text, mode=None):
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        if mode is not None:
            os.chmod(path, mode)

    def _fixture(self):
        """(base, clone, pr_sha): a hostile PR head fetchable from a bare remote.

        The hooks live on MAIN as well as on the PR branch, because a relative
        `core.hooksPath` resolves against the top of the CURRENT working tree
        (measured: with the hook only on the PR head, `worktree add` looked in
        the operator's own checkout and found nothing). That is the realistic
        shape anyway -- the operator ran the repository's own setup line, and the
        repository's committed `.githooks/` is what it points at.
        """
        base = self.enterContext(tempfile.TemporaryDirectory())
        origin = os.path.join(base, "origin.git")
        seed = os.path.join(base, "seed")
        clone = os.path.join(base, "clone")
        _git(base, "init", "-q", "--bare", "-b", "main", origin)
        _git(base, "init", "-q", "-b", "main", seed)
        _git(seed, "config", "user.email", "t@t")
        _git(seed, "config", "user.name", "t")
        os.makedirs(os.path.join(seed, ".githooks"))
        for name, marker in (("post-checkout", "hook-ran"),
                             ("reference-transaction", "ref-hook-ran")):
            self._write(os.path.join(seed, ".githooks", name),
                        self._marker_script(base, marker), 0o755)
        self._write(os.path.join(seed, "README.md"), "base\n")
        _git(seed, "add", "-A")
        _git(seed, "commit", "-qm", "init")
        _git(seed, "remote", "add", "origin", origin)
        _git(seed, "push", "-q", "origin", "main")

        _git(seed, "checkout", "-q", "-b", "pr")
        self._write(os.path.join(seed, ".gitattributes"), "*.txt filter=evil\n")
        # No `filter.evil` is configured HERE, so the blob is committed raw and
        # the smudge output below is provably not what the PR authored.
        self._write(os.path.join(seed, "evil.sh"),
                    "printf hit > %s\nprintf 'SMUDGED\\n'\n"
                    % shlex.quote(os.path.join(base, "smudge-ran")))
        with open(os.path.join(seed, "payload.txt"), "wb") as fh:
            fh.write(self.PAYLOAD)
        _git(seed, "add", "-A")
        _git(seed, "commit", "-qm", "hostile")
        pr_sha = self._read(seed, "rev-parse", "HEAD")
        _git(seed, "push", "-q", "origin", "pr")
        # What GitHub exposes as the PR head, and what `acquire_pr` fetches.
        _git(origin, "update-ref", "refs/pull/7/head", pr_sha)

        _git(base, "clone", "-q", origin, clone)
        # The operator's own repo-local config, set AFTER the clone so the clone
        # itself runs nothing. Every one of these is a line a real repository
        # asks for; none of them is fetched, which is why config is the vector.
        _git(clone, "config", "core.hooksPath", ".githooks")
        _git(clone, "config", "filter.evil.smudge", "sh ./evil.sh")
        _git(clone, "config", "filter.evil.required", "true")
        return base, clone, pr_sha

    def _read(self, repo, *args):
        return subprocess.run(["git", "-C", repo, *args], check=True,
                              capture_output=True, text=True, timeout=30).stdout.strip()

    def _marker(self, base, name):
        return os.path.join(base, name)

    def _prove_the_fixture_is_live(self, base, clone, pr_sha):
        """Vacuity guard: plain git DOES run all three, then clean up."""
        live = os.path.join(base, "live-wt")
        _git(clone, "fetch", "-q", "--no-write-fetch-head", "origin",
             "refs/pull/7/head:refs/panopticon/live")
        self.assertTrue(os.path.exists(self._marker(base, "ref-hook-ran")),
                        "fixture is inert: the fetch never ran reference-transaction")
        _git(clone, "worktree", "add", "--detach", live, pr_sha)
        self.assertTrue(os.path.exists(self._marker(base, "hook-ran")),
                        "fixture is inert: worktree add never ran post-checkout")
        self.assertTrue(os.path.exists(self._marker(base, "smudge-ran")),
                        "fixture is inert: worktree add never ran the smudge filter")
        with open(os.path.join(live, "payload.txt"), "rb") as fh:
            self.assertEqual(fh.read(), b"SMUDGED\n",
                             "fixture is inert: the filter did not replace the blob")
        _git(clone, "worktree", "remove", "--force", live)
        _git(clone, "update-ref", "-d", "refs/panopticon/live")
        for name in self.MARKERS:            # after the cleanup, which re-fires
            os.remove(self._marker(base, name))

    def _runner(self, global_config=None):
        """`gh pr view` answered here; every git call is the real thing.

        `global_config` (#2041) points the calls that keep the OPERATOR's
        environment at a throwaway `GIT_CONFIG_GLOBAL`, so the refusal's remedy
        can be proved without writing a `remote.origin.uploadpack` into the
        test HOME every other test in this process shares. It reaches the fetch
        and nothing else: every confined call passes its own `env=`, which this
        never overrides.
        """
        def runner(argv, **kwargs):
            if list(argv[:3]) == ["gh", "pr", "view"]:
                return subprocess.CompletedProcess(argv, 0, '{"baseRefName": "main"}', "")
            if global_config is not None and "env" not in kwargs:
                kwargs["env"] = dict(os.environ, GIT_CONFIG_GLOBAL=global_config)
            return subprocess.run(argv, **kwargs)
        return runner

    def test_acquire_and_release_run_no_hook_and_no_smudge_filter(self):
        base, clone, pr_sha = self._fixture()
        self._prove_the_fixture_is_live(base, clone, pr_sha)
        wt = diff_map._worktree_dir(clone, 7)
        self.addCleanup(shutil.rmtree, wt, ignore_errors=True)

        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            info = diff_map.acquire_pr(7, repo=clone, runner=self._runner())

        for name in self.MARKERS:
            self.assertFalse(os.path.exists(self._marker(base, name)),
                             "%s: the target ran code during acquisition" % name)
        self.assertEqual(info["worktree"], wt)
        self.assertEqual(info["base"], "main")
        self.assertEqual(info["head_sha"], pr_sha)
        self.assertTrue(os.path.isdir(wt))
        self.assertEqual(self._read(wt, "rev-parse", "HEAD"), pr_sha)
        # The reviewed bytes are the COMMITTED bytes: no filter rewrote them.
        with open(os.path.join(wt, "payload.txt"), "rb") as fh:
            self.assertEqual(fh.read(), self.PAYLOAD)
        # The throwaway fetch ref is deleted even though the worktree survives.
        self.assertEqual(self._read(clone, "for-each-ref", "--format=%(refname)",
                                    "refs/panopticon/"), "")
        # The neutralization is disclosed by key, never by value (#2013).
        self.assertIn("suppressed 'filter.evil.smudge' in '.'", err.getvalue())
        self.assertIn("suppressed 'filter.evil.required' in '.'", err.getvalue())
        self.assertNotIn("evil.sh", err.getvalue())

        with contextlib.redirect_stderr(io.StringIO()):
            diff_map.release_worktree(wt, repo=clone, runner=self._runner())
        self.assertFalse(os.path.exists(wt))
        for name in self.MARKERS:
            self.assertFalse(os.path.exists(self._marker(base, name)),
                             "%s: the target ran code during teardown" % name)

    def test_reacquiring_reuses_the_worktree_and_still_runs_nothing(self):
        """The resume path, through real git rather than a fake runner.

        `worktree list` is parsed for the deterministic path, and `rev-parse
        HEAD` runs in the PR WORKTREE -- a second repository root, whose `.git`
        is a file and whose tree is the attacker's. A fake runner cannot see
        either of those refused, which is the whole reason this one is real
        (#1877's lesson, in the small).
        """
        base, clone, pr_sha = self._fixture()
        self._prove_the_fixture_is_live(base, clone, pr_sha)
        wt = diff_map._worktree_dir(clone, 7)
        self.addCleanup(shutil.rmtree, wt, ignore_errors=True)
        with contextlib.redirect_stderr(io.StringIO()):
            first = diff_map.acquire_pr(7, repo=clone, runner=self._runner())
            second = diff_map.acquire_pr(7, repo=clone, runner=self._runner())
        self.assertEqual(first, second)
        self.assertEqual(second["head_sha"], pr_sha)
        # Reused, not re-created: the main worktree and exactly one throwaway.
        listing = [line for line in self._read(clone, "worktree", "list").splitlines()
                   if line.strip()]
        self.assertEqual(len(listing), 2, listing)
        self.assertTrue(any(line.split()[:1] == [wt] for line in listing), listing)
        for name in self.MARKERS:
            self.assertFalse(os.path.exists(self._marker(base, name)),
                             "%s: the target ran code on the resume path" % name)
        with contextlib.redirect_stderr(io.StringIO()):
            diff_map.release_worktree(wt, repo=clone, runner=self._runner())
        self.assertFalse(os.path.exists(wt))


    # --- #2041: the fetch refuses a transport command setting ----------------
    TRANSPORT_MARKER = "transport-ran"

    def _refusing_command(self, base):
        """A transport command that records that it ran, and then FAILS.

        Failing is the point: a command that succeeded would let the fetch
        continue, and the test could not tell "never ran" from "ran and did no
        harm". The marker is the evidence in both directions.
        """
        path = os.path.join(base, "transport.sh")
        self._write(path, "#!/bin/sh\nprintf hit > %s\nexit 1\n"
                    % shlex.quote(self._marker(base, self.TRANSPORT_MARKER)), 0o755)
        return path

    def _prove_the_transport_command_runs(self, base, clone):
        """Vacuity guard: plain git, carrying the fetch's OWN pins, runs it.

        Both pins applied, because those are exactly what the shipped fetch
        carries -- the marker appearing under them is why #2041 is a residual of
        #2012 rather than something its pins already closed.
        """
        marker = self._marker(base, self.TRANSPORT_MARKER)
        proc = subprocess.run(
            ["git", "-C", clone, "-c", "core.fsmonitor=false",
             "-c", "core.hooksPath=" + diff_map.safe_git.no_hooks_path(),
             "fetch", "--no-write-fetch-head", "origin",
             "refs/pull/7/head:refs/panopticon/live"],
            capture_output=True, text=True, timeout=60)
        self.assertNotEqual(proc.returncode, 0, proc.stderr)
        self.assertTrue(os.path.exists(marker),
                        "fixture is inert: the fetch never ran the transport command")
        os.remove(marker)
        self.assertEqual(self._read(clone, "for-each-ref", "--format=%(refname)",
                                    "refs/panopticon/"), "",
                         "the proof fetch left a ref behind")

    def _assert_refused_naming(self, key, base, clone, wt):
        """`acquire_pr` refuses, names `key` and the remedy, and ran nothing."""
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(RuntimeError) as caught:
                diff_map.acquire_pr(7, repo=clone, runner=self._runner())
        # What it DID first: a refusal that still fetched would also raise.
        for name in (*self.MARKERS, self.TRANSPORT_MARKER):
            self.assertFalse(os.path.exists(self._marker(base, name)),
                             "%s: the refused acquisition ran code" % name)
        self.assertFalse(os.path.exists(wt), "a refused acquisition built a worktree")
        self.assertEqual(self._read(clone, "for-each-ref", "--format=%(refname)",
                                    "refs/panopticon/"), "",
                         "a refused acquisition fetched a ref")
        message = str(caught.exception)
        self.assertIn("refusing to fetch", message)
        self.assertIn(key, message)
        self.assertIn("git config --global", message)
        self.assertIn("git config --unset", message)
        # The KEY, never the VALUE: these are command lines (#2013's rule).
        self.assertNotIn("transport.sh", message)

    def test_a_repo_local_ssh_command_refuses_the_fetch_with_a_remedy(self):
        """(a) The measured shape: `core.sshCommand` on an `ssh://` remote."""
        base, clone, _pr_sha = self._fixture()
        _git(clone, "remote", "set-url", "origin", "ssh://git@example.invalid/x.git")
        _git(clone, "config", "core.sshCommand", self._refusing_command(base))
        self._prove_the_transport_command_runs(base, clone)
        wt = diff_map._worktree_dir(clone, 7)
        self.addCleanup(shutil.rmtree, wt, ignore_errors=True)
        # Lowercased section and variable: the case `config --list` prints.
        self._assert_refused_naming("core.sshcommand", base, clone, wt)

    def test_a_repo_local_uploadpack_refuses_the_fetch_with_a_remedy(self):
        """(b) The other measured shape: `remote.<name>.uploadpack`, which the
        local-path origin this fixture already clones from runs LOCALLY."""
        base, clone, _pr_sha = self._fixture()
        _git(clone, "config", "remote.origin.uploadpack", self._refusing_command(base))
        self._prove_the_transport_command_runs(base, clone)
        wt = diff_map._worktree_dir(clone, 7)
        self.addCleanup(shutil.rmtree, wt, ignore_errors=True)
        self._assert_refused_naming("remote.origin.uploadpack", base, clone, wt)

    def test_the_remedy_the_refusal_names_actually_works(self):
        """(c) The SAME key in the operator's GLOBAL config is honoured.

        Not a cosmetic difference: the refusal tells the operator to move the
        line to `--global`, so acquisition has to succeed there -- and on this
        local-path origin the moved `uploadpack` really does run (it execs the
        real `git upload-pack`), which is the proof that the refusal is scoped
        to the checkout's own file and the fetch is otherwise unchanged.
        """
        base, clone, pr_sha = self._fixture()
        marker = self._marker(base, self.TRANSPORT_MARKER)
        script = os.path.join(base, "global-uploadpack.sh")
        self._write(script, '#!/bin/sh\nprintf hit > %s\nexec git upload-pack "$@"\n'
                    % shlex.quote(marker), 0o755)
        operator_config = os.path.join(base, "operator-gitconfig")
        self._write(operator_config,
                    '[remote "origin"]\n\tuploadpack = "%s"\n' % script)
        wt = diff_map._worktree_dir(clone, 7)
        self.addCleanup(shutil.rmtree, wt, ignore_errors=True)
        with contextlib.redirect_stderr(io.StringIO()):
            info = diff_map.acquire_pr(7, repo=clone,
                                       runner=self._runner(global_config=operator_config))
        self.assertEqual(info["head_sha"], pr_sha)
        self.assertTrue(os.path.isdir(wt))
        self.assertTrue(os.path.exists(marker),
                        "the operator's own global config was not honoured by the fetch")
        for name in self.MARKERS:
            self.assertFalse(os.path.exists(self._marker(base, name)),
                             "%s: the target ran code during acquisition" % name)

    def _write_worktree_config(self, clone, text):
        """`$GIT_DIR/config.worktree` for the main worktree of `clone`."""
        with open(os.path.join(clone, ".git", "config.worktree"), "w",
                  encoding="utf-8") as fh:
            fh.write(text)

    def test_a_worktree_scoped_transport_setting_refuses_the_fetch(self):
        """C1: the same key, moved into `$GIT_DIR/config.worktree`.

        `extensions.worktreeConfig = true` in `.git/config` makes git read that
        second file, and the fetch obeys it -- both files are written with the
        one capability the threat model already grants (a `.git/config` written
        by something hostile), so a read that cannot see it is bypassable by the
        attacker it exists for.
        """
        base, clone, _pr_sha = self._fixture()
        _git(clone, "config", "extensions.worktreeConfig", "true")
        self._write_worktree_config(
            clone, '[remote "origin"]\n\tuploadpack = "%s"\n'
            % self._refusing_command(base))
        self._prove_the_transport_command_runs(base, clone)
        wt = diff_map._worktree_dir(clone, 7)
        self.addCleanup(shutil.rmtree, wt, ignore_errors=True)
        self._assert_refused_naming("remote.origin.uploadpack", base, clone, wt)

    def test_a_local_transport_setting_still_refuses_with_worktree_config_on(self):
        """The mirror of C1, and why the read is scope-FILTERED, not `--worktree`.

        Measured on git 2.50.1: with `extensions.worktreeConfig` ON,
        `git config --list --worktree --includes` lists the worktree file ALONE
        -- the `.git/config` keys are not in it. A read scoped that way would
        stop seeing the ordinary repo-local key, so the attacker would only have
        to enable the extension, leave `config.worktree` empty, and keep the
        payload exactly where it already was.
        """
        base, clone, _pr_sha = self._fixture()
        _git(clone, "config", "extensions.worktreeConfig", "true")
        self._write_worktree_config(clone, "")
        _git(clone, "config", "remote.origin.uploadpack", self._refusing_command(base))
        self._prove_the_transport_command_runs(base, clone)
        wt = diff_map._worktree_dir(clone, 7)
        self.addCleanup(shutil.rmtree, wt, ignore_errors=True)
        self._assert_refused_naming("remote.origin.uploadpack", base, clone, wt)

    def test_acquisition_still_works_in_a_checkout_that_has_another_worktree(self):
        """No transport key, a second worktree, no `worktreeConfig`: acquire.

        Measured on git 2.50.1: `git config --list --worktree --includes` DIES
        there (`rc=128`, "cannot be used with multiple working trees unless the
        config extension worktreeConfig is enabled"). That is an ordinary
        operator setup -- this project's own -- so a read spelled with that flag
        would turn every `--pr` run in such a checkout into a refusal to
        resolve the review root.
        """
        base, clone, pr_sha = self._fixture()
        _git(clone, "worktree", "add", "-q", "--detach",
             os.path.join(base, "operator-wt"), "HEAD")
        for name in self.MARKERS:      # the operator's own add fires their hook
            if os.path.exists(self._marker(base, name)):
                os.remove(self._marker(base, name))
        wt = diff_map._worktree_dir(clone, 7)
        self.addCleanup(shutil.rmtree, wt, ignore_errors=True)
        with contextlib.redirect_stderr(io.StringIO()):
            info = diff_map.acquire_pr(7, repo=clone, runner=self._runner())
        self.assertEqual(info["head_sha"], pr_sha)
        self.assertTrue(os.path.isdir(wt))
        for name in (*self.MARKERS, self.TRANSPORT_MARKER):
            self.assertFalse(os.path.exists(self._marker(base, name)),
                             "%s: the target ran code during acquisition" % name)

    def test_a_transport_setting_that_was_emptied_is_not_refused(self):
        """(d) The classifier tests VALUES: an emptied key executes nothing.

        Non-vacuous by construction -- the same key, set, refuses first.
        """
        base, clone, pr_sha = self._fixture()
        _git(clone, "config", "core.sshCommand", self._refusing_command(base))
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(RuntimeError):
                diff_map.acquire_pr(7, repo=clone, runner=self._runner())
        _git(clone, "config", "core.sshCommand", "")
        wt = diff_map._worktree_dir(clone, 7)
        self.addCleanup(shutil.rmtree, wt, ignore_errors=True)
        with contextlib.redirect_stderr(io.StringIO()):
            info = diff_map.acquire_pr(7, repo=clone, runner=self._runner())
        self.assertEqual(info["head_sha"], pr_sha)
        self.assertTrue(os.path.isdir(wt))
        for name in (*self.MARKERS, self.TRANSPORT_MARKER):
            self.assertFalse(os.path.exists(self._marker(base, name)),
                             "%s: the target ran code during acquisition" % name)

    def test_the_reuse_path_does_not_refuse_because_it_does_not_fetch(self):
        """(e) A resume performs no fetch, so there is nothing to refuse.

        Refusing here would strand a resumable run over a setting that cannot
        be reached on this path: the worktree is already built and pinned, and
        the two calls the reuse path makes are confined probes.
        """
        base, clone, pr_sha = self._fixture()
        wt = diff_map._worktree_dir(clone, 7)
        self.addCleanup(shutil.rmtree, wt, ignore_errors=True)
        with contextlib.redirect_stderr(io.StringIO()):
            first = diff_map.acquire_pr(7, repo=clone, runner=self._runner())
        _git(clone, "config", "core.sshCommand", self._refusing_command(base))
        with contextlib.redirect_stderr(io.StringIO()):
            second = diff_map.acquire_pr(7, repo=clone, runner=self._runner())
        self.assertEqual(first, second)
        self.assertEqual(second["head_sha"], pr_sha)
        for name in (*self.MARKERS, self.TRANSPORT_MARKER):
            self.assertFalse(os.path.exists(self._marker(base, name)),
                             "%s: the target ran code on the resume path" % name)
        with contextlib.redirect_stderr(io.StringIO()):
            diff_map.release_worktree(wt, repo=clone, runner=self._runner())
        self.assertFalse(os.path.exists(wt))


class TestDiffMapFailures(unittest.TestCase):
    def test_hunk_map_fallback_parser_and_failures(self):
        # coverage gap filler
        import scripts.diff_map as dm   # #run7 TST-G2A: one module identity (matches line 5)
        res = dm.diff_anchors(".", "nonexistent-branch-12345")
        self.assertIsNone(res.get("base_commit"))

        with self.assertRaises(dm.DiffMapError):   # #1256: fails closed
            dm.hunk_map(".", "nonexistent-base")

    def test_hunk_map_skips_untracked_symlink_outside_repo(self):
        # #1260: untracked-file line count must not follow symlinks outside repo.
        with tempfile.TemporaryDirectory() as outside_dir:
            outside = os.path.join(outside_dir, "outside_target.txt")
            with open(outside, "w", encoding="utf-8") as fh:
                fh.write("1\n2\n3\n4\n5\n")
            with tempfile.TemporaryDirectory() as d:
                _git(d, "init", "-q")
                _git(d, "config", "user.name", "T")
                _git(d, "config", "user.email", "t@example.com")
                with open(os.path.join(d, "committed.txt"), "w", encoding="utf-8") as fh:
                    fh.write("line\n")
                _git(d, "add", "committed.txt")
                _git(d, "commit", "-qm", "init")
                with open(os.path.join(d, "safe.txt"), "w", encoding="utf-8") as fh:
                    fh.write("a\nb\nc\n")
                os.symlink(outside, os.path.join(d, "link.txt"))
                hm = diff_map.hunk_map(d, "HEAD")
                self.assertIn("safe.txt", hm)
                self.assertEqual(hm["safe.txt"], [(1, 3)])
                self.assertNotIn("link.txt", hm)
                self.assertNotIn("outside_target.txt", hm)

    def test_hunk_map_raises_on_ls_files_failure(self):
        # #1257: a failed `git ls-files` must not silently drop untracked files.
        with tempfile.TemporaryDirectory() as d:
            _git(d, "init", "-q")
            _git(d, "config", "user.name", "T")
            _git(d, "config", "user.email", "t@example.com")
            with open(os.path.join(d, "committed.txt"), "w", encoding="utf-8") as fh:
                fh.write("line\n")
            _git(d, "add", "committed.txt")
            _git(d, "commit", "-qm", "init")

            def fake_run_git(repo, args, timeout=60, text=True):
                if args[:2] == ["merge-base", "HEAD"]:
                    class R: returncode = 0; stdout = "HEAD\n"; stderr = ""
                    return R()
                if len(args) > 4 and args[4] == "diff":
                    class R: returncode = 0; stdout = b""; stderr = b""
                    return R()
                if args[:2] == ["ls-files", "--others"]:
                    # bytes: #1739 reads this listing with -z/text=False.
                    class R: returncode = 1; stdout = b""; stderr = b"mock ls-files failure"
                    return R()
                return subprocess.run([shutil.which("git") or "git", "-C", repo, *args],
                                      capture_output=True, text=True, timeout=timeout)

            with mock.patch.object(diff_map, "_run_git", side_effect=fake_run_git):
                with self.assertRaisesRegex(RuntimeError, "git ls-files failed"):
                    diff_map.hunk_map(d, "HEAD")


class TestSyncConfig(unittest.TestCase):
    """#run8 SEC-D1C / #1681: _sync_config OVERWRITES whatever the PR shipped
    under either root config name with the operator's own file, and must not
    follow a symlinked destination out of the worktree (CWE-59)."""

    def _repo_with_config(self, d, name="panopticon.yml"):
        repo = os.path.join(d, "repo")
        os.makedirs(repo)
        with open(os.path.join(repo, name), "w", encoding="utf-8") as fh:
            fh.write("version: 1\ngroups: {}\n")
        return repo

    def test_copies_into_worktree_normally(self):
        with tempfile.TemporaryDirectory() as d:
            repo = self._repo_with_config(d)
            wt = os.path.join(d, "wt"); os.makedirs(wt)
            self.assertEqual(diff_map._sync_config(repo, wt), [])
            with open(os.path.join(wt, "panopticon.yml"), encoding="utf-8") as fh:
                self.assertEqual(fh.read(), "version: 1\ngroups: {}\n")

    def test_noop_when_operator_has_no_config(self):
        # #1681 fix round 2 item 5 (R18): still holds after the restructure --
        # a BARE worktree (nothing for the unconditional removal loop to find)
        # plus no operator config yields [] and writes nothing.
        with tempfile.TemporaryDirectory() as d:
            repo = os.path.join(d, "repo"); os.makedirs(repo)
            wt = os.path.join(d, "wt"); os.makedirs(wt)
            self.assertEqual(diff_map._sync_config(repo, wt), [])
            self.assertFalse(os.path.exists(os.path.join(wt, "panopticon.yml")))

    def test_no_operator_config_but_pr_ships_one_is_still_removed(self):
        # #1681 fix round 2 item 5 (controller ruling R18): even with NO
        # operator config anywhere, a PR-shipped file at either name must
        # never govern its own review -- the removal loop runs regardless,
        # and the caller is told why nothing was copied back.
        with tempfile.TemporaryDirectory() as d:
            repo = os.path.join(d, "repo"); os.makedirs(repo)
            wt = os.path.join(d, "wt"); os.makedirs(wt)
            with open(os.path.join(wt, "panopticon.yml"), "w", encoding="utf-8") as fh:
                fh.write("version: 1\ngroups:\n  Evil:\n    match: ['**']\n")
            notes = diff_map._sync_config(repo, wt)
            self.assertFalse(os.path.exists(os.path.join(wt, "panopticon.yml")))
            self.assertTrue(any("removed the PR's panopticon.yml" in n for n in notes), notes)
            self.assertTrue(any("no operator config" in n for n in notes), notes)

    def test_operator_file_overwrites_a_pr_shipped_one_and_says_so(self):
        with tempfile.TemporaryDirectory() as d:
            repo = self._repo_with_config(d)
            wt = os.path.join(d, "wt"); os.makedirs(wt)
            with open(os.path.join(wt, "panopticon.yml"), "w") as fh:
                fh.write("version: 1\ngroups:\n  Evil:\n    match: ['**']\n")
            notes = diff_map._sync_config(repo, wt)
            with open(os.path.join(wt, "panopticon.yml"), encoding="utf-8") as fh:
                self.assertEqual(fh.read(), "version: 1\ngroups: {}\n")
            self.assertTrue(any("overwrote" in n and "panopticon.yml" in n for n in notes))

    def test_both_names_in_the_worktree_are_removed_before_the_copy(self):
        with tempfile.TemporaryDirectory() as d:
            repo = self._repo_with_config(d, name=".panopticon.yml")
            wt = os.path.join(d, "wt"); os.makedirs(wt)
            with open(os.path.join(wt, "panopticon.yml"), "w", encoding="utf-8") as fh:
                fh.write("version: 1\ngroups:\n  Evil:\n    match: ['**']\n")
            notes = diff_map._sync_config(repo, wt)
            self.assertFalse(os.path.exists(os.path.join(wt, "panopticon.yml")))
            with open(os.path.join(wt, ".panopticon.yml"), encoding="utf-8") as fh:
                self.assertEqual(fh.read(), "version: 1\ngroups: {}\n")
            self.assertTrue(any("removed" in n for n in notes))

    def test_a_symlink_at_either_name_in_the_worktree_is_unlinked_not_followed(self):
        with tempfile.TemporaryDirectory() as d:
            repo = self._repo_with_config(d)
            wt = os.path.join(d, "wt"); os.makedirs(wt)
            outside = os.path.join(d, "outside.yml")
            with open(outside, "w", encoding="utf-8") as fh:
                fh.write("i must not be read or written through the link\n")
            os.symlink(outside, os.path.join(wt, "panopticon.yml"))
            os.symlink(outside, os.path.join(wt, ".panopticon.yml"))
            diff_map._sync_config(repo, wt)
            self.assertFalse(os.path.islink(os.path.join(wt, "panopticon.yml")))
            with open(os.path.join(wt, "panopticon.yml"), encoding="utf-8") as fh:
                self.assertEqual(fh.read(), "version: 1\ngroups: {}\n")
            # minor 6: the OTHER name's symlink was unlinked too, not just the
            # one that got recreated -- it must not still be lying around.
            self.assertFalse(os.path.lexists(os.path.join(wt, ".panopticon.yml")))
            # the link was unlinked, never followed: the file it pointed at is untouched
            with open(outside, encoding="utf-8") as fh:
                self.assertEqual(fh.read(), "i must not be read or written through the link\n")

    def test_rejects_a_worktree_root_that_is_a_symlink(self):
        with tempfile.TemporaryDirectory() as d:
            repo = self._repo_with_config(d)
            escape = os.path.join(d, "escape"); os.makedirs(escape)
            wt = os.path.join(d, "wt"); os.symlink(escape, wt)
            with self.assertRaisesRegex(RuntimeError, "symlinked worktree"):
                diff_map._sync_config(repo, wt)
            self.assertFalse(os.path.exists(os.path.join(escape, "panopticon.yml")))

    def test_rejects_a_missing_worktree_with_its_own_message(self):
        # minor 5: a MISSING worktree is not a SYMLINKED one -- the two used to
        # share one message, which would call a plain typo'd/never-created
        # path "symlinked".
        with tempfile.TemporaryDirectory() as d:
            repo = self._repo_with_config(d)
            wt = os.path.join(d, "does-not-exist")
            with self.assertRaisesRegex(RuntimeError, "missing worktree"):
                diff_map._sync_config(repo, wt)

    def test_resuming_a_previous_sync_refreshes_rather_than_removes(self):
        # #1681 fix round 1 item 1: the reuse/resume acquire_pr call site finds
        # the operator's file ALREADY in the worktree from a prior sync in the
        # same run. Re-syncing must not claim it "removed the PR's" file --
        # the PR never shipped it; a previous _sync_config call wrote it.
        with tempfile.TemporaryDirectory() as d:
            repo = self._repo_with_config(d)
            wt = os.path.join(d, "wt"); os.makedirs(wt)
            first = diff_map._sync_config(repo, wt)
            self.assertEqual(first, [])   # empty worktree: plain copy, nothing to report
            second = diff_map._sync_config(repo, wt)
            self.assertTrue(any("refreshed" in n for n in second), second)
            self.assertFalse(any("removed the PR's" in n for n in second), second)
            with open(os.path.join(wt, "panopticon.yml"), encoding="utf-8") as fh:
                self.assertEqual(fh.read(), "version: 1\ngroups: {}\n")

    def test_a_size_mismatched_file_is_removed_without_being_read(self):
        # #1681 fix round 2 item 1: the size from the already-done `lstat`
        # must rule a byte-compare out before anything is opened at all -- a
        # large PR-planted file at the config name is never read just to
        # prove it differs from the (small) operator copy.
        with tempfile.TemporaryDirectory() as d:
            repo = self._repo_with_config(d)
            wt = os.path.join(d, "wt"); os.makedirs(wt)
            big = os.path.join(wt, "panopticon.yml")
            with open(big, "wb") as fh:
                fh.write(b"x" * (3 * 1024 * 1024))
            real_open = os.open
            def guarded_open(path, flags=os.O_RDONLY, *a, **kw):
                # READS only: since fix round 3 M1 the operator's copy is
                # written through `os.open` too, and that write is the point of
                # the call -- what must never happen is OPENING the blob to
                # compare bytes with it.
                if (os.path.abspath(path) == os.path.abspath(big)
                        and flags & os.O_ACCMODE == os.O_RDONLY):
                    raise AssertionError("must not read a size-mismatched file")
                return real_open(path, flags, *a, **kw)
            with mock.patch("os.open", side_effect=guarded_open):
                notes = diff_map._sync_config(repo, wt)
            # the 3MB blob is gone -- `big` IS the destination name, so the
            # operator's copy legitimately lands there afterward; what proves
            # the size guard worked is that it is now the SMALL operator
            # content, not the original blob (and the guard above proves it
            # got there without ever being read for a byte-compare).
            with open(big, encoding="utf-8") as fh:
                self.assertEqual(fh.read(), "version: 1\ngroups: {}\n")
            self.assertTrue(any("removed the PR's panopticon.yml" in n for n in notes), notes)

    def test_refresh_only_applies_to_the_operators_own_name(self):
        # #1681 fix round 2 item 2: a BYTE-IDENTICAL file under the OTHER
        # (non-canonical) name is still removed, never "refreshed" -- that
        # fast path only ever applies to the destination matching the
        # operator's own file, so the worktree never ends up with both names
        # present (which would raise its own "both present" disclosure the
        # next time something reads config from the worktree).
        with tempfile.TemporaryDirectory() as d:
            repo = self._repo_with_config(d)   # operator's file is "panopticon.yml"
            wt = os.path.join(d, "wt"); os.makedirs(wt)
            with open(os.path.join(wt, ".panopticon.yml"), "w", encoding="utf-8") as fh:
                fh.write("version: 1\ngroups: {}\n")   # byte-identical, WRONG name
            notes = diff_map._sync_config(repo, wt)
            self.assertFalse(os.path.exists(os.path.join(wt, ".panopticon.yml")))
            self.assertTrue(any("removed the PR's .panopticon.yml" in n for n in notes), notes)
            self.assertFalse(any("refreshed" in n for n in notes), notes)
            with open(os.path.join(wt, "panopticon.yml"), encoding="utf-8") as fh:
                self.assertEqual(fh.read(), "version: 1\ngroups: {}\n")

    def test_a_link_planted_after_the_removal_is_not_written_through(self):
        # M1: the destination was `os.unlink(dst)` and then
        # `shutil.copy2(src, dst)` -- two opens of one name in a directory
        # holding attacker-controlled PR content. copy2 FOLLOWS whatever is at
        # the path when it opens it, so a link planted in that window carried
        # the operator's config onto its target. The write is an exclusive
        # O_NOFOLLOW create now: a path that came back is refused, loudly.
        with tempfile.TemporaryDirectory() as d:
            repo = self._repo_with_config(d)
            wt = os.path.join(d, "wt"); os.makedirs(wt)
            dst = os.path.join(wt, "panopticon.yml")
            with open(dst, "w", encoding="utf-8") as fh:
                fh.write("version: 1\ngroups:\n  Evil:\n    match: ['**']\n")
            outside = os.path.join(d, "outside.yml")
            with open(outside, "w", encoding="utf-8") as fh:
                fh.write("i must not be written through the link\n")
            real_unlink = os.unlink

            def racing_unlink(path, *a, **kw):
                real_unlink(path, *a, **kw)
                if os.path.abspath(path) == os.path.abspath(dst):
                    os.symlink(outside, dst)        # planted inside the window

            with mock.patch("os.unlink", side_effect=racing_unlink):
                with self.assertRaisesRegex(RuntimeError, "reappeared"):
                    diff_map._sync_config(repo, wt)
            self.assertTrue(os.path.islink(dst))
            with open(outside, encoding="utf-8") as fh:
                self.assertEqual(fh.read(), "i must not be written through the link\n")

    def test_an_over_cap_operator_config_is_disclosed_and_not_copied(self):
        # M3: this read the operator's file unbounded while every other reader
        # takes MAX_CONFIG_BYTES + 1 and refuses the extra byte. Same cap, same
        # refusal -- copying a file `read_document` will refuse would hand the
        # review a config nothing downstream can read.
        cap = diff_map.repo_config.MAX_CONFIG_BYTES
        with tempfile.TemporaryDirectory() as d:
            repo = os.path.join(d, "repo"); os.makedirs(repo)
            with open(os.path.join(repo, "panopticon.yml"), "w", encoding="utf-8") as fh:
                fh.write("version: 1\n#" + "x" * cap + "\n")
            wt = os.path.join(d, "wt"); os.makedirs(wt)
            with open(os.path.join(wt, "panopticon.yml"), "w", encoding="utf-8") as fh:
                fh.write("version: 1\ngroups:\n  Evil:\n    match: ['**']\n")
            notes = diff_map._sync_config(repo, wt)
            self.assertTrue(any("exceeds" in n for n in notes), notes)
            # refused == absent for the removal loop (R18): the PR's own file
            # still must not govern its own review.
            self.assertFalse(os.path.exists(os.path.join(wt, "panopticon.yml")))
            self.assertTrue(any("no operator config" in n for n in notes), notes)

    def test_an_unchanged_destination_is_not_rewritten(self):
        # M2: the docstring said a byte-identical destination was "left
        # alone" while the code fell through to an unconditional copy2 that
        # rewrote it. The skip is real now -- proved by the file's identity
        # (inode + mtime) surviving the second sync.
        with tempfile.TemporaryDirectory() as d:
            repo = self._repo_with_config(d)
            wt = os.path.join(d, "wt"); os.makedirs(wt)
            dst = os.path.join(wt, "panopticon.yml")
            diff_map._sync_config(repo, wt)
            before = os.stat(dst)
            notes = diff_map._sync_config(repo, wt)
            after = os.stat(dst)
            self.assertTrue(any("refreshed" in n for n in notes), notes)
            # ctime, not mtime: copy2 restores the SOURCE's mtime, so only the
            # inode-change stamp tells a rewrite from a genuine skip.
            self.assertEqual((before.st_ino, before.st_ctime_ns),
                             (after.st_ino, after.st_ctime_ns))
            with open(dst, encoding="utf-8") as fh:
                self.assertEqual(fh.read(), "version: 1\ngroups: {}\n")

    def test_both_names_present_in_the_operators_repo_discloses_on_success_too(self):
        # #1681 fix round 2 item 4: `res.disclosures` used to reach the caller
        # only on the no-config branch -- the "both present" note is exactly
        # as real on a successful sync and must not go missing there.
        with tempfile.TemporaryDirectory() as d:
            repo = os.path.join(d, "repo"); os.makedirs(repo)
            with open(os.path.join(repo, "panopticon.yml"), "w", encoding="utf-8") as fh:
                fh.write("version: 1\ngroups: {}\n")
            with open(os.path.join(repo, ".panopticon.yml"), "w", encoding="utf-8") as fh:
                fh.write("version: 1\ngroups: {}\n")
            wt = os.path.join(d, "wt"); os.makedirs(wt)
            notes = diff_map._sync_config(repo, wt)
            self.assertTrue(any("both" in n and "present" in n for n in notes), notes)
            with open(os.path.join(wt, "panopticon.yml"), encoding="utf-8") as fh:
                self.assertEqual(fh.read(), "version: 1\ngroups: {}\n")

    def test_operator_side_symlinked_config_still_removes_the_prs_file(self):
        # #1681 fix round 1 item 2 + fix round 2 item 5 (controller ruling
        # R18, which closes the re-review's O1 and supersedes this test's
        # original round-1 assertion that the worktree was left "untouched"):
        # repo_config.resolve refuses an OPERATOR-side symlinked config and
        # discloses why -- that disclosure must still reach the caller -- but
        # a REFUSED operator config is exactly like NO operator config for
        # the removal loop: the PR's own file must never govern its own
        # review, so it is removed regardless of whether the operator has a
        # usable config.
        with tempfile.TemporaryDirectory() as d:
            repo = os.path.join(d, "repo"); os.makedirs(repo)
            elsewhere = os.path.join(d, "elsewhere.yml")
            with open(elsewhere, "w", encoding="utf-8") as fh:
                fh.write("version: 1\ngroups: {}\n")
            os.symlink(elsewhere, os.path.join(repo, "panopticon.yml"))
            wt = os.path.join(d, "wt"); os.makedirs(wt)
            with open(os.path.join(wt, "panopticon.yml"), "w", encoding="utf-8") as fh:
                fh.write("version: 1\ngroups:\n  Evil:\n    match: ['**']\n")
            notes = diff_map._sync_config(repo, wt)
            self.assertTrue(any("symlink" in n for n in notes), notes)
            self.assertTrue(any("removed the PR's panopticon.yml" in n for n in notes), notes)
            self.assertFalse(os.path.exists(os.path.join(wt, "panopticon.yml")))
