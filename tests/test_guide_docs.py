import glob
import os
import re
import unittest

import scripts.hosts as hosts
from tests._test_helpers import SKILL_ROOT as ROOT
from tests.doc_helpers import (
    _CHAPTER_DIR, _DOC_PATH, _FENCE,
    _read_doc, _read_skill_md, _unwrap,
)

class TestTheGuideResolvesInEveryInstallLayout(unittest.TestCase):
    """#1637 P01: `skill/` is what gets symlinked into `~/.claude/skills/`,
    `~/.kimi/skills/` and `~/.agents/skills/` (README), so SKILL.md's links are
    resolved relative to SKILL.md's OWN directory in every installed layout --
    and in the source checkout too. They pointed at `docs/PANOPTICON.md`, which
    lived at the REPO ROOT and never at `skill/docs/`, so the first read the
    skill instructs failed everywhere. The guide moved INTO the skill; the root
    path stays as a symlink so every root-level reference (README, DEVELOPMENT,
    docs/) keeps resolving to the same bytes.
    """

    ROOT_DOC = os.path.join(ROOT, os.pardir, "docs", "PANOPTICON.md")
    SKILL_DOC = os.path.join(ROOT, "docs", "PANOPTICON.md")
    ROOT_CHAPTERS = os.path.join(ROOT, os.pardir, "docs", "guide")

    def test_every_relative_link_in_skill_md_resolves_from_skill_mds_directory(self):
        skill_md = _read_skill_md()
        targets = sorted({
            t for t in re.findall(r"\]\(([^)]+)\)", skill_md)
            if not t.startswith(("http://", "https://", "#", "/"))})
        self.assertIn("docs/PANOPTICON.md", targets)
        missing = [t for t in targets
                   if not os.path.exists(os.path.join(ROOT, t.split("#", 1)[0]))]
        self.assertEqual(missing, [],
                         "SKILL.md link(s) that do not resolve from %s -- the "
                         "first read the skill instructs fails in every "
                         "installed layout:\n%s" % (ROOT, "\n".join(missing)))

    def test_the_guide_lives_inside_the_skill(self):
        self.assertTrue(os.path.isfile(self.SKILL_DOC), self.SKILL_DOC)

    def test_the_root_path_is_a_symlink_onto_the_very_same_file(self):
        self.assertTrue(os.path.islink(self.ROOT_DOC),
                        "%s must stay a symlink so README/DEVELOPMENT/docs "
                        "references keep resolving" % self.ROOT_DOC)
        self.assertTrue(os.path.samefile(self.ROOT_DOC, self.SKILL_DOC))
        self.assertEqual(os.readlink(self.ROOT_DOC),
                         os.path.join(os.pardir, "skill", "docs", "PANOPTICON.md"))

    def test_hosts_guide_path_names_that_file(self):
        self.assertEqual(os.path.realpath(hosts.guide_path()),
                         os.path.realpath(self.SKILL_DOC))
        self.assertTrue(os.path.isfile(hosts.guide_path()))

    def test_the_chapters_have_a_root_symlink_of_their_own(self):
        """The mirror of the `docs/PANOPTICON.md` link above, for the same
        reason: README, SECURITY and FAMILY-PR-GUARDRAILS now link individual
        chapters as `docs/guide/<name>.md`, and those references resolve only
        while the root path exists. A directory symlink, not eight file ones,
        so a new chapter needs no second step to be reachable."""
        self.assertTrue(os.path.islink(self.ROOT_CHAPTERS),
                        "%s must stay a symlink so root-level chapter links "
                        "keep resolving" % self.ROOT_CHAPTERS)
        self.assertEqual(os.readlink(self.ROOT_CHAPTERS),
                         os.path.join(os.pardir, "skill", "docs", "guide"))
        for path in hosts.guide_documents()[1:]:
            with self.subTest(chapter=os.path.basename(path)):
                through_root = os.path.join(self.ROOT_CHAPTERS,
                                            os.path.basename(path))
                self.assertTrue(os.path.samefile(through_root, path))


class TestTheGuideIsAnIndexPlusChapters(unittest.TestCase):
    """The 2026-09-24 split. Three facts hold the guide together, and each one
    is a way the whole document silently loses a section if it stops holding:

    * every chapter file opens with the ORIGINAL H2 line -- that heading is the
      marker `_section` slices on, so a chapter that renames or drops it takes
      a dozen content guards down with it (they would fail loudly, which is the
      point of pinning it here, once, with the reason);
    * the index's `## Contents` list names every chapter, in document order,
      and each entry's LABEL is that chapter's heading -- so a reader's table
      of contents cannot drift from what the chapters actually say;
    * the index itself keeps only the front matter. A section that reappears
      there is a section readers meet twice.
    """

    def _index(self):
        with open(_DOC_PATH, encoding="utf-8") as fh:
            return fh.read()

    def _contents_entries(self):
        """The Contents list, one folded line per entry (the entries are
        wrapped on disk like every other list item)."""
        block = _unwrap(self._index()).split("\n## Contents\n", 1)
        self.assertEqual(2, len(block), "the index lost its `## Contents` list")
        entries = [line for line in block[1].split("\n") if line.strip()]
        self.assertTrue(entries, "the `## Contents` list has no entries")
        return entries

    def _contents(self):
        """[(entry label, chapter file name)] from the index's Contents list."""
        pairs = []
        for entry in self._contents_entries():
            m = re.match(r"- \[([^\]]+)\]\(guide/([a-z0-9-]+\.md)\)", entry)
            self.assertIsNotNone(
                m, "a Contents entry that does not link a chapter: %r" % entry)
            pairs.append(m.groups())
        return pairs

    def test_the_contents_list_names_every_chapter_in_document_order(self):
        """Against `hosts.GUIDE_CHAPTERS`, which is what `driver readiness`
        checks for on disk -- a chapter the reader's table of contents links
        and readiness never looks for, or the reverse, is the drift this
        catches."""
        self.assertEqual(list(hosts.GUIDE_CHAPTERS),
                         [name for _label, name in self._contents()])

    def test_every_chapter_hosts_names_is_a_file_that_exists(self):
        for path in hosts.guide_documents():
            with self.subTest(document=os.path.basename(path)):
                self.assertTrue(os.path.isfile(path), path)

    def test_every_chapter_opens_with_the_heading_its_contents_entry_names(self):
        for label, name in self._contents():
            with self.subTest(chapter=name):
                with open(os.path.join(_CHAPTER_DIR, name), encoding="utf-8") as fh:
                    lines = fh.read().split("\n")
                self.assertEqual("## " + label, lines[0])
                # One H2 per chapter: a second one means a section moved into
                # the wrong file, where the Contents list cannot advertise it.
                self.assertEqual(["## " + label],
                                 [ln for ln in lines if ln.startswith("## ")])

    def test_every_contents_entry_says_what_the_chapter_covers(self):
        for entry in self._contents_entries():
            with self.subTest(entry=entry[:60]):
                self.assertRegex(entry, r"\) — \S")

    def test_the_index_keeps_the_front_matter_and_nothing_a_chapter_owns(self):
        index = self._index()
        self.assertTrue(index.startswith("# panopticon\n"))
        self.assertEqual(["## Overview", "## Required sub-skills", "## Modes",
                          "## Global flags", "## Contents"],
                         [ln for ln in index.split("\n") if ln.startswith("## ")])

    def test_x0x_siblings_use_the_report_filename_stem_everywhere(self):
        paths = (
            os.path.join(ROOT, "docs", "guide", "output.md"),
            os.path.join(ROOT, "docs", "guide", "driver-run-loop.md"),
            os.path.join(ROOT, "reference", "x0x-report-schema.json"),
        )
        for path in paths:
            with self.subTest(path=os.path.relpath(path, ROOT)):
                with open(path, encoding="utf-8") as fh:
                    text = fh.read()
                folded = " ".join(text.split())
                self.assertIn("<report-stem>", folded)
                self.assertIn("report filename without", folded)
                self.assertNotRegex(folded, r"<stem>-(?:report-)?x0x")

    MAX_COLUMNS = 120

    @staticmethod
    def _is_one_token(line):
        """True when the line cannot be wrapped any narrower: one word, or one
        inline code span (which may hold spaces and must never be broken)."""
        bare = line.strip()
        return (" " not in bare
                or re.fullmatch(r"[^`\s]*`[^`]*`[^`\s]*", bare) is not None)

    def test_no_line_in_the_guide_exceeds_120_columns(self):
        """The guard that keeps the 2026-09-24 reflow from regressing. Wrapped
        at 100; 120 is the slack an edit may take before it has to re-wrap.
        Three kinds of line are exempt because wrapping them would change what
        they mean: a fenced code line, a table row, and a line holding a single
        unbreakable token."""
        paths = sorted(glob.glob(os.path.join(ROOT, "docs", "**", "*.md"),
                                 recursive=True))
        self.assertTrue(paths, "no markdown under %s/docs" % ROOT)
        offenders = []
        for path in paths:
            with open(path, encoding="utf-8") as fh:
                body = fh.read()
            in_fence = False
            for number, line in enumerate(body.split("\n"), 1):
                if _FENCE.match(line):
                    in_fence = not in_fence
                    continue
                if (in_fence or line.lstrip().startswith("|")
                        or len(line) <= self.MAX_COLUMNS
                        or self._is_one_token(line)):
                    continue
                offenders.append("%s:%d is %d columns"
                                 % (os.path.relpath(path, ROOT), number, len(line)))
        self.assertEqual([], offenders, "\n".join(offenders))

    def test_the_column_guards_exemption_is_only_for_unbreakable_lines(self):
        """A guard whose exemption is wide is not a guard. Prose is never
        exempt, however long; a lone code span always is, because the wrap
        would land inside it."""
        self.assertFalse(self._is_one_token("  a long sentence a wrap could fix"))
        self.assertFalse(self._is_one_token("  `--flag` and some more prose"))
        self.assertTrue(self._is_one_token("  `docker pull x && docker tag x y`"))
        self.assertTrue(self._is_one_token("  https://example.invalid/" + "x" * 200))

    def test_the_fold_the_content_guards_read_through_is_a_fixed_point(self):
        """`_read_doc()` already folds, so folding again must change nothing --
        the property that makes every phrase pinned in this file a phrase of
        the guide's prose rather than of one particular wrapping of it."""
        doc = _read_doc()
        self.assertEqual(doc, _unwrap(doc))

    def test_the_concatenation_reads_as_one_document(self):
        """What every content test in this file depends on: `_read_doc()` is
        the whole guide, each moved heading present exactly once and in order."""
        doc = _read_doc()
        headings = [ln for ln in doc.split("\n") if ln.startswith("## ")]
        self.assertEqual(
            ["## Overview", "## Required sub-skills", "## Modes",
             "## Global flags", "## Contents"]
            + ["## " + label for label, _name in self._contents()],
            headings)
