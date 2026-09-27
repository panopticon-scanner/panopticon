import os
import re

from tests._test_helpers import SKILL_ROOT as ROOT   # #run7 TST-G1B: shared path anchor
import scripts.hosts as hosts

# #run7 QAL-D1C: the PANOPTICON.md guide was re-opened inline in 10 places.
# #1637 P01: it lives INSIDE the skill now (the repo-root path is a symlink
# onto it), so this anchor is `skill/docs/` -- the one constant that moved.
_DOC_PATH = hosts.guide_path()
# #1344 plan 5 T5: shared anchor for the dispatched-role template files.
AGENTS_DIR = os.path.join(ROOT, "agents")

# Owner ruling 2026-09-24 (first external review): 19,573 words in 210 lines,
# 42 of them over 1,000 characters, is not readable source. The guide is an
# index (front matter + Modes + Global flags + a Contents list) plus ONE FILE
# PER H2 under `skill/docs/guide/`. The split MOVED prose and rewrote none of
# it, so every phrase pinned below is still pinned -- the body tests read the
# CONCATENATION of the index and its chapters, in order, the way a reader
# reads the guide. `_section`'s H2 markers slice that concatenation exactly as
# they sliced the single file.
_GUIDE_CHAPTERS = hosts.GUIDE_CHAPTERS
_CHAPTER_DIR = os.path.join(os.path.dirname(_DOC_PATH), "guide")
_GUIDE_DOCUMENTS = hosts.guide_documents()


_FENCE = re.compile(r"^\s*(```|~~~)")
_HEADING = re.compile(r"^#{1,6}\s")
_LIST_ITEM = re.compile(r"^([-*+]|\d+[.)])\s+")


def _unwrap(text):
    """One line per block: soft-wrapped prose folded back together, with fenced
    code, blank lines and headings left exactly as written.

    The chapters are wrapped at 100 columns, and a wrap is not a content
    change -- but almost every pin in this file is a substring of the guide's
    PROSE, and 30 of them broke the moment a pinned phrase spanned a line
    break. Folding per BLOCK, rather than collapsing all whitespace to single
    spaces, is deliberate: `_section` slices on markers that contain newlines
    (`"\\n## "`, and the `"\\n\\n"` that ends the gemini paragraph), three
    guards below pull the ONE `splitlines()` line a sentence lives on and
    assert against it, and two more count offending LINES -- a blanket
    `re.sub(r"\\s+", " ")` would break the first pair outright and quietly
    make the rest vacuous. This fold keeps every one of them meaning what it
    meant, because its output is the guide as it was written before the wrap.
    """
    out, in_fence, open_block = [], False, False
    for line in text.split("\n"):
        if _FENCE.match(line):
            in_fence = not in_fence
            out.append(line)
            open_block = False
        elif in_fence:
            out.append(line)
            open_block = False
        elif not line.strip():
            out.append("")
            open_block = False
        elif _HEADING.match(line):
            out.append(line.rstrip())
            open_block = False
        elif open_block and not _LIST_ITEM.match(line):
            out[-1] = out[-1].rstrip() + " " + line.strip()
        else:
            out.append(line.rstrip())
            open_block = True
    return "\n".join(out)


def _read_doc():
    parts = []
    for path in _GUIDE_DOCUMENTS:
        with open(path, encoding="utf-8") as fh:
            parts.append(fh.read())
    return _unwrap("\n".join(parts))


def _read_skill_md():
    with open(os.path.join(ROOT, "SKILL.md"), encoding="utf-8") as fh:
        return fh.read()


def _section(text, start, end):
    """Slice `text` between two heading markers, asserting BOTH exist first so a
    renamed marker fails loudly instead of raising an opaque IndexError (missing
    start) or silently over-scoping to the rest of the doc (missing end, a
    false-pass). #run7 ARC-A2B/TST-B3A."""
    assert start in text, "section marker not found: %r" % (start,)
    assert end in text, "section marker not found: %r" % (end,)
    return text.split(start, 1)[1].split(end, 1)[0]

def _registered_driver_flags():
    """Every option string `driver`'s parser actually registers, plus the
    positionals, keyed by the name a doc would use."""
    import scripts.driver as driver
    parser = driver.build_parser()
    options, positionals = set(), set()

    def _harvest(p):
        for action in p._actions:
            if action.option_strings:
                options.update(action.option_strings)
            elif action.dest not in ("command", "help"):
                positionals.add(action.dest)
        for group in p._subparsers._group_actions if p._subparsers else []:
            for sub in getattr(group, "choices", {}).values():
                _harvest(sub)

    _harvest(parser)
    return options, positionals

# #1637 P03: `superpowers:writing-plans` defaults to `docs/superpowers/plans/`,
# which in THIS repo is a symlink to a sibling private checkout a reviewing
# host cannot write. Run-13 improvised `.panopticon/scratch/`. The plan is a
# review artifact, so it belongs in the review's artifact space, and the skill
# has to say so in the same breath as it requires the sub-skill.
PLAN_LOCATION = (
    "Save the review plan to `.panopticon/runs/<tag>/plan.md` (or "
    "`.panopticon/scratch/<run>/` before a run exists) — never to "
    "`docs/superpowers/`, which is not this review's artifact space.")


# #1637 P02: SKILL.md required three `superpowers:*` sub-skills and said
# nothing about where a host finds them or what to do when it cannot. Run-13's
# controller searched another host's plugin cache to answer both questions and
# then invented its own fallbacks. The roots below are where hosts TYPICALLY
# look -- read-only, never written, and `driver readiness` reports which ones
# it found (tests/phases/test_readiness_verb.py pins the code to this list).
SKILL_ROOTS = ("~/.claude/plugins/…/superpowers/", "~/.codex/skills/",
               "~/.agents/skills/", "~/.kimi/skills/")
