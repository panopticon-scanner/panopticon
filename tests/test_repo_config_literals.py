"""#1681 Plan 1 ratchet: only `repo_config.py` may spell a config filename.

`PENDING` lists the production modules still carrying a literal while the
plan is in flight; each task removes the modules it repoints, and the last
task empties the set. A NEW literal anywhere else fails immediately."""
import os
import re
import unittest

from conftest import REPO_ROOT

SCRIPTS = os.path.join(REPO_ROOT, "skill", "scripts")
OWNER = os.path.join(SCRIPTS, "repo_config.py")
LITERALS = re.compile(r"""(?<![\w-])(\.?panopticon\.yml(\.draft)?|groups\.yml(\.draft)?|config\.json)(?![\w-])""")
PENDING = frozenset({
    "setup_flow.py",
    "phases/setup.py", "orchestrate.py", "diff_map.py", "phases/readiness.py",
    "setup_proposal.py",
    "coverage_model.py", "grouping_engine.py", "groups_schema.py",
    "ingest_tools.py", "phases/coverage.py", "phases/discovery.py",
    "phases/inventory.py", "phases/review.py", "phases/verify_tools.py",
    "probes/common.py", "synth/grading.py", "synth/plan.py", "synth/repair.py",
})


def _offenders():
    found = set()
    for d, dirs, files in os.walk(SCRIPTS):
        dirs[:] = sorted(x for x in dirs if x not in {"__pycache__", "fixtures", "goldens"})
        for f in sorted(files):
            path = os.path.join(d, f)
            if not f.endswith(".py") or path == OWNER:
                continue
            with open(path, encoding="utf-8") as fh:
                if LITERALS.search(fh.read()):
                    found.add(os.path.relpath(path, SCRIPTS))
    return found


class TestConfigNameLiterals(unittest.TestCase):
    def test_only_the_pending_modules_spell_a_config_name(self):
        extra = _offenders() - PENDING
        self.assertEqual(extra, set(), "spell config names through repo_config: %s" % sorted(extra))

    def test_the_owner_spells_them(self):
        with open(OWNER, encoding="utf-8") as fh:
            self.assertTrue(LITERALS.search(fh.read()))

    def test_pattern_matches_path_embedded_spellings(self):
        self.assertTrue(LITERALS.search(".panopticon/groups.yml"))
        self.assertTrue(LITERALS.search("root/.panopticon/config.json"))
        self.assertFalse(LITERALS.search("tools-config.json"))
        self.assertFalse(LITERALS.search("my-groups.yml"))
