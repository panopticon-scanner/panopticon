"""#2099: the contract between discovery's and coverage's file signals.

Discovery classifies files to seed the `panels` schedule it writes into
groups.json (`discovery.compute_group_panels`). Coverage classifies them to
decide the objective floor: `coverage_model.applicable_global_floor` plus
`applicable_sec_floor`, then committed `panels:`, scout widening and `exclude`.
The two differ, and this file states how:

- **Only coverage's answer routes.** Nothing reads groups.json `panels`.
  `TheScheduleRoutesNothingTest` makes that an enforced fact.
- **One predicate is shared,** `discovery.is_test_file` (#1770).
- **Every other difference is labelled,** row by row, as required or
  accidental. The accidental ones assert TODAY's behaviour and name the issue
  that holds their ruling, so a later change flips a row visibly instead of
  drifting silently. The routing ones were ruled on in #3484 and are required
  now; what remains accidental routes nothing (#3485).
"""
import json
import os
import re
import tempfile
import unittest
from unittest import mock

from scripts import coverage_model, discovery, groups_schema, hosts
import scripts.phases.coverage as coverage
import scripts.phases.runio as runio
from tests._test_helpers import write_host_evidence

REQUIRED = "required"
SHARED = "shared"            # both sides answer through the same predicate
AGREE = "agree"
NON_ROUTING = "accidental, non-routing (#3485)"

# (path, discovery's (is_test_file, is_database_file, is_architecture_file),
#  coverage's objective floor for a group of just this file, label, why)
SIGNALS = [
    ("README.md", (False, False, True), ["COD"], REQUIRED,
     "ARC: discovery asks 'infra/doc file?', coverage asks '>= 2 directories?'; "
     "a README is not SEC code (#3338)"),
    ("LICENSE", (False, False, True), ["COD"], REQUIRED, "as README.md"),
    ("docs/guide.md", (False, False, False), ["COD"], REQUIRED,
     "documentation is not SEC code (#3338)"),
    ("assets/logo.png", (False, False, False), [], REQUIRED,
     "an asset has no COD or SEC surface (#1489, #3338); discovery schedules both"),
    ("Dockerfile", (False, False, True), ["COD", "SEC"], REQUIRED,
     "ARC is structural in coverage, a file kind in discovery"),
    ("tests/conftest.py", (False, False, False), ["COD", "SEC", "TST"], REQUIRED,
     "test SURFACE, not a test file: the naming rule also routes files between "
     "groups (partition_test_files), so the surface hints must not leak into it"),
    ("features/login.feature", (False, False, False), ["COD", "SEC", "TST"], REQUIRED,
     "as tests/conftest.py"),
    ("tests/fixtures/data.json", (False, False, False), ["COD", "SEC", "TST"], REQUIRED,
     "as tests/conftest.py"),
    ("src/AppTest.java", (True, False, False), ["COD", "SEC", "TST"], SHARED,
     "discovery.is_test_file, which coverage's TST signal unions in (#1770)"),
    ("app/models/user.py", (False, True, False), ["COD", "DAT", "SEC"], AGREE, ""),
    ("db/migrate/001_init.rb", (False, True, False), ["COD", "DAT", "SEC"], REQUIRED,
     "#3484 R1: a `migrate/` directory segment is a DB surface (Rails' db/migrate)"),
    ("migrate/002_users.rb", (False, True, False), ["COD", "DAT", "SEC"], REQUIRED,
     "#3484 R1: a top-level migrate/ segment too"),
    ("src/immigrate.py", (False, False, False), ["COD", "SEC"], REQUIRED,
     "#3484 R1: a segment, not a substring"),
    ("src/migrated_users.py", (False, False, False), ["COD", "SEC"], REQUIRED,
     "#3484 R1: a segment, not a substring"),
    ("bin/migrate.rb", (False, False, False), ["COD", "SEC"], REQUIRED,
     "#3484 R1: a FILE named migrate is not the segment"),
    ("lib/immigrate/rules.rb", (False, False, False), ["COD", "SEC"], REQUIRED,
     "#3484 R1: a directory ending in `migrate` is not the segment"),
    # #3484 R2: `schema`, `seed` and `entity` are words. They must start a path
    # segment or follow a dot and end at a separator, or be a CamelCase `Entity`.
    ("src/identity.py", (False, False, False), ["COD", "SEC"], REQUIRED,
     "#3484 R2: `entity` inside `identity` is not the word"),
    ("src/identities.py", (False, False, False), ["COD", "SEC"], REQUIRED,
     "#3484 R2: nor is `entities` inside `identities`"),
    ("config/initializers/html_entities.rb", (False, False, False), ["COD", "SEC"], REQUIRED,
     "#3484 R2: railsgoat's HTML entities; an `_` compound is not the word"),
    ("src/random_seed.py", (False, False, False), ["COD", "SEC"], REQUIRED,
     "#3484 R2: `seed` after `random_` is not the word"),
    ("lib/seedling.py", (False, False, False), ["COD", "SEC"], REQUIRED,
     "#3484 R2: the word must END at a separator"),
    ("src/jsonschema_util.py", (False, False, False), ["COD", "SEC"], REQUIRED,
     "#3484 R2: `schema` inside `jsonschema` is not the word"),
    ("src/config_schema.py", (False, False, False), ["COD", "SEC"], REQUIRED,
     "#3484 R2: a JSON-Schema module, an `_` compound"),
    ("src/schematics/index.ts", (False, False, False), ["COD", "SEC"], REQUIRED,
     "#3484 R2: Angular schematics; the word must END at a separator"),
    ("db/schema.rb", (False, False, False), ["COD", "DAT", "SEC"], REQUIRED,
     "#3484 R2: Rails' schema; only the `schema` word draws its DAT"),
    ("schema.sql", (False, True, False), ["COD", "DAT", "SEC"], REQUIRED, "#3484 R2 keeps"),
    ("prisma/schema.prisma", (False, True, False), ["COD", "DAT", "SEC"], REQUIRED,
     "#3484 R2 keeps"),
    ("src/cats/cat.schema.ts", (False, True, False), ["COD", "DAT", "SEC"], REQUIRED,
     "#3484 R2: Mongoose's `.schema.` suffix, a dot-led word"),
    ("db/seeds.rb", (False, False, False), ["COD", "DAT", "SEC"], REQUIRED,
     "#3484 R2: Rails' seeds; only the `seed` word draws its DAT"),
    ("seeds/001.sql", (False, True, False), ["COD", "DAT", "SEC"], REQUIRED, "#3484 R2 keeps"),
    ("db/seed_users.rb", (False, False, False), ["COD", "DAT", "SEC"], REQUIRED,
     "#3484 R2: a word may END at `_`; only the `seed` word draws its DAT"),
    ("src/entities/user.ts", (False, True, False), ["COD", "DAT", "SEC"], REQUIRED,
     "#3484 R2 keeps"),
    ("app/entity/Order.java", (False, True, False), ["COD", "DAT", "SEC"], REQUIRED,
     "#3484 R2 keeps"),
    ("src/user.entity.ts", (False, False, False), ["COD", "DAT", "SEC"], REQUIRED,
     "#3484 R2: TypeORM's `.entity.` suffix, a dot-led word"),
    ("UserEntity.java", (False, False, False), ["COD", "DAT", "SEC"], REQUIRED,
     "#3484 R2: a CamelCase `Entity`, matched case-sensitively"),
    # #3484 R3: `/test_` starts a path segment; `.spec.` skips yaml/yml/json.
    ("src/latest_version.py", (False, False, False), ["COD", "SEC"], REQUIRED,
     "#3484 R3: `test_` inside `latest_` does not start a segment"),
    ("src/contest_results.py", (False, False, False), ["COD", "SEC"], REQUIRED,
     "#3484 R3: nor inside `contest_`"),
    ("api/openapi.spec.yaml", (False, False, False), ["COD", "SEC"], REQUIRED,
     "#3484 R3: an API description, not a test"),
    ("api/openapi.spec.yml", (False, False, False), ["COD", "SEC"], REQUIRED, "#3484 R3: as .yaml"),
    ("api/user.spec.json", (False, False, False), ["COD", "SEC"], REQUIRED, "#3484 R3: as .yaml"),
    ("tests/test_api.py", (True, False, False), ["COD", "SEC", "TST"], REQUIRED, "#3484 R3 keeps"),
    ("test_api.py", (True, False, False), ["COD", "SEC", "TST"], REQUIRED,
     "#3484 R3 keeps, at the top level too"),
    ("src/test_main.c", (False, False, False), ["COD", "SEC", "TST"], REQUIRED,
     "#3484 R3: only the `/test_` hint draws its TST"),
    ("src/foo.spec.ts", (True, False, False), ["COD", "SEC", "TST"], REQUIRED,
     "#3484 R3 keeps; the naming rule decides it"),
    ("foo.spec.js", (True, False, False), ["COD", "SEC", "TST"], REQUIRED, "as src/foo.spec.ts"),
    ("src/__snapshots__/foo.spec.ts.snap", (False, False, False), ["COD", "SEC", "TST"], REQUIRED,
     "#3484 R3: only `.spec.` draws its TST"),
    ("src/db.query.py", (False, False, False), ["COD", "DAT", "SEC"], NON_ROUTING,
     "discovery's DAT is narrower (no `/db.`); only coverage's answer routes"),
    ("app/Models/User.cs", (False, False, False), ["COD", "DAT", "SEC"], NON_ROUTING,
     "discovery's patterns are case-sensitive"),
    ("src/repository.py", (False, False, False), ["COD", "DAT", "SEC"], NON_ROUTING,
     "discovery matches only a repository/ directory"),
    ("data/app.sqlite", (False, False, False), ["COD", "DAT", "SEC"], NON_ROUTING,
     "discovery matches only `.sql$`"),
]


class TheSignalsTest(unittest.TestCase):
    def test_each_row_is_todays_answer_on_both_sides(self):
        for path, disc, floor, label, why in SIGNALS:
            with self.subTest(path=path, label=label):
                self.assertEqual(disc, (discovery.is_test_file(path),
                                        discovery.is_database_file(path),
                                        discovery.is_architecture_file(path)), why)
                self.assertEqual(floor, sorted(coverage_model.applicable_global_floor([path], None)
                                               | coverage_model.applicable_sec_floor([path])), why)

    def test_the_test_file_rule_is_the_one_shared_predicate(self):
        # Coverage's TST signal is discovery's naming rule OR its own hints, so a
        # naming-rule test file always draws TST, on any convention.
        for path in ("AuthTest.php", "AccountTests.cs", "app_tests.py", "x_test.go",
                     "src/__tests__/a.js", "spec/models/user_spec.rb"):
            with self.subTest(path=path):
                self.assertTrue(discovery.is_test_file(path))
                self.assertIn("TST", coverage_model.applicable_global_floor([path], None))

    def test_which_half_of_the_tst_signal_decides_a_spec_file(self):
        # #3484 R3. The TST signal is `discovery.is_test_file` OR the hints, and
        # the naming rule decides first. Narrowing `.spec.` therefore cannot
        # drop a JS/TS spec test: with the `.spec.` hint switched off entirely,
        # the naming rule alone still draws TST for every one. The hint is what
        # carries the spec files that rule does not know.
        never = re.compile(r"(?!)")
        with mock.patch.object(coverage_model, "_SPEC_HINT", never):
            for path in ("src/foo.spec.ts", "foo.spec.js", "a/b.spec.mjs", "c.spec.tsx"):
                with self.subTest(path=path, half="naming rule"):
                    self.assertIn("TST", coverage_model.applicable_global_floor([path], None))
            with self.subTest(half="hint"):
                self.assertNotIn("TST", coverage_model.applicable_global_floor(
                    ["src/__snapshots__/foo.spec.ts.snap"], None))

    def test_every_row_is_labelled_and_every_accidental_row_names_its_issue(self):
        labels = {label for _p, _d, _f, label, _w in SIGNALS}
        self.assertEqual({REQUIRED, SHARED, AGREE, NON_ROUTING}, labels)
        for path, _d, _f, label, why in SIGNALS:
            if label in (REQUIRED, NON_ROUTING):
                self.assertTrue(why, path)


# Representative groups, routed through the real coverage phase.
GROUPS = {
    "Readme": ["README.md"],
    "Assets": ["assets/logo.png", "assets/icon.svg"],
    "Docs": ["docs/a.md", "docs/b.rst", "LICENSE"],
    "DbQuery": ["src/db.query.py"],
    "Rails": ["db/migrate/001_init.rb"],
    "Conftest": ["tests/conftest.py"],
    "Ident": ["src/identity.py"],
    "Latest": ["src/latest_version.py"],
    "ApiSpec": ["api/openapi.spec.yaml"],
    "Committed": ["src/a.py"],
    "Widened": ["src/b.py"],
    "Excl": ["src/c.py", "tests/test_c.py"],
}
COMMITTED = {"Committed": "    panels: [DAT]\n", "Excl": "    exclude: [TST, SEC]\n"}
SCOUT = {"Widened": ["AGT"]}


class _Phase(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.addCleanup(self._t.cleanup)
        self.root = os.path.realpath(self._t.name)
        os.makedirs(runio._pano(self.root))
        write_host_evidence(self.root, {c: hosts.PROVEN for c in hosts.CAPABILITIES})
        self.manifest = {"run_id": "R", "security_mode": "standard", "host": "claude"}
        with open(os.path.join(self.root, "panopticon.yml"), "w") as fh:
            fh.write("version: 1\ngroups:\n" + "".join(
                "  %s:\n    match: %s\n%s" % (name, json.dumps(files), COMMITTED.get(name, ""))
                for name, files in GROUPS.items()))
        for name in GROUPS:
            runio._write_json(runio._pano(self.root, "scout-%s.json" % name),
                              {"group": name, "domains": SCOUT.get(name, [])})

    def _route(self, panels):
        """Write groups.json with `panels(files)` on each entry (None: no key),
        run the coverage phase to completion and return every coverage file's
        bytes."""
        groups = []
        for name, files in GROUPS.items():
            entry = {"name": name, "files": files}
            value = panels(files)
            if value is not None:
                entry["panels"] = value
            groups.append(entry)
        runio._write_json(runio._pano(self.root, "groups.json"), {"groups": groups})
        for name in GROUPS:
            path = runio._pano(self.root, "coverage-%s.json" % name)
            if os.path.exists(path):
                os.remove(path)
        for _ in range(len(GROUPS) + 1):
            if coverage.coverage_done(self.root, self.manifest):
                break
            self.assertEqual("advanced", coverage.coverage_execute(self.root, self.manifest).kind)
        self.assertTrue(coverage.coverage_done(self.root, self.manifest))
        out = {}
        for name in GROUPS:
            with open(runio._pano(self.root, "coverage-%s.json" % name), "rb") as fh:
                out[name] = fh.read()
        return out


class TheScheduleRoutesNothingTest(_Phase):
    """Discovery's `panels` is a schedule nothing routes on. Deleting it, or
    claiming every domain and every legacy panel name, leaves every coverage
    file byte-identical to the one discovery's real schedule produces."""

    def test_deleted_or_everything_routes_exactly_like_discoverys_own(self):
        everything = sorted(groups_schema.DOMAINS) + list(discovery.PANEL_PRIORITY)
        baseline = self._route(lambda files: discovery.compute_group_panels(files))
        self.assertEqual(baseline, self._route(lambda files: None))
        self.assertEqual(baseline, self._route(lambda files: everything))


class RoutingThroughTheEffectiveMatrixTest(_Phase):
    """Committed floors, scout widening and `exclude` still compose with the
    objective floor exactly as before."""

    EXPECTED = {
        # group: (floor, scout_added, excluded, effective, exclude_rejected)
        "Readme": (["COD"], [], [], ["COD"], None),
        "Assets": ([], [], [], [], None),
        "Docs": (["ARC", "COD"], [], [], ["ARC", "COD"], None),        # two directories
        "DbQuery": (["COD", "DAT", "SEC"], [], [], ["COD", "DAT", "SEC"], None),
        "Rails": (["COD", "DAT", "SEC"], [], [], ["COD", "DAT", "SEC"], None),  # #3484 R1
        "Conftest": (["COD", "SEC", "TST"], [], [], ["COD", "SEC", "TST"], None),
        "Ident": (["COD", "SEC"], [], [], ["COD", "SEC"], None),        # #3484 R2
        "Latest": (["COD", "SEC"], [], [], ["COD", "SEC"], None),       # #3484 R3
        "ApiSpec": (["COD", "SEC"], [], [], ["COD", "SEC"], None),      # #3484 R3
        "Committed": (["COD", "DAT", "SEC"], [], [], ["COD", "DAT", "SEC"], None),
        "Widened": (["COD", "SEC"], ["AGT"], [], ["AGT", "COD", "SEC"], None),
        "Excl": (["ARC", "COD", "SEC", "TST"], [], ["TST"], ["ARC", "COD", "SEC"], ["SEC"]),
    }

    def test_representative_groups(self):
        routed = self._route(lambda files: discovery.compute_group_panels(files))
        for name, expected in self.EXPECTED.items():
            with self.subTest(group=name):
                cov = json.loads(routed[name])
                self.assertEqual(expected, (cov["floor"], cov["scout_added"], cov["excluded"],
                                            cov["effective"], cov.get("exclude_rejected")))
        # The committed floor, not the file gate, put DAT on `Committed`: the gate
        # suppressed DAT, and the committed `panels: [DAT]` still runs it.
        self.assertIn("DAT", json.loads(routed["Committed"])["global_floor_suppressed"])


if __name__ == "__main__":
    unittest.main()
