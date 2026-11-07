"""#2099/#3485: the file-signal and retired-schedule contracts.

Coverage owns the objective floor: `coverage_model.applicable_global_floor`
plus `applicable_sec_floor`, then committed `panels:`, scout widening and
`exclude`. Discovery shares only the test-file naming predicate (#1770); its
unread legacy `panels` schedule was deleted in #3485.

The coverage rows below pin every signal calibrated in #2099/#3484. The legacy
schedule survives only as fixture data proving that an old groups.json still
loads and routes byte-identically to a new artifact that omits the field.
"""
import json
import os
import re
import tempfile
import unittest
from unittest import mock

from scripts import coverage_model, discovery, groups_schema, hosts
import scripts.phases.coverage as coverage
import scripts.phases.discovery as discovery_phase
import scripts.phases.runio as runio
from tests._test_helpers import write_host_evidence

COVERAGE = "coverage"
SHARED = "shared"            # coverage calls discovery.is_test_file

# (path, discovery's shared is_test_file answer,
#  coverage's objective floor for a group of just this file, label, why)
SIGNALS = [
    ("README.md", False, ["COD"], COVERAGE,
     "ARC requires at least two directories; a README is not SEC code (#3338)"),
    ("LICENSE", False, ["COD"], COVERAGE, "as README.md"),
    ("docs/guide.md", False, ["COD"], COVERAGE,
     "documentation is not SEC code (#3338)"),
    ("assets/logo.png", False, [], COVERAGE,
     "an asset has no COD or SEC surface (#1489, #3338)"),
    ("Dockerfile", False, ["COD", "SEC"], COVERAGE,
     "ARC is structural, so one Dockerfile alone does not draw it"),
    ("tests/conftest.py", False, ["COD", "SEC", "TST"], COVERAGE,
     "test SURFACE, not a test file: the naming rule also routes files between "
     "groups (partition_test_files), so the surface hints must not leak into it"),
    ("features/login.feature", False, ["COD", "SEC", "TST"], COVERAGE,
     "as tests/conftest.py"),
    ("tests/fixtures/data.json", False, ["COD", "SEC", "TST"], COVERAGE,
     "as tests/conftest.py"),
    ("src/AppTest.java", True, ["COD", "SEC", "TST"], SHARED,
     "discovery.is_test_file, which coverage's TST signal unions in (#1770)"),
    ("app/models/user.py", False, ["COD", "DAT", "SEC"], COVERAGE,
     "a models directory is a DAT surface"),
    ("db/migrate/001_init.rb", False, ["COD", "DAT", "SEC"], COVERAGE,
     "#3484 R1: a `migrate/` directory segment is a DB surface (Rails' db/migrate)"),
    ("migrate/002_users.rb", False, ["COD", "DAT", "SEC"], COVERAGE,
     "#3484 R1: a top-level migrate/ segment too"),
    ("src/immigrate.py", False, ["COD", "SEC"], COVERAGE,
     "#3484 R1: a segment, not a substring"),
    ("src/migrated_users.py", False, ["COD", "SEC"], COVERAGE,
     "#3484 R1: a segment, not a substring"),
    ("bin/migrate.rb", False, ["COD", "SEC"], COVERAGE,
     "#3484 R1: a FILE named migrate is not the segment"),
    ("lib/immigrate/rules.rb", False, ["COD", "SEC"], COVERAGE,
     "#3484 R1: a directory ending in `migrate` is not the segment"),
    # #3484 R2: `schema`, `seed` and `entity` are words. They must start a path
    # segment or follow a dot and end at a separator, or be a CamelCase `Entity`.
    ("src/identity.py", False, ["COD", "SEC"], COVERAGE,
     "#3484 R2: `entity` inside `identity` is not the word"),
    ("src/identities.py", False, ["COD", "SEC"], COVERAGE,
     "#3484 R2: nor is `entities` inside `identities`"),
    ("config/initializers/html_entities.rb", False, ["COD", "SEC"], COVERAGE,
     "#3484 R2: railsgoat's HTML entities; an `_` compound is not the word"),
    ("src/random_seed.py", False, ["COD", "SEC"], COVERAGE,
     "#3484 R2: `seed` after `random_` is not the word"),
    ("lib/seedling.py", False, ["COD", "SEC"], COVERAGE,
     "#3484 R2: the word must END at a separator"),
    ("src/jsonschema_util.py", False, ["COD", "SEC"], COVERAGE,
     "#3484 R2: `schema` inside `jsonschema` is not the word"),
    ("src/config_schema.py", False, ["COD", "SEC"], COVERAGE,
     "#3484 R2: a JSON-Schema module, an `_` compound"),
    ("src/schematics/index.ts", False, ["COD", "SEC"], COVERAGE,
     "#3484 R2: Angular schematics; the word must END at a separator"),
    ("db/schema.rb", False, ["COD", "DAT", "SEC"], COVERAGE,
     "#3484 R2: Rails' schema; only the `schema` word draws its DAT"),
    ("schema.sql", False, ["COD", "DAT", "SEC"], COVERAGE, "#3484 R2 keeps"),
    ("prisma/schema.prisma", False, ["COD", "DAT", "SEC"], COVERAGE,
     "#3484 R2 keeps"),
    ("src/cats/cat.schema.ts", False, ["COD", "DAT", "SEC"], COVERAGE,
     "#3484 R2: Mongoose's `.schema.` suffix, a dot-led word"),
    ("db/seeds.rb", False, ["COD", "DAT", "SEC"], COVERAGE,
     "#3484 R2: Rails' seeds; only the `seed` word draws its DAT"),
    ("seeds/001.sql", False, ["COD", "DAT", "SEC"], COVERAGE, "#3484 R2 keeps"),
    ("db/seed_users.rb", False, ["COD", "DAT", "SEC"], COVERAGE,
     "#3484 R2: a word may END at `_`; only the `seed` word draws its DAT"),
    ("src/entities/user.ts", False, ["COD", "DAT", "SEC"], COVERAGE,
     "#3484 R2 keeps"),
    ("app/entity/Order.java", False, ["COD", "DAT", "SEC"], COVERAGE,
     "#3484 R2 keeps"),
    ("src/user.entity.ts", False, ["COD", "DAT", "SEC"], COVERAGE,
     "#3484 R2: TypeORM's `.entity.` suffix, a dot-led word"),
    ("UserEntity.java", False, ["COD", "DAT", "SEC"], COVERAGE,
     "#3484 R2: a CamelCase `Entity`, matched case-sensitively"),
    # #3484 R3: `/test_` starts a path segment; `.spec.` skips yaml/yml/json.
    ("src/latest_version.py", False, ["COD", "SEC"], COVERAGE,
     "#3484 R3: `test_` inside `latest_` does not start a segment"),
    ("src/contest_results.py", False, ["COD", "SEC"], COVERAGE,
     "#3484 R3: nor inside `contest_`"),
    ("api/openapi.spec.yaml", False, ["COD", "SEC"], COVERAGE,
     "#3484 R3: an API description, not a test"),
    ("api/openapi.spec.yml", False, ["COD", "SEC"], COVERAGE, "#3484 R3: as .yaml"),
    ("api/user.spec.json", False, ["COD", "SEC"], COVERAGE, "#3484 R3: as .yaml"),
    ("tests/test_api.py", True, ["COD", "SEC", "TST"], COVERAGE, "#3484 R3 keeps"),
    ("test_api.py", True, ["COD", "SEC", "TST"], COVERAGE,
     "#3484 R3 keeps, at the top level too"),
    ("src/test_main.c", False, ["COD", "SEC", "TST"], COVERAGE,
     "#3484 R3: only the `/test_` hint draws its TST"),
    ("src/foo.spec.ts", True, ["COD", "SEC", "TST"], COVERAGE,
     "#3484 R3 keeps; the naming rule decides it"),
    ("foo.spec.js", True, ["COD", "SEC", "TST"], COVERAGE, "as src/foo.spec.ts"),
    ("src/__snapshots__/foo.spec.ts.snap", False, ["COD", "SEC", "TST"], COVERAGE,
     "#3484 R3: only `.spec.` draws its TST"),
    ("src/db.query.py", False, ["COD", "DAT", "SEC"], COVERAGE,
     "the `/db.` hint draws DAT"),
    ("app/Models/User.cs", False, ["COD", "DAT", "SEC"], COVERAGE,
     "the model-directory hint is case-insensitive"),
    ("src/repository.py", False, ["COD", "DAT", "SEC"], COVERAGE,
     "the repository filename hint draws DAT"),
    ("data/app.sqlite", False, ["COD", "DAT", "SEC"], COVERAGE,
     "a database extension draws DAT"),
]


class TheSignalsTest(unittest.TestCase):
    def test_each_row_is_todays_coverage_answer(self):
        for path, is_test, floor, label, why in SIGNALS:
            with self.subTest(path=path, label=label):
                self.assertEqual(is_test, discovery.is_test_file(path), why)
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

    def test_every_row_is_labelled_and_explained(self):
        labels = {label for _p, _d, _f, label, _w in SIGNALS}
        self.assertEqual({COVERAGE, SHARED}, labels)
        for path, _d, _f, _label, why in SIGNALS:
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

# Exact output of the retired discovery.compute_group_panels over GROUPS on the
# #3485 parent. Fixture data, not a second derivation: it exists only to prove
# old run folders keep loading and route like new schedule-free artifacts.
LEGACY_GROUP_PANELS = {
    "Readme": ["security", "architecture", "code"],
    "Assets": ["security", "code"],
    "Docs": ["security", "architecture", "code"],
    "DbQuery": ["security", "code"],
    "Rails": ["security", "database", "code"],
    "Conftest": ["security", "code"],
    "Ident": ["security", "code"],
    "Latest": ["security", "code"],
    "ApiSpec": ["security", "code"],
    "Committed": ["security", "code"],
    "Widened": ["security", "code"],
    "Excl": ["security", "code", "test"],
}
LEGACY_PANEL_NAMES = ["security", "redteam", "architecture", "database", "code", "test"]


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
        """Write groups.json with `panels(name, files)` per entry (None: omit),
        run the coverage phase to completion and return every coverage file's
        bytes."""
        groups = []
        for name, files in GROUPS.items():
            entry = {"name": name, "files": files}
            value = panels(name, files)
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
    """The retired groups.json `panels` schedule routes nothing (#3485)."""

    def test_old_artifact_loads_and_routes_exactly_like_omission(self):
        legacy_groups = [
            {"name": name, "files": files, "panels": LEGACY_GROUP_PANELS[name]}
            for name, files in GROUPS.items()
        ]
        legacy_doc = {"run_id": self.manifest["run_id"], "groups": legacy_groups}
        self.assertEqual(discovery_phase.groups_artifact_errors(
            legacy_doc, self.manifest), [])

        legacy = self._route(lambda name, _files: LEGACY_GROUP_PANELS[name])
        omitted = self._route(lambda _name, _files: None)
        everything = sorted(groups_schema.DOMAINS) + LEGACY_PANEL_NAMES
        self.assertEqual(legacy, omitted)
        self.assertEqual(legacy, self._route(lambda _name, _files: everything))


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
        routed = self._route(lambda _name, _files: None)
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
