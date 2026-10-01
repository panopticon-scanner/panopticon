"""The tools manifest's own tests (#1762 ARC-2609514778, part 3 of 3).

`scripts.tools_manifest` was lifted out of `run_tools` whole in split 3 of 3, so
the centre of this file is a PARITY golden rather than new behaviour: the exact
BYTES `tools-manifest.json` is written with, captured from the tree before the
move and compared byte for byte after it. The manifest is a published schema
other tools parse (`security_gate`, the tools phase, `synthesize`), and an
extraction that changes one key, one value or the order they sit in is not a
pure extraction.

The golden is a LITERAL on purpose. It must be regenerated -- by the command in
the PR's implementation notes, from the then-current main -- by any later change
that legitimately alters a manifest key, a posture value or the JSON encoding;
a difference produced by anything else is the change being wrong.

Below the golden is everything that came out of `tests/test_run_tools_core.py` with
the writer, names and bodies unchanged: six self-contained scope-row tests
gathered into one new class, then the two classes whose subject was already the
manifest -- its redaction claim and its suppression-comment posture, both of which
drive `run_tools()` to fill a ledger and then ask the manifest what it published.
Three writer tests stayed behind on purpose, each because it also drives
production code that did NOT move: `test_manifest_discloses_missing_selected_tools`
and `test_manifest_selection_excludes_offline_policy_skips` are about
`select_tools`/`filter_online` feeding the manifest, and
`test_manifest_and_redacted_capture_keep_only_safe_parser_facts` is a
capture+parse+ingest chain that ends at a manifest read.

`skill/scripts/run_manifest.py` writes the OTHER manifest (the review run's) and
has its own `write_manifest`; `tests/test_run_manifest.py` is its file.
"""
import contextlib
import io
import json
import os
import tempfile
import unittest
from unittest import mock

import scripts.run_tools as rt
import scripts.scanner_config as sc
import scripts.tool_capture as tc
import scripts.tools_manifest as tm

from tests.run_tools_test_helpers import _FakeResult

# One fixed selection for every case: bandit and trivy are the two tools
# `SCANNER_OWNED_CONFIG` stages (so `scanner_config` fills), gitleaks is the one
# tool an ignore-file observation may be published for, semgrep is the
# ingest-lever suppression row and gosec the no-knob residual. Five tools fill
# all five ledgers from one run.
_TOOLS = ("semgrep", "bandit", "gitleaks", "trivy", "gosec")
# An adapter whose whole surface fell under the gate's globs, and the globs that
# did it: both are published on every manifest, `[]` included.
_EXCLUDED_SCOPE = ("npm-audit",)
_GLOBS = ("vendor/**", "docs/*.md")
# One row per `_excluded_dir_row` branch: skipped on the marker, detected but
# scanned with a note, and the marker-without-shape reason that is never handed
# to a scanner.
_EXCLUDED_DIRS = (
    {"path": ".venv", "reason": "pyvenv.cfg"},
    {"path": "tools/venv", "reason": "name", "skipped": False,
     "note": "scanned: the directory name cannot be handed to an exclusion knob"},
    {"path": "src", "reason": "pyvenv.cfg-without-shape", "skipped": False,
     "note": "scanned: a pyvenv.cfg with no interpreter or site-packages under it"},
)
_SANITIZED = {"pip-audit": {"source": "requirements.txt", "kept": 2,
                            "dropped": [{"line": "-e .", "reason": "local path"}],
                            "hashes_stripped": True}}
# The refusal posture, as `egress` spells it: the adapter leaves `selected` for
# `excluded_scope` and the manifest says why.
_REFUSED_NETWORK = {"semgrep": "none", "bandit": "none", "gitleaks": "none",
                    "trivy": "none", "gosec": "none",
                    "pip-audit": "excluded:online egress unavailable"}
# A capture with BOTH file_coverage branches in it: one row eslint could not
# parse and the typescript-parser envelope the adapter writes when it had to
# fall back. Modelled on `TestEslintFileCoverageCapture`'s payloads.
_ESLINT_CAPTURE = {
    "panopticon_eslint": {"version": 1, "typescript_parser": "unavailable",
                          "files_count": 1, "files": ["nested/app.ts"]},
    "results": [
        {"filePath": "/src/good.js",
         "messages": [{"ruleId": "security/detect-eval-with-expression",
                       "message": "eval with expression", "line": 1}]},
        {"filePath": "/src/bad.js", "fatalErrorCount": 1,
         "messages": [{"ruleId": None, "fatal": True,
                       "message": "Parsing error: source unavailable"}]},
    ],
}

# case -> (security mode driven, run_id written, shape)
_CASES = {
    "standard/with-run-id": ("standard", "c3-golden-run", "driven"),
    "standard/no-run-id": ("standard", None, "driven"),
    "redteam/with-run-id": ("redteam", "c3-golden-run", "driven"),
    "redteam/no-run-id": ("redteam", None, "driven"),
    "standard/eslint-file-coverage": ("standard", "c3-golden-run", "eslint"),
    "standard/an-adapter-refused-egress": ("standard", "c3-golden-run", "refused"),
    "standard/nothing-produced": ("standard", "c3-golden-run", "nothing-produced"),
}


def _drive(target, security_mode, tools):
    """Fill the five ledgers the way a real scan does, with a faked runner.

    Through `run_tools()`, the public entry -- so the postures the golden pins
    are the ones the production loop observes itself granting, not values this
    test composed. `run_tools()` clears all five ledgers on entry, so every case
    is independent of the one before it.
    """
    def runner(cmd, **_kw):
        return _FakeResult(returncode=0, stdout=b'{"runs":[]}')
    with contextlib.redirect_stderr(io.StringIO()):
        return rt.run_tools(target, list(tools), os.path.join(target, "tools"),
                            runner=runner, venv_dirs=[],
                            security_mode=security_mode)


def _case_bytes(case, d):
    """`(the file's bytes, the returned payload)` for one golden case."""
    mode, run_id, shape = _CASES[case]
    written = _drive(d, mode, () if shape == "nothing-produced" else _TOOLS)
    kwargs = {"excluded_scope": _EXCLUDED_SCOPE, "run_id": run_id,
              "excluded_dirs": _EXCLUDED_DIRS, "sanitized": _SANITIZED,
              "exclude_globs": _GLOBS}
    selected = list(_TOOLS)
    if shape == "eslint":
        capture = os.path.join(d, "tools", "eslint-security.json")
        with open(capture, "w", encoding="utf-8") as fh:
            json.dump(_ESLINT_CAPTURE, fh)
        written = list(written) + [capture]
    elif shape == "refused":
        # The refused adapter is SELECTED here, so the filter that moves it out
        # of `selected` and into `excluded_scope` is the branch being pinned:
        # a tool left in both lists reads as a required scanner that went
        # missing, and `security_gate` rejects the overlap outright.
        kwargs["network"] = dict(_REFUSED_NETWORK)
        selected = selected + ["pip-audit"]
    path = os.path.join(d, "manifest", "tools-manifest.json")
    payload = tm.write_manifest(path, selected, written, **kwargs)
    with open(path, "rb") as fh:
        return fh.read(), payload


# Captured from the tree at the commit this split branched from, BEFORE any code
# moved (the command is in the PR's implementation notes). A difference here is
# the extraction being wrong: fix the extraction, never this table.
GOLDEN: dict[str, str] = {
    "redteam/no-run-id": """\
{
  "schema_version": 1,
  "run_id": null,
  "file_coverage": {},
  "selected": [
    "semgrep",
    "bandit",
    "gitleaks",
    "trivy",
    "gosec"
  ],
  "produced": [
    "bandit",
    "gitleaks",
    "gosec",
    "semgrep",
    "trivy"
  ],
  "missing": [],
  "redacted": true,
  "excluded_scope": [
    "npm-audit"
  ],
  "network": {
    "semgrep": "none",
    "bandit": "none",
    "gitleaks": "none",
    "trivy": "none",
    "gosec": "none"
  },
  "suppression_comments": {
    "semgrep": "ignored",
    "bandit": "ignored",
    "gitleaks": "ignored",
    "trivy": "n/a",
    "gosec": "honoured"
  },
  "ignore_files": {
    "gitleaks": "absent"
  },
  "scanner_config": {
    "bandit": "scanner-owned",
    "trivy": "scanner-owned"
  },
  "scanner_scope": {
    "semgrep": "test-paths-v1"
  },
  "sanitized": {
    "pip-audit": {
      "source": "requirements.txt",
      "kept": 2,
      "dropped": [
        {
          "line": "-e .",
          "reason": "local path"
        }
      ],
      "hashes_stripped": true
    }
  },
  "exclude_globs": [
    "vendor/**",
    "docs/*.md"
  ],
  "excluded_dirs": [
    {
      "path": ".venv",
      "reason": "pyvenv.cfg",
      "skipped": true
    },
    {
      "path": "tools/venv",
      "reason": "name",
      "skipped": false,
      "note": "scanned: the directory name cannot be handed to an exclusion knob"
    },
    {
      "path": "src",
      "reason": "pyvenv.cfg-without-shape",
      "skipped": false,
      "note": "scanned: a pyvenv.cfg with no interpreter or site-packages under it"
    }
  ],
  "depth_bound": 3
}
""",
    "redteam/with-run-id": """\
{
  "schema_version": 1,
  "run_id": "c3-golden-run",
  "file_coverage": {},
  "selected": [
    "semgrep",
    "bandit",
    "gitleaks",
    "trivy",
    "gosec"
  ],
  "produced": [
    "bandit",
    "gitleaks",
    "gosec",
    "semgrep",
    "trivy"
  ],
  "missing": [],
  "redacted": true,
  "excluded_scope": [
    "npm-audit"
  ],
  "network": {
    "semgrep": "none",
    "bandit": "none",
    "gitleaks": "none",
    "trivy": "none",
    "gosec": "none"
  },
  "suppression_comments": {
    "semgrep": "ignored",
    "bandit": "ignored",
    "gitleaks": "ignored",
    "trivy": "n/a",
    "gosec": "honoured"
  },
  "ignore_files": {
    "gitleaks": "absent"
  },
  "scanner_config": {
    "bandit": "scanner-owned",
    "trivy": "scanner-owned"
  },
  "scanner_scope": {
    "semgrep": "test-paths-v1"
  },
  "sanitized": {
    "pip-audit": {
      "source": "requirements.txt",
      "kept": 2,
      "dropped": [
        {
          "line": "-e .",
          "reason": "local path"
        }
      ],
      "hashes_stripped": true
    }
  },
  "exclude_globs": [
    "vendor/**",
    "docs/*.md"
  ],
  "excluded_dirs": [
    {
      "path": ".venv",
      "reason": "pyvenv.cfg",
      "skipped": true
    },
    {
      "path": "tools/venv",
      "reason": "name",
      "skipped": false,
      "note": "scanned: the directory name cannot be handed to an exclusion knob"
    },
    {
      "path": "src",
      "reason": "pyvenv.cfg-without-shape",
      "skipped": false,
      "note": "scanned: a pyvenv.cfg with no interpreter or site-packages under it"
    }
  ],
  "depth_bound": 3
}
""",
    "standard/an-adapter-refused-egress": """\
{
  "schema_version": 1,
  "run_id": "c3-golden-run",
  "file_coverage": {},
  "selected": [
    "semgrep",
    "bandit",
    "gitleaks",
    "trivy",
    "gosec"
  ],
  "produced": [
    "bandit",
    "gitleaks",
    "gosec",
    "semgrep",
    "trivy"
  ],
  "missing": [],
  "redacted": true,
  "excluded_scope": [
    "npm-audit",
    "pip-audit"
  ],
  "network": {
    "semgrep": "none",
    "bandit": "none",
    "gitleaks": "none",
    "trivy": "none",
    "gosec": "none",
    "pip-audit": "excluded:online egress unavailable"
  },
  "suppression_comments": {
    "semgrep": "honoured",
    "bandit": "honoured",
    "gitleaks": "honoured",
    "trivy": "n/a",
    "gosec": "honoured"
  },
  "ignore_files": {
    "gitleaks": "absent"
  },
  "scanner_config": {
    "bandit": "scanner-owned",
    "trivy": "scanner-owned"
  },
  "scanner_scope": {
    "semgrep": "test-paths-v1"
  },
  "sanitized": {
    "pip-audit": {
      "source": "requirements.txt",
      "kept": 2,
      "dropped": [
        {
          "line": "-e .",
          "reason": "local path"
        }
      ],
      "hashes_stripped": true
    }
  },
  "exclude_globs": [
    "vendor/**",
    "docs/*.md"
  ],
  "excluded_dirs": [
    {
      "path": ".venv",
      "reason": "pyvenv.cfg",
      "skipped": true
    },
    {
      "path": "tools/venv",
      "reason": "name",
      "skipped": false,
      "note": "scanned: the directory name cannot be handed to an exclusion knob"
    },
    {
      "path": "src",
      "reason": "pyvenv.cfg-without-shape",
      "skipped": false,
      "note": "scanned: a pyvenv.cfg with no interpreter or site-packages under it"
    }
  ],
  "depth_bound": 3
}
""",
    "standard/eslint-file-coverage": """\
{
  "schema_version": 1,
  "run_id": "c3-golden-run",
  "file_coverage": {
    "eslint-security": {
      "status": "partial",
      "parsed_files": 1,
      "unparsed_files": 1,
      "unavailable_files": 1,
      "files": [
        {
          "file": "bad.js",
          "reason": "parse_error"
        },
        {
          "file": "nested/app.ts",
          "reason": "typescript_parser_unavailable"
        }
      ],
      "files_omitted": 0,
      "capabilities_unavailable": [
        "typescript_parser"
      ]
    }
  },
  "selected": [
    "semgrep",
    "bandit",
    "gitleaks",
    "trivy",
    "gosec"
  ],
  "produced": [
    "bandit",
    "eslint-security",
    "gitleaks",
    "gosec",
    "semgrep",
    "trivy"
  ],
  "missing": [],
  "redacted": false,
  "excluded_scope": [
    "npm-audit"
  ],
  "network": {
    "semgrep": "none",
    "bandit": "none",
    "gitleaks": "none",
    "trivy": "none",
    "gosec": "none"
  },
  "suppression_comments": {
    "semgrep": "honoured",
    "bandit": "honoured",
    "gitleaks": "honoured",
    "trivy": "n/a",
    "gosec": "honoured"
  },
  "ignore_files": {
    "gitleaks": "absent"
  },
  "scanner_config": {
    "bandit": "scanner-owned",
    "trivy": "scanner-owned"
  },
  "scanner_scope": {
    "semgrep": "test-paths-v1"
  },
  "sanitized": {
    "pip-audit": {
      "source": "requirements.txt",
      "kept": 2,
      "dropped": [
        {
          "line": "-e .",
          "reason": "local path"
        }
      ],
      "hashes_stripped": true
    }
  },
  "exclude_globs": [
    "vendor/**",
    "docs/*.md"
  ],
  "excluded_dirs": [
    {
      "path": ".venv",
      "reason": "pyvenv.cfg",
      "skipped": true
    },
    {
      "path": "tools/venv",
      "reason": "name",
      "skipped": false,
      "note": "scanned: the directory name cannot be handed to an exclusion knob"
    },
    {
      "path": "src",
      "reason": "pyvenv.cfg-without-shape",
      "skipped": false,
      "note": "scanned: a pyvenv.cfg with no interpreter or site-packages under it"
    }
  ],
  "depth_bound": 3
}
""",
    "standard/no-run-id": """\
{
  "schema_version": 1,
  "run_id": null,
  "file_coverage": {},
  "selected": [
    "semgrep",
    "bandit",
    "gitleaks",
    "trivy",
    "gosec"
  ],
  "produced": [
    "bandit",
    "gitleaks",
    "gosec",
    "semgrep",
    "trivy"
  ],
  "missing": [],
  "redacted": true,
  "excluded_scope": [
    "npm-audit"
  ],
  "network": {
    "semgrep": "none",
    "bandit": "none",
    "gitleaks": "none",
    "trivy": "none",
    "gosec": "none"
  },
  "suppression_comments": {
    "semgrep": "honoured",
    "bandit": "honoured",
    "gitleaks": "honoured",
    "trivy": "n/a",
    "gosec": "honoured"
  },
  "ignore_files": {
    "gitleaks": "absent"
  },
  "scanner_config": {
    "bandit": "scanner-owned",
    "trivy": "scanner-owned"
  },
  "scanner_scope": {
    "semgrep": "test-paths-v1"
  },
  "sanitized": {
    "pip-audit": {
      "source": "requirements.txt",
      "kept": 2,
      "dropped": [
        {
          "line": "-e .",
          "reason": "local path"
        }
      ],
      "hashes_stripped": true
    }
  },
  "exclude_globs": [
    "vendor/**",
    "docs/*.md"
  ],
  "excluded_dirs": [
    {
      "path": ".venv",
      "reason": "pyvenv.cfg",
      "skipped": true
    },
    {
      "path": "tools/venv",
      "reason": "name",
      "skipped": false,
      "note": "scanned: the directory name cannot be handed to an exclusion knob"
    },
    {
      "path": "src",
      "reason": "pyvenv.cfg-without-shape",
      "skipped": false,
      "note": "scanned: a pyvenv.cfg with no interpreter or site-packages under it"
    }
  ],
  "depth_bound": 3
}
""",
    "standard/nothing-produced": """\
{
  "schema_version": 1,
  "run_id": "c3-golden-run",
  "file_coverage": {},
  "selected": [
    "semgrep",
    "bandit",
    "gitleaks",
    "trivy",
    "gosec"
  ],
  "produced": [],
  "missing": [
    "bandit",
    "gitleaks",
    "gosec",
    "semgrep",
    "trivy"
  ],
  "redacted": false,
  "excluded_scope": [
    "npm-audit"
  ],
  "network": {},
  "suppression_comments": {},
  "ignore_files": {},
  "scanner_config": {},
  "scanner_scope": {},
  "sanitized": {
    "pip-audit": {
      "source": "requirements.txt",
      "kept": 2,
      "dropped": [
        {
          "line": "-e .",
          "reason": "local path"
        }
      ],
      "hashes_stripped": true
    }
  },
  "exclude_globs": [
    "vendor/**",
    "docs/*.md"
  ],
  "excluded_dirs": [
    {
      "path": ".venv",
      "reason": "pyvenv.cfg",
      "skipped": true
    },
    {
      "path": "tools/venv",
      "reason": "name",
      "skipped": false,
      "note": "scanned: the directory name cannot be handed to an exclusion knob"
    },
    {
      "path": "src",
      "reason": "pyvenv.cfg-without-shape",
      "skipped": false,
      "note": "scanned: a pyvenv.cfg with no interpreter or site-packages under it"
    }
  ],
  "depth_bound": 3
}
""",
    "standard/with-run-id": """\
{
  "schema_version": 1,
  "run_id": "c3-golden-run",
  "file_coverage": {},
  "selected": [
    "semgrep",
    "bandit",
    "gitleaks",
    "trivy",
    "gosec"
  ],
  "produced": [
    "bandit",
    "gitleaks",
    "gosec",
    "semgrep",
    "trivy"
  ],
  "missing": [],
  "redacted": true,
  "excluded_scope": [
    "npm-audit"
  ],
  "network": {
    "semgrep": "none",
    "bandit": "none",
    "gitleaks": "none",
    "trivy": "none",
    "gosec": "none"
  },
  "suppression_comments": {
    "semgrep": "honoured",
    "bandit": "honoured",
    "gitleaks": "honoured",
    "trivy": "n/a",
    "gosec": "honoured"
  },
  "ignore_files": {
    "gitleaks": "absent"
  },
  "scanner_config": {
    "bandit": "scanner-owned",
    "trivy": "scanner-owned"
  },
  "scanner_scope": {
    "semgrep": "test-paths-v1"
  },
  "sanitized": {
    "pip-audit": {
      "source": "requirements.txt",
      "kept": 2,
      "dropped": [
        {
          "line": "-e .",
          "reason": "local path"
        }
      ],
      "hashes_stripped": true
    }
  },
  "exclude_globs": [
    "vendor/**",
    "docs/*.md"
  ],
  "excluded_dirs": [
    {
      "path": ".venv",
      "reason": "pyvenv.cfg",
      "skipped": true
    },
    {
      "path": "tools/venv",
      "reason": "name",
      "skipped": false,
      "note": "scanned: the directory name cannot be handed to an exclusion knob"
    },
    {
      "path": "src",
      "reason": "pyvenv.cfg-without-shape",
      "skipped": false,
      "note": "scanned: a pyvenv.cfg with no interpreter or site-packages under it"
    }
  ],
  "depth_bound": 3
}
""",
}


class TestTheManifestBytesSurviveTheExtraction(unittest.TestCase):
    """Seven manifests, all five ledgers populated by a real dispatch, both
    security modes, `run_id` set and unset, the eslint `file_coverage` read, an
    adapter refused its egress, and the docker-absent shape where nothing was
    produced. The comparison is the FILE, not the returned dict: the bytes are
    what `security_gate` and the tools phase parse."""

    def test_every_case_lands_exactly_the_golden_bytes(self):
        for case in sorted(_CASES):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as d:
                data, payload = _case_bytes(case, d)
                self.assertEqual(data.decode("utf-8"), GOLDEN[case])
                self.assertEqual(data, GOLDEN[case].encode("utf-8"))
                # the returned dict and the written bytes are one answer: the
                # phase copies the return value, the gate reads the file.
                self.assertEqual(payload, json.loads(data))

    def test_the_golden_pins_every_case_and_no_stale_one(self):
        self.assertEqual(sorted(GOLDEN), sorted(_CASES))

    def test_the_golden_can_mean_the_bytes_it_is_compared_to(self):
        """The literal's own precondition, which the emitter checked and the tree
        has to keep checking.

        `json.dump` runs with `ensure_ascii=True`, so the moment a manifest value
        carries a non-ASCII character -- a path under `excluded_dirs`, a
        `sanitized` reason, a tool name -- the FILE gets `\\uXXXX` as six ASCII
        bytes while a `\"\"\"...\"\"\"` literal decodes the same source to ONE
        character, and the byte assertion above fails for a reason that has
        nothing to do with the change under test. A Windows-style path does the
        same with `\\\\`. Either case means the golden must move out of a Python
        literal (or be escaped deliberately), and this says so at the point of
        failure instead of leaving it to be diagnosed.
        """
        for case, text in sorted(GOLDEN.items()):
            with self.subTest(case=case):
                self.assertNotIn("\\", text,
                                 "a backslash in the golden cannot survive the "
                                 "round trip through a Python string literal")
                self.assertTrue(text.isascii(),
                                "json.dump escapes non-ASCII to \\uXXXX in the "
                                "FILE; this literal holds the decoded character")


class TestTheManifestPublishesItsScopeRows(unittest.TestCase):
    """Six rows the manifest states on EVERY manifest -- the excluded scope, the
    pruned virtualenv rows with their depth bound, the exclude globs and the
    sanitizer disclosure -- each also at its empty value, because absence must
    not be readable as "nobody measured"; they came out of
    `tests/test_run_tools_core.py` with the writer, names and bodies unchanged."""

    def test_manifest_records_excluded_scope(self):
        with tempfile.TemporaryDirectory() as d:
            payload = tm.write_manifest(
                os.path.join(d, "m.json"), ["semgrep"], [],
                excluded_scope=["eslint-security"])
            self.assertEqual(payload["excluded_scope"], ["eslint-security"])
            self.assertNotIn("eslint-security", payload["selected"])

    def test_manifest_records_excluded_dirs_with_reasons(self):
        with tempfile.TemporaryDirectory() as d:
            payload = tm.write_manifest(
                os.path.join(d, "m.json"), ["semgrep"], [],
                excluded_dirs=[{"path": ".venv", "reason": "pyvenv.cfg"},
                               {"path": "venv", "reason": "name"}])
            # #1740: `skipped` defaults to True, the pre-#1740 meaning of
            # this list, for a caller handing `find_virtualenvs` output in.
            self.assertEqual(payload["excluded_dirs"],
                             [{"path": ".venv", "reason": "pyvenv.cfg",
                               "skipped": True},
                              {"path": "venv", "reason": "name",
                               "skipped": True}])
            # F2: the list is what the SCAN was told to skip, found by a
            # depth-bounded walk -- ingest prunes a superset, at any depth.
            self.assertEqual(payload["depth_bound"], rt.VENV_MAX_DEPTH)
            with open(os.path.join(d, "m.json"), encoding="utf-8") as fh:
                self.assertEqual(json.load(fh), payload)

    def test_manifest_records_the_exclude_globs_it_was_given(self):
        # #1740 fix round 1: the committed `exclude_paths:` policy now reaches
        # the scan, so the manifest says which globs this run was handed --
        # beside `excluded_scope` (the adapters those globs disqualified) and
        # `excluded_dirs` (the virtualenvs). Stated on every manifest, `[]`
        # included: absence must not read as "nobody measured".
        with tempfile.TemporaryDirectory() as d:
            payload = tm.write_manifest(os.path.join(d, "m.json"), ["semgrep"], [],
                                        exclude_globs=["tests/fixtures/**"])
            self.assertEqual(payload["exclude_globs"], ["tests/fixtures/**"])
            bare = tm.write_manifest(os.path.join(d, "b.json"), ["semgrep"], [])
            self.assertEqual(bare["exclude_globs"], [])

    def test_manifest_records_what_the_sanitizer_dropped(self):
        # #1646 ruling 3: the audit was PARTIAL and the manifest says so.
        block = {"pip-audit": {"source": "requirements.txt", "kept": 2,
                               "dropped": [{"line": "-e .", "reason": "editable"}],
                               "hashes_stripped": True}}
        with tempfile.TemporaryDirectory() as d:
            payload = tm.write_manifest(os.path.join(d, "m.json"), ["pip-audit"],
                                        [], sanitized=block)
            self.assertEqual(payload["sanitized"], block)
            with open(os.path.join(d, "m.json"), encoding="utf-8") as fh:
                self.assertEqual(json.load(fh)["sanitized"], block)

    def test_manifest_sanitized_defaults_to_empty(self):
        # Stated on every manifest, `{}` included: absence must not be readable
        # as "nobody measured" -- the same rule `excluded_dirs` follows.
        with tempfile.TemporaryDirectory() as d:
            payload = tm.write_manifest(os.path.join(d, "m.json"), ["semgrep"], [])
            self.assertEqual(payload["sanitized"], {})

    def test_manifest_excluded_dirs_defaults_to_empty(self):
        with tempfile.TemporaryDirectory() as d:
            payload = tm.write_manifest(os.path.join(d, "m.json"), ["semgrep"], [])
            self.assertEqual(payload["excluded_dirs"], [])
            self.assertEqual(payload["depth_bound"], rt.VENV_MAX_DEPTH)


class TestTheManifestReportsTheRedactionPass(unittest.TestCase):
    """#1639 P11 fix round 1 (F5): `tools-ran.json`'s `redacted` claim used to
    be a literal in the phase module asserting another module's behaviour. The
    runner reports what it actually did -- `tool_capture._redact_capture`
    records each capture it passes, `write_manifest` publishes it, and the phase
    copies the answer instead of restating it."""

    TOKEN = "ghp_" + "MANIFEST" + "M" * 28

    def _run(self, d, patch_identity=False):
        payload = json.dumps({"runs": [{"results": [
            {"ruleId": "r", "message": {"text": self.TOKEN}}]}]}).encode()

        def runner(cmd, **kw):
            return _FakeResult(returncode=0, stdout=payload)

        out_dir = os.path.join(d, "tools")
        ctx = (mock.patch.object(tc, "_redact_capture", lambda tool, data: data)
               if patch_identity else contextlib.nullcontext())
        with contextlib.redirect_stderr(io.StringIO()), ctx:
            written = rt.run_tools(d, ["gitleaks", "semgrep"], out_dir, runner=runner)
        return tm.write_manifest(os.path.join(d, "tools-manifest.json"),
                                 ["gitleaks", "semgrep"], written)

    def test_a_run_through_the_choke_point_claims_the_pass(self):
        with tempfile.TemporaryDirectory() as d:
            payload = self._run(d)
        self.assertEqual(payload["produced"], ["gitleaks", "semgrep"])
        self.assertIs(payload["redacted"], True)

    def test_bypassing_the_choke_point_makes_the_claim_go_false(self):
        """The coupling: with the redactor replaced by identity the captures are
        written unmasked, and the artifact says so rather than repeating a
        literal `true` nobody checked."""
        with tempfile.TemporaryDirectory() as d:
            payload = self._run(d, patch_identity=True)
            with open(os.path.join(d, "tools", "gitleaks.sarif"), "rb") as fh:
                self.assertIn(self.TOKEN.encode(), fh.read())   # non-vacuous
        self.assertEqual(payload["produced"], ["gitleaks", "semgrep"])
        self.assertIs(payload["redacted"], False)

    def test_no_capture_written_makes_no_claim(self):
        # The docker-absent manifest (produced=[]): nothing was written, so
        # there is nothing to vouch for.
        with tempfile.TemporaryDirectory() as d:
            payload = tm.write_manifest(os.path.join(d, "m.json"),
                                        ["gitleaks"], [])
        self.assertIs(payload["redacted"], False)


class TestTheManifestPublishesTheSuppressionPosture(unittest.TestCase):
    """#1839 (run-14 SEC-284952751): under `standard` an inline suppression
    comment in the target's own source is HONOURED -- an operator's reviewed,
    in-diff decision about their own repository -- and that is a coverage fact a
    reader of the artifacts is entitled to. So it is honoured DISCLOSED, not
    silently: `tools-manifest.json` carries one row per assessed tool.

    Like `network` and `redacted`, the claim is an OBSERVATION of what decided
    it: the argv the runner built for a flag-lever tool (bandit, gitleaks), so
    it cannot outlive the flag; the run's mode for an ingest-lever tool
    (semgrep, `SUPPRESSION_INGEST_LEVER`), where no flag decides and the mode
    is the fact.
    """

    TOOLS = ["semgrep", "bandit", "trivy", "gitleaks", "gosec"]

    def _manifest(self, d, tools=None, **kwargs):
        def runner(cmd, **kw):
            return _FakeResult(returncode=0, stdout=b'{"runs":[]}')
        tools = list(self.TOOLS if tools is None else tools)
        with contextlib.redirect_stderr(io.StringIO()):
            written = rt.run_tools(d, tools, os.path.join(d, "tools"),
                                   runner=runner, venv_dirs=[], **kwargs)
        return tm.write_manifest(os.path.join(d, "tools-manifest.json"),
                                 tools, written)

    def test_standard_says_the_comments_stood(self):
        with tempfile.TemporaryDirectory() as d:
            payload = self._manifest(d, security_mode="standard")
        self.assertEqual(payload["suppression_comments"],
                         {"semgrep": "honoured", "bandit": "honoured",
                          "gitleaks": "honoured", "gosec": "honoured",
                          "trivy": "n/a"})

    def test_redteam_says_they_were_ignored(self):
        with tempfile.TemporaryDirectory() as d:
            payload = self._manifest(d, security_mode="redteam")
        self.assertEqual(payload["suppression_comments"],
                         {"semgrep": "ignored", "bandit": "ignored",
                          "gitleaks": "ignored",
                          # No knob verified at the pin: the residual is
                          # disclosed in BOTH modes rather than invented.
                          "gosec": "honoured",
                          "trivy": "n/a"})

    def test_an_unassessed_tool_gets_no_row(self):
        # Absent is not `n/a`: "nobody looked" and "there is nothing to look
        # at" are different claims, and the tool axis has been burned by
        # reading one as the other (#1839's own `excluded_dirs` note).
        with tempfile.TemporaryDirectory() as d:
            payload = self._manifest(d, tools=["brakeman"])
        self.assertNotIn("brakeman", payload["suppression_comments"])
        self.assertNotIn("brakeman", sc.SUPPRESSION_COMMENTS)

    def test_the_claim_follows_the_argv_and_not_the_intent(self):
        # The coupling, the same way the redaction claim is coupled -- for a
        # tool whose ARGV is the lever. With bandit's knob taken out of the
        # table the redteam argv carries no `--ignore-nosec`, bandit really does
        # honour a `# nosec`, and the manifest says `honoured` instead of
        # repeating the mode back.
        table = dict(sc.SUPPRESSION_COMMENTS)
        table["bandit"] = ("# nosec", None)
        with tempfile.TemporaryDirectory() as d, \
                mock.patch.object(sc, "SUPPRESSION_COMMENTS", table):
            payload = self._manifest(d, tools=["bandit"],
                                     security_mode="redteam")
        self.assertEqual(payload["suppression_comments"],
                         {"bandit": "honoured"})

    def test_an_ingest_lever_tools_row_follows_the_mode_not_the_flag(self):
        # Re-review finding 3. semgrep's `--disable-nosem` is BELT at the pin:
        # the scanner marks and reports a `# nosemgrep`'d result either way, and
        # `sarif_utils.sarif_to_findings` is what honours the comment (under
        # `standard`) or ignores it (under `redteam`). So reading semgrep's row
        # off the argv publishes a FALSE COVERAGE CLAIM the moment the belt comes
        # off: `honoured` on a redteam run whose ingest ignores every such
        # comment. The row follows what actually governs -- the mode.
        table = dict(sc.SUPPRESSION_COMMENTS)
        table["semgrep"] = ("# nosemgrep", None)   # the belt taken off
        for mode, expected in (("redteam", "ignored"), ("standard", "honoured")):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as d, \
                    mock.patch.object(sc, "SUPPRESSION_COMMENTS", table):
                payload = self._manifest(d, tools=["semgrep"],
                                         security_mode=mode)
            self.assertEqual(payload["suppression_comments"],
                             {"semgrep": expected})

    def test_the_belt_is_still_on_the_real_redteam_argv(self):
        # The test above patches the flag away, so this one pins that the
        # unpatched redteam launch still carries it -- the belt is documented,
        # and a later semgrep may act on it.
        calls = []

        def runner(cmd, **kw):
            calls.append(list(cmd))
            return _FakeResult(returncode=0, stdout=b'{"runs":[]}')
        with tempfile.TemporaryDirectory() as d, \
                contextlib.redirect_stderr(io.StringIO()):
            rt.run_tools(d, ["semgrep"], os.path.join(d, "tools"),
                         runner=runner, venv_dirs=[], security_mode="redteam")
        self.assertIn("--disable-nosem", calls[0])

    def test_the_ledger_is_this_runs_and_not_the_last_one(self):
        with tempfile.TemporaryDirectory() as d:
            self._manifest(d, tools=["semgrep"], security_mode="redteam")
            payload = self._manifest(d, tools=["bandit"],
                                     security_mode="standard")
        self.assertEqual(payload["suppression_comments"],
                         {"bandit": "honoured"})

    def test_a_scan_that_never_ran_claims_nothing(self):
        # The docker-absent manifest: no tool was launched, so there is no
        # observation to publish.
        with tempfile.TemporaryDirectory() as d:
            payload = tm.write_manifest(os.path.join(d, "m.json"),
                                        ["semgrep"], [],
                                        suppression_comments={})
        self.assertEqual(payload["suppression_comments"], {})

    def test_explicit_ignore_file_observation_is_filtered_to_produced_gitleaks(self):
        with tempfile.TemporaryDirectory() as d:
            capture = os.path.join(d, "gitleaks.sarif")
            with open(capture, "wb") as fh:
                fh.write(b'{"runs":[]}')
            payload = tm.write_manifest(os.path.join(d, "m.json"),
                                        ["gitleaks", "semgrep"], [capture],
                                        ignore_files={"gitleaks": "neutralised",
                                                      "semgrep": "honoured"})
            missing = tm.write_manifest(os.path.join(d, "n.json"),
                                        ["gitleaks"], [],
                                        ignore_files={"gitleaks": "neutralised"})
        self.assertEqual(payload["ignore_files"], {"gitleaks": "neutralised"})
        self.assertEqual(missing["ignore_files"], {})

    def test_unknown_ignore_file_observation_cannot_invalidate_manifest(self):
        with tempfile.TemporaryDirectory() as d:
            capture = os.path.join(d, "gitleaks.sarif")
            with open(capture, "wb") as fh:
                fh.write(b'{"runs":[]}')
            for value in (None, 3, [], {}, "unexpected"):
                with self.subTest(value=value):
                    payload = tm.write_manifest(os.path.join(d, "m.json"),
                                                ["gitleaks"], [capture],
                                                ignore_files={"gitleaks": value})
                    self.assertEqual(payload["ignore_files"], {})


class TestSemgrepScopeBaselineTransition(unittest.TestCase):
    @staticmethod
    def _manifest(path, selected, produced, *, scope=None, globs=("fixtures/**",)):
        payload = {"selected": selected, "produced": produced,
                   "missing": sorted(set(selected) - set(produced)),
                   "redacted": True,
                   "network": {tool: "none" for tool in produced},
                   "suppression_comments": ({"semgrep": "ignored"}
                                             if "semgrep" in produced else {}),
                   "scanner_config": {}, "exclude_globs": list(globs)}
        if scope is not None:
            payload["scanner_scope"] = scope
        with open(path, "w", encoding="utf-8") as stream:
            json.dump(payload, stream)
        return payload

    def test_transition_requires_both_real_semgrep_captures_and_an_old_marker(self):
        current = {"selected": ["semgrep"], "produced": ["semgrep"],
                   "scanner_scope": {"semgrep": tm.SEMGREP_SCOPE_POLICY}}
        baseline = {"selected": ["semgrep"], "produced": ["semgrep"]}
        self.assertTrue(tm.semgrep_scope_transition_needed(current, baseline))
        for changed_current, changed_base in (
                ({**current, "produced": []}, baseline),
                (current, {**baseline, "produced": []}),
                (current, {**baseline, "scanner_scope": {
                    "semgrep": tm.SEMGREP_SCOPE_POLICY}})):
            with self.subTest(current=changed_current, baseline=changed_base):
                self.assertFalse(tm.semgrep_scope_transition_needed(
                    changed_current, changed_base))

    def test_transition_cli_prints_the_workflow_boolean(self):
        with tempfile.TemporaryDirectory() as root:
            current = os.path.join(root, "current.json")
            baseline = os.path.join(root, "baseline.json")
            self._manifest(current, ["semgrep"], ["semgrep"],
                           scope={"semgrep": tm.SEMGREP_SCOPE_POLICY})
            self._manifest(baseline, ["semgrep"], ["semgrep"])
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                rc = tm.manifest_cli([
                    "semgrep-scope-transition-needed",
                    "--current-manifest", current,
                    "--baseline-manifest", baseline,
                ])
        self.assertEqual(rc, 0)
        self.assertEqual(output.getvalue(), "true\n")

    def test_preparation_replaces_only_semgrep_and_publishes_marker_last(self):
        with tempfile.TemporaryDirectory() as root:
            base_dir = os.path.join(root, "base")
            expanded_dir = os.path.join(root, "expanded")
            os.mkdir(base_dir)
            os.mkdir(expanded_dir)
            base_manifest = os.path.join(root, "base.json")
            expanded_manifest = os.path.join(root, "expanded.json")
            self._manifest(base_manifest, ["bandit", "semgrep"],
                           ["bandit", "semgrep"])
            self._manifest(expanded_manifest, ["semgrep"], ["semgrep"],
                           scope={"semgrep": tm.SEMGREP_SCOPE_POLICY})
            old = '{"runs":[{"properties":{"scope":"old"}}]}'
            new = '{"runs":[{"properties":{"scope":"expanded"}}]}'
            with open(os.path.join(base_dir, "semgrep.sarif"), "w") as stream:
                stream.write(old)
            with open(os.path.join(base_dir, "bandit.sarif"), "w") as stream:
                stream.write("bandit stays")
            with open(os.path.join(expanded_dir, "semgrep.sarif"), "w") as stream:
                stream.write(new)

            tm.prepare_semgrep_scope_baseline(
                base_dir, base_manifest, expanded_dir, expanded_manifest)

            with open(base_manifest, encoding="utf-8") as stream:
                prepared = json.load(stream)
            with open(os.path.join(base_dir, "semgrep.sarif"), encoding="utf-8") as stream:
                self.assertEqual(stream.read(), new)
            with open(os.path.join(base_dir, "bandit.sarif"), encoding="utf-8") as stream:
                self.assertEqual(stream.read(), "bandit stays")
            self.assertEqual(prepared["selected"], ["bandit", "semgrep"])
            self.assertEqual(prepared["scanner_scope"],
                             {"semgrep": tm.SEMGREP_SCOPE_POLICY})

    def test_different_exclusion_policy_refuses_without_mutating_baseline(self):
        with tempfile.TemporaryDirectory() as root:
            base_dir = os.path.join(root, "base")
            expanded_dir = os.path.join(root, "expanded")
            os.mkdir(base_dir)
            os.mkdir(expanded_dir)
            base_manifest = os.path.join(root, "base.json")
            expanded_manifest = os.path.join(root, "expanded.json")
            self._manifest(base_manifest, ["semgrep"], ["semgrep"])
            self._manifest(expanded_manifest, ["semgrep"], ["semgrep"],
                           scope={"semgrep": tm.SEMGREP_SCOPE_POLICY}, globs=())
            capture = os.path.join(base_dir, "semgrep.sarif")
            with open(capture, "w") as stream:
                stream.write('{"runs":[]}')
            with open(expanded_dir + "/semgrep.sarif", "w") as stream:
                stream.write('{"runs":[]}')
            before_manifest = open(base_manifest, "rb").read()
            before_capture = open(capture, "rb").read()

            with self.assertRaisesRegex(ValueError, "different scan policy"):
                tm.prepare_semgrep_scope_baseline(
                    base_dir, base_manifest, expanded_dir, expanded_manifest)

            self.assertEqual(open(base_manifest, "rb").read(), before_manifest)
            self.assertEqual(open(capture, "rb").read(), before_capture)


if __name__ == "__main__":
    unittest.main()
