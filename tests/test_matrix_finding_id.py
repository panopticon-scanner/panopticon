import json
import re
import tempfile
from pathlib import Path
import unittest

import scripts.evidence as evidence
import scripts.synthesize as synthesize

ID_RE = re.compile(r"^[A-Z]{2,8}-[0-9]{3,}$")


def _f(**kw):
    base = {
        "domain": "SEC",
        "category": "secrets",
        "location": {"file": "app/config.py", "line_start": 12},
        "title": "Hardcoded secret",
        "panel": "security",
    }
    base.update(kw)
    return base


class TestMatrixFindingId(unittest.TestCase):
    def test_id_is_schema_valid_and_domain_prefixed(self):
        fid = evidence.matrix_finding_id(_f())
        self.assertTrue(ID_RE.match(fid), fid)
        self.assertTrue(fid.startswith("SEC-"))

    def test_id_is_deterministic(self):
        self.assertEqual(evidence.matrix_finding_id(_f()), evidence.matrix_finding_id(_f()))

    def test_same_title_different_line_distinct_ids(self):
        a = evidence.matrix_finding_id(_f(location={"file": "a.py", "line_start": 1}))
        b = evidence.matrix_finding_id(_f(location={"file": "a.py", "line_start": 9}))
        self.assertNotEqual(a, b)

    def test_prefix_from_code_then_gen(self):
        self.assertTrue(
            evidence.matrix_finding_id(_f(domain=None, code="COD-F1A")).startswith("COD-")
        )
        fid = evidence.matrix_finding_id(_f(domain=None, code=None))
        self.assertTrue(fid.startswith("GEN-") and ID_RE.match(fid))

    def test_whitespace_in_title_does_not_change_id(self):
        a = evidence.matrix_finding_id(_f(title="Hardcoded secret"))
        b = evidence.matrix_finding_id(_f(title="Hardcoded   secret"))
        self.assertEqual(a, b)

    def test_invalid_domain_falls_back_to_gen(self):
        for bad in ["sec", "TOOLONGDOMAIN", "ÀÁ", "S3C"]:
            fid = evidence.matrix_finding_id(_f(domain=bad))
            self.assertTrue(fid.startswith("GEN-") and ID_RE.match(fid), (bad, fid))

    def test_non_string_domain_does_not_crash(self):
        fid = evidence.matrix_finding_id(_f(domain=["S", "E", "C"]))
        self.assertTrue(fid.startswith("GEN-") and ID_RE.match(fid))

    def test_load_findings_fills_missing_id_and_keeps_valid_one(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "findings-app-SEC.json"
            p.write_text(
                json.dumps(
                    {
                        "findings": [
                            {
                                "domain": "SEC",
                                "code": "SEC-A1A",
                                "severity": "HIGH",
                                "title": "Hardcoded secret",
                                "description": "x",
                                "location": {"file": "app/config.py", "line_start": 12},
                                "category": "secrets",
                                "source_role": "domain_panel",
                            },
                            {
                                "id": "SEC-001",
                                "domain": "SEC",
                                "severity": "LOW",
                                "title": "keep me",
                                "location": {"file": "a.py", "line_start": 1},
                                "category": "x",
                            },
                        ]
                    }
                )
            )
            out = synthesize.load_findings([str(p)])
            self.assertTrue(ID_RE.match(out[0]["id"]))
            self.assertEqual(out[1]["id"], "SEC-001")

    def test_matrix_report_has_no_id_schema_error(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "findings-app-COD.json"
            p.write_text(
                json.dumps(
                    {
                        "findings": [
                            {
                                "domain": "COD",
                                "code": "COD-A1A",
                                "severity": "LOW",
                                "title": "off-by-one",
                                "description": "x",
                                "location": {"file": "a.py", "line_start": 3},
                                "category": "logic",
                            }
                        ]
                    }
                )
            )
            out = str(Path(d) / "report.json")
            synthesize.main(["--out", out, str(p)])
            with open(out, encoding="utf-8") as fh:
                rep = json.load(fh)
            self.assertTrue(ID_RE.match(rep["findings"][0]["id"]))


if __name__ == "__main__":
    unittest.main()
