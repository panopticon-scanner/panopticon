"""#3593: advisories against a Cargo workspace package are controller facts."""

import json
import os
import tempfile
import unittest

import scripts.evidence as evidence
import scripts.ingest_tools as ingest_tools
import scripts.phases.runio as runio
import scripts.phases.verify_tools as verify_tools
import scripts.synth.findings as findings_mod
import scripts.synth.report as report_mod


WORKSPACE_NAME = "workspace-app"
WORKSPACE_VERSION = "1.2.3"
REGISTRY_NAME = "registry-dep"
REGISTRY_VERSION = "4.5.6"


def _write_lock(root):
    with open(os.path.join(root, "Cargo.lock"), "w", encoding="utf-8") as fh:
        fh.write(
            'version = 3\n\n'
            '[[package]]\n'
            'name = "workspace-app"\n'
            'version = "1.2.3"\n\n'
            '[[package]]\n'
            'name = "registry-dep"\n'
            'version = "4.5.6"\n'
            'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
        )


def _osv_package(name, version, advisory):
    return {
        "package": {"name": name, "version": version, "ecosystem": "crates.io"},
        "vulnerabilities": [{
            "id": advisory,
            "summary": "affected package",
            "database_specific": {"severity": "CRITICAL"},
        }],
        "groups": [],
    }


def _osv_document():
    return {
        "results": [{
            "source": {"path": "/src/Cargo.lock"},
            "packages": [
                _osv_package(WORKSPACE_NAME, WORKSPACE_VERSION, "RUSTSEC-2099-0001"),
                _osv_package(REGISTRY_NAME, REGISTRY_VERSION, "RUSTSEC-2099-0002"),
            ],
        }]
    }


def _trivy_document(name=WORKSPACE_NAME, version=WORKSPACE_VERSION):
    advisory = "CVE-2099-12345"
    return {
        "runs": [{
            "tool": {"driver": {"name": "trivy", "rules": [{
                "id": advisory,
                "properties": {
                    "security-severity": "9.8",
                    "tags": ["vulnerability", "security", "CRITICAL"],
                },
            }]}},
            "results": [{
                "ruleId": advisory,
                "level": "error",
                "message": {"text": (
                    "Package: %s\nInstalled Version: %s\n"
                    "Vulnerability %s\nSeverity: CRITICAL" % (name, version, advisory)
                )},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": "Cargo.lock"},
                    "region": {"startLine": 1},
                }}],
            }],
        }]
    }


class TestCargoFirstPartyAdvisoryIngest(unittest.TestCase):
    def _ingest(self, filename, document, lock_text=None):
        root = tempfile.TemporaryDirectory()
        self.addCleanup(root.cleanup)
        if lock_text is None:
            _write_lock(root.name)
        else:
            with open(os.path.join(root.name, "Cargo.lock"), "w", encoding="utf-8") as fh:
                fh.write(lock_text)
        tools = os.path.join(root.name, "tools")
        os.mkdir(tools)
        with open(os.path.join(tools, filename), "w", encoding="utf-8") as fh:
            json.dump(document, fh)
        return ingest_tools.ingest_dir(tools, "g1", target_root=root.name)

    def test_osv_workspace_package_is_reframed_but_registry_dependency_is_not(self):
        findings = self._ingest("osv-scanner.json", _osv_document())
        by_package = {f["tool_evidence"]["package_name"]: f for f in findings}

        workspace = by_package[WORKSPACE_NAME]
        self.assertTrue(evidence.is_first_party_advisory(workspace))
        self.assertEqual(workspace["tool_evidence"]["package_origin"], "first_party")
        self.assertIn("this project", workspace["impact"].lower())
        self.assertIn("first-party code", workspace["remediation"].lower())
        self.assertNotIn("upgrade", workspace["remediation"].lower())

        registry = by_package[REGISTRY_NAME]
        self.assertFalse(evidence.is_first_party_advisory(registry))
        self.assertNotIn("package_origin", registry["tool_evidence"])
        self.assertIn("upgrade", registry["remediation"].lower())

    def test_trivy_workspace_package_uses_the_same_ingest_classification(self):
        finding = self._ingest("trivy.sarif", _trivy_document())[0]
        self.assertTrue(evidence.is_first_party_advisory(finding))
        self.assertEqual(finding["tool_evidence"]["package_origin"], "first_party")
        self.assertIn("this project", finding["impact"].lower())
        self.assertIn("first-party code", finding["remediation"].lower())

    def test_trivy_registry_package_stays_on_the_advisor_path(self):
        finding = self._ingest(
            "trivy.sarif", _trivy_document(REGISTRY_NAME, REGISTRY_VERSION))[0]
        self.assertFalse(evidence.is_first_party_advisory(finding))
        self.assertNotIn("package_origin", finding["tool_evidence"])

    def test_driver_dispatches_only_the_registry_advisory(self):
        root = tempfile.TemporaryDirectory()
        self.addCleanup(root.cleanup)
        _write_lock(root.name)
        tools = runio._pano(root.name, "tools")
        os.makedirs(tools)
        with open(os.path.join(tools, "osv-scanner.json"), "w", encoding="utf-8") as fh:
            json.dump(_osv_document(), fh)
        runio._write_json(runio._pano(root.name, "tools-ran.json"), {
            "ran": True,
            "run_id": "RID",
        })
        runio._write_json(runio._pano(root.name, "tools-manifest.json"), {
            "run_id": "RID",
            "selected": ["osv-scanner"],
            "produced": ["osv-scanner"],
            "missing": [],
            "outputs": ["osv-scanner.json"],
        })

        queue = verify_tools._tool_verify_queue(root.name, {
            "run_id": "RID",
            "security_mode": "standard",
            "flags": {},
        })
        self.assertEqual(len(queue), 1)
        _queue_id, finding = queue[0]
        self.assertEqual(finding["tool_evidence"]["package_name"], REGISTRY_NAME)
        self.assertFalse(evidence.is_first_party_advisory(finding))

    def test_ambiguous_local_and_registry_identity_stays_on_the_advisor_path(self):
        duplicate = (
            'version = 3\n\n'
            '[[package]]\nname = "workspace-app"\nversion = "1.2.3"\n\n'
            '[[package]]\nname = "workspace-app"\nversion = "1.2.3"\n'
            'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
        )
        document = {"results": [{
            "source": {"path": "/src/Cargo.lock"},
            "packages": [_osv_package(
                WORKSPACE_NAME, WORKSPACE_VERSION, "RUSTSEC-2099-0001")],
        }]}
        finding = self._ingest("osv-scanner.json", document, duplicate)[0]
        self.assertFalse(evidence.is_first_party_advisory(finding))
        self.assertNotIn("package_origin", finding["tool_evidence"])


class TestFirstPartyAdvisoryVerification(unittest.TestCase):
    @staticmethod
    def _finding(fid, package_origin=None):
        tool_evidence = {
            "rule_id": "RUSTSEC-2099-0001",
            "package_name": WORKSPACE_NAME,
            "vulnerable_versions": WORKSPACE_VERSION,
        }
        if package_origin is not None:
            tool_evidence["package_origin"] = package_origin
        return {
            "id": fid,
            "title": "workspace-app 1.2.3: RUSTSEC-2099-0001",
            "severity": "CRITICAL",
            "confidence": "CERTAIN",
            "panel": "security",
            "category": "dependency_vulnerability",
            "source": "tool:osv-scanner",
            "location": {"file": "Cargo.lock", "line_start": 1},
            "tool_evidence": tool_evidence,
            "provenance": {"confirmation_reasoning": "RUSTSEC-2099-0001"},
        }

    def test_first_party_advisory_is_confirmed_without_an_advisor(self):
        finding = self._finding("OS-001", "first_party")
        self.assertEqual(evidence.build_verify_queue([finding]), ([], 0))
        derived = evidence.derive_evidence(finding)
        self.assertEqual(derived["status"], "tool_confirmed")
        self.assertEqual(derived["verified_by"], "tool:osv-scanner")
        self.assertIn("project's own Cargo package", derived["reasoning"])

    def test_registry_dependency_still_queues_and_needs_confirmation(self):
        finding = self._finding("OS-002")
        entries, cut = evidence.build_verify_queue([finding])
        self.assertEqual((len(entries), cut), (1, 0))
        self.assertIs(entries[0]["finding"], finding)
        self.assertEqual(evidence.derive_evidence(finding)["status"], "tool_reported")

    def test_first_party_advisory_does_not_spend_the_max_verify_budget(self):
        first_party = self._finding("OS-003", "first_party")
        registry = self._finding("OS-004")
        entries, cut = evidence.build_verify_queue([first_party, registry], max_verify=1)
        self.assertEqual(cut, 0)
        self.assertEqual([entry["finding"] for entry in entries], [registry])

    def test_agent_cannot_self_assert_the_queue_exemption(self):
        finding = self._finding("AG-001", "first_party")
        finding.pop("source")
        self.assertFalse(evidence.is_first_party_advisory(finding))
        self.assertEqual(len(evidence.build_verify_queue([finding])[0]), 1)
        self.assertEqual(evidence.derive_evidence(finding)["status"], "unverified")

    def test_a_stale_rejection_cannot_bind_to_the_unqueued_advisory(self):
        finding = self._finding("OS-005", "first_party")
        fingerprint = evidence.finding_fingerprint(finding)
        report = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(
                target="project", fail_on="high", timestamp="2026-11-13T00:00:00Z"),
            findings=findings_mod.FindingSet(
                findings=[finding],
                verdicts={fingerprint: {
                    "finding_id": finding["id"],
                    "verdict": "REJECTED",
                    "reasoning": "not a third-party dependency",
                }},
                verdicts_supplied=True,
            ),
        ))
        self.assertEqual([f["id"] for f in report["findings"]], [finding["id"]])
        self.assertEqual(report["findings"][0]["evidence"]["status"], "tool_confirmed")
        self.assertEqual(report["discarded_claims"], [])
        self.assertEqual(report["meta"]["coverage"]["verdicts"]["queued"], 0)
        self.assertEqual(report["meta"]["coverage"]["verdicts"]["unknown"], 1)


if __name__ == "__main__":
    unittest.main()
