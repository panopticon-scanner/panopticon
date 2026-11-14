"""#3593: advisories against a Cargo workspace package are controller facts."""

import json
import os
import tempfile
import unittest
from unittest import mock

import scripts.evidence as evidence
import scripts.first_party_advisory as first_party_advisory
import scripts.ingest_tools as ingest_tools
import scripts.phases.runio as runio
import scripts.phases.verify_tools as verify_tools
import scripts.synth.findings as findings_mod
import scripts.synth.report as report_mod


WORKSPACE_NAME = "workspace-app"
WORKSPACE_VERSION = "1.2.3"
REGISTRY_NAME = "registry-dep"
REGISTRY_VERSION = "4.5.6"
_DEFAULT_MANIFEST = object()


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


def _write_manifest(root, text=None):
    if text is None:
        text = (
            '[package]\n'
            'name = "workspace-app"\n'
            'version = "1.2.3"\n'
        )
    with open(os.path.join(root, "Cargo.toml"), "w", encoding="utf-8") as fh:
        fh.write(text)


def _ingest_document(root, filename, document, *, name_root=True):
    tools = os.path.join(root, "tools")
    os.mkdir(tools)
    with open(os.path.join(tools, filename), "w", encoding="utf-8") as fh:
        json.dump(document, fh)
    return ingest_tools.ingest_dir(
        tools, "g1", target_root=root if name_root else None)


def _raw_advisory_finding(*, path="Cargo.lock", source="tool:osv-scanner",
                          package=WORKSPACE_NAME, version=WORKSPACE_VERSION,
                          kind=None):
    tool_evidence = {
        "rule_id": "RUSTSEC-2099-0001",
        "package_name": package,
        "vulnerable_versions": version,
    }
    if kind is not None:
        tool_evidence["kind"] = kind
    return {
        "id": "OS-001",
        "title": "%s %s: RUSTSEC-2099-0001" % (package, version),
        "source": source,
        "location": {"file": path, "line_start": 1},
        "tool_evidence": tool_evidence,
    }


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
    def _ingest(self, filename, document, lock_text=None, *, name_root=True,
                manifest_text=_DEFAULT_MANIFEST):
        root = tempfile.TemporaryDirectory()
        self.addCleanup(root.cleanup)
        if lock_text is None:
            _write_lock(root.name)
        else:
            with open(os.path.join(root.name, "Cargo.lock"), "w", encoding="utf-8") as fh:
                fh.write(lock_text)
        if manifest_text is _DEFAULT_MANIFEST:
            _write_manifest(root.name)
        elif manifest_text is not None:
            _write_manifest(root.name, manifest_text)
        return _ingest_document(root.name, filename, document, name_root=name_root)

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
        self.assertNotIn("package_name", finding["tool_evidence"])
        self.assertEqual(finding["tool_evidence"]["advisory_package"], {
            "name": WORKSPACE_NAME,
            "version": WORKSPACE_VERSION,
        })
        self.assertIn("this project", finding["impact"].lower())
        self.assertIn("first-party code", finding["remediation"].lower())

    def test_trivy_marking_does_not_change_fingerprint_or_reconcile_identity(self):
        plain = self._ingest(
            "trivy.sarif", _trivy_document(), name_root=False)[0]
        marked = self._ingest("trivy.sarif", _trivy_document())[0]
        self.assertEqual(
            evidence.finding_fingerprint(marked), evidence.finding_fingerprint(plain))
        self.assertEqual(evidence.reconcile_key(marked), evidence.reconcile_key(plain))
        self.assertNotIn("package_name", marked["tool_evidence"])

    def test_trivy_registry_package_stays_on_the_advisor_path(self):
        finding = self._ingest(
            "trivy.sarif", _trivy_document(REGISTRY_NAME, REGISTRY_VERSION))[0]
        self.assertFalse(evidence.is_first_party_advisory(finding))
        self.assertNotIn("package_origin", finding["tool_evidence"])

    def test_rootless_ci_ingest_keeps_the_existing_gate_path(self):
        findings = self._ingest(
            "osv-scanner.json", _osv_document(), name_root=False)
        self.assertEqual(len(findings), 2)
        self.assertFalse(any(evidence.is_first_party_advisory(f) for f in findings))

    def test_driver_dispatches_only_the_registry_advisory(self):
        root = tempfile.TemporaryDirectory()
        self.addCleanup(root.cleanup)
        _write_lock(root.name)
        _write_manifest(root.name)
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

    def test_deeply_nested_lock_fails_closed_without_crashing_ingest(self):
        nested = "x = %s0%s\n" % ("[" * 1200, "]" * 1200)
        document = {"results": [{
            "source": {"path": "/src/Cargo.lock"},
            "packages": [_osv_package(
                WORKSPACE_NAME, WORKSPACE_VERSION, "RUSTSEC-2099-0001")],
        }]}
        finding = self._ingest("osv-scanner.json", document, nested)[0]
        self.assertNotIn("package_origin", finding["tool_evidence"])

    def test_empty_or_non_string_lock_source_is_not_first_party(self):
        for source in ('""', "1"):
            with self.subTest(source=source):
                lock = (
                    'version = 3\n\n'
                    '[[package]]\n'
                    'name = "workspace-app"\n'
                    'version = "1.2.3"\n'
                    'source = %s\n' % source
                )
                finding = self._ingest(
                    "osv-scanner.json", _osv_document(), lock)[0]
                self.assertNotIn("package_origin", finding["tool_evidence"])

    def test_lock_path_must_be_relative_confined_and_not_a_symlink_escape(self):
        parent = tempfile.TemporaryDirectory()
        self.addCleanup(parent.cleanup)
        root = os.path.join(parent.name, "target")
        outside = os.path.join(parent.name, "outside")
        os.mkdir(root)
        os.mkdir(outside)
        _write_lock(root)
        _write_manifest(root)
        _write_lock(outside)
        _write_manifest(outside)
        os.symlink(outside, os.path.join(root, "escape"))

        for path in (os.path.join(outside, "Cargo.lock"),
                     "../Cargo.lock", "escape/Cargo.lock"):
            with self.subTest(path=path):
                finding = _raw_advisory_finding(path=path)
                first_party_advisory.mark(
                    [finding], root, first_party_advisory.IngestCache())
                self.assertNotIn("package_origin", finding["tool_evidence"])

    def test_non_cargo_lock_is_not_classified(self):
        root = tempfile.TemporaryDirectory()
        self.addCleanup(root.cleanup)
        _write_lock(root.name)
        _write_manifest(root.name)
        finding = _raw_advisory_finding(path="package-lock.json")
        first_party_advisory.mark(
            [finding], root.name, first_party_advisory.IngestCache())
        self.assertNotIn("package_origin", finding["tool_evidence"])

    def test_advisory_version_must_match_the_same_lock_identity(self):
        lock = (
            'version = 3\n\n'
            '[[package]]\nname = "foo"\nversion = "1.0"\n\n'
            '[[package]]\nname = "foo"\nversion = "2.0"\n'
            'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
        )
        manifest = '[package]\nname = "foo"\nversion = "1.0"\n'
        document = {"results": [{
            "source": {"path": "/src/Cargo.lock"},
            "packages": [_osv_package("foo", "2.0", "RUSTSEC-2099-0001")],
        }]}
        finding = self._ingest(
            "osv-scanner.json", document, lock, manifest_text=manifest)[0]
        self.assertNotIn("package_origin", finding["tool_evidence"])

    def test_sourceless_lock_identity_must_also_match_the_manifest_version(self):
        lock = (
            'version = 3\n\n'
            '[[package]]\nname = "workspace-app"\nversion = "1.2.3"\n'
        )
        manifest = '[package]\nname = "workspace-app"\nversion = "9.9.9"\n'
        document = {"results": [{
            "source": {"path": "/src/Cargo.lock"},
            "packages": [_osv_package(
                WORKSPACE_NAME, WORKSPACE_VERSION, "RUSTSEC-2099-0001")],
        }]}
        finding = self._ingest(
            "osv-scanner.json", document, lock, manifest_text=manifest)[0]
        self.assertNotIn("package_origin", finding["tool_evidence"])

    def test_in_tree_publishable_workspace_member_is_classified(self):
        root = tempfile.TemporaryDirectory()
        self.addCleanup(root.cleanup)
        _write_lock(root.name)
        _write_manifest(root.name, '[workspace]\nmembers = ["crates/*"]\n')
        member = os.path.join(root.name, "crates", "workspace-app")
        os.makedirs(member)
        _write_manifest(member)
        finding = _ingest_document(
            root.name, "osv-scanner.json", _osv_document())[0]
        self.assertTrue(evidence.is_first_party_advisory(finding))

    def test_private_registry_only_manifest_stays_on_the_advisor_path(self):
        manifest = (
            '[package]\nname = "workspace-app"\nversion = "1.2.3"\n'
            'publish = ["custom-registry"]\n'
        )
        finding = self._ingest(
            "osv-scanner.json", _osv_document(), manifest_text=manifest)[0]
        self.assertNotIn("package_origin", finding["tool_evidence"])

    def test_crates_io_publish_list_is_classified(self):
        manifest = (
            '[package]\nname = "workspace-app"\nversion = "1.2.3"\n'
            'publish = ["custom-registry", "crates-io"]\n'
        )
        finding = self._ingest(
            "osv-scanner.json", _osv_document(), manifest_text=manifest)[0]
        self.assertTrue(evidence.is_first_party_advisory(finding))

    def test_empty_publish_list_stays_on_the_advisor_path(self):
        manifest = (
            '[package]\nname = "workspace-app"\nversion = "1.2.3"\n'
            'publish = []\n'
        )
        finding = self._ingest(
            "osv-scanner.json", _osv_document(), manifest_text=manifest)[0]
        self.assertNotIn("package_origin", finding["tool_evidence"])

    def test_unparseable_sibling_invalidates_the_whole_manifest_set(self):
        root = tempfile.TemporaryDirectory()
        self.addCleanup(root.cleanup)
        _write_lock(root.name)
        _write_manifest(root.name, '[workspace]\nmembers = ["good", "bad"]\n')
        good = os.path.join(root.name, "good")
        bad = os.path.join(root.name, "bad")
        os.mkdir(good)
        os.mkdir(bad)
        _write_manifest(good)
        _write_manifest(bad, "[package\n")
        finding = _ingest_document(
            root.name, "osv-scanner.json", _osv_document())[0]
        self.assertNotIn("package_origin", finding["tool_evidence"])

    def test_outside_path_on_sibling_invalidates_the_whole_manifest_set(self):
        root = tempfile.TemporaryDirectory()
        self.addCleanup(root.cleanup)
        _write_lock(root.name)
        _write_manifest(root.name, '[workspace]\nmembers = ["good", "bad"]\n')
        good = os.path.join(root.name, "good")
        bad = os.path.join(root.name, "bad")
        os.mkdir(good)
        os.mkdir(bad)
        _write_manifest(good)
        _write_manifest(bad, (
            '[package]\nname = "sibling"\nversion = "0.1.0"\n'
            '[dependencies.outside]\npath = "../../outside"\n'
        ))
        finding = _ingest_document(
            root.name, "osv-scanner.json", _osv_document())[0]
        self.assertNotIn("package_origin", finding["tool_evidence"])

    def test_escaping_workspace_member_invalidates_the_whole_manifest_set(self):
        parent = tempfile.TemporaryDirectory()
        self.addCleanup(parent.cleanup)
        root = os.path.join(parent.name, "target")
        outside = os.path.join(parent.name, "outside")
        os.mkdir(root)
        os.mkdir(outside)
        _write_lock(root)
        _write_manifest(root, (
            '[workspace]\nmembers = ["good", "../outside"]\n'
        ))
        os.mkdir(os.path.join(root, "good"))
        _write_manifest(os.path.join(root, "good"))
        _write_manifest(outside, (
            '[package]\nname = "sibling"\nversion = "0.1.0"\n'
        ))
        finding = _ingest_document(
            root, "osv-scanner.json", _osv_document())[0]
        self.assertNotIn("package_origin", finding["tool_evidence"])

    def test_publish_false_manifest_stays_on_the_advisor_path(self):
        manifest = (
            '[package]\nname = "workspace-app"\nversion = "1.2.3"\n'
            'publish = false\n'
        )
        finding = self._ingest(
            "osv-scanner.json", _osv_document(), manifest_text=manifest)[0]
        self.assertNotIn("package_origin", finding["tool_evidence"])

    def test_unparseable_member_manifest_stays_on_the_advisor_path(self):
        finding = self._ingest(
            "osv-scanner.json", _osv_document(), manifest_text="[package\n")[0]
        self.assertNotIn("package_origin", finding["tool_evidence"])

    def test_unreadable_member_manifest_stays_on_the_advisor_path(self):
        root = tempfile.TemporaryDirectory()
        self.addCleanup(root.cleanup)
        _write_lock(root.name)
        os.mkdir(os.path.join(root.name, "Cargo.toml"))
        finding = _ingest_document(
            root.name, "osv-scanner.json", _osv_document())[0]
        self.assertNotIn("package_origin", finding["tool_evidence"])

    def test_outside_tree_path_member_stays_on_the_advisor_path(self):
        parent = tempfile.TemporaryDirectory()
        self.addCleanup(parent.cleanup)
        root = os.path.join(parent.name, "target")
        outside = os.path.join(parent.name, "outside")
        os.mkdir(root)
        os.mkdir(outside)
        _write_lock(root)
        _write_manifest(outside)
        _write_manifest(root, (
            '[package]\nname = "host"\nversion = "0.1.0"\n'
            '[dependencies.workspace-app]\npath = "../outside"\n'
        ))
        finding = _ingest_document(
            root, "osv-scanner.json", _osv_document())[0]
        self.assertNotIn("package_origin", finding["tool_evidence"])

    def test_ingest_manifest_budget_is_exactly_48_mib(self):
        self.assertEqual(
            first_party_advisory.MAX_CARGO_MANIFEST_INGEST_BYTES,
            48 * 1024 * 1024,
        )

    def test_parsed_manifest_cache_is_shared_across_two_locks(self):
        root = tempfile.TemporaryDirectory()
        self.addCleanup(root.cleanup)
        shared = os.path.join(root.name, "shared")
        os.mkdir(shared)
        _write_manifest(shared)
        tools = os.path.join(root.name, "tools")
        os.mkdir(tools)
        for project in ("one", "two"):
            project_root = os.path.join(root.name, project)
            os.mkdir(project_root)
            _write_lock(project_root)
            _write_manifest(project_root, (
                '[package]\nname = "host-%s"\nversion = "0.1.0"\n'
                '[dependencies.workspace-app]\npath = "../shared"\n' % project
            ))
            document = {"results": [{
                "source": {"path": "/src/%s/Cargo.lock" % project},
                "packages": [_osv_package(
                    WORKSPACE_NAME, WORKSPACE_VERSION,
                    "RUSTSEC-2099-%s" % ("0001" if project == "one" else "0002"))],
            }]}
            suffix = "json" if project == "one" else "sarif"
            with open(os.path.join(tools, "osv-scanner.%s" % suffix), "w",
                      encoding="utf-8") as fh:
                json.dump(document, fh)

        reads = []
        read_regular_bytes = first_party_advisory.safe_write.read_regular_bytes

        def counted_read(path, limit):
            reads.append(os.path.realpath(path))
            return read_regular_bytes(path, limit)

        with mock.patch.object(
                first_party_advisory.safe_write, "read_regular_bytes",
                side_effect=counted_read):
            findings = ingest_tools.ingest_dir(
                tools, "g1", target_root=root.name)

        self.assertEqual(
            [finding["tool_evidence"].get("package_origin")
             for finding in findings],
            ["first_party", "first_party"],
        )
        self.assertEqual(reads.count(os.path.realpath(
            os.path.join(shared, "Cargo.toml"))), 1)

    def test_manifest_budget_exhaustion_keeps_every_unresolved_finding_advisory(self):
        root = tempfile.TemporaryDirectory()
        self.addCleanup(root.cleanup)
        decided_root = os.path.join(root.name, "decided")
        exhausted_root = os.path.join(root.name, "exhausted")
        os.mkdir(decided_root)
        os.mkdir(exhausted_root)
        _write_lock(decided_root)
        _write_lock(exhausted_root)
        decided_manifest = (
            '[package]\nname = "workspace-app"\nversion = "1.2.3"\n'
        )
        _write_manifest(decided_root, decided_manifest)
        _write_manifest(exhausted_root, decided_manifest + "# padding\n")

        decided = _raw_advisory_finding(path="decided/Cargo.lock")
        exhausted = _raw_advisory_finding(path="exhausted/Cargo.lock")
        exhausted["id"] = "OS-002"
        unresolved_cache_hit = _raw_advisory_finding(path="decided/Cargo.lock")
        unresolved_cache_hit["id"] = "OS-003"
        budget = len(decided_manifest.encode("utf-8")) + 1
        with mock.patch.object(
                first_party_advisory,
                "MAX_CARGO_MANIFEST_INGEST_BYTES", budget):
            cache = first_party_advisory.IngestCache()
            first_party_advisory.mark([decided], root.name, cache)
            first_party_advisory.mark([exhausted], root.name, cache)
            first_party_advisory.mark(
                [unresolved_cache_hit], root.name, cache)

        self.assertEqual(
            decided["tool_evidence"].get("package_origin"), "first_party")
        self.assertNotIn("package_origin", exhausted["tool_evidence"])
        self.assertNotIn(
            "package_origin", unresolved_cache_hit["tool_evidence"])
        self.assertTrue(cache.manifest_budget_exhausted)
        self.assertEqual(cache.manifest_bytes_remaining, 0)

    def test_one_classification_error_does_not_drop_later_findings(self):
        root = tempfile.TemporaryDirectory()
        self.addCleanup(root.cleanup)
        _write_lock(root.name)
        _write_manifest(root.name)
        first = _raw_advisory_finding()
        second = _raw_advisory_finding()
        second["id"] = "OS-002"
        with mock.patch.object(
                first_party_advisory, "_advisory_package",
                side_effect=[RuntimeError("bad finding"),
                             (WORKSPACE_NAME, WORKSPACE_VERSION)]):
            first_party_advisory.mark(
                [first, second], root.name,
                first_party_advisory.IngestCache())
        self.assertNotIn("package_origin", first["tool_evidence"])
        self.assertEqual(
            second["tool_evidence"].get("package_origin"), "first_party")

    def test_secret_and_non_dependency_adapters_are_never_classified(self):
        root = tempfile.TemporaryDirectory()
        self.addCleanup(root.cleanup)
        _write_lock(root.name)
        _write_manifest(root.name)
        secret = _raw_advisory_finding(source="tool:trivy", kind="secret")
        secret["title"] = (
            "Package: workspace-app Installed Version: 1.2.3 secret")
        non_dependency = _raw_advisory_finding(source="tool:semgrep")
        first_party_advisory.mark(
            [secret, non_dependency], root.name,
            first_party_advisory.IngestCache())
        self.assertNotIn("package_origin", secret["tool_evidence"])
        self.assertNotIn("package_origin", non_dependency["tool_evidence"])


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
        self.assertIn("exact name and version", derived["reasoning"])
        self.assertIn("in-tree publishable Cargo member", derived["reasoning"])

    def test_registry_dependency_still_queues_and_needs_confirmation(self):
        finding = self._finding("OS-002")
        entries, cut = evidence.build_verify_queue([finding])
        self.assertEqual((len(entries), cut), (1, 0))
        self.assertIs(entries[0]["finding"], finding)
        self.assertEqual(evidence.derive_evidence(finding)["status"], "tool_reported")

    def test_unknown_package_origin_does_not_count_as_first_party(self):
        finding = self._finding("OS-UNKNOWN", "unknown")
        self.assertFalse(evidence.is_first_party_advisory(finding))
        self.assertEqual(len(evidence.build_verify_queue([finding])[0]), 1)

    def test_explicit_advisor_rejection_precedes_first_party_confirmation(self):
        finding = self._finding("OS-REJECTED", "first_party")
        derived = evidence.derive_evidence(finding, {
            "verdict": "REJECTED",
            "reasoning": "the advisor disproved the claim",
        })
        self.assertEqual(derived["status"], "rejected")
        self.assertEqual(derived["reasoning"], "the advisor disproved the claim")

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
