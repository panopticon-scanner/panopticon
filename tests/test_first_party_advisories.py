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

    def test_cached_toml_cannot_bypass_real_path_confinement(self):
        parent = tempfile.TemporaryDirectory()
        self.addCleanup(parent.cleanup)
        root = os.path.join(parent.name, "target")
        outside = os.path.join(parent.name, "outside")
        os.mkdir(root)
        os.mkdir(outside)
        _write_manifest(outside)
        outside_manifest = os.path.realpath(
            os.path.join(outside, "Cargo.toml"))
        cache = first_party_advisory.IngestCache()
        cache.manifests[("toml", outside_manifest)] = {
            "package": {"name": WORKSPACE_NAME, "version": WORKSPACE_VERSION},
        }
        remaining = cache.manifest_bytes_remaining

        self.assertIsNone(first_party_advisory._read_toml(
            outside_manifest, root, cache))
        self.assertEqual(cache.manifest_bytes_remaining, remaining)

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

    def test_budget_charges_two_complete_graphs_before_refusing_the_third(self):
        root = tempfile.TemporaryDirectory()
        self.addCleanup(root.cleanup)
        manifest = (
            '[package]\nname = "workspace-app"\nversion = "1.2.3"\n'
        )
        findings = []
        lock_sizes = []
        for index, project in enumerate(("one", "two", "three"), 1):
            project_root = os.path.join(root.name, project)
            os.mkdir(project_root)
            _write_lock(project_root)
            _write_manifest(project_root, manifest)
            lock_sizes.append(os.path.getsize(
                os.path.join(project_root, "Cargo.lock")))
            finding = _raw_advisory_finding(
                path="%s/Cargo.lock" % project)
            finding["id"] = "OS-%03d" % index
            findings.append(finding)

        manifest_size = len(manifest.encode("utf-8"))
        budget = sum(lock_sizes) + 2 * manifest_size + 1
        with mock.patch.object(
                first_party_advisory,
                "MAX_CARGO_MANIFEST_INGEST_BYTES", budget):
            cache = first_party_advisory.IngestCache()
            first_party_advisory.mark([findings[0]], root.name, cache)
            self.assertEqual(
                cache.manifest_bytes_remaining,
                budget - lock_sizes[0] - manifest_size,
            )
            first_party_advisory.mark([findings[1]], root.name, cache)
            self.assertEqual(
                cache.manifest_bytes_remaining,
                budget - sum(lock_sizes[:2]) - 2 * manifest_size,
            )
            first_party_advisory.mark([findings[2]], root.name, cache)

        self.assertEqual(
            [finding["tool_evidence"].get("package_origin")
             for finding in findings],
            ["first_party", "first_party", None],
        )
        self.assertTrue(cache.manifest_budget_exhausted)
        self.assertEqual(cache.manifest_bytes_remaining, 0)

    def test_exact_root_budget_refuses_an_unread_private_redeclaration(self):
        root = tempfile.TemporaryDirectory()
        self.addCleanup(root.cleanup)
        _write_lock(root.name)
        root_manifest = (
            '[package]\nname = "workspace-app"\nversion = "1.2.3"\n'
            '[dependencies.private]\npath = "private"\n'
        )
        _write_manifest(root.name, root_manifest)
        private = os.path.join(root.name, "private")
        os.mkdir(private)
        _write_manifest(private, (
            '[package]\nname = "workspace-app"\nversion = "1.2.3"\n'
            'publish = false\n'
        ))
        budget = (
            os.path.getsize(os.path.join(root.name, "Cargo.lock"))
            + len(root_manifest.encode("utf-8"))
        )
        finding = _raw_advisory_finding()

        with mock.patch.object(
                first_party_advisory,
                "MAX_CARGO_MANIFEST_INGEST_BYTES", budget):
            cache = first_party_advisory.IngestCache()
            first_party_advisory.mark([finding], root.name, cache)

        self.assertNotIn("package_origin", finding["tool_evidence"])
        self.assertTrue(cache.manifest_budget_exhausted)
        self.assertEqual(cache.manifest_bytes_remaining, 0)

    def test_completed_lock_origins_are_reused_after_exact_exhaustion(self):
        root = tempfile.TemporaryDirectory()
        self.addCleanup(root.cleanup)
        _write_lock(root.name)
        manifest = (
            '[package]\nname = "workspace-app"\nversion = "1.2.3"\n'
        )
        _write_manifest(root.name, manifest)
        first = _raw_advisory_finding()
        second = _raw_advisory_finding(source="tool:trivy")
        second["id"] = "TR-002"
        budget = (
            os.path.getsize(os.path.join(root.name, "Cargo.lock"))
            + len(manifest.encode("utf-8"))
        )

        with mock.patch.object(
                first_party_advisory,
                "MAX_CARGO_MANIFEST_INGEST_BYTES", budget):
            cache = first_party_advisory.IngestCache()
            first_party_advisory.mark([first, second], root.name, cache)

        self.assertTrue(cache.manifest_budget_exhausted)
        self.assertEqual(
            [finding["tool_evidence"].get("package_origin")
             for finding in (first, second)],
            ["first_party", "first_party"],
        )

    def test_cargo_lock_bytes_spend_the_shared_ingest_budget(self):
        root = tempfile.TemporaryDirectory()
        self.addCleanup(root.cleanup)
        _write_lock(root.name)
        _write_manifest(root.name)
        lock_size = os.path.getsize(os.path.join(root.name, "Cargo.lock"))
        finding = _raw_advisory_finding()

        with mock.patch.object(
                first_party_advisory,
                "MAX_CARGO_MANIFEST_INGEST_BYTES", lock_size):
            cache = first_party_advisory.IngestCache()
            first_party_advisory.mark([finding], root.name, cache)

        self.assertNotIn("package_origin", finding["tool_evidence"])
        self.assertEqual(cache.manifests, {
            ("toml", os.path.realpath(os.path.join(root.name, "Cargo.toml"))): None,
        })
        self.assertTrue(cache.manifest_budget_exhausted)
        self.assertEqual(cache.manifest_bytes_remaining, 0)

    def test_each_ingest_gets_a_fresh_budget_and_reports_exhaustion(self):
        first_root = tempfile.TemporaryDirectory()
        second_root = tempfile.TemporaryDirectory()
        self.addCleanup(first_root.cleanup)
        self.addCleanup(second_root.cleanup)
        _write_lock(first_root.name)
        _write_lock(second_root.name)
        first_manifest = (
            '[package]\nname = "workspace-app"\nversion = "1.2.3"\n'
            '[dependencies.private]\npath = "private"\n'
        )
        _write_manifest(first_root.name, first_manifest)
        private = os.path.join(first_root.name, "private")
        os.mkdir(private)
        _write_manifest(private, (
            '[package]\nname = "workspace-app"\nversion = "1.2.3"\n'
            'publish = false\n'
        ))
        _write_manifest(second_root.name)

        def tools_output(root):
            tools = os.path.join(root, "tools")
            os.mkdir(tools)
            document = {"results": [{
                "source": {"path": "/src/Cargo.lock"},
                "packages": [_osv_package(
                    WORKSPACE_NAME, WORKSPACE_VERSION, "RUSTSEC-2099-0001")],
            }]}
            with open(os.path.join(tools, "osv-scanner.json"), "w",
                      encoding="utf-8") as fh:
                json.dump(document, fh)
            return tools

        first_tools = tools_output(first_root.name)
        second_tools = tools_output(second_root.name)
        budget = (
            os.path.getsize(os.path.join(first_root.name, "Cargo.lock"))
            + len(first_manifest.encode("utf-8"))
        )
        with mock.patch.object(
                first_party_advisory,
                "MAX_CARGO_MANIFEST_INGEST_BYTES", budget):
            first_findings, first_dispositions = ingest_tools.ingest_dir_detailed(
                first_tools, "g1", target_root=first_root.name)
            second_findings, second_dispositions = ingest_tools.ingest_dir_detailed(
                second_tools, "g1", target_root=second_root.name)

        self.assertNotIn(
            "package_origin", first_findings[0]["tool_evidence"])
        self.assertEqual(
            first_dispositions["osv-scanner"].get(
                "advisory_manifest_budget_exhausted"),
            1,
        )
        self.assertEqual(
            second_findings[0]["tool_evidence"].get("package_origin"),
            "first_party",
        )
        self.assertNotIn(
            "advisory_manifest_budget_exhausted",
            second_dispositions["osv-scanner"],
        )

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


NPM_ROOT = ("web-app", "2.0.0")
NPM_MEMBER = ("@acme/lib", "1.4.0")
NPM_REGISTRY = ("left-pad", "1.3.0")


def _npm_lock(**extra_packages):
    """A lockfile v3 for a private root with one linked workspace member and one
    registry package; `extra_packages` adds or replaces `packages` entries."""
    packages = {
        "": {"name": NPM_ROOT[0], "version": NPM_ROOT[1], "workspaces": ["packages/*"]},
        "packages/lib": {"name": NPM_MEMBER[0], "version": NPM_MEMBER[1]},
        "node_modules/@acme/lib": {"resolved": "packages/lib", "link": True},
        "node_modules/left-pad": {
            "version": NPM_REGISTRY[1], "integrity": "sha512-x",
            "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"},
    }
    packages.update(extra_packages)
    return {"name": NPM_ROOT[0], "version": NPM_ROOT[1], "lockfileVersion": 3,
            "packages": {k: v for k, v in packages.items() if v is not None}}


def _write_json(path, document):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(document, fh)


def _npm_tree(root, *, lock=None, lock_name="package-lock.json", member=None, top=None):
    """A fixture npm project under `root`: package.json, packages/lib/package.json, lock."""
    _write_json(os.path.join(root, "package.json"), top if top is not None else {
        "name": NPM_ROOT[0], "version": NPM_ROOT[1], "private": True,
        "workspaces": ["packages/*"]})
    if member is not False:
        _write_json(os.path.join(root, "packages", "lib", "package.json"),
                    member if member is not None else
                    {"name": NPM_MEMBER[0], "version": NPM_MEMBER[1]})
    _write_json(os.path.join(root, lock_name), lock if lock is not None else _npm_lock())


def _npm_osv_document(lock_name="package-lock.json"):
    def package(name, version, advisory):
        return {"package": {"name": name, "version": version, "ecosystem": "npm"},
                "vulnerabilities": [{"id": advisory, "summary": "affected package",
                                     "database_specific": {"severity": "HIGH"}}],
                "groups": []}
    return {"results": [{"source": {"path": "/src/" + lock_name}, "packages": [
        package(*NPM_MEMBER, "GHSA-aaaa-bbbb-cccc"),
        package(*NPM_REGISTRY, "GHSA-dddd-eeee-ffff"),
        package(*NPM_ROOT, "GHSA-gggg-hhhh-iiii")]}]}


class TestNpmFirstPartyAdvisory(unittest.TestCase):
    """#3623: npm workspaces and local packages, mirroring the Cargo marker. A lockfile
    v2+ key outside node_modules is a local package; it is first-party only when it is
    the root or a linked one, its realpath is in the review root, and its own
    package.json proves the exact identity and is publishable. Fixtures only."""

    def setUp(self):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        self.root = os.path.realpath(d.name)

    def _mark(self, package, *, path="package-lock.json", source="tool:osv-scanner",
              cache=None):
        finding = _raw_advisory_finding(path=path, source=source, package=package[0],
                                        version=package[1])
        first_party_advisory.mark([finding], self.root,
                                  cache or first_party_advisory.IngestCache())
        return finding

    def _origin(self, package, **kw):
        return self._mark(package, **kw)["tool_evidence"].get("package_origin")

    def test_osv_workspace_member_is_reframed_but_the_registry_package_is_not(self):
        _npm_tree(self.root)
        findings = _ingest_document(self.root, "osv-scanner.json", _npm_osv_document())
        by_package = {f["tool_evidence"]["package_name"]: f for f in findings}
        member = by_package[NPM_MEMBER[0]]
        self.assertTrue(evidence.is_first_party_advisory(member))
        self.assertIn("npm package", member["impact"])
        self.assertIn("workspace/local package", member["remediation"])
        self.assertNotIn("upgrade", member["remediation"].lower())
        registry = by_package[NPM_REGISTRY[0]]
        self.assertFalse(evidence.is_first_party_advisory(registry))
        self.assertNotIn("package_origin", registry["tool_evidence"])

    def test_a_private_root_is_first_party_only_because_it_is_the_review_root(self):
        _npm_tree(self.root)
        self.assertEqual("first_party", self._origin(NPM_ROOT))
        # The same private package one level down is NOT the review root.
        nested = os.path.join(self.root, "app")
        _npm_tree(nested)
        self.assertIsNone(self._origin(NPM_ROOT, path="app/package-lock.json"))

    def test_a_private_member_stays_on_the_advisor_path(self):
        _npm_tree(self.root, member={"name": NPM_MEMBER[0], "version": NPM_MEMBER[1],
                                     "private": True})
        self.assertIsNone(self._origin(NPM_MEMBER))

    def test_publish_config_decides_public_versus_private_only(self):
        for registry, expected in (("https://registry.npmjs.org/", "first_party"),
                                   ("https://registry.npmjs.org", "first_party"),
                                   ("https://npm.example.internal/", None),
                                   ("https://registry.npmjs.org.evil.example", None)):
            with self.subTest(registry=registry):
                _npm_tree(self.root, member={"name": NPM_MEMBER[0], "version": NPM_MEMBER[1],
                                             "publishConfig": {"registry": registry}})
                self.assertEqual(expected, self._origin(NPM_MEMBER))

    def test_malformed_manifest_fields_fail_closed(self):
        for member in ({"name": NPM_MEMBER[0], "version": NPM_MEMBER[1], "private": "no"},
                       {"name": NPM_MEMBER[0], "version": NPM_MEMBER[1], "private": 0},
                       {"name": NPM_MEMBER[0], "version": NPM_MEMBER[1], "private": None},
                       {"name": NPM_MEMBER[0], "version": NPM_MEMBER[1], "publishConfig": 1},
                       {"name": NPM_MEMBER[0], "version": NPM_MEMBER[1],
                        "publishConfig": {"registry": 5}},
                       {"name": NPM_MEMBER[0]}, {"version": NPM_MEMBER[1]}):
            with self.subTest(member=member):
                _npm_tree(self.root, member=member)
                self.assertIsNone(self._origin(NPM_MEMBER))

    def test_a_member_npm_did_not_link_stays_on_the_advisor_path(self):
        _npm_tree(self.root, lock=_npm_lock(**{"node_modules/@acme/lib": None}))
        self.assertIsNone(self._origin(NPM_MEMBER))

    def test_a_version_mismatch_stays_on_the_advisor_path(self):
        # The lock and the member manifest disagree (a stale lock) ...
        _npm_tree(self.root, member={"name": NPM_MEMBER[0], "version": "1.4.1"})
        self.assertIsNone(self._origin(NPM_MEMBER))
        self.assertIsNone(self._origin((NPM_MEMBER[0], "1.4.1")))
        # ... or the advisory names another version of a proved member.
        _npm_tree(self.root)
        self.assertIsNone(self._origin((NPM_MEMBER[0], "1.4.1")))
        self.assertEqual("first_party", self._origin(NPM_MEMBER))

    def test_a_redeclaration_outside_the_tree_stays_on_the_advisor_path(self):
        outside = tempfile.TemporaryDirectory()
        self.addCleanup(outside.cleanup)
        twin = os.path.join(outside.name, "lib")
        _write_json(os.path.join(twin, "package.json"),
                    {"name": NPM_MEMBER[0], "version": NPM_MEMBER[1]})
        rel = os.path.relpath(twin, self.root)
        _npm_tree(self.root, lock=_npm_lock(**{
            rel: {"name": NPM_MEMBER[0], "version": NPM_MEMBER[1]},
            "node_modules/twin": {"resolved": rel, "link": True}}))
        self.assertIsNone(self._origin(NPM_MEMBER))

    def test_a_member_linked_out_of_the_tree_stays_on_the_advisor_path(self):
        outside = tempfile.TemporaryDirectory()
        self.addCleanup(outside.cleanup)
        _write_json(os.path.join(outside.name, "package.json"),
                    {"name": NPM_MEMBER[0], "version": NPM_MEMBER[1]})
        _npm_tree(self.root, member=False)
        os.makedirs(os.path.join(self.root, "packages"), exist_ok=True)
        os.symlink(outside.name, os.path.join(self.root, "packages", "lib"))
        self.assertIsNone(self._origin(NPM_MEMBER))

    def test_a_registry_copy_of_the_same_identity_is_ambiguous(self):
        for key in ("node_modules/other/node_modules/@acme/lib", "node_modules/@acme/lib2"):
            with self.subTest(key=key):
                entry = {"version": NPM_MEMBER[1], "resolved": "https://registry.npmjs.org/x"}
                if key.endswith("lib2"):
                    entry["name"] = NPM_MEMBER[0]       # an aliased install, named in the lock
                _npm_tree(self.root, lock=_npm_lock(**{key: entry}))
                self.assertIsNone(self._origin(NPM_MEMBER))

    def test_a_nested_registry_install_of_another_package_changes_nothing(self):
        _npm_tree(self.root, lock=_npm_lock(**{
            "node_modules/other/node_modules/@acme/util": {
                "version": "9.9.9", "resolved": "https://registry.npmjs.org/x"}}))
        self.assertEqual("first_party", self._origin(NPM_MEMBER))

    def test_a_root_entry_without_a_name_takes_the_locks_name(self):
        lock = _npm_lock(**{"": {"version": NPM_ROOT[1]}})
        _npm_tree(self.root, lock=lock)
        self.assertEqual("first_party", self._origin(NPM_ROOT))

    def test_a_cached_manifest_cannot_bypass_confinement(self):
        # One cache, two roots, two locks: `lib/package.json`, read in-tree under the wider
        # root, must not be reused once the narrower review root does not contain it.
        _write_json(os.path.join(self.root, "lib", "package.json"),
                    {"name": NPM_MEMBER[0], "version": NPM_MEMBER[1]})
        wide_lock = _npm_lock(**{"packages/lib": None, "node_modules/@acme/lib": None,
                                 "lib": {"name": NPM_MEMBER[0], "version": NPM_MEMBER[1]},
                                 "node_modules/lib": {"resolved": "lib", "link": True}})
        _npm_tree(self.root, lock=wide_lock, member=False)
        app = os.path.join(self.root, "app")
        narrow_lock = _npm_lock(**{"packages/lib": None, "node_modules/@acme/lib": None,
                                   "../lib": {"name": NPM_MEMBER[0], "version": NPM_MEMBER[1]},
                                   "node_modules/lib": {"resolved": "../lib", "link": True}})
        _npm_tree(app, lock=narrow_lock, member=False)
        cache = first_party_advisory.IngestCache()
        self.assertEqual("first_party", self._origin(NPM_MEMBER, cache=cache))
        self.assertIn(("json", os.path.join(self.root, "lib", "package.json")), cache.manifests)
        narrow = _raw_advisory_finding(path="package-lock.json", package=NPM_MEMBER[0],
                                       version=NPM_MEMBER[1])
        first_party_advisory.mark([narrow], app, cache)
        self.assertNotIn("package_origin", narrow["tool_evidence"])

    def test_a_malformed_install_entry_fails_the_whole_lock(self):
        # #3639 review: osv names a registry install from its key path, so an entry whose
        # own name or version is unreadable would hide that third-party copy.
        bad = {
            "null name": {"node_modules/@acme/lib2": {"name": None, "version": "1.4.0",
                                                      "resolved": "https://registry.npmjs.org/x"}},
            "int name": {"node_modules/@acme/lib2": {"name": 5, "version": "1.4.0"}},
            "missing version": {"node_modules/other/node_modules/@acme/lib": {
                "resolved": "https://registry.npmjs.org/x"}},
            "int version": {"node_modules/other": {"version": 1}},
            "registry link": {"node_modules/@acme/lib": {
                "resolved": "https://registry.npmjs.org/@acme/lib/-/lib-1.4.0.tgz",
                "link": True}},
            "file: link": {"node_modules/@acme/lib": {"resolved": "file:packages/lib",
                                                      "link": True}},
            "absolute link": {"node_modules/@acme/lib": {
                "resolved": os.path.join(self.root, "packages", "lib"), "link": True}},
            "empty link": {"node_modules/@acme/lib": {"resolved": "", "link": True}},
            "local null name": {"packages/lib": {"name": None, "version": "1.4.0"}},
        }
        for label, extra in bad.items():
            with self.subTest(entry=label):
                _npm_tree(self.root, lock=_npm_lock(**extra))
                self.assertIsNone(self._origin(NPM_MEMBER))
                self.assertIsNone(self._origin(NPM_ROOT))

    def test_only_the_review_roots_own_lock_is_the_reviewed_project(self):
        # #3639 review: npm publishes a shrinkwrap inside its tarball, and a vendored
        # project carries its own lock; either names somebody else's root.
        _npm_tree(self.root)
        for where, lock_name in ((os.path.join("node_modules", "left-pad"),
                                  "npm-shrinkwrap.json"),
                                 (os.path.join("vendor", "y"), "package-lock.json")):
            with self.subTest(lock=where):
                nested = os.path.join(self.root, where)
                top = {"name": NPM_REGISTRY[0], "version": NPM_REGISTRY[1]}
                lock = {"name": NPM_REGISTRY[0], "version": NPM_REGISTRY[1],
                        "lockfileVersion": 3,
                        "packages": {"": {"name": NPM_REGISTRY[0],
                                          "version": NPM_REGISTRY[1]}}}
                _write_json(os.path.join(nested, "package.json"), top)
                _write_json(os.path.join(nested, lock_name), lock)
                path = "/".join(where.split(os.sep) + [lock_name])
                self.assertIsNone(self._origin(NPM_REGISTRY, path=path))
        self.assertEqual("first_party", self._origin(NPM_MEMBER))

    def test_the_parse_cache_never_answers_one_format_with_the_other(self):
        # #3639 review: Cargo.toml symlinked to package.json. Read first as JSON (an npm
        # finding), the document carries a Cargo-shaped table; the TOML read must not
        # reuse it, whatever the order.
        top = {"name": NPM_ROOT[0], "version": NPM_ROOT[1],
               "package": {"name": WORKSPACE_NAME, "version": WORKSPACE_VERSION}}
        _npm_tree(self.root, top=top)
        _write_lock(self.root)
        os.symlink(os.path.join(self.root, "package.json"),
                   os.path.join(self.root, "Cargo.toml"))
        for order in ("npm first", "cargo first"):
            with self.subTest(order=order):
                cache = first_party_advisory.IngestCache()
                cargo = _raw_advisory_finding()
                if order == "npm first":
                    self.assertEqual("first_party", self._origin(NPM_ROOT, cache=cache))
                first_party_advisory.mark([cargo], self.root, cache)
                self.assertNotIn("package_origin", cargo["tool_evidence"])

    def test_the_entry_and_local_caps_are_exact(self):
        # 64 x MAX_CARGO_MANIFESTS lock entries and MAX_CARGO_MANIFESTS local packages.
        def filler(n):
            return {"node_modules/f%d" % i: {"version": "1.0.0", "resolved": "https://r/x"}
                    for i in range(n)}
        with mock.patch.object(first_party_advisory, "MAX_CARGO_MANIFESTS", 2):
            for entries, expected in ((128, "first_party"), (129, None)):
                with self.subTest(entries=entries):
                    _npm_tree(self.root, lock=_npm_lock(**filler(entries - 4)))
                    self.assertEqual(expected, self._origin(NPM_MEMBER))
            _write_json(os.path.join(self.root, "packages", "util", "package.json"),
                        {"name": "@acme/util", "version": "0.1.0"})
            _npm_tree(self.root, lock=_npm_lock(**{
                "packages/util": {"name": "@acme/util", "version": "0.1.0"},
                "node_modules/@acme/util": {"resolved": "packages/util", "link": True}}))
            self.assertIsNone(self._origin(NPM_MEMBER))         # 3 local packages > 2

    def test_a_malformed_or_old_lock_classifies_nothing(self):
        locks = {
            "v1 lock": {"name": NPM_ROOT[0], "lockfileVersion": 1, "dependencies": {}},
            "packages not an object": dict(_npm_lock(), packages=[]),
            "entry not an object": _npm_lock(**{"node_modules/x": "1.0.0"}),
            "bad node_modules key": _npm_lock(**{"node_modules": {"version": "1"}}),
            "link without resolved": _npm_lock(**{"node_modules/y": {"link": True}}),
        }
        for label, lock in locks.items():
            with self.subTest(lock=label):
                _npm_tree(self.root, lock=lock)
                self.assertIsNone(self._origin(NPM_MEMBER))
                self.assertIsNone(self._origin(NPM_ROOT))

    def test_a_duplicate_key_in_the_lock_classifies_nothing(self):
        _npm_tree(self.root)
        text = json.dumps(_npm_lock())
        dup = text.replace('"packages": {', '"packages": {"packages/lib": {"name": "x", '
                           '"version": "0"}, ', 1)
        with open(os.path.join(self.root, "package-lock.json"), "w", encoding="utf-8") as fh:
            fh.write(dup)
        self.assertIsNone(self._origin(NPM_MEMBER))

    def test_the_lock_path_must_be_confined_and_named_as_npm_reads_it(self):
        _npm_tree(self.root)
        for path in ("../package-lock.json", "/package-lock.json", "yarn.lock",
                     "sub/../package-lock.json", "package.json"):
            with self.subTest(path=path):
                self.assertIsNone(self._origin(NPM_MEMBER, path=path))

    def test_npm_shrinkwrap_is_read_the_same_way(self):
        _npm_tree(self.root, lock_name="npm-shrinkwrap.json")
        self.assertEqual("first_party", self._origin(NPM_MEMBER, path="npm-shrinkwrap.json"))

    def test_trivy_uses_the_same_classification_without_changing_identity(self):
        _npm_tree(self.root)
        doc = _trivy_document(*NPM_MEMBER)
        doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"][
            "artifactLocation"]["uri"] = "package-lock.json"
        plain = _ingest_document(self.root, "trivy.sarif", doc, name_root=False)[0]
        os.rename(os.path.join(self.root, "tools"), os.path.join(self.root, "tools-plain"))
        marked = _ingest_document(self.root, "trivy.sarif", doc)[0]
        self.assertTrue(evidence.is_first_party_advisory(marked))
        self.assertEqual({"name": NPM_MEMBER[0], "version": NPM_MEMBER[1]},
                         marked["tool_evidence"]["advisory_package"])
        self.assertEqual(evidence.finding_fingerprint(marked), evidence.finding_fingerprint(plain))
        self.assertEqual(evidence.reconcile_key(marked), evidence.reconcile_key(plain))

    def test_npm_audit_is_never_classified_even_when_its_range_equals_the_version(self):
        # #3639 review: a single-version GHSA gives vulnerable_versions == "1.4.0". It is
        # still a range, not an installed version: npm classification is limited to the
        # scanners that report one.
        _npm_tree(self.root)
        for version in ("<1.4.1", NPM_MEMBER[1]):
            with self.subTest(version=version):
                self.assertIsNone(self._origin((NPM_MEMBER[0], version),
                                               source="tool:npm-audit"))
        self.assertEqual("first_party", self._origin(NPM_MEMBER, source="tool:trivy"))

    def test_exact_budget_refuses_an_unread_private_redeclaration(self):
        # M10-style (#3634): the budget covers the lock and the root package.json exactly,
        # so the private redeclaration of the root identity is never read -- and an unread
        # declaration must keep the identity off the first-party path.
        lock = _npm_lock(**{
            "private": {"name": NPM_ROOT[0], "version": NPM_ROOT[1]},
            "node_modules/private-copy": {"resolved": "private", "link": True}})
        _npm_tree(self.root, lock=lock)
        _write_json(os.path.join(self.root, "private", "package.json"),
                    {"name": NPM_ROOT[0], "version": NPM_ROOT[1], "private": True})
        budget = (os.path.getsize(os.path.join(self.root, "package-lock.json"))
                  + os.path.getsize(os.path.join(self.root, "package.json")))
        with mock.patch.object(first_party_advisory, "MAX_CARGO_MANIFEST_INGEST_BYTES",
                               budget):
            cache = first_party_advisory.IngestCache()
            self.assertIsNone(self._origin(NPM_ROOT, cache=cache))
        self.assertTrue(cache.manifest_budget_exhausted)
        self.assertEqual(0, cache.manifest_bytes_remaining)
        self.assertIsNone(cache.manifests[("json", os.path.join(self.root, "private",
                                                                "package.json"))])

    def test_lock_bytes_spend_the_shared_ingest_budget(self):
        _npm_tree(self.root)
        lock_size = os.path.getsize(os.path.join(self.root, "package-lock.json"))
        with mock.patch.object(first_party_advisory, "MAX_CARGO_MANIFEST_INGEST_BYTES",
                               lock_size):
            cache = first_party_advisory.IngestCache()
            self.assertIsNone(self._origin(NPM_MEMBER, cache=cache))
        self.assertTrue(cache.manifest_budget_exhausted)
        self.assertEqual(0, cache.manifest_bytes_remaining)
        self.assertIsNone(cache.manifests[("json", os.path.join(self.root, "packages", "lib",
                                                                "package.json"))])

    def test_cargo_and_npm_share_one_budget_and_cache(self):
        _npm_tree(self.root)
        _write_lock(self.root)
        _write_manifest(self.root)
        cache = first_party_advisory.IngestCache()
        npm = self._mark(NPM_MEMBER, cache=cache)
        cargo = _raw_advisory_finding()
        first_party_advisory.mark([cargo], self.root, cache)
        self.assertEqual("first_party", npm["tool_evidence"]["package_origin"])
        self.assertEqual("first_party", cargo["tool_evidence"]["package_origin"])
        self.assertIn("Cargo package", cargo["impact"])
        spent = sum(os.path.getsize(os.path.join(self.root, p)) for p in (
            "package-lock.json", "package.json", "packages/lib/package.json",
            "Cargo.lock", "Cargo.toml"))
        self.assertEqual(first_party_advisory.MAX_CARGO_MANIFEST_INGEST_BYTES - spent,
                         cache.manifest_bytes_remaining)


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
