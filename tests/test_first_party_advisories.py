"""#3593: advisories against a Cargo workspace package are controller facts."""

import copy
import itertools
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
import scripts.synth.corroborate as corroborate
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

    def _workspace_finding(self, members, root_manifest='[workspace]\nmembers = ["crates/*"]\n'):
        """The advisory on the lock's sourceless `workspace-app 1.2.3`, in a workspace
        whose members are `members` ({directory under crates/: manifest text})."""
        root = tempfile.TemporaryDirectory()
        self.addCleanup(root.cleanup)
        _write_lock(root.name)
        _write_manifest(root.name, root_manifest)
        for name, text in members.items():
            member = os.path.join(root.name, "crates", name)
            os.makedirs(member)
            _write_manifest(member, text)
        return _ingest_document(root.name, "osv-scanner.json", _osv_document())[0]

    def test_two_members_declaring_one_identity_are_ambiguous_whatever_they_publish(self):
        """#3593, "ambiguity fails closed" (#3720). An identity is first-party when ONE
        manifest in the tree declares it, and that one is publishable. Two members that
        declare `workspace-app 1.2.3` do not say which of them the lock entry is, so the
        advisory stays on the advisor path: one of them private, in either order, or
        both publishable."""
        package = '[package]\nname = "workspace-app"\nversion = "1.2.3"\n'
        private = package + 'publish = false\n'
        self.assertTrue(evidence.is_first_party_advisory(self._workspace_finding({"a": package})))
        for label, members in (("private, then publishable", {"a": private, "b": package}),
                               ("publishable, then private", {"a": package, "b": private}),
                               ("both publishable", {"a": package, "b": package})):
            with self.subTest(label):
                finding = self._workspace_finding(members)
                self.assertFalse(evidence.is_first_party_advisory(finding))
                self.assertNotIn("package_origin", finding["tool_evidence"])

    def test_a_manifest_reached_under_two_workspace_inheritances_is_ambiguous(self):
        """#3593 (#3720). `crates/a` takes its version from the workspace it is read
        under. It is a member of the root workspace (1.2.3), and it is a path dependency
        of `crates/b`, which is a workspace of its own (9.9.9). Which version it has
        depends on the road taken, so nothing in the tree is proved first-party."""
        root_manifest = ('[workspace]\nmembers = ["crates/*"]\n\n'
                         '[workspace.package]\nversion = "1.2.3"\n')
        app = '[package]\nname = "workspace-app"\nversion.workspace = true\n'
        other = ('[package]\nname = "other"\nversion = "0.1.0"\n\n'
                 '[dependencies]\nworkspace-app = { path = "../a" }\n')
        nested = other + '\n[workspace]\n\n[workspace.package]\nversion = "9.9.9"\n'
        # Reached twice under ONE inheritance, it is the same manifest read the same way.
        self.assertTrue(evidence.is_first_party_advisory(
            self._workspace_finding({"a": app, "b": other}, root_manifest)))
        finding = self._workspace_finding({"a": app, "b": nested}, root_manifest)
        self.assertFalse(evidence.is_first_party_advisory(finding))
        self.assertNotIn("package_origin", finding["tool_evidence"])

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

    def test_oversized_manifest_that_drains_budget_reports_one_exhaustion(self):
        root = tempfile.TemporaryDirectory()
        self.addCleanup(root.cleanup)
        _write_lock(root.name)
        _write_manifest(root.name)
        tools = os.path.join(root.name, "tools")
        os.mkdir(tools)
        document = {"results": [{
            "source": {"path": "/src/Cargo.lock"},
            "packages": [_osv_package(
                WORKSPACE_NAME, WORKSPACE_VERSION, "RUSTSEC-2099-0001")],
        }]}
        with open(os.path.join(tools, "osv-scanner.json"), "w",
                  encoding="utf-8") as fh:
            json.dump(document, fh)
        budget = os.path.getsize(os.path.join(root.name, "Cargo.lock")) + 1

        with mock.patch.object(
                first_party_advisory,
                "MAX_CARGO_MANIFEST_INGEST_BYTES", budget):
            ingested, dispositions = ingest_tools.ingest_dir_detailed(
                tools, "g1", target_root=root.name)

        self.assertNotIn("package_origin", ingested[0]["tool_evidence"])
        self.assertEqual(
            dispositions["osv-scanner"].get(
                "advisory_manifest_budget_exhausted"),
            1,
        )

    def test_budget_exhaustion_disposition_is_per_tool_file(self):
        root = tempfile.TemporaryDirectory()
        self.addCleanup(root.cleanup)
        _write_lock(root.name)
        _write_manifest(root.name)
        tools = os.path.join(root.name, "tools")
        os.mkdir(tools)
        osv_document = {"results": [{
            "source": {"path": "/src/Cargo.lock"},
            "packages": [_osv_package(
                WORKSPACE_NAME, WORKSPACE_VERSION, "RUSTSEC-2099-0001")],
        }]}
        for filename, document in (
                ("osv-scanner.json", osv_document),
                ("trivy.sarif", _trivy_document())):
            with open(os.path.join(tools, filename), "w", encoding="utf-8") as fh:
                json.dump(document, fh)
        budget = os.path.getsize(os.path.join(root.name, "Cargo.lock")) + 1

        with mock.patch.object(
                first_party_advisory,
                "MAX_CARGO_MANIFEST_INGEST_BYTES", budget):
            _ingested, dispositions = ingest_tools.ingest_dir_detailed(
                tools, "g1", target_root=root.name)

        self.assertEqual(
            dispositions["osv-scanner"].get(
                "advisory_manifest_budget_exhausted"),
            1,
        )
        self.assertNotIn(
            "advisory_manifest_budget_exhausted",
            dispositions["trivy"],
        )

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

    def test_a_disguised_or_dangling_link_fails_the_whole_lock(self):
        # #3653: a link must name a real local entry of this lock. Each `resolved` below
        # slips past a scheme check anchored at character 0, or names no local key; beside
        # the real workspace link it must not leave the member first-party.
        disguised = {
            "leading space": " https://registry.npmjs.org/x.tgz",
            "leading newline": "\nhttps://x",
            "percent-encoded scheme": "https%3A//registry.npmjs.org/x.tgz",
            "schemeless registry": "registry.npmjs.org/@acme/lib/-/lib-1.4.0.tgz",
            "dangling": "packages/nonexistent",
            "an install, not a local key": "node_modules/left-pad",
            "drive letter (R13)": "C:/x",
        }
        for label, resolved in disguised.items():
            with self.subTest(resolved=label):
                _npm_tree(self.root, lock=_npm_lock(**{
                    "node_modules/other/node_modules/@acme/lib": {"resolved": resolved,
                                                                  "link": True}}))
                self.assertIsNone(self._origin(NPM_MEMBER))
                self.assertIsNone(self._origin(NPM_ROOT))

    def test_a_link_carrying_its_own_version_or_integrity_fails_the_whole_lock(self):
        # #3653: npm writes neither on a link entry; one that does is not a link.
        for label, extra in (("version", {"version": NPM_MEMBER[1]}),
                             ("integrity", {"integrity": "sha512-x"})):
            with self.subTest(field=label):
                _npm_tree(self.root, lock=_npm_lock(**{"node_modules/@acme/lib": dict(
                    {"resolved": "packages/lib", "link": True}, **extra)}))
                self.assertIsNone(self._origin(NPM_MEMBER))
                self.assertIsNone(self._origin(NPM_ROOT))

    def test_a_link_is_matched_to_its_local_entry_after_normalisation(self):
        for resolved in ("packages/lib", "./packages/lib", "packages/lib/",
                         "packages/x/../lib"):
            with self.subTest(resolved=resolved):
                _npm_tree(self.root, lock=_npm_lock(**{
                    "node_modules/@acme/lib": {"resolved": resolved, "link": True}}))
                self.assertEqual("first_party", self._origin(NPM_MEMBER))
        # The lock key is normalised the same way the link is matched to it later.
        with self.subTest(key="./packages/lib"):
            _npm_tree(self.root, lock=_npm_lock(**{
                "packages/lib": None,
                "./packages/lib": {"name": NPM_MEMBER[0], "version": NPM_MEMBER[1]}}))
            self.assertEqual("first_party", self._origin(NPM_MEMBER))

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

    def test_a_lock_resolving_to_another_name_is_refused(self):
        # #3686 review F1, which lives in the shared lock-path check: a package-lock.json
        # symlinked to a shrinkwrap (or any other name) is not read.
        _npm_tree(self.root, lock_name="npm-shrinkwrap.json")
        os.symlink("npm-shrinkwrap.json", os.path.join(self.root, "package-lock.json"))
        self.assertIsNone(self._origin(NPM_MEMBER))
        self.assertEqual("first_party", self._origin(NPM_MEMBER, path="npm-shrinkwrap.json"))

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


PY_ROOT = ("acme-app", "0.3.0")
PY_MEMBER = ("acme-lib", "1.2.0")
PY_REGISTRY = ("requests", "2.0.0")
_UV_REGISTRY = '{ registry = "https://pypi.org/simple" }'


def _uv_entry(name, version, source):
    version_line = "" if version is None else 'version = "%s"\n' % version
    source_line = "" if source is None else "source = %s\n" % source
    return '[[package]]\nname = "%s"\n%s%s\n' % (name, version_line, source_line)


def _uv_lock(*, root='{ editable = "." }', member='{ editable = "packages/lib" }',
             extra=""):
    """A uv.lock: the editable root, one editable workspace member, one PyPI package."""
    return ('version = 1\nrequires-python = ">=3.11"\n\n'
            + (_uv_entry(*PY_ROOT, root) if root is not None else "")
            + (_uv_entry(*PY_MEMBER, member) if member is not None else "")
            + _uv_entry(*PY_REGISTRY, _UV_REGISTRY) + extra)


def _pyproject(name, version, extra=""):
    return '[project]\nname = "%s"\nversion = "%s"\n%s' % (name, version, extra)


def _write_text(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)


def _py_tree(root, *, lock=None, lock_name="uv.lock", member=None, top=None):
    """A fixture Python project: pyproject.toml, packages/lib/pyproject.toml, a lock."""
    _write_text(os.path.join(root, "pyproject.toml"),
                top if top is not None else _pyproject(*PY_ROOT))
    if member is not False:
        _write_text(os.path.join(root, "packages", "lib", "pyproject.toml"),
                    member if member is not None else _pyproject("acme_lib", PY_MEMBER[1]))
    _write_text(os.path.join(root, lock_name), lock if lock is not None else _uv_lock())


def _poetry_lock(member_source='type = "directory"\nurl = "packages/lib"\n', extra=""):
    return ('[[package]]\nname = "%s"\nversion = "%s"\ndevelop = true\n\n'
            '[package.source]\n%s\n'
            '[[package]]\nname = "%s"\nversion = "%s"\n\n%s'
            '[metadata]\nlock-version = "2.0"\n'
            % (PY_MEMBER + (member_source,) + PY_REGISTRY + (extra,)))


def _pdm_lock(member_fields='path = "./packages/lib"\neditable = true\n', extra=""):
    return ('[metadata]\nlock_version = "4.4"\n\n'
            '[[package]]\nname = "%s"\nversion = "%s"\n%s\n'
            '[[package]]\nname = "%s"\nversion = "%s"\n\n%s'
            % (PY_MEMBER + (member_fields,) + PY_REGISTRY + (extra,)))


class TestPythonFirstPartyAdvisory(unittest.TestCase):
    """#3623 Python: uv.lock, poetry.lock and pdm.lock local-path packages, mirroring the
    Cargo and npm markers under the three owner rulings (review-root exemption, a dynamic
    version fails closed, Pipfile.lock / requirements.txt out of scope). Fixtures only."""

    def setUp(self):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        self.root = os.path.realpath(d.name)

    def _mark(self, package, *, path="uv.lock", source="tool:osv-scanner", cache=None):
        finding = _raw_advisory_finding(path=path, source=source, package=package[0],
                                        version=package[1])
        first_party_advisory.mark([finding], self.root,
                                  cache or first_party_advisory.IngestCache())
        return finding

    def _origin(self, package, **kw):
        return self._mark(package, **kw)["tool_evidence"].get("package_origin")

    def test_a_uv_member_and_root_are_reframed_but_the_registry_package_is_not(self):
        _py_tree(self.root)
        member = self._mark(PY_MEMBER)
        self.assertTrue(evidence.is_first_party_advisory(member))
        self.assertIn("acme-lib 1.2.0 Python package", member["impact"])
        self.assertIn("workspace/path package", member["remediation"])
        self.assertNotIn("upgrade", member["remediation"].lower())
        self.assertEqual("first_party", self._origin(PY_ROOT))
        registry = self._mark(PY_REGISTRY)
        self.assertNotIn("package_origin", registry["tool_evidence"])
        self.assertFalse(evidence.is_first_party_advisory(registry))

    def test_names_compare_under_pep_503(self):
        # The lock says acme-lib, the manifest acme_lib, the scanner Acme.Lib.
        _py_tree(self.root)
        for name in ("Acme.Lib", "ACME_LIB", "acme--lib", "acme-lib"):
            with self.subTest(name=name):
                self.assertEqual("first_party", self._origin((name, PY_MEMBER[1])))
        for name in ("acmelib", "acme-lib2"):
            with self.subTest(name=name):
                self.assertIsNone(self._origin((name, PY_MEMBER[1])))

    def test_osv_ingest_of_a_poetry_lock_classifies_the_path_member(self):
        _py_tree(self.root, lock=_poetry_lock(), lock_name="poetry.lock")
        def package(name, version, advisory):
            return {"package": {"name": name, "version": version, "ecosystem": "PyPI"},
                    "vulnerabilities": [{"id": advisory, "summary": "affected package",
                                         "database_specific": {"severity": "HIGH"}}],
                    "groups": []}
        doc = {"results": [{"source": {"path": "/src/poetry.lock"}, "packages": [
            package(*PY_MEMBER, "PYSEC-2099-1"), package(*PY_REGISTRY, "PYSEC-2099-2")]}]}
        findings = _ingest_document(self.root, "osv-scanner.json", doc)
        by_package = {f["tool_evidence"]["package_name"]: f for f in findings}
        self.assertTrue(evidence.is_first_party_advisory(by_package[PY_MEMBER[0]]))
        self.assertFalse(evidence.is_first_party_advisory(by_package[PY_REGISTRY[0]]))

    def test_trivy_uses_the_same_classification_without_changing_identity(self):
        _py_tree(self.root)
        doc = _trivy_document(*PY_MEMBER)
        doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"][
            "artifactLocation"]["uri"] = "uv.lock"
        plain = _ingest_document(self.root, "trivy.sarif", doc, name_root=False)[0]
        os.rename(os.path.join(self.root, "tools"), os.path.join(self.root, "tools-plain"))
        marked = _ingest_document(self.root, "trivy.sarif", doc)[0]
        self.assertTrue(evidence.is_first_party_advisory(marked))
        self.assertEqual({"name": PY_MEMBER[0], "version": PY_MEMBER[1]},
                         marked["tool_evidence"]["advisory_package"])
        self.assertEqual(evidence.finding_fingerprint(marked), evidence.finding_fingerprint(plain))
        self.assertEqual(evidence.reconcile_key(marked), evidence.reconcile_key(plain))

    def test_pip_audit_is_never_classified(self):
        _py_tree(self.root)
        self.assertIsNone(self._origin(PY_MEMBER, source="tool:pip-audit"))
        self.assertEqual("first_party", self._origin(PY_MEMBER, source="tool:trivy"))

    # Ruling 1: the review-root exemption, and no exemption for a member.
    _UNPUBLISHABLE = {
        "classifier": 'classifiers = ["Private :: Do Not Upload"]\n',
        "classifier, padded": 'classifiers = [" Private :: Do Not Upload "]\n',
        "poetry package-mode": '\n[tool.poetry]\npackage-mode = false\n',
        "uv package": '\n[tool.uv]\npackage = false\n',
        # #3686 review: PyPI refuses every `Private ::` classifier, and PDM's
        # `distribution = false` is its `package-mode = false`.
        "another Private classifier": 'classifiers = ["Private :: Internal Only"]\n',
        "pdm distribution": '\n[tool.pdm]\ndistribution = false\n',
        # #3686 review round 3, F1: dynamic classifiers are filled in at build time, so
        # a `Private ::` one cannot be seen. Unseen is unpublishable.
        "dynamic classifiers": 'dynamic = ["classifiers"]\n',
        "dynamic classifiers beside static ones":
            'dynamic = ["readme", "classifiers"]\nclassifiers = ["Topic :: Software"]\n',
    }

    def test_an_unpublishable_review_root_is_still_first_party(self):
        for label, extra in self._UNPUBLISHABLE.items():
            with self.subTest(marker=label):
                _py_tree(self.root, top=_pyproject(*PY_ROOT, extra))
                self.assertEqual("first_party", self._origin(PY_ROOT))
        _py_tree(self.root, lock=_uv_lock(root='{ virtual = "." }'))
        self.assertEqual("first_party", self._origin(PY_ROOT))

    def test_an_unpublishable_member_stays_on_the_advisor_path(self):
        for label, extra in self._UNPUBLISHABLE.items():
            with self.subTest(marker=label):
                _py_tree(self.root, member=_pyproject(*PY_MEMBER, extra))
                self.assertIsNone(self._origin(PY_MEMBER))
                self.assertEqual("first_party", self._origin(PY_ROOT))
        _py_tree(self.root, lock=_uv_lock(member='{ virtual = "packages/lib" }'))
        self.assertIsNone(self._origin(PY_MEMBER))
        # Explicitly publishable flags change nothing.
        _py_tree(self.root, member=_pyproject(
            *PY_MEMBER, '\n[tool.poetry]\npackage-mode = true\n[tool.uv]\npackage = true\n'
            '[tool.pdm]\ndistribution = true\n'))
        self.assertEqual("first_party", self._origin(PY_MEMBER))
        # Another dynamic field hides no classifier.
        _py_tree(self.root, member=_pyproject(*PY_MEMBER, 'dynamic = ["readme"]\n'))
        self.assertEqual("first_party", self._origin(PY_MEMBER))
        # `Private ::` is a prefix, not a substring.
        _py_tree(self.root, member=_pyproject(
            *PY_MEMBER, 'classifiers = ["Topic :: Private :: X", "Private::Tight"]\n'))
        self.assertEqual("first_party", self._origin(PY_MEMBER))

    def test_the_root_exemption_belongs_to_the_review_root_only(self):
        # The same unpublishable project one level down is not the review root.
        nested = os.path.join(self.root, "app")
        _py_tree(nested, top=_pyproject(*PY_ROOT, self._UNPUBLISHABLE["classifier"]))
        _py_tree(self.root, lock=_uv_lock(root='{ editable = "app" }'))
        self.assertIsNone(self._origin(PY_ROOT))

    # Ruling 2: a dynamic version fails closed.
    def test_a_dynamic_or_missing_version_fails_closed(self):
        manifests = {
            "dynamic version": '[project]\nname = "acme-lib"\ndynamic = ["version"]\n'
                               '\n[tool.poetry]\nversion = "1.2.0"\n',
            "dynamic with a static twin": _pyproject(*PY_MEMBER, 'dynamic = ["version"]\n'),
            "no version": '[project]\nname = "acme-lib"\n',
            "poetry without version": '[tool.poetry]\nname = "acme-lib"\n',
        }
        for label, member in manifests.items():
            with self.subTest(manifest=label):
                _py_tree(self.root, member=member)
                self.assertIsNone(self._origin(PY_MEMBER))
        # Other dynamic fields are fine.
        _py_tree(self.root, member=_pyproject(*PY_MEMBER, 'dynamic = ["readme"]\n'))
        self.assertEqual("first_party", self._origin(PY_MEMBER))

    def test_a_lock_entry_without_a_version_is_skipped_not_matched(self):
        lock = _uv_lock(member=None, extra=_uv_entry(PY_MEMBER[0], None,
                                                     '{ editable = "packages/lib" }'))
        _py_tree(self.root, lock=lock)
        self.assertIsNone(self._origin(PY_MEMBER))
        self.assertEqual("first_party", self._origin(PY_ROOT))

    # Ruling 3: Pipfile.lock and requirements.txt are out of scope.
    def test_pipfile_lock_and_requirements_path_entries_never_classify(self):
        _py_tree(self.root)
        _write_text(os.path.join(self.root, "Pipfile.lock"), json.dumps({
            "_meta": {}, "default": {"acme-lib": {"path": "./packages/lib",
                                                   "editable": True,
                                                   "version": "==1.2.0"}}}))
        _write_text(os.path.join(self.root, "requirements.txt"),
                    "-e ./packages/lib\n./packages/lib\nacme-lib @ file:./packages/lib\n")
        for path in ("Pipfile.lock", "requirements.txt"):
            for source in ("tool:osv-scanner", "tool:trivy", "tool:pip-audit"):
                with self.subTest(path=path, source=source):
                    self.assertIsNone(self._origin(PY_MEMBER, path=path, source=source))

    def test_project_comes_before_legacy_poetry_metadata(self):
        both = _pyproject(*PY_MEMBER, '\n[tool.poetry]\nname = "other"\nversion = "9.9.9"\n')
        _py_tree(self.root, member=both)
        self.assertEqual("first_party", self._origin(PY_MEMBER))
        _py_tree(self.root, member=_pyproject("other", "9.9.9",
                                              '\n[tool.poetry]\nname = "acme-lib"\n'
                                              'version = "1.2.0"\n'))
        self.assertIsNone(self._origin(PY_MEMBER))
        _py_tree(self.root, member='[tool.poetry]\nname = "acme-lib"\nversion = "1.2.0"\n')
        self.assertEqual("first_party", self._origin(PY_MEMBER))
        # A legacy Poetry project with the private classifier is still unpublishable.
        _py_tree(self.root, member='[tool.poetry]\nname = "acme-lib"\nversion = "1.2.0"\n'
                                   'classifiers = ["Private :: Do Not Upload"]\n')
        self.assertIsNone(self._origin(PY_MEMBER))

    def test_malformed_manifest_fields_fail_closed(self):
        for member in ('tool = 1\n' + _pyproject(*PY_MEMBER),
                       'project = 1\n',
                       _pyproject(*PY_MEMBER, 'dynamic = "version"\n'),
                       _pyproject(*PY_MEMBER, 'dynamic = [1]\n'),
                       _pyproject(*PY_MEMBER, 'classifiers = "x"\n'),
                       _pyproject(*PY_MEMBER, 'classifiers = [1]\n'),
                       _pyproject(*PY_MEMBER, '\n[tool.poetry]\npackage-mode = "no"\n'),
                       _pyproject(*PY_MEMBER, '\n[tool.uv]\npackage = 0\n'),
                       _pyproject(*PY_MEMBER, '[tool]\npoetry = 1\n'),
                       _pyproject(*PY_MEMBER, '[tool]\nuv = 1\n'),
                       _pyproject(*PY_MEMBER, '[tool]\npdm = 1\n'),
                       _pyproject(*PY_MEMBER, '\n[tool.pdm]\ndistribution = "no"\n'),
                       '[project]\nname = 1\nversion = "1.2.0"\n',
                       '[project]\nname = "acme-lib"\nversion = ""\n',
                       '[build-system]\nrequires = []\n',
                       'not toml [\n'):
            with self.subTest(member=member):
                _py_tree(self.root, member=member)
                self.assertIsNone(self._origin(PY_MEMBER))
                # Only that identity: the root in the same lock is still proved.
                self.assertEqual("first_party", self._origin(PY_ROOT))

    def test_a_version_mismatch_stays_on_the_advisor_path(self):
        _py_tree(self.root, member=_pyproject(PY_MEMBER[0], "1.2.1"))
        self.assertIsNone(self._origin(PY_MEMBER))
        self.assertIsNone(self._origin((PY_MEMBER[0], "1.2.1")))
        _py_tree(self.root)
        self.assertIsNone(self._origin((PY_MEMBER[0], "1.2.1")))
        self.assertIsNone(self._origin((PY_MEMBER[0], "1.2")))     # no PEP 440 folding

    def test_every_same_identity_entry_must_be_local(self):
        for label, source in (("registry", _UV_REGISTRY),
                              ("git", '{ git = "https://example.invalid/x.git#abc" }'),
                              ("url", '{ url = "https://example.invalid/x.tar.gz" }'),
                              ("archive", '{ path = "dist/acme_lib-1.2.0.whl" }'),
                              ("no source", None)):
            with self.subTest(copy=label):
                _py_tree(self.root, lock=_uv_lock(extra=_uv_entry(*PY_MEMBER, source)))
                self.assertIsNone(self._origin(PY_MEMBER))
                self.assertEqual("first_party", self._origin(PY_ROOT))

    def test_a_pep_440_equal_non_local_spelling_is_ambiguous(self):
        # #3686 review: confirmation stays an exact match, but a registry copy spelled
        # differently for the same release still makes the identity ambiguous.
        local = _uv_entry(PY_MEMBER[0], "1.2.0rc1", '{ editable = "packages/lib" }')
        for registry, expected in (("1.2.0-rc1", None), ("1.2rc1", None),
                                   ("v1.2.0.RC1", None), ("0!1.2.0c1", None),
                                   ("1.2.0rc2", "first_party"), ("1.2.0", "first_party"),
                                   ("1.2.0rc1+local", "first_party")):
            with self.subTest(registry=registry):
                _py_tree(self.root, member=_pyproject(PY_MEMBER[0], "1.2.0rc1"),
                         lock=_uv_lock(member=None, extra=local + _uv_entry(
                             PY_MEMBER[0], registry, _UV_REGISTRY)))
                self.assertEqual(expected, self._origin((PY_MEMBER[0], "1.2.0rc1")))
        # An advisory naming another spelling of a proved local release is not confirmed.
        _py_tree(self.root, member=_pyproject(PY_MEMBER[0], "1.2.0rc1"),
                 lock=_uv_lock(member=None, extra=local))
        self.assertEqual("first_party", self._origin((PY_MEMBER[0], "1.2.0rc1")))
        self.assertIsNone(self._origin((PY_MEMBER[0], "1.2.0-rc1")))

    def test_a_version_past_the_int_digit_limit_fails_closed_for_its_identity_only(self):
        # #3686 review N1: int() refuses more than 4300 digits. Such a version keys as
        # its own text, so the lock still parses and only that identity is affected.
        huge = "1." + "9" * 5000
        self.assertEqual(huge, first_party_advisory._pep440_key(" %s " % huge.upper()))
        self.assertEqual("1!" + huge, first_party_advisory._pep440_key("1!" + huge))
        _py_tree(self.root, lock=_uv_lock(extra=_uv_entry("other", huge, _UV_REGISTRY)))
        self.assertEqual("first_party", self._origin(PY_MEMBER))
        self.assertEqual("first_party", self._origin(PY_ROOT))
        self.assertIsNone(self._origin(("other", huge)))

    def test_the_pep_440_key_agrees_only_on_equal_releases(self):
        key = first_party_advisory._pep440_key
        for a, b in (("1.0", "1.0.0"), ("1.0a1", "1.0.alpha1"), ("1.0b2", "1.0-beta.2"),
                     ("1.0rc1", "1.0c1"), ("1.0rc1", "1.0pre1"), ("1.0rc1", "1.0preview1"),
                     ("1.0-1", "1.0.post1"), ("1.0.post1", "1.0r1"), ("1.0.post1", "1.0rev1"),
                     ("1.0.dev", "1.0dev0"), ("1.0a", "1.0a0"), ("1.0.post", "1.0post0"),
                     ("V1.0", " 1.0 "), ("0!1.0", "1.0"), ("00!1.0", "1.0"),
                     ("1.0+Ubuntu.1", "1.0+ubuntu-1"), ("1.0+1", "1.0+01"),
                     ("not a version", " NOT A VERSION")):
            with self.subTest(equal=(a, b)):
                self.assertEqual(key(a), key(b))
        for a, b in (("1.0", "1.0.post0"), ("1.0a1", "1.0b1"), ("1.0", "1.0.dev0"),
                     ("1.0", "1.0+local"), ("1!1.0", "1.0"), ("1.0rc1", "1.0rc2"),
                     ("1.0", "1.1"), ("1.0.post1", "1.0.post2"), ("1.0.dev1", "1.0.dev2"),
                     ("1.0+a", "1.0+b"), ("1.0-1", "1.0-2"),
                     # Not versions: each keys as its own text.
                     ("1.0.", "1.0"), ("1..0", "1.0"), (".1", "1"), ("1.0+", "1.0"),
                     ("1!", "1"), ("x!1.0", "1.0"), ("1.0+a..b", "1.0+a.b"),
                     ("1.0rc1x", "1.0rc1"), ("\u0661.0", "1.0"),
                     # An invalid local label is not a version, so a `v` still differs.
                     ("v1.0+a..b", "1.0+a..b")):
            with self.subTest(different=(a, b)):
                self.assertNotEqual(key(a), key(b))

    def test_a_lock_symlinked_to_another_format_is_refused(self):
        # #3686 review F1: the parser follows the resolved name, so a lock must resolve
        # to a file of its own name. P2: poetry.lock -> pdm.lock, where PDM's `path`
        # would read a PyPI package as local.
        _write_text(os.path.join(self.root, "vend", "pyproject.toml"),
                    _pyproject(*PY_REGISTRY))
        _write_text(os.path.join(self.root, "pdm.lock"),
                    '[[package]]\nname = "requests"\nversion = "2.0.0"\npath = "./vend"\n')
        os.symlink("pdm.lock", os.path.join(self.root, "poetry.lock"))
        cache = first_party_advisory.IngestCache()
        self.assertIsNone(self._origin(PY_REGISTRY, path="poetry.lock", cache=cache))
        # P10: a verdict cached for the real pdm.lock is never served to the symlink.
        self.assertEqual("first_party", self._origin(PY_REGISTRY, path="pdm.lock",
                                                     cache=cache))
        self.assertIsNone(self._origin(PY_REGISTRY, path="poetry.lock", cache=cache))

    def test_a_uv_lock_symlinked_to_pdm_or_cargo_is_refused(self):
        # P1: uv.lock -> pdm.lock, where the PDM parser cannot see the registry source.
        _py_tree(self.root, lock_name="pdm.lock", lock=(
            '[[package]]\nname = "acme-lib"\nversion = "1.2.0"\npath = "./packages/lib"\n'
            'source = { registry = "https://pypi.org/simple" }\n'))
        os.symlink("pdm.lock", os.path.join(self.root, "uv.lock"))
        self.assertIsNone(self._origin(PY_MEMBER))
        # uv.lock -> Cargo.lock would reach the Cargo branch.
        _write_lock(self.root)
        _write_manifest(self.root)
        os.remove(os.path.join(self.root, "uv.lock"))
        os.symlink("Cargo.lock", os.path.join(self.root, "uv.lock"))
        self.assertIsNone(self._origin((WORKSPACE_NAME, WORKSPACE_VERSION)))
        self.assertEqual("first_party", self._origin((WORKSPACE_NAME, WORKSPACE_VERSION),
                                                     path="Cargo.lock"))

    def test_a_symlinked_python_lock_is_never_the_review_roots_own(self):
        # Same name: it resolves into another directory, which is not the review root.
        _py_tree(self.root, lock_name=os.path.join("locks", "uv.lock"))
        os.symlink(os.path.join("locks", "uv.lock"), os.path.join(self.root, "uv.lock"))
        self.assertIsNone(self._origin(PY_MEMBER))
        # Root directory: it resolves to another name.
        _py_tree(self.root, lock_name="real.lock")
        os.remove(os.path.join(self.root, "uv.lock"))
        os.symlink("real.lock", os.path.join(self.root, "uv.lock"))
        self.assertIsNone(self._origin(PY_MEMBER))

    def test_a_directory_source_is_local_too(self):
        _py_tree(self.root, lock=_uv_lock(member='{ directory = "packages/lib" }'))
        self.assertEqual("first_party", self._origin(PY_MEMBER))

    def test_an_archive_source_is_never_local_even_when_it_names_a_project(self):
        # uv's `path` and Poetry's `file` are archive sources; naming a directory that
        # holds a matching pyproject.toml does not make them a local project.
        _py_tree(self.root, lock=_uv_lock(member='{ path = "packages/lib" }'))
        self.assertIsNone(self._origin(PY_MEMBER))
        _py_tree(self.root, lock=_poetry_lock('type = "file"\nurl = "packages/lib"\n'),
                 lock_name="poetry.lock")
        self.assertIsNone(self._origin(PY_MEMBER, path="poetry.lock"))

    def test_an_absolute_or_url_path_is_not_local(self):
        # Both resolve to a real in-tree project: the absolute one directly, the URL one
        # because a directory with that literal name exists. Neither is a lock's local path.
        _write_text(os.path.join(self.root, "file:packages", "lib", "pyproject.toml"),
                    _pyproject(*PY_MEMBER))
        for path in (os.path.join(self.root, "packages", "lib"), "file:packages/lib"):
            with self.subTest(path=path):
                _py_tree(self.root, lock=_uv_lock(member='{ editable = %s }'
                                                  % json.dumps(path)))
                self.assertIsNone(self._origin(PY_MEMBER))
                self.assertEqual("first_party", self._origin(PY_ROOT))

    def test_a_member_outside_the_tree_stays_on_the_advisor_path(self):
        outside = tempfile.TemporaryDirectory()
        self.addCleanup(outside.cleanup)
        _write_text(os.path.join(outside.name, "pyproject.toml"), _pyproject(*PY_MEMBER))
        rel = os.path.relpath(outside.name, self.root)
        _py_tree(self.root, lock=_uv_lock(member='{ editable = %s }' % json.dumps(rel)))
        self.assertIsNone(self._origin(PY_MEMBER))

    def test_a_member_symlinked_out_of_the_tree_stays_on_the_advisor_path(self):
        outside = tempfile.TemporaryDirectory()
        self.addCleanup(outside.cleanup)
        _write_text(os.path.join(outside.name, "pyproject.toml"), _pyproject(*PY_MEMBER))
        _py_tree(self.root, member=False)
        os.makedirs(os.path.join(self.root, "packages"), exist_ok=True)
        os.symlink(outside.name, os.path.join(self.root, "packages", "lib"))
        self.assertIsNone(self._origin(PY_MEMBER))

    def test_a_malformed_lock_classifies_nothing(self):
        locks = {
            "not toml": "[[package]\n",
            "package not a list": 'package = "x"\n',
            "entry not a table": 'package = [1]\n',
            "entry not a table beside real ones": (
                'package = [{ name = "acme-app", version = "0.3.0", '
                'source = { editable = "." } }, 1]\n'),
            "entry without a name": _uv_lock(extra='[[package]]\nversion = "1"\n'
                                                   'source = %s\n\n' % _UV_REGISTRY),
            "registry entry without a version": _uv_lock(
                extra=_uv_entry("other", None, _UV_REGISTRY)),
            "two source kinds": _uv_lock(
                extra=_uv_entry("other", "1", '{ registry = "r", editable = "x" }')),
            "unknown source kind": _uv_lock(extra=_uv_entry("other", "1", '{ svn = "x" }')),
            "source not a table": _uv_lock(extra=_uv_entry("other", "1", '"pypi"')),
            "source a list": _uv_lock(extra=_uv_entry("other", "1", '["editable", "."]')),
            # #3686 review N2: a string or list naming a known kind is still not a table.
            "source a registry string": _uv_lock(extra=_uv_entry("other", "1", '"registry"')),
            "source a registry list": _uv_lock(extra=_uv_entry("other", "1", '["registry"]')),
            "empty local path": _uv_lock(extra=_uv_entry("other", "1", '{ editable = "" }')),
            "non-string local path": _uv_lock(extra=_uv_entry("other", "1",
                                                              '{ directory = 1 }')),
        }
        for label, lock in locks.items():
            with self.subTest(lock=label):
                _py_tree(self.root, lock=lock)
                self.assertIsNone(self._origin(PY_MEMBER))
                self.assertIsNone(self._origin(PY_ROOT))

    def test_poetry_sources(self):
        _py_tree(self.root, lock=_poetry_lock(), lock_name="poetry.lock")
        self.assertEqual("first_party", self._origin(PY_MEMBER, path="poetry.lock"))
        self.assertIsNone(self._origin(PY_REGISTRY, path="poetry.lock"))
        for label, source in (("file", 'type = "file"\nurl = "dist/a.whl"\n'),
                              ("git", 'type = "git"\nurl = "https://example.invalid/x"\n'),
                              ("legacy", 'type = "legacy"\nurl = "https://example.invalid"\n'),
                              ("absolute", 'type = "directory"\nurl = %s\n'
                               % json.dumps(os.path.join(self.root, "packages", "lib")))):
            with self.subTest(source=label):
                _py_tree(self.root, lock=_poetry_lock(source), lock_name="poetry.lock")
                self.assertIsNone(self._origin(PY_MEMBER, path="poetry.lock"))
        for label, source in (("no type", 'url = "packages/lib"\n'),
                              ("directory without url", 'type = "directory"\n')):
            with self.subTest(malformed=label):
                _py_tree(self.root, lock=_poetry_lock(source), lock_name="poetry.lock")
                self.assertIsNone(self._origin(PY_MEMBER, path="poetry.lock"))

    def test_another_entrys_source_decides_the_whole_lock_only_when_malformed(self):
        other = '[[package]]\nname = "other"\nversion = "1"\n%s\n'
        for label, lock_name, lock, expected in (
                ("poetry type not a string", "poetry.lock",
                 _poetry_lock(extra=other % '\n[package.source]\ntype = 1\n'), None),
                ("poetry source not a table", "poetry.lock",
                 _poetry_lock(extra=other % 'source = "pypi"'), None),
                ("poetry url source", "poetry.lock",
                 _poetry_lock(extra=other % '\n[package.source]\ntype = "url"\n'
                                            'url = "https://example.invalid/x.whl"\n'),
                 "first_party"),
                ("pdm url source", "pdm.lock",
                 _pdm_lock(extra=other % 'url = "https://example.invalid/x.whl"'),
                 "first_party"),
                ("pdm git source", "pdm.lock",
                 _pdm_lock(extra=other % 'git = "https://example.invalid/x"'), "first_party")):
            with self.subTest(lock=label):
                _py_tree(self.root, lock=lock, lock_name=lock_name)
                self.assertEqual(expected, self._origin(PY_MEMBER, path=lock_name))

    def test_poetry_registry_copy_of_a_path_member_is_ambiguous(self):
        extra = '[[package]]\nname = "acme_lib"\nversion = "1.2.0"\n\n'
        _py_tree(self.root, lock=_poetry_lock(extra=extra), lock_name="poetry.lock")
        self.assertIsNone(self._origin(PY_MEMBER, path="poetry.lock"))

    def test_pdm_sources(self):
        _py_tree(self.root, lock=_pdm_lock(), lock_name="pdm.lock")
        self.assertEqual("first_party", self._origin(PY_MEMBER, path="pdm.lock"))
        self.assertIsNone(self._origin(PY_REGISTRY, path="pdm.lock"))
        for label, fields in (("git", 'git = "https://example.invalid/x"\n'),
                              ("url", 'url = "https://example.invalid/x.whl"\n'),
                              ("wheel path", 'path = "./dist/acme_lib-1.2.0.whl"\n'),
                              ("path and git", 'path = "./packages/lib"\n'
                                               'git = "https://example.invalid/x"\n')):
            with self.subTest(fields=label):
                _py_tree(self.root, lock=_pdm_lock(fields), lock_name="pdm.lock")
                self.assertIsNone(self._origin(PY_MEMBER, path="pdm.lock"))

    def test_only_the_review_roots_own_lock_is_the_reviewed_project(self):
        nested = os.path.join(self.root, "vendor", "y")
        _py_tree(nested)
        _py_tree(self.root)
        self.assertIsNone(self._origin(PY_MEMBER, path="vendor/y/uv.lock"))
        self.assertEqual("first_party", self._origin(PY_MEMBER))

    def test_the_lock_path_must_be_confined_and_named_as_the_tools_read_it(self):
        _py_tree(self.root)
        for path in ("../uv.lock", "/uv.lock", "sub/../uv.lock", "pyproject.toml",
                     "UV.lock", "Pipfile"):
            with self.subTest(path=path):
                self.assertIsNone(self._origin(PY_MEMBER, path=path))

    def test_the_entry_and_local_caps_are_exact(self):
        with mock.patch.object(first_party_advisory, "MAX_CARGO_MANIFESTS", 2):
            # 2 local + 1 registry + 125 = 128 entries; one more is 129.
            for count, expected in ((125, "first_party"), (126, None)):
                with self.subTest(entries=count + 3):
                    filler = "".join(_uv_entry("f%d" % i, "1.0.0", _UV_REGISTRY)
                                     for i in range(count))
                    _py_tree(self.root, lock=_uv_lock(extra=filler))
                    self.assertEqual(expected, self._origin(PY_MEMBER))
            _write_text(os.path.join(self.root, "packages", "util", "pyproject.toml"),
                        _pyproject("acme-util", "0.1.0"))
            _py_tree(self.root, lock=_uv_lock(extra=_uv_entry(
                "acme-util", "0.1.0", '{ editable = "packages/util" }')))
            self.assertIsNone(self._origin(PY_MEMBER))          # 3 local packages > 2

    def test_lock_bytes_spend_the_shared_ingest_budget(self):
        _py_tree(self.root)
        lock_size = os.path.getsize(os.path.join(self.root, "uv.lock"))
        with mock.patch.object(first_party_advisory, "MAX_CARGO_MANIFEST_INGEST_BYTES",
                               lock_size):
            cache = first_party_advisory.IngestCache()
            self.assertIsNone(self._origin(PY_MEMBER, cache=cache))
        self.assertTrue(cache.manifest_budget_exhausted)
        self.assertEqual(0, cache.manifest_bytes_remaining)

    def test_a_padded_manifest_identity_is_not_the_locks(self):
        # #3686 review round 3, F4: the manifest's name and version are compared as
        # written; nothing strips them.
        for label, member in (("version", _pyproject(PY_MEMBER[0], " 1.2.0")),
                              ("version, trailing", _pyproject(PY_MEMBER[0], "1.2.0 ")),
                              ("name", _pyproject(" acme-lib", PY_MEMBER[1])),
                              ("name, trailing", _pyproject("acme-lib ", PY_MEMBER[1]))):
            with self.subTest(padded=label):
                _py_tree(self.root, member=member)
                self.assertIsNone(self._origin(PY_MEMBER))
                self.assertEqual("first_party", self._origin(PY_ROOT))

    def test_a_lock_name_that_is_not_a_pep_508_name_fails_the_lock(self):
        # #3686 review round 3, F3: `"acme-lib "` would not make `acme-lib` ambiguous.
        for name in ("acme-lib ", " acme-lib", "acme lib", "-acme", "acme-", "acme/lib",
                     "acm\u00e9", ".", ""):
            with self.subTest(name=name):
                _py_tree(self.root, lock=_uv_lock(
                    extra=_uv_entry(name, PY_MEMBER[1], _UV_REGISTRY)))
                self.assertIsNone(self._origin(PY_MEMBER))
                self.assertIsNone(self._origin(PY_ROOT))
        for name in ("A", "a1", "Acme.Lib_x-1"):
            with self.subTest(valid=name):
                _py_tree(self.root, lock=_uv_lock(extra=_uv_entry(name, "9", _UV_REGISTRY)))
                self.assertEqual("first_party", self._origin(PY_MEMBER))

    def test_two_local_spellings_of_one_release_are_ambiguous(self):
        # #3686 review round 3, F2: local `1.2.0` beside local `1.2` is one release
        # declared twice, whichever of them a manifest proves.
        twin = _uv_entry(PY_MEMBER[0], "1.2", '{ editable = "packages/twin" }')
        _py_tree(self.root, lock=_uv_lock(extra=twin))
        _write_text(os.path.join(self.root, "packages", "twin", "pyproject.toml"),
                    _pyproject(PY_MEMBER[0], "1.2"))
        self.assertIsNone(self._origin(PY_MEMBER))
        self.assertIsNone(self._origin((PY_MEMBER[0], "1.2")))
        self.assertEqual("first_party", self._origin(PY_ROOT))
        # A different release of the same name is not a twin.
        other = _uv_entry(PY_MEMBER[0], "1.3", '{ editable = "packages/twin" }')
        _py_tree(self.root, lock=_uv_lock(extra=other))
        self.assertEqual("first_party", self._origin(PY_MEMBER))

    def test_the_lock_cap_is_16_mib(self):
        self.assertEqual(16 * 1024 * 1024, first_party_advisory.MAX_PYTHON_LOCK_BYTES)

    def test_an_oversized_lock_classifies_nothing(self):
        _py_tree(self.root)
        lock_size = os.path.getsize(os.path.join(self.root, "uv.lock"))
        for limit, expected in ((lock_size, "first_party"), (lock_size - 1, None)):
            with self.subTest(limit=limit), \
                    mock.patch.object(first_party_advisory, "MAX_PYTHON_LOCK_BYTES", limit):
                self.assertEqual(expected, self._origin(PY_MEMBER))

    def test_exact_budget_refuses_an_unread_private_redeclaration(self):
        # The budget covers the lock, the root and the member manifests exactly, so a
        # private redeclaration of the member identity is never read -- and an unread
        # declaration keeps the identity off the first-party path.
        lock = _uv_lock(extra=_uv_entry(*PY_MEMBER, '{ editable = "private" }'))
        _py_tree(self.root, lock=lock)
        _write_text(os.path.join(self.root, "private", "pyproject.toml"),
                    _pyproject(*PY_MEMBER, 'classifiers = ["Private :: Do Not Upload"]\n'))
        budget = sum(os.path.getsize(os.path.join(self.root, p)) for p in (
            "uv.lock", "pyproject.toml", "packages/lib/pyproject.toml"))
        with mock.patch.object(first_party_advisory, "MAX_CARGO_MANIFEST_INGEST_BYTES",
                               budget):
            cache = first_party_advisory.IngestCache()
            self.assertIsNone(self._origin(PY_MEMBER, cache=cache))
        self.assertTrue(cache.manifest_budget_exhausted)
        self.assertIsNone(cache.manifests[("toml", os.path.join(self.root, "private",
                                                                "pyproject.toml"))])

    def test_cargo_npm_and_python_share_one_budget_and_cache(self):
        _py_tree(self.root)
        _write_lock(self.root)
        _write_manifest(self.root)
        cache = first_party_advisory.IngestCache()
        python = self._mark(PY_MEMBER, cache=cache)
        cargo = _raw_advisory_finding()
        first_party_advisory.mark([cargo], self.root, cache)
        self.assertEqual("first_party", python["tool_evidence"]["package_origin"])
        self.assertEqual("first_party", cargo["tool_evidence"]["package_origin"])
        spent = sum(os.path.getsize(os.path.join(self.root, p)) for p in (
            "uv.lock", "pyproject.toml", "packages/lib/pyproject.toml",
            "Cargo.lock", "Cargo.toml"))
        self.assertEqual(first_party_advisory.MAX_CARGO_MANIFEST_INGEST_BYTES - spent,
                         cache.manifest_bytes_remaining)
        # A second finding against the same lock reuses its origins.
        self.assertEqual("first_party", self._origin(PY_ROOT, cache=cache))
        self.assertEqual(first_party_advisory.MAX_CARGO_MANIFEST_INGEST_BYTES - spent,
                         cache.manifest_bytes_remaining)


def _cargo_audit_document():
    return {"vulnerabilities": {"list": [{
        "advisory": {"id": "RUSTSEC-2099-0001", "title": "affected", "cvss": None},
        "package": {"name": WORKSPACE_NAME, "version": WORKSPACE_VERSION},
        "versions": {}}]}}


class TestFirstPartyAdvisoryStability(unittest.TestCase):
    """#3649: on identical tool output, a first-party advisory's presence and status
    may not depend on which tools reported, their order, or what an agent claimed at
    the same locus. Trivy reports each package at its own Cargo.lock line, so its
    advisory can sit alone at a locus; an agent finding there made an exactly-two
    tool+agent pair, and `dedupe` kept the MORE SEVERE member -- the agent's claim,
    when it was more severe -- so the advisory either vanished or was queued to the
    advisor as `needs_more_info`. Every queued finding gets NEEDS_MORE_INFO here, as
    an advisor that cannot confirm would give it."""

    TRIVY_LINE = 3

    def _tools(self):
        trivy = _trivy_document()
        trivy["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"][
            "startLine"] = self.TRIVY_LINE
        return {"cargo-audit.json": _cargo_audit_document(),
                "osv-scanner.json": _osv_document(), "trivy.sarif": trivy}

    @staticmethod
    def _agent(line, severity, category="dependency_vulnerability"):
        return {"id": "AG-1", "title": "workspace-app is pinned in the lock",
                "severity": severity, "confidence": "LIKELY", "panel": "security",
                "category": category, "description": "an agent's own claim",
                "location": {"file": "Cargo.lock", "line_start": line}}

    def _ingest(self, names):
        root = tempfile.TemporaryDirectory()
        self.addCleanup(root.cleanup)
        _write_lock(root.name)
        _write_manifest(root.name)
        tools = os.path.join(root.name, "tools")
        os.mkdir(tools)
        documents = self._tools()
        for name in names:
            with open(os.path.join(tools, name), "w", encoding="utf-8") as fh:
                json.dump(documents[name], fh)
        return ingest_tools.ingest_dir(tools, "g1", target_root=root.name)

    @staticmethod
    def _report(findings):
        return {(f.get("source"), evidence.tool_rule_id(f)): f["evidence"]["status"]
                for f in TestFirstPartyAdvisoryStability._report_findings(findings)
                if evidence.is_tool_sourced(f)
                and evidence.tool_rule_id(f) != "RUSTSEC-2099-0002"}

    @staticmethod
    def _report_findings(findings):
        prepared, _ = corroborate.prepare_for_queue([dict(f) for f in findings])
        entries, _cut = evidence.build_verify_queue(prepared)
        verdicts = {entry["queue_id"]: {"finding_id": entry["finding"]["id"],
                                        "verdict": "NEEDS_MORE_INFO",
                                        "reasoning": "cannot confirm"}
                    for entry in entries}
        report = report_mod.build_report(report_mod.ReportInputs(
            run=report_mod.RunConfig(target="project", fail_on="high",
                                     timestamp="2026-11-14T00:00:00Z"),
            findings=findings_mod.FindingSet(findings=[dict(f) for f in findings],
                                             verdicts=verdicts, verdicts_supplied=True)))
        return report["findings"]

    def test_status_never_depends_on_an_agent_claim_or_the_tool_subset(self):
        names = sorted(self._tools())
        for r in range(1, len(names) + 1):
            for subset in itertools.combinations(names, r):
                base = self._ingest(subset)
                expected = self._report(base)
                self.assertTrue(expected)
                self.assertEqual({"tool_confirmed"}, set(expected.values()), subset)
                for line in (1, self.TRIVY_LINE):
                    for severity in ("CRITICAL", "LOW"):
                        for category in ("dependency_vulnerability", "configuration"):
                            agent = self._agent(line, severity, category)
                            with self.subTest(tools=subset, line=line, severity=severity,
                                              category=category):
                                self.assertEqual(expected, self._report(base + [agent]))
                                self.assertEqual(expected,
                                                 self._report([agent] + base[::-1]))

    def test_the_agent_claim_survives_beside_the_advisory_as_its_own_claim(self):
        # cargo-audit's category is the agent's, so the pair corroborates; Trivy's
        # legacy-SARIF category is its rule id, so it does not -- both keep both.
        for tool, line, reinforced in (("cargo-audit.json", 1, True),
                                       ("trivy.sarif", self.TRIVY_LINE, False)):
            with self.subTest(tool=tool):
                base = self._ingest([tool])
                agent = self._agent(line, "CRITICAL")
                prepared, _ = corroborate.prepare_for_queue(
                    [dict(f) for f in base + [agent]])
                self.assertEqual(2, len(prepared))
                advisory = next(f for f in prepared if evidence.is_tool_sourced(f))
                self.assertTrue(evidence.is_first_party_advisory(advisory))
                self.assertEqual(reinforced, bool(advisory.get("reinforced")))
                entries, _ = evidence.build_verify_queue(prepared)
                self.assertEqual(["AG-1"], [e["finding"]["id"] for e in entries])

    def test_a_cross_tool_duplicate_keeps_the_most_severe_then_the_source(self):
        # osv-scanner (CRITICAL) and cargo-audit (LOW, no CVSS) report one advisory on one
        # package at Cargo.lock:1: the most severe survives, in either input order.
        base = [f for f in self._ingest(["cargo-audit.json", "osv-scanner.json"])
                if evidence.tool_rule_id(f) == "RUSTSEC-2099-0001"]
        for members in (base, base[::-1]):
            out = findings_mod.aggregate_tool_findings([dict(f) for f in members])
            self.assertEqual([("tool:osv-scanner", "CRITICAL", 2)],
                             [(f["source"], f["severity"], f["occurrences"]) for f in out])
        # Equal severity: the source decides, not the order.
        same = [dict(f, severity="CRITICAL") for f in base]
        for members in (same, same[::-1]):
            out = findings_mod.aggregate_tool_findings([dict(f) for f in members])
            self.assertEqual(["tool:cargo-audit"], [f["source"] for f in out])

    def test_the_more_severe_duplicate_gates_by_owner_ruling(self):
        # #3655 owner ruling: severity wins among same-locus duplicates, even when that
        # turns a gate from PASS to FAIL. osv CRITICAL + cargo-audit LOW at Cargo.lock:1
        # with --fail-on high now FAILs in either input order; cargo-audit alone PASSes.
        def gate(findings):
            report = report_mod.build_report(report_mod.ReportInputs(
                run=report_mod.RunConfig(target="project", fail_on="high",
                                         timestamp="2026-11-14T00:00:00Z"),
                findings=findings_mod.FindingSet(findings=[dict(f) for f in findings])))
            return report["summary"]["gate"]
        both = [f for f in self._ingest(["cargo-audit.json", "osv-scanner.json"])
                if evidence.tool_rule_id(f) == "RUSTSEC-2099-0001"]
        self.assertEqual({"CRITICAL", "LOW"}, {f["severity"] for f in both})
        self.assertEqual("FAIL", gate(both))
        self.assertEqual("FAIL", gate(both[::-1]))
        self.assertEqual("PASS", gate([f for f in both if f["severity"] == "LOW"]))

    def test_the_lowest_line_is_shown_and_the_worst_hit_gives_the_severity(self):
        # Which hit is SHOWN is decided by the LOWEST LINE, then severity (#3731: no
        # longer by a locus an agent flagged): the LOW at line 1, in either input order. Its severity is the
        # group's worst (#3732): it read LOW, and the CRITICAL at line 5 was only an
        # additional locus. `severity_from` names the hit that gave it.
        base = [f for f in self._ingest(["cargo-audit.json", "osv-scanner.json"])
                if evidence.tool_rule_id(f) == "RUSTSEC-2099-0001"]
        low, critical = sorted(base, key=lambda f: f["severity"] != "LOW")
        self.assertEqual(("LOW", "CRITICAL"), (low["severity"], critical["severity"]))
        critical = dict(critical, location={"file": "Cargo.lock", "line_start": 5})
        for members in ([low, critical], [critical, low]):
            out = findings_mod.aggregate_tool_findings(copy.deepcopy(members))
            self.assertEqual([("CRITICAL", 1, low["source"])],
                             [(f["severity"], f["location"]["line_start"], f["source"])
                              for f in out])
            self.assertEqual({"file": "Cargo.lock", "line_start": 5,
                              "shown_hit_severity": "LOW"}, out[0]["severity_from"])

    def test_a_full_tie_is_broken_by_the_reported_version_then_the_title(self):
        # Every member of a group shares one fingerprint, so only content left over --
        # the version, then the title -- separates two copies at one locus.
        osv = [f for f in self._ingest(["osv-scanner.json"])
               if evidence.tool_rule_id(f) == "RUSTSEC-2099-0002"][0]
        older = dict(osv, tool_evidence=dict(osv["tool_evidence"], vulnerable_versions="0.8.0"),
                     title="z")
        newer = dict(osv, tool_evidence=dict(osv["tool_evidence"], vulnerable_versions="0.9.0"),
                     title="a")
        retitled = dict(older, title="a")
        for pair, expected in (([older, newer], ("0.8.0", "z")),
                               ([older, retitled], ("0.8.0", "a"))):
            for members in (pair, pair[::-1]):
                out = findings_mod.aggregate_tool_findings([dict(f) for f in members])
                self.assertEqual([expected], [(f["tool_evidence"]["vulnerable_versions"],
                                               f["title"]) for f in out])

    def test_an_ordinary_tool_agent_pair_still_collapses(self):
        # The exemption is the first-party mark and nothing else: a registry advisory
        # alone at a locus with one agent finding still collapses to one survivor.
        base = [f for f in self._ingest(["osv-scanner.json"])
                if not evidence.is_first_party_advisory(f)]
        for f in base:
            f["location"] = {"file": "Cargo.lock", "line_start": 9}
        prepared, _ = corroborate.prepare_for_queue(
            [dict(f) for f in base + [self._agent(9, "CRITICAL")]])
        self.assertEqual(1, len(prepared))


class TestFirstPartyAdvisoryBesideARegistryCopy(unittest.TestCase):
    """#3655 review: a lock holding the project's own `workspace-app 1.2.3` AND a registry
    `workspace-app 0.9.0` names one package twice. Grouped by name alone, the two copies
    of one advisory merged and one was dropped -- by input order (F1) or by an agent's
    line (F2) -- so the first-party advisory's status depended on both."""

    REGISTRY_COPY = "0.9.0"
    COPY_LINE = 9

    def _root(self):
        root = tempfile.TemporaryDirectory()
        self.addCleanup(root.cleanup)
        _write_lock(root.name)
        with open(os.path.join(root.name, "Cargo.lock"), "a", encoding="utf-8") as fh:
            fh.write('\n[[package]]\nname = "%s"\nversion = "%s"\n'
                     'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
                     % (WORKSPACE_NAME, self.REGISTRY_COPY))
        _write_manifest(root.name)
        return root.name

    def _ingest(self, filename, document):
        return _ingest_document(self._root(), filename, document)

    @staticmethod
    def _statuses(findings):
        tool = [f for f in TestFirstPartyAdvisoryStability._report_findings(findings)
                if evidence.is_tool_sourced(f)
                and evidence.tool_rule_id(f) != "RUSTSEC-2099-0002"]
        return sorted((evidence.is_first_party_advisory(f), f["evidence"]["status"])
                      for f in tool)

    EXPECTED = [(False, "needs_more_info"), (True, "tool_confirmed")]

    def test_f1_osv_input_order_keeps_both_copies(self):
        own = _osv_package(WORKSPACE_NAME, WORKSPACE_VERSION, "RUSTSEC-2099-0001")
        copy = _osv_package(WORKSPACE_NAME, self.REGISTRY_COPY, "RUSTSEC-2099-0001")
        for packages in ([own, copy], [copy, own]):
            with self.subTest(first=packages[0]["package"]["version"]):
                document = {"results": [{"source": {"path": "/src/Cargo.lock"},
                                         "packages": packages}]}
                findings = self._ingest("osv-scanner.json", document)
                self.assertEqual(self.EXPECTED, self._statuses(findings))
                self.assertEqual(self.EXPECTED, self._statuses(findings[::-1]))

    def test_f2_an_agent_line_cannot_pick_the_registry_copy(self):
        trivy = _trivy_document()
        result = trivy["runs"][0]["results"][0]
        result["locations"][0]["physicalLocation"]["region"]["startLine"] = 3
        copy = json.loads(json.dumps(result))
        copy["message"]["text"] = copy["message"]["text"].replace(
            WORKSPACE_VERSION, self.REGISTRY_COPY)
        copy["locations"][0]["physicalLocation"]["region"]["startLine"] = self.COPY_LINE
        trivy["runs"][0]["results"].append(copy)
        findings = self._ingest("trivy.sarif", trivy)
        self.assertEqual(self.EXPECTED, self._statuses(findings))
        for severity in ("LOW", "CRITICAL"):
            for category in ("configuration", "dependency_vulnerability"):
                agent = TestFirstPartyAdvisoryStability._agent(self.COPY_LINE, severity,
                                                               category)
                with self.subTest(severity=severity, category=category):
                    self.assertEqual(self.EXPECTED, self._statuses(findings + [agent]))
                    self.assertEqual(self.EXPECTED,
                                     self._statuses([agent] + findings[::-1]))


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

    def test_the_confirmation_names_the_ecosystem_that_matched(self):
        # #3692 review item 6: it said "Cargo member" whatever the lock was.
        for lock, form in (("Cargo.lock", "Cargo member"),
                           ("crates/app/Cargo.lock", "Cargo member"),
                           ("package-lock.json", "npm workspace package"),
                           ("npm-shrinkwrap.json", "npm workspace package"),
                           ("uv.lock", "Python workspace package"),
                           ("poetry.lock", "Python workspace package"),
                           ("pdm.lock", "Python workspace package"),
                           ("Gemfile.lock", "Ruby path gem"),
                           ("some.lock", "package"), (None, "package"), (7, "package")):
            with self.subTest(lock=lock):
                finding = self._finding("OS-001", "first_party")
                finding["location"] = {"file": lock, "line_start": 1}
                self.assertEqual(form, evidence.first_party_package_form(finding))
                reasoning = evidence.derive_evidence(finding)["reasoning"]
                self.assertEqual("Advisory database matched the exact name and version of "
                                 "this project's in-tree publishable %s." % form, reasoning)
        finding = self._finding("OS-001", "first_party")
        del finding["location"]
        self.assertEqual("package", evidence.first_party_package_form(finding))

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
