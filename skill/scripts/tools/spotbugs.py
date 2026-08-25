"""SpotBugs + FindSecBugs adapter for Java/Kotlin security findings."""
from __future__ import annotations
import os

try:
    import defusedxml.ElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET  # nosec B405

from .base import as_list, make_finding, omit_none, run_tool

_SPOTBUGS_CWE = {
    "SQL_NONCONSTANT_STRING_PASSED_TO_EXECUTE": "CWE-89",
    "SQL_PREPARED_STATEMENT_GENERATED_FROM_NONCONSTANT_STRING": "CWE-89",
    "COMMAND_INJECTION": "CWE-78",
    "PATH_TRAVERSAL_IN": "CWE-22",
    "WEAK_TRUST_MANAGER": "CWE-295",
    "WEAK_HOSTNAME_VERIFIER": "CWE-295",
    "HARDCODED_KEY": "CWE-798",
}

_PRIORITY_TO_SEVERITY = {
    "1": "HIGH",    # SpotBugs high priority / confidence
    "2": "MEDIUM",  # SpotBugs normal priority
    "3": "LOW",     # SpotBugs low priority
}


class SpotBugsAdapter:
    name = "spotbugs"
    prefix = "SB"
    DROP_IF_NO_LOCATION = False

    @staticmethod
    def _classes_dir(target: str):
        for rel in (("target", "classes"), ("build", "classes")):
            d = os.path.join(target, *rel)
            if os.path.isdir(d):
                return d
        return None

    def is_applicable(self, target: str) -> bool:
        # #run7 COD-C2A: SpotBugs/FindSecBugs analyzes JVM BYTECODE (.class), not
        # source. A build-manifest repo with no compiled output (the common
        # read-only static-analysis case) was marked applicable, then invoke ran
        # against a dir with zero .class files -> empty XML / "selected but
        # unproduced". Require a manifest AND a compiled classes dir. (Without a
        # build step Java coverage is impossible; gating applicability is the
        # honest fix rather than pretending to cover un-built repos.)
        markers = ["pom.xml", "build.gradle", "build.gradle.kts"]
        has_manifest = any(os.path.exists(os.path.join(target, m)) for m in markers)
        return has_manifest and self._classes_dir(target) is not None

    def invoke(self, target: str) -> tuple[bytes, int]:
        classes = self._classes_dir(target) or target
        spotbugs_home = os.environ.get("SPOTBUGS_HOME", "/opt/spotbugs")
        plugin_jar = os.path.join(spotbugs_home, "plugin", "findsecbugs-plugin.jar")
        cmd = [
            os.path.join(spotbugs_home, "bin", "spotbugs"),
            "-textui", "-xml", "-pluginList", plugin_jar,
            classes,
        ]
        return run_tool(cmd, timeout=600)

    def parse(self, raw: bytes, group: str) -> list[dict]:
        text = raw.decode("utf-8", errors="replace").strip()
        if not text:
            return []
        root = ET.fromstring(text)  # nosec B314
        out = []
        n = 1
        for bug in root.findall("BugInstance"):
            btype = bug.get("type", "")
            priority = bug.get("priority", "3")
            severity = _PRIORITY_TO_SEVERITY.get(priority, "MEDIUM")
            source = bug.find(".//SourceLine")
            sourcepath = source.get("sourcepath", "") if source is not None else ""
            if sourcepath:
                file_path = sourcepath
                line = source.get("start")
            else:
                # #run7 COD-C3A: no <SourceLine> -> derive the file from the
                # BugInstance's <Class classname> (com.example.App ->
                # com/example/App.java) so a real finding stays matchable by the
                # delta/--pr gate instead of carrying an empty, unscopable
                # location.file. (We KEEP the finding -- #1196 -- unlike the
                # SCS/#476 drop policy, which discarded compiler-diagnostic noise.)
                cls = bug.find(".//Class")
                classname = cls.get("classname", "") if cls is not None else ""
                file_path = (classname.replace(".", "/") + ".java") if classname else ""
                line = 1
            cwe = _SPOTBUGS_CWE.get(btype)
            out.append(make_finding(
                self, n, group,
                title=f"{btype}",
                severity=severity,
                confidence="LIKELY",
                category="jvm_security",
                location={"file": file_path, "line_start": int(line) if line else 1},
                description=f"SpotBugs/FindSecBugs detected issue type {btype}.",
                impact="Potential security flaw in JVM bytecode.",
                remediation="Review the FindSecBugs documentation for this bug type and refactor.",
                citations={"cwe": as_list(cwe)},
                tool_evidence=omit_none({"rule_id": btype}),
            ))
            n += 1
        return out
