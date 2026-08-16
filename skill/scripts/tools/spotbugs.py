"""SpotBugs + FindSecBugs adapter for Java/Kotlin security findings."""
from __future__ import annotations
import os
import xml.etree.ElementTree as ET
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


class SpotBugsAdapter:
    name = "spotbugs"
    prefix = "SB"

    def is_applicable(self, target: str) -> bool:
        markers = ["pom.xml", "build.gradle", "build.gradle.kts"]
        return any(os.path.exists(os.path.join(target, m)) for m in markers)

    def invoke(self, target: str) -> tuple[bytes, int]:
        classes = os.path.join(target, "target", "classes")
        if not os.path.isdir(classes):
            classes = os.path.join(target, "build", "classes")
        if not os.path.isdir(classes):
            classes = target
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
        root = ET.fromstring(text)
        out = []
        n = 1
        for bug in root.findall("BugInstance"):
            btype = bug.get("type", "")
            priority = bug.get("priority", "3")
            severity = { "1": "HIGH", "2": "MEDIUM", "3": "LOW" }.get(priority, "MEDIUM")
            source = bug.find(".//SourceLine")
            file_path = source.get("sourcepath", "") if source is not None else ""
            line = source.get("start") if source is not None else 1
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
