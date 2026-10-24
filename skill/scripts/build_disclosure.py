"""Human disclosures for the adapter that executes the target's build.

roslyn-secguard builds the reviewed repository (its MSBuild and analyzer code),
so it is opt-in and off by default (#3265, owner ruling 2026-10-23), and when
it does run it builds ONE solution or project (#3248). The report's Markdown
and HTML views say both the same way; this module owns the sentences, so
neither view carries a second copy. Every sentence is a constant with the
adapter's name and a count in it -- nothing else from the target.
"""

NOT_RUN = ("%s not run: it executes the target's build; pass "
           "--allow-target-build to enable.")


def not_run_lines(coverage):
    """One line per name in `meta.coverage.target_build_not_run`, sorted; [] on
    anything else. `synth.tool_axis` has already repaired the list to the
    adapters this build knows execute a target build."""
    names = coverage.get("target_build_not_run") if isinstance(coverage, dict) else None
    if not isinstance(names, list):
        return []
    return [NOT_RUN % name for name in sorted({n for n in names if isinstance(n, str) and n})]


def partial_audit_line(name, count):
    """The coverage-line sentence for a `meta.tools.sanitized` row (#1646).

    pip-audit's dropped rows are requirement lines; roslyn-secguard's are the
    projects its one build did not reach (#3248), so the sentence names them as
    such rather than as requirements."""
    if name == "roslyn-secguard":
        return ("%s: %d project%s not analysed (outside the one solution or "
                "project it builds)" % (name, count, "" if count == 1 else "s"))
    return "%s: %d requirement lines not audited (editable/local/VCS)" % (name, count)
