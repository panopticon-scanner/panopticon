#!/usr/bin/env python3
"""Hold the vendored Semgrep rules to path patterns that cannot be made slow (#3762).

Semgrep matches every target file's path against each rule's `paths.include` and
`paths.exclude` with wcmatch, and the pinned wcmatch (8.5.2, which Semgrep requires)
takes polynomial time, O(n^k), to reject a crafted name against a pattern with k `*`
in it (GHSA-53pm-wgxf-c6qf). The names are the scanned target's. The patterns are
these rules', so they are the half we control: with at most two `*` in a path
component the slowest match measured was under two milliseconds, and with four it
was 1.7 seconds for one file name.

So the image build fails when a rule carries a pattern with more than two `*` in
one path component, and fails closed on anything it cannot read as Semgrep reads it:
a rule file that does not parse, or a `paths` value that is not the shape Semgrep
expects. Semgrep reads `paths` at the top level of a rule and nowhere else
(`semgrep/rule.py`: `self._raw.get("paths", {})`, then `include` and `exclude`).
"""

import argparse
import os
from pathlib import Path

import yaml


ISSUE = "#3762"
MAX_STARS = 2
SUFFIXES = (".yml", ".yaml")


class RulePathError(RuntimeError):
    pass


def stars_per_component(pattern):
    """The number of `*` in each `/`-separated component of `pattern`. `**` is two."""
    return [component.count("*") for component in pattern.split("/")]


def _patterns(paths, where):
    """Every include and exclude pattern of one rule's `paths` value."""
    if paths is None:
        return []
    if not isinstance(paths, dict):
        raise RulePathError("%s: `paths` is %s, not a mapping (%s)"
                            % (where, type(paths).__name__, ISSUE))
    found = []
    for key in ("include", "exclude"):
        entries = paths.get(key)
        if entries is None:
            continue
        if not isinstance(entries, list):
            raise RulePathError("%s: `paths.%s` is %s, not a list (%s)"
                                % (where, key, type(entries).__name__, ISSUE))
        for entry in entries:
            if not isinstance(entry, str):
                raise RulePathError("%s: a `paths.%s` entry is %s, not a string (%s)"
                                    % (where, key, type(entry).__name__, ISSUE))
            found.append((key, entry))
    return found


def check_file(path, shown):
    """The (rule id, key, pattern) triples of one rule file; raises on what it cannot
    read and on a pattern over the limit."""
    try:
        with open(path, encoding="utf-8") as handle:
            document = yaml.safe_load(handle)
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise RulePathError("%s: cannot be read as a rule file: %s (%s)"
                            % (shown, " ".join(str(exc).split())[:200], ISSUE)) from exc
    if not isinstance(document, dict) or not isinstance(document.get("rules"), list):
        raise RulePathError("%s: has no `rules` list (%s)" % (shown, ISSUE))
    seen = []
    for index, rule in enumerate(document["rules"]):
        if not isinstance(rule, dict):
            raise RulePathError("%s: rule %d is %s, not a mapping (%s)"
                                % (shown, index, type(rule).__name__, ISSUE))
        rule_id = rule.get("id")
        where = "%s: rule %r" % (shown, rule_id if isinstance(rule_id, str) else index)
        for key, pattern in _patterns(rule.get("paths"), where):
            worst = max(stars_per_component(pattern))
            if worst > MAX_STARS:
                raise RulePathError(
                    "%s: `paths.%s` pattern %r has %d `*` in one path component; the "
                    "limit is %d, because Semgrep matches target file names against it "
                    "with a matcher that is polynomial in that number (%s)"
                    % (where, key, pattern, worst, MAX_STARS, ISSUE))
            seen.append((rule_id, key, pattern))
    return seen


def check_tree(rules_root):
    """Check every rule file under `rules_root`; returns (files, patterns) counted."""
    rules_root = Path(rules_root)
    if not rules_root.is_dir():
        raise RulePathError("%s: not a directory (%s)" % (rules_root, ISSUE))
    files = patterns = 0
    for folder, directories, names in os.walk(rules_root):
        directories.sort()
        for name in sorted(names):
            if not name.endswith(SUFFIXES):
                continue
            path = Path(folder) / name
            patterns += len(check_file(path, str(path.relative_to(rules_root))))
            files += 1
    if not files:
        raise RulePathError("%s: holds no rule file (%s)" % (rules_root, ISSUE))
    return files, patterns


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--rules-root", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        files, patterns = check_tree(args.rules_root)
    except RulePathError as exc:
        parser.exit(1, "semgrep rule path check failed: %s\n" % exc)
    print("semgrep rule path check: %d rule file(s), %d path pattern(s), none with more "
          "than %d `*` in one path component" % (files, patterns, MAX_STARS))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
