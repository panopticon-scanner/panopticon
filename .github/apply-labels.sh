#!/usr/bin/env bash
# Apply .github/labels.yml to the repository's GitHub label set.
#
# Idempotent: creates labels that are missing, updates colour/description on
# labels that already exist. Never deletes labels it does not know about.
#
# Usage:  bash .github/apply-labels.sh [--dry-run]
# Auth:   uses whatever `gh` is configured; for this project that means
#         export GH_CONFIG_DIR="$HOME/.config/gh-psyberone"
set -euo pipefail

DRY_RUN=0
[[ "${1:-}" == "--dry-run" ]] && DRY_RUN=1

CATALOG="$(dirname "$0")/labels.yml"
[[ -f "$CATALOG" ]] || { echo "label catalog not found: $CATALOG" >&2; exit 1; }
command -v gh >/dev/null || { echo "gh CLI not found" >&2; exit 1; }

# Parse the constrained catalog shape (name/color/description triples) with
# stdlib python — no PyYAML dependency, matching the project's stdlib-only rule.
python3 - "$CATALOG" <<'PY' | while IFS=$'\t' read -r name color desc; do
import re, sys
text = open(sys.argv[1], encoding="utf-8").read()
entries, cur = [], {}
for line in text.splitlines():
    m = re.match(r'\s*- name:\s*"(.+)"\s*$', line)
    if m:
        if cur:
            entries.append(cur)
        cur = {"name": m.group(1)}
        continue
    m = re.match(r'\s*color:\s*"(.+)"\s*$', line)
    if m and cur:
        cur["color"] = m.group(1)
        continue
    m = re.match(r'\s*description:\s*"(.+)"\s*$', line)
    if m and cur:
        cur["description"] = m.group(1)
if cur:
    entries.append(cur)
for e in entries:
    print("\t".join([e["name"], e.get("color", "ededed"), e.get("description", "")]))
PY
  if [[ "$DRY_RUN" == "1" ]]; then
    echo "would apply: $name ($color) — $desc"
    continue
  fi
  if gh label create "$name" --color "$color" --description "$desc" 2>/dev/null; then
    echo "created: $name"
  else
    gh label edit "$name" --color "$color" --description "$desc" >/dev/null
    echo "updated: $name"
  fi
done
