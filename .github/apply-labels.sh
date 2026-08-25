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

CATALOG="${CATALOG:-$(dirname "$0")/labels.yml}"
[[ -f "$CATALOG" ]] || { echo "label catalog not found: $CATALOG" >&2; exit 1; }
command -v gh >/dev/null || { echo "gh CLI not found" >&2; exit 1; }

# Preflight: writing labels needs push access, and GitHub answers 404 — not
# 403 — for writes on a repo you cannot push to. Without this check that
# surfaces as `HTTP 404 ... /labels/severity:critical` for a label that
# plainly exists, which reads like a catalog bug rather than wrong-account.
# This project routinely switches gh identities, so check once and say which
# account is actually in use.
if [[ "$DRY_RUN" == "0" ]]; then
  if ! who="$(gh api user --jq .login 2>&1)"; then
    echo "apply-labels: unable to determine authenticated user: $who" >&2
    echo "  For this project: export GH_CONFIG_DIR=\"\$HOME/.config/gh-psyberone\"" >&2
    exit 1
  fi

  if ! slug="$(gh repo view --json nameWithOwner --jq .nameWithOwner 2>&1)"; then
    echo "apply-labels: cannot resolve the repository from this directory: $slug" >&2
    exit 1
  fi

  # No backslashes: inside $(...) already in double quotes, \" would pass a
  # literal quote character to gh, making the path "repos/owner/name" — which
  # 404s for every account, including one with admin.
  if ! can_push="$(gh api "repos/$slug" --jq '.permissions.push' 2>&1)"; then
    echo "apply-labels: cannot check push permissions for $slug: $can_push" >&2
    exit 1
  fi
  if [[ "$can_push" != "true" ]]; then
    echo "apply-labels: authenticated as '$who', which cannot push to $slug." >&2
    echo "  Label writes would fail as a misleading HTTP 404." >&2
    echo "  Fix: export GH_CONFIG_DIR=\"\$HOME/.config/gh-psyberone\"" >&2
    exit 1
  fi
fi

# Parse the constrained catalog shape (name/color/description triples) with
# PyYAML, which is already a runtime dependency declared in pyproject.toml.
python3 -c 'import yaml' >/dev/null 2>&1 || {
  echo "apply-labels: PyYAML is required but not installed" >&2
  exit 1
}
python3 - "$CATALOG" <<'PY' | while IFS=$'\t' read -r name color desc; do
import sys
import yaml
with open(sys.argv[1], encoding="utf-8") as fh:
    labels = yaml.safe_load(fh)
# The catalog may be either a flat list or a dict of category -> list.
if isinstance(labels, list):
    entries = labels
else:
    entries = [entry for category in labels.values() for entry in category]
for entry in entries:
    description = entry.get("description", "").replace("\n", " ").strip()
    print("\t".join([
        entry["name"],
        entry.get("color", "ededed"),
        description,
    ]))
PY
  if [[ "$DRY_RUN" == "1" ]]; then
    echo "would apply: $name ($color) — $desc"
    continue
  fi
  # Only "already exists" may fall through to an edit. Swallowing every
  # create error here is what turned a wrong-account run into a 404 about a
  # label that exists.
  if err="$(gh label create "$name" --color "$color" --description "$desc" 2>&1)"; then
    echo "created: $name"
  elif [[ "$err" == *"already exists"* ]]; then
    if ! err="$(gh label edit "$name" --color "$color" --description "$desc" 2>&1)"; then
      echo "apply-labels: cannot update '$name': $err" >&2
      exit 1
    fi
    echo "updated: $name"
  else
    echo "apply-labels: cannot create '$name': $err" >&2
    exit 1
  fi
done
