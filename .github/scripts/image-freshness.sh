#!/usr/bin/env bash
# Usage: image-freshness.sh <updated_at_iso> <max_age_days> [<image_name>]
# Emits GitHub Actions annotations and exits:
#   0 ok        image is fresh
#   0 warning   updated_at is empty/missing (API failed) -- skip this run
#   1 error     image is stale or updated_at is unparseable
set -euo pipefail

updated_at="${1:-}"
max_age_days="${2:-}"
image_name="${3:-panopticon-tools}"

if [ -z "${updated_at}" ]; then
  echo "::warning::Could not determine ${image_name}:latest publish time; skipping freshness check."
  exit 0
fi

if ! built=$(python3 -c '
import datetime, sys
ts = sys.argv[1]
if ts.endswith("Z"):
    ts = ts[:-1] + "+00:00"
print(int(datetime.datetime.fromisoformat(ts).timestamp()))
' "${updated_at}" 2>/dev/null); then
  echo "::error::Invalid updated_at timestamp: ${updated_at}"
  exit 1
fi

now=$(date -u +%s)
age_days=$(( (now - built) / 86400 ))
echo "${image_name}:latest last published ${updated_at} (${age_days}d ago)"

if [ "${age_days}" -gt "${max_age_days}" ]; then
  echo "::error::${image_name}:latest is ${age_days}d old (> ${max_age_days}d): the nightly docker-publish build is failing or its schedule is disabled. Check the 'Publish panopticon-tools image' workflow."
  exit 1
fi

echo "::notice::${image_name}:latest is fresh (${age_days}d <= ${max_age_days}d)."
exit 0
