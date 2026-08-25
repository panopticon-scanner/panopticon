#!/usr/bin/env bash
set -euo pipefail
event_name="${1:-${GITHUB_EVENT_NAME:-}}"
tag="${2}"
if [[ "$event_name" != "push" ]]; then
    echo "sync=true"
    exit 0
fi
if docker manifest inspect "$tag" >/dev/null 2>&1; then
    echo "sync=false"
else
    echo "sync=true"
fi
