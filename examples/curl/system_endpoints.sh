#!/usr/bin/env bash
# Hit all Milestone-1 system endpoints of a running WhatsCore instance.
# Usage: ./examples/curl/system_endpoints.sh [BASE_URL]
set -euo pipefail

BASE_URL="${1:-http://localhost:8080}"

for endpoint in health ready version; do
    printf '\n=== GET %s/%s ===\n' "$BASE_URL" "$endpoint"
    curl -fsS "$BASE_URL/$endpoint"
    echo
done
