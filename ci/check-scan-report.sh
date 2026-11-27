#!/usr/bin/env bash
# Scanner stdout must contain structured JSON. Preserve stderr and fail on errors.
set -euo pipefail
kind=$1
shift
mkdir -p scan-reports
report="scan-reports/$kind.json"
rc=0
"$@" >"$report" || rc=$?
python3 ci/check-scan-report.py "$kind" "$report" "$rc"
