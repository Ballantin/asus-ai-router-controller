#!/usr/bin/env bash
# CI only: findings are advisory during baseline; unexpected exit codes fail.
set -euo pipefail
name=$1
finding_codes=$2
shift 2
mkdir -p scan-reports
set +e
"$@" 2>&1 | tee "scan-reports/$name.txt"
statuses=("${PIPESTATUS[@]}")
set -e
rc=${statuses[0]}
if [[ ${statuses[1]} != 0 ]]; then
    echo "Report capture failed for $name" >&2
    exit 1
fi
if [[ $rc == 0 ]]; then
    result="completed (exit 0; consult report)"
elif [[ ",$finding_codes," == *",$rc,"* ]]; then
    result="advisory findings (exit $rc; review report)"
else
    result="scanner error (exit $rc)"
fi
printf '%s: %s\n' "$name" "$result"
if [[ -n ${GITHUB_STEP_SUMMARY:-} ]]; then
    printf -- '- **%s:** %s\n' "$name" "$result" >> "$GITHUB_STEP_SUMMARY"
fi
if [[ $rc != 0 && ",$finding_codes," != *",$rc,"* ]]; then
    exit "$rc"
fi
