#!/usr/bin/env bash
# Distinguish actual structured findings from Semgrep startup/scan errors.
set -euo pipefail
mkdir -p scan-reports
report=scan-reports/semgrep.json
sarif=scan-reports/semgrep.sarif
rm -f "$report" "$sarif"
rc=0
"$1" scan --metrics=off --strict --error --json --output "$report" --sarif-output "$sarif" \
    --config p/security-audit --config ci/semgrep.yml router docker tests || rc=$?
python3 - "$report" "$rc" "$sarif" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
rc = int(sys.argv[2])
if not path.is_file():
    sys.exit("Semgrep produced no report: scanner execution failed")
data = json.loads(path.read_text())
results = data.get("results")
errors = data.get("errors")
scanned = data.get("paths", {}).get("scanned")
if not isinstance(results, list) or not isinstance(errors, list) or not scanned:
    sys.exit("Semgrep report incomplete or no files scanned")
if errors:
    print(json.dumps(errors, indent=2))
    sys.exit("Semgrep reported scan errors")
if rc not in (0, 1) or (rc == 1) != bool(results):
    sys.exit(f"Semgrep exit status {rc} inconsistent with report")
sarif = json.loads(Path(sys.argv[3]).read_text())
runs = sarif.get("runs")
if sarif.get("version") != "2.1.0" or not isinstance(runs, list) or not runs:
    sys.exit("Missing or invalid SARIF output")
if any(not isinstance(run.get("results"), list) for run in runs):
    sys.exit("Invalid SARIF results")
if sum(len(run["results"]) for run in runs) != len(results):
    sys.exit("SARIF and JSON finding counts differ")
print(f"Semgrep scanned {len(scanned)} files; {len(results)} findings")
for result in results:
    print(json.dumps(result))
sys.exit(10 if results else 0)
PY
