#!/usr/bin/env python3
"""Fail-closed gates for structured scanner reports; preserve raw evidence."""
import json
import sys
from pathlib import Path


def need(condition, message):
    if not condition:
        raise ValueError(message)


def severity(value, levels):
    need(isinstance(value, str) and value.upper() in levels, f"unknown severity {value!r}")
    return value.upper()


def evaluate(kind, data, rc):
    blocked = []
    advisory = []
    if kind == "bandit":
        need(rc in (0, 1), f"Bandit scanner exit {rc}")
        need(isinstance(data["results"], list) and data["errors"] == [], "Bandit scan errors")
        need(data["metrics"]["_totals"]["loc"] > 0, "Bandit scanned no source")
        need((rc == 1) == bool(data["results"]), "Bandit result/exit mismatch")
        for f in data["results"]:
            level = severity(f["issue_severity"], {"LOW", "MEDIUM", "HIGH"})
            (blocked if level != "LOW" else advisory).append(f"{f['test_id']} {f['filename']}")
    elif kind == "hadolint":
        need(rc in (0, 1), f"Hadolint scanner exit {rc}")
        need(isinstance(data, list), "invalid Hadolint report")
        for f in data:
            level = severity(f["level"], {"ERROR", "WARNING", "INFO", "STYLE", "IGNORE"})
            exception = f["code"] == "DL3018" and f["line"] == 2 and level == "WARNING"
            (blocked if level in ("ERROR", "WARNING") and not exception else advisory).append(
                f"{f['code']} Dockerfile:{f['line']}")
        need(rc == 0 or bool(blocked or advisory), "Hadolint nonzero without findings")
    elif kind in ("trivy-image", "trivy-config"):
        need(rc in (0, 10), f"Trivy scanner exit {rc}")
        need(data["SchemaVersion"] == 2, "invalid Trivy schema")
        results = data["Results"]
        need(isinstance(results, list) and results, "Trivy scanned no targets")
        if kind == "trivy-image":
            need(data["Metadata"]["OS"]["Family"] == "alpine", "expected Alpine OS scan")
            need(any(r.get("Class") == "os-pkgs" for r in results), "missing OS package result")
        else:
            need(any(r.get("Type") == "dockerfile" and r.get("Target") == "Dockerfile"
                     for r in results), "missing Dockerfile scan")
        count = 0
        for r in results:
            key = "Vulnerabilities" if kind == "trivy-image" else "Misconfigurations"
            for f in r.get(key) or []:
                if kind == "trivy-config" and f.get("Status") != "FAIL":
                    continue
                count += 1
                level = severity(f["Severity"], {"UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"})
                code = f["VulnerabilityID"] if kind == "trivy-image" else f["ID"]
                exception = (kind == "trivy-config" and r.get("Type") == "dockerfile"
                             and r["Target"] == "Dockerfile" and code == "DS-0002"
                             and level == "HIGH")
                (blocked if level in ("HIGH", "CRITICAL") and not exception else advisory).append(
                    f"{code} {r['Target']}")
        need((rc == 10) == bool(count), "Trivy result/exit mismatch")
    else:
        raise ValueError(f"unknown gate: {kind}")
    return blocked, advisory


def main():
    kind, filename, rc = sys.argv[1:]
    blocked, advisory = evaluate(kind, json.loads(Path(filename).read_text()), int(rc))
    for item in advisory:
        print("ADVISORY:", item)
    for item in blocked:
        print("BLOCK:", item)
    print(f"{kind}: {len(blocked)} blocking, {len(advisory)} advisory")
    sys.exit(10 if blocked else 0)


if __name__ == "__main__":
    main()
