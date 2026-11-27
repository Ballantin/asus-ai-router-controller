#!/usr/bin/env python3
"""Positive and negative gate controls, using synthetic scanner reports."""
import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "gate", Path(__file__).resolve().parents[1] / "ci/check-scan-report.py")
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


def check(kind, data, rc, count):
    blocked, _ = gate.evaluate(kind, data, rc)
    if len(blocked) != count:
        raise AssertionError((kind, blocked, count))


def invalid(kind, data, rc):
    try:
        gate.evaluate(kind, data, rc)
    except (ValueError, KeyError, TypeError):
        return
    raise AssertionError(f"invalid report accepted: {kind}")


def bandit(level):
    return {"errors": [], "metrics": {"_totals": {"loc": 1}},
            "results": [{"issue_severity": level, "test_id": "B000", "filename": "test.py"}]}


def image(level):
    return {"SchemaVersion": 2, "Metadata": {"OS": {"Family": "alpine"}},
            "Results": [{"Class": "os-pkgs", "Target": "alpine",
                         "Vulnerabilities": [{"Severity": level, "VulnerabilityID": "CVE-test"}]}]}


def config(code, level, target="Dockerfile"):
    return {"SchemaVersion": 2, "Results": [
        {"Target": "Dockerfile", "Type": "dockerfile", "Misconfigurations": []},
        {"Target": target, "Type": "dockerfile", "Misconfigurations": [
            {"ID": code, "Severity": level, "Status": "FAIL"}]}]}


check("bandit", bandit("LOW"), 1, 0)
check("bandit", bandit("MEDIUM"), 1, 1)
check("bandit", bandit("HIGH"), 1, 1)
invalid("bandit", bandit("LOW"), 2)
invalid("bandit", bandit("LOW"), 0)
invalid("bandit", {"results": [], "errors": ["failure"]}, 1)
for level in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
    check("trivy-image", image(level), 10, int(level in ("HIGH", "CRITICAL")))
invalid("trivy-image", image("HIGH"), 0)
invalid("trivy-image", image("HIGH"), 1)
invalid("trivy-image", {"SchemaVersion": 2, "Results": []}, 0)
check("trivy-config", config("DS-0002", "HIGH"), 10, 0)
check("trivy-config", config("DS-0002", "HIGH", "other/Dockerfile"), 10, 1)
check("trivy-config", config("DS-0002", "CRITICAL"), 10, 1)
check("trivy-config", config("DS-9999", "HIGH"), 10, 1)
check("trivy-config", config("DS-0026", "LOW"), 10, 0)
check("hadolint", [{"code": "DL3018", "line": 2, "level": "warning"}], 1, 0)
check("hadolint", [{"code": "DL3018", "line": 3, "level": "warning"}], 1, 1)
check("hadolint", [{"code": "DL9999", "line": 2, "level": "warning"}], 1, 1)
invalid("hadolint", [], 1)
print("Structured scanner gate controls passed")
