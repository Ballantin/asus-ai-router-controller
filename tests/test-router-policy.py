#!/usr/bin/env python3
"""Inert lexical fixtures; never execute fixture shell commands."""

import importlib.util
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("policy", ROOT / "ci/router-policy.py")
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)

# Expected results are independently specified, not derived from regexes.
CASES = [
    ("eval \"$value\"", "router-no-eval"),
    ("  eval \"$value\"", "router-no-eval"),
    ("true; eval \"$value\"", "router-no-eval"),
    ("true | eval \"$value\"", "router-no-eval"),
    ("conntrack -F", "router-no-global-conntrack-flush"),
    ("conntrack --flush", "router-no-global-conntrack-flush"),
    ("iptables -F", "router-no-unscoped-firewall-flush"),
    ("iptables -t nat --flush", "router-no-unscoped-firewall-flush"),
    ("iptables --flush; true", "router-no-unscoped-firewall-flush"),
    ("# eval \"$value\"", None),
    ("#conntrack -F", None),
    ("#iptables -F", None),
    ("iptables -t nat -F AI_NAT_SNAT", None),
    ("iptables --flush AI_NAT_DNAT", None),
    ("conntrack -L", None),
    ("iptables -t nat -S", None),
]


def check(condition, message):
    if not condition:
        raise AssertionError(message)


def pairs(report):
    return {(f["rule"], f["line"]) for f in report["findings"]}


def run():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "router").mkdir()
        (root / "ci").mkdir()
        for name in policy.REQUIRED:
            (root / "router" / name).write_text("#!/bin/sh\n", encoding="utf-8")
        fixture = root / "router/fixture.sh"
        fixture.write_text("\n".join(line for line, _ in CASES) + "\n", encoding="utf-8")
        expected = {(rule, line) for line, (_, rule) in enumerate(CASES, 1) if rule}
        report = policy.scan(root)
        check(pairs(report) == expected, f"Unexpected policy findings: {pairs(report)}")
        check(len(report["scanned"]) == 4, "incomplete script coverage")
        results = policy.sarif(report)["runs"][0]["results"]
        check({(r["ruleId"], r["locations"][0]["physicalLocation"]["region"]["startLine"])
               for r in results} == expected, "SARIF findings mismatch")

        # During migration only: compare the exact old custom rules with the
        # same inert fixtures, including rejected and allowed commands.
        if len(sys.argv) == 2:
            # Explicitly anchor the legacy rule paths to the isolated scan root.
            # Preserve the regexes and scope; only remove targeting ambiguity.
            config = (ROOT / "ci/semgrep.yml").read_text(encoding="utf-8")
            (root / "ci/semgrep.yml").write_text(
                config.replace("router/*.sh", "/router/*.sh"), encoding="utf-8")
            executable = str(Path(sys.argv[1]).resolve())
            legacy = subprocess.run(
                [executable, "scan", "--metrics=off", "--strict", "--error",
                 "--no-git-ignore", "--project-root", str(root),
                 "--json", "--output", "legacy.json",
                 "--config", "ci/semgrep.yml", "router/fixture.sh"],
                cwd=root, check=False, capture_output=True, text=True)
            check(legacy.returncode == 1,
                  f"Legacy scanner exit {legacy.returncode}: {legacy.stderr}")
            data = json.loads((root / "legacy.json").read_text(encoding="utf-8"))
            check(not data["errors"], "Legacy scanner returned scan errors")
            check("router/fixture.sh" in data["paths"]["scanned"], "Legacy fixture not scanned")
            old = {(f["check_id"].rsplit(".", 1)[-1], f["start"]["line"])
                   for f in data["results"]}
            check(old == expected, f"Legacy findings differ: {old} vs {expected}")
            print(f"Legacy Semgrep parity: {len(expected)} findings, {len(CASES)} fixtures")

        fixture.unlink()
        check(not policy.scan(root)["findings"], "clean scripts rejected")
        (root / "router/nat-controller.sh").unlink()
        try:
            policy.scan(root)
        except ValueError:
            pass
        else:
            raise AssertionError("missing required source accepted")
        (root / "router/nat-controller.sh").write_bytes(b"\x00")
        try:
            policy.scan(root)
        except ValueError:
            pass
        else:
            raise AssertionError("NUL-containing source accepted")
    print(f"Router policy controls passed: {len(CASES)} command fixtures, missing/invalid source")


if __name__ == "__main__":
    run()
