#!/usr/bin/env python3
"""Local router safety policy: deterministic lexical checks, not a shell parser."""

import argparse
import json
import re
import sys
from pathlib import Path

# Preserve the three existing local Semgrep patterns and their scope.
# These are deliberately conservative heuristics; mock transaction tests
# and ShellCheck provide independent safeguards.
RULES = {
    "router-no-eval": (
        "Do not introduce shell eval into privileged router code.",
        r"(?m)^[ \t]*(?:[^#\n;]*[;|][ \t]*)?eval(?:[ \t]|$)",
    ),
    "router-no-global-conntrack-flush": (
        "Global conntrack flush violates the controller safety contract.",
        r"(?m)^[ \t]*(?!#)[^\n]*\bconntrack[ \t]+(?:-F|--flush)(?:[ \t]|$)",
    ),
    "router-no-unscoped-firewall-flush": (
        "Unscoped iptables flush violates the controller safety contract.",
        r"(?m)^[ \t]*(?!#)[^\n]*\biptables[ \t]+(?:-t[ \t]+[a-z]+[ \t]+)?"
        r"(?:-F|--flush)[ \t]*(?:$|[;|])",
    ),
}
REQUIRED = {"nat-controller.sh", "dnat-validate.sh", "wan-check.sh"}


def scan(root):
    router = root / "router"
    if router.is_symlink():
        raise ValueError("router directory must not be a symlink")
    paths = sorted(router.glob("*.sh"))
    if not REQUIRED.issubset({p.name for p in paths}):
        raise ValueError("required router scripts missing")
    findings = []
    scanned = []
    for path in paths:
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"not a regular router script: {path}")
        source = path.read_text(encoding="utf-8")
        if not source.strip() or "\x00" in source:
            raise ValueError(f"empty or invalid router script: {path}")
        relative = path.relative_to(root).as_posix()
        scanned.append(relative)
        for rule, (message, pattern) in RULES.items():
            for match in re.finditer(pattern, source):
                findings.append({
                    "rule": rule,
                    "path": relative,
                    "line": source.count("\n", 0, match.start()) + 1,
                    "message": message,
                })
    return {"scanned": scanned, "findings": findings, "rules": list(RULES)}


def sarif(report):
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "Router safety policy",
                "version": "1.0.0",
                "rules": [
                    {"id": rule, "shortDescription": {"text": message},
                     "defaultConfiguration": {"level": "error"}}
                    for rule, (message, _) in RULES.items()
                ],
            }},
            "results": [
                {"ruleId": finding["rule"], "level": "error",
                 "message": {"text": finding["message"]},
                 "locations": [{"physicalLocation": {
                     "artifactLocation": {"uri": finding["path"]},
                     "region": {"startLine": finding["line"]},
                 }}]}
                for finding in report["findings"]
            ],
        }],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--output-dir", type=Path, default=Path("scan-reports"))
    args = parser.parse_args()
    try:
        report = scan(args.root)
        args.output_dir.mkdir(parents=True, exist_ok=True)
        for name, data in (("router-policy.json", report),
                           ("router-policy.sarif", sarif(report))):
            (args.output_dir / name).write_text(
                json.dumps(data, indent=2) + "\n", encoding="utf-8")
    except (OSError, ValueError) as error:
        sys.exit(f"Router policy scan failed: {error}")
    for finding in report["findings"]:
        print(f'{finding["path"]}:{finding["line"]}: {finding["rule"]}')
    print(f'Router policy: {len(report["scanned"])} files, '
          f'{len(report["rules"])} rules, {len(report["findings"])} findings')
    sys.exit(10 if report["findings"] else 0)


if __name__ == "__main__":
    main()
