# Security policy

## Supported versions

This is an experimental, independently maintained project. Security fixes target the latest published release and active development branch where applicable. Older releases are not guaranteed backports. Consult the release notes and hardware acceptance documentation before updating. No service-level agreement or warranty is offered.

## Reporting a vulnerability

Use [GitHub private vulnerability reporting](https://github.com/Ballantin/asus-ai-router-controller/security/advisories/new). Please do not publish exploitable details, credentials, private deployment information or raw operational logs in a public issue.

Include the affected version or commit, hardware and firmware version if relevant, impact, prerequisites, minimal safe reproduction steps, and sanitized evidence. Clearly identify any suggested fix or mitigation. Do not test against systems you do not own or have explicit authorization to test.

The maintainer will review reports as availability permits, coordinate disclosure and publish fixes or mitigations when appropriate. No fixed response or remediation deadline is promised.

## Scope and limitations

Report issues in the controller, its configuration parser, scheduler, installation procedure or project CI pipeline here. ASUS firmware and third-party component vulnerabilities should also be reported to their respective maintainers. Never include real SSH keys, public address allocations, internal network details or credentials in reports.

The project uses regression tests, static analysis, dependency and container scans, secret detection and documented hardware acceptance. Passing scans do not establish absence of vulnerabilities or prove firmware safety. Follow the [installation and safety guidance](docs/installation.md) and use AUDIT before enforcement. Production deployment remains an administrator decision.
