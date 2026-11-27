# Security scanning and quality assurance

## Baseline phase

The Security baseline workflow is separate from existing functional regressions. Runs on development/main pushes, pull requests and manual dispatch; weekly scanning begins when the workflow is on the default branch. Findings are advisory during baseline collection. Unexpected scanner failures are errors, not evidence of a clean scan. Review every scanner output and distinguish findings, skipped inputs and operational failures; some tools share exit codes for findings and errors. GitHub job success does not mean zero vulnerabilities.

| Scanner | Scope |
| --- | --- |
| ShellCheck | POSIX production and regression shell scripts |
| Ruff | Python test quality |
| Bandit | Python test security |
| Hadolint | Dockerfile |
| Semgrep | Registry security-audit rules plus local heuristic safety rules |
| zizmor | Offline GitHub Actions security audit |
| Gitleaks | Reachable Git history; redacted logs only; no uploaded secret report |
| Trivy | Newly built ARM64 scheduler image packages, Docker configuration |
| Dependabot | Proposed GitHub Actions and Docker dependency updates; effective on default branch |

Reports are attached to workflow runs for 14 days except the secret scan. Review redacted Gitleaks logs without republishing matches. A detected secret requires containment and rotation, not merely deletion from Git.

The scanner workflow uses GitHub-hosted runners, contents-read permission, no persisted checkout credentials, no repository secrets, no deployment access, no production Docker socket and no privileged scanner containers. Action references in this workflow are full commit SHAs. Scanner tool versions are explicit but package dependencies, registry rules, distro packages and container tags are not fully immutable; record image digests and review provenance before promoting baseline to mandatory gates. Trivy 0.69.3 is explicitly selected because the upstream incident advisory identifies it as known safe (https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23); do not use latest or the affected versions. The build tests the current Dockerfile and package repositories, not the exact deployed image or ASUS firmware. Local heuristic rules are not proof of invariant enforcement, and AWK coverage remains limited.

## Follow-up

Review the first scan results before adding suppressions or mandatory gates. Add verified project-specific checks and parser fuzzing. Enable GitHub native CodeQL default setup for Python and Actions where available, secret scanning and push protection, Dependabot security alerts and updates, and branch protection after administrator review. These settings are not enabled by this branch alone. No automatic merge or dependency deployment. Docker package/firmware changes still require appropriate acceptance testing. Do not publish private operational data.

## Baseline #2 triage (2026-11-27)

Run 46009253244 at 93c9f9c; regression #29 passed. Gitleaks: no leaks in 25 reachable commits. ShellCheck: six informational findings (three compound conditions, trap callback, two literal injection fixtures). Ruff: one unused import. Bandit: 93 low, zero medium/high; 83 B101 assertions, 3 B404 subprocess imports, 3 B607 partial executable paths, 4 B603 subprocess calls without shell. Assertions intentionally enforce test expectations; CI explicitly disables Python optimization. Test subprocesses use fixed executables and controlled arguments; no production Python code. Remove partial executable paths and retain other findings as documented test-only exceptions pending targeted gate configuration. Hadolint DL3018: unpinned apk package; prefer security updates while testing, exact reproducible deployment image pinning remains a separate task. zizmor: zero reported, five suppressed; offline checks do not cover known vulnerable actions, ref confusion or impostor commits. Semgrep failed importing pkg_resources and exit 1 was incorrectly accepted; add compatible setuptools and structured report verification, no findings accepted without successful scan evidence.

Trivy image: 15 package findings (2 high, 7 medium, 6 low, zero critical), eight distinct reported CVEs: libcrypto3/libssl3 3.5.9-r0, reported fixes 3.5.9-r2; zlib 1.3.2-r1, reported fix 1.4-r0. Add apk upgrade before install and rescan; package availability must be verified by CI. CVE-2026-124709 is QUIC-related per scanner, applicability to SSH scheduler not established. Dockerfile config: DS-0002 high (root), DS-0026 low (healthcheck). Compose was not scanned by Trivy (one detected file, Dockerfile only). Non-root migration requires SSH key ownership/home path and stock AI-board acceptance; do not change current deployment blindly. Healthcheck must measure scheduler progress without invoking privileged controller or modifying read-only rootfs; plan with telemetry. Neither is dismissed as false positive. Existing image rebuild changes require separate hardware acceptance before deployment.
