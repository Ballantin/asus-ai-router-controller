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

## Verified baseline #3 and dependency hardening

Security baseline #3 (46010139380) and regression #30 (46010139317) succeeded at d5d96df. ShellCheck and Ruff clean; Semgrep scanned 10 files and reported zero findings; Gitleaks found no leaks in 26 commits; Bandit 90 low (no medium/high); Hadolint DL3018 remains; zizmor zero reported and five suppressed; Dockerfile root and healthcheck findings remain. Alpine upgrade installed libcrypto3/libssl3 3.5.9-r2 and zlib 1.4-r0. Trivy inspected 22 packages on Alpine 3.22.8 and reported zero vulnerabilities. No deployed image or firmware was scanned.

The next CI revision pins scanner container manifests to digests observed in the successful run and ShellCheck to its observed Ubuntu package version. Three separate Python requirements files capture all scanner package versions reported by that run; install with --no-deps, then pip check and freeze. Dependabot pip configuration monitors these files subject to GitHub manifest discovery. These are version locks, not wheel hash locks or independent provenance attestations. The runner, system dependencies, pip bootstrap, Semgrep remote rules and Trivy vulnerability/check databases remain mutable; security intelligence must stay fresh. Validate digest pulls and dependency completeness in CI before gating. Scheduler apk upgrades intentionally remain dynamic; reproducible deployment requires separately recording and retaining an approved image digest. Update scanner pins through reviewed PRs, with upstream security/provenance review and fresh scans; do not automatically deploy updates. Scanner digests in workflow shell commands are not guaranteed to receive Dependabot updates.

## Repository configuration checkpoint

On 2026-11-27 the GitHub API returned active Protect main (28239782) and Protect release tags (28240927) rulesets, both with no bypass actors. Main targets default branch, prohibits deletion and non-fast-forward updates, requires PR/conversation resolution and strict regression status check from GitHub Actions; zero required approvals for sole maintainer. Tags target refs/tags/v*, prohibit update/deletion/non-fast-forward, allow creation. Auto-merge disabled. Owner screenshots confirmed dependency graph, Dependabot alerts/malware/security/grouped updates, CodeQL default setup, secret scanning/push protection, read-only Actions defaults, external contributor approval and no Actions PR creation/approval; owner reported private reporting and immutable releases enabled. Administrative settings endpoints were inaccessible to connector; these settings were not independently verified. SHA enforcement deferred until merge and compatibility review. Security gates remain advisory. Recheck owner-confirmed auto-triage and code scanning thresholds before enforcement.

## Extended security coverage

Baseline #4 (46015847717) and regression #31 passed with pinned scanner dependencies at 272938b; actual logs verified all three container digests, pip consistency, zero ShellCheck/Ruff/Semgrep findings, Gitleaks no leaks in 27 commits, and zero reported package vulnerabilities. Remaining advisory findings unchanged.

Regression CI now checks normalized Docker Compose JSON without starting services, using a synthetic username. It enforces read-only root and SSH volume, no capabilities/privilege escalation, no device/socket/bind mounts, approved network and service settings, bounded logging and expected SSH command fragments. Eight negative controls prove representative unsafe mutations are rejected. Command-fragment checks are heuristic, not a shell semantic proof. Host networking and root remain intentional current architecture, pending non-root migration. The mock NAT transaction interpreter rejects modifications outside owned chains except exact owned hook jumps, supplementing existing read-only filter checks and no-flush assertions. Deterministic bounded AWK property tests use seed 0xA504, Python ipaddress and independent port interval overlap calculations, invalid field/control-byte mutations, all-or-nothing rejection, metadata, 4096-rule and 256-port-list limits, native overlap and Force structural rejection. These run on hosted CI awk, not the target BusyBox build; no real firewall or router is accessed. Production files unchanged in this checkpoint. Review new failures before enabling security gates.

Regression #32 failed before new checks ran because the mock-router.py executable mode was accidentally reset to 100644 by the commit. The non-privileged runner denied the fallback host iptables read. Restore 100755 and add explicit isolated mock resolution/executable preflight before executing the engine. No production access or firewall mutation occurred. Re-run all suites.
