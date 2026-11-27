# Project status — 2026-11-27

[v0.4.0](https://github.com/Ballantin/asus-ai-router-controller/releases/tag/v0.4.0) was published from merge commit `3cc2fa9a225611fdb145f7a7f11d2638e403bc7d`. [Post-merge Regression tests #25](https://github.com/Ballantin/asus-ai-router-controller/actions/runs/46004174491) passed at that commit. The release was hardware-tested on PPPoE. v0.4.5 is planned from the v0.4.0 tag once the DHCP connection and routed IPv4 allocation are active.

- Implemented source-aware DNAT parsing, native conflict checks, Force, combined reconciliation and selective runtime withdrawal.
- Pre-deployment review covered migration compatibility, config capture and races, managed chain ownership, withdrawal checks, desired-state revalidation and post-commit verification. Failed WAN reads now block reconciliation even when partial output matches the expected value. Regression tests inject that condition after dry-run.
- [Migration and rollback](docs/v0.4.0-migration.md) and [hardware acceptance](docs/acceptance-tests.md#v040-hardware-acceptance-plan) record the release procedure. Hardware testing on stock Asuswrt with a PPPoE WAN verified TCP and UDP forwarding, TCP source selection on one WAN port across two distinct LAN hosts, native rule precedence, selective and last-rule withdrawal, and rollback to v0.3.0.
- Tested candidate `958f7f409df746ffb545be0878e4895491d27f59` restored both managed hooks via the scheduler about 12 seconds after a firewall restart request. The native FORWARD snapshot matched and representative native HTTPS and managed DNAT probes succeeded. The full NAT snapshot differed after the ASUS rebuild. Broadcom flow-cache counters increased in both directions on a sustained TCP DNAT flow. The DISABLED rehearsal preserved native rules and restored v0.3.0 with scheduled `IN_SYNC`.
- An independent mobile UDP probe did not reach the listener on the Linode-only WAN port. The authorised Linode probe succeeded, and a mobile-authorised control confirmed the test app could reach the same listener. DHCP and additional public addresses remain unverified. Deployment requires administrator approval.

## Security baseline workstream

Independent branch `develop/security-hardening` from the post-release v0.4.0 main checkpoint. Advisory scan workflow, local rules, Dependabot configuration and security baseline documentation added; first scanner execution and findings review pending. Production router and release unchanged. DHCP and routed-address acceptance remain a separate v0.4.5 milestone.

Security baseline #2 (46009253244) and regression #29 passed workflow execution at 93c9f9c; log review found Semgrep startup failure misclassified as advisory, 15 package findings, two Dockerfile findings, and test-only/quality findings. First remediation addresses scanner validity, shell clarity and test quality, and requests updated Alpine packages. Rescan pending; no production deployment.

Security baseline #3 and regression #30 passed; verified logs show zero ShellCheck/Ruff/Semgrep findings, no detected secrets and zero package vulnerabilities in rebuilt ARM64 image. Scanner container digests and observed Python dependency versions pinned in next CI revision; verification pending. GitHub main and release tag rulesets independently verified active, no bypass actors. See docs/security-assurance.md for limitations and remaining tasks.

Security baseline #4/regression #31 passed with pinned dependencies. Extended coverage adds normalized Compose security contract/negative controls, deterministic AWK property tests and mock NAT transaction ownership assertions. CI verification pending; no production file changes in this checkpoint.

Regression #33/security baseline #6 passed at 7a8d972: 814 parser executions and eight Compose negative controls, all six suites passed. SECURITY.md and validated Semgrep SARIF publication added; publication CI pending. No production changes.

Security baseline #7/regression #34 passed, including GitHub SARIF upload and processing. Owner approved mandatory gate thresholds; implementation and synthetic negative controls added, validation pending. Branch ruleset still requires regression only until new checks validated and owner updates settings.
