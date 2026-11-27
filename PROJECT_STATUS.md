# Project status — 2026-11-27

[v0.4.0](https://github.com/Ballantin/asus-ai-router-controller/releases/tag/v0.4.0) was published from merge commit `3cc2fa9a225611fdb145f7a7f11d2638e403bc7d`. [Post-merge Regression tests #25](https://github.com/Ballantin/asus-ai-router-controller/actions/runs/46004174491) passed at that commit. The release was hardware-tested on PPPoE. v0.4.5 is planned once the DHCP connection and routed IPv4 allocation are active; proposed base is the security-hardened main branch, subject to owner confirmation.

- Implemented source-aware DNAT parsing, native conflict checks, Force, combined reconciliation and selective runtime withdrawal.
- Pre-deployment review covered migration compatibility, config capture and races, managed chain ownership, withdrawal checks, desired-state revalidation and post-commit verification. Failed WAN reads now block reconciliation even when partial output matches the expected value. Regression tests inject that condition after dry-run.
- [Migration and rollback](docs/v0.4.0-migration.md) and [hardware acceptance](docs/acceptance-tests.md#v040-hardware-acceptance-plan) record the release procedure. Hardware testing on stock Asuswrt with a PPPoE WAN verified TCP and UDP forwarding, TCP source selection on one WAN port across two distinct LAN hosts, native rule precedence, selective and last-rule withdrawal, and rollback to v0.3.0.
- Tested candidate `958f7f409df746ffb545be0878e4895491d27f59` restored both managed hooks via the scheduler about 12 seconds after a firewall restart request. The native FORWARD snapshot matched and representative native HTTPS and managed DNAT probes succeeded. The full NAT snapshot differed after the ASUS rebuild. Broadcom flow-cache counters increased in both directions on a sustained TCP DNAT flow. The DISABLED rehearsal preserved native rules and restored v0.3.0 with scheduled `IN_SYNC`.
- An independent mobile UDP probe did not reach the listener on the Linode-only WAN port. The authorised Linode probe succeeded, and a mobile-authorised control confirmed the test app could reach the same listener. DHCP and additional public addresses remain unverified. Deployment requires administrator approval.

## Security hardening workstream — implementation complete, 2026-11-27

Approved PRs [#3](https://github.com/Ballantin/asus-ai-router-controller/pull/3), [#12](https://github.com/Ballantin/asus-ai-router-controller/pull/12), [#13](https://github.com/Ballantin/asus-ai-router-controller/pull/13) and [#15](https://github.com/Ballantin/asus-ai-router-controller/pull/15) merged without protection bypass. Final implementation baseline `c8131b04eb892a4ea6e98079f5cf45714075ed71` passed all post-merge workflows: [regression](https://github.com/Ballantin/asus-ai-router-controller/actions/runs/46026198599), [security](https://github.com/Ballantin/asus-ai-router-controller/actions/runs/46026199022), [managed analysis](https://github.com/Ballantin/asus-ai-router-controller/actions/runs/46026198790) and [dependency graph](https://github.com/Ballantin/asus-ai-router-controller/actions/runs/46026213706).

- Five mandatory GitHub Actions checks, strict up-to-date branch policy, no bypass; full SHA enforcement owner-confirmed and validated by subsequent CI.
- Eight regression suites, 814 deterministic parser executions, eight Compose negative controls, scanner gate controls and 16 router-policy command fixtures plus missing/invalid-source controls.
- Zero blocking findings, zero reported ARM64 scheduler package vulnerabilities, no detected leaks in 45 reachable commits, successful router-policy SARIF processing.
- Owner dashboard confirmed zero open Dependabot alerts, all 11 historical alerts Fixed (2 high, 8 moderate, 1 low), none dismissed. Semgrep environment retired; three local rules demonstrated fixture parity. Registry coverage is not equivalent.
- Only open PR at checkpoint: #7 Alpine 3.24, deferred for hardware acceptance. No new release or deployment.

See [security assurance](docs/security-assurance.md) for current policy, evidence, exceptions and continuing maintenance. Security implementation acceptance complete; documentation closure PR requires normal CI and approval. Outstanding engineering: non-root scheduler, meaningful healthcheck, reproducible deployment image, firmware acceptance, scanner coverage/provenance improvements. These are not completed by CI success.

## Next milestone

Confirm ISP activation, DHCP WAN and additional IPv4 delivery before starting v0.4.5. Preserve current required workflows by branching from updated main (owner to confirm). Hardware acceptance of revised scripts/image and separate release/deployment approval remain necessary.
