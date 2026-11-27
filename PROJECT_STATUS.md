# Project status — checkpoint 2026-11-27

Stable main: v0.3.0, 06afeb27fc374d6ebd7f78cf18b9c62c25dc2022. Development branch: develop/v0.4.0; last code checkpoint a25926104c808cbe7acd83eb65f287818da63c69. CI runs #8–13 passed (reported by maintainer from Actions UI); latest #13 passed in 12 seconds. This documentation commit does not constitute additional software or hardware validation.

## Completed
- v0.3.0 primary-address SNAT, autonomous recovery and native offload evidence on stock GT-BE19000AI.
- v0.4.0 source-aware eight-field DNAT parser, destination validator, native conflict detector, per-rule Force override, combined transactional reconciliation and mocked regression tests.
- Initial pre-deployment code review.

## Next
1. Runtime policy agreed: selective withdrawal, configurable PRESERVE / WITHDRAW_UNSAFE (default) / WITHDRAW_UNVERIFIED. Parser and destination classification implemented as first stage; controller integration and CI pending.
2. Configuration snapshots, inspection error checks and additional race/transaction regression cases implemented in the subsequent hardening commit; CI pending. Still add direct inspection failure injection and integrate runtime withdrawal policy.
3. Update migration and rollback documentation; validate BusyBox syntax, actual iptables canonicalisation, scheduler timeout and firmware prerequisites.
4. Draft PR; controlled hardware acceptance with isolated source-restricted services, negative tests, native preservation, restart recovery and hardware offload evidence.
5. Merge only after explicit approval and acceptance. v0.5.0 telemetry follows.

Additional public IP routing, DHCP WAN, reboot persistence and maximum throughput remain unvalidated. No v0.4.0 live deployment has been performed at this checkpoint.

See [decisions](docs/DECISIONS.md), [handover](docs/HANDOVER.md), [design](docs/v0.4.0-design.md) and [roadmap](ROADMAP.md).
