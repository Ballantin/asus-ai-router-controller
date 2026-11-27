# Project status — checkpoint 2026-11-27

Stable main: v0.3.0, 06afeb27fc374d6ebd7f78cf18b9c62c25dc2022. Development branch: develop/v0.4.0; last code checkpoint 207d6efa4d100b6169bab5aa45c6a33aa89c2665. CI runs #17 (23s) and #18 (22s) passed, with all four suites independently verified via Actions job results. This documentation commit does not constitute additional software or hardware validation.

## Completed
- v0.3.0 primary-address SNAT, autonomous recovery and native offload evidence on stock GT-BE19000AI.
- v0.4.0 source-aware eight-field DNAT parser, destination validator, native conflict detector, per-rule Force override, combined transactional reconciliation and mocked regression tests.
- Initial pre-deployment code review.

## Next
1. Runtime policy agreed: selective withdrawal, configurable PRESERVE / WITHDRAW_UNSAFE (default) / WITHDRAW_UNVERIFIED. Parser, destination classification and selective withdrawal integration implemented; CI passed per maintainer report; hardware verification pending.
2. Configuration snapshots, inspection error checks and additional race/transaction regression cases implemented in the subsequent hardening commit; CI passed as part of latest development head per maintainer report. Direct inspection failure injection and withdrawal failure-path coverage implemented in subsequent hardening commit; CI pending.
3. Update migration and rollback documentation; validate BusyBox syntax, actual iptables canonicalisation, scheduler timeout and firmware prerequisites.
4. Draft PR; controlled hardware acceptance with isolated source-restricted services, negative tests, native preservation, restart recovery and hardware offload evidence.
5. Merge only after explicit approval and acceptance. v0.5.0 telemetry follows.

Additional public IP routing, DHCP WAN, reboot persistence and maximum throughput remain unvalidated. No v0.4.0 live deployment has been performed at this checkpoint.

See [decisions](docs/DECISIONS.md), [handover](docs/HANDOVER.md), [design](docs/v0.4.0-design.md) and [roadmap](ROADMAP.md).

Latest integrated runtime policy commit 207d6efa4d100b6169bab5aa45c6a33aa89c2665 passed CI per maintainer report. Run #17 (45965740168), 23s; documentation checkpoint #18 (45966138604), 22s. No hardware validation implied.
