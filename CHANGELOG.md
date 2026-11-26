# Changelog

## 0.4.0 — in development
- Add standalone DNAT parser mode, documented disabled-by-default template and parser tests.
- Add destination safety, native conflict analysis and per-rule Force override.
- Integrate both managed chains into a single drift-based NAT transaction. Hardware acceptance pending.

## 0.3.0 — 2026-11-26 (experimental, hardware acceptance completed)
- External general and ordered SNAT configuration with documented templates and strict AWK validation.
- Parser and mocked transaction regression tests; CI workflow.
- No Docker scheduler changes. Primary-WAN SNAT, multiple-rule reconciliation, invalid-input safety, cleanup, autonomous firewall restart recovery and bidirectional hardware offload verified on stock firmware. Additional IPs, DHCP, reboot persistence and maximum throughput remain pending.

## 0.2.0 — 2026-11-26 (experimental baseline)
- Router-side WAN validation, exclusive controller lock, audit/enforce/disabled modes.
- Dedicated SNAT chain, transactional changes, drift detection and post-commit verification.
- AI board scheduler 0.1.0: pinned SSH host key, dedicated restricted key, persistent read-only volume, 30-second polling, timeouts and log rotation.
- Demonstrated recovery after actual ASUS firewall restart.
- Public snapshot sanitises local test addresses and SSH username.
- No iptables comment matches: dry-run passed but kernel commit failed on tested firmware.

