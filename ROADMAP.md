# Project roadmap

This roadmap describes the intended development direction. Future milestones are provisional, not release-date commitments.

| Version | Objective | Status |
|---|---|---|
| v0.1.0 | Initial proof of concept | Complete |
| v0.2.0 | Autonomous SNAT reconciliation | Complete |
| v0.3.0 | Externalised SNAT configuration | Complete (experimental, hardware-tested scope) |
| v0.4.0 | Configurable DNAT management | Planned |
| v0.5.0 | Telemetry and monitoring | Planned |

## Completed milestones

- **v0.1.0:** establish the feasibility of custom NAT with native hardware offloading.
- **v0.2.0:** dedicated managed SNAT chain, transactional reconciliation, restricted SSH orchestration and automatic drift recovery.
- **v0.3.0:** self-documenting external configuration, ordered SNAT rules, strict validation, regression tests, CI and hardware acceptance for primary-WAN-address SNAT.

See [changelog](CHANGELOG.md) and [acceptance results](docs/acceptance-tests.md).

## Planned milestones

### v0.4.0 — DNAT

- Self-documenting external DNAT configuration.
- Ordered, individually enabled destination translation rules with strict input validation.
- Dedicated managed chains and transactional reconciliation; evaluate forwarding policy and interaction with native ASUS rules.
- Regression tests, hardware acceptance, and verification of hardware offloading where supported.

### v0.5.0 — Telemetry and monitoring

- Structured reconciliation status and error reporting.
- Investigate metrics for WAN state, drift, reconciliation and recovery.
- Investigate hardware acceleration visibility and integration with external monitoring systems.
- Document operational behaviour and monitoring setup.

## Outstanding hardware validation

These items are separate from the completed v0.3.0 acceptance scope:

- Additional public IPv4 address routing and translation.
- DHCP WAN discovery and compatibility.
- Full router reboot and offline startup persistence.
- Maximum achievable throughput under realistic traffic.

DNAT is not yet implemented. No claim of universal firmware compatibility, additional-address offloading or maximum throughput is made.

## Development principles

Retain stock firmware and native hardware-accelerated forwarding; preserve unmanaged ASUS firewall rules; keep configuration self-documenting; never commit private deployment data. Develop in version-specific branches, run automated regression tests, and merge only after acceptance testing and review. Keep known limitations explicit.
