# asus-ai-router-controller

Autonomous router configuration management using the ASUS AI board and native hardware-accelerated NAT.

## Status: experimental proof of concept

Development branch v0.4.0: DNAT parser and template under development; live engine remains v0.3.0. See [DNAT design](docs/v0.4.0-design.md).

Router engine v0.3.0 and AI board Docker scheduler v0.1.0. Primary-address SNAT and autonomous recovery hardware-validated on a GT-BE19000AI with stock Asuswrt, BusyBox 1.24.1 and iptables 1.4.12.2. No custom firmware required. This is not a production-ready multi-IP NAT release.

The AI board periodically invokes a restricted SSH command over its internal management link. The main router validates WAN state, compares desired and actual NAT rules, and applies changes to a dedicated chain only when necessary. Traffic forwarding remains on the main router.

- [Installation and safety](docs/installation.md)
- [Acceptance tests and limitations](docs/acceptance-tests.md)
- [Changelog](CHANGELOG.md)
- [Project roadmap](ROADMAP.md)

The published baseline replaces private test addresses with documentation addresses and parameterises the SSH username. The v0.3.0 router engine was downloaded from its pinned public commit and tested with local configuration; the public scheduler username adaptation has not been separately retested. Do not deploy unchanged or enable enforcement until local settings are reviewed.

v0.3.0 adds externalised, self-documenting SNAT configuration. See [development acceptance](docs/v0.3.0-testing.md). Additional public IPs, DHCP WAN, reboot persistence and maximum throughput remain unvalidated. DNAT is not implemented.

Independent community project; not affiliated with ASUS. See LICENSE.
