# asus-ai-router-controller

Autonomous router configuration management using the ASUS AI board and native hardware-accelerated NAT.

## Status: experimental proof of concept

Development branch: router engine v0.3.0 (not hardware-validated); AI board Docker scheduler v0.1.0. The v0.2.0 baseline was tested. Tested on a GT-BE19000AI with stock Asuswrt, BusyBox 1.24.1 and iptables 1.4.12.2. No custom firmware required. This is not a production-ready multi-IP NAT release.

The AI board periodically invokes a restricted SSH command over its internal management link. The main router validates WAN state, compares desired and actual NAT rules, and applies changes to a dedicated chain only when necessary. Traffic forwarding remains on the main router.

- [Installation and safety](docs/installation.md)
- [Acceptance tests and limitations](docs/acceptance-tests.md)
- [Changelog](CHANGELOG.md)

The published baseline replaces private test addresses with documentation addresses and parameterises the SSH username. These public adaptations have not been retested on hardware. Do not deploy unchanged or enable enforcement until local settings are reviewed.

This branch adds externalised, self-documenting SNAT configuration. See [development acceptance](docs/v0.3.0-testing.md). DNAT and additional public IPs remain unvalidated.

Independent community project; not affiliated with ASUS. See LICENSE.
