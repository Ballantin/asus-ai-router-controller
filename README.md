# asus-ai-router-controller

Autonomous router configuration management using the ASUS AI board and native hardware-accelerated NAT.

## Status

[v0.4.0](https://github.com/Ballantin/asus-ai-router-controller/releases/tag/v0.4.0) is the current experimental release. It combines primary-address SNAT and source-aware TCP and UDP DNAT. Hardware acceptance used a GT-BE19000AI running stock Asuswrt with BusyBox 1.24.1, iptables 1.4.12.2 and a PPPoE WAN. The AI board scheduler is v0.1.0.

The AI board invokes a restricted SSH command over its internal management link. The main router validates WAN state and applies changes only to the managed NAT chains when necessary. Existing ASUS forwards retain precedence. DNAT defaults to strict conflict handling and supports an explicit per-rule override. See the [DNAT design](docs/v0.4.0-design.md).

- [Installation and safety](docs/installation.md)
- [Migration and rollback](docs/v0.4.0-migration.md)
- [Hardware acceptance results](docs/acceptance-tests.md#v040-hardware-acceptance-results)
- [Changelog](CHANGELOG.md)
- [Project roadmap](ROADMAP.md)
- [Security policy and private vulnerability reporting](SECURITY.md)
- [Security assurance and scanning](docs/security-assurance.md)

Review local settings and start in AUDIT before enabling enforcement. DHCP WAN and routed additional IPv4 addresses are planned for v0.4.5 validation. Full router reboot, offline startup and maximum throughput remain unverified.

Independent community project. See [LICENSE](LICENSE).
