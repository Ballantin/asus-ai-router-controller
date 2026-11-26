# Changelog

## 0.2.0 — 2026-11-26 (experimental baseline)
- Router-side WAN validation, exclusive controller lock, audit/enforce/disabled modes.
- Dedicated SNAT chain, transactional changes, drift detection and post-commit verification.
- AI board scheduler 0.1.0: pinned SSH host key, dedicated restricted key, persistent read-only volume, 30-second polling, timeouts and log rotation.
- Demonstrated recovery after actual ASUS firewall restart.
- Public snapshot sanitises local test addresses and SSH username.
- No iptables comment matches: dry-run passed but kernel commit failed on tested firmware.

## Planned 0.3.0
- External SNAT rules and general configuration, multiple ordered rules and comprehensive in-file syntax documentation.
