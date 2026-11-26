# Acceptance tests

Original private proof of concept, GT-BE19000AI stock firmware, 2026-11-26. Public examples are sanitised; they have not been separately tested.

| Test | Result |
|---|---|
| Native MASQUERADE, explicit SNAT, dedicated custom SNAT chain | Hardware offload observed for all three using primary WAN IP |
| Custom SNAT flow counters | Hardware hits and bytes increased in both directions; active flows' software counters remained unchanged between samples |
| WAN detection | PPPoE logical interface and source agreed with kernel route |
| Restricted SSH | Forced command overrides requested command; PTY and local forwarding refused; no remote listener observed (no explicit rejection received) |
| Persistent credentials | Named volume mounted; authentication succeeded after reported container recreation |
| flock | Second lock request failed without waiting |
| iptables-restore --test --noflush | Parsed test, no live changes |
| Comment match | Dry-run succeeded; commit failed; removing comment allowed commit |
| Transactional install and rollback | Passed; original POSTROUTING rules preserved |
| Audit, enforce, disabled, idempotency | Passed |
| Missing jump and chain recovery | Passed via manual trigger |
| Autonomous polling and jump recovery | Passed |
| ASUS service restart_firewall | Native firewall regenerated; custom jump subsequently restored |

Pending: complete reboot and offline startup, DHCP WAN validation, real additional public IPs, DNAT, full throughput tests.

## Limitations

Legacy iptables has no observed --wait option. Controller flock only serialises controller processes, not ASUS firewall writers. A race remains between snapshot and commit. Post-commit verification reports unexpected changes; it cannot undo them safely. Dry-run is not proof of kernel acceptance. SSH timeout does not guarantee termination of router-side work. A firewall reload creates a temporary gap until reconciliation. Existing conntrack mappings can outlive rule changes. WAN mismatch prevents new enforcement but does not remove existing rules in this version. Reserve AI_NAT_SNAT exclusively for this controller; chain name is the ownership boundary. Host networking shares the AI board network namespace. No claim of universal firmware compatibility or security isolation.
