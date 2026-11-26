# Acceptance tests

## v0.2.0 baseline

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

## v0.3.0 hardware acceptance — 2026-11-26

Tested engine commit: 9a45a097edf99f54b50d8173646373aa2efece36. GT-BE19000AI stock firmware, BusyBox 1.24.1, iptables 1.4.12.2, single PPPoE WAN. Existing AI board scheduler v0.1.0 and credentials retained. Local test addresses are omitted.

| Test | Observed result |
|---|---|
| Pinned HTTPS download, staged installation, shell and AWK compatibility | Passed |
| Migration from single hardcoded rule to external configuration | AUDIT returned IN_SYNC, exit 0 |
| Five enabled rules and one disabled rule | Correct ordering, host /32 normalisation, UDP range, TCP protocol-only, ICMP and any-protocol rules; disabled entry excluded |
| AUDIT with drift | Reported desired rules; full NAT snapshot unchanged |
| Multi-rule ENFORCE | One transaction; actual iptables -S output exactly matched desired rules; native rules independently unchanged |
| Repeated ENFORCE | IN_SYNC, no transaction |
| Invalid IPv4 appended to valid rules | Filename and line diagnostic, exit 1; full NAT snapshot unchanged; restoring valid file returned IN_SYNC |
| DISABLED and repeated DISABLED | Chain and jump removed, native snapshot identical; subsequent execution already clean |
| Re-enable | Chain recreated, exact five-rule NAT snapshot restored |
| Autonomous SSH execution and missing jump | Scheduler recovered jump; next cycle IN_SYNC |
| Actual firewall restart | Managed chain and jump removed asynchronously, recreated automatically; two following cycles IN_SYNC |
| Primary-address SNAT hardware acceleration | Active inbound and outbound hardware counters increased while software counters were unchanged |

### Firewall restart recovery

The restart command returned before regeneration completed. Immediate inspection still showed the managed rules; the jump was absent at the next one-second observation. Two-second polling subsequently showed the jump absent through approximately 25 seconds after the restart request, and present by approximately 27 seconds. Scheduler logs corroborated a new-chain transaction, successful reconciliation and two subsequent IN_SYNC cycles. Approximately 35 ms elapsed between the transaction proposal log marker and verified reconciliation log marker; this is not an isolated kernel commit benchmark. The 30-second polling cadence dominates observed recovery latency, but is not a hard recovery SLA.

### Hardware flow regression

Controlled IPv4 HTTPS download using primary-address SNAT; two active flow entries for the same connection were sampled. Inactive companion entries did not change.

| Counter | First sample | Second sample | Delta |
|---|---:|---:|---:|
| Inbound HW packets | 21017 | 32469 | 11452 |
| Inbound HW bytes | 31818576 | 49156904 | 17338328 |
| Inbound SW packets | 1 | 1 | 0 |
| Outbound HW packets | 4044 | 6332 | 2288 |
| Outbound HW bytes | 219540 | 343740 | 124200 |
| Outbound SW packets | 1 | 1 | 0 |

The custom NAT rule counted one packet (48 bytes), consistent with first-packet connection tracking. Hardware acceleration remained enabled in L2/L3 mode. These observations establish offloading for the sampled active flows, not a universal acceleration or throughput guarantee.

CI run [45873999103](https://github.com/Ballantin/asus-ai-router-controller/actions/runs/45873999103) passed parser/shell checks and mocked reconciliation. No code changes were required during the hardware acceptance campaign.

Not yet validated on hardware: explicit additional public address translation, DHCP WAN, full router reboot/offline startup, maximum throughput, empty enabled ruleset and other parser edge cases covered only by software tests. DNAT is outside this milestone.

## Limitations

Legacy iptables has no observed --wait option. Controller flock only serialises controller processes, not ASUS firewall writers. A race remains between snapshot and commit. Post-commit verification reports unexpected changes; it cannot undo them safely. Dry-run is not proof of kernel acceptance. SSH timeout does not guarantee termination of router-side work. A firewall reload creates a temporary gap until reconciliation. Existing conntrack mappings can outlive rule changes. WAN mismatch prevents new enforcement but does not remove existing rules in this version. Reserve AI_NAT_SNAT exclusively for this controller; chain name is the ownership boundary. Host networking shares the AI board network namespace. No claim of universal firmware compatibility or security isolation.
