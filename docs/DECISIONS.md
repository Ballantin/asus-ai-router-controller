# Architectural decisions

## Accepted
- Stock Asuswrt, no firmware replacement; AI board schedules restricted SSH, main router owns forwarding.
- Dedicated SNAT/DNAT chains; first POSTROUTING and last PREROUTING respectively. Native destination forwarding wins. No filter mutation.
- Validate complete desired configuration before writes; one no-flush NAT transaction for drifted chains only; dry-run, recheck, verify. No blind rollback of stale native state.
- AUDIT read-only; DISABLED removes owned chains without WAN or rules-file validation. Empty SNAT retains empty chain; empty DNAT removes chain and jump.
- Source-aware DNAT: TCP/UDP/both, lists/ranges, same-port or single-port translation. Reject overlapping managed tuples. Interface allowlist and destination route safety mandatory.
- Force=1 per enabled rule overrides only native conflict findings. Metadata separate from canonical rules; warnings include source line. Force cannot override ownership, malformed config, destination, WAN, structural or transaction safeguards.
- Preserve native rules and hardware acceleration; no global conntrack flush. IPv6/hairpin deferred.
- Version-specific branches for development; explicit approval for release merge; no private deployment information in public history.

- Runtime destination policy agreed: PRESERVE, WITHDRAW_UNSAFE (default), WITHDRAW_UNVERIFIED. Classify installed destinations separately from proposed rules; withdraw only affected mappings in ENFORCE through verified transactions, retain unaffected ordering, restore only after full desired validation. Invalid edits alone never trigger withdrawal. Force is independent. No conntrack flush.

## Open
- Runtime selective withdrawal and WAN read error handling passed regression CI. Hardware acceptance is pending.
- Pre-commit configuration and state checks are implemented. There is no global native-writer lock or cross-table atomicity.
- ISP extra-address delivery and real DHCP/offload acceptance pending.
