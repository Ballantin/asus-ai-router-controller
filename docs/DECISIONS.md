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

- Runtime selective withdrawal passed regression CI and stock Asuswrt PPPoE hardware acceptance. See [acceptance results](acceptance-tests.md#v040-hardware-acceptance-results).

## Open
- Pre-commit configuration and state checks are implemented. There is no global native-writer lock or cross-table atomicity.
- ISP extra-address delivery and real DHCP/offload acceptance pending.

## Security assurance
- Introduce independent advisory CI scanning and review the initial findings before selecting blocking release gates. Never treat a successful advisory scan job as proof of a clean report. No production deployment changes in the baseline branch.

- Owner approved mandatory thresholds in security-assurance.md; five required GitHub Actions checks independently verified on main ruleset. SARIF publication separate and not required for PRs. Root scheduler and current apk package-pinning findings are scoped tracked exceptions, not global suppressions. Security source merge does not authorize hardware deployment or release. Retain mandatory CI when starting v0.4.5.

- Owner approved replacing Semgrep after validated local-rule fixture parity and review of observed registry coverage. Retain mandatory static-security check and router-policy SARIF, other independent scanners and regression safeguards. Local lexical policy is not a general-purpose SAST engine; revisit coverage when introducing new technologies. Remove vulnerable scanner dependencies rather than override constraints or dismiss alerts. Validate standalone candidate and obtain merge approval.
