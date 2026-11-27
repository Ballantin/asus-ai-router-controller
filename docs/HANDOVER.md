# Development handover

Read PROJECT_STATUS.md, DECISIONS.md, v0.4.0-design.md, installation.md, acceptance-tests.md, ROADMAP.md and CHANGELOG.md. Verify branch heads and latest CI before editing. Do not assume a passing mock proves firmware behaviour.

Code map: router/nat-controller.sh orchestrates; nat-config.awk parses; wan-check.sh validates primary WAN; dnat-validate.sh validates destinations; dnat-conflicts.awk analyses native NAT; tests/test-config.sh, test-reconcile.py, mock-router.py, test-dnat-validate.py and test-dnat-conflicts.py provide regressions. AI board Docker scheduler v0.1.0 remains unchanged.

Firmware baseline: GT-BE19000AI stock Asuswrt, Linux 4.19.294, aarch64, BusyBox 1.24.1, iptables 1.4.12.2. --test --noflush supported, -w unavailable; do not assume full GNU utilities or all extensions. Comment-match dry-run was not proof of kernel commit support. Scheduler 30-second sleep, 15-second SSH timeout. Main router has flock, awk, sed, cmp, sha256sum, logger; no git/mktemp/diff/timeout assumed.

v0.4.0 has shipped. Use the release tag as the v0.4.5 base after confirming DHCP service and additional-address routing. The release checkpoint and CI are recorded in [Project status](../PROJECT_STATUS.md). Follow the [migration and rollback runbook](v0.4.0-migration.md) and [hardware acceptance plan](acceptance-tests.md#v040-hardware-acceptance-plan) after approval. Use synthetic documentation addresses and retain operational evidence privately. Record the exact firmware, pinned candidate and outcome. Release merge requires separate approval.
