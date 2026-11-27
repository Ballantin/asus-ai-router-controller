# Project status — 2026-11-27

Public main remains v0.3.0 at `06afeb27fc374d6ebd7f78cf18b9c62c25dc2022`. Active development is `develop/v0.4.0`. Latest verified code is `5fc7f1214e7b53b5bfb7cfe712f49cac240420f8`, with [Regression tests #20](https://github.com/Ballantin/asus-ai-router-controller/actions/runs/45980797283) passing. The recovered checkpoint `a12e4aa9e492d8d3d64205d9d36adbb56e3a343f` passed [Regression tests #19](https://github.com/Ballantin/asus-ai-router-controller/actions/runs/45966474992).

- Implemented source-aware DNAT parsing, native conflict checks, Force, combined reconciliation and selective runtime withdrawal.
- Pre-deployment review covered migration compatibility, config capture and races, managed chain ownership, withdrawal checks, desired-state revalidation and post-commit verification. Failed WAN reads now block reconciliation even when partial output matches the expected value. Regression tests inject that condition after dry-run.
- [Migration and rollback](docs/v0.4.0-migration.md) and [hardware acceptance](docs/acceptance-tests.md#v040-hardware-acceptance-plan) are ready for review. No v0.4.0 hardware acceptance has been recorded.
- Next gate is approval for controlled hardware acceptance. Confirm legacy iptables numbered delete and canonical output, 15-second scheduler budget, native policy, restricted forwarding, recovery and hardware acceleration. Confirm DHCP and additional public address routing before testing those variants. Merge requires separate approval.
