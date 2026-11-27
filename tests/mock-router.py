#!/usr/bin/env python3
"""Minimal transactional NAT model, not an emulation of kernel or firmware."""
import json
import os
import pathlib
import sys

root = pathlib.Path(os.environ["MOCK_ROOT"])
state = root / "state.json"
cmd = pathlib.Path(sys.argv[0]).name
args = sys.argv[1:]
if cmd == "logger":
    sys.exit(0)
if cmd == "nvram":
    values = {"wan0_gw_ifname": "ppp0", "wan0_ipaddr": "203.0.113.10", "wan0_ifname": "eth0"}
    if args[1] == "wan0_ipaddr" and (root / "wan-changed").exists():
        values[args[1]] = "203.0.113.99"
    print(values[args[1]])
    sys.exit(0)
data = json.loads(state.read_text())
if cmd == "iptables":
    if args == ["-t", "filter", "-S", "FORWARD"]:
        print("-P FORWARD ACCEPT")
        if not (root / "no-filter").exists():
            print("-A FORWARD -m conntrack --ctstate DNAT -j ACCEPT")
        if (root / "filter-changed").exists():
            print("-A FORWARD -p tcp -j RETURN")
        print("-A FORWARD -j DROP")
        sys.exit(0)
    assert args == ["-t", "nat", "-S"], args
    print("-P POSTROUTING ACCEPT")
    print("-P PREROUTING ACCEPT")
    for chain in data:
        if chain not in ("POSTROUTING", "PREROUTING"):
            print("-N " + chain)
    for chain, rules in data.items():
        for rule in rules:
            print("-A " + chain + " " + rule)
    sys.exit(0)
assert cmd == "iptables-restore", cmd
assert "--noflush" in args
lines = sys.stdin.read().splitlines()
assert lines[0] == "*nat" and lines[-1] == "COMMIT"
for line in lines[1:-1]:
    op, chain, *tail = line.split()
    rule = " ".join(tail)
    if op == "-N":
        assert chain not in data
        data[chain] = []
    elif op == "-F":
        data[chain] = []
    elif op == "-X":
        assert not data[chain]
        del data[chain]
    elif op == "-A":
        data.setdefault(chain, []).append(rule)
    elif op == "-D":
        data[chain].remove(rule)
    elif op == "-I":
        assert tail[0] == "1"
        data[chain].insert(0, " ".join(tail[1:]))
    else:
        raise AssertionError(line)
if "--test" in args:
    if (root / "fail-test").exists():
        sys.exit(1)
    # Simulate independent changes only after the dry-run has succeeded.
    for event, marker in (("race-wan", "wan-changed"),
                          ("race-filter", "filter-changed"),
                          ("race-destination", "fail-destination")):
        if (root / event).exists():
            (root / marker).touch()
    for name in ("nat-controller.conf", "snat-rules.conf", "dnat-rules.conf"):
        if (root / ("race-" + name)).exists():
            with (root / name).open("a") as f:
                f.write("# concurrent edit\n")
    if (root / "race-nat").exists():
        original = json.loads(state.read_text())
        original["POSTROUTING"].append("-p udp -j RETURN")
        state.write_text(json.dumps(original))
    sys.exit(0)
if (root / "fail-commit").exists():
    sys.exit(1)
if (root / "bad-postcommit").exists():
    data["POSTROUTING"].append("-p tcp -j RETURN")
state.write_text(json.dumps(data))
with (root / "commits").open("a") as log:
    log.write("commit\n")
(root / "last-transaction").write_text("\n".join(lines))
