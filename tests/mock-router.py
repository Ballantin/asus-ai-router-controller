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
    values = {"wan0_gw_ifname": "ppp0", "wan0_ipaddr": "203.0.113.10"}
    print(values[args[1]])
    sys.exit(0)
data = json.loads(state.read_text())
if cmd == "iptables":
    assert args == ["-t", "nat", "-S"], args
    print("-P POSTROUTING ACCEPT")
    for chain in data:
        if chain != "POSTROUTING":
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
        data[chain].append(rule)
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
    sys.exit(0)
if (root / "fail-commit").exists():
    sys.exit(1)
state.write_text(json.dumps(data))
with (root / "commits").open("a") as log:
    log.write("commit\n")
