#!/usr/bin/env python3
"""Bounded, reproducible parser property tests; no firewall operations."""
import ipaddress
import os
import pathlib
import random
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
SEED = 0xA504
RNG = random.Random(SEED)
BASE = "-P PREROUTING ACCEPT\n-P POSTROUTING ACCEPT\n-N VSERVER\n"
COUNT = 0


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def run(args, data=None):
    global COUNT
    COUNT += 1
    return subprocess.run(args, input=data, capture_output=True, timeout=10,
                          env={**os.environ, "LC_ALL": "C"}, check=False)


def parse(kind, data, metadata=False):
    return run(["/usr/bin/awk", "-v", "kind=" + kind, "-v", "wan_if=ppp0",
                "-v", "wan_ip=203.0.113.10", "-v", "metadata=" + str(int(metadata)),
                "-f", str(ROOT / "router/nat-config.awk")], data)


def rejected(kind, data):
    result = parse(kind, data)
    require(result.returncode == 1 and result.stdout == b"",
            (kind, data[:300], result.returncode, result.stdout[:300], result.stderr))


def mapping(source="any", proto="tcp", port="443", enabled=1, force=0):
    return f"{enabled}|WAN_IP|{source}|{proto}|{port}|192.168.1.100|same|{force}\n"


def canonical(source, proto, port):
    prefix = "" if source == "0.0.0.0/0" else f" -s {source}"
    return (f"-A AI_NAT_DNAT{prefix} -d 203.0.113.10/32 -i ppp0 -p {proto}"
            f" -m {proto} --dport {port} -j DNAT --to-destination 192.168.1.100\n")


def network():
    return ipaddress.IPv4Network((RNG.getrandbits(32), RNG.randrange(33)), strict=False)


def ports():
    start = RNG.choice([1, 65535, RNG.randint(1, 65535)])
    return start, min(65535, start + RNG.randrange(32))


def port_text(pair):
    return str(pair[0]) if pair[0] == pair[1] else f"{pair[0]}:{pair[1]}"


def conflict(desired, snapshot, tmp):
    d = tmp / "desired"
    n = tmp / "native"
    d.write_bytes(desired)
    n.write_text(snapshot)
    return run(["/usr/bin/awk", "-v", "desired_file=" + str(d), "-f",
                str(ROOT / "router/dnat-conflicts.awk"), str(d), str(n)])


def main():
    general = b"MODE=AUDIT\nEXPECTED_WAN_IP=203.0.113.10\n"
    snat = b"1|192.168.1.100|any|tcp|443|WAN_IP\n"
    dnat = mapping().encode()
    # Guaranteed-invalid field replacements, including control bytes.
    for kind, seed in (("snat", snat), ("dnat", dnat)):
        fields = seed.rstrip(b"\n").split(b"|")
        for index in range(len(fields)):
            for invalid in (b"", b"$(id)", b";x", b"\x00", b"\r", b"\t", b"\xff",
                            b"x" * 4096, b"1|2"):
                mutated = fields.copy()
                mutated[index] = invalid
                rejected(kind, seed + b"|".join(mutated) + b"\n")
    for bad in (b"MODE=ENFORCE\n", b"UNKNOWN=1\n", b"MODE=AUDIT\x00\n",
                b"DNAT_ALLOWED_INTERFACES=br0,br0\n", b"DNAT_RUNTIME_POLICY=bogus\n",
                b"DNAT_ALLOWED_INTERFACES=" + b",".join(
                    f"br{i}".encode() for i in range(33)) + b"\n"):
        rejected("general", general + bad)
    for p in ("0", "65536", "-1", "+1", "01", "2:1", "1:65536", "1,", "1,,2"):
        rejected("dnat", dnat + mapping(port=p).encode())
    rejected("dnat", mapping(port=",".join(map(str, range(1, 258)))).encode())
    # Exercise the expansion boundary without expensive ambiguous overlaps.
    full = "".join(mapping(port=",".join(map(str, range(i, i + 256))), proto="both")
                   for i in range(1, 2049, 256)).encode()
    result = parse("dnat", full)
    require(result.returncode == 0 and len(result.stdout.splitlines()) == 4096,
            "4096 expansion boundary")
    rejected("dnat", full + mapping(port="2049").encode())
    with tempfile.TemporaryDirectory() as directory:
        tmp = pathlib.Path(directory)
        for i in range(160):
            a = network()
            b = a if i % 3 == 0 else network()
            p = ports()
            q = p if i % 4 == 0 else ports()
            proto = RNG.choice(("tcp", "udp"))
            other = proto if i % 5 else ("udp" if proto == "tcp" else "tcp")
            first = mapping(str(a), proto, port_text(p))
            second = mapping(str(b), other, port_text(q))
            overlap = a.overlaps(b) and proto == other and p[0] <= q[1] and q[0] <= p[1]
            expected = canonical(str(a), proto, port_text(p))
            result = parse("dnat", first.encode())
            require(result.returncode == 0 and result.stdout == expected.encode(),
                    ("canonical", first, result.stdout, result.stderr))
            meta = parse("dnat", ("# header\n" + first).encode(), True)
            require(meta.returncode == 0 and meta.stdout == ("0|2|" + expected).encode(),
                    ("metadata", first, meta.stdout))
            pair = (first + second).encode()
            if overlap:
                rejected("dnat", pair)
            else:
                result = parse("dnat", pair)
                require(result.returncode == 0 and result.stdout == (
                    expected + canonical(str(b), other, port_text(q))).encode(),
                    ("pair", pair, result.stderr))
            # Independent interval oracle for supported native predicates.
            native = (BASE + f"-A PREROUTING -s {b} -j VSERVER\n"
                      f"-A VSERVER -d 203.0.113.10/32 -p {other} -m {other}"
                      f" --dport {port_text(q)} -j DNAT --to-destination 192.168.1.101\n")
            result = conflict(meta.stdout, native, tmp)
            require(result.returncode == int(overlap), ("native overlap", first, native,
                                                        result.stderr))
            if overlap:
                forced = conflict(b"1" + meta.stdout[1:], native, tmp)
                require(forced.returncode == 0 and b"overridden" in forced.stderr,
                        ("force", first, forced.stderr))
        meta = parse("dnat", dnat, True).stdout
        for snapshot in (BASE + "-A VSERVER -j AI_NAT_DNAT\n",
                         BASE + "-A PREROUTING -j VSERVER\n-A VSERVER -j VSERVER\n",
                         "-P POSTROUTING ACCEPT\n",
                         BASE + "-A UNDECLARED -j RETURN\n"):
            for flag in (b"0", b"1"):
                result = conflict(flag + meta[1:], snapshot, tmp)
                require(result.returncode == 1, ("structural rejection", snapshot, flag))
    print(f"Parser fuzz properties passed: seed={SEED}, subprocess cases={COUNT}")


if __name__ == "__main__":
    main()
