#!/usr/bin/env python3
"""Conservative native NAT overlap checks; no real firewall access."""
import pathlib
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
BASE = """-P PREROUTING ACCEPT
-P POSTROUTING ACCEPT
-N VUPNP
-N VSERVER
-N CHILD
-N AI_NAT_DNAT
-A PREROUTING -j VUPNP
-A PREROUTING -d 203.0.113.10/32 -j VSERVER
-A PREROUTING -j AI_NAT_DNAT
-A VSERVER -p tcp -m tcp --dport 443 -j DNAT --to-destination 192.168.1.100:1443
-A VSERVER -p udp -m udp --dport 8000:9000 -j DNAT --to-destination 192.168.1.100
"""
def rule(ip="203.0.113.10", proto="tcp", port="443", src="", force=0, line=1):
    return (f"{force}|{line}|-A AI_NAT_DNAT " + ("-s " + src + " " if src else "") +
            f"-d {ip}/32 -i ppp0 -p {proto} -m {proto} --dport {port}"
            " -j DNAT --to-destination 192.168.1.101\n")

with tempfile.TemporaryDirectory() as tmp:
    d = pathlib.Path(tmp) / "desired"
    n = pathlib.Path(tmp) / "native"
    def check(wanted, ok, extra="", base=BASE, warning=None):
        d.write_text(wanted)
        n.write_text(base + extra)
        r = subprocess.run(["/usr/bin/awk", "-v", "desired_file=" + str(d), "-f",
                            str(ROOT / "router/dnat-conflicts.awk"), str(d), str(n)],
                           text=True, capture_output=True)
        assert (r.returncode == 0) == ok, (wanted, extra, r.stdout, r.stderr)
        if warning is not None:
            assert (warning in r.stderr), r.stderr
    check("", True)
    check(rule(), False)
    check(rule(ip="203.0.113.11"), True)
    check(rule(proto="udp"), True)
    check(rule(proto="udp", port="8500"), False)
    check(rule(proto="udp", port="7990:8000"), False)
    check(rule(proto="udp", port="9001"), True)
    check(rule(ip="203.0.113.11"), False,
          "-A VUPNP -p tcp -m tcp --dport 443 -j DNAT --to-destination 192.168.1.100\n")
    source = "-A VUPNP -s 198.51.100.0/25 -j CHILD\n"
    child = "-A CHILD -p tcp -m tcp --dport 443 -j DNAT --to-destination 192.168.1.100\n"
    check(rule(ip="203.0.113.11", src="198.51.100.128/25"), True, source + child)
    check(rule(ip="203.0.113.11", src="198.51.100.0/24"), False, source + child)
    check(rule(ip="203.0.113.11"), True,
          "-A VUPNP -i br0 -j CHILD\n" + child)
    check(rule(ip="203.0.113.11"), False,
          "-A VUPNP -i ppp+ -j CHILD\n" + child)
    check(rule(ip="203.0.113.11"), True,
          "-A VSERVER -m multiport --dports 443,444 -j DNAT --to-destination 192.168.1.100\n")
    check(rule(ip="203.0.113.11"), False,
          "-A VUPNP -m multiport --dports 443,444 -j DNAT --to-destination 192.168.1.100\n")
    check(rule(ip="203.0.113.11"), False, "-A VUPNP -j VUPNP\n")
    check(rule(ip="203.0.113.11"), False, "-A VUPNP -g CHILD\n")
    check(rule(ip="203.0.113.11"), False, "-A VUPNP -j UNKNOWN\n")
    check(rule(ip="203.0.113.11"), False, "-A VUPNP -j REDIRECT --to-ports 443\n")
    check(rule(ip="203.0.113.11"), True,
          "-A POSTROUTING -j UNKNOWN\n")
    check(rule(ip="203.0.113.11"), True,
          "-A AI_NAT_DNAT -p tcp -j DNAT --to-destination 192.168.1.102\n")
    check(rule(ip="203.0.113.11"), False, "-A VUPNP -j AI_NAT_DNAT\n")
    check(rule(ip="203.0.113.11"), False,
          "-A VUPNP ! -s 198.51.100.0/24 -j CHILD\n" + child)
    check(rule(ip="203.0.113.11"), False,
          "-A VUPNP -m comment --comment \"-d 192.0.2.1\" -j CHILD\n" + child)
    check(rule(ip="203.0.113.11"), True,
          "-A VUPNP -d 192.0.2.1/32 -m comment --comment \"opaque\" -j CHILD\n" + child)
    check(rule(ip="203.0.113.11"), False, base="-P POSTROUTING ACCEPT\n")
    check(rule(force=1, line=12), True, warning="line 12: native conflict overridden")
    check(rule(ip="203.0.113.11", force=1), True,
          "-A VUPNP -m multiport --dports 443,444 -j DNAT --to-destination 192.168.1.100\n",
          warning="native conflict overridden")
    check(rule(force=1) + rule(proto="udp", port="8500", line=2), False)
    check(rule(force=1) + rule(ip="203.0.113.11", line=2), True)
    check(rule(force=1), False, "-A VUPNP -j AI_NAT_DNAT\n")
    check(rule(force=1), False, "-A POSTROUTING -j AI_NAT_DNAT\n")
    check(rule(force=1), False, base="-P POSTROUTING ACCEPT\n")
    check(rule(force=1, ip="203.0.113.11"), False, "-A VUPNP -j VUPNP\n")
    check(rule(force=2), False)
    check(rule(force=1).replace("-p tcp", "-p invalid"), False)
    check(rule(force=1, ip="203.0.113.11"), True, warning="Force enabled")
print("Native DNAT conflict tests passed")
