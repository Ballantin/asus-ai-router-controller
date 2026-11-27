#!/usr/bin/env python3
"""Read-only validator tests with isolated mocked ip commands."""
import pathlib
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory() as tmp:
    root = pathlib.Path(tmp)
    ip = root / "ip"
    ip.write_text("""#!/bin/sh
case "$*" in
  '-4 addr show') printf '%s\\n' '1: lo:' '    inet 127.0.0.1/8 scope host lo' '2: br0:' '    inet 192.168.1.1/24 brd 192.168.1.255 scope global br0' '3: br1:' '    inet 192.168.2.1/24 brd 192.168.2.255 scope global br1' ;;
  '-4 route show table local') printf '%s\\n' 'local 192.168.1.1 dev br0' 'broadcast 192.168.1.255 dev br0' ;;
  '-4 addr show dev br0') echo '    inet 192.168.1.1/24 brd 192.168.1.255 scope global br0' ;;
  '-4 addr show dev br1') echo '    inet 192.168.2.1/24 brd 192.168.2.255 scope global br1' ;;
  '-4 route get 192.168.1.100') echo '192.168.1.100 dev br0 src 192.168.1.1' ;;
  '-4 route get 192.168.2.100') echo '192.168.2.100 dev br1 src 192.168.2.1' ;;
  '-4 route get 192.168.1.0') echo '192.168.1.0 dev br0 src 192.168.1.1' ;;
  '-4 route get 192.168.3.100') echo '192.168.3.100 via 192.168.1.2 dev br0' ;;
  '-4 route get 203.0.113.20') echo '203.0.113.20 dev ppp0' ;;
  '-4 route get 192.168.1.200') echo '192.168.1.200 dev br0 linkdown' ;;
  *) exit 1 ;;
esac
""")
    ip.chmod(0o755)
    validator = root / "validator.sh"
    validator.write_text((ROOT / "router/dnat-validate.sh").read_text().replace(
        "PATH=/usr/sbin:/usr/bin:/sbin:/bin",
        "PATH=" + str(root) + ":/usr/sbin:/usr/bin:/sbin:/bin"))
    def check(targets, ok, allowed="br0"):
        rules = "\n".join(
            "-A AI_NAT_DNAT -d 203.0.113.10/32 -i ppp0 -p tcp -m tcp --dport 8443 -j DNAT --to-destination " + t
            for t in targets)
        result = subprocess.run(["/bin/sh", str(validator), allowed, "ppp0", "eth0"],
                                input=rules, text=True, capture_output=True)
        assert (result.returncode == 0) == ok, (targets, allowed, result.stderr)
    check([], True, "")
    check(["192.168.1.100:443"], True)
    check(["192.168.1.100", "192.168.2.100"], True, "br0,br1")
    check(["192.168.2.100"], False)
    for target in ["192.168.1.1", "192.168.1.255", "192.168.1.0",
                   "192.168.3.100", "203.0.113.20", "192.168.1.200",
                   "192.168.1.99", "127.0.0.1", "169.254.0.2", "224.0.0.1"]:
        check([target], False)
    for allowed in ["", "br0,ppp0", "br0,eth0", "br0,eth.ai-10",
                    "br0,lo", "br0,br0", "br0,"]:
        check(["192.168.1.100"], False, allowed)
    check(["192.168.1.100", "192.168.2.100"], False)
    targets = ["192.168.1.100", "192.168.2.100", "192.168.1.99", "192.168.1.200", "192.168.1.1", "192.168.3.100"]
    rules = "\n".join("-A AI_NAT_DNAT -d 203.0.113.10/32 -i ppp0 -p tcp -m tcp --dport 8443 -j DNAT --to-destination " + t for t in targets)
    result = subprocess.run(["/bin/sh", str(validator), "br0", "ppp0", "eth0", "--classify"],
                            input=rules, text=True, capture_output=True)
    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines() == [
        "192.168.1.100|SAFE", "192.168.2.100|UNSAFE",
        "192.168.1.99|UNVERIFIED", "192.168.1.200|UNVERIFIED",
        "192.168.1.1|UNSAFE", "192.168.3.100|UNSAFE"], result.stdout + result.stderr
    for bad_target in ("192.168.1.100:0", "192.168.1.100:65536", "192.168.1.100:443:444", "192.168.1.100:80-90"):
        check([bad_target], False)
print("Destination validation tests passed")
