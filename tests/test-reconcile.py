#!/usr/bin/env python3
"""Run the real shell engine against isolated mock commands; never touch host NAT."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

repo = Path(__file__).resolve().parent.parent
native = "-o ppp0 -j MASQUERADE"
jump = "-j AI_NAT_SNAT"
with tempfile.TemporaryDirectory() as td:
    root = Path(td)
    binpath = root / "bin"
    binpath.mkdir()
    for name in ("iptables", "iptables-restore", "nvram", "logger"):
        (binpath / name).symlink_to(repo / "tests/mock-router.py")
    # Substitute only in temporary test copy; no runtime override in production.
    source = (repo / "router/nat-controller.sh").read_text()
    for old, new in (
        ("PATH=/usr/sbin:/usr/bin:/sbin:/bin", f'PATH="{binpath}:/usr/sbin:/usr/bin:/sbin:/bin"'),
        ('BASE="/jffs/custom"', f'BASE="{root}"'),
        ('RUNTIME="/tmp/nat-controller"', f'RUNTIME="{root}/runtime"'),
    ):
        assert old in source
        source = source.replace(old, new, 1)
    engine = root / "engine.sh"
    engine.write_text(source)
    for name in ("nat-config.awk", "dnat-conflicts.awk"):
        shutil.copy(repo / "router" / name, root)
    # Real destination validator is covered separately; inject its failure here.
    validator = root / "dnat-validate.sh"
    validator.write_text('#!/bin/sh\ncat >/dev/null\n[ ! -f "$MOCK_ROOT/fail-destination" ]\n')
    validator.chmod(0o700)
    dnat = root / "dnat-rules.conf"
    dnat.write_text("# empty\n")
    wan = root / "wan-check.sh"
    wan.write_text("#!/bin/sh\nexit 0\n")
    wan.chmod(0o700)
    state = root / "state.json"
    rules = root / "snat-rules.conf"
    config = root / "nat-controller.conf"
    commits = root / "commits"
    env = dict(os.environ, MOCK_ROOT=str(root))
    def mode(value, ip="203.0.113.10"):
        config.write_text(f"MODE={value}\nEXPECTED_WAN_IP={ip}\nDNAT_ALLOWED_INTERFACES=br0\n")
    def get():
        return json.loads(state.read_text())
    def put(data):
        state.write_text(json.dumps(data))
    def count():
        return len(commits.read_text().splitlines()) if commits.exists() else 0
    def run(status, ok=True):
        result = subprocess.run(["/bin/sh", str(engine)], env=env, text=True,
                                capture_output=True, timeout=10)
        assert (result.returncode == 0) == ok, result.stdout + result.stderr
        assert status in result.stdout, result.stdout + result.stderr
        return result
    def native_ok():
        assert [r for r in get()["POSTROUTING"] if r != jump] == [native]
    put({"POSTROUTING": [native]})
    valid = ("1|192.168.1.100|any|tcp|443|WAN_IP\n"
             "1|192.168.1.0/24|any|udp|8000:9000|203.0.113.11\n")
    rules.write_text(valid)
    mode("AUDIT")
    run("DRIFT_DETECTED")
    assert count() == 0
    mode("ENFORCE")
    run("RECONCILED")
    assert count() == 1
    assert get()["POSTROUTING"] == [jump, native]
    assert len(get()["AI_NAT_SNAT"]) == 2
    assert "--dport 443" in get()["AI_NAT_SNAT"][0]
    assert "--dport 8000:9000" in get()["AI_NAT_SNAT"][1]
    native_ok()
    run("IN_SYNC")
    assert count() == 1
    # Reject bad config even after a valid line, without touching existing rules.
    before = get()
    rules.write_text(valid + "invalid\n")
    run("Invalid SNAT configuration", False)
    assert get() == before and count() == 1
    rules.write_text(valid)
    mode("ENFORCE", "203.0.113.99")
    run("primary WAN IP mismatch", False)
    assert get() == before and count() == 1
    mode("ENFORCE")
    # Missing jump and duplicate jump recovery.
    data = get()
    data["POSTROUTING"].remove(jump)
    put(data)
    mode("AUDIT")
    run("DRIFT_DETECTED")
    assert get() == data and count() == 1
    mode("ENFORCE")
    run("RECONCILED")
    data = get()
    data["POSTROUTING"].insert(0, jump)
    put(data)
    run("RECONCILED")
    assert get()["POSTROUTING"] == [jump, native]
    # Missing chain; failed dry-run and failed commit must preserve table.
    put({"POSTROUTING": [native]})
    for marker, message in (("fail-test", "Transaction validation failed"),
                            ("fail-commit", "Transaction commit failed")):
        (root / marker).touch()
        n = count()
        run(message, False)
        assert get() == {"POSTROUTING": [native]} and count() == n
        (root / marker).unlink()
    run("RECONCILED")
    # Empty configuration and disabled cleanup.
    rules.write_text("# empty\n")
    run("RECONCILED")
    assert get()["AI_NAT_SNAT"] == []
    run("IN_SYNC")
    mode("DISABLED")
    run("Status: DISABLED")
    assert get() == {"POSTROUTING": [native]}
    n = count()
    run("already clean")
    assert count() == n
    # Unexpected references are refused, not removed.
    put({"POSTROUTING": [native], "AI_NAT_SNAT": [],
         "OTHER": [jump]})
    before = get()
    run("Unexpected references", False)
    assert get() == before and count() == n
    # Combined v0.4.0 cases.
    dj = "-j AI_NAT_DNAT"
    native_pre = "-d 203.0.113.10/32 -j VSERVER"
    native_dnat = "-p tcp -m tcp --dport 443 -j DNAT --to-destination 192.168.1.101"
    base = {"POSTROUTING": [native], "PREROUTING": [native_pre],
            "VSERVER": [native_dnat]}
    put(base)
    rules.write_text(valid)
    good = "1|WAN_IP|any|tcp|8443|192.168.1.100|443|0\n"
    dnat.write_text(good)
    mode("AUDIT")
    n = count()
    run("DRIFT_DETECTED")
    assert get() == base and count() == n
    mode("ENFORCE")
    run("RECONCILED")
    assert count() == n+1
    assert get()["POSTROUTING"] == [jump, native]
    assert get()["PREROUTING"] == [native_pre, dj]
    assert get()["VSERVER"] == [native_dnat]
    assert len(get()["AI_NAT_DNAT"]) == 1
    tx = (root / "last-transaction").read_text()
    assert "-N AI_NAT_SNAT" in tx and "-N AI_NAT_DNAT" in tx
    run("IN_SYNC")
    assert count() == n+1
    before = get()
    # Invalid DNAT blocks even pending SNAT changes.
    rules.write_text("# empty\n")
    dnat.write_text(good + "bad\n")
    run("Invalid DNAT configuration", False)
    assert get() == before and count() == n+1
    dnat.write_text(good)
    rules.write_text(valid)
    for marker, message in (("fail-destination", "DNAT destination validation failed"),
                            ("no-filter", "Required native DNAT forwarding rule unavailable")):
        (root / marker).touch()
        run(message, False)
        assert get() == before and count() == n+1
        (root / marker).unlink()
    dnat.write_text(good.replace("8443", "443"))
    run("Native DNAT conflict validation failed", False)
    assert get() == before and count() == n+1
    dnat.write_text(good.replace("8443", "443").replace("|0\n", "|1\n"))
    result = run("RECONCILED")
    assert "native conflict overridden" in result.stderr
    tx = (root / "last-transaction").read_text()
    assert "AI_NAT_SNAT" not in tx
    result = run("IN_SYNC")
    assert "Force enabled" in result.stderr
    # SNAT-only drift must leave DNAT unchanged.
    rules.write_text("# empty\n")
    run("RECONCILED")
    assert "AI_NAT_DNAT" not in (root / "last-transaction").read_text()
    # Duplicate/misordered DNAT jump recovery.
    data = get()
    data["PREROUTING"] = [dj, native_pre, dj]
    put(data)
    run("RECONCILED")
    assert get()["PREROUTING"] == [native_pre, dj]
    # Empty DNAT removes owned chain, not native rules.
    dnat.write_text("# empty\n")
    run("RECONCILED")
    assert "AI_NAT_DNAT" not in get() and get()["PREROUTING"] == [native_pre]
    # Missing DNAT file fails rather than silently removing mappings.
    dnat.unlink()
    before = get()
    n = count()
    run("Invalid DNAT configuration", False)
    assert get() == before and count() == n
    dnat.write_text(good)
    run("RECONCILED")
    mode("DISABLED")
    dnat.unlink()
    rules.unlink()
    run("Status: DISABLED")
    assert get() == base
    n = count()
    run("already clean")
    assert count() == n
    # Foreign DNAT reference blocks cleanup even when config is absent.
    put(dict(base, AI_NAT_DNAT=[], OTHER=[dj]))
    before = get()
    run("Unexpected references", False)
    assert get() == before and count() == n
print("Mock reconciliation regression tests passed")
