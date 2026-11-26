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
    shutil.copy(repo / "router/nat-config.awk", root)
    wan = root / "wan-check.sh"
    wan.write_text("#!/bin/sh\nexit 0\n")
    wan.chmod(0o700)
    state = root / "state.json"
    rules = root / "snat-rules.conf"
    config = root / "nat-controller.conf"
    commits = root / "commits"
    env = dict(os.environ, MOCK_ROOT=str(root))
    def mode(value, ip="203.0.113.10"):
        config.write_text(f"MODE={value}\nEXPECTED_WAN_IP={ip}\n")
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
print("Mock reconciliation regression tests passed")
