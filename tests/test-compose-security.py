#!/usr/bin/env python3
"""Check normalized Compose configuration, without starting a container."""
import copy
import json
import sys


def require(condition, message):
    if not condition:
        raise ValueError(message)


def validate(config):
    require(set(config["services"]) == {"router-controller"}, "unexpected service")
    s = config["services"]["router-controller"]
    require(s.get("read_only") is True, "root filesystem must be read-only")
    require(s.get("privileged", False) is False, "privileged container forbidden")
    require(s.get("cap_drop") == ["ALL"] and not s.get("cap_add"), "capability policy")
    require(set(s.get("security_opt", [])) == {"no-new-privileges:true"},
            "security option policy")
    require(s.get("network_mode") == "host", "expected AI-board host networking")
    require(s.get("init") is True, "init required")
    require(s.get("restart") == "unless-stopped", "restart policy")
    for key in ("devices", "device_cgroup_rules", "pid", "ipc", "uts",
                "userns_mode", "volumes_from", "configs", "secrets", "ports",
                "tmpfs", "build", "entrypoint", "post_start", "pre_stop"):
        require(not s.get(key), f"unexpected {key}")
    mounts = s.get("volumes", [])
    require(len(mounts) == 1, "only dedicated SSH volume allowed")
    m = mounts[0]
    require(m.get("type") == "volume" and m.get("source") == "router-controller-ssh"
            and m.get("target") == "/root/.ssh" and m.get("read_only") is True,
            "SSH volume must be read-only; no bind mounts or Docker socket")
    require(set(config.get("volumes", {})) == {"router-controller-ssh"}
            and config["volumes"]["router-controller-ssh"].get("external") is True,
            "external SSH volume required")
    require(s.get("image") == "router-controller:0.1.0", "unexpected scheduler image")
    require(s.get("logging", {}).get("driver") == "json-file"
            and s["logging"].get("options") == {"max-size": "5m", "max-file": "3"},
            "bounded logging required")
    env = s.get("environment", {})
    require(set(env) == {"ROUTER_USER", "TZ", "RECONCILE_INTERVAL"}
            and env["ROUTER_USER"] == "ci-validation"
            and env["TZ"] == "UTC" and str(env["RECONCILE_INTERVAL"]) == "30",
            "unexpected environment")
    cmd = s.get("command", [])
    require(len(cmd) == 3 and cmd[:2] == ["/bin/sh", "-c"], "scheduler command shape")
    for fragment in ("StrictHostKeyChecking=yes", "BatchMode=yes", "IdentitiesOnly=yes",
                     "timeout -s TERM -k 5 15 ssh -T", "-i /root/.ssh/router_controller",
                     "@169.254.0.1"):
        require(fragment in cmd[2], f"missing SSH safeguard: {fragment}")
    require("StrictHostKeyChecking=no" not in cmd[2], "host verification disabled")


def main():
    config = json.load(sys.stdin)
    validate(config)
    # Prove the check rejects representative regressions.
    mutations = [
        ("privileged", True), ("read_only", False), ("cap_drop", []),
        ("cap_add", ["NET_ADMIN"]), ("security_opt", []),
        ("devices", ["/dev/mem"]), ("pid", "host"),
        ("volumes", [{"type": "bind", "source": "/var/run/docker.sock",
                      "target": "/var/run/docker.sock"}]),
    ]
    for key, value in mutations:
        changed = copy.deepcopy(config)
        changed["services"]["router-controller"][key] = value
        try:
            validate(changed)
        except ValueError:
            continue
        raise RuntimeError(f"negative control accepted: {key}")
    print(f"Compose security contract passed; {len(mutations)} negative controls rejected")


if __name__ == "__main__":
    main()
