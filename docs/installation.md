# Installation — development v0.3.0

For experienced administrators with local recovery access. Back up router settings before changes. Use a dedicated test window. Do not expose SSH to the WAN.

1. On the router, create /jffs/custom (mode 700). Copy the router shell scripts (mode 700) and nat-config.awk (mode 600) there. Copy both .conf.example templates to their corresponding .conf names (mode 600). Set EXPECTED_WAN_IP to the actual primary WAN address and review SNAT entries; the example is disabled by default. Start with MODE=AUDIT. Stop an existing scheduler during migration and see the development acceptance document.
2. Enable LAN-only SSH via the ASUS GUI. Verify the AI board can reach the router internal management address (169.254.0.1 on tested hardware).
3. Build router-controller:0.1.0 from docker/Dockerfile using Portainer. Create external named volume router-controller-ssh. Use a temporary Alpine/OpenSSH container with that volume mounted read/write at /root/.ssh to generate a dedicated Ed25519 key (ssh-keygen -t ed25519 -f /root/.ssh/router_controller -N ''). Set directory mode 700 and private key mode 600. Verify the router host public key via an independent trusted session and pin it in known_hosts for the internal address. Never copy private keys into Git.
4. In ASUS Administration > System > Authorized Keys, add the dedicated public key prefixed with:
       command="/jffs/custom/nat-controller.sh",no-port-forwarding,no-agent-forwarding,no-X11-forwarding,no-pty
   Keep other authorised keys intact. Test authentication, forced command, PTY and forwarding restrictions independently before enabling automation.
5. Deploy docker/docker-compose.yml in Portainer, setting ROUTER_USER to your actual router administrator username in stack environment variables. Disable image re-pull for locally built image. Confirm repeated successful AUDIT logs.
6. Only after review, edit MODE=ENFORCE in the general configuration and replace it atomically, observe reconciliation, verify native rules, and verify subsequent IN_SYNC logs. To remove managed rules, set MODE=DISABLED, allow one successful cycle, verify chain and jump removal, then stop the container. Revoke the dedicated key if uninstalling.

For atomic updates, write a sibling .new file, set appropriate permissions, run sh -n for scripts, then mv -f into place. Never flush the native NAT table. Do not use real WAN addresses, credentials or diagnostic logs in public commits.
