#!/bin/sh
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
VERSION="0.3.0"
BASE="/jffs/custom"
RUNTIME="/tmp/nat-controller"
CHAIN="AI_NAT_SNAT"
umask 077

fail() {
    echo "ERROR: $*"
    logger -t ai-nat-controller "ERROR: $*"
    exit 1
}
mkdir -p "$RUNTIME" || exit 1
exec 9>"$RUNTIME/controller.lock" || exit 1
if ! flock -n 9; then
    echo "SKIP: Controller already running"
    exit 0
fi
GENERAL="$(awk -v kind=general -f "$BASE/nat-config.awk" "$BASE/nat-controller.conf")" ||
    fail "Invalid general configuration"
MODE="$(printf '%s\n' "$GENERAL" | sed -n '1p')"
EXPECTED_WAN_IP="$(printf '%s\n' "$GENERAL" | sed -n '2p')"
case "$MODE" in
    DISABLED|AUDIT|ENFORCE) ;;
    *) fail "Invalid operating mode: $MODE" ;;
esac
echo "Controller: NAT"
echo "Version: $VERSION"
echo "Mode: $MODE"
echo "Timestamp: $(date '+%Y-%m-%d %H:%M:%S %Z')"

if [ "$MODE" != "DISABLED" ]; then
    "$BASE/wan-check.sh" || fail "WAN validation failed"
    WAN_IF="$(nvram get wan0_gw_ifname)"
    WAN_IP="$(nvram get wan0_ipaddr)"
    [ "$WAN_IP" = "$EXPECTED_WAN_IP" ] ||
        fail "Configured primary WAN IP mismatch"
    DESIRED_RULES="$(awk -v kind=snat -v wan_if="$WAN_IF" -v wan_ip="$WAN_IP" -f "$BASE/nat-config.awk" "$BASE/snat-rules.conf")" ||
        fail "Invalid SNAT configuration"
fi
SNAPSHOT="$(iptables -t nat -S)" ||
    fail "Cannot inspect NAT table"
JUMP="-A POSTROUTING -j $CHAIN"
CHAIN_EXISTS="$(printf '%s\n' "$SNAPSHOT" |
    awk -v c="$CHAIN" '$1=="-N" && $2==c {found=1} END {print found+0}')"
JUMP_COUNT="$(printf '%s\n' "$SNAPSHOT" |
    awk -v j="$JUMP" '$0==j {n++} END {print n+0}')"
FIRST_RULE="$(printf '%s\n' "$SNAPSHOT" |
    awk '$1=="-A" && $2=="POSTROUTING" {print; exit}')"
ACTUAL_RULES="$(printf '%s\n' "$SNAPSHOT" |
    awk -v c="$CHAIN" '$1=="-A" && $2==c {print}')"
FOREIGN_REFS="$(printf '%s\n' "$SNAPSHOT" |
    awk -v c="$CHAIN" -v j="$JUMP" '
        $1=="-A" {
            for(i=1;i<NF;i++) {
                if(($i=="-j" || $i=="-g") &&
                   $(i+1)==c && $0!=j)
                    print
            }
        }
    ')"
[ -z "$FOREIGN_REFS" ] || fail "Unexpected references to $CHAIN"
echo "Chain exists: $CHAIN_EXISTS"
echo "Jump count: $JUMP_COUNT"

if [ "$MODE" = "DISABLED" ]; then
    if [ "$CHAIN_EXISTS" = "0" ]; then
        echo "Status: DISABLED (already clean)"
        exit 0
    fi
else
    if [ "$CHAIN_EXISTS" = "1" ] &&
       [ "$JUMP_COUNT" = "1" ] &&
       [ "$FIRST_RULE" = "$JUMP" ] &&
       [ "$ACTUAL_RULES" = "$DESIRED_RULES" ]; then
        echo "Status: IN_SYNC"
        exit 0
    fi
    echo "Status: DRIFT_DETECTED"
    if [ "$MODE" = "AUDIT" ]; then
        echo "Action: None (audit mode)"
        echo "Desired rules:"
        printf '%s\n' "$DESIRED_RULES"
        exit 0
    fi
fi
TRANSACTION="$(
    echo '*nat'
    n="$JUMP_COUNT"
    while [ "$n" -gt 0 ]; do
        echo "-D POSTROUTING -j $CHAIN"
        n=$((n - 1))
    done
    if [ "$MODE" = "DISABLED" ]; then
        echo "-F $CHAIN"
        echo "-X $CHAIN"
    else
        if [ "$CHAIN_EXISTS" = "1" ]; then
            echo "-F $CHAIN"
        else
            echo "-N $CHAIN"
        fi
        if [ -n "$DESIRED_RULES" ]; then
            printf '%s\n' "$DESIRED_RULES"
        fi
        echo "-I POSTROUTING 1 -j $CHAIN"
    fi
    echo 'COMMIT'
)"
echo "--- Proposed transaction ---"
printf '%s\n' "$TRANSACTION"
printf '%s\n' "$TRANSACTION" |
    iptables-restore --test --noflush ||
    fail "Transaction validation failed"
CURRENT="$(iptables -t nat -S)" || fail "Cannot recheck NAT table"
[ "$CURRENT" = "$SNAPSHOT" ] ||
    fail "NAT table changed during reconciliation"
printf '%s\n' "$TRANSACTION" |
    iptables-restore --noflush ||
    fail "Transaction commit failed"
AFTER="$(iptables -t nat -S)" || fail "Cannot verify NAT table"

native_rules() {
    printf '%s\n' "$1" |
        awk -v c="$CHAIN" -v j="$JUMP" '
            $0==j {next}
            ($1=="-N" || $1=="-A") && $2==c {next}
            {print}
        '
}
[ "$(native_rules "$SNAPSHOT")" = "$(native_rules "$AFTER")" ] ||
    fail "Unmanaged NAT configuration changed"

if [ "$MODE" = "DISABLED" ]; then
    if printf '%s\n' "$AFTER" | grep -q "^[-]N $CHAIN\$"; then
        fail "Chain removal verification failed"
    fi
    if printf '%s\n' "$AFTER" | grep -Fxq -- "$JUMP"; then
        fail "Jump removal verification failed"
    fi
    echo "Status: DISABLED"
    logger -t ai-nat-controller "Managed chain removed"
else
    VERIFIED_RULES="$(printf '%s\n' "$AFTER" |
        awk -v c="$CHAIN" '$1=="-A" && $2==c {print}')"
    VERIFIED_JUMPS="$(printf '%s\n' "$AFTER" |
        awk -v j="$JUMP" '$0==j {n++} END {print n+0}')"
    VERIFIED_FIRST="$(printf '%s\n' "$AFTER" |
        awk '$1=="-A" && $2=="POSTROUTING" {print; exit}')"
    [ "$VERIFIED_RULES" = "$DESIRED_RULES" ] &&
    [ "$VERIFIED_JUMPS" = "1" ] &&
    [ "$VERIFIED_FIRST" = "$JUMP" ] ||
        fail "Post-commit verification failed"
    echo "Status: RECONCILED"
    logger -t ai-nat-controller "SNAT configuration reconciled"
fi
exit 0
