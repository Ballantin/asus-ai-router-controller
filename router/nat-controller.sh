#!/bin/sh
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
VERSION="0.4.0"
BASE="/jffs/custom"
RUNTIME="/tmp/nat-controller"
SNAT="AI_NAT_SNAT"
DNAT="AI_NAT_DNAT"
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
META="$RUNTIME/dnat-metadata"
NATIVE="$RUNTIME/nat-snapshot"
cleanup() { rm -f "$META" "$NATIVE"; }
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

GENERAL="$(awk -v kind=general -f "$BASE/nat-config.awk" "$BASE/nat-controller.conf")" ||
    fail "Invalid general configuration"
MODE="$(printf '%s\n' "$GENERAL" | sed -n '1p')"
EXPECTED_WAN_IP="$(printf '%s\n' "$GENERAL" | sed -n '2p')"
ALLOW="$(printf '%s\n' "$GENERAL" | sed -n '3p')"
case "$MODE" in
    DISABLED|AUDIT|ENFORCE) ;;
    *) fail "Invalid operating mode"
esac
echo "Controller: NAT"
echo "Version: $VERSION"
echo "Mode: $MODE"
echo "Timestamp: $(date '+%Y-%m-%d %H:%M:%S %Z')"

SNAT_DESIRED=
DNAT_DESIRED=
FILTER=
validate_destinations() {
    printf '%s\n' "$DNAT_DESIRED" |
        "$BASE/dnat-validate.sh" "$ALLOW" "$WAN_IF" "$WAN_PHYS" ||
        fail "DNAT destination validation failed"
}
read_filter() {
    iptables -t filter -S FORWARD
}
if [ "$MODE" != "DISABLED" ]; then
    "$BASE/wan-check.sh" || fail "WAN validation failed"
    WAN_IF="$(nvram get wan0_gw_ifname)" || fail "Cannot read WAN interface"
    WAN_IP="$(nvram get wan0_ipaddr)" || fail "Cannot read WAN IP"
    [ "$WAN_IP" = "$EXPECTED_WAN_IP" ] || fail "Configured primary WAN IP mismatch"
    SNAT_DESIRED="$(awk -v kind=snat -v wan_if="$WAN_IF" -v wan_ip="$WAN_IP" -f "$BASE/nat-config.awk" "$BASE/snat-rules.conf")" ||
        fail "Invalid SNAT configuration"
    awk -v kind=dnat -v metadata=1 -v wan_if="$WAN_IF" -v wan_ip="$WAN_IP" -f "$BASE/nat-config.awk" "$BASE/dnat-rules.conf" >"$META" ||
        fail "Invalid DNAT configuration"
    DNAT_DESIRED="$(cut -d '|' -f 3 "$META")" || fail "Cannot extract DNAT rules"
    if [ -n "$DNAT_DESIRED" ]; then
        WAN_PHYS="$(nvram get wan0_ifname)" || fail "Cannot read physical WAN"
        validate_destinations
        FILTER="$(read_filter)" || fail "Cannot inspect native FORWARD"
        printf '%s\n' "$FILTER" | grep -Fxq -- '-A FORWARD -m conntrack --ctstate DNAT -j ACCEPT' ||
            fail "Required native DNAT forwarding rule unavailable"
    fi
fi
SNAPSHOT="$(iptables -t nat -S)" || fail "Cannot inspect NAT table"

# Only exact unconditional jumps from their respective built-in chains
# are owned. Reject other references, including references between chains.
check_ownership() {
    printf '%s\n' "$1" | awk '
        $1=="-A" {
            for(i=3;i<NF;i++) {
                if(($i=="-j" || $i=="-g" || $i=="--jump" || $i=="--goto") &&
                   ($(i+1)=="AI_NAT_SNAT" || $(i+1)=="AI_NAT_DNAT") &&
                   $0!="-A POSTROUTING -j AI_NAT_SNAT" &&
                   $0!="-A PREROUTING -j AI_NAT_DNAT") bad=1
            }
        }
        END {exit bad+0}
    '
}
check_ownership "$SNAPSHOT" || fail "Unexpected references to managed chains"
if [ -n "$DNAT_DESIRED" ]; then
    printf '%s\n' "$SNAPSHOT" >"$NATIVE" || fail "Cannot save NAT snapshot"
    awk -v desired_file="$META" -f "$BASE/dnat-conflicts.awk" "$META" "$NATIVE" ||
        fail "Native DNAT conflict validation failed"
fi

# Inspect one chain. Sets EXISTS, JUMPS, DRIFT and ACTUAL in caller.
# An empty DNAT ruleset requires no chain; SNAT retains v0.3 behaviour.
inspect() {
    table="$1"; chain="$2"; hook="$3"; position="$4"; wanted="$5"; enabled="$6"
    jump="-A $hook -j $chain"
    EXISTS="$(printf '%s\n' "$table" | awk -v c="$chain" '$1=="-N" && $2==c {n++} END {print n+0}')"
    JUMPS="$(printf '%s\n' "$table" | awk -v j="$jump" '$0==j {n++} END {print n+0}')"
    ACTUAL="$(printf '%s\n' "$table" | awk -v c="$chain" '$1=="-A" && $2==c {print}')"
    EDGE="$(printf '%s\n' "$table" | awk -v h="$hook" -v p="$position" '
        $1=="-A" && $2==h {last=$0; if(p=="first") exit}
        END {if(last!="") print last}
    ')"
    DRIFT=1
    if [ "$enabled" = 0 ]; then
        if [ "$EXISTS" = 0 ] && [ "$JUMPS" = 0 ] && [ -z "$ACTUAL" ]; then DRIFT=0; fi
    elif [ "$EXISTS" = 1 ] && [ "$JUMPS" = 1 ] &&
         [ "$EDGE" = "$jump" ] && [ "$ACTUAL" = "$wanted" ]; then
        DRIFT=0
    fi
}
SNAT_ENABLED=1
DNAT_ENABLED=0
[ "$MODE" != DISABLED ] || SNAT_ENABLED=0
[ -z "$DNAT_DESIRED" ] || DNAT_ENABLED=1
inspect "$SNAPSHOT" "$SNAT" POSTROUTING first "$SNAT_DESIRED" "$SNAT_ENABLED"
S_EXISTS="$EXISTS"; S_JUMPS="$JUMPS"; S_DRIFT="$DRIFT"
inspect "$SNAPSHOT" "$DNAT" PREROUTING last "$DNAT_DESIRED" "$DNAT_ENABLED"
D_EXISTS="$EXISTS"; D_JUMPS="$JUMPS"; D_DRIFT="$DRIFT"
echo "SNAT chain exists: $S_EXISTS; jump count: $S_JUMPS; drift: $S_DRIFT"
echo "DNAT chain exists: $D_EXISTS; jump count: $D_JUMPS; drift: $D_DRIFT"
if [ "$S_DRIFT" = 0 ] && [ "$D_DRIFT" = 0 ]; then
    if [ "$MODE" = DISABLED ]; then echo "Status: DISABLED (already clean)"
    else echo "Status: IN_SYNC"; fi
    exit 0
fi
echo "Status: DRIFT_DETECTED"
if [ "$MODE" = AUDIT ]; then
    echo "Action: None (audit mode)"
    echo "Desired SNAT rules:"
    printf '%s\n' "$SNAT_DESIRED"
    echo "Desired DNAT rules:"
    printf '%s\n' "$DNAT_DESIRED"
    exit 0
fi

emit_chain() {
    c="$1"; h="$2"; pos="$3"; exists="$4"; n="$5"; on="$6"; desired="$7"
    while [ "$n" -gt 0 ]; do
        echo "-D $h -j $c"
        n=$((n-1))
    done
    if [ "$on" = 0 ]; then
        if [ "$exists" = 1 ]; then
            echo "-F $c"
            echo "-X $c"
        fi
    else
        if [ "$exists" = 1 ]; then echo "-F $c"; else echo "-N $c"; fi
        if [ -n "$desired" ]; then printf '%s\n' "$desired"; fi
        if [ "$pos" = first ]; then echo "-I $h 1 -j $c"
        else echo "-A $h -j $c"; fi
    fi
}
TRANSACTION="$(
    echo '*nat'
    if [ "$S_DRIFT" = 1 ]; then
        emit_chain "$SNAT" POSTROUTING first "$S_EXISTS" "$S_JUMPS" "$SNAT_ENABLED" "$SNAT_DESIRED"
    fi
    if [ "$D_DRIFT" = 1 ]; then
        emit_chain "$DNAT" PREROUTING last "$D_EXISTS" "$D_JUMPS" "$DNAT_ENABLED" "$DNAT_DESIRED"
    fi
    echo COMMIT
)"
echo "--- Proposed transaction ---"
printf '%s\n' "$TRANSACTION"
printf '%s\n' "$TRANSACTION" | iptables-restore --test --noflush ||
    fail "Transaction validation failed"
if [ "$MODE" != DISABLED ]; then
    "$BASE/wan-check.sh" || fail "WAN changed before commit"
    [ "$(nvram get wan0_gw_ifname)" = "$WAN_IF" ] &&
    [ "$(nvram get wan0_ipaddr)" = "$WAN_IP" ] || fail "WAN changed before commit"
    if [ -n "$DNAT_DESIRED" ]; then
        [ "$(nvram get wan0_ifname)" = "$WAN_PHYS" ] || fail "Physical WAN changed before commit"
        validate_destinations
        FILTER_NOW="$(read_filter)" || fail "Cannot recheck native FORWARD"
        [ "$FILTER_NOW" = "$FILTER" ] || fail "Native FORWARD changed during reconciliation"
    fi
fi
CURRENT="$(iptables -t nat -S)" || fail "Cannot recheck NAT table"
[ "$CURRENT" = "$SNAPSHOT" ] || fail "NAT table changed during reconciliation"
printf '%s\n' "$TRANSACTION" | iptables-restore --noflush ||
    fail "Transaction commit failed"
AFTER="$(iptables -t nat -S)" || fail "Cannot verify NAT table"
native_rules() {
    printf '%s\n' "$1" | awk '
        $0=="-A POSTROUTING -j AI_NAT_SNAT" || $0=="-A PREROUTING -j AI_NAT_DNAT" {next}
        ($1=="-N" || $1=="-A") && ($2=="AI_NAT_SNAT" || $2=="AI_NAT_DNAT") {next}
        {print}
    '
}
[ "$(native_rules "$SNAPSHOT")" = "$(native_rules "$AFTER")" ] ||
    fail "Unmanaged NAT configuration changed"
check_ownership "$AFTER" || fail "Unexpected references after commit"
inspect "$AFTER" "$SNAT" POSTROUTING first "$SNAT_DESIRED" "$SNAT_ENABLED"
[ "$DRIFT" = 0 ] || fail "SNAT post-commit verification failed"
inspect "$AFTER" "$DNAT" PREROUTING last "$DNAT_DESIRED" "$DNAT_ENABLED"
[ "$DRIFT" = 0 ] || fail "DNAT post-commit verification failed"
if [ -n "$DNAT_DESIRED" ]; then
    FILTER_NOW="$(read_filter)" || fail "Cannot verify native FORWARD"
    [ "$FILTER_NOW" = "$FILTER" ] || fail "Native FORWARD changed after commit"
fi
if [ "$MODE" = DISABLED ]; then
    echo "Status: DISABLED"
    logger -t ai-nat-controller "Managed chains removed"
else
    echo "Status: RECONCILED"
    logger -t ai-nat-controller "NAT configuration reconciled"
fi
exit 0
