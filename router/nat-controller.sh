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
GENERAL_COPY="$RUNTIME/general.conf"
SNAT_COPY="$RUNTIME/snat.conf"
DNAT_COPY="$RUNTIME/dnat.conf"
# Cleanup is invoked by EXIT trap, not by a direct call.
# shellcheck disable=SC2317
cleanup() { rm -f "$META" "$NATIVE" "$GENERAL_COPY" "$SNAT_COPY" "$DNAT_COPY"; }
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

cp "$BASE/nat-controller.conf" "$GENERAL_COPY" || fail "Cannot snapshot general configuration"
GENERAL="$(awk -v kind=general -f "$BASE/nat-config.awk" "$GENERAL_COPY")" ||
    fail "Invalid general configuration"
MODE="$(printf '%s\n' "$GENERAL" | sed -n '1p')"
EXPECTED_WAN_IP="$(printf '%s\n' "$GENERAL" | sed -n '2p')"
ALLOW="$(printf '%s\n' "$GENERAL" | sed -n '3p')"
POLICY="$(printf '%s\n' "$GENERAL" | sed -n '4p')"
case "$POLICY" in
    PRESERVE|WITHDRAW_UNSAFE|WITHDRAW_UNVERIFIED) ;;
    *) fail "Invalid runtime policy" ;;
esac
case "$MODE" in
    DISABLED|AUDIT|ENFORCE) ;;
    *) fail "Invalid operating mode"
esac
echo "Controller: NAT"
echo "Version: $VERSION"
echo "Mode: $MODE"
echo "Timestamp: $(date '+%Y-%m-%d %H:%M:%S %Z')"

# Parse immutable copies; compare their exact bytes with the live files.
# DISABLED deliberately requires only the general configuration.
check_config() {
    cmp -s "$GENERAL_COPY" "$BASE/nat-controller.conf" ||
        fail "General configuration changed during reconciliation"
    if [ "$MODE" != DISABLED ]; then
        cmp -s "$SNAT_COPY" "$BASE/snat-rules.conf" ||
            fail "SNAT configuration changed during reconciliation"
        cmp -s "$DNAT_COPY" "$BASE/dnat-rules.conf" ||
            fail "DNAT configuration changed during reconciliation"
    fi
}
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
# Inspect installed destinations independently, before proposed-rule validation.
# Only an explicit classification can authorise withdrawal. No raw snapshot
# rule is re-emitted: delete affected entries by descending rule number.
runtime_plan() {
    installed="$1"
    classes="$(printf '%s\n' "$installed" |
        "$BASE/dnat-validate.sh" "$ALLOW" "$WAN_IF" "$WAN_PHYS" --classify)" || return 1
    # Require complete, unique, recognised classification records for every
    # installed destination. The validator rejects unsupported rule targets.
    printf '%s\n' "$installed" | awk -v classes="$classes" -v policy="$POLICY" '
        BEGIN {
            n=split(classes,records,"\n")
            for(i=1;i<=n;i++) {
                if(split(records[i],a,"[|]")!=2 || a[1] in status ||
                   a[2] !~ /^(SAFE|UNSAFE|UNVERIFIED)$/) {bad=1; exit 1}
                status[a[1]]=a[2]
            }
        }
        {
            split($NF,t,":")
            if(!(t[1] in status)) {bad=1; exit 1}
            used[t[1]]=1
            if((status[t[1]]=="UNSAFE" && policy!="PRESERVE") ||
               (status[t[1]]=="UNVERIFIED" && policy=="WITHDRAW_UNVERIFIED"))
                remove[NR]=1
        }
        END {
            if(bad) exit 1
            for(k in status) if(!(k in used)) exit 1
            for(i=NR;i>=1;i--) if(remove[i]) print i
        }'
}
# Compare full snapshot after removing precisely the indexed DNAT entries.
# Retain the existing jump and chain (even if empty) for this safety-only
# transaction. Ordinary desired-state reconciliation handles later cleanup.
withdraw_expected() {
    printf '%s\n' "$SNAPSHOT" | awk -v positions="$1" '
        BEGIN {n=split(positions,a,"\n"); for(i=1;i<=n;i++) remove[a[i]]=1}
        $1=="-A" && $2=="AI_NAT_DNAT" {if(remove[++idx]) next}
        {print}'
}
runtime_safety() {
    [ "$MODE" != DISABLED ] || return 0
    INSTALLED="$(printf '%s\n' "$SNAPSHOT" |
        awk '$1=="-A" && $2=="AI_NAT_DNAT" {print}')" ||
        fail "Cannot inspect installed DNAT"
    [ -n "$INSTALLED" ] || return 0
    WAN_IF="$(nvram get wan0_gw_ifname)" || fail "Cannot read runtime WAN interface"
    WAN_PHYS="$(nvram get wan0_ifname)" || fail "Cannot read runtime physical WAN"
    PLAN="$(runtime_plan "$INSTALLED")" || fail "Installed DNAT classification failed"
    [ -n "$PLAN" ] || return 0
    echo "WARNING: Runtime DNAT withdrawal candidate rule numbers:"
    printf '%s\n' "$PLAN"
    if [ "$MODE" = AUDIT ]; then
        echo "Action: None (audit mode)"
        return 0
    fi
    EXPECTED="$(withdraw_expected "$PLAN")" || fail "Cannot calculate withdrawal result"
    SAFETY_TX="$(
        echo '*nat'
        for index in $PLAN; do echo "-D AI_NAT_DNAT $index"; done
        echo COMMIT
    )"
    printf '%s\n' "$SAFETY_TX" | iptables-restore --test --noflush ||
        fail "Runtime withdrawal transaction validation failed"
    NOW_IF="$(nvram get wan0_gw_ifname)" || fail "Cannot recheck runtime WAN interface"
    NOW_PHYS="$(nvram get wan0_ifname)" || fail "Cannot recheck runtime physical WAN"
    if [ "$NOW_IF" != "$WAN_IF" ] || [ "$NOW_PHYS" != "$WAN_PHYS" ]; then
        fail "WAN interfaces changed during runtime withdrawal"
    fi
    RECHECK="$(runtime_plan "$INSTALLED")" || fail "Runtime withdrawal reclassification failed"
    [ "$PLAN" = "$RECHECK" ] || fail "Runtime destination classification changed"
    cmp -s "$GENERAL_COPY" "$BASE/nat-controller.conf" ||
        fail "General configuration changed during runtime withdrawal"
    CURRENT="$(iptables -t nat -S)" || fail "Cannot recheck NAT before withdrawal"
    [ "$CURRENT" = "$SNAPSHOT" ] || fail "NAT table changed during runtime withdrawal"
    printf '%s\n' "$SAFETY_TX" | iptables-restore --noflush ||
        fail "Runtime withdrawal commit failed"
    AFTER="$(iptables -t nat -S)" || fail "Cannot verify runtime withdrawal"
    [ "$AFTER" = "$EXPECTED" ] || fail "Runtime withdrawal verification failed"
    echo "Status: DNAT_WITHDRAWN"
    logger -t ai-nat-controller "WARNING: Unsafe or unverified DNAT mappings withdrawn; existing conntrack may survive"
    # Never mix safety-only withdrawal and desired-state installation in
    # one cycle. Next cycle independently validates the complete proposal.
    exit 1
}
runtime_safety
if [ "$MODE" != "DISABLED" ]; then
    cp "$BASE/snat-rules.conf" "$SNAT_COPY" || fail "Invalid SNAT configuration: cannot snapshot"
    cp "$BASE/dnat-rules.conf" "$DNAT_COPY" || fail "Invalid DNAT configuration: cannot snapshot"
    check_config
    "$BASE/wan-check.sh" || fail "WAN validation failed"
    WAN_IF="$(nvram get wan0_gw_ifname)" || fail "Cannot read WAN interface"
    WAN_IP="$(nvram get wan0_ipaddr)" || fail "Cannot read WAN IP"
    [ "$WAN_IP" = "$EXPECTED_WAN_IP" ] || fail "Configured primary WAN IP mismatch"
    SNAT_DESIRED="$(awk -v kind=snat -v wan_if="$WAN_IF" -v wan_ip="$WAN_IP" -f "$BASE/nat-config.awk" "$SNAT_COPY")" ||
        fail "Invalid SNAT configuration"
    awk -v kind=dnat -v metadata=1 -v wan_if="$WAN_IF" -v wan_ip="$WAN_IP" -f "$BASE/nat-config.awk" "$DNAT_COPY" >"$META" ||
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
    EXISTS="$(printf '%s\n' "$table" | awk -v c="$chain" '$1=="-N" && $2==c {n++} END {print n+0}')" || fail "Cannot inspect managed chain $chain"
    JUMPS="$(printf '%s\n' "$table" | awk -v j="$jump" '$0==j {n++} END {print n+0}')" || fail "Cannot inspect managed chain $chain"
    ACTUAL="$(printf '%s\n' "$table" | awk -v c="$chain" '$1=="-A" && $2==c {print}')" || fail "Cannot inspect managed chain $chain"
    EDGE="$(printf '%s\n' "$table" | awk -v h="$hook" -v p="$position" '
        $1=="-A" && $2==h {last=$0; if(p=="first") exit}
        END {if(last!="") print last}
    ')" || fail "Cannot inspect managed hook $hook"
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
check_config
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
    NOW_IF="$(nvram get wan0_gw_ifname)" || fail "Cannot recheck WAN interface"
    NOW_IP="$(nvram get wan0_ipaddr)" || fail "Cannot recheck WAN IP"
    if [ "$NOW_IF" != "$WAN_IF" ] || [ "$NOW_IP" != "$WAN_IP" ]; then
        fail "WAN changed before commit"
    fi
    if [ -n "$DNAT_DESIRED" ]; then
        NOW_PHYS="$(nvram get wan0_ifname)" || fail "Cannot recheck physical WAN"
        [ "$NOW_PHYS" = "$WAN_PHYS" ] || fail "Physical WAN changed before commit"
        validate_destinations
        FILTER_NOW="$(read_filter)" || fail "Cannot recheck native FORWARD"
        [ "$FILTER_NOW" = "$FILTER" ] || fail "Native FORWARD changed during reconciliation"
    fi
fi
check_config
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
NATIVE_BEFORE="$(native_rules "$SNAPSHOT")" || fail "Cannot inspect original unmanaged NAT"
NATIVE_AFTER="$(native_rules "$AFTER")" || fail "Cannot inspect committed unmanaged NAT"
[ "$NATIVE_BEFORE" = "$NATIVE_AFTER" ] ||
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
