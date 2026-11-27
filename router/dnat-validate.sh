#!/bin/sh
# Read-only destination validation. Input: canonical rules from nat-config.awk.
# Arguments: allowed-interface CSV, logical WAN interface, physical WAN interface.
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
fail() { echo "DNAT destination validation: $*" >&2; exit 1; }
[ "$#" -eq 3 ] || [ "$#" -eq 4 ] || fail "expected allowlist, logical WAN, physical WAN and optional --classify"
CLASSIFY=0
if [ "$#" -eq 4 ]; then
    [ "$4" = --classify ] || fail "invalid classification option"
    CLASSIFY=1
fi
# In classification mode emit one target|status record per destination.
# Exit nonzero only for invalid input/policy or classifier failure.
report() {
    echo "DNAT destination $TARGET: $1 ($2)" >&2
    if [ "$CLASSIFY" = 1 ]; then
        printf '%s|%s\n' "$TARGET" "$1"
    else
        [ "$1" = SAFE ] || exit 1
    fi
}
ALLOW="$1"
WAN="$2"
PHYSICAL="$3"
RULES="$(cat)" || fail "cannot read rules"
[ -n "$RULES" ] || exit 0
if [ -z "$ALLOW" ] || [ -z "$WAN" ] || [ -z "$PHYSICAL" ]; then
    fail "missing interface policy"
fi
# Reject unsafe allowlist entries even if not used by a particular rule.
awk -v list="$ALLOW" -v wan="$WAN" -v physical="$PHYSICAL" 'BEGIN {
    n=split(list,a,",")
    for(i=1;i<=n;i++) {
        x=a[i]
        if(x !~ /^[a-zA-Z0-9_][a-zA-Z0-9_.-]*$/ || length(x)>15 ||
           x==wan || x==physical || x=="lo" || x=="eth.ai" ||
           x ~ /^eth[.]ai[-.]/ || x in seen) exit 1
        seen[x]=1
    }
    if(n<1 || n>32) exit 1
}' || fail "unsafe interface allowlist"
# Extract targets only from canonical DNAT rules; never evaluate input as shell.
TARGETS="$(printf '%s\n' "$RULES" | awk '
    function valid(s,a,i) {
        if(split(s,a,"[.]")!=4) return 0
        for(i=1;i<=4;i++)
            if(a[i] !~ /^(0|[1-9][0-9]*)$/ || length(a[i])>3 || a[i]+0>255) return 0
        return a[1]>0 && a[1]!=127 && a[1]<224 && !(a[1]==169 && a[2]==254)
    }
    {
        if($1!="-A" || $2!="AI_NAT_DNAT" || $(NF-2)!="DNAT" ||
           $(NF-3)!="-j" || $(NF-1)!="--to-destination") exit 1
        n=split($NF,t,":")
        if(n>2 || !valid(t[1]) ||
           (n==2 && (t[2] !~ /^[1-9][0-9]*$/ || length(t[2])>5 || t[2]+0>65535))) exit 1
        if(!seen[t[1]]++) print t[1]
    }')" || fail "malformed canonical rules"
[ -n "$TARGETS" ] || fail "no destinations extracted"
INVENTORY_OK=1
ADDR="$(ip -4 addr show)" || INVENTORY_OK=0
LOCAL="$(ip -4 route show table local)" || INVENTORY_OK=0
[ -n "$ADDR" ] && [ -n "$LOCAL" ] || INVENTORY_OK=0
for TARGET in $TARGETS; do
    if [ "$INVENTORY_OK" = 0 ]; then
        report UNVERIFIED "address or local-route inventory unavailable"
        continue
    fi
    # Check all assigned addresses, not just the destination interface.
    printf '%s\n' "$ADDR" | awk -v dst="$TARGET" '
        $1=="inet" {
            split($2,a,"/")
            if(a[1]==dst) bad=1
            for(i=3;i<NF;i++) if($i=="brd" && $(i+1)==dst) bad=1
        }
        END {exit (bad?10:0)}
    '
    RC=$?
    if [ "$RC" != 0 ]; then
        if [ "$RC" = 10 ]; then report UNSAFE "router-local or broadcast"
        else report UNVERIFIED "address inspection failed"; fi
        continue
    fi
    printf '%s\n' "$LOCAL" | awk -v dst="$TARGET" '
        ($1=="local" || $1=="broadcast" || $1=="anycast") &&
        ($2==dst || $2==dst "/32") {bad=1}
        END {exit (bad?10:0)}
    '
    RC=$?
    if [ "$RC" != 0 ]; then
        if [ "$RC" = 10 ]; then report UNSAFE "local/broadcast route"
        else report UNVERIFIED "local route inspection failed"; fi
        continue
    fi
    if ! ROUTE="$(ip -4 route get "$TARGET")"; then
        report UNVERIFIED "route lookup failed"
        continue
    fi
    DEV="$(printf '%s\n' "$ROUTE" | awk -v dst="$TARGET" '
        NR==1 {
            if($1!=dst) exit 1
            for(i=2;i<=NF;i++) {
                if($i=="via") indirect=1
                if($i=="linkdown" || $i=="dead") unavailable=1
                if($i=="dev") {if(++n!=1 || i==NF) exit 1; dev=$(i+1)}
            }
            if(n!=1 || unavailable || dev !~ /^[a-zA-Z0-9_][a-zA-Z0-9_.-]*$/ || length(dev)>15) exit 1
            if(indirect) exit 10
            print dev
        }
        END {if(NR==0) exit 1}
    ')"
    RC=$?
    if [ "$RC" != 0 ]; then
        if [ "$RC" = 10 ]; then report UNSAFE "indirect route"
        else report UNVERIFIED "route unavailable or unsupported"; fi
        continue
    fi
    case ",$ALLOW," in
        *,"$DEV",*) ;;
        *) report UNSAFE "unauthorised interface $DEV"; continue ;;
    esac
    # Confirm target is inside an assigned subnet on the selected interface,
    # and is neither its network nor directed broadcast address.
    # /31 and /32 are deliberately unsupported in this initial LAN policy.
    if ! IFADDR="$(ip -4 addr show dev "$DEV")"; then
        report UNVERIFIED "cannot inspect $DEV"
        continue
    fi
    printf '%s\n' "$IFADDR" | awk -v dst="$TARGET" '
        function num(s,a) {
            split(s,a,"[.]")
            return ((a[1]*256+a[2])*256+a[3])*256+a[4]
        }
        $1=="inet" {
            if(split($2,a,"/")!=2 || a[2] !~ /^[0-9]+$/ || a[2]<1 || a[2]>30) {unsupported=1; next}
            if(split(a[1],oct,"[.]")!=4) {unsupported=1; next}
            for(i=1;i<=4;i++) if(oct[i] !~ /^(0|[1-9][0-9]*)$/ || length(oct[i])>3 || oct[i]+0>255) {unsupported=1; next}
            observed=1
            size=2^(32-a[2])
            base=int(num(a[1])/size)*size
            if(num(dst)>base && num(dst)<base+size-1) good=1
            if(num(dst)==base || num(dst)==base+size-1) bad=1
        }
        END {exit (bad?10:good?0:unsupported?1:observed?10:1)}
    '
    RC=$?
    if [ "$RC" = 10 ]; then report UNSAFE "not a usable host on $DEV"
    elif [ "$RC" != 0 ]; then report UNVERIFIED "subnet inspection unavailable"
    else report SAFE "authorised directly connected host"; fi
done
[ "$CLASSIFY" = 1 ] || echo "DNAT destinations validated"
