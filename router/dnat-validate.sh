#!/bin/sh
# Read-only destination validation. Input: canonical rules from nat-config.awk.
# Arguments: allowed-interface CSV, logical WAN interface, physical WAN interface.
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
fail() { echo "DNAT destination validation: $*" >&2; exit 1; }
[ "$#" -eq 3 ] || fail "expected allowlist, logical WAN and physical WAN"
ALLOW="$1"
WAN="$2"
PHYSICAL="$3"
RULES="$(cat)" || fail "cannot read rules"
[ -n "$RULES" ] || exit 0
[ -n "$ALLOW" ] && [ -n "$WAN" ] && [ -n "$PHYSICAL" ] || fail "missing interface policy"
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
        split($NF,t,":")
        if(!valid(t[1])) exit 1
        if(!seen[t[1]]++) print t[1]
    }')" || fail "malformed canonical rules"
[ -n "$TARGETS" ] || fail "no destinations extracted"
ADDR="$(ip -4 addr show)" || fail "cannot inspect IPv4 addresses"
[ -n "$ADDR" ] || fail "empty IPv4 address inventory"
LOCAL="$(ip -4 route show table local)" || fail "cannot inspect local routes"
[ -n "$LOCAL" ] || fail "empty local route table"
for TARGET in $TARGETS; do
    # Check all assigned addresses, not just the destination interface.
    printf '%s\n' "$ADDR" | awk -v dst="$TARGET" '
        $1=="inet" {
            split($2,a,"/")
            if(a[1]==dst) bad=1
            for(i=3;i<NF;i++) if($i=="brd" && $(i+1)==dst) bad=1
        }
        END {exit bad+0}
    ' || fail "$TARGET is router-local or broadcast"
    printf '%s\n' "$LOCAL" | awk -v dst="$TARGET" '
        ($1=="local" || $1=="broadcast" || $1=="anycast") &&
        ($2==dst || $2==dst "/32") {bad=1}
        END {exit bad+0}
    ' || fail "$TARGET has a local/broadcast route"
    ROUTE="$(ip -4 route get "$TARGET")" || fail "route lookup failed for $TARGET"
    DEV="$(printf '%s\n' "$ROUTE" | awk -v dst="$TARGET" '
        NR==1 {
            if($1!=dst) exit 1
            for(i=2;i<=NF;i++) {
                if($i=="via" || $i=="linkdown" || $i=="dead") exit 1
                if($i=="dev") {if(++n!=1 || i==NF) exit 1; dev=$(i+1)}
            }
            if(n!=1) exit 1
            print dev
        }
        END {if(NR==0) exit 1}
    ')" || fail "$TARGET is not directly routed"
    case ",$ALLOW," in
        *,"$DEV",*) ;;
        *) fail "$TARGET routes through unauthorised interface $DEV" ;;
    esac
    # Confirm target is inside an assigned subnet on the selected interface,
    # and is neither its network nor directed broadcast address.
    # /31 and /32 are deliberately unsupported in this initial LAN policy.
    IFADDR="$(ip -4 addr show dev "$DEV")" || fail "cannot inspect $DEV"
    printf '%s\n' "$IFADDR" | awk -v dst="$TARGET" '
        function num(s,a) {
            split(s,a,"[.]")
            return ((a[1]*256+a[2])*256+a[3])*256+a[4]
        }
        $1=="inet" {
            split($2,a,"/")
            if(a[2] !~ /^[0-9]+$/ || a[2]<1 || a[2]>30) next
            size=2^(32-a[2])
            base=int(num(a[1])/size)*size
            if(num(dst)>base && num(dst)<base+size-1) good=1
            if(num(dst)==base || num(dst)==base+size-1) bad=1
        }
        END {exit (!good || bad)}
    ' || fail "$TARGET is not a usable host on $DEV"
done
echo "DNAT destinations validated"
