#!/bin/sh
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
WAN_PROTO="$(nvram get wan0_proto)" || exit 1
WAN_PHYS="$(nvram get wan0_ifname)" || exit 1
WAN_IF="$(nvram get wan0_gw_ifname)" || exit 1
WAN_IP="$(nvram get wan0_ipaddr)" || exit 1
WAN_STATE="$(nvram get wan0_state_t)" || exit 1
WAN_GW="$(nvram get wan0_gateway)" || exit 1
ROUTE="$(ip -4 route get 1.1.1.1 2>/dev/null)" || exit 1
ROUTE_IF="$(echo "$ROUTE" | awk 'NR==1 {for(i=1;i<NF;i++) if($i=="dev") {print $(i+1); exit}}')"
ROUTE_IP="$(echo "$ROUTE" | awk 'NR==1 {for(i=1;i<NF;i++) if($i=="src") {print $(i+1); exit}}')"
echo "Protocol:           $WAN_PROTO"
echo "Physical interface: $WAN_PHYS"
echo "Logical interface:  $WAN_IF"
echo "WAN address:        $WAN_IP"
echo "Gateway:            $WAN_GW"
echo "WAN state:          $WAN_STATE"
echo "Route interface:    $ROUTE_IF"
echo "Route source:       $ROUTE_IP"
if [ "$WAN_STATE" != "2" ]; then
    echo "ERROR: WAN not connected"
    exit 1
fi
if [ -z "$WAN_IF" ] || [ ! -d "/sys/class/net/$WAN_IF" ]; then
    echo "ERROR: WAN interface unavailable"
    exit 1
fi
if [ -z "$WAN_IP" ] || [ "$WAN_IP" = "0.0.0.0" ]; then
    echo "ERROR: WAN address unavailable"
    exit 1
fi
if [ "$WAN_IF" != "$ROUTE_IF" ]; then
    echo "ERROR: WAN interface mismatch"
    exit 1
fi
if [ "$WAN_IP" != "$ROUTE_IP" ]; then
    echo "ERROR: WAN source address mismatch"
    exit 1
fi
ADDR="$(ip -4 addr show dev "$WAN_IF")" || exit 1
if ! printf '%s\n' "$ADDR" | awk -v ip="$WAN_IP" '
    $1=="inet" {
        split($2,a,"/")
        if(a[1]==ip) found=1
    }
    END {exit !found}
'; then
    echo "ERROR: WAN address not assigned to interface"
    exit 1
fi
echo "WAN validation: OK"
exit 0
