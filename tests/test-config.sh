#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
P=router/nat-config.awk
parse() {
    awk -v kind=snat -v wan_if=ppp0 -v wan_ip=203.0.113.10 -f "$P"
}
check() {
    got="$(printf '%s\n' "$1" | parse)"
    [ "$got" = "$2" ] || { printf 'Unexpected output: %s\n' "$got"; exit 1; }
}
bad() {
    if printf '%s\n' "$1" | parse >/dev/null 2>&1; then
        printf 'Accepted invalid input: %s\n' "$1"; exit 1
    fi
}
check '1|192.168.1.100|198.51.100.20|tcp|443|WAN_IP' '-A AI_NAT_SNAT -s 192.168.1.100/32 -d 198.51.100.20/32 -o ppp0 -p tcp -m tcp --dport 443 -j SNAT --to-source 203.0.113.10'
check '1|192.168.1.0/24|any|udp|8000:9000|203.0.113.11' '-A AI_NAT_SNAT -s 192.168.1.0/24 -o ppp0 -p udp -m udp --dport 8000:9000 -j SNAT --to-source 203.0.113.11'
check '1|0.0.0.0/0|any|any|any|WAN_IP' '-A AI_NAT_SNAT -o ppp0 -j SNAT --to-source 203.0.113.10'
check '0|192.168.1.100|any|icmp|any|WAN_IP' ''
check '1|192.168.1.100|any|icmp|any|WAN_IP
1|192.168.1.100|any|tcp|any|203.0.113.11' '-A AI_NAT_SNAT -s 192.168.1.100/32 -o ppp0 -p icmp -j SNAT --to-source 203.0.113.10
-A AI_NAT_SNAT -s 192.168.1.100/32 -o ppp0 -p tcp -j SNAT --to-source 203.0.113.11'
bad '1|192.168.1.256|any|tcp|443|WAN_IP'
bad '1|192.168.1.1/24|any|tcp|443|WAN_IP'
bad '1|192.168.1.0/33|any|tcp|443|WAN_IP'
bad '1|192.168.1.100|any|icmp|443|WAN_IP'
bad '1|192.168.1.100|any|tcp|9000:8000|WAN_IP'
bad '1|192.168.1.100|any|tcp|65536|WAN_IP'
bad '1|192.168.1.100|any|gre|any|WAN_IP'
bad '1|192.168.1.100|any|tcp|443'
bad '0|invalid|any|tcp|443|WAN_IP'
# Literal shell injection fixture; must not expand.
# shellcheck disable=SC2016
bad '1|192.168.1.100|any|tcp|443|$(id)'
[ "$(awk -v kind=general -f "$P" router/nat-controller.conf.example)" = 'AUDIT
203.0.113.10
br0
WITHDRAW_UNSAFE' ]
if printf 'MODE=AUDIT\nMODE=ENFORCE\nEXPECTED_WAN_IP=203.0.113.10\n' | awk -v kind=general -f "$P" >/dev/null 2>&1; then exit 1; fi
check '1|192.168.1.100|any|tcp|443:443|WAN_IP' '-A AI_NAT_SNAT -s 192.168.1.100/32 -o ppp0 -p tcp -m tcp --dport 443 -j SNAT --to-source 203.0.113.10'
check '# comment

0|192.168.1.100|any|udp|53|WAN_IP' ''
bad '1|192.168.01.100|any|tcp|443|WAN_IP'
bad '1|192.168.1.100|any|tcp|0|WAN_IP'
bad '1|192.168.1.100|any|tcp|443|WAN_IP|extra'
bad '1|192.168.1.100|any|tcp|443|WAN_IP # comment'
bad '1|192.168.1.100|any|any|443|WAN_IP'
# No output from a partially valid file.
out="$(printf '%s\n' '1|192.168.1.100|any|tcp|443|WAN_IP' 'invalid' | parse 2>/dev/null)" && exit 1
[ -z "$out" ]
parse_dnat() {
    awk -v kind=dnat -v wan_if=ppp0 -v wan_ip=203.0.113.10 -f "$P"
}
dnat_check() {
    got="$(printf '%s\n' "$1" | parse_dnat)"
    [ "$got" = "$2" ] || { printf 'Unexpected DNAT output: %s\n' "$got"; exit 1; }
}
dnat_bad() {
    if printf '%s\n' "$1" | parse_dnat >/dev/null 2>&1; then
        printf 'Accepted invalid DNAT input: %s\n' "$1"; exit 1
    fi
}
dnat_check '1|WAN_IP|any|tcp|8443|192.168.1.100|443|0
1|203.0.113.11|198.51.100.0/24|udp|51820|192.168.1.101|same|0' '-A AI_NAT_DNAT -d 203.0.113.10/32 -i ppp0 -p tcp -m tcp --dport 8443 -j DNAT --to-destination 192.168.1.100:443
-A AI_NAT_DNAT -s 198.51.100.0/24 -d 203.0.113.11/32 -i ppp0 -p udp -m udp --dport 51820 -j DNAT --to-destination 192.168.1.101'
dnat_check '1|WAN_IP|any|both|80,100:102|192.168.1.100|same|0' '-A AI_NAT_DNAT -d 203.0.113.10/32 -i ppp0 -p tcp -m tcp --dport 80 -j DNAT --to-destination 192.168.1.100
-A AI_NAT_DNAT -d 203.0.113.10/32 -i ppp0 -p udp -m udp --dport 80 -j DNAT --to-destination 192.168.1.100
-A AI_NAT_DNAT -d 203.0.113.10/32 -i ppp0 -p tcp -m tcp --dport 100:102 -j DNAT --to-destination 192.168.1.100
-A AI_NAT_DNAT -d 203.0.113.10/32 -i ppp0 -p udp -m udp --dport 100:102 -j DNAT --to-destination 192.168.1.100'
dnat_check '0|WAN_IP|any|tcp|8443|192.168.1.100|443|0' ''
printf '%s\n' '1|WAN_IP|198.51.100.0/25|tcp|443|192.168.1.100|same|0' '1|WAN_IP|198.51.100.128/25|tcp|443|192.168.1.101|same|0' | parse_dnat >/dev/null
dnat_bad '1|WAN_IP|any|any|8443|192.168.1.100|443|0'
dnat_bad '1|WAN_IP|any|tcp|0|192.168.1.100|443|0'
dnat_bad '1|WAN_IP|any|tcp|8443|192.168.1.100|65536|0'
dnat_bad '1|WAN_IP|any|tcp|8000:9000|192.168.1.100|443|0'
dnat_bad '1|WAN_IP|any|tcp|8443|192.168.1.0/24|443|0'
dnat_bad '1|any|any|tcp|8443|192.168.1.100|443|0'
dnat_bad '1|WAN_IP|any|tcp|8443|192.168.1.999|443|0'
# Literal shell injection fixture; must not expand.
# shellcheck disable=SC2016
dnat_bad '0|WAN_IP|any|tcp|8443|192.168.1.100|$(id)|0'
dnat_bad '1|WAN_IP|any|tcp|8443|127.0.0.1|443|0'
dnat_bad '1|WAN_IP|any|tcp|8443|169.254.0.2|443|0'
dnat_bad '1|WAN_IP|any|tcp|80,|192.168.1.100|same|0'
dnat_bad '1|WAN_IP|any|both|80,79:81|192.168.1.100|same|0'
dnat_bad '1|WAN_IP|any|tcp|8443|192.168.1.100|443|0
1|203.0.113.10|198.51.100.0/24|tcp|8443|192.168.1.101|443|0'
dnat_bad '1|WAN_IP|198.51.100.0/24|both|8000:9000|192.168.1.100|same|0
1|WAN_IP|198.51.100.128/25|udp|8500|192.168.1.101|same|0'
out="$(printf '%s\n' '1|WAN_IP|any|tcp|8443|192.168.1.100|443|0' 'invalid' | parse_dnat 2>/dev/null)" && exit 1
[ -z "$out" ]
[ -z "$(parse_dnat < router/dnat-rules.conf.example)" ]
dnat_bad '1|WAN_IP|any|tcp|8443|192.168.1.100|443|2'
dnat_bad '0|WAN_IP|any|tcp|8443|192.168.1.100|443|yes'
dnat_bad '1|WAN_IP|any|tcp|8443|192.168.1.100|443'
dnat_bad '1|WAN_IP|any|tcp|8443|127.0.0.1|443|1'
dnat_bad '1|WAN_IP|any|tcp|8443|192.168.1.100|443|1
1|WAN_IP|any|tcp|8443|192.168.1.101|443|0'
dnat_check '1|WAN_IP|any|tcp|8443|192.168.1.100|443|1' '-A AI_NAT_DNAT -d 203.0.113.10/32 -i ppp0 -p tcp -m tcp --dport 8443 -j DNAT --to-destination 192.168.1.100:443'
meta="$(printf '%s\n' '# header' '1|WAN_IP|any|both|80,81|192.168.1.100|same|1' '0|WAN_IP|any|tcp|82|192.168.1.100|same|0' '1|WAN_IP|any|tcp|83|192.168.1.100|same|0' | awk -v kind=dnat -v metadata=1 -v wan_if=ppp0 -v wan_ip=203.0.113.10 -f "$P")"
[ "$(printf '%s\n' "$meta" | cut -d '|' -f 1,2)" = '1|2
1|2
1|2
1|2
0|4' ]
for policy in PRESERVE WITHDRAW_UNSAFE WITHDRAW_UNVERIFIED; do
    got="$(printf '%s\n' 'MODE=AUDIT' 'EXPECTED_WAN_IP=203.0.113.10' "DNAT_RUNTIME_POLICY=$policy" | awk -v kind=general -f "$P")"
    [ "$(printf '%s\n' "$got" | sed -n '4p')" = "$policy" ]
done
for invalid in 'DNAT_RUNTIME_POLICY=invalid' 'DNAT_RUNTIME_POLICY=' 'DNAT_RUNTIME_POLICY=PRESERVE
DNAT_RUNTIME_POLICY=WITHDRAW_UNSAFE'; do
    if printf '%s\n' 'MODE=AUDIT' 'EXPECTED_WAN_IP=203.0.113.10' "$invalid" | awk -v kind=general -f "$P" >/dev/null 2>&1; then exit 1; fi
done
sh -n router/nat-controller.sh
sh -n router/wan-check.sh
echo 'Parser regression tests passed'
