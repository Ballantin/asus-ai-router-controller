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
bad '1|192.168.1.100|any|tcp|443|$(id)'
[ "$(awk -v kind=general -f "$P" router/nat-controller.conf.example)" = 'AUDIT
203.0.113.10' ]
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
dnat_check '1|WAN_IP|tcp|8443|192.168.1.100|443
1|203.0.113.11|udp|51820|192.168.1.101|51820' '-A AI_NAT_DNAT -d 203.0.113.10/32 -i ppp0 -p tcp -m tcp --dport 8443 -j DNAT --to-destination 192.168.1.100:443
-A AI_NAT_DNAT -d 203.0.113.11/32 -i ppp0 -p udp -m udp --dport 51820 -j DNAT --to-destination 192.168.1.101:51820'
dnat_check '0|WAN_IP|tcp|8443|192.168.1.100|443' ''
dnat_bad '1|WAN_IP|any|8443|192.168.1.100|443'
dnat_bad '1|WAN_IP|tcp|0|192.168.1.100|443'
dnat_bad '1|WAN_IP|tcp|8443|192.168.1.100|65536'
dnat_bad '1|WAN_IP|tcp|8000:9000|192.168.1.100|443'
dnat_bad '1|WAN_IP|tcp|8443|192.168.1.0/24|443'
dnat_bad '1|any|tcp|8443|192.168.1.100|443'
dnat_bad '1|WAN_IP|tcp|8443|192.168.1.999|443'
dnat_bad '0|WAN_IP|tcp|8443|192.168.1.100|$(id)'
dnat_bad '1|WAN_IP|tcp|8443|192.168.1.100|443
1|203.0.113.10|tcp|8443|192.168.1.101|443'
out="$(printf '%s\n' '1|WAN_IP|tcp|8443|192.168.1.100|443' 'invalid' | parse_dnat 2>/dev/null)" && exit 1
[ -z "$out" ]
[ -z "$(parse_dnat < router/dnat-rules.conf.example)" ]
sh -n router/nat-controller.sh
sh -n router/wan-check.sh
echo 'Parser regression tests passed'
