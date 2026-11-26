# POSIX awk parser; output canonical iptables -S syntax only on success.
# Usage: awk -v kind=general -f nat-config.awk nat-controller.conf
# or: awk -v kind=snat -v wan_if=... -v wan_ip=... -f nat-config.awk snat-rules.conf
function reject(msg) {
    print FILENAME ":" FNR ": " msg > "/dev/stderr"
    bad=1
    exit 1
}
function uint(s,max) {
    return s ~ /^(0|[1-9][0-9]*)$/ && length(s)<=5 && s+0<=max
}
function ipv4(s, a,n,i) {
    n=split(s,a,"[.]")
    if(n!=4) return 0
    for(i=1;i<=4;i++) if(!uint(a[i],255)) return 0
    return 1
}
function cidr(s, a,b,n,p,i,block) {
    n=split(s,a,"/")
    if(n>2 || !ipv4(a[1])) reject("invalid IPv4 address or CIDR")
    p=32
    if(n==2) {
        if(!uint(a[2],32)) reject("invalid CIDR prefix")
        p=a[2]+0
    }
    # Require network-aligned CIDRs; avoid silent normalisation.
    split(a[1],b,"[.]")
    for(i=1;i<=4;i++) {
        block=2^(8-(p>=8?8:p))
        if((b[i]+0)%block!=0) reject("CIDR has host bits set")
        p=(p>=8?p-8:0)
    }
    return a[1] "/" (n==2?a[2]:32)
}
function port(s,a,n) {
    n=split(s,a,":")
    if(n>2 || !uint(a[1],65535) || a[1]+0<1) reject("invalid port")
    if(n==2 && (!uint(a[2],65535) || a[2]+0<a[1]+0)) reject("invalid port range")
    return n==2 && a[1]+0==a[2]+0?a[1]:s
}
BEGIN {
    if(kind!="general" && kind!="snat" && kind!="dnat") reject("invalid parser mode")
    if((kind=="snat" || kind=="dnat") && (!ipv4(wan_ip) || wan_if !~ /^[a-zA-Z0-9_][a-zA-Z0-9_.-]*$/ || length(wan_if)>15))
        reject("invalid WAN parameters")
}
 /^[ \t]*($|#)/ {next}
{
    if(kind=="general") {
        if($0 ~ /[ \t\r]/ || split($0,f,"=")!=2) reject("expected KEY=VALUE")
        if(f[1]=="MODE") {
            if(seenmode++ || f[2] !~ /^(DISABLED|AUDIT|ENFORCE)$/) reject("invalid or duplicate MODE")
            mode=f[2]
        } else if(f[1]=="EXPECTED_WAN_IP") {
            if(seenip++ || !ipv4(f[2])) reject("invalid or duplicate EXPECTED_WAN_IP")
            expected=f[2]
        } else reject("unknown configuration key")
        next
    }
    if($0 ~ /[ \t\r]/ || split($0,f,"[|]")!=6) reject("expected six pipe-delimited fields")
    if(f[1] !~ /^(0|1)$/) reject("invalid enabled flag")
    if(kind=="dnat") {
        public_ip=(f[2]=="WAN_IP"?wan_ip:f[2])
        if(!ipv4(public_ip) || public_ip=="0.0.0.0") reject("invalid external IPv4 address")
        if(f[3]!="tcp" && f[3]!="udp") reject("DNAT requires tcp or udp")
        if(!uint(f[4],65535) || f[4]+0<1) reject("invalid external port")
        if(!ipv4(f[5]) || f[5]=="0.0.0.0") reject("invalid internal IPv4 address")
        if(!uint(f[6],65535) || f[6]+0<1) reject("invalid internal port")
        if(f[1]=="0") next
        key=public_ip "|" f[3] "|" f[4]
        if(dnat_seen[key]++) reject("duplicate enabled external address/protocol/port")
        rules[++count]="-A AI_NAT_DNAT -d " public_ip "/32 -i " wan_if " -p " f[3] " -m " f[3] " --dport " f[4] " -j DNAT --to-destination " f[5] ":" f[6]
        next
    }
    src=cidr(f[2])
    dst=(f[3]=="any"?"0.0.0.0/0":cidr(f[3]))
    proto=f[4]
    if(proto !~ /^(any|tcp|udp|icmp)$/) reject("unsupported protocol")
    p=f[5]
    if(p!="any") {
        if(proto!="tcp" && proto!="udp") reject("ports require tcp or udp")
        p=port(p)
    }
    target=(f[6]=="WAN_IP"?wan_ip:f[6])
    if(!ipv4(target)) reject("invalid translation address")
    if(f[1]=="0") next
    rule="-A AI_NAT_SNAT"
    if(src!="0.0.0.0/0") rule=rule " -s " src
    if(dst!="0.0.0.0/0") rule=rule " -d " dst
    rule=rule " -o " wan_if
    if(proto!="any") rule=rule " -p " proto
    if(p!="any") rule=rule " -m " proto " --dport " p
    rule=rule " -j SNAT --to-source " target
    rules[++count]=rule
}
END {
    if(bad) exit 1
    if(kind=="general") {
        if(!seenmode || !seenip) reject("MODE and EXPECTED_WAN_IP required")
        print mode
        print expected
    } else for(i=1;i<=count;i++) print rules[i]
}
