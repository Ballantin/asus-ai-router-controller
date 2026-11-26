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
# Numeric network interval for overlap checking (IPv4 fits exactly in awk doubles).
function ipnum(s, a) {
    split(s,a,"[.]")
    return ((a[1]*256+a[2])*256+a[3])*256+a[4]
}
function hostaddr(s, a) {
    if(!ipv4(s)) return 0
    split(s,a,"[.]")
    return a[1]>0 && a[1]!=127 && a[1]<224 && !(a[1]==169 && a[2]==254)
}
function iface(s) {
    return s ~ /^[a-zA-Z0-9_][a-zA-Z0-9_.-]*$/ && length(s)<=15
}
function dnat_rule(proto, p, lo, hi, net, bits, low, high, i, r, a) {
    split(p,a,":")
    lo=a[1]+0
    hi=(a[2]==""?lo:a[2]+0)
    split(src,a,"/")
    low=ipnum(a[1])
    high=low+2^(32-a[2])-1
    for(i=1;i<=count;i++)
        if(dip[i]==public_ip && dproto[i]==proto && lo<=dhi[i] && hi>=dlo[i] && low<=dhigh[i] && high>=dlow[i])
            reject("overlapping enabled DNAT mappings")
    if(count>=4096) reject("too many expanded DNAT rules (maximum 4096)")
    r="-A AI_NAT_DNAT"
    if(src!="0.0.0.0/0") r=r " -s " src
    r=r " -d " public_ip "/32 -i " wan_if " -p " proto " -m " proto " --dport " p " -j DNAT --to-destination " target
    if(f[7]!="same") r=r ":" f[7]
    rules[++count]=r
    dip[count]=public_ip
    dproto[count]=proto
    dlo[count]=lo
    dhi[count]=hi
    dlow[count]=low
    dhigh[count]=high
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
        } else if(f[1]=="DNAT_ALLOWED_INTERFACES") {
            if(seenallow++) reject("duplicate DNAT_ALLOWED_INTERFACES")
            n=split(f[2],interfaces,",")
            if(n<1 || n>32) reject("invalid interface list")
            for(i=1;i<=n;i++)
                if(!iface(interfaces[i]) || interfaces[i]=="lo" || interfaces[i] in allowed)
                    reject("invalid or duplicate allowed interface")
                else allowed[interfaces[i]]=1
            allowlist=f[2]
        } else reject("unknown configuration key")
        next
    }
    if($0 ~ /[ \t\r]/ || split($0,f,"[|]")!=(kind=="dnat"?7:6)) reject("incorrect number of pipe-delimited fields")
    if(f[1] !~ /^(0|1)$/) reject("invalid enabled flag")
    if(kind=="dnat") {
        public_ip=(f[2]=="WAN_IP"?wan_ip:f[2])
        if(!hostaddr(public_ip)) reject("invalid external IPv4 address")
        src=(f[3]=="any"?"0.0.0.0/0":cidr(f[3]))
        if(f[4] !~ /^(tcp|udp|both)$/) reject("DNAT requires tcp, udp or both")
        n=split(f[5],ports,",")
        if(n<1 || n>256) reject("invalid port list (maximum 256 entries)")
        target=f[6]
        if(!hostaddr(target)) reject("invalid internal IPv4 address")
        if(f[7]!="same" && (!uint(f[7],65535) || f[7]+0<1)) reject("invalid internal port")
        for(k=1;k<=n;k++) {
            pp=port(ports[k])
            if(f[7]!="same" && (n!=1 || ports[k] ~ /:/)) reject("translated port requires one external port")
            if(f[1]=="1") {
                if(f[4]!="udp") dnat_rule("tcp",pp)
                if(f[4]!="tcp") dnat_rule("udp",pp)
            }
        }
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
        if(seenallow) print allowlist
    } else for(i=1;i<=count;i++) print rules[i]
}
