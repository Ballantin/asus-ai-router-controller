# POSIX awk: conservative overlap analysis of a native NAT snapshot.
# Input: metadata-mode desired DNAT file, then iptables -t nat -S snapshot.
# Each desired record: Force|configuration line|canonical rule.
# Invoke with -v desired_file=PATH and both filenames (including empty files).
# No shell execution or firewall changes.
function fail(msg) {
    print "DNAT conflict check: " msg > "/dev/stderr"
    bad=1
    exit 1
}
function finding(msg) {
    if(!forced) fail(msg)
    print "WARNING: DNAT configuration line " config_line ": native conflict overridden: " msg > "/dev/stderr"
}
function number(s,max) {
    return s ~ /^(0|[1-9][0-9]*)$/ && length(s)<=10 && s+0<=max
}
function network(s, a,b,n,i,p,v,size) {
    n=split(s,a,"/")
    if(n>2 || split(a[1],b,"[.]")!=4) return 0
    v=0
    for(i=1;i<=4;i++) {
        if(!number(b[i],255)) return 0
        v=v*256+b[i]
    }
    p=32
    if(n==2) {
        if(!number(a[2],32)) return 0
        p=a[2]+0
    }
    size=2^(32-p)
    if(v%size!=0) return 0
    netlo=v
    nethi=v+size-1
    return 1
}
function port(s,a,n) {
    n=split(s,a,":")
    if(n>2 || !number(a[1],65535)) return 0
    plo=a[1]+0
    phi=plo
    if(n==2) {
        if(!number(a[2],65535) || a[2]+0<plo) return 0
        phi=a[2]+0
    }
    return 1
}
# Compare each supported positive predicate with the current candidate.
# Unsupported predicates are not interpreted as matches or exclusions.
# We only trust disjointness from independently understood predicates.
function parse(line, a,n,i,x,y,z,neg,proto,mod,seenjump,seen) {
    n=split(line,a," ")
    unknown=0; excluded=0; jump=""; goto_flag=0
    neg=0; proto=""; mod=""
    for(i=3;i<=n;i++) {
        x=a[i]
        if(x=="!") {unknown=1; neg=1; continue}
        if(x=="-j" || x=="-g") {
            if(neg || i==n || seenjump++) {unknown=1; break}
            jump=a[++i]
            goto_flag=(x=="-g")
            # Target options are not match predicates. Only the known
            # translation option is recognised; other suffixes are opaque.
            if(jump=="DNAT" && i+2==n && a[i+1]=="--to-destination") i=n
            else if(jump=="REDIRECT" && i+2==n && a[i+1]=="--to-ports") i=n
            else if(i!=n) {unknown=1; break}
            break
        }
        if(x!="-s" && x!="-d" && x!="-i" && x!="-p" && x!="-m" && x!="--dport") {
            # Unknown option may consume further tokens. Do not infer
            # exclusions from any subsequent tokens.
            unknown=1
            break
        }
        if(i==n) {unknown=1; break}
        y=a[++i]
        if(y=="!" || y ~ /^-/) {unknown=1; break}
        if(seen[x]++) {unknown=1; break}
        if(neg) {neg=0; continue}
        if(x=="-s" || x=="-d") {
            if(!network(y)) {unknown=1; break}
            if(x=="-s" && (nethi<sl || netlo>sh)) excluded=1
            if(x=="-d" && (nethi<dl || netlo>dh)) excluded=1
            # Inherit intersections by shrinking candidate intervals.
            if(x=="-s") {if(netlo>sl) sl=netlo; if(nethi<sh) sh=nethi}
            else {if(netlo>dl) dl=netlo; if(nethi<dh) dh=nethi}
        } else if(x=="-i") {
            if(y ~ /^[a-zA-Z0-9_][a-zA-Z0-9_.-]*[+]$/) {
                z=substr(y,1,length(y)-1)
                if(substr(ci,1,length(z))!=z) excluded=1
            } else if(y ~ /^[a-zA-Z0-9_][a-zA-Z0-9_.-]*$/) {
                if(y!=ci) excluded=1
            } else {unknown=1; break}
        } else if(x=="-p") {
            proto=y
            if(y=="6") y="tcp"
            if(y=="17") y="udp"
            if(y=="tcp" || y=="udp" || y=="icmp" || y=="1") {
                if(y!=cp) excluded=1
            } else if(y!="all" && y!="0") {unknown=1; break}
        } else if(x=="-m") {
            if(y!="tcp" && y!="udp") {unknown=1; break}
            mod=y
            if(y!=cp) excluded=1
        } else if(x=="--dport") {
            if((mod!="tcp" && mod!="udp") || !port(y)) {unknown=1; break}
            if(phi<pl || plo>ph) excluded=1
            if(plo>pl) pl=plo
            if(phi<ph) ph=phi
        }
    }
    if(!seenjump) unknown=1
}
# Walk all potentially reachable rules. Deliberately over-approximate
# fall-through after RETURN/terminal rules rather than subtracting sets.
function walk(chain,depth, i,line,os,oh,od,odh,op,oph,t,g,u,e) {
    if(depth>32 || active[chain]) fail("cycle or excessive chain depth: " chain)
    if(!declared[chain]) fail("missing native chain: " chain)
    active[chain]=1
    for(i=1;i<=nr[chain];i++) {
        if(++steps>1000000) fail("analysis work limit exceeded")
        line=rules[chain,i]
        os=sl; oh=sh; od=dl; odh=dh; op=pl; oph=ph
        parse(line)
        t=jump; g=goto_flag; u=unknown; e=excluded
        if(!e) {
            if(u || g) finding("unsupported overlapping native rule in " chain ": " line)
            else if(t=="AI_NAT_DNAT") {
                if(chain!="PREROUTING" || line!="-A PREROUTING -j AI_NAT_DNAT")
                    fail("unexpected managed chain reference in " chain)
                # Own jump is reconciled separately, never analyse its rules.
            } else if(t=="DNAT" || t=="REDIRECT" || t=="NETMAP")
                finding("overlapping native translation in " chain ": " line)
            else if(t=="RETURN") {
                # Safe over-approximation: continue scanning possible paths.
            } else if(t in declared) walk(t,depth+1)
            else finding("unsupported overlapping native target in " chain ": " line)
        }
        sl=os; sh=oh; dl=od; dh=odh; pl=op; ph=oph
    }
    active[chain]=0
}
# Desired lines are emitted by our parser. Extract exact supported fields;
# refuse malformed input rather than assume a wildcard.
function desired(line, a,n,i,x,y,s,d,p,iface,proto,t,seen) {
    n=split(line,a," ")
    if(a[1]!="-A" || a[2]!="AI_NAT_DNAT") fail("invalid desired chain")
    s="0.0.0.0/0"
    for(i=3;i<=n;i+=2) {
        x=a[i]; y=a[i+1]
        if(seen[x]++ || i==n) fail("invalid desired rule")
        if(x=="-s") s=y
        else if(x=="-d") d=y
        else if(x=="-i") iface=y
        else if(x=="-p") proto=y
        else if(x=="-m") p=y
        else if(x=="--dport") t=y
        else if(x=="-j") {
            if(y!="DNAT" || i+3!=n || a[i+2]!="--to-destination" || a[i+3]=="")
                fail("invalid desired DNAT target")
            break
        } else fail("unsupported desired predicate")
    }
    if(!seen["-j"] || !network(s)) fail("invalid desired source")
    sl=netlo; sh=nethi
    if(!network(d) || netlo!=nethi) fail("invalid desired destination")
    dl=netlo; dh=nethi
    if(iface !~ /^[a-zA-Z0-9_][a-zA-Z0-9_.-]*$/ || length(iface)>15 ||
       (proto!="tcp" && proto!="udp") || p!=proto || !port(t) || plo<1)
        fail("invalid desired interface/protocol/port")
    ci=iface; cp=proto; pl=plo; ph=phi
}
BEGIN {
    if(desired_file=="" || ARGC!=3 || ARGV[1]!=desired_file || ARGV[2]==desired_file)
        fail("expected desired_file and distinct NAT snapshot")
}
FILENAME==desired_file {
    if($0!="") {
        if(++nd>4096) fail("desired rule limit exceeded")
        if(split($0,record,"[|]")!=3 || record[1] !~ /^(0|1)$/ ||
           !number(record[2],2147483647) || record[2]+0<1 || record[3]=="")
            fail("invalid desired metadata")
        flags[nd]=record[1]+0
        source_lines[nd]=record[2]
        wanted[nd]=record[3]
    }
    next
}
{
    if($1=="-P" || $1=="-N") {
        if($2=="" || $2 in declared) fail("invalid or duplicate chain declaration")
        declared[$2]=1
    } else if($1=="-A") {
        if(!($2 in declared)) fail("rule for undeclared chain")
        if(++total>32768) fail("native rule limit exceeded")
        rules[$2,++nr[$2]]=$0
    } else if($0!="") fail("unrecognised NAT snapshot record")
}
END {
    if(bad) exit 1
    if(!nd) exit 0
    if(!declared["PREROUTING"]) fail("missing PREROUTING")
    # Ownership is a global invariant, regardless of candidate overlap
    # or Force. Inspect every chain, including unreachable ones.
    for(chain in declared)
        for(j=1;j<=nr[chain];j++) {
            raw=rules[chain,j]
            if(raw ~ /(^|[[:space:]])(-j|-g|--jump|--goto)[[:space:]]+AI_NAT_DNAT([[:space:]]|$)/ &&
               raw!="-A PREROUTING -j AI_NAT_DNAT")
                fail("unexpected managed chain reference in " chain)
        }
    for(k=1;k<=nd;k++) {
        forced=flags[k]
        config_line=source_lines[k]
        desired(wanted[k])
        if(forced) print "WARNING: DNAT configuration line " config_line ": Force enabled" > "/dev/stderr"
        walk("PREROUTING",1)
    }
    print "DNAT native conflict check passed"
}
