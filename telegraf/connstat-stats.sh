#!/bin/sh
#
# Collect per-connection TCP stats from connstat and aggregate by remote
# endpoint (laddr:raddr:rport) to bound cardinality on engines with many
# connections — e.g. Oracle dNFS (hundreds of connections per VDB host) or
# Elastic Data (many connections per object storage endpoint IP).
# Mirrors the aggregation done by LocalTCPStatsCollector in the mgmt stack.
#
# Service name lookup reads from /etc/services, matching LocalTCPStatsCollector
# exactly. lport is checked before rport so that listening services (where the
# engine is the server) are identified correctly. Falls back to "unknown".
#
# Output fields per aggregated endpoint:
#   laddr, raddr, rport, service
#   inbytes, outbytes, retranssegs, suna, unsent  (summed across connections)
#   swnd, cwnd, rwnd, rtt                          (averaged across connections)
#   connections                                    (count of aggregated conns)
#
/usr/bin/connstat -PLe -i 10 -T u \
    -o laddr,lport,raddr,rport,inbytes,outbytes,retranssegs,suna,unsent,swnd,cwnd,rwnd,rtt \
    | awk -F',' '
BEGIN {
    # Load port->service mapping from /etc/services, same as LocalTCPStatsCollector.
    # Pattern matches lines of the form: "servicename  port/tcp"
    while ((getline line < "/etc/services") > 0) {
        sub(/^[[:space:]]+/, "", line)
        if (line ~ /^(#|$)/) continue
        n = split(line, f, /[[:space:]]+/)
        if (n >= 2 && f[2] ~ /\/tcp/) {
            split(f[2], pf, "/")
            port = pf[1] + 0
            if (!(port in svc)) svc[port] = f[1]
        }
    }
    close("/etc/services")
    # Delphix DSP (Session Protocol) port — not present in /etc/services.
    # Matches the ServiceProtocol special-case in LocalTCPStatsCollector.
    svc[50001] = "dlpx-sp"
}
/^=/ {
    for (key in cnt) {
        n = cnt[key]
        split(key, k, SUBSEP)
        print k[1] "," k[2] "," k[3] "," k[4] "," \
              inb[key] "," outb[key] "," ret[key] "," sun[key] "," uns[key] "," \
              int(sw[key]/n) "," int(cw[key]/n) "," int(rw[key]/n) "," int(rt[key]/n) "," n
    }
    delete cnt; delete inb; delete outb; delete ret
    delete sun; delete uns; delete sw; delete cw; delete rw; delete rt
    next
}
NF == 13 {
    lport = $2 + 0
    rport = $4 + 0
    if (lport in svc) {
        service = svc[lport]
    } else if (rport in svc) {
        service = svc[rport]
    } else {
        service = "unknown"
    }
    key = $1 SUBSEP $3 SUBSEP rport SUBSEP service
    inb[key] += $5;  outb[key] += $6;  ret[key] += $7
    sun[key] += $8;  uns[key]  += $9
    sw[key]  += $10; cw[key]   += $11; rw[key]  += $12; rt[key] += $13
    cnt[key]++
}
'
