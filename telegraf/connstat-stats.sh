#!/bin/sh
#
# Collect per-connection TCP stats from connstat and aggregate by remote
# endpoint (laddr:raddr:service) to bound cardinality on engines with many
# connections — e.g. Oracle dNFS (hundreds of connections per VDB host) or
# Elastic Data (many connections per object storage endpoint IP).
# Mirrors the aggregation done by LocalTCPStatsCollector in the mgmt stack.
#
# Service name lookup reads from /etc/services, matching LocalTCPStatsCollector
# exactly. lport is checked before rport so that listening services (where the
# engine is the server) are identified correctly. Falls back to "unknown".
#
# Output fields per aggregated endpoint:
#   laddr, raddr, service
#   inbytes, outbytes, retranssegs, suna, unsent  (summed across connections)
#   swnd, cwnd, rwnd, rtt                          (averaged across connections)
#   connections                                    (count of aggregated conns)
#
# mawk (the default awk on Delphix engines) does not flush its stdout buffer
# when writing to a Telegraf execd pipe, even with explicit fflush() calls.
# Wrapping connstat in a loop with -c 2 causes awk to exit naturally after
# each 10-second interval, which triggers the C runtime exit flush (fclose)
# and reliably delivers data to Telegraf.
while true; do
/usr/bin/connstat -PLe -i 10 -c 2 -T u \
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
    # Delphix-specific ports not present in /etc/services.
    # Matches LocalTCPStatsCollector.getService() special-cases exactly.
    svc[8415]  = "dlpx-sp"              # DSP (ServiceProtocol.PORT)
    svc[50001] = "network-throughput-test" # TtcpPerfSession.DEFAULT_PORT
    svc[8341]  = "oracle-logsync"       # HTTP server (TunableRegistry.HTTP_SERVER_PORT default)
    svc[9100]  = "dlpx-connector"       # Host Connector (Connector.DEFAULT_PORT)
}
/^=/ {
    for (key in cnt) {
        n = cnt[key]
        split(key, k, SUBSEP)
        print k[1] "," k[2] "," k[3] "," \
              inb[key] "," outb[key] "," ret[key] "," sun[key] "," uns[key] "," \
              int(sw[key]/n) "," int(cw[key]/n) "," int(rw[key]/n) "," int(rt[key]/n) "," n
    }
    fflush()
    delete cnt; delete inb; delete outb; delete ret
    delete sun; delete uns; delete sw; delete cw; delete rw; delete rt
    next
}
NF == 13 {
    if (($2 + 0) in svc) {
        service = svc[$2 + 0]
    } else if (($4 + 0) in svc) {
        service = svc[$4 + 0]
    } else {
        service = "unknown"
    }
    key = $1 SUBSEP $3 SUBSEP service
    inb[key] += $5;  outb[key] += $6;  ret[key] += $7
    sun[key] += $8;  uns[key]  += $9
    sw[key]  += $10; cw[key]   += $11; rw[key]  += $12; rt[key] += $13
    cnt[key]++
}
END {
    for (key in cnt) {
        n = cnt[key]
        split(key, k, SUBSEP)
        print k[1] "," k[2] "," k[3] "," \
              inb[key] "," outb[key] "," ret[key] "," sun[key] "," uns[key] "," \
              int(sw[key]/n) "," int(cw[key]/n) "," int(rw[key]/n) "," int(rt[key]/n) "," n
    }
    fflush()
}
'
done
