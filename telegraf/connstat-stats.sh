#!/bin/sh
/usr/bin/connstat -PLe -i 10 -T u \
    -o laddr,lport,raddr,rport,inbytes,outbytes,retranssegs,suna,unsent,swnd,cwnd,rwnd,rtt \
    | grep --line-buffered -v "^="
