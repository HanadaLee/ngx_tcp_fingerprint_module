#!/bin/sh
#
# Builds nginx with the module and checks the variables against real SYNs.
# Each case runs in its own network namespace, where the TCP sysctls change
# the client's SYN (options, TTL, ECN) without touching the host.
#
# Usage, as root on Linux:  t/test.sh [nginx version]
# Needs: cc, make, curl (with HTTP/2), openssl, libpcre2-dev, zlib1g-dev,
# libssl-dev, util-linux (unshare), iproute2 (tc, netem), python3.

set -eu

VERSION=${1:-1.31.7}
MODULE=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

echo "building nginx $VERSION with $MODULE"
curl -fsSL "https://nginx.org/download/nginx-$VERSION.tar.gz" | tar -xz -C "$WORK"
(
    cd "$WORK/nginx-$VERSION"
    ./configure --with-compat --with-http_ssl_module --with-http_v2_module \
        --without-http_gzip_module --with-cc-opt=-Werror \
        --add-dynamic-module="$MODULE" >/dev/null
    make -j"$(nproc)" >/dev/null
)
NGINX=$WORK/nginx-$VERSION/objs/nginx
SO=$WORK/nginx-$VERSION/objs/ngx_http_tcp_fingerprint_module.so

openssl req -x509 -newkey rsa:2048 -nodes -subj /CN=localhost -days 1 \
    -keyout "$WORK/key.pem" -out "$WORK/cert.pem" 2>/dev/null

conf() {
    mkdir -p "$WORK/logs"
    cat > "$WORK/nginx.conf" <<EOF
load_module $SO;
pid $WORK/nginx.pid;
error_log $WORK/logs/error.log notice;
events {}
http {
    tcp_fingerprint $1;
    access_log off;
    server {
        listen 127.0.0.1:8080;
        listen [::1]:8080;
        listen 127.0.0.1:8443 ssl;
        http2 on;
        ssl_certificate $WORK/cert.pem;
        ssl_certificate_key $WORK/key.pem;
        location / {
            return 200 "\$tcpfp_signature\n";
        }
        location /vars {
            return 200 "ttl=\$tcpfp_ttl ittl=\$tcpfp_ittl hops=\$tcpfp_hops win=\$tcpfp_win mss=\$tcpfp_mss ws=\$tcpfp_wscale opts=\$tcpfp_options quirks=\$tcpfp_quirks\n";
        }
        location /rtt {
            return 200 "\$tcpfp_tls_rtt \$tcpfp_tcp_rtt\n";
        }
    }
}
EOF
}

FAIL=0

# check NAME 'sysctl settings' 'curl arguments' 'expected regex'
check() {
    out=$(unshare -n sh -c "
        ip link set lo up
        for s in $2; do sysctl -qw \"\$s\"; done
        $NGINX -p $WORK -c $WORK/nginx.conf
        sleep 0.3
        curl -sk $3
        $NGINX -p $WORK -c $WORK/nginx.conf -s stop
        sleep 0.2
    " 2>&1 | tr '\n' '|')
    if printf '%s' "$out" | grep -Eq "^$4\$"; then
        echo "ok    $1: $out"
    else
        echo "FAIL  $1: got '$out', expected /$4/"
        FAIL=1
    fi
}

conf on

# loopback: MTU 65536, so MSS 65495 (IPv4) and 65476 (IPv6)

check "Linux defaults" "" \
    "http://127.0.0.1:8080/" \
    '4:64\+0:0:65495:[^,]+,[0-9]+:mss,sok,ts,nop,ws:df(,id\+)?:0\|'

check "every variable" "" \
    "http://127.0.0.1:8080/vars" \
    'ttl=64 ittl=64 hops=0 win=[0-9]+ mss=65495 ws=[0-9]+ opts=mss,sok,ts,nop,ws quirks=df(,id\+)?\|'

check "no timestamps" "net.ipv4.tcp_timestamps=0" \
    "http://127.0.0.1:8080/" \
    '4:64\+0:0:65495:[^,]+,[0-9]+:mss,nop,nop,sok,nop,ws:df(,id\+)?:0\|'

check "MSS only: no window scale" \
    "net.ipv4.tcp_timestamps=0 net.ipv4.tcp_sack=0 net.ipv4.tcp_window_scaling=0" \
    "http://127.0.0.1:8080/vars" \
    'ttl=64 ittl=64 hops=0 win=[0-9]+ mss=65495 ws= opts=mss quirks=df(,id\+)?\|'

check "TTL 100: initial 128, 28 hops" "net.ipv4.ip_default_ttl=100" \
    "http://127.0.0.1:8080/" \
    '4:100\+28:0:65495:[^:]+:mss,sok,ts,nop,ws:df(,id\+)?:0\|'

check "TTL 128" "net.ipv4.ip_default_ttl=128" \
    "http://127.0.0.1:8080/vars" \
    'ttl=128 ittl=128 hops=0 .*\|'

check "ECN requested in the SYN" "net.ipv4.tcp_ecn=1" \
    "http://127.0.0.1:8080/vars" \
    '.* quirks=df(,id\+)?,ecn\|'

check "IPv6 hop limit 100, Linux sets a flow label" "net.ipv6.conf.lo.hop_limit=100" \
    "-g http://[::1]:8080/" \
    '6:100\+28:0:65476:[^:]+:mss,sok,ts,nop,ws:flow:0\|'

check "keepalive: same SYN for every request" "" \
    "http://127.0.0.1:8080/a http://127.0.0.1:8080/b" \
    '(4:64\+0:[^|]+)\|\1\|'

check "HTTP/2 streams" "" \
    "--http2 https://127.0.0.1:8443/a https://127.0.0.1:8443/b" \
    '(4:64\+0:[^|]+)\|\1\|'

# TCP relay for the tunnel case: the client's TCP ends here, its TLS goes
# on to nginx, as through a CONNECT proxy
cat > "$WORK/relay.py" <<'PY'
import socket, threading
def pipe(a, b):
    while True:
        d = a.recv(65536)
        if not d:
            break
        b.sendall(d)
    b.shutdown(socket.SHUT_WR)
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", 9443))
s.listen()
while True:
    c, _ = s.accept()
    u = socket.create_connection(("127.0.0.1", 8443))
    threading.Thread(target=pipe, args=(c, u), daemon=True).start()
    threading.Thread(target=pipe, args=(u, c), daemon=True).start()
PY

# rtt NAME 'setup commands' 'curl arguments' 'awk condition on the output
# fields: TLS RTT, TCP RTT (microseconds), then the next request's'
rtt() {
    out=$(unshare -n sh -c "
        ip link set lo up
        $2
        $NGINX -p $WORK -c $WORK/nginx.conf
        sleep 0.3
        curl -sk $3
        $NGINX -p $WORK -c $WORK/nginx.conf -s stop
        [ -z \"\${RELAY:-}\" ] || kill \$RELAY
        sleep 0.2
    " 2>&1 | tr '\n' ' ')
    if printf '%s\n' "$out" | awk "{ exit !($4) }"; then
        echo "ok    $1: $out"
    else
        echo "FAIL  $1: got '$out', expected $4"
        FAIL=1
    fi
}

rtt "TLS 1.3 direct, 20 ms RTT: both close" \
    "tc qdisc add dev lo root netem delay 10ms" \
    "https://127.0.0.1:8443/rtt" \
    '$1 >= 19000 && $1 < 40000 && $2 >= 19000 && $2 < 40000'

rtt "TLS 1.3 through a relay, 60 ms behind it: TLS only" \
    "tc qdisc add dev lo root handle 1: prio
     tc qdisc add dev lo parent 1:3 handle 30: netem delay 30ms
     tc filter add dev lo parent 1: protocol ip u32 match ip dport 9443 0xffff flowid 1:3
     tc filter add dev lo parent 1: protocol ip u32 match ip sport 9443 0xffff flowid 1:3
     python3 $WORK/relay.py >/dev/null 2>&1 & RELAY=\$! ; sleep 0.3" \
    "https://127.0.0.1:9443/rtt" \
    '$1 >= 59000 && $2 < 10000'

rtt "HTTP/2 streams: one handshake" "" \
    "--http2 https://127.0.0.1:8443/rtt https://127.0.0.1:8443/rtt" \
    'NF == 4 && $1 > 0 && $2 > 0 && $1 == $3 && $2 == $4'

check "TLS 1.2: no TLS RTT" "" \
    "--tls-max 1.2 https://127.0.0.1:8443/rtt" \
    ' \|'

check "plain HTTP: no TLS RTT" "" \
    "http://127.0.0.1:8080/rtt" \
    ' \|'

conf off

check "tcp_fingerprint off" "" \
    "http://127.0.0.1:8080/" \
    '\|'

check "tcp_fingerprint off: no TLS RTT" "" \
    "https://127.0.0.1:8443/rtt" \
    ' \|'

if grep -E '\[(alert|crit|emerg)\]' "$WORK/logs/error.log"; then
    FAIL=1
fi

if command -v njs >/dev/null; then
    njs -p "$MODULE/examples" "$MODULE/t/examples.js" || FAIL=1
else
    echo "skip  examples: no njs command line"
fi

exit $FAIL
