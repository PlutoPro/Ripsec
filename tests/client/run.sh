#!/usr/bin/env bash
# The Ripsec client against the Ripsec server, over a real network with kernel ESP on the
# server. Needs Docker and the ripsec-strongswan image built by tests/interop/run.sh (used
# here only because it has ip and ping).
set -u
export MSYS_NO_PATHCONV=1
root="$(cd "$(dirname "$0")/../.." && pwd)"
command -v cygpath >/dev/null && root="$(cygpath -m "$root")"
net=ripsec-client-test
failures=0

docker run --rm -v "$root:/src" -v ripsec-cargo:/usr/local/cargo/registry -v ripsec-target:/target \
  -e CARGO_TARGET_DIR=/target -w /src rust:trixie cargo build --release --workspace || exit 1

cleanup() { docker rm -f rc-server rc-client >/dev/null 2>&1; docker network rm $net >/dev/null 2>&1; }
cleanup
trap cleanup EXIT
docker network create --subnet 172.31.251.0/24 $net >/dev/null || exit 1

secret=client-test-secret-not-for-real-use-0123456789
server_setup='
mkdir -p /etc/ripsec /var/lib/ripsec
ip addr add 10.50.0.1/32 dev lo
ip addr add 10.51.0.1/32 dev lo
cat > /etc/ripsec/ripsec.toml <<EOF
listen = "172.31.251.2"
public_address = "172.31.251.2"
server_id = "vpn.ripsec.test"
pool = "10.99.0.0/24"
dns = []
local_subnets = ["0.0.0.0/0"]
[web]
listen = "127.0.0.1:8480"
public_url = "https://vpn.ripsec.test"
[oidc]
issuer = "https://id.ripsec.test"
client_id = "ripsec"
EOF
[ -f /var/lib/ripsec/devices.json ] || cat > /var/lib/ripsec/devices.json <<EOF
[{"id":"dev1@ripsec","name":"client","owner":"t","owner_name":"tester","secret":"SECRET","created":0,"expires":null}]
EOF
exec /target/release/ripsec'

docker run -d --name rc-server --network $net --ip 172.31.251.2 --cap-add NET_ADMIN \
  -v ripsec-target:/target ripsec-strongswan bash -c "${server_setup//SECRET/$secret}" >/dev/null || exit 1
docker run -d --name rc-client --network $net --ip 172.31.251.3 --cap-add NET_ADMIN \
  --device /dev/net/tun -v ripsec-target:/target:ro ripsec-strongswan sleep infinity >/dev/null || exit 1

client() { docker exec rc-client "$@"; }
pause() { sleep "$1"; }

# The profile as the portal writes it, with the given routes and secret.
profile() { # file, remote_ts, secret
  client bash -c "cat > /tmp/$1 <<EOF
connections {
  ripsec {
    version = 2
    remote_addrs = 172.31.251.2
    local {
      auth = psk
      id = dev1@ripsec
    }
    remote {
      auth = psk
      id = vpn.ripsec.test
    }
    children {
      net {
        remote_ts = $2
      }
    }
  }
}
secrets {
  ike-ripsec {
    secret = \"$3\"
  }
}
EOF"
}

check() { # description, command...
  local what="$1"; shift
  if "$@" >/tmp/ripsec-check.log 2>&1; then echo "PASS  $what"
  else echo "FAIL  $what"; sed 's/^/      /' /tmp/ripsec-check.log | tail -15; failures=$((failures+1)); fi
}
# eventually <seconds> <command...>
eventually() {
  local left="$1"; shift
  until "$@" >/dev/null 2>&1; do
    left=$((left-1)); [ $left -gt 0 ] || { "$@"; return 1; }
    pause 1
  done
}
log_has() { client grep -q "$1" /tmp/client.log; }
server_has() { docker logs rc-server 2>&1 | grep -q "$1"; }
start() { client bash -c "/target/release/ripsec-client connect /tmp/$1 ${2:-} >/tmp/client.log 2>&1 & echo \$! >/tmp/client.pid"; }
running() { client bash -c 'kill -0 $(cat /tmp/client.pid) 2>/dev/null && ! grep -q "^State:.*Z" /proc/$(cat /tmp/client.pid)/status'; }
stopped() { ! running; }
stop() { client bash -c 'kill -INT $(cat /tmp/client.pid)'; eventually 15 stopped; }
ping_ok() { client ping -c 3 -W 2 "${1:-10.50.0.1}"; }
no_interface() { ! client ip link show ripsec0; }

profile ok.conf 0.0.0.0/0 "$secret"
profile split.conf 10.50.0.0/24 "$secret"
profile wrong.conf 0.0.0.0/0 not-the-secret

echo "== handshake"
eventually 20 server_has "IKEv2 listening"
check "check command succeeds with post-quantum keys" client /target/release/ripsec-client check /tmp/ok.conf
check "wrong secret is refused" bash -c \
  '! docker exec rc-client /target/release/ripsec-client check /tmp/wrong.conf'
check "server logged why" server_has "authentication failed for dev1@ripsec"
check "no interface is left behind" no_interface

echo "== full tunnel"
start ok.conf
check "connects" eventually 20 log_has "connected: address 10.99.0"
check "server sees a post-quantum session" server_has "connected, post-quantum=true"
check "traffic through the tunnel" ping_ok
check "traffic really uses the tunnel" bash -c "docker exec rc-client ip route get 10.50.0.1 | grep -q ripsec0"
check "the server itself stays outside it" bash -c "docker exec rc-client ip route get 172.31.251.2 | grep -q eth0"
check "large packets" client ping -c 3 -W 2 -s 4000 10.50.0.1
check "2000 packets without loss" bash -c \
  "docker exec rc-client ping -f -c 2000 -s 1200 10.50.0.1 | grep -q ' 0% packet loss'"
echo "      idling 75 seconds to exercise liveness checks in both directions"
pause 75
check "still connected after idling" running
check "traffic after idling" ping_ok
check "server did not give up on us" bash -c '! docker logs rc-server 2>&1 | grep -q "stopped responding"'
check "stops on interrupt" stop
check "server was told" eventually 5 server_has "dev1@ripsec disconnected"
check "server removed all kernel state" bash -c '[ -z "$(docker exec rc-server ip xfrm state)" ]'
check "interface and routes are gone" no_interface

echo "== split tunnel"
start split.conf
check "connects" eventually 20 log_has "routing 10.50.0.0/24"
check "reaches the allowed network" ping_ok
check "nothing else is routed" bash -c "docker exec rc-client ip route get 10.51.0.1 | grep -q eth0"
check "stops" stop
check "a route outside the profile is refused" bash -c \
  '! docker exec rc-client timeout 20 /target/release/ripsec-client connect /tmp/split.conf --route 10.51.0.0/24'
start ok.conf "--route 10.51.0.0/24"
check "--route narrows a full tunnel" eventually 20 log_has "routing 10.51.0.0/24"
check "reaches it" ping_ok 10.51.0.1
check "stops" stop

echo "== server failures"
start ok.conf
check "connects" eventually 20 log_has "connected:"
docker kill rc-server >/dev/null
check "notices the server is gone" eventually 90 log_has "stopped responding"
docker start rc-server >/dev/null
check "reconnects when it returns" eventually 90 bash -c \
  '[ "$(docker exec rc-client grep -c "^connected:" /tmp/client.log)" -ge 2 ]'
check "traffic after reconnecting" ping_ok
docker stop -t 10 rc-server >/dev/null
check "exits when the server closes the connection" eventually 15 stopped
check "and says so" log_has "the server closed the connection"
check "interface is gone" no_interface

[ $failures -eq 0 ] || { echo "== client log"; client cat /tmp/client.log; echo "== server log"; docker logs rc-server 2>&1 | tail -30; }
echo
[ $failures -eq 0 ] && echo "all checks passed" || echo "$failures check(s) failed"
exit $failures
