#!/usr/bin/env bash
# Interoperability test: strongSwan (client) against ripsec (server), with real kernel ESP.
# Needs Docker with a Linux kernel that has IPsec support. Run from anywhere.
set -u
export MSYS_NO_PATHCONV=1
root="$(cd "$(dirname "$0")/../.." && pwd)"
command -v cygpath >/dev/null && root="$(cygpath -m "$root")"
net=ripsec-test
failures=0

docker image inspect ripsec-strongswan >/dev/null 2>&1 \
  || docker build -t ripsec-strongswan -f "$root/tests/interop/strongswan.Dockerfile" "$root/tests/interop" || exit 1
docker run --rm -v "$root:/src" -v ripsec-cargo:/usr/local/cargo/registry -v ripsec-target:/target \
  -e CARGO_TARGET_DIR=/target -w /src rust:trixie cargo build --release || exit 1

cleanup() { docker rm -f rs-server rs-client >/dev/null 2>&1; docker network rm $net >/dev/null 2>&1; }
cleanup
trap cleanup EXIT
docker network create --subnet 172.31.250.0/24 $net >/dev/null || exit 1

secret=interop-test-secret-not-for-real-use-0123456789
server_setup='
mkdir -p /etc/ripsec /var/lib/ripsec
ip addr add 10.50.0.1/32 dev lo
cat > /etc/ripsec/ripsec.toml <<EOF
listen = "172.31.250.2"
public_address = "172.31.250.2"
server_id = "vpn.ripsec.test"
pool = "10.99.0.0/24"
dns = ["10.50.0.1"]
local_subnets = ["10.50.0.0/24"]
[web]
listen = "127.0.0.1:8480"
public_url = "https://vpn.ripsec.test"
[oidc]
issuer = "https://id.ripsec.test"
client_id = "ripsec"
EOF
cat > /var/lib/ripsec/devices.json <<EOF
[{"id":"dev1@ripsec","name":"interop","owner":"t","owner_name":"tester","secret":"SECRET","created":0,"expires":null},
 {"id":"site1@ripsec","name":"branch","owner":"t","owner_name":"tester","secret":"SECRET","remote_subnets":["10.60.0.0/24"],"created":0,"expires":null}]
EOF
exec /target/release/ripsec'

docker run -d --name rs-server --network $net --ip 172.31.250.2 --cap-add NET_ADMIN \
  -v ripsec-target:/target ripsec-strongswan bash -c "${server_setup//SECRET/$secret}" >/dev/null || exit 1
docker run -d --name rs-client --network $net --ip 172.31.250.3 --cap-add NET_ADMIN \
  ripsec-strongswan bash -c 'exec /usr/libexec/ipsec/charon' >/dev/null || exit 1

client() { docker exec rs-client "$@"; }

# configure <ike proposal> <esp proposal> <secret> <force udp encapsulation: yes|no>
configure() {
  client bash -c "cat > /etc/swanctl/swanctl.conf <<EOF
connections {
  ripsec {
    version = 2
    remote_addrs = 172.31.250.2
    proposals = $1
    vips = 0.0.0.0
    encap = $4
    local { auth = psk
            id = dev1@ripsec }
    remote { auth = psk
             id = vpn.ripsec.test }
    children { net { remote_ts = 10.50.0.0/24
                     esp_proposals = $2 } }
  }
}
secrets { ike-ripsec { id-1 = dev1@ripsec
                       id-2 = vpn.ripsec.test
                       secret = \"$3\" } }
EOF
for i in \$(seq 50); do swanctl --stats >/dev/null 2>&1 && break; read -t 0.1 <> <(:); done
swanctl --load-all --clear >/dev/null"
}

check() { # description, command...
  local what="$1"; shift
  if "$@" >/tmp/ripsec-check.log 2>&1; then echo "PASS  $what"
  else echo "FAIL  $what"; sed 's/^/      /' /tmp/ripsec-check.log | tail -25; failures=$((failures+1)); fi
}
# A rejected connection must fail AND the server must log the expected reason.
rejected() { # description, expected server log text
  if up >/tmp/ripsec-check.log 2>&1; then echo "FAIL  $1 (connected)"; failures=$((failures+1))
  else check "$1" bash -c "docker logs rs-server 2>&1 | grep -q '$2'"; fi
}
child_spis() { client swanctl --list-sas | grep -E '^ +(in|out) ' | awk '{print $2}' | tr -d ',' ; }
ike_spis() { client swanctl --list-sas | grep -oE '[0-9a-f]{16}_i\*? [0-9a-f]{16}_r'; }
# changes <function listing SPIs> <command...>: the command must lead to new SPIs.
changes() {
  local list="$1" before after; shift
  before="$($list)"
  "$@" || return 1
  sleep_ms 2000
  after="$($list)"
  echo "before: $before"; echo "after:  $after"
  [ -n "$after" ] && [ "$before" != "$after" ]
}

up() { client swanctl --initiate --child net --timeout 10; }
down() { client swanctl --terminate --ike ripsec --timeout 10 >/dev/null 2>&1; }
ping_ok() { client ping -c 3 -W 2 10.50.0.1; }
sas_have() { client swanctl --list-sas | grep -q "$1"; }
server_clean() { [ -z "$(docker exec rs-server ip xfrm state)" ] && [ -z "$(docker exec rs-server ip xfrm policy)" ]; }

run_suite() { # label, ike, esp, encap
  echo "== $1"
  configure "$2" "$3" "$secret" "$4"
  check "handshake" up
  check "ML-KEM negotiated" sas_have ML_KEM
  check "traffic through the tunnel" ping_ok
  check "CHILD SA rekey" changes child_spis client swanctl --rekey --child net
  check "traffic after CHILD rekey" ping_ok
  check "IKE SA rekey" changes ike_spis client swanctl --rekey --ike ripsec
  check "traffic after IKE rekey" ping_ok
  check "still post-quantum after rekey" sas_have ML_KEM
  check "CHILD SA rekey on the new IKE SA" changes child_spis client swanctl --rekey --child net
  check "traffic at the end" ping_ok
  down
  sleep_ms 500
  check "server removed all kernel state" server_clean
}
sleep_ms() { sleep "$(awk "BEGIN{print $1/1000}")"; }

run_suite "X25519 + ML-KEM-768" aes256gcm16-prfsha384-x25519-ke1_mlkem768 aes256gcm16-x25519-ke1_mlkem768-esn no
run_suite "ECP-384 + ML-KEM-1024 (fragmented), UDP encapsulation" \
  aes256gcm16-prfsha512-ecp384-ke1_mlkem1024 aes128gcm16-ecp384-ke1_mlkem1024 yes

echo "== site-to-site gateway"
client ip addr add 10.60.0.1/32 dev lo
docker exec rs-server ip route add 10.60.0.0/24 dev eth0 src 10.50.0.1
client bash -c "cat > /etc/swanctl/swanctl.conf <<EOF
connections { ripsec {
    version = 2
    remote_addrs = 172.31.250.2
    proposals = aes256gcm16-prfsha384-x25519-ke1_mlkem768
    local { auth = psk
            id = site1@ripsec }
    remote { auth = psk
             id = vpn.ripsec.test }
    children { net { local_ts = 10.60.0.0/24
                     remote_ts = 10.50.0.0/24
                     esp_proposals = aes256gcm16-x25519-ke1_mlkem768 } }
} }
secrets { ike-ripsec { id-1 = site1@ripsec
                       id-2 = vpn.ripsec.test
                       secret = \"$secret\" } }
EOF
swanctl --load-all --clear >/dev/null"
check "gateway handshake" up
check "branch to head office" client ping -c 3 -W 2 -I 10.60.0.1 10.50.0.1
check "head office to branch" docker exec rs-server ping -c 3 -W 2 -I 10.50.0.1 10.60.0.1
down
sleep_ms 500
check "server removed all kernel state" server_clean

echo "== rejections"
configure aes256gcm16-prfsha384-x25519 aes256gcm16 "$secret" no
rejected "classical-only peer is refused" "no acceptable IKE proposal"
down
configure aes256gcm16-prfsha384-x25519-ke1_mlkem768 aes256gcm16 wrong-secret no
rejected "wrong secret is refused" "authentication failed for dev1@ripsec"
down

echo "== server memory"
docker exec rs-server bash -c 'grep -E "VmRSS|VmHWM|Threads" /proc/$(pgrep -x ripsec 2>/dev/null || echo 1)/status'
echo "== server log"
docker logs rs-server 2>&1 | tail -20
[ $failures -eq 0 ] || { echo "== client log"; docker logs rs-client 2>&1 | tail -60; }
echo
[ $failures -eq 0 ] && echo "all checks passed" || echo "$failures check(s) failed"
exit $failures
