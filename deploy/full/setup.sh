#!/bin/sh
# Test certificates and the gateway client secret, written once into named volumes. The CA's
# private key is discarded. The files are world-readable inside the volumes: test use only.
set -eu

if [ -f /out/ca/ca.crt ] && [ -f /out/secret/client-secret ]; then
  echo "already set up"
  exit 0
fi
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$work"
ec="-newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes"

openssl req -x509 $ec -days 825 -subj "/CN=ripsec test CA" -keyout ca.key -out ca.crt \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign" 2>/dev/null

issue() { # file name, DNS name, destination
  openssl req $ec -subj "/CN=$1" -keyout "$1.key" -out "$1.csr" 2>/dev/null
  printf 'subjectAltName=DNS:%s\nextendedKeyUsage=serverAuth\n' "$2" > "$1.ext"
  openssl x509 -req -in "$1.csr" -CA ca.crt -CAkey ca.key -CAcreateserial -days 825 \
    -extfile "$1.ext" -out "$1.crt" 2>/dev/null
  cp "$1.crt" "$1.key" "$3/"
  chmod 444 "$3/$1.crt" "$3/$1.key"
}
issue kv kv.ripsec.test /out/kv
issue keycloak keycloak /out/keycloak

openssl rand -hex 32 > /out/secret/client-secret
cp ca.crt /out/ca/
chmod 444 /out/secret/client-secret /out/ca/ca.crt
echo "certificates and gateway secret created"
