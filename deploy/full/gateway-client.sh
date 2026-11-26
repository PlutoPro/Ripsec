#!/bin/sh
# Waits for Keycloak, then (re)creates the gateway client with the generated secret.
set -eu

for i in $(seq 120); do
  wget -q -O /dev/null "$KEYCLOAK_URL/realms/kv/.well-known/openid-configuration" && break
  sleep 2
done
RIPSEC_GATEWAY_SECRET=$(cat /secret/client-secret)
export RIPSEC_GATEWAY_SECRET
exec python3 -B /ripsec-gateway.py --replace
