#!/bin/sh
# Masquerade traffic from VPN clients, then run the server.
# Packets that match an IPsec policy on the way out must not be rewritten.
set -e
POOL="${RIPSEC_POOL:-10.99.0.0/24}"
iptables -t nat -C POSTROUTING -s "$POOL" -m policy --dir out --pol none -j MASQUERADE 2>/dev/null \
  || iptables -t nat -A POSTROUTING -s "$POOL" -m policy --dir out --pol none -j MASQUERADE \
  || echo "warning: could not add the NAT rule; clients may not reach the internet" >&2
exec ripsec --config /etc/ripsec/ripsec.toml
