#!/bin/sh
# Reads a strongSwan device profile from the portal on stdin and connects with it.
set -e
tr -d '\r' | sed 's/remote_addrs = .*/remote_addrs = ripsec/' > /etc/swanctl/swanctl.conf
swanctl --terminate --ike ripsec --force >/dev/null 2>&1 || true
swanctl --load-all --clear
swanctl --initiate --child net --timeout 15
swanctl --list-sas
