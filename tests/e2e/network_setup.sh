#!/bin/sh
# Address plan for the E2E tests, shared by the bubblewrap sandbox (sandbox_init.sh) and the Docker
# test container (tests/docker/in-container.sh). Needs CAP_NET_ADMIN in a private network namespace
# with no route out.
set -eu
ip link set lo up
add4() { for a in "$@"; do ip addr add "$a/32" dev lo; done; }
add6() { for a in "$@"; do ip -6 addr add "$a/128" dev lo nodad; done; }
# "Public" origins.
add4 93.184.215.14 93.184.215.15 93.184.215.16 93.184.215.17
add6 2606:2800:220:1::14
# Sandbox clients and the proxy's own listener address; load balancer.
add4 10.20.0.1 10.20.0.7 10.20.0.8 10.30.0.1
# "Internal" destinations the proxy must never reach.
add4 169.254.169.254 192.0.0.192 168.63.129.16 10.0.0.5 100.100.100.200 198.18.0.1 172.16.0.9 192.168.1.9
add6 64:ff9b::a9fe:a9fe 2002:a9fe:a9fe::1 2001:0:a9fe:a9fe::1 fd00:ec2::254

# Sanity: there must be no route out of this namespace.
if python3 -c 'import socket; socket.create_connection(("1.1.1.1", 53), timeout=1)' 2>/dev/null; then
  echo "e2e: test network unexpectedly has outside connectivity" >&2; exit 3
fi
