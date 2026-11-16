#!/bin/sh
# Runs inside the outer sandbox as namespace-root: mount the toolchain, configure
# the private network, then run the E2E test suite.
set -eu
mkdir -p /mnt/upper /mnt/work
mount -t overlay overlay -o "lowerdir=$EGRESS_E2E_ROOT/usr:/usr,upperdir=/mnt/upper,workdir=/mnt/work" /usr
sh "$EGRESS_E2E_REPO/tests/e2e/network_setup.sh"
cd "$EGRESS_E2E_REPO"
exec python3 -m unittest discover -s "${EGRESS_E2E_SUITE:-tests/e2e}" -t . -p 'test_*.py' "$@"
