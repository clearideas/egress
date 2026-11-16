#!/bin/sh
# Runs inside the E2E test container (docker run --network none --cap-add NET_ADMIN ...), as root.
# Fixtures run as root; Squid, its helpers and the monitor run as the image's unprivileged user.
set -eu
sh /src/tests/e2e/network_setup.sh
WORK=$(mktemp -d /tmp/egress-e2e.XXXXXX)
chmod 0755 "$WORK"
export EGRESS_E2E_WORK="$WORK" EGRESS_E2E_REPO=/src EGRESS_E2E_RUNTIME=container
export EGRESS_E2E_RUN_AS="${EGRESS_E2E_RUN_AS:-squid}" TMPDIR="$WORK" PYTHONDONTWRITEBYTECODE=1
# Only the tests are taken from the checkout; the package under test is the one installed in the image.
export PYTHONPATH=/src
cd /src
echo "e2e: $(squid -v | head -1); $(python3 --version); package $(python3 -c 'import clearideas_egress, os; print(os.path.dirname(clearideas_egress.__file__))')" >&2
exec python3 -m unittest discover -s "${EGRESS_E2E_SUITE:-tests/e2e}" -t /src -p "${EGRESS_E2E_PATTERN:-test_*.py}" "$@"
