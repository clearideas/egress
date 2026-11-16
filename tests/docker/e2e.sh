#!/bin/sh
# Build the production image and run the E2E suite inside a container built from it.
#   tests/docker/e2e.sh [unittest args, e.g. -k sni]
# Environment: EGRESS_IMAGE (default clearideas-egress:test), DOCKER (default docker),
#              EGRESS_IMAGE_PREBUILT=1 to test an already built $EGRESS_IMAGE instead of building it,
#              EGRESS_DOCKER_VOLUME_OPTS (default "ro"; SELinux hosts: "ro,z").
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
DOCKER=${DOCKER:-docker}
IMAGE=${EGRESS_IMAGE:-clearideas-egress:test}

if [ "${EGRESS_IMAGE_PREBUILT:-0}" != 1 ]; then
  echo "docker e2e: building $IMAGE" >&2
  $DOCKER build -q -t "$IMAGE" "$REPO" >/dev/null
fi
$DOCKER build -q -t "$IMAGE-e2e" --build-arg BASE="$IMAGE" -f "$HERE/Dockerfile.e2e" "$HERE" >/dev/null

# --network none: no route out (only loopback); NET_ADMIN: test addresses and nftables inside the
# container's own network namespace. SYS_PTRACE lets the root test harness inspect the unprivileged
# proxy process environments for leaked secrets. IPv6 must be enabled on loopback for the IPv6 cases.
run_suite() {
  $DOCKER run --rm --network none --cap-add NET_ADMIN --cap-add SYS_PTRACE \
    --sysctl net.ipv6.conf.all.disable_ipv6=0 --sysctl net.ipv6.conf.lo.disable_ipv6=0 \
    -e EGRESS_E2E_SUITE="${EGRESS_E2E_SUITE:-tests/e2e}" \
    -e EGRESS_E2E_PATTERN="${EGRESS_E2E_PATTERN:-test_*.py}" \
    -e EGRESS_PERF_SECONDS="${EGRESS_PERF_SECONDS:-8}" \
    -v "$REPO:/src:${EGRESS_DOCKER_VOLUME_OPTS:-ro}" "$IMAGE-e2e" "$@"
}

# A long-lived test container accumulates state across dozens of short-lived Squid
# instances. Isolate each module so the full suite has the same clean start as a
# focused run. Keep -k focused runs in one container for quick diagnosis.
focused=0
for arg in "$@"; do
  [ "$arg" = -k ] && focused=1
done
if [ "${EGRESS_E2E_SUITE:-tests/e2e}" != tests/e2e ] || [ -n "${EGRESS_E2E_PATTERN:-}" ] || [ "$focused" = 1 ]; then
  run_suite "$@"
else
  for module in "$REPO"/tests/e2e/test_*.py; do
    EGRESS_E2E_PATTERN=$(basename "$module")
    export EGRESS_E2E_PATTERN
    echo "docker e2e: $EGRESS_E2E_PATTERN" >&2
    run_suite "$@"
  done
fi
