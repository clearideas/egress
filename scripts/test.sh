#!/bin/sh
# The whole test suite in one command (`make test`). Sets up what it needs, picks a way to run the
# end-to-end tests on this machine, and fails -- rather than silently skipping -- when it can't.
#
# Stages
#   unit    unit tests + byte-compile (host Python >= 3.11; otherwise inside the image via Docker)
#   e2e     real Squid, fixtures on fake public IPs, no route out. Runner:
#             bwrap   rootless bubblewrap sandbox with the pinned Ubuntu 24.04 toolchain
#                     (Linux amd64 with unprivileged user namespaces; toolchain downloaded once)
#             docker  inside a container built from the production image (tests/docker/e2e.sh):
#                     the image's own Squid, Python, package and entrypoint (macOS, Windows, any Linux)
#   smoke   black-box test of the production image as deployed (tests/docker/smoke.py); needs Docker
#
# Environment
#   EGRESS_TEST_RUNNER  auto (default) | bwrap | docker | none   -- E2E runner; "none" skips E2E
#   EGRESS_TEST_SMOKE   auto (default: when Docker is available) | 1 | 0
#   PYTHON              Python interpreter for the unit tests (default: newest python3.x >= 3.11)
#   DOCKER              container CLI (default docker; podman is not tested)
#   EGRESS_IMAGE        image tag to build and test (default clearideas-egress:test)
#   EGRESS_DOCKER_VOLUME_OPTS  bind-mount options (default ro; SELinux hosts: ro,z)
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/.." && pwd)
cd "$REPO" || exit 2
RUNNER=${EGRESS_TEST_RUNNER:-auto}
SMOKE=${EGRESS_TEST_SMOKE:-auto}
DOCKER=${DOCKER:-docker}
export DOCKER
IMAGE=${EGRESS_IMAGE:-clearideas-egress:test}
export EGRESS_IMAGE="$IMAGE"
SUMMARY=""
FAILED=0
IMAGE_BUILT=0

say() { printf '\n==> %s\n' "$*" >&2; }
record() { # <stage> <PASS|FAIL|SKIP> [note]
  SUMMARY="$SUMMARY$(printf '%-6s %-5s %s' "$1" "$2" "${3:-}")
"
  [ "$2" = FAIL ] && FAILED=1
  return 0
}

# --- environment probes ----------------------------------------------------------
find_python() {
  for candidate in ${PYTHON:-} python3 python3.13 python3.12 python3.11; do
    command -v "$candidate" >/dev/null 2>&1 || continue
    if "$candidate" -c 'import sys; raise SystemExit(sys.version_info < (3, 11))' 2>/dev/null; then
      command -v "$candidate"; return 0
    fi
  done
  return 1
}

docker_ok() { command -v "$DOCKER" >/dev/null 2>&1 && "$DOCKER" info >/dev/null 2>&1; }

# Why bwrap can't be used here (empty when it can).
bwrap_problem() {
  [ "$(uname -s)" = Linux ] || { echo "not Linux"; return; }
  command -v bwrap >/dev/null 2>&1 || { echo "bubblewrap not installed (Ubuntu/Debian: sudo apt-get install bubblewrap)"; return; }
  if ! bwrap --ro-bind / / --dev /dev --proc /proc --unshare-all --uid 0 --gid 0 --cap-add ALL true >/dev/null 2>&1; then
    echo "unprivileged user namespaces are blocked (Ubuntu 24.04: sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0)"
    return
  fi
  cache=${EGRESS_E2E_CACHE:-$REPO/.e2e-cache}
  if [ -f "$cache/root/.complete" ] && cmp -s tests/e2e/toolchain.lock "$cache/root/.lock"; then return; fi
  # The toolchain is pinned Ubuntu 24.04 (noble) amd64 packages, fetched with the host's apt.
  # shellcheck source=/dev/null
  . /etc/os-release 2>/dev/null || true
  if [ "${VERSION_CODENAME:-}" != noble ] || [ "$(dpkg --print-architecture 2>/dev/null)" != amd64 ] \
     || ! command -v apt-get >/dev/null 2>&1; then
    echo "the pinned E2E toolchain needs an Ubuntu 24.04 amd64 host (or a populated .e2e-cache)"
    return
  fi
}

build_image() {
  [ "$IMAGE_BUILT" = 1 ] && return 0
  say "building $IMAGE"
  "$DOCKER" build -q -t "$IMAGE" "$REPO" >/dev/null && IMAGE_BUILT=1
}

# --- unit ------------------------------------------------------------------------
if PY=$(find_python); then
  say "unit tests ($("$PY" --version 2>&1))"
  if PYTHONPATH=src "$PY" -m unittest discover -s tests/unit -t . && "$PY" -m compileall -q src tests >/dev/null; then
    record unit PASS "$("$PY" --version 2>&1)"
  else
    record unit FAIL
  fi
elif docker_ok; then
  say "unit tests (no Python >= 3.11 on this host: running inside the image)"
  if build_image && "$DOCKER" run --rm -v "$REPO:/src:${EGRESS_DOCKER_VOLUME_OPTS:-ro}" -w /src -e PYTHONPATH=/src/src -e PYTHONDONTWRITEBYTECODE=1 \
       --entrypoint python3 "$IMAGE" -m unittest discover -s tests/unit -t .; then
    record unit PASS "in $IMAGE"
  else
    record unit FAIL "in $IMAGE"
  fi
else
  record unit FAIL "needs Python >= 3.11 (or Docker)"
fi

# --- e2e -------------------------------------------------------------------------
if [ "$RUNNER" = auto ]; then
  problem=$(bwrap_problem)
  if [ -z "$problem" ]; then
    RUNNER=bwrap
  elif docker_ok; then
    say "e2e: using Docker ($problem)"
    RUNNER=docker
  else
    RUNNER=unavailable
    record e2e FAIL "no runner: bwrap: $problem; Docker: not available. Install Docker, or set EGRESS_TEST_RUNNER=none to skip"
  fi
fi
case "$RUNNER" in
  bwrap)
    say "e2e in a bubblewrap sandbox"
    problem=$(bwrap_problem)
    if [ -n "$problem" ]; then
      record e2e FAIL "bwrap: $problem"
    elif tests/e2e/run.sh; then
      record e2e PASS bwrap
    else
      record e2e FAIL bwrap
    fi ;;
  docker)
    say "e2e in a container built from the image"
    if ! docker_ok; then
      record e2e FAIL "Docker is not available ($DOCKER info failed)"
    elif build_image && EGRESS_IMAGE_PREBUILT=1 tests/docker/e2e.sh; then
      record e2e PASS docker
    else
      record e2e FAIL docker
    fi ;;
  none) record e2e SKIP "EGRESS_TEST_RUNNER=none" ;;
  unavailable) ;;
  *) record e2e FAIL "unknown EGRESS_TEST_RUNNER=$RUNNER (auto|bwrap|docker|none)" ;;
esac

# --- smoke -----------------------------------------------------------------------
if [ "$SMOKE" = auto ]; then
  if docker_ok; then SMOKE=1; else SMOKE=0; record smoke SKIP "Docker not available"; fi
fi
if [ "$SMOKE" = 1 ]; then
  say "image smoke test"
  SMOKE_PY=$(command -v python3 || true)
  if [ -z "$SMOKE_PY" ]; then
    record smoke FAIL "needs python3 on the host"
  elif ! docker_ok; then
    record smoke FAIL "Docker is not available"
  elif build_image && "$SMOKE_PY" tests/docker/smoke.py --no-build --image "$IMAGE"; then
    record smoke PASS
  else
    record smoke FAIL
  fi
fi

printf '\n==> summary\n%s' "$SUMMARY" >&2
exit "$FAILED"
