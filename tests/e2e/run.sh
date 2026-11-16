#!/bin/sh
# End-to-end tests in an isolated bubblewrap sandbox (no root, no Docker).
#
#   outer sandbox: new user+network namespace (no route out), namespace-root,
#                  pinned toolchain overlaid on /usr, fixtures on fake public IPs
#   nested sandbox: Squid + helpers as uid 1000, all capabilities dropped,
#                   read-only root filesystem except the per-test run directory
#
# Usage: tests/e2e/run.sh [unittest args, e.g. test_c1_dns or -k sni]
#        EGRESS_E2E_TARGET=baseline tests/e2e/run.sh ...   # run against the pre-remediation code
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
CACHE=${EGRESS_E2E_CACHE:-$REPO/.e2e-cache}

command -v bwrap >/dev/null || { echo "e2e: bubblewrap (bwrap) is required" >&2; exit 2; }
"$HERE/fetch_toolchain.sh" >/dev/null
ROOT="$CACHE/root"
WORK=$(mktemp -d "${TMPDIR:-/tmp}/egress-e2e.XXXXXX")
if [ "${EGRESS_E2E_KEEP:-0}" = 1 ]; then echo "e2e: keeping $WORK" >&2; else trap 'rm -rf "$WORK"' EXIT INT TERM; fi

BASELINE_BIND=""
if [ -n "${EGRESS_E2E_BASELINE_DIR:-}" ]; then BASELINE_BIND="--ro-bind $EGRESS_E2E_BASELINE_DIR $EGRESS_E2E_BASELINE_DIR"; fi

# shellcheck disable=SC2086
bwrap \
  --ro-bind / / \
  --bind "$WORK" "$WORK" \
  --ro-bind "$REPO" "$REPO" \
  $BASELINE_BIND \
  --dev /dev --proc /proc --tmpfs /run --tmpfs /mnt \
  --unshare-all --uid 0 --gid 0 --cap-add ALL --die-with-parent \
  --setenv EGRESS_E2E_WORK "$WORK" \
  --setenv EGRESS_E2E_ROOT "$ROOT" \
  --setenv EGRESS_E2E_REPO "$REPO" \
  --setenv PYTHONDONTWRITEBYTECODE 1 \
  --setenv EGRESS_E2E_TRACE "${EGRESS_E2E_TRACE:-}" \
  --setenv EGRESS_E2E_SUITE "${EGRESS_E2E_SUITE:-tests/e2e}" \
  --setenv EGRESS_E2E_RUNTIME "${EGRESS_E2E_RUNTIME:-bwrap}" \
  --setenv EGRESS_E2E_PACKAGE_PATH "${EGRESS_E2E_PACKAGE_PATH:-}" \
  --setenv TMPDIR "$WORK" \
  --setenv PYTHONPATH "$REPO/src" \
  --chdir "$REPO" \
  /bin/sh "$HERE/sandbox_init.sh" "$@"
