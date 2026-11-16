#!/bin/sh
# Container entrypoint: render Squid's configuration from EGRESS_* settings,
# validate it, and exec Squid in the foreground as the (non-root) container user.
#
# Secrets must not live in the environment of Squid or its helpers (review M-7):
# values passed as EGRESS_POLICY_TOKEN / EGRESS_DEMO_PASSWORD are moved into files
# under $EGRESS_RUN_DIR and unset before Squid starts. Prefer the *_FILE variants.
set -eu
umask 077

RUN_DIR="${EGRESS_RUN_DIR:-/run/egress}"
export EGRESS_RUN_DIR="$RUN_DIR"
if [ "$(id -u)" = 0 ] && [ "${EGRESS_ALLOW_ROOT:-0}" != 1 ]; then
  echo "egress: refusing to run as root; run the container as an unprivileged user" >&2
  exit 1
fi
PYTHON="${EGRESS_PYTHON:-$(command -v python3)}"
export EGRESS_PYTHON="$PYTHON"
mkdir -p "$RUN_DIR/tmp"
# The root filesystem is read-only in production (compose read_only / readOnlyRootFilesystem);
# tools such as htpasswd need a writable temporary directory.
export TMPDIR="$RUN_DIR/tmp"

# Move an inline secret into a file and drop it from the environment.
secret_to_file() { # <VAR> <file name>
  eval "value=\${$1:-}"
  if [ -n "$value" ]; then
    printf '%s' "$value" > "$RUN_DIR/$2"
    eval "export $1_FILE=\"\$RUN_DIR/\$2\""
  fi
  unset "$1" value
}
secret_to_file EGRESS_POLICY_TOKEN policy-token

# Demo / single-user mode (Compose quick start only).
if [ -n "${EGRESS_DEMO_USER:-}" ]; then
  case "$EGRESS_DEMO_USER" in *[!a-z0-9._-]*) echo "egress: EGRESS_DEMO_USER must match [a-z0-9._-]+" >&2; exit 1;; esac
  if [ -n "${EGRESS_DEMO_PASSWORD_FILE:-}" ]; then
    password=$(cat "$EGRESS_DEMO_PASSWORD_FILE")
  else
    password="${EGRESS_DEMO_PASSWORD:?set EGRESS_DEMO_PASSWORD or EGRESS_DEMO_PASSWORD_FILE}"
  fi
  unset EGRESS_DEMO_PASSWORD
  # -i reads the password from stdin so it never appears in a process argument list.
  printf '%s\n' "$password" | htpasswd -i -cB "$RUN_DIR/htpasswd" "$EGRESS_DEMO_USER" >/dev/null 2>&1
  unset password
  export EGRESS_AUTH_MODE=htpasswd EGRESS_HTPASSWD_FILE="$RUN_DIR/htpasswd"
fi

# Identifies this instance in logs and metrics (the pod name in Kubernetes).
export EGRESS_INSTANCE_ID="${EGRESS_INSTANCE_ID:-$(hostname 2>/dev/null || echo egress)}"

"$PYTHON" -m clearideas_egress.render >/dev/null
if ! squid -k parse -f "$RUN_DIR/squid.conf" >"$RUN_DIR/parse.log" 2>&1; then
  cat "$RUN_DIR/parse.log" >&2
  echo "egress: generated squid.conf failed validation" >&2
  exit 1
fi
# Health, readiness and metrics (EGRESS_MONITOR_PORT, default 9090). Set EGRESS_MONITOR=off to run
# clearideas-egress-monitor as a separate (sidecar) container sharing $EGRESS_RUN_DIR instead.
# The container runs under "tini -g", so SIGTERM reaches both Squid and the monitor.
if [ "${EGRESS_MONITOR:-on}" != off ]; then
  "$PYTHON" -m clearideas_egress monitor &
fi
exec squid -N -f "$RUN_DIR/squid.conf"
