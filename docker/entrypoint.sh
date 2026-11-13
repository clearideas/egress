#!/bin/sh
set -eu
: "${EGRESS_PROXY_USER:?Set EGRESS_PROXY_USER}"
: "${EGRESS_PROXY_PASSWORD:?Set EGRESS_PROXY_PASSWORD}"
case "$EGRESS_PROXY_USER" in *[!a-zA-Z0-9._-]*|'') echo 'Invalid EGRESS_PROXY_USER' >&2; exit 1;; esac

AUTH_HELPER="$(command -v basic_ncsa_auth || true)"
if [ -z "$AUTH_HELPER" ]; then
  AUTH_HELPER="$(find /usr/lib /usr/libexec -name basic_ncsa_auth -print -quit 2>/dev/null)"
fi
test -n "$AUTH_HELPER"
sed "s#__BASIC_AUTH_HELPER__#${AUTH_HELPER}#g" /etc/squid/squid.conf.template > /etc/squid/squid.conf
umask 077
htpasswd -bcB /etc/squid/passwd "$EGRESS_PROXY_USER" "$EGRESS_PROXY_PASSWORD" >/dev/null
chown root:squid /etc/squid/passwd
chmod 0640 /etc/squid/passwd
squid -k parse -f /etc/squid/squid.conf
exec squid -N -f /etc/squid/squid.conf
