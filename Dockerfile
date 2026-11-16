# Multi-platform image index for Python 3.12.16 on Alpine 3.24 (2026-11-16).
# (tests/unit/test_deploy.py SupplyChainTests checks the Dockerfile's basics.)
ARG PYTHON_IMAGE=python:3.12-alpine@sha256:c5ba3deef00c7758561a0f03c26f44f10589263d40e732b8748e0d1f38f6dd89
FROM ${PYTHON_IMAGE}

# openssl: generates the throwaway certificate Squid requires on its ssl-bump port.
# Squid revision tested by the unit, E2E and image smoke suites.
ARG SQUID_PACKAGE=squid=7.6-r0
RUN apk add --no-cache "${SQUID_PACKAGE}" apache2-utils openssl tini

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src/ ./src/
RUN python -m pip install --no-cache-dir . && rm -rf /app/src

COPY docker/entrypoint.sh /usr/local/bin/egress-entrypoint
# Strip CRs (Windows checkouts). The Alpine squid package's user is uid/gid 31; fail the build
# loudly if that ever changes, because the numeric USER below lets Kubernetes verify runAsNonRoot.
RUN [ "$(id -u squid):$(id -g squid)" = "31:31" ] \
  && sed -i 's/\r$//' /usr/local/bin/egress-entrypoint \
  && chmod 0755 /usr/local/bin/egress-entrypoint \
  && mkdir -p /run/egress \
  && chown squid:squid /run/egress \
  && chmod 0700 /run/egress

# Never run as root (review M-7). Squid listens on an unprivileged port. Numeric (user "squid") so that
# Kubernetes can enforce runAsNonRoot without an explicit runAsUser.
USER 31:31
ENV EGRESS_RUN_DIR=/run/egress
# 3128: proxy; 9090: /livez, /readyz, /metrics (restrict to the kubelet and Prometheus)
EXPOSE 3128 9090
# -g: forward signals to the whole process group (Squid and the monitor) for graceful drain.
ENTRYPOINT ["/sbin/tini", "-g", "--", "/usr/local/bin/egress-entrypoint"]
