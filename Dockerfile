FROM python:3.12-alpine
RUN apk add --no-cache squid apache2-utils tini
WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src/ ./src/
RUN python -m pip install --no-cache-dir .
COPY docker/squid.conf.template /etc/squid/squid.conf.template
COPY docker/entrypoint.sh /usr/local/bin/egress-entrypoint
RUN chmod +x /usr/local/bin/egress-entrypoint \
  && mkdir -p /var/log/squid /run/squid \
  && chown -R squid:squid /var/log/squid /run/squid
EXPOSE 3128
ENTRYPOINT ["/sbin/tini", "--", "/usr/local/bin/egress-entrypoint"]
