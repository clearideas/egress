FROM node:22-alpine
RUN apk add --no-cache squid apache2-utils tini
WORKDIR /app
COPY package.json ./
COPY src/ ./src/
COPY bin/ ./bin/
COPY docker/squid.conf.template /etc/squid/squid.conf.template
COPY docker/entrypoint.sh /usr/local/bin/egress-entrypoint
RUN chmod +x /app/bin/egress-acl.js /usr/local/bin/egress-entrypoint \
  && ln -s /app/bin/egress-acl.js /usr/local/bin/clearideas-egress-acl \
  && mkdir -p /var/log/squid /run/squid \
  && chown -R squid:squid /var/log/squid /run/squid
EXPOSE 3128
ENTRYPOINT ["/sbin/tini", "--", "/usr/local/bin/egress-entrypoint"]
