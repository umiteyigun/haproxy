FROM ghcr.io/coreruleset/modsecurity-crs:nginx

# Copy custom rules and configuration
COPY rules/ /etc/modsecurity.d/rules/
COPY modsecurity.conf /etc/modsecurity.d/modsecurity.conf
COPY crs-setup.conf /etc/modsecurity.d/crs-setup.conf

# Enable audit logging to stdout for easier ingestion
RUN sed -i 's/SecAuditLog .*/SecAuditLog \/dev\/stdout/' /etc/modsecurity.d/modsecurity.conf

CMD ["/docker-entrypoint.sh"]
