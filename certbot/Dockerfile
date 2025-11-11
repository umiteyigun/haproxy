FROM certbot/certbot:latest

# Install system dependencies
RUN apk add --no-cache \
    expect \
    tcl \
    bind-tools \
    curl \
    jq \
    bash \
    openssl

# Install DNS plugins
RUN pip install --no-cache-dir \
    certbot-dns-cloudflare \
    certbot-dns-route53 \
    certbot-dns-digitalocean \
    certbot-dns-godaddy \
    certbot-dns-ovh \
    certbot-dns-google \
    certbot-dns-dnsimple \
    certbot-dns-rfc2136

# Create non-root user for security
RUN addgroup -g 1000 certbot && \
    adduser -D -u 1000 -G certbot certbot

# Create necessary directories
RUN mkdir -p /etc/letsencrypt/creds /var/log/letsencrypt /scripts && \
    chown -R certbot:certbot /etc/letsencrypt /var/log/letsencrypt /scripts

# Copy expect script
COPY expect-certbot.sh /scripts/expect-certbot.sh
RUN chmod +x /scripts/expect-certbot.sh && \
    chown certbot:certbot /scripts/expect-certbot.sh

# Add health check script
COPY healthcheck.sh /scripts/healthcheck.sh
RUN chmod +x /scripts/healthcheck.sh

# Switch to non-root user
USER certbot

# Set working directory
WORKDIR /etc/letsencrypt

# Add health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD ["/scripts/healthcheck.sh"]

# Note: Hurricane Electric (he-net) DNS API integration
# Create credentials file with format: dns_he_net_api_key = <api_key>
# Custom plugin implementation available in ssl-manager.js

