FROM alpine:3.19

# Install fail2ban and dependencies
RUN apk add --no-cache \
    fail2ban \
    iptables \
    python3 \
    py3-pip \
    tzdata \
    bash

# Create necessary directories
RUN mkdir -p /var/run/fail2ban \
    /var/log/fail2ban \
    /var/log/haproxy \
    /var/lib/fail2ban \
    /etc/fail2ban/filter.d \
    /etc/fail2ban/action.d \
    /etc/fail2ban/jail.d

# Create empty log file and fix permissions
RUN touch /var/log/fail2ban/fail2ban.log && \
    chmod 666 /var/log/fail2ban/fail2ban.log

# Copy configuration files
COPY fail2ban/jail.local /etc/fail2ban/jail.local
COPY fail2ban/filter.d/* /etc/fail2ban/filter.d/
# COPY fail2ban/action.d/* /etc/fail2ban/action.d/ (Use defaults)

# Set timezone
ENV TZ=Europe/Istanbul

# Healthcheck
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD fail2ban-client ping || exit 1

# Start fail2ban in foreground
CMD ["fail2ban-server", "-f", "-x", "-v", "start"]
