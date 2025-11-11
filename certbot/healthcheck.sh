#!/bin/bash
# Health check script for Certbot container

set -e

# Check if certbot is available
if ! command -v certbot > /dev/null 2>&1; then
    echo "ERROR: certbot command not found"
    exit 1
fi

# Check if expect is available
if ! command -v expect > /dev/null 2>&1; then
    echo "ERROR: expect command not found"
    exit 1
fi

# Check if DNS tools are available
if ! command -v dig > /dev/null 2>&1; then
    echo "ERROR: dig command not found"
    exit 1
fi

# Check if credentials directory is accessible
if [ ! -d "/etc/letsencrypt/creds" ]; then
    echo "ERROR: credentials directory not found"
    exit 1
fi

# Check if Let's Encrypt directory is writable
if [ ! -w "/etc/letsencrypt" ]; then
    echo "ERROR: Let's Encrypt directory not writable"
    exit 1
fi

# Test certbot version
CERTBOT_VERSION=$(certbot --version 2>&1 | grep -o '[0-9]\+\.[0-9]\+\.[0-9]\+' | head -1)
if [ -z "$CERTBOT_VERSION" ]; then
    echo "ERROR: Could not determine certbot version"
    exit 1
fi

echo "OK: Certbot container healthy (version: $CERTBOT_VERSION)"
exit 0
