#!/bin/bash
# Volume Mount Validation Script
# Bu script tüm volume mount'ların doğru şekilde yapılandırıldığını kontrol eder

set -e

echo "=== HAProxy Docker Volume Mount Validation ==="
echo

# Renk kodları
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Kontrol fonksiyonu
check_directory() {
    local dir="$1"
    local description="$2"
    local required="$3"
    
    if [ -d "$dir" ]; then
        echo -e "${GREEN}✓${NC} $description: $dir"
        
        # Dizin izinlerini kontrol et
        local perms=$(stat -f "%A" "$dir" 2>/dev/null || stat -c "%a" "$dir" 2>/dev/null)
        echo "  Permissions: $perms"
        
        # Dosya sayısını göster
        local file_count=$(find "$dir" -type f 2>/dev/null | wc -l | tr -d ' ')
        echo "  Files: $file_count"
        
    elif [ "$required" = "true" ]; then
        echo -e "${RED}✗${NC} $description: $dir (MISSING - REQUIRED)"
        return 1
    else
        echo -e "${YELLOW}!${NC} $description: $dir (missing - will be created)"
    fi
    echo
}

check_file() {
    local file="$1"
    local description="$2"
    local required="$3"
    
    if [ -f "$file" ]; then
        echo -e "${GREEN}✓${NC} $description: $file"
        
        # Dosya boyutunu göster
        local size=$(du -h "$file" | cut -f1)
        echo "  Size: $size"
        
        # Dosya izinlerini kontrol et
        local perms=$(stat -f "%A" "$file" 2>/dev/null || stat -c "%a" "$file" 2>/dev/null)
        echo "  Permissions: $perms"
        
    elif [ "$required" = "true" ]; then
        echo -e "${RED}✗${NC} $description: $file (MISSING - REQUIRED)"
        return 1
    else
        echo -e "${YELLOW}!${NC} $description: $file (missing - will be created)"
    fi
    echo
}

echo "Checking HAProxy volumes..."
check_file "./haproxy/haproxy.cfg" "HAProxy Main Config" "true"
check_directory "./haproxy/config.d" "HAProxy Config Directory" "true"
check_directory "./haproxy/maps" "HAProxy Maps Directory" "true"
check_directory "./haproxy/certs" "HAProxy Certificates" "true"
check_directory "./haproxy/sockets" "HAProxy Sockets" "false"
check_directory "./logs/haproxy" "HAProxy Logs" "false"

echo "Checking Certbot volumes..."
check_directory "./certbot/conf" "Certbot Configuration" "false"
check_directory "./certbot/www" "Certbot Webroot" "false"
check_directory "./certbot/creds" "Certbot Credentials" "true"
check_directory "./logs/certbot" "Certbot Logs" "false"

echo "Checking API volumes..."
check_directory "./data/api" "API Data Directory" "false"
check_directory "./logs/api" "API Logs Directory" "false"

echo "Checking Web volumes..."
check_directory "./web" "Web Files" "true"
check_directory "./web/.well-known/acme-challenge" "ACME Challenge Directory" "false"

echo "Checking Database volumes..."
check_directory "./data/postgres" "PostgreSQL Data" "false"

echo "Checking Docker socket..."
check_file "/var/run/docker.sock" "Docker Socket" "true"

echo -e "${GREEN}=== Volume Mount Validation Complete ===${NC}"
echo ""
echo "To create missing directories, run:"
echo "mkdir -p ./haproxy/sockets ./certbot/conf ./certbot/www ./data/api ./logs/{api,certbot,haproxy} ./web/.well-known/acme-challenge"
echo ""
echo "To set proper permissions:"
echo "chmod 755 ./haproxy/sockets ./certbot/conf ./certbot/www"
echo "chmod 600 ./certbot/creds/*.ini"
echo "chmod 644 ./haproxy/haproxy.cfg"
