#!/bin/bash
# Manual DNS Challenge Flow Test Script
# Bu script manuel DNS challenge flow'unu test eder

set -e

echo "=== HAProxy Docker Manual DNS Challenge Test ==="
echo

# Renk kodları
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test fonksiyonları
test_step() {
    local step_name="$1"
    local command="$2"
    
    echo -e "${BLUE}Testing:${NC} $step_name"
    
    if eval "$command"; then
        echo -e "${GREEN}✓${NC} $step_name: PASSED"
    else
        echo -e "${RED}✗${NC} $step_name: FAILED"
        return 1
    fi
    echo
}

check_container() {
    local container_name="$1"
    
    if docker ps --format 'table {{.Names}}' | grep -q "^$container_name$"; then
        echo -e "${GREEN}✓${NC} Container $container_name is running"
        return 0
    else
        echo -e "${RED}✗${NC} Container $container_name is not running"
        return 1
    fi
}

check_port() {
    local port="$1"
    local service="$2"
    
    if nc -z localhost "$port" 2>/dev/null; then
        echo -e "${GREEN}✓${NC} $service (port $port) is accessible"
        return 0
    else
        echo -e "${RED}✗${NC} $service (port $port) is not accessible"
        return 1
    fi
}

test_api_endpoint() {
    local endpoint="$1"
    local expected_status="$2"
    
    local response=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost:3000$endpoint" 2>/dev/null || echo "000")
    
    if [ "$response" = "$expected_status" ]; then
        echo -e "${GREEN}✓${NC} API endpoint $endpoint returns $response"
        return 0
    else
        echo -e "${RED}✗${NC} API endpoint $endpoint returns $response (expected $expected_status)"
        return 1
    fi
}

# Ana test süreci
echo "Step 1: Docker Container Status Check"
echo "====================================="
check_container "haproxy" || echo "HAProxy container not running"
check_container "certbot" || echo "Certbot container not running"
check_container "haproxy-api" || echo "API container not running"
check_container "haproxy-web" || echo "Web container not running"
check_container "haproxy-db" || echo "Database container not running"
echo

echo "Step 2: Port Accessibility Check"
echo "==============================="
check_port 80 "HAProxy HTTP" || echo "HAProxy HTTP not accessible"
check_port 443 "HAProxy HTTPS" || echo "HAProxy HTTPS not accessible"
check_port 3000 "API Server" || echo "API Server not accessible"
check_port 8404 "HAProxy Stats" || echo "HAProxy Stats not accessible"
echo

echo "Step 3: API Endpoint Tests"
echo "========================="
test_api_endpoint "/" "200" || echo "API root endpoint failed"
test_api_endpoint "/api/health" "200" || echo "API health endpoint failed"
test_api_endpoint "/api/ssl/certificates" "401" || echo "API SSL endpoint failed (should require auth)"
echo

echo "Step 4: Docker Compose Status"
echo "============================"
if [ -f "docker-compose.yml" ]; then
    echo "Docker Compose file exists"
    
    # Container durumlarını göster
    echo "Container status:"
    docker-compose ps 2>/dev/null || echo "Docker Compose not running or not available"
    echo
    
    # Log'ları kontrol et
    echo "Recent container logs:"
    echo "API logs (last 5 lines):"
    docker-compose logs --tail=5 api 2>/dev/null || echo "API logs not available"
    echo
    
    echo "Web logs (last 5 lines):"
    docker-compose logs --tail=5 web 2>/dev/null || echo "Web logs not available"
    echo
else
    echo -e "${RED}✗${NC} docker-compose.yml not found"
fi

echo "Step 5: Manual DNS Challenge Simulation"
echo "======================================"
echo "To test manual DNS challenge flow:"
echo "1. Start containers: docker-compose up -d"
echo "2. Access web interface: http://localhost:3000"
echo "3. Navigate to SSL management section"
echo "4. Request wildcard certificate for test domain"
echo "5. Verify DNS challenge modal appears"
echo "6. Check TXT record format and values"
echo "7. Test DNS propagation checker"
echo

echo -e "${BLUE}=== Test Complete ===${NC}"
echo ""
echo "To start the system:"
echo "cd /Users/umiteyigun/projeler/haproxy"
echo "docker-compose up -d"
echo ""
echo "To view logs:"
echo "docker-compose logs -f api"
echo "docker-compose logs -f web"
