#!/bin/bash

echo "=== HAProxy Docker Test Başlatılıyor ==="
echo

# Proje dizinine git
cd /Users/umiteyigun/projeler/haproxy

# Docker container'ları kontrol et
echo "Docker container durumları:"
docker ps -a --filter name=haproxy --filter name=certbot --filter name=api
echo

# Eğer container'lar çalışmıyorsa başlat
echo "Container'ları başlatıyorum..."
docker-compose up -d
echo

# 10 saniye bekle
echo "Container'ların başlaması için 10 saniye bekleniyor..."
sleep 10

# Container durumlarını tekrar kontrol et
echo "Container durumları (başlatma sonrası):"
docker ps --filter name=haproxy --filter name=certbot --filter name=api
echo

# Port'ları kontrol et
echo "Port kontrolü:"
echo "- Port 3000 (API): "
curl -s -o /dev/null -w "%{http_code}" http://localhost:3000 || echo "Bağlantı başarısız"
echo
echo "- Port 8080 (Web): "
curl -s -o /dev/null -w "%{http_code}" http://localhost:8080 || echo "Bağlantı başarısız"
echo
echo "- Port 80 (HAProxy): "
curl -s -o /dev/null -w "%{http_code}" http://localhost:80 || echo "Bağlantı başarısız"
echo

# Test script'ini çalıştır
echo "=== Test Script Çalıştırılıyor ==="
chmod +x ./test-manual-dns.sh
./test-manual-dns.sh
