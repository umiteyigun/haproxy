#!/bin/bash

echo "=== HAProxy Docker Quick Test ==="
echo

# Proje dizinine git
cd /Users/umiteyigun/projeler/haproxy

# Docker servisinin çalışıp çalışmadığını kontrol et
echo "Docker servisi kontrolü:"
docker --version
echo

# Mevcut container'ları kontrol et
echo "Mevcut container'lar:"
docker ps -a
echo

# Eğer container'lar varsa durdur
echo "Eski container'ları temizliyorum..."
docker-compose down 2>/dev/null || true
echo

# Container'ları başlat
echo "Container'ları başlatıyorum..."
docker-compose up -d --build
echo

# 15 saniye bekle
echo "Container'ların başlaması için 15 saniye bekleniyor..."
sleep 15

# Container durumlarını kontrol et
echo "Container durumları:"
docker ps
echo

# Container loglarını kısaca kontrol et
echo "=== API Container Logları ==="
docker logs api --tail 10
echo

echo "=== Web Container Logları ==="
docker logs web --tail 10
echo

# Port kontrolleri
echo "=== Port Kontrolleri ==="
echo "API (3000): "
curl -s -m 5 http://localhost:3000/api/health || echo "Bağlantı başarısız"
echo

echo "Web (8080): "
curl -s -m 5 http://localhost:8080 | head -c 100 || echo "Bağlantı başarısız"
echo

echo "HAProxy (80): "
curl -s -m 5 http://localhost:80 | head -c 100 || echo "Bağlantı başarısız"
echo

echo "=== Test Tamamlandı ==="
