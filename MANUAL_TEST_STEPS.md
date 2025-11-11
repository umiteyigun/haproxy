# HAProxy Docker Manual Test Adımları

## 1. Ön Koşullar

### Docker Desktop Kontrolü
- Docker Desktop'ın çalıştığından emin olun
- Terminal'de `docker --version` komutunu çalıştırın

### Proje Dizini
```bash
cd /Users/umiteyigun/projeler/haproxy
```

## 2. Container Başlatma

### Eski Container'ları Temizle
```bash
docker-compose down
docker system prune -f
```

### Container'ları Başlat
```bash
docker-compose up -d --build
```

### Container Durumunu Kontrol Et
```bash
docker ps
docker logs api
docker logs web
docker logs haproxy
```

## 3. Servis Kontrolleri

### API Servisi (Port 3000)
```bash
curl http://localhost:3000/api/health
```
Beklenen: `{"status":"ok","timestamp":"..."}` 

### Web Arayüzü (Port 8080)
```bash
curl http://localhost:8080
```
Beklenen: HTML içeriği

### HAProxy (Port 80)
```bash
curl http://localhost:80
```
Beklenen: HAProxy default page veya redirect

## 4. SSL Test Senaryosu

### Web Arayüzünden Test
1. Browser'da `http://localhost:8080` açın
2. SSL Certificate Request formunu doldurun:
   - Domain: `*.test.example.com`
   - Email: `test@example.com`
   - DNS Provider: `manual` (test için)
3. "Request Certificate" butonuna tıklayın

### Beklenen Sonuç
- DNS Challenge modal'ı açılmalı
- TXT record bilgileri gösterilmeli
- Copy butonları çalışmalı
- DNS propagation checker aktif olmalı

## 5. Manual DNS Challenge Test

### TXT Record Ekleme (Simülasyon)
1. Modal'daki TXT record bilgilerini kopyalayın
2. DNS sağlayıcınızda TXT record ekleyin:
   - Name: `_acme-challenge.test.example.com`
   - Value: Modal'da gösterilen değer

3. DNS propagation kontrolü:
   ```bash
   dig TXT _acme-challenge.test.example.com @8.8.8.8
   ```

### Challenge Tamamlama
1. Web arayüzünde "DNS Propagation Check" butonuna tıklayın
2. DNS kaydı doğrulandıktan sonra "Continue" butonuna tıklayın

## 6. Hata Senaryoları Testi

### Geçersiz Domain
- Domain: `invalid..domain`
- Beklenen: Validation hatası

### Geçersiz Email
- Email: `invalid-email`
- Beklenen: Email format hatası

### DNS Challenge Timeout
- TXT record eklemeden "Continue" butonuna tıklayın
- Beklenen: DNS verification hatası

## 7. Log Analizi

### Container Logları
```bash
# API logları
docker logs api -f

# SSL Manager logları
tail -f /Users/umiteyigun/projeler/haproxy/logs/ssl-manager.log

# Certbot logları
docker logs certbot -f
```

### Beklenen Log İçerikleri
- API: HTTP request/response logları
- SSL Manager: DNS challenge adımları
- Certbot: Certificate generation süreci

## 8. Cleanup

### Test Sonrası Temizlik
```bash
# Container'ları durdur
docker-compose down

# Test sertifikalarını temizle
rm -rf /Users/umiteyigun/projeler/haproxy/data/letsencrypt/live/test.example.com

# Log dosyalarını temizle (opsiyonel)
rm -f /Users/umiteyigun/projeler/haproxy/logs/*.log
```

## Troubleshooting

### Container Başlamazsa
1. Port çakışması kontrolü: `lsof -i :3000,8080,80`
2. Docker resource'larını kontrol edin
3. Docker Desktop'u restart edin

### SSL Challenge Başarısızsa
1. DNS propagation süresini artırın
2. Certbot staging environment kullanın
3. Manual DNS challenge adımlarını tekrar kontrol edin

### Web Arayüzü Çalışmazsa
1. Browser console'u kontrol edin
2. API endpoint'lerinin erişilebilir olduğunu kontrol edin
3. CORS ayarlarını kontrol edin
