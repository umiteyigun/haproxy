# HAProxy Yönetim Sistemi

Bu proje, HAProxy için port forwarding ve ingress kurallarını yönetmek için kapsamlı bir yönetim sistemidir.

## Özellikler

- ✅ **Port Forwarding**: TCP/HTTP port forwarding kuralları yönetimi
- ✅ **Ingress Kuralları**: Domain ve path bazlı routing kuralları
- ✅ **SSL Yönetimi**: Let's Encrypt (Certbot) ile otomatik SSL sertifikası
- ✅ **Web UI**: Modern ve kullanıcı dostu web arayüzü
- ✅ **REST API**: Tüm işlemler için RESTful API
- ✅ **Dinamik Konfigürasyon**: HAProxy config'i otomatik olarak güncellenir

## Yapı

```
haproxy/
├── docker-compose.yml      # Docker Compose yapılandırması
├── haproxy/
│   ├── haproxy.cfg         # Ana HAProxy konfigürasyonu
│   └── config.d/           # Dinamik kural dosyaları
├── api/
│   ├── server.js           # REST API sunucusu
│   ├── ssl-manager.js      # SSL yönetim modülü
│   └── package.json
├── web/
│   ├── index.html          # Web UI
│   ├── app.js              # Frontend JavaScript
│   └── Dockerfile
└── certbot/                # Certbot volume'ları
```

## Kurulum

### 1. Gereksinimler

- Docker ve Docker Compose
- En az 2GB RAM
- 80, 443, 3000, 8080 portları açık olmalı

### 2. Yapılandırma

`docker-compose.yml` dosyasındaki şifreleri değiştirin:

```yaml
POSTGRES_PASSWORD: haproxy_password_change_me
```

### 3. Başlangıç

- Varsayılan yönetici kullanıcı bilgileri `.env`/environment üzerinden oluşturulur. Örnek:

  ```env
  ADMIN_EMAIL=admin@example.com
  ADMIN_PASSWORD=admin12345
  JWT_SECRET=çok-gizli-bir-ifade
  ```

  API konteyneri ilk açılışta bu bilgileri kullanarak `members` tablosuna bir admin hesabı seed eder. Prod ortamında bu değerleri mutlaka değiştirin.

### 4. Başlatma

```bash
docker-compose build --no-cache
docker-compose up -d
```

Servisler:
- **HAProxy**: `http://localhost:80` (HTTP), `https://localhost:443` (HTTPS)
- **Web UI**: `http://localhost:8080`
- **API**: `http://localhost:3000`
- **HAProxy Stats**: `http://localhost:8404/stats`

## Kullanım

### Web UI

1. Tarayıcıda `http://localhost:8080` adresine gidin
2. Sol menüden istediğiniz bölüme geçin:
   - **Ingress Kuralları**: Domain bazlı routing kuralları
   - **Port Forwarding**: TCP/HTTP port yönlendirme kuralları
   - **SSL Sertifikaları**: SSL sertifikası yönetimi

### API Endpoints

#### Ingress Kuralları

- `GET /api/rules` - Tüm ingress kurallarını listele
- `POST /api/rules` - Yeni ingress kuralı ekle
- `PUT /api/rules/:id` - Ingress kuralını güncelle
- `DELETE /api/rules/:id` - Ingress kuralını sil

**Örnek:**
```bash
curl -X POST http://localhost:3000/api/rules \
  -H "Content-Type: application/json" \
  -d '{
    "name": "my-app",
    "domain": "example.com",
    "path": "/api",
    "backend_host": "192.168.1.100",
    "backend_port": 8080,
    "ssl_enabled": true
  }'
```

#### Port Forwarding

- `GET /api/port-forwarding` - Tüm port forwarding kurallarını listele
- `POST /api/port-forwarding` - Yeni port forwarding kuralı ekle
- `PUT /api/port-forwarding/:id` - Port forwarding kuralını güncelle
- `DELETE /api/port-forwarding/:id` - Port forwarding kuralını sil

**Örnek:**
```bash
curl -X POST http://localhost:3000/api/port-forwarding \
  -H "Content-Type: application/json" \
  -d '{
    "name": "ssh-forward",
    "frontend_port": 2222,
    "backend_host": "192.168.1.100",
    "backend_port": 22,
    "protocol": "tcp"
  }'
```

#### SSL Yönetimi

- `GET /api/ssl/certificates` - Tüm SSL sertifikalarını listele
- `POST /api/ssl/request` - Yeni SSL sertifikası talep et
- `POST /api/ssl/renew` - SSL sertifikalarını yenile

**Örnek:**
```bash
curl -X POST http://localhost:3000/api/ssl/request \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "example.com",
    "email": "admin@example.com"
  }'
```

## SSL Sertifikası Kurulumu

1. Domain'inizin DNS kaydını bu sunucuya yönlendirin
2. Web UI'dan veya API'den SSL sertifikası talep edin
3. Certbot otomatik olarak sertifikayı oluşturacak
4. HAProxy config otomatik olarak güncellenecek

## Notlar

- HAProxy config dosyaları `haproxy/config.d/` dizininde otomatik oluşturulur
- SSL sertifikaları günlük olarak kontrol edilir ve otomatik yenilenir
- Tüm değişiklikler veritabanında saklanır
- HAProxy config değişiklikleri otomatik olarak uygulanır

## Güvenlik

- Production ortamında mutlaka şifreleri değiştirin
- Web UI ve API için authentication ekleyin
- SSL sertifikalarını düzenli olarak kontrol edin
- Firewall kurallarını yapılandırın

## Sorun Giderme

### HAProxy başlamıyor
- `docker-compose logs haproxy` ile logları kontrol edin
- HAProxy config dosyasını kontrol edin: `haproxy/haproxy.cfg`

### SSL sertifikası alınamıyor
- Domain DNS kaydını kontrol edin
- 80 portunun açık olduğundan emin olun
- Certbot loglarını kontrol edin: `docker-compose logs certbot`

### API bağlanamıyor
- Database servisinin çalıştığını kontrol edin
- API loglarını kontrol edin: `docker-compose logs api`

## Monitoring

An optional Loki + Promtail + Grafana stack is available under `monitoring/`.

### Prerequisites
- Ana WAF stack’in (`docker-compose up -d haproxy spoa`) çalışıyor olması önerilir; Promtail varsayılan olarak `logs/haproxy` ve `modsecurity/logs` dizinlerini okur.
- Docker Compose yüklü olmalı.
- Grafana varsayılan yönetici bilgileri `admin/admin`; `.env` dosyasında `GRAFANA_ADMIN_USER` ve `GRAFANA_ADMIN_PASSWORD` ile özelleştirilebilir.

### Komutlar
```bash
make monitoring-up      # start monitoring containers (Loki, Promtail, Grafana)
make monitoring-logs    # tail monitoring container logs
make monitoring-down    # stop and remove monitoring stack
```

Grafana arayüzü <http://localhost:3001/> üzerinden erişilebilir. "WAF Logs" dashboard’u varsayılan olarak HAProxy ve ModSecurity loglarını gösterir; logları görebilmek için ilgili servislerin stdout veya dosya çıktılarının Promtail tarafından okunuyor olması yeterlidir.

## Lisans

MIT

