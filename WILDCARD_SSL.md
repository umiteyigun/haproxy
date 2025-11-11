# Wildcard SSL ve Multi-Domain Yönetimi

## Özellikler

✅ **Multi-Domain Routing**: Sınırsız domain ekleme ve yönetimi
✅ **Wildcard SSL**: `*.example.com` formatında wildcard sertifikalar
✅ **DNS-01 Challenge**: Cloudflare, AWS Route53, DigitalOcean, GoDaddy desteği
✅ **Otomatik SSL Yenileme**: Günlük otomatik kontrol ve yenileme
✅ **Dinamik Config**: HAProxy config otomatik güncellenir

## Wildcard SSL Kullanımı

### 1. DNS Provider Credentials Ekleme

`certbot/creds/` klasörüne DNS provider credentials dosyasını ekleyin:

**Cloudflare** (`certbot/creds/cloudflare.ini`):
```ini
dns_cloudflare_api_token = YOUR_API_TOKEN
```

**AWS Route53** (`certbot/creds/route53.ini`):
```ini
dns_route53_access_key_id = YOUR_ACCESS_KEY
dns_route53_secret_access_key = YOUR_SECRET_KEY
```

**DigitalOcean** (`certbot/creds/digitalocean.ini`):
```ini
dns_digitalocean_token = YOUR_API_TOKEN
```

**GoDaddy** (`certbot/creds/godaddy.ini`):
```ini
dns_godaddy_api_key = YOUR_API_KEY
dns_godaddy_api_secret = YOUR_API_SECRET
```

### 2. Wildcard SSL İsteme

**Web UI'dan:**
1. Ingress kuralı ekle/düzenle
2. "Wildcard SSL" checkbox'ını işaretle
3. DNS Provider seç
4. Kaydet

**API'den:**
```bash
curl -X POST http://localhost:3000/api/ssl/request \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "*.example.com",
    "email": "admin@example.com",
    "dnsProvider": "cloudflare"
  }'
```

### 3. Normal Domain SSL

Normal domain için wildcard checkbox'ını işaretlemeden SSL ekleyebilirsiniz. Bu durumda HTTP-01 challenge kullanılır (webroot).

## Multi-Domain Routing

Her domain için ayrı ingress kuralı ekleyin:
- Domain: `example.com`
- Backend: `192.168.1.100:8080`
- Path (opsiyonel): `/api`

Sistem otomatik olarak:
- HAProxy config'e ACL ve backend ekler
- Domain → backend mapping oluşturur
- Her domain için ayrı routing sağlar

## SSL Sertifikası Yönetimi

- **Otomatik Yenileme**: Her gün saat 02:00'da kontrol edilir
- **Manuel Yenileme**: API'den `/api/ssl/renew` endpoint'i ile
- **Sertifika Listesi**: `/api/ssl/certificates` ile tüm sertifikaları görüntüleyin

## Notlar

- Wildcard SSL için DNS provider credentials zorunludur
- Sertifikalar `haproxy/certs/` klasörüne kaydedilir
- Wildcard sertifikalar base domain adıyla kaydedilir (örn: `example.com.pem`)
- SSL eklenen domainler için HTTPS frontend otomatik aktif olur

