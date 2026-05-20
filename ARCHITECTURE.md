# HAProxy Advanced Security Dashboard — Mimari & Proje Dokümantasyonu

## İçindekiler

1. [Genel Bakış](#genel-bakış)
2. [Mimari Diyagram](#mimari-diyagram)
3. [Başlatma Sırası](#başlatma-sırası)
4. [Alt Projeler](#alt-projeler)
   - [HAProxy](#1-haproxy)
   - [API (Node.js)](#2-api-nodejs)
   - [Web UI (Angular + Nginx)](#3-web-ui-angular--nginx)
   - [Database (PostgreSQL)](#4-database-postgresql)
   - [SPOA / ModSecurity WAF](#5-spoa--modsecurity-waf)
   - [Guard (DDoS Koruma)](#6-guard-ddos-koruma)
   - [Certbot (SSL)](#7-certbot-ssl)
   - [Monitoring Stack (Loki/Promtail/Grafana)](#8-monitoring-stack-lokipromtailgrafana)
5. [Ağ Yapısı](#ağ-yapısı)
6. [Paylaşılan Volume'lar](#paylaşılan-volumelar)
7. [Ortam Değişkenleri](#ortam-değişkenleri)
8. [Sık Kullanılan Komutlar](#sık-kullanılan-komutlar)

---

## Genel Bakış

Bu proje, HAProxy tabanlı gelişmiş bir güvenlik platformudur. Reverse proxy, WAF (Web Application Firewall), DDoS koruması, otomatik SSL sertifika yönetimi ve merkezi bir yönetim arayüzünü tek bir Docker Compose stack'inde bir araya getirir.

**Ana bileşenler:**

| Servis | Teknoloji | Rol |
|---|---|---|
| `haproxy` | HAProxy 2.8 | Reverse proxy, yük dengeleme, ACL |
| `api` | Node.js / Express | Yönetim REST API'si |
| `web` | Angular / Nginx | Web yönetim arayüzü |
| `db` | PostgreSQL 15 | Kalıcı veri depolama |
| `spoa` | ModSecurity v2 + SPOA | WAF motoru |
| `guard` | Python 3.11 | DDoS / brute-force tespit + iptables ban |
| `certbot` | Certbot + DNS eklentileri | Let's Encrypt SSL sertifika yönetimi |
| `loki` | Grafana Loki | Log toplayıcı (opsiyonel) |
| `promtail` | Grafana Promtail | Log göndericisi (opsiyonel) |
| `grafana` | Grafana | Log görselleştirme (opsiyonel) |

---

## Mimari Diyagram

```
                        ┌─────────────────────────────────────┐
                        │           INTERNET (80/443)          │
                        └──────────────────┬──────────────────┘
                                           │
                        ┌──────────────────▼──────────────────┐
                        │         HAProxy (host network)       │
                        │   • Reverse proxy / load balancer    │
                        │   • ACL tabanlı yönlendirme          │
                        │   • Rate limiting (100 req/10s)      │
                        │   • IP kara/beyaz liste              │
                        │   • Bad User-Agent filtresi          │
                        │   • SPOE filtresi → WAF              │
                        └──┬─────────────────┬────────────────┘
                           │ SPOE (port 12345)│ HTTP Proxy
               ┌───────────▼───────┐  ┌──────▼──────────────┐
               │  SPOA/ModSecurity │  │   Web UI (port 8088) │
               │  (WAF motoru)     │  │   Angular + Nginx    │
               │  OWASP CRS v4     │  │                      │
               └───────────────────┘  └──────┬───────────────┘
                                             │ /api/* proxy
                              ┌──────────────▼──────────────┐
                              │   API - Node.js (port 3000)  │
                              │   • JWT kimlik doğrulama     │
                              │   • Kural CRUD               │
                              │   • HAProxy config üretimi   │
                              │   • HAProxy reload           │
                              │   • SSL sertifika yönetimi   │
                              │   • OWASP CRS yönetimi       │
                              │   • DNS challenge otomasyonu │
                              └──────────────┬──────────────┘
                                             │ pg bağlantısı
                              ┌──────────────▼──────────────┐
                              │   PostgreSQL 15 (port 5432)  │
                              │   DB: haproxy                │
                              │   Tablolar: rules,           │
                              │   certificates, members,     │
                              │   settings, port_forwarding  │
                              └─────────────────────────────┘

                 ┌─────────────────────────────────────────────┐
                 │    Guard (host network, arka planda)         │
                 │    • HAProxy loglarını tail ile izler        │
                 │    • 5 başarısız istek → 1 saatlik iptables │
                 │    • Kritik path erişimi → anında ban        │
                 └─────────────────────────────────────────────┘

                 ┌─────────────────────────────────────────────┐
                 │    Monitoring Stack (opsiyonel, ayrı compose)│
                 │    Loki → Promtail → HAProxy/ModSec logları  │
                 │    Grafana → :3001                           │
                 └─────────────────────────────────────────────┘
```

---

## Başlatma Sırası

Servisler arasındaki `depends_on` ilişkilerine göre doğru başlatma sırası şu şekildedir:

```
1. db          (bağımsız — hiçbir servise bağımlı değil)
       ↓
2. api         (db'ye bağımlı)
   spoa        (bağımsız — api ile paralel başlayabilir)
       ↓
3. web         (api'ye bağımlı)
       ↓
4. haproxy     (api + spoa'ya bağımlı)

5. guard       (bağımsız — haproxy loglarını izler, herhangi bir sırada başlayabilir)
```

> **Not:** Docker Compose `depends_on` yalnızca konteynerin başlatılmasını bekler, servisin hazır olmasını garanti etmez. API kendi içinde veritabanı bağlantısı için 30 yeniden deneme (2s aralıkla) yapar.

---

## Alt Projeler

---

### 1. HAProxy

**Dizin:** `haproxy/`
**Image:** `haproxy:2.8-alpine` (önceden hazır image)

#### Ne Yapar?

Tüm gelen HTTP/HTTPS trafiğinin giriş noktasıdır. Domain ve path bazlı yönlendirme, rate limiting, IP engelleme ve ModSecurity WAF entegrasyonu sağlar.

#### Temel Özellikler

- **Reverse proxy:** Domain adına göre backend servislerine yönlendirme
- **SPOE filtresi:** Her HTTP isteğini ModSecurity'e gönderir, WAF kararına göre isteği engeller veya geçirir
- **Rate limiting:** `stick-table` ile 10 saniyede 100'den fazla istek yapan IP'leri 429 ile reddeder
- **IP kara listesi:** `haproxy/config.d/ip_blacklist.lst` dosyasındaki IP'leri 403 ile reddeder
- **IP beyaz listesi:** `haproxy/config.d/whitelist.lst` dosyasındaki IP'ler rate limiting'den muaftır
- **Bad User-Agent filtresi:** `haproxy/maps/bad_useragents.lst` dosyasındaki User-Agent string'lerini 403 ile reddeder
- **Let's Encrypt desteği:** `/.well-known/acme-challenge/` path'ini WAF ve rate limiting'den muaf tutar
- **HAProxy stats socket:** `/app/sockets/haproxy.sock` üzerinden API'nin dinamik komut göndermesini sağlar

#### Bağımlılıklar (Servisler)

| Bağımlı Olduğu | Açıklama |
|---|---|
| `api` | HAProxy config dosyasını API üretir ve reload tetikler |
| `spoa` | SPOE protokolü ile WAF kararları almak için gerekli |

#### Bağımlılıklar (Dosyalar)

| Dosya | Açıklama |
|---|---|
| `haproxy/haproxy.cfg` | Ana HAProxy konfigürasyonu |
| `haproxy/config.d/` | ACL, port, ingress ek konfigürasyonları |
| `haproxy/maps/bad_useragents.lst` | Engellenen User-Agent listesi |
| `haproxy/modsecurity.conf` | SPOE filtre konfigürasyonu |
| `haproxy/certs/` | SSL sertifika dosyaları (.pem) |

#### Nasıl Çalıştırılır?

```bash
# Tüm stack ile başlatma
docker compose up -d haproxy

# Sadece config doğrulama
docker compose config >/dev/null

# Log izleme
docker logs haproxy --tail 50 -f

# HAProxy'yi yeniden yükle (config yeniden okur, bağlantıları kesmez)
docker exec haproxy haproxy -sf $(cat /var/run/haproxy.pid)
# veya API üzerinden: POST /api/haproxy/reload
```

---

### 2. API (Node.js)

**Dizin:** `api/`
**Dockerfile:** `api/Dockerfile`
**Port:** `127.0.0.1:3000`

#### Ne Yapar?

Tüm yönetim işlemlerinin merkezi REST API'sidir. HAProxy konfigürasyonunu veritabanındaki kurallara göre dinamik olarak üretir ve HAProxy'yi yeniden yükler. SSL sertifika yönetimi, WAF kural yönetimi ve DNS challenge otomasyonu da bu serviste yer alır.

#### Temel Modüller

| Dosya | Açıklama |
|---|---|
| `server.js` | Ana Express uygulaması, tüm route tanımlamaları, veritabanı init |
| `ssl-manager.js` | Let's Encrypt sertifika yaşam döngüsü, Certbot orkestrasyonu |
| `crs-manager.js` | OWASP CRS rule dosyalarını listeleme, okuma, etkinleştirme/devre dışı bırakma |
| `he-dns-manager.js` | Hurricane Electric, Cloudflare, AXFR ile DNS challenge otomasyonu |

#### Kimlik Doğrulama

- JWT tabanlı, 12 saat geçerlilik süresi
- `/health` endpoint'i herkese açık
- Diğer tüm `/api/*` route'ları `Authorization: Bearer <token>` başlığı gerektirir
- İlk başlatmada `ADMIN_EMAIL` / `ADMIN_PASSWORD` ortam değişkenlerinden admin kullanıcısı oluşturulur

#### Veritabanı Tabloları

| Tablo | Açıklama |
|---|---|
| `rules` | Proxy kuralları (domain, backend, SSL, LB modu) |
| `rule_backends` | Kural başına birden fazla backend desteği |
| `port_forwarding` | TCP port yönlendirme kuralları |
| `certificates` | SSL sertifika kayıtları |
| `members` | Kullanıcı hesapları |
| `settings` | Uygulama ayarları |

#### Bağımlılıklar

| Paket | Sürüm | Kullanım |
|---|---|---|
| `express` | ^4.18.2 | HTTP framework |
| `pg` | ^8.11.3 | PostgreSQL bağlantısı |
| `jsonwebtoken` | ^9.0.2 | JWT üretimi ve doğrulama |
| `bcryptjs` | ^2.4.3 | Parola hash'leme |
| `ws` | ^8.14.2 | WebSocket (gerçek zamanlı log akışı) |
| `node-cron` | ^3.0.3 | Zamanlanmış sertifika yenileme |
| `axios` | ^1.6.2 | HTTP istekleri (Cloudflare DNS vb.) |
| `js-yaml` | ^4.1.0 | YAML parsing |
| `csv-parse` | ^5.5.3 | CSV dosyası import |

#### Bağımlılıklar (Servisler)

| Bağımlı Olduğu | Açıklama |
|---|---|
| `db` | Tüm kural ve sertifika verilerinin kalıcı depolanması |
| Docker socket | Certbot konteynerini başlatmak için `/var/run/docker.sock` |

#### Nasıl Çalıştırılır?

```bash
# Docker ile
docker compose up -d api

# Yerel geliştirme (DB çalışıyor olmalı)
cd api
npm install
npm run dev     # nodemon ile hot reload
npm start       # production

# Loglar
docker logs haproxy-api --tail 50 -f
```

---

### 3. Web UI (Angular + Nginx)

**Dizin:** `web/`
**Dockerfile:** `web/Dockerfile`
**Port:** `127.0.0.1:8088`

#### Ne Yapar?

HAProxy ve tüm güvenlik özelliklerinin yönetildiği tarayıcı tabanlı arayüzdür. Angular (PrimeNG tabanlı Sakai-NG şablonu) ile geliştirilmiş SPA uygulamasıdır; Nginx üzerinde çalışır.

#### Bileşenler

| Dosya | Açıklama |
|---|---|
| `web/sakai-ng/` | Angular uygulaması (PrimeNG komponentleri) |
| `web/app.js` | Statik HTML sayfaları için JS mantığı |
| `web/index.html` | Ana yönetim paneli |
| `web/login.html` | Giriş sayfası |
| `web/nginx.conf` | Nginx konfigürasyonu |

#### Nginx Proxy Kuralları

Nginx, gelen istekleri şu şekilde yönlendirir:

| Path | Hedef |
|---|---|
| `/api/*` | `http://api:3000` |
| `/auth/*` | `http://api:3000` |
| `/health` | `http://api:3000` |
| Diğer tüm | Angular SPA (`index.html`) |

#### Derleme Süreci (Multi-stage Docker)

1. `node:20-alpine` ile Angular uygulaması `npm run build --configuration production` komutuyla derlenir
2. Derlenen dosyalar `nginx:alpine` image'ına kopyalanır

#### Bağımlılıklar

| Bağımlı Olduğu | Açıklama |
|---|---|
| `api` | Tüm yönetim işlemleri API üzerinden yapılır |

#### Nasıl Çalıştırılır?

```bash
# Docker ile
docker compose up -d web

# Web arayüzüne erişim (HAProxy üzerinden)
# http://<sunucu-ip>/

# Doğrudan erişim (geliştirme)
# http://localhost:8088
```

---

### 4. Database (PostgreSQL)

**Image:** `postgres:15-alpine`
**Port:** `5432` (yalnızca `haproxy-network` içinden erişilebilir)

#### Ne Yapar?

API servisinin tüm kalıcı verilerini depolar. Dışarıya port açmaz; yalnızca iç ağ üzerinden erişilebilir.

#### Veri Kalıcılığı

Veriler `./data/postgres` dizinine bağlı bir volume üzerinde saklanır.

#### Bağımlılıklar

| Bağımlı Olduğu | Açıklama |
|---|---|
| — | Hiçbir servise bağımlı değil, ilk başlayan servislerdendir |

#### Nasıl Çalıştırılır?

```bash
# Docker ile
docker compose up -d db

# Doğrudan bağlanma (debug)
docker exec -it haproxy-db psql -U haproxy -d haproxy

# Yedekleme
docker exec haproxy-db pg_dump -U haproxy haproxy > backup.sql
```

---

### 5. SPOA / ModSecurity WAF

**Dizin:** `spoa/`
**Dockerfile:** `spoa/Dockerfile`
**Port:** `127.0.0.1:12345`

#### Ne Yapar?

HAProxy ile SPOE (Stream Processing Offload Engine) protokolü üzerinden haberleşen ModSecurity WAF motorudur. HAProxy her HTTP isteğini bu servise gönderir; servis OWASP CRS v4 kurallarına göre isteği analiz eder ve HAProxy'ye izin ver / reddet kararını bildirir.

#### SPOE Bağlantısı

```
HAProxy (filter spoe) ──SPOE protocol (TCP 12345)──▶ SPOA/ModSecurity
                                                          │
                                              OWASP CRS v4 kuralları
                                              modsecurity/ dizini
```

#### Mod Seçenekleri

| Ortam Değişkeni | Değer | Davranış |
|---|---|---|
| `MODSEC_RULE_ENGINE` | `DetectionOnly` | Sadece log yazar, engellemez |
| `MODSEC_RULE_ENGINE` | `On` | Kötü istekleri engeller (503) |

> **Uyarı:** `docker-compose.yml`'de varsayılan değer `On`'dur. `modsecurity/modsecurity.conf` dosyasında `DetectionOnly` olarak ayarlıdır. SPOA container'ının env değişkeni önceliklidir.

#### Derleme Süreci

`spoa/Dockerfile` Alpine üzerinde sıfırdan ModSecurity v2.9.11 ve `haproxy/spoa-modsecurity` derler. `spoa/spoa.patch` dosyasındaki yamalar uygulandıktan sonra binary oluşturulur.

#### Kural Yapısı

| Dizin | Açıklama |
|---|---|
| `modsecurity/crs/` | OWASP CRS v4 (doğrudan düzenleme yapılmaz) |
| `modsecurity/rules/` | Özel kurallar (API üzerinden yönetilir) |
| `modsecurity/crs-setup.conf` | CRS ana konfigürasyonu |

#### Bağımlılıklar

| Bağımlı Olduğu | Açıklama |
|---|---|
| — | Bağımsız servis; HAProxy ona bağlanır |

#### Nasıl Çalıştırılır?

```bash
# Docker ile
docker compose up -d spoa

# Loglar
docker logs haproxy-spoa --tail 50 -f

# WAF audit logları
cat modsecurity/logs/modsec_audit.log

# Smoke test
make test-waf

# Üst rule hit raporu
make waf-report
```

---

### 6. Guard (DDoS Koruma)

**Dizin:** `guard/`
**Dockerfile:** `guard/Dockerfile`
**Ağ:** `host` (iptables erişimi için)

#### Ne Yapar?

HAProxy log dosyasını sürekli izler. Belirli bir zaman diliminde fazla başarısız istek yapan IP'leri `iptables` ile sistemden tamamen engeller.

#### Ban Mantığı

```
60 saniye içinde 5+ başarısız istek (401/403/404/429)
           ↓
    IP → iptables DROP (1 saat)
           ↓
    ban geçmişi /app/bans_history.json dosyasına kaydedilir
```

#### Kritik Path Kuralı (Anında Ban)

Aşağıdaki path'lere yapılan ilk erişimde IP anında engellenir (sayaç beklemeden):

```
.env, .git, wp-admin, wp-login, config.php,
/api/.env, /backend/.env, /shell, /admin/
```

#### Görmezden Gelinen 404'ler

Aşağıdaki uzantılara yapılan 404 istekleri yanlış pozitif engelini önlemek için sayılmaz:

```
/UploadSanal/, /favicon.ico, .jpg, .png, .gif, .css, .js, .woff
```

#### Beyaz Liste

`guard/whitelist.txt` dosyasındaki IP'ler hiçbir zaman engellenmez. Bu dosya API üzerinden de güncellenebilir.

#### UDP Syslog Sunucusu

Guard aynı zamanda UDP 514 portunda bir syslog sunucusu çalıştırır. HAProxy loglarını hem dosyadan hem de doğrudan UDP üzerinden alabilir.

#### Yönetim Scriptleri

| Script | Açıklama |
|---|---|
| `guard/scripts/list-bans.sh` | Mevcut iptables yasaklarını listele |
| `guard/scripts/unban-ip.sh <ip>` | Belirli bir IP'nin yasağını kaldır |
| `guard/scripts/manual-ban.sh <ip>` | IP'yi manuel olarak yasakla |
| `guard/scripts/add-whitelist.sh <ip>` | Beyaz listeye IP ekle |

#### Bağımlılıklar

| Bağımlı Olduğu | Açıklama |
|---|---|
| `iptables` | Host sistem üzerinde iptables çalışıyor olmalı |
| HAProxy logları | `./logs/haproxy/` dizini paylaşımlı volume üzerinden okunur |

#### Nasıl Çalıştırılır?

```bash
# Docker ile
docker compose up -d guard

# Aktif yasakları göster
docker exec haproxy-guard bash /app/scripts/list-bans.sh

# IP yasağını kaldır
docker exec haproxy-guard bash /app/scripts/unban-ip.sh 1.2.3.4

# Loglar
docker logs haproxy-guard --tail 50 -f
```

---

### 7. Certbot (SSL)

**Dizin:** `certbot/`
**Dockerfile:** `certbot/Dockerfile`

#### Ne Yapar?

Let's Encrypt sertifikalarının alınması ve yenilenmesi için kullanılan araçtır. Ana uygulama Docker Compose'da sürekli çalışan bir servis olarak değil, API (`ssl-manager.js`) tarafından ihtiyaç duyulduğunda başlatılan geçici bir konteyner olarak kullanılır.

#### Desteklenen DNS Sağlayıcıları

| Sağlayıcı | Plugin |
|---|---|
| Cloudflare | `certbot-dns-cloudflare` |
| Route53 (AWS) | `certbot-dns-route53` |
| DigitalOcean | `certbot-dns-digitalocean` |
| GoDaddy | `certbot-dns-godaddy` |
| OVH | `certbot-dns-ovh` |
| Google Cloud DNS | `certbot-dns-google` |
| DNSimple | `certbot-dns-dnsimple` |
| RFC2136 (BIND) | `certbot-dns-rfc2136` |
| Hurricane Electric | `he-dns-manager.js` (özel uygulama) |

#### Credentials Dosyaları

`certbot/creds/` dizininde DNS sağlayıcısına özel credential dosyaları bulunur. `certbot/creds/cloudflare.ini.example` dosyası örnek format gösterir.

#### Sertifika Depolama

Alınan sertifikalar `haproxy/certs/` dizininde `.pem` formatında saklanır ve HAProxy tarafından doğrudan kullanılır.

#### Bağımlılıklar

| Bağımlı Olduğu | Açıklama |
|---|---|
| `api` | API, `ssl-manager.js` aracılığıyla Certbot'u yönetir |
| DNS sağlayıcısı | DNS challenge için ilgili DNS sağlayıcısına erişim |

#### Nasıl Çalıştırılır?

```bash
# API üzerinden (önerilen yöntem)
# POST /api/certificates/request

# Sertifikaları listele
# GET /api/certificates

# Manuel Certbot çalıştırma
docker run --rm \
  -v ./certbot/conf:/etc/letsencrypt \
  -v ./certbot/www:/var/www/certbot \
  certbot/certbot certonly --webroot \
  -w /var/www/certbot \
  -d example.com

# Let's Encrypt HTTP challenge (HAProxy web-root üzerinden)
# HAProxy /.well-known/acme-challenge/ path'ini certbot/www volume'una yönlendirir
```

---

### 8. Monitoring Stack (Loki/Promtail/Grafana)

**Dizin:** `monitoring/`
**Compose dosyası:** `monitoring/docker-compose.monitoring.yml`
**Durum:** Opsiyonel, ayrı bir compose dosyasıyla yönetilir

#### Ne Yapar?

HAProxy ve ModSecurity loglarını toplar, saklar ve görselleştirir. Ana docker-compose stack'inden bağımsızdır.

#### Servisler

| Servis | Port | Açıklama |
|---|---|---|
| `loki` | 3100 | Log depolama ve sorgulama motoru |
| `promtail` | — | Log dosyalarını okuyup Loki'ye gönderir |
| `grafana` | 3001 | Log görselleştirme arayüzü |

#### İzlenen Log Kaynakları

| Kaynak | Container path |
|---|---|
| HAProxy logları | `../logs/` → `/var/log/haproxy` |
| ModSecurity logları | `../modsecurity/logs/` → `/var/log/modsecurity` |
| Host sistem logları | `/var/log/` → `/var/log/host` |

#### Başlatma/Durdurma

```bash
# Başlat
make monitoring-up
# veya
docker compose -f monitoring/docker-compose.monitoring.yml up -d

# Durdur
make monitoring-down

# Loglar
make monitoring-logs

# Grafana'ya erişim
# http://localhost:3001  (varsayılan: admin/admin)
```

---

## Ağ Yapısı

```
haproxy-network (bridge)
│
├── api          (container_name: haproxy-api)
├── web          (container_name: haproxy-web)
├── db           (container_name: haproxy-db)
└── spoa         (container_name: haproxy-spoa)

host network (doğrudan host ağ stack'i)
├── haproxy      (container_name: haproxy)       ← tüm portlar doğrudan host'ta
└── guard        (container_name: haproxy-guard) ← iptables erişimi için
```

> `haproxy-network` içindeki servisler birbirine servis adıyla erişir (örn. `http://api:3000`).
> `host network` modundaki servisler `host.docker.internal` aracılığıyla bridge network servislerine ulaşır.

---

## Paylaşılan Volume'lar

| Volume / Bind mount | Oluşturan | Okuyan / Kullanan |
|---|---|---|
| `./haproxy/haproxy.cfg` | API (kural değişikliklerinde üretir) | HAProxy |
| `./haproxy/config.d/` | API | HAProxy, Guard |
| `./haproxy/maps/` | API | HAProxy |
| `./haproxy/certs/` | API / ssl-manager | HAProxy, Certbot |
| `./haproxy/sockets/` | HAProxy (`.sock` dosyası) | API (komut gönderir) |
| `./logs/haproxy/` | HAProxy | Guard, Promtail |
| `./modsecurity/rules/` | API / CRS manager | SPOA |
| `./modsecurity/crs/` | Manuel / OWASP güncellemeleri | SPOA, API |
| `./modsecurity/logs/` | SPOA (audit log) | Promtail |
| `./certbot/conf/` | Certbot | API / ssl-manager |
| `./guard/whitelist.txt` | API / el ile | Guard |
| `acme_sh_data` (Docker volume) | acme.sh | API / ssl-manager |
| `/var/run/docker.sock` | Docker daemon | API (Certbot konteyneri yönetimi) |

---

## Ortam Değişkenleri

### Kritik — Üretimde Mutlaka Değiştirin

| Değişken | Varsayılan | Servis | Açıklama |
|---|---|---|---|
| `JWT_SECRET` | `change_this_secret` | api | JWT imzalama anahtarı |
| `ADMIN_PASSWORD` | `admin12345` | api | İlk admin parolası |
| `DB_PASSWORD` | `haproxy_password_change_me` | api, db | PostgreSQL parolası |

### Yapılandırma

| Değişken | Varsayılan | Servis | Açıklama |
|---|---|---|---|
| `MODSEC_RULE_ENGINE` | `On` | spoa | WAF modu: `On` veya `DetectionOnly` |
| `MODSEC_AUDIT_ENGINE` | `RelevantOnly` | spoa | Audit log seviyesi |
| `HAPROXY_PUBLIC_IP` | `195.87.80.166` | api | DNS challenge callback IP'si |
| `LOG_LEVEL` | `info` | api | API log seviyesi |
| `ADMIN_EMAIL` | `admin@example.com` | api | İlk admin e-postası |
| `GRAFANA_ADMIN_PASSWORD` | `admin` | grafana | Grafana admin parolası |

---

## Sık Kullanılan Komutlar

```bash
# Tüm stack'i başlat
docker compose up -d --build

# Tüm stack'i durdur
docker compose down

# Belirli bir servisi yeniden derle ve başlat
docker compose up -d --build api

# Tüm servis durumlarını göster
docker compose ps

# HAProxy config doğrula
docker compose config >/dev/null

# HAProxy + ModSecurity loglarını izle
make waf-logs

# WAF smoke testi çalıştır
make test-waf

# WAF audit raporu oluştur
make waf-report

# Monitoring stack'i başlat
make monitoring-up

# Guard'ın yasakladığı IP'leri listele
docker exec haproxy-guard bash /app/scripts/list-bans.sh

# API container'ına bağlan
docker exec -it haproxy-api sh

# Veritabanına bağlan
docker exec -it haproxy-db psql -U haproxy -d haproxy
```

---

## Bağımlılık Özeti (Grafik)

```
db
└─▶ api
    ├─▶ web ─▶ haproxy
    │              │
    └─▶ (config)   └─▶ spoa (SPOE bağlantısı)

guard ──▶ (./logs/haproxy volume) ──▶ haproxy log dosyalarını okur
certbot ──▶ (api tarafından yönetilir) ──▶ certbot/conf, haproxy/certs

[Opsiyonel]
loki ◀── promtail ◀── haproxy/modsecurity logları
grafana ──▶ loki
```
