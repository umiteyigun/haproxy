# HAProxy WAF Implementation Plan

## Amaç
- HAProxy katmanında temel güvenlik filtreleri ve hız limitleri aktifleştirmek.
- OWASP CRS tabanlı ModSecurity motorunu HAProxy ile entegre ederek imza tabanlı WAF sağlayıcıyı devreye almak.
- Süreci Docker tabanlı ortamda yönetip CI/CD pipeline’ına entegre etmek.

---

## Faz 1 – Temel ACL & Rate Limiting
1. **IP/UA Kara Liste Kontrolleri**
   - `haproxy/config.d/` altında `acl_blacklist.lst` benzeri dosya oluştur.
   - `http-request deny if { src -f … }` ve `hdr_sub(User-Agent)` kontrolleri ekle.
2. **Stick-Table ile Rate Limit**
   - Login/API endpoint’leri için stick-table tanımla.
   - Belirli eşikler aşıldığında 429/403 döndür.
3. **Basit Payload Filtreleri (Lua)**
   - HAProxy container’ına Lua desteği ekle.
   - `lua/waf_checks.lua` içinde JSON/x-www-form-urlencoded parametre denetimleri (şüpheli pattern) uygula.
4. **Loglama**
   - Engellenen istekleri HAProxy stdout üzerinden `logs/haproxy/` klasörüne yönlendir.

### Çıktılar
- Güncellenmiş `haproxy/haproxy.cfg` veya `config.d/` dosyaları.
- Kara liste ve rate limit tanımları.
- Temel Lua scriptleri.

---

## Faz 2 – ModSecurity + OWASP CRS Entegrasyonu
1. **SPOA İmajı** ✅
   - `spoa/Dockerfile` ModSecurity 2.9.11 ve OWASP CRS’i derleyerek tek bir konteyner oluşturuyor.
   - Build sırasında `spoa/spoa.patch` ve `spoa/start.sh` uygulanıyor.
2. **Docker Compose Güncellemesi** ✅
   - Ayrı `modsecurity` servisi kaldırıldı; `spoa` servisi depo kökünden build alıyor ve loglar host’a mount ediliyor.
3. **HAProxy Filter Konfigürasyonu** ✅
   - `haproxy/haproxy.cfg` frontendlere `filter spoe engine modsecurity config /usr/local/etc/haproxy/modsecurity.conf` eklendi.
   - `haproxy/modsecurity.conf` içinde `[modsecurity]` bölümü, timeout’lar ve `on-frontend-http-request` event’i tanımlandı.
4. **Detection Modu** ✅
   - ModSecurity `SecRuleEngine DetectionOnly` olarak çalışıyor; custom kurallar `modsecurity/rules` altına eklenebiliyor.
5. **Log & Alerting** 🔄
   - Şimdilik `/var/log/modsecurity` bind mount ile host’a aktarılıyor.
   - `scripts/waf_smoke_test.sh` CLI üzerinden iyi/kötü User-Agent senaryolarını doğruluyor; `make test-waf` hedefi ile entegre edildi.
   - ELK/Grafana entegrasyonu Faz 3 kapsamında tamamlanacak.

### Çıktılar
- Yeni Docker servisi (`spoa`).
- HAProxy config’inde SPOE filter.
- OWASP CRS kural seti yapılandırması ve otomatik WAF smoke testi.

---

## Faz 3 – Yönetim & Otomasyon
1. **CI/CD Entegrasyonu** ✅
   - `.github/workflows/waf-ci.yml` HAProxy/SPOA build eder, konfigürasyon testi ve smoke testi çalıştırır.
   - `Makefile` içerisindeki `test-waf` hedefi yerelde aynı senaryoyu tekrarlar.
2. **Konfigürasyon Yönetimi** 🔄
   - WAF kuralları repo içinde version control (tamamlandı); ortam bazlı override dosyaları ve yayın süreci tanımlanacak.
3. **Monitoring** 🔄
   - Prometheus/Grafana ile WAF metrikleri (engellenen istek sayısı vs.) toplanacak.
   - Alertmanager ile kritik eşikler için bildirim tasarlanacak.
4. **Failover Politikası** 🔄
   - ModSecurity/SPOE servisi down olursa: `t_idle` ve `on-error` davranışı belirlenecek (passthrough vs block).

### Çıktılar
- Çalışan CI pipeline, Makefile hedefleri.
- (Planlanan) Monitoring/alerting dashboardları.

---

## Takvim & Sorumluluk
- **Hafta 1:** Faz 1 uygulama + test.
- **Hafta 2-3:** ModSecurity entegrasyonu, tuning.
- **Hafta 4:** CI/CD, monitoring ve dokümantasyon.

Sorumluluklar ortam ve ekip rollerine göre netleştirilecek.

---

## Dokümantasyon & Test
- Her faz sonunda güncellenmiş README/WAF dokümanları.
- `test_manuel_dns.sh` benzeri script ile WAF test senaryoları (legit & malicious istekler).
- Blocking/allowing testleri için Postman/pytest senaryoları.

---

## Ek Notlar
- WAF’ı sadece HTTP(S) trafiğinde devreye al; TCP port yönlendirmeleri için ayrı politika gerekiyor.
- HAProxy reload öncesi config test (`haproxy -c -f ...`).
- Performans testleri: WAF açıldıktan sonra latency ölçümü (k6, wrk vb.).
