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
1. **ModSecurity Container**
   - `docker-compose.yml` içine `modsecurity` servisi ekle.
   - OWASP CRS kural setlerini `modsecurity/rules/` altında tut.
2. **SPOE Agent**
   - `haproxytech/spoa-modsecurity` agent’ını kullan veya özel SPOE container oluştur.
   - HAProxy -> SPOE -> ModSecurity iletişimini MTLS ile güvenli hale getir.
3. **HAProxy Filter Konfigürasyonu**
   - `filter spoe engine modsecurity config /etc/haproxy/modsecurity.conf` benzeri yapı.
   - Tüm HTTP frontend’lerine filter ekle.
4. **Deneme (Detection) Modu**
   - İlk etapta sadece loglama, bloklama yok.
   - False-positive tuning: `SecRuleEngine DetectionOnly`, sonra `On`.
5. **Log & Alerting**
   - ModSecurity audit loglarını `logs/modsecurity/` altına yaz.
   - Opsiyonel: Logları ELK/Grafana’ya yönlendir.

### Çıktılar
- Yeni Docker servisi (`modsecurity`, `spoa`).
- HAProxy config’inde SPOE filter.
- OWASP CRS kural seti yapılandırması.

---

## Faz 3 – Yönetim & Otomasyon
1. **CI/CD Entegrasyonu**
   - ModSecurity kural güncellemeleri için pipeline oluştur.
   - `make test-waf` hedefi ile HAProxy & ModSecurity config lint.
2. **Konfigürasyon Yönetimi**
   - WAF kuralları repo içinde version control.
   - Ortam bazlı (dev/stage/prod) override dosyaları.
3. **Monitoring**
   - Prometheus/Grafana ile WAF metrikleri (engellenen istek sayısı vs.).
   - Alertmanager ile kritik eşikler için bildirim.
4. **Failover Politikası**
   - ModSecurity/SPOE servisi down olursa: `t_idle` ve `on-error` davranışını belirle (pass-through vs block).

### Çıktılar
- Pipeline scriptleri, Makefile hedefleri.
- Monitoring/alerting dashboardları.

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
