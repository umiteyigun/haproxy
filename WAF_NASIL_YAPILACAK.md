# WAF Nasıl Yapılacak?

Bu doküman, projede planlanan WAF (Web Application Firewall) çalışmalarının fazlara göre nasıl uygulanacağını ve dosya yollarını özetler. Her faz tamamlandıkça ilgili bölüm genel README gibi güncellenecek.

---

## Faz 1 – HAProxy ACL & Rate Limiting (Tamamlandı)
**Amaç:** Temel saldırı yüzeyini daraltmak için IP kara listesi, User-Agent filtrasyonu ve hız limitleme mekanizmalarını HAProxy üzerinde devreye almak.

### Uygulanan Adımlar
- `haproxy/haproxy.cfg` – `http_frontend` ve `https_frontend` bloklarına IP kara listesi, rate limit ve kötü kullanıcı ajanı kontrolleri eklendi.
- `haproxy/config.d/ip_blacklist.lst` – CIDR veya IP bazlı engelenen kaynak listesini yönetmek için dosya oluşturuldu. (Örnek içerik: tek IP ya da 24’lük CIDR blokları)
- `haproxy/maps/bad_useragents.lst` – Şüpheli User-Agent kalıpları için yönetilebilen liste.

### Notlar
- LetsEncrypt ACME doğrulamaları (`/.well-known/acme-challenge/`) rate limit kontrollerinden muaf tutuldu.
- HAProxy konfigürasyonu doğrulamak için: `docker-compose exec haproxy haproxy -c -f /usr/local/etc/haproxy/haproxy.cfg`
- Kara liste veya User-Agent listesine yeni kayıt eklemek için ilgili dosyaları düzenleyip HAProxy’yi yeniden yüklemek yeterli.

---

## Faz 2 – ModSecurity + SPOE Entegrasyonu (Sürmekte)
**Hedef:** OWASP CRS (Core Rule Set) tabanlı imza kontrollerini HAProxy üzerine taşımak.

### Yapılanlar
- `spoa/Dockerfile` – `jcmoraisjr/modsecurity-spoa` reposundan uyarlanan yapı ile ModSecurity 2.9.11 ve OWASP CRS paketleri tek bir imajda derleniyor.
- `spoa/start.sh` & `spoa/spoa.patch` – SPOA agent’ı için entrypoint ve build patch dosyaları eklendi.
- `docker-compose.yml` – Ayrı `modsecurity` servisi kaldırıldı; `spoa` servisi depo kökünden build alacak şekilde güncellendi ve log dizini mount edildi.
- `haproxy/modsecurity.conf` – `[modsecurity]` bölümü, timeout değerleri ve `on-frontend-http-request` event tanımı ile güncellendi.
- `haproxy/haproxy.cfg` – HTTP/HTTPS frontend’lerine SPOE filtreleri ve WAF ACL kuralları eklendi; dinamik placeholder’lar (ACL/redirect/backend) geri yüklendi.
- `scripts/waf_smoke_test.sh` – İyi ve kötü User-Agent senaryolarını kullanarak WAF’ın temel davranışını otomatik test eden betik.

### Test Notları
- Benign istek (301 yönlendirme beklenir):
  - `curl -s -o /dev/null -w "%{http_code}\n" -H "Host: ssl.trtek.tr" -H "User-Agent: Mozilla/5.0" http://localhost/`
- Kötü amaçlı tarayıcı taklidi (403 beklenir):
  - `curl -s -o /dev/null -w "%{http_code}\n" -H "Host: ssl.trtek.tr" -H "User-Agent: sqlmap" http://localhost/`
- HAProxy loglarında 403 satırları `PR--` olarak görülebilir (bkz. `docker logs haproxy --tail 5`).

### Yapılacaklar
- OWASP CRS üzerinde kurum ihtiyaçlarına göre tuning (false-positive analizi, ek kural dosyaları).
- DetectionOnly modundan Block moduna geçiş için kontrol listesi oluşturma.
- SPOA bağlantısı için ek güvenlik (mTLS, health-check, on-error davranışı) değerlendirmesi.
- ModSecurity loglarının merkezi izleme sistemine aktarılması.

> Bu faz uygulandıkça bölüm adım adım genişletilecek.

---

## Faz 3 – CI/CD, Monitoring ve Dokümantasyon (Başlatıldı)
**Hedef:** WAF konfigürasyonlarını otomasyona almak, izleme/uyarı mekanizmalarını devreye sokmak.

- `Makefile` → `make test-waf` hedefi SPOA/HAProxy imajlarını build edip, stack’i ayağa kaldırarak duman testi çalıştırır.
- `.github/workflows/waf-ci.yml` → Her push/PR’da WAF bileşenlerini build eder, HAProxy syntax kontrolü yapar ve smoke test betiğini çalıştırır.
- WAF logları (HAProxy ve ModSecurity) için `make waf-logs` ile hızlı erişim sağlandı.
- Performans ve latency ölçümleri ile merkezi log/monitoring entegrasyonu sonraki iterasyonlarda tamamlanacak.
- Bu README ve `docs/WAF_PLAN.md` düzenli olarak güncellenecek.

> Faz 3 kapsamında kalan işler: merkezi log shipping, uyarı mekanizmaları, üretim ortamı için performans ölçümleri.

---

## İlgili Dokümanlar
- `docs/WAF_PLAN.md` – Üç fazlı WAF proje planı (detaylı görev listesi).
- `README.md` – Proje genel yönetim dokümanı.

Geri bildirim veya yeni gereksinim olması durumunda bu dosya üzerinden ilerleyebiliriz.
