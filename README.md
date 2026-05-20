# HAProxy Advanced Security Dashboard 🛡️🚀

Bu proje, HAProxy tabanlı altyapılar için geliştirilmiş, yüksek güvenlikli ve kullanıcı dostu bir yönetim panelidir. Sadece yük dengeleme değil, aynı zamanda aktif bir siber savunma kalkanı sunar.

## ✨ Öne Çıkan Özellikler

### 🛡️ Akıllı Güvenlik Duvarı (Guard System)
*   **Otomatik Ban:** 60 saniye içinde 5 hatalı (401, 403, 404, 429) istek yapan IP adreslerini otomatik olarak 1 saat boyunca engeller.
*   **Zeki Ayıklama:** `/UploadSanal/` veya `.jpg`, `.png` gibi masum 404 hatalarını görmezden gelir, false-positive oranını düşürür.
*   **Kritik Yol Koruması:** `.env`, `.git`, `config.php` gibi dosyaları arayan saldırganları anında (tek hatada) banlayarak sert bir savunma yapar.
*   **Detaylı Analiz:** Banlanan IP'lerin hangi sayfada hata aldığını ve hangi kodları tetiklediğini panel üzerinden görebilirsiniz.

### 🧱 WAF (ModSecurity + OWASP CRS)
*   **OWASP Core Rule Set:** SQL Injection, XSS, Local File Inclusion gibi binlerce profesyonel saldırı imzasını içeren CRS v4 aktif olarak çalışır.
*   **Kural Yönetimi:** Web arayüzü üzerinden kendi ModSecurity kurallarınızı ( `.conf`) oluşturabilir, düzenleyebilir ve silebilirsiniz.
*   **SPOA Entegrasyonu:** HAProxy ile tam uyumlu SPOA (Stream Processing Offload Agent) mimarisi.

### 📊 Modern Yönetim Paneli
*   **Güvenlik Dashboard:** Banlı IP'ler, Beyaz Liste (Whitelist) ve WAF kuralları için merkezi yönetim.
*   **SSL Yönetimi:** Certbot entegrasyonu ile otomatik SSL sertifikası üretimi.
*   **Canlı İstatistik:** HAProxy trafik verilerini görsel grafiklerle izleme.

## 🚀 Kurulum

1. Depoyu klonlayın:
```bash
git clone https://github.com/umiteyigun/haproxy.git
cd haproxy
```

2. Docker Compose ile ayağa kaldırın:
```bash
docker compose up -d --build
```

3. Paneli açın:
`http://sunucu-ip-adresi:3000`

## 🛠️ Teknoloji Yığını
*   **Backend:** Node.js, Express
*   **DB:** PostgreSQL
*   **Security:** Python 3 (Guard), ModSecurity, iptables
*   **Frontend:** HTML5, Bootstrap 5, Vanilla JS

---
Geliştiren: **Ümit Eyigün** & **Antigravity AI**
