# PrimeNG Tablo Geliştirme Planı

## Özet

Uygulamadaki tüm PrimeNG `p-table` bileşenlerine aşağıdaki özellikler eklenecektir:

| Özellik | Detay |
|---------|-------|
| Gelişmiş Sayfalama | İlk/Son sayfa butonları, rows-per-page seçici, sayfa raporu metni |
| Çok-Sütun Sıralama | Tüm veri sütunlarında `[sortMode]="'multiple'"` |
| Gelişmiş Filtreleme | Kolon başlığında filtre ikonu + dropdown menü (`filterDisplay="menu"`) |
| Yenile Butonu | Her sayfanın toolbar'ında `pi-refresh` ikonu ile yenile butonu |
| ProgressSpinner Overlay | p-table yüklenme sırasında `p-progressSpinner` gösterimi |
| Büyük Veri Performansı | Sayfalama ile DOM renderı sınırlı, OnPush change detection |

## Kapsam Dışı

- API'ye server-side pagination eklenmesi
- Yeni servis metotları yazılması
- Mevcut CRUD dialog mantığının değiştirilmesi

## Etkilenen Sayfalar

| Sayfa | Tablo Sayısı | Bileşen Dosyası |
|-------|-------------|-----------------|
| WAF | 2 | `pages/waf/waf.ts` + `waf.html` |
| Members | 1 | `pages/members/members.ts` + `members.html` |
| Logs | 1 | `pages/logs/logs.ts` + `logs.html` |
| Dashboard | 1 | `pages/dashboard/dashboard.ts` + `dashboard.html` |
| Ingress | 1 | `pages/ingress/ingress.ts` + `ingress.html` |
| SSL | 1 | `pages/ssl/ssl.ts` + `ssl.html` |
| Port Forward | 1 | `pages/port-forward/port-forward.ts` + `port-forward.html` |
| Connections | 1 | `pages/connections/connections.ts` + `connections.html` |

---

## Faz 1 — Plan Dosyası

Bu dosya ✅

---

## Faz 2 — PrimeNG Modül Eklemeleri

Her bileşenin `imports[]` dizisine eklenecek:
- `ProgressSpinnerModule` (`primeng/progressspinner`)
- `InputNumberModule` (`primeng/inputnumber`) — sayısal filtreler için

---

## Faz 3 — Gelişmiş Sayfalama

Her `<p-table>` öğesine eklenecek property'ler:

```html
[paginator]="true"
[rows]="25"
[rowsPerPageOptions]="[10, 25, 50, 100]"
[showFirstLastIcon]="true"
[showCurrentPageReport]="true"
currentPageReportTemplate="Toplam {totalRecords} kayıttan {first}-{last} gösteriliyor"
```

**İstisnalar:**
- Dashboard: `[rows]="10"` (mevcut değer korunur)
- Logs: `[rows]="50"` + `[rowsPerPageOptions]="[25, 50, 100, 200]"`
- Connections: `[rows]="50"`

---

## Faz 4 — Yenile Butonu

Her sayfanın toolbar'ına eklenecek buton:

```html
<p-button
  icon="pi pi-refresh"
  label="Yenile"
  severity="secondary"
  (onClick)="load()"
  [loading]="loading()"
/>
```

**İstisnalar:**
- Dashboard: `(onClick)="loadStats()"`
- WAF: ayrı `loadRules()` + `loadCrsRules()` butonları

---

## Faz 5 — Çok-Sütun Sıralama

Her `<p-table>` öğesine:
```html
[sortMode]="'multiple'"
```

Her `<th>` (aksiyon kolonu hariç):
```html
<th pSortableColumn="fieldname">
  <div class="flex align-items-center gap-2">
    Başlık <p-sortIcon field="fieldname" />
  </div>
</th>
```

---

## Faz 6 — Gelişmiş Kolon Filtreleme

Her `<p-table>` öğesine:
```html
[filterDisplay]="'menu'"
```

Sütun tiplerine göre filtre:

```html
<!-- Metin sütunlar -->
<p-columnFilter type="text" field="name" display="menu" />

<!-- Sayısal sütunlar -->
<p-columnFilter type="numeric" field="port" display="menu" />

<!-- Tarih sütunları -->
<p-columnFilter type="date" field="expires_at" display="menu" />
```

**Logs & Connections Özel Durum:**
- Mevcut `filtered = computed(...)` signal'ı kaldırılır
- `[value]="logs()"` / `[value]="connections()"` kullanılır
- Global arama input'u korunur: `dt.filterGlobal($event.target.value, 'contains')`
- `[globalFilterFields]` property'si tanımlanır

**WAF CRS Özel Durum:**
- `enabled` toggle sütununa filtre EKLENMEZ (aksiyon sütunu gibi muamele)

---

## Faz 7 — ProgressSpinner Overlay

Her p-table içine yükleme şablonu:

```html
<p-table [loading]="loading()">
  <ng-template pTemplate="loadingicon">
    <p-progressSpinner
      strokeWidth="4"
      animationDuration=".8s"
      styleClass="w-4rem h-4rem"
    />
  </ng-template>
  ...
</p-table>
```

Bu yöntem:
- p-table'ın built-in overlay mekanizmasını kullanır (tablo üzerine yarı saydam örtü)
- UI kesintiye uğramaz (rest of page interactive remains)
- Yükleme ikonu p-progressSpinner ile değiştirilir

---

## Faz 8 — Büyük Veri Performansı

- **Sayfalama mekanizması:** DOM renderı sadece aktif sayfadaki N satırla sınırlı → büyük dataset'lerde otomatik performans
- **Angular OnPush CD:** Signal tabanlı bileşenler OnPush ile tam uyumlu
- **Logs:** `[scrollable]="true" scrollHeight="65vh"` korunur (pagination + scroll beraber çalışır)
- **Connections:** `[scrollable]="true" scrollHeight="60vh"` korunur

```typescript
// Her bileşene eklenecek
changeDetection: ChangeDetectionStrategy.OnPush
```

---

## Doğrulama Kontrol Listesi

- [ ] `ng build` — sıfır TypeScript/template hatası
- [ ] Her sayfa: ilk/son sayfa butonları görünür
- [ ] Rows-per-page dropdown çalışır
- [ ] Sayfa rapor metni (1-25 / toplam) görünür
- [ ] Sütun başlığına tıkla → sıralama ok ikonu + çok-sütun sıralama
- [ ] Filtre (huni) ikonuna tıkla → koşullu filtre menüsü açılır
- [ ] Birden fazla filtre koşulu girilebilir (AND/OR)
- [ ] Yenile butonuna tıkla → loading spinner + veri yenilenir
- [ ] Ağı yavaşlat (DevTools throttle) → ProgressSpinner overlay görünür, sayfa donmaz
- [ ] WAF CRS toggle → filtreler aktifken toggle çalışır
- [ ] Logs/Connections: global arama + column filter beraber çalışır
