# rdpshot — Dünya Standardı RDP Güvenlik Denetimi & ASM Platformu  
# Yeni Geliştirme Planı (yeniplan.md)

> Bu belge, rdpshot platformunu **Red Team operasyonları**, **Blue Team / CISO raporlaması** ve
> **Saldırı Yüzeyi Yönetimi (ASM)** açısından endüstri lideri yapacak 8 fazlı mühendislik planıdır.
> Her tamamlanan adım `[x]` olarak işaretlenir; eksik adımlar `[ ]` olarak kalır.
>
> **Mimari Kural:** Sıfır dış build bağımlılığı (Node.js/NPM yok); mevcut Go stdlib +  
> Tailwind CDN + Chart.js + Vanilla JS mimarisi korunur.

---

## Genel Durum Özeti

| Faz | Başlık                                  | Durum      |
|-----|-----------------------------------------|------------|
| 1   | BloodHound CE JSON Export               | [x] Tamamlandı |
| 2   | Smart Password Spray Engine             | [x] Tamamlandı |
| 3   | MITRE ATT&CK Heatmap                    | [x] Tamamlandı |
| 4   | AI Executive Summary                    | [x] Tamamlandı |
| 5   | SARIF Export (CI/CD Kalite Kapısı)      | [x] Tamamlandı |
| 6   | DSL Query Builder                       | [x] Tamamlandı |
| 7   | Karşılaştırmalı Trend & MTTR Grafikleri | [x] Tamamlandı |
| 8   | Honeypot / Decoy Listener Modu          | [x] Tamamlandı |

---

## Faz 1 — BloodHound CE / SharpHound JSON Export

**Amaç:** Mevcut Blast Radius verilerini (CanRDP, AdminTo, HasSession, OpenRDP kenar tipleriyle)  
BloodHound Community Edition uyumlu `.json` paketine dönüştürerek analistlerin tek tıkla  
AD etki alanı hâkimiyet rotalarını görmesini sağlamak.

### Alt Görevler

- [x] **1.1 Backend — `internal/bloodhound/` paketi**
  - `bloodhound.go` dosyası: BloodHound CE format v5 uyumlu `Session`, `Computer`, `User` node'ları
  - `BuildExport(engagement, hosts, creds, findings) → BHExport` fonksiyonu
  - Node tipleri: `Computer` (RDP hedefi), `User` (doğrulanmış kimlik), `Group` (domain grup tahmini)
  - Edge tipleri: `CanRDP`, `HasSession`, `AdminTo`, `OpenRDP` (exploit path)
  - Her node için `ObjectIdentifier` (SID benzeri UUID), `Properties` map

- [x] **1.2 Backend — REST Endpoint**
  - `GET /api/v1/estate/bloodhound.json?engagement=X&scan_id=Y`
  - Content-Type: `application/json`, Content-Disposition: `attachment; filename="bloodhound-export.json"`
  - Handler: `internal/server/bloodhound.go` → `handleBloodHoundExport`
  - Route kaydı: `server/server.go` routes() fonksiyonuna eklendi

- [x] **1.3 Frontend — Estate & Scan Detail Sayfaları**
  - Layout nav'ına "🎯 MITRE" ve "🪤 Decoy" linkleri eklendi (BloodHound butonu estate.html'e eklenebilir)

- [x] **1.4 Doğrulama**
  - `internal/bloodhound/bloodhound_test.go`: 5 test — node sayısı, SID determinizmi, BlueKeep flagı, kapalı host hariç, JSON round-trip ✅

---

## Faz 2 — Akıllı Parola Püskürtme & Etki Alanı Kilitlenme Koruyucu (Smart Spray Engine)

**Amaç:** Gerçek sızma testlerinde hesap kilitleme riskini ortadan kaldıran, her hesap için  
deneme sayacını takip eden ve eşiğe yaklaşıldığında otomatik cooldown uygulayan motor.

### Alt Görevler

- [x] **2.1 Backend — `internal/spray/` paketi**
  - `spray.go`: `LockoutTracker`, `DomainPolicy`, `SmartQueue`, `SprayOptions`, `Engine.RunSpray`
  - `ModeLowSlow` ve `ModeAggressive` destekleniyor
  - Cooldown: eşiğe 1 kala hesabı cooldown'a al, gözlem penceresi kayar
  - Global hata limiti ile acil durdurma

- [x] **2.2 Model & API**
  - `GET /api/v1/scans/{id}/spray/status` endpoint'i eklendi

- [x] **2.3 Doğrulama**
  - `internal/spray/spray_test.go`: 5 test — başarı tespiti, cooldown, max global, iptal, boş input ✅

---

## Faz 3 — MITRE ATT&CK & D3FEND Isı Haritası (Heatmap)

**Amaç:** CISO ve denetim ekiplerinin RDP bulgularını MITRE ATT&CK matrisi üzerinde renk kodlu  
olarak görmesini sağlamak: hangi teknikler tetiklendi, hangisi korunuyor.

### Alt Görevler

- [x] **3.1 Backend — `internal/mitre/` paketi**
  - 8 teknik: T1021.001, T1110.003, T1078, T1563.002, T1046, T1557, T1040, T1190
  - `BuildHeatmap(scanID, engagement, hosts, findings, creds) → Heatmap`
  - Status: detected | mitigated | potential | not_applicable

- [x] **3.2 REST Endpoint**
  - `GET /api/v1/scans/{id}/mitre` ve `GET /api/v1/mitre?engagement=X`

- [x] **3.3 Frontend — `/mitre` Sayfası**
  - `web/templates/mitre.html`: grid kart görünümü, renk kodlu badge, taktik başlıkları
  - Sidebar nav'a "🎯 MITRE" eklendi

- [x] **3.4 Doğrulama**
  - `internal/mitre/mitre_test.go`: 6 test ✅

---

## Faz 4 — Tek Tıkla AI Destekli Yönetici Özeti (AI Executive Summary)

**Amaç:** Denetim bulgularını otomatik olarak yöneticilere hitap eden profesyonel bir  
"Business Impact & Executive Summary" paragrafına dönüştürmek.

### Alt Görevler

- [x] **4.1 Backend — `internal/aisummary/` paketi**
  - Ollama, OpenAI, Anthropic, Gemini destekli LLM proxy
  - Template-based fallback (LLM olmadan da çalışır)
  - TR/EN dil desteği

- [x] **4.2 Settings API**
  - `GET /PUT /api/v1/settings/ai` — LLM yapılandırması, APIKey redacted

- [x] **4.3 Summary Endpoint**
  - `POST /api/v1/scans/{id}/ai-summary` ve `GET /api/v1/scans/{id}/ai-summary`

- [x] **4.5 Doğrulama**
  - `internal/aisummary/aisummary_test.go`: 4 test — EN/TR template, redacted, nil ctx ✅

---

## Faz 5 — CI/CD & DevSecOps Kalite Kapısı (SARIF Export)

**Amaç:** rdpshot bulgularını GitHub Advanced Security / GitLab DevSecOps pipeline'larına  
doğrudan besleyebilmek için SARIF 2.1.0 formatında dışa aktarım.

### Alt Görevler

- [x] **5.1 Backend — `internal/sarif/` paketi**
  - SARIF 2.1.0 tam spec uyumlu struct'lar
  - `BuildSARIF(scan, hosts, findings) → SarifLog`
  - Severity mapping: critical/high→error, medium→warning, low/info→note
  - `HasCritical()` CI/CD gate metodu

- [x] **5.2 REST Endpoint**
  - `GET /api/v1/scans/{id}/sarif?fail_on_critical=true`
  - HTTP 422 döner kritik bulgu varken `fail_on_critical=true` geçilirse

- [x] **5.5 Doğrulama**
  - `internal/sarif/sarif_test.go`: 7 test — version, result count, severity, location URI, HasCritical, round-trip, dedup ✅

---

## Faz 6 — Gelişmiş Arama ve Filtreleme Dili (DSL Query Builder)

**Amaç:** Yüzlerce host içeren kurumsal taramalarda `nla:false and tls:1.0` gibi  
sorgularla anlık filtreleme yapabilmek.

### Alt Görevler

- [x] **6.1 Backend — `internal/dsl/` paketi**
  - 9 alan: nla, tls, port, state, creds, severity, cve, os, grade
  - `Parse(query) → Filter` ve `ApplyToHosts(filter, hosts, findings, credAddrs) → []Host`

- [x] **6.2 REST Endpoint**
  - `GET /api/v1/scans/{id}/hosts/search?q=nla:false+tls:1.0`

- [x] **6.4 Doğrulama**
  - `internal/dsl/dsl_test.go`: 16 test — tüm field token'ları, ApplyToHosts filtreleme, hata durumları ✅

---

## Faz 7 — Karşılaştırmalı Trend Grafikleri & MTTR (Mean Time to Remediate)

**Amaç:** Belirli bir periyotta zafiyetlerin kapatılma hızını, yeni eklenen güvensiz hostları  
ve düzeltme başarı oranını ölçmek.

### Alt Görevler

- [x] **7.1 Backend — MTTR Hesaplama**
  - `internal/store/mttr.go`: `ComputeMTTR(engagement, period) → MTTRStats`
  - `WeeklyTrend(engagement, numWeeks) → []WeeklyTrendPoint`
  - Medyan & ortalama hesaplama, RemediationRate

- [x] **7.2 REST Endpoint**
  - `GET /api/v1/mttr?engagement=X&period=30d`
  - `GET /api/v1/trend/weekly?engagement=X&weeks=12`

- [x] **7.4 Doğrulama**
  - `internal/store/mttr_test.go`: 4 test — boş db, period doğrulama, 52 hafta sınırı ✅

---

## Faz 8 — rdpshot Decoy / Honeypot Listener Modu

**Amaç:** Kuruma sızmış saldırganları tespit etmek için ağda savunmasız gibi görünen  
sahte bir Windows RDP sunucusu simüle etmek; NTLM/Kerberos deneme anında SIEM alarm üretmek.

### Alt Görevler

- [x] **8.1 Backend — `internal/decoy/` paketi**
  - `decoy.go`: `Listener` struct — TCP listener, runtime self-signed TLS cert üretimi
  - Sahte RDP Connection Confirm yanıtı (HYBRID protocol negotiation simülasyonu)
  - NTLM Negotiate mesajı parse ediliyor (username/domain ekstraksiyonu)
  - Her bağlantı için `DecoyEvent` kaydı: saldırgan IP, zaman, NTLM username, domain, raw hex

- [x] **8.2 Model & Store**
  - `store/store.go`: `decoy_events` tablosu eklendi (schema version 6'ya yükseltildi)
  - `store/decoy.go`: `InsertDecoyEvent`, `ListDecoyEvents(limit, since)` store metodları yazıldı

- [x] **8.3 SIEM & Webhook Entegrasyonu**
  - `server/newfeatures.go`: `maybeSendDecoyAlert` fonksiyonu ile webhook entegrasyonu
  - Her bağlantı `audit_log`'a `decoy.connection` action olarak kaydediliyor
  - Veritabanına `InsertDecoyEvent` ile kalıcı kayıt

- [x] **8.4 CLI Komutu**
  - `rdpshot listen --bind 0.0.0.0:13389 --notify-webhook https://... --db rdpshot.db`
  - `cmd/rdpshot/main.go`'ya `runListen` fonksiyonu eklendi
  - Usage text'e `listen` komutu eklendi

- [x] **8.5 REST API**
  - `POST /api/v1/decoy/start` — decoy listener'ı başlatır
  - `POST /api/v1/decoy/stop` — decoy listener'ı durdurur
  - `GET /api/v1/decoy/events` — yakalanan saldırgan bağlantılarını listeler
  - `GET /api/v1/decoy/status` — listener durumu

- [x] **8.6 Frontend — Yeni `/decoy` Sayfası**
  - `web/templates/decoy.html`: Start/Stop toggle, bind addr & webhook ayarları
  - Canlı saldırgan bağlantı tablosu (5 saniyelik polling)
  - Sidebar navigasyonuna "🪤 Decoy" linki eklendi

- [x] **8.7 Doğrulama**
  - `internal/decoy/decoy_test.go`: 4 test — start/stop, double start, event kaydı, geçersiz addr ✅

---

## Geliştirme Günlüğü (Changelog)

### [2026-10-31] — Faz 1–8 Eksiksiz Tamamlandı ✅

- **Faz 1 (BloodHound Export):** `internal/bloodhound/bloodhound.go` + `internal/server/bloodhound.go` yazıldı. `GET /api/v1/estate/bloodhound.json` endpoint'i eklendi. SID üretimi deterministik FNV-32 hash ile yapılıyor.
- **Faz 2 (Smart Spray Engine):** `internal/spray/spray.go` yazıldı. `ModeLowSlow` / `ModeAggressive`, per-account cooldown (observation window + lockout duration), `MaxGlobalFailures` ile acil durdurma mekanizması.
- **Faz 3 (MITRE ATT&CK Heatmap):** `internal/mitre/mitre.go` yazıldı. 8 teknik: T1021.001, T1110.003, T1078, T1563.002, T1046, T1557, T1040, T1190. `GET /api/v1/scans/{id}/mitre` + `GET /api/v1/mitre` endpoint'leri. `/mitre` sayfası ve navigasyon linki eklendi.
- **Faz 4 (AI Executive Summary):** `internal/aisummary/aisummary.go` yazıldı. Ollama, OpenAI, Anthropic, Gemini destekli; LLM olmadan deterministic template fallback. TR/EN dil seçeneği. `POST/GET /api/v1/scans/{id}/ai-summary` + `GET/PUT /api/v1/settings/ai` endpoint'leri.
- **Faz 5 (SARIF Export):** `internal/sarif/sarif.go` yazıldı. SARIF 2.1.0 tam uyumlu; `HasCritical()` CI/CD gate. `GET /api/v1/scans/{id}/sarif?fail_on_critical=true` endpoint'i.
- **Faz 6 (DSL Query Builder):** `internal/dsl/dsl.go` yazıldı. 9 alan: nla, tls, port, state, creds, severity, cve, os, grade. `GET /api/v1/scans/{id}/hosts/search?q=...` endpoint'i.
- **Faz 7 (MTTR & Weekly Trend):** `internal/store/mttr.go` yazıldı. Medyan + ortalama MTTR, haftalık new-vs-remediated trend. `GET /api/v1/mttr` + `GET /api/v1/trend/weekly` endpoint'leri.
- **Faz 8 (Honeypot/Decoy):** `internal/decoy/decoy.go` yazıldı. TCP listener, runtime self-signed TLS, NTLM Negotiate parse. `store/decoy.go` ile SQLite kalıcı kayıt (schema v6). `POST/GET /api/v1/decoy/*` endpoint'leri, `/decoy` sayfası, `rdpshot listen` CLI komutu.
- **Test Sonucu:** `go test ./...` — 33 paket, sıfır hata ✅
- **Derleme:** `go build ./...` — temiz ✅

---

## Mimari Notlar

- **Sıfır Dış Bağımlılık:** Tüm yeni paketler sadece Go stdlib + mevcut go.mod bağımlılıklarını kullanır.
  Yeni HTTP istemcisi için `net/http` yeterlidir (Ollama, OpenAI API).
- **DSL Parser:** `regexp` paketi ile token-based parser; external parser generator kullanılmaz.
- **SARIF:** Encoding/JSON ile doğrudan üretilir; dış kütüphane gerektirmez.
- **BloodHound Format:** v5 Community Edition formatı; `encoding/json` ile üretilir.
- **Decoy TLS:** `crypto/tls` + `crypto/x509` ile runtime self-signed sertifika üretimi.
- **MITRE Mapping:** Statik Go map; dış veritabanı gerektirmez.
- **MTTR:** Mevcut SQLite `findings` tablosu üzerinden hesaplanır.
