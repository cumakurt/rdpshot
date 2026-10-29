# rdpshot — Uygulama Planı (v2)

> Bu belge `rdp_plan.md` içindeki vizyonu temel alır ve onu **uygulanabilir bir mühendislik planına** dönüştürür.
> Kod, değişken adları, loglar ve API İngilizcedir; plan belgeleri Türkçe yazılır (proje konvansiyonu).

## Proje Bilgileri

| | |
|---|---|
| **Geliştirici** | Cuma KURT |
| **E-posta** | [cumakurt@gmail.com](mailto:cumakurt@gmail.com) |
| **GitHub** | [github.com/cumakurt/rdpshot](https://github.com/cumakurt/rdpshot) |
| **LinkedIn** | [linkedin.com/in/cuma-kurt-34414917](https://www.linkedin.com/in/cuma-kurt-34414917/) |
| **Lisans** | [GNU General Public License v3.0](LICENSE) (GPL-3.0) |

---

## 1. Amaç ve Kapsam

**rdpshot**, yetkili sızma testi ve denetim senaryolarında RDP (Remote Desktop Protocol) servislerini
keşfetmek, yapılandırma/zafiyet taramak ve (yetki dahilinde) kimlik doğrulama kontrolleri yapmak için
geliştirilmiş kurumsal sınıf bir denetim aracıdır.

**Teslim edilen yetenekler (v1):**

1. Hedef yönetimi: IP, CIDR, hostname, port aralığı, dosyadan hedef okuma, blacklist/scope sınırlaması.
2. Keşif (recon): TCP port taraması, TPKT/COTP/X.224 RDP negotiation analizi, NLA tespiti,
   TLS parmak izi ve sertifika analizi, sunucu tarafı şifreleme (encryption level/method) analizi.
3. Zafiyet tespiti: BlueKeep (CVE-2019-0708) **güvenli kanal-probe**, NLA zorunluluğu eksikliği,
   zayıf şifreleme/zayıf TLS, self-signed veya süresi geçmiş sertifika, DejaBlue (CVE-2019-1181/1182)
   için **dürüst sezgisel değerlendirme** (uzaktan kesin tespit mümkün değildir; `potential` raporlanır).
4. Kimlik doğrulama denetimi (opsiyonel, açık onay gerektirir): NLA/CredSSP + NTLMv2 üzerinden
   worker-pool tabanlı sözlük denemeleri; hedef başına başarısız deneme limiti, lockout algılama,
   adaptif hız sınırlandırma ve jitter.
5. Oturum doğrulama: başarılı kimlik bilgisi sonrası ekran görüntüsü yakalama (`xfreerdp` tabanlı
   grabber) ve meta verilerinin kaydı.
6. Kalıcılık: SQLite (`modernc.org/sqlite`) üzerinde tarama, host, bulgu, kimlik bilgisi ve
   screenshot meta verisi.
7. Raporlama: HTML, CSV, PDF.
8. Arayüz: Dashboard, canlı tarama izleme (SSE), screenshot galerisi, zafiyet/rapor merkezi.
9. CLI: `scan`, `serve`, `report`, `targets`, `version` alt komutları; tek binary.

---

## 2. Yasal / Etik Çerçeve (Zorunlu Guardrail)

Bu araç çift kullanımlıdır (dual-use). Bu nedenle kod seviyesinde aşağıdaki guardrail'ler zorunludur:

* Kimlik doğrulama denemeleri ve ekran görüntüsü yakalama **varsayılan olarak kapalıdır**.
  `--enable-auth` / `--enable-screenshots` bayrakları **ve** `--ack-authorized` onayı birlikte
  verilmeden çalışmazlar.
* Hedef listesi dışında (blacklist) kalan hiçbir adrese istek atılmaz.
* Hedef başına maksimum başarısız deneme (`--max-auth-failures`, varsayılan 5) ve genel hız
  sınırı (`--rate`, varsayılan 10 bağlantı/sn) aşılmaz; hesap kilidi (lockout) sinyali algılanırsa
  o hedef için deneme derhal durur.
* BlueKeep kontrolü **yalnızca güvenli tespit probe'u** yapar; herhangi bir exploit/payload
  üretilmez ve çalıştırılmaz.
* Web arayüzü varsayılan olarak yalnızca `127.0.0.1` adresini dinler; dışarı açılırsa `RDSHOT_TOKEN`
  tabanlı basit bir bearer-token koruması devreye girer.
* Kimlik bilgileri veritabanına yazılırken dosya izinleri `0600` olacak şekilde saklanır ve
  raporlarda maskelenerek gösterilir (rapor üretirken `--reveal-secrets` ile açılır).

---

## 3. Teknoloji Kararları ve Gerekçeleri

| Alan | Karar | Gerekçe |
|---|---|---|
| Dil | Go 1.27 | Derlenmiş tek binary, güçlü eşzamanlılık, cross-compile |
| HTTP | `net/http` (stdlib, Go 1.22 pattern routing) | Fiber yerine stdlib; bağımlılık yüzeyi ve bakım riski azalır, yeterli performans |
| Canlı akış | **SSE** (`text/event-stream`) | WebSocket yerine SSE: tek yönlü ilerleme akışı için yeterli, proxy/HTML uyumu yüksek, ek bağımlılık yok |
| Loglama | `log/slog` (stdlib) | Yapılandırılmış loglama; zap bağımlılığı olmadan aynı ihtiyacın karşılanması |
| Konfigürasyon | `flag` + env + JSON config dosyası | Viper yerine stdlib; öncelik sırası deterministik (flag > env > config > default) |
| Veritabanı | `modernc.org/sqlite` (pure Go, CGO yok) | Taşınabilir, SQL rapor sorguları kolay, Docker'da sorunsuz |
| PDF | `github.com/go-pdf/fpdf` | Saf Go, bakımlı fork, header/footer ve tablo çizimi yeterli |
| NTLMv2 | `golang.org/x/crypto/md4` + kendi implementasyonumuz | NTLM protokolü standart; yalnızca MD4 için x/crypto |
| RDP protokolü | Kendi implementasyonumuz (`internal/rdp`) | TPKT/COTP/X.224 + RDP_NEG + MCS/GCC + CredSSP; bağımlılık yok, test edilebilir |
| Frontend | TailwindCSS (CDN) + HTMX + Alpine.js + Chart.js | Node build zinciri olmadan modern arayüz; rdp_plan.md'deki tasarım dili korunur |
| Test | `go test` + golden byte fixture'ları + fuzz | Protokol kodu byte-seviyesinde doğrulanır |

**Bilinçli sapmalar (rdp_plan.md'ye göre):**

* `cmd/cli` + `cmd/web` yerine **tek binary** (`rdpshot`) + alt komutlar → dağıtım ve sürüm yönetimi sadeleşir.
* Fiber + WebSocket yerine `net/http` + SSE → aynı işlevsellik, daha az bağımlılık.
* BoltDB seçeneği kullanılmaz; tek kalıcılık katmanı SQLite'tır.

---

## 4. Mimari Katmanlar ve Veri Akışı

```text
                 ┌────────────────────────────────────────────────┐
                 │                cmd/rdpshot (CLI)               │
                 │   scan | serve | report | targets | version    │
                 └───────────────┬────────────────────────────────┘
                                 │
        ┌────────────────────────┼─────────────────────────┐
        │                        │                         │
┌───────▼────────┐      ┌────────▼────────┐       ┌────────▼────────┐
│ internal/server│      │ internal/scanner│       │internal/reporter│
│ REST + SSE +   │◄────►│ Engine (worker  │       │ HTML / CSV / PDF│
│ web UI         │      │ pool, rate lim) │       └────────┬────────┘
└───────┬────────┘      └───┬────────┬────┘                │
        │                   │        │                     │
        │            ┌──────▼──┐ ┌───▼────────┐            │
        │            │internal/│ │internal/   │            │
        │            │  rdp    │ │  vuln      │            │
        │            │ protokol│ │ checks     │            │
        │            └──────┬──┘ └───┬────────┘            │
        │                   │        │                     │
        │            ┌──────▼────────▼─────┐      ┌────────▼────────┐
        │            │ internal/brute      │      │internal/screenshot│
        │            │ + auth (CredSSP)    │      │ xfreerdp grabber  │
        │            └──────────┬──────────┘      └────────┬──────────┘
        │                       │                          │
        └───────────┬───────────┴──────────┬───────────────┘
                    │                      │
             ┌──────▼───────┐       ┌──────▼───────┐
             │internal/store│       │internal/events│
             │   SQLite     │       │  Hub (pub/sub)│
             └──────────────┘       └──────────────┘
```

**Katman kuralları:**

* `internal/model` hiçbir pakete bağımlı değildir; tüm paylaşılan tipler oradadır.
* `internal/rdp` yalnızca protokol bilir; iş kuralı (zafiyet kararı) `internal/vuln`'dedir.
* `internal/store` tek veri erişim noktasıdır; SQL yalnızca bu pakette görünür.
* `internal/events`, `scanner`/`brute`/`screenshot` üreticileri ile `server` (SSE) tüketicisi
  arasında gevşek bağlantı sağlar; `Hub` bounded kuyruklu, drop-olabilir bir broadcast'tir
  (yavaş tüketici taramayı yavaşlatmaz).

---

## 5. Modül Sorumlulukları

### 5.1 `internal/model`
Paylaşılan domain tipleri: `Scan`, `ScanOptions`, `Progress`, `Endpoint`, `Host`, `ServiceInfo`,
`Finding`, `Credential`, `Screenshot`, `Severity`, `Summary`, `Event`. JSON etiketleri API ile
aynıdır. `Finding.Status` değerleri: `vulnerable | potential | not_vulnerable | inconclusive`.

### 5.2 `internal/config`
* Öncelik: CLI flag > env (`RDSHOT_*`) > config dosyası (`--config`) > default.
* Alanlar: DB yolu, çıktı dizinleri, timeout, rate, concurrency, wordlist yolları, sunucu adresi,
  token, log seviyesi/formatı.
* Doğrulama: negatif değerler, yazılamaz dizinler, olmayan wordlist dosyaları açık hata verir.

### 5.3 `internal/target`
* Spec sözdizimi: `192.168.1.10`, `10.0.0.0/24`, `host.example.com`, `10.0.0.5:3389`,
  `@file.txt` (satır bazlı), port listesi `3389,3390,33800-33900`.
* Blacklist: IP/CIDR eşleşmesi; scope dışına çıkılmaz.
* Güvenlik limitleri: tek CIDR'de maksimum genişleme, toplam hedef tavanı (`--max-targets`),
  hostname çözümleme hataları yutulmaz, raporlanır.
* Çıktı: deterministik `[]model.Endpoint` (adres, port) — tekrarsız.

### 5.4 `internal/rdp` (protokol paketi)
* `tpkt.go`: TPKT framing (versiyon, uzunluk), güvenli okuma (uzunluk doğrulaması, limit).
* `x224.go`: Connection Request/Confirm, cookie (`mstshash`), **RDP_NEG_REQ/RSP/FAILURE** ayrıştırma.
* `negotiation.go`: `PROTOCOL_RDP/SSL/HYBRID/HYBRID_EX/RDSTLS` bayrakları, failure code sözlüğü.
* `tlsinfo.go`: TLS el sıkışması yakalama; sürüm, cipher, ALPN, sertifika zinciri, SHA-256 parmak izi,
  self-signed tespiti, geçerlilik süresi.
* `mcs.go`: MCS Connect Initial/Response (BER) + GCC ConferenceCreateRequest (PER) kodlama/çözümleme;
  client core/security/network/cluster data blokları; server core/security/network data çözümleme
  (encryption level/method, MCS channel id, channel id listesi).
* `probe.go`: Yüksek seviye `Probe`: dial → X.224 negotiation → (TLS) → MCS bilgi toplama →
  `ServiceInfo` üretimi. Her adımda hata `inconclusive` kanıtıyla döner, panic olmaz.

### 5.5 `internal/vuln`
* `Check` arayüzü: `ID/Title/Severity/CVE/CVSS/Remediation/Run(ctx, *rdp.Session) []model.Finding`.
* Katalog (v1):
  | Check ID | Severity | Yöntem |
  |---|---|---|
  | `rdp-service-exposed` | info | RDP portu açık |
  | `nla-not-required` | high | RDP_NEG sonucu NLA (HYBRID) seçilmediyse |
  | `bluekeep-cve-2019-0708` | critical | `MS_T120` kanal join probe'u (güvenli tespit) |
  | `dejablue-cve-2019-1181-1182` | critical | Sezgisel: NLA kapalı + eski build → `potential` |
  | `weak-encryption` | high | encryption level `none/low` veya 40/56-bit method |
  | `weak-tls` | medium | TLS1.0/1.1 veya zayıf cipher (RC4/3DES/NULL) |
  | `self-signed-cert` | medium | Zinciri kendine imzalı |
  | `expired-cert` | medium | `NotAfter < now` |
* Her bulgu `Evidence` (ham bayt/alan dökümü) ve `Status` taşır; kesinleşmemiş sonuç
  `inconclusive` olarak raporlanır (asla `vulnerable` yapılmaz).

### 5.6 `internal/brute` + `internal/auth` + `internal/ntlm` + `internal/credssp`
* `Authenticator` arayüzü: `Authenticate(ctx, endpoint, credential) error`.
* `internal/ntlm`: NTLMv2 (NT hash, HMAC-MD5, NTLMv2 blob/AV pair, LMv2), NEGOTIATE/CHALLENGE/
  AUTHENTICATE mesaj serileştirme/çözümleme; MS-NLMP test vektörleriyle unit test.
* `internal/credssp`: TSRequest (ASN.1 DER), SPNEGO/NTLM token sarmalama, pubKeyAuth akışı.
* `internal/auth`: NLA/CredSSP üzerinden RDP oturum doğrulama; hata sınıflandırması
  (`ErrAuthFailed`, `ErrAccountLocked`, `ErrNLARequired`, `ErrProtocol`, `ErrTimeout`).
* `internal/brute`: aday üretici (user × password, veya user:pass çift dosyası), worker pool,
  hedef başına fail-safe, lockout'ta durma, jitter'lı token-bucket gecikme, olay yayını.

### 5.7 `internal/screenshot`
* `Grabber` arayüzü: `Grab(ctx, endpoint, credential) (model.Screenshot, error)`.
* v1: `XFreeRDPGrabber` — `xfreerdp` + headless X (`xvfb-run`) + görüntü yakalama; sistemde
  araç yoksa temiz hata (`ErrGrabberUnavailable`) ve bilgilendirme bulgusu üretir.
* Dosya adları sanitize edilir (`IP_port_user_timestamp.png`), yol geçişi (path traversal) engellenir.
* M5'te saf-Go RDP grafik istemcisi (bitmap decode) hedeflenir; arayüz hazır olduğundan
  mevcut kod değişmeden yeni grabber eklenebilir.

### 5.8 `internal/store`
* Şema (özet): `scans`, `hosts`, `findings`, `credentials`, `screenshots` + indexler.
* Sürümlü migrasyon (`schema_version`), transaction'lı yazma, hazırlıklı sorgular.
* Sorgular: tarama listesi/detayı, bulgu listesi, severity dağılımı, CVE bazlı özet, galeri listesi.

### 5.9 `internal/events`
* `Hub`: subscribe/publish; kanal başına bounded kuyruk (yavaş abone için drop + `dropped` sayacı).
* Event tipleri: `scan.started`, `scan.progress`, `host.done`, `finding`, `credential`,
  `screenshot`, `log`, `scan.finished`, `scan.failed`.

### 5.10 `internal/server` + `web/`
* REST uçları (JSON):
  * `POST /api/v1/scans` — yeni tarama başlatır
  * `GET /api/v1/scans` — geçmiş taramalar
  * `GET /api/v1/scans/{id}` — detay + ilerleme
  * `POST /api/v1/scans/{id}/cancel` — iptal
  * `GET /api/v1/scans/{id}/findings|hosts|screenshots`
  * `GET /api/v1/scans/{id}/report?format=html|csv|pdf`
  * `GET /api/v1/summary` — dashboard özet
  * `GET /api/v1/events` — SSE canlı akış (`?scan=` ile filtre)
* Web sayfaları: `/` dashboard, `/scans`, `/scans/{id}`, `/gallery`, `/reports`.
* Görsel dil: rdp_plan.md'deki "Cyber-Command Center" (Slate-950 zemin, indigo/emerald/rose vurgu).

### 5.11 `internal/reporter`
* HTML: gömülü şablon; özet kartları, severity dağılımı, host/bulgu tabloları, screenshot önizleme.
* CSV: SIEM uyumlu düz döküm (`scan_id,address,port,check_id,severity,status,cve,evidence,...`).
* PDF: yönetici özeti (scope, tarih, risk dağılımı tablosu, kritik bulgular, remediation).

---

## 6. Protokol Mühendisliği Notları

### 6.1 X.224 / RDP_NEG akışı
```text
Client → TPKT{ X.224 CR, RDP_NEG_REQ{ requestedProtocols: SSL|HYBRID|HYBRID_EX } }
Server → TPKT{ X.224 CC, RDP_NEG_RSP{ selectedProtocol } }   | RDP_NEG_FAILURE{ code }
```
* `selectedProtocol = 0` → klasik RDP security (NLA yok) → BlueKeep probe'u uygundur.
* `selectedProtocol = 1` (SSL) → TLS, NLA yok.
* `selectedProtocol = 2/10` (HYBRID/HYBRID_EX) → CredSSP/NLA zorunlu.
* `RDP_NEG_FAILURE` kodları ayrı raporlanır (ör. `HYBRID_REQUIRED_BY_SERVER` → NLA zorunlu).

### 6.2 BlueKeep güvenli tespit (MS_T120)
BlueKeep, `MS_T120` adlı dahili kanalın istemci tarafından farklı bir kanal id'siyle
talep edilmesi durumunda UAF koşuluna neden olur. **Güvenli tespit** şöyledir:

1. RDP security ile (NLA'sız) MCS Connect Initial gönderilir; `clientNetworkData` içine
   `MS_T120` kanalı **normal olmayan** bir id ile eklenir.
2. Sunucunun MCS Connect Response ve Channel Join (`MCS Erect/Attach/ChannelJoin`) yanıtı incelenir.
3. Yamasız sunucu talebi kabul eder (`vulnerable`); yamalı sunucu kanalı reddeder/bağlantıyı
   sonlandırır (`not_vulnerable`); yanıt yetersizse `inconclusive`.
4. NLA zorunlu sunucularda bu aşama uzaktan yapılamaz → sonuç `inconclusive` + not.

Hiçbir aşamada shellcode/payload üretilmez; yalnızca protokol seviyesinde talep/yanıt analizi yapılır.

### 6.3 CredSSP / NTLMv2 akışı (kimlik doğrulama)
```text
TLS handshake (NLA)
Client → TSRequest{ negoTokens: SPNEGO(NTLM NEGOTIATE) }
Server → TSRequest{ negoTokens: SPNEGO(NTLM CHALLENGE) }
Client → TSRequest{ negoTokens: SPNEGO(NTLM AUTHENTICATE + NTLMv2 response),
                    authInfo: RC4-HMAC(sessionKey) of NTLM AUTHENTICATE message,
                    pubKeyAuth: RC4-HMAC(sessionKey) of server public key }
Server → TSRequest{ pubKeyAuth: RC4-HMAC(sessionKey) of client public key }   // success
```
Başarısızlıkta sunucu `errorCode` (NTSTATUS) döndürür; `0xC000006A` (wrong password),
`0xC0000234` (locked out), `0xC0000072` (disabled) ayrıştırılıp brüt motoruna iletilir.

---

## 7. Veri Modeli (SQLite)

```sql
CREATE TABLE scans (
  id TEXT PRIMARY KEY, name TEXT NOT NULL,
  created_at TEXT NOT NULL, started_at TEXT, finished_at TEXT,
  status TEXT NOT NULL, options_json TEXT NOT NULL,
  total_targets INTEGER NOT NULL DEFAULT 0,
  done_targets INTEGER NOT NULL DEFAULT 0,
  error TEXT
);
CREATE TABLE hosts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id TEXT NOT NULL, address TEXT NOT NULL, port INTEGER NOT NULL,
  state TEXT NOT NULL, service_json TEXT NOT NULL, updated_at TEXT NOT NULL,
  UNIQUE(scan_id, address, port)
);
CREATE TABLE findings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id TEXT NOT NULL, host_id INTEGER NOT NULL,
  address TEXT NOT NULL, port INTEGER NOT NULL,
  check_id TEXT NOT NULL, title TEXT NOT NULL, severity TEXT NOT NULL,
  status TEXT NOT NULL, cvss REAL NOT NULL DEFAULT 0, cve TEXT,
  evidence TEXT, remediation TEXT, detected_at TEXT NOT NULL
);
CREATE TABLE credentials (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id TEXT NOT NULL, host_id INTEGER NOT NULL,
  address TEXT NOT NULL, port INTEGER NOT NULL,
  username TEXT NOT NULL, secret TEXT NOT NULL,
  domain TEXT, method TEXT NOT NULL, verified_at TEXT NOT NULL
);
CREATE TABLE screenshots (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id TEXT NOT NULL, host_id INTEGER NOT NULL,
  address TEXT NOT NULL, port INTEGER NOT NULL, username TEXT,
  file_path TEXT NOT NULL, width INTEGER, height INTEGER, captured_at TEXT NOT NULL
);
CREATE INDEX idx_findings_scan ON findings(scan_id, severity);
CREATE INDEX idx_hosts_scan ON hosts(scan_id);
CREATE INDEX idx_credentials_scan ON credentials(scan_id);
CREATE INDEX idx_screenshots_scan ON screenshots(scan_id);
```

`*_json` alanları, protokol seviyesindeki ham kanıtın (ServiceInfo) esnek biçimde saklanmasını sağlar.

---

## 8. Web Arayüzü Planı

| Ekran | Yol | İçerik |
|---|---|---|
| Dashboard | `/` | Özet kartları (hedef, bulgu, giriş, screenshot), hızlı tarama formu, canlı log terminali |
| Tarama Detayı | `/scans/{id}` | İlerleme çubuğu, aktif worker'lar, bulgu tablosu (glow hover), iptal butonu |
| Galeri | `/gallery` | Responsive kart ızgarası, thumbnail + zoom, IP/kullanıcı arama filtresi |
| Rapor Merkezi | `/reports` | Chart.js risk dağılımı, CVE listesi, PDF/HTML/CSV export butonları (spinner) |

Tasarım token'ları: `bg-slate-950`, kart `bg-slate-900/60 border-slate-800`,
vurgu `indigo-500/emerald-500/rose-500`, mono font (canlı log), `active:scale-95` mikro etkileşimler.
Tüm sayfalar mobil uyumludur (responsive grid).

---

## 9. Konfigürasyon Yüzeyi

| Anahtar | Env | Flag | Varsayılan |
|---|---|---|---|
| db path | `RDSHOT_DB` | `--db` | `outputs/rdpshot.db` |
| outputs dir | `RDSHOT_OUTPUTS` | `--outputs` | `outputs` |
| concurrency | `RDSHOT_CONCURRENCY` | `--concurrency` | `64` |
| rate (conn/sn) | `RDSHOT_RATE` | `--rate` | `10` |
| dial timeout | `RDSHOT_TIMEOUT` | `--timeout` | `5s` |
| max targets | `RDSHOT_MAX_TARGETS` | `--max-targets` | `65536` |
| max auth failures/host | `RDSHOT_MAX_AUTH_FAILURES` | `--max-auth-failures` | `5` |
| server addr | `RDSHOT_ADDR` | `--addr` | `127.0.0.1:8722` |
| auth token | `RDSHOT_TOKEN` | `--token` | boş (yalnızca localhost) |
| log level/format | `RDSHOT_LOG_LEVEL/FORMAT` | `--log-level/--log-format` | `info` / `text` |

---

## 10. Test ve Doğrulama Stratejisi

1. **Unit test:** hedef ayrıştırma, config önceliği, rate limiter, fail-safe sayaçları, rapor üretimi.
2. **Golden test:** X.224 CR/CC, RDP_NEG, MCS/GCC blob'ları bilinen bayt dizileriyle karşılaştırılır.
3. **Fuzz:** `x224.Parse`, `mcs.ParseConnectResponse`, `store` girişleri `go test -fuzz` ile taranır
   (panik/taşma olmamalı).
4. **Protokol simülasyonu:** `net.Pipe` üzerinde sahte RDP sunucusu ile negotiation senaryoları
   (NLA'lı, NLA'sız, NEG_FAILURE) test edilir.
5. **Build doğrulama:** `go vet`, `go test ./...`, `GOOS=linux/windows/darwin` cross-compile,
   Docker multi-stage build.
6. **Entegrasyon (manuel):** yetkili test ortamında gerçek Windows RDP hedefine karşı `scan` ve
   `--enable-auth --ack-authorized` koşuları; sonuçlar raporlanır.

---

## 11. Build ve Dağıtım

* `Makefile`: `build`, `test`, `vet`, `lint`, `docker`, `cross`, `clean`.
* `Dockerfile`: multi-stage (builder → distroless/scratch), non-root kullanıcı, volume `outputs/`.
* `docker-compose.yml`: servis + çıktı volume'u, yalnızca gerekli port yayını.
* `.gitignore`: `outputs/`, binary, `*.db`, `*.png` (kanıt görüntüleri repoya girmez).

---

## 12. Dizin Yapısı (Final)

```text
rdpshot/
├── cmd/rdpshot/main.go
├── internal/
│   ├── model/        config/      target/     rdp/
│   ├── vuln/         scanner/     brute/
│   ├── ntlm/         credssp/     auth/       screenshot/
│   ├── store/        events/      reporter/   server/
├── web/
│   ├── templates/    (layout, dashboard, scans, scan_detail, gallery, reports)
│   └── static/       (css/, js/)
├── wordlists/        (default_users.txt, default_passwords.txt)
├── outputs/          (reports/, screenshots/ — gitignore)
├── Dockerfile  docker-compose.yml  Makefile  README.md  plan.md  rdp_plan.md
├── go.mod  go.sum
```

---

## 13. Kilometre Taşları ve Kabul Kriterleri

| Kilometre | İçerik | Kabul kriteri |
|---|---|---|
| **M0** | İskelet, model, config, target, store, events | `go build ./...` temiz, store testleri geçer |
| **M1** | `internal/rdp` protokol katmanı + recon | Golden testler geçer; NLA/TLS/sertifika bilgisi doğru |
| **M2** | `internal/vuln` katalog + BlueKeep güvenli probe | Check registry çalışır, durumlar dürüst raporlanır |
| **M3** | `internal/brute` + ntlm/credssp/auth | NTLMv2 vektör testleri geçer; fail-safe/lockout doğrulanır |
| **M4** | screenshot + reporter (HTML/CSV/PDF) | Raporlar üretilir, dosya adları güvenli |
| **M5** | `internal/server` + web UI + CLI entegrasyonu | Uçlar çalışır, SSE canlı akış, Docker build geçer |

---

## 14. Riskler ve Azaltım

| Risk | Etki | Azaltım |
|---|---|---|
| RDP sunucu farklılıkları (fingerprint sapmaları) | Yanlış `inconclusive` | Her bulguda kanıt + güven seviyesi; fuzz ile parser sağlamlığı |
| NTLMv2/CredSSP implementasyon hatası | Auth denemeleri başarısız | MS-NLMP vektör testleri, hata sınıflandırma, `--enable-auth` ile izole |
| Hedef lockout | Operasyonel zarar | Hedef başına fail-safe, lockout algılama, adaptif rate |
| Web arayüzüne yetkisiz erişim | Veri sızıntısı | Varsayılan localhost, token koruması, hassas alan maskesi |
| Screenshot için harici araç bağımlılığı | Özellik eksik | `ErrGrabberUnavailable` + net dokümantasyon; M5 saf-Go hedefi |

---

## 15. Kapsam Dışı (Out of Scope)

* Herhangi bir RDP zafiyeti için exploit/payload/shellcode üretimi veya çalıştırılması.
* Kimlik bilgisi dökümü (LSASS, ticket, hash) ve yan yanal hareket (lateral movement) yetenekleri.
* Kalıcılık (persistence), C2, dosya sızdırma.
* Yetkisiz erişim için araç kullanımı (dokümantasyonda açık uyarı ve onay mekanizması bulunur).