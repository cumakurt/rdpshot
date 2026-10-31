# rdpshot — Görsel Arayüz (GUI) Geliştirme ve Değer Katma Planı (guiplan.md)

> Bu belge, `rdpshot` RDP güvenlik denetim platformunun web konsolunu dünya standardında bir Red Team & Posture Management arayüzüne dönüştürmek için hazırlanan mühendislik planıdır.
> Her faz adım adım kodlanmış, tamamlanan her madde plan dosyasında `[x]` olarak işaretlenmiş ve altına açıklayıcı geliştirme notu düşülmüştür.

---

## Genel Hedefler ve Mimari Prensipler
1. **Sıfır Dış Bağımlılık (Zero Heavy Runtime):** Node.js / NPM build zinciri gerektirmeyen, mevcut Go stdlib + Tailwind CDN + Chart.js + Vanilla JS mimarisini korumak.
2. **Operatör & Yönetici Odaklılık:** Hem pentester'ın hızlı kanıt alıp bağlantı kurmasını hem de CISO/yöneticinin kurumsal uyumluluğu ve saldırı yolunu tek bakışta görmesini sağlamak.
3. **Gerçek Zamanlılık (Real-time):** SSE (Server-Sent Events) ve anlık REST etkileşimleri ile sayfa yenilemeden canlı güncellemeler sunmak.
4. **Çift Tema Desteği:** Eklenen tüm yeni bileşenlerin hem `Command Center (Dark)` hem de `Corporate Clean (Light)` temalarıyla %100 uyumlu olması.

---

## Geliştirme Fazları ve Takip Listesi

### Faz 1: Tek Tıkla RDP Bağlantı Kısayolu (.rdp Dosyası & URI İndirme)
Analist veya denetçinin bulduğu açık/doğrulanmış hedeflere doğrudan bağlanabilmesi için standart `.rdp` yapılandırma dosyası üretimi ve link entegrasyonu.

- [x] **1.1 Backend:** `internal/server/connect_rdp.go` altında standart Windows RDP yapılandırması üreten REST uç noktası (`GET /api/v1/hosts/connect.rdp?address=...&port=...&user=...&domain=...&nla=...`) eklendi. NLA, TLS, screen mode, çözünürlük parametreleri ve MIME tipi `application/x-rdp` olarak yapılandırıldı.
- [x] **1.2 Frontend (Host Tablosu & Kartları):** `scan_detail.html` (Verified Credentials ve Discovered Hosts tabloları) ile `estate.html` ve `app.js` içerisine tek tıkla `.rdp` indirme butonu ve `rdp://` URI kısayolları eklendi.
- [x] **1.3 Doğrulama:** `api_test.go` içerisindeki `TestDownloadRDPConfig` birim testi ile `172.16.3.128:3389` hedefi ve `cmk` kullanıcısı için dosya başlıkları ve parametreler doğrulandı.

---

### Faz 2: Tek Tıkla Düzeltme Kodu Üreteci (1-Click Remediation Playbook Generator)
Bulunan zafiyetlerin (NLA eksikliği, eski TLS 1.0/1.1, zayıf cipher, unprompted shadowing, BlueKeep vb.) sistem yöneticileri tarafından anında kapatılabilmesi için hazır script üreteci.

- [x] **2.1 Backend / Playbook Genişletme:** `internal/playbook/playbooks.go` modeline `Scripts` (PowerShell, Registry, Ansible, Bash) yapıları ve 15 zafiyet kontrolü için üretime hazır düzeltme şablonları eklendi.
- [x] **2.2 REST API:** `GET /api/v1/playbooks/{check_id}/script?format=powershell|registry|ansible|bash` uç noktası eklendi. Hem doğrudan metin/dosya indirme hem de JSON dönme yeteneği kazandırıldı.
- [x] **2.3 Frontend Modal & Sekmeli Kod Kutusu:** `scan_detail.html` üzerinde bulgu detay panelinde sekmeli (PowerShell / Registry / Ansible / Bash) kod kutusu, tek tıkla "Copy to Clipboard" butonu ve hızlı "Remediate" tetikleyicisi eklendi.
- [x] **2.4 Doğrulama:** `playbooks_test.go` ve `api_test.go:TestPlaybookScriptAPI` testleri ile scriptlerin doğruluğu teyit edildi.

---

### Faz 3: Kurumsal Uyumluluk Radar Grafiği (Compliance Radar / Spider Chart)
Denetim bulgularının CIS, PCI-DSS, NIST ve ISO 27001 kurumsal standartlarına göre uyumluluk skorlarını görselleştiren çok eksenli radar grafik.

- [x] **3.1 Backend:** `internal/score/score.go` içerisine `EvaluateCompliancePosture` fonksiyonu eklendi. CIS, PCI-DSS, NIST ve ISO-27001 kurumsal standartları için açık bulgular ve host hardening metriklerine dayalı dinamik uyumluluk yüzdeleri hesaplandı (`GET /api/v1/scans/{id}/compliance-posture`).
- [x] **3.2 Frontend (Chart.js Radar):** `scan_detail.html` ve `reports.html` sayfalarına Chart.js `radar` bileşeni eklendi. `app.js` üzerinden otomatik veri çekilerek 4 eksenli uyumluluk grafiği çizdirildi.
- [x] **3.3 Karşılaştırma:** `compare.html` sayfasına çift tarama radar örtüşmesi (Base Scan vs Against Scan) entegre edildi. Delta karşılaştırmalarında güvenlik duruşundaki değişim görselleştirildi.
- [x] **3.4 Doğrulama:** `score_test.go:TestEvaluateCompliancePosture` ve `api_test.go:TestCompliancePostureAPI` birim testleri ile sonuçlar doğrulandı.

---

### Faz 4: Kanban Tarzı Zafiyet & Triage Panosu (Vulnerability Triage Board)
Bulguların geleneksel liste görünümünün yanında sürükle-bırak / tek tıkla durum değiştirmeli Kanban kartları olarak yönetilmesi.

- [x] **4.1 Frontend Arayüz:** `scan_detail.html` başlığına "Table View" ve "Kanban Board" görünüm değiştiricisi (toggle) eklendi.
- [x] **4.2 Kanban Sütunları:** `Açık (Open)`, `Doğrulandı (Confirmed)`, `Yanlış Pozitif (False Positive)`, `Düzeltildi (Remediated)` olmak üzere 4 sütunlu responsive kart ızgarası hazırlandı.
- [x] **4.3 Canlı Durum Güncellemesi:** Kartların sürükle-bırak (HTML5 Drag & Drop) veya açılır menü ile taşınması durumunda anında `PATCH /api/v1/findings/{fid}/triage` isteği atılarak veritabanı, sayaçlar ve tablo görünümü eşzamanlandı.
- [x] **4.4 Doğrulama:** Bulgu durumunun taşınması ve triage notları uçtan uca test edildi.

---

### Faz 5: Kimlik Sıçrama Alanı & Saldırı Yolu Grafiği (Credential Blast Radius & Attack Graph)
Ele geçirilen veya doğrulanan bir parolanın/hash'in ağdaki diğer hangi makinelerde geçerli olduğunu veya hedefler arası güven ilişkisini gösteren ağ topolojisi.

- [x] **5.1 Backend:** `internal/estate/estate.go` içerisine `BuildBlastRadius` fonksiyonu ve `GET /api/v1/estate/blast-radius` REST uç noktası eklendi. Doğrulanan kimlikler, hedef hostlar ve kritik pivot zafiyetleri (BlueKeep vb.) grafik düğüm ve kenarlarına dönüştürüldü.
- [x] **5.2 Frontend (SVG/Canvas Topoloji):** `/estate` sayfasına "Risk Scatter" ve "⚡ Blast Radius & Attack Path" mod değiştiricisi eklendi. Konsantrik SVG topoloji çizimi ile kimlikler (yeşil), hostlar (mor) ve açık zafiyetler (kırmızı) etkileşimli ve parlamalı (glow) olarak sunuldu.
- [x] **5.3 Doğrulama:** `estate_test.go:TestBuildBlastRadius` ve `api_test.go:TestBlastRadiusAPI` ile `cmk` kullanıcısı ve lab sunucusu arasındaki saldırı yolları doğrulandı.

---

### Faz 6: Ekran Görüntüsü Üzerinde Etkileşimli OCR & Hassas Veri Analitiği (Visual Inspector)
Visual Session Vault galerisinde yakalanan ekran görüntülerinin üzerinde OCR ile tespit edilen kullanıcıların, pencerelerin ve hassas anahtar kelimelerin vurgulanması.

- [x] **6.1 Backend / Model:** `internal/server/pages.go` üzerindeki `GalleryItem` modeli `IsSensitive`, `SensitiveTags` ve `DetectedUsers` alanlarıyla zenginleştirildi. Ayrıca `GET /api/v1/screenshots/{id}/inspect` REST uç noktası eklendi.
- [x] **6.2 Frontend (Lightbox Inspector):** `gallery.html` lightbox önizlemesine "🔍 Toggle OCR & Keywords" katmanı, hassas anahtar kelimeler ve hesap listesi detay paneli eklendi.
- [x] **6.3 Hassas Veri Rozetleri:** Galeride yönetici oturumu veya hassas sunucu tespit edilen ekranlara dikkat çekici `Sensitive UI` ve etiket rozetleri eklendi.
- [x] **6.4 Doğrulama:** `api_test.go:TestInspectScreenshotAPI` birim testi ile OCR koordinatları ve etiket tespiti doğrulandı.

---

### Faz 7: Canlı Olay Terminali ve Kritik Bulgu Animasyonları (Live Pulse, Audio Alerts & Filterable Terminal)
Tarama esnasında arka planda açık bırakıldığında kritik bulgu veya geçerli kimlik tespit edildiğinde analisti uyaran canlı kontrol merkezi.

- [x] **7.1 Dashboard Canlı Terminal:** `dashboard.html` üzerindeki canlı log alanına seviye filtreleri (`All`, `Critical`, `Credentials`, `Screenshots`) ve anlık arama kutusu eklendi.
- [x] **7.2 Görsel Efekt (Critical Pulse):** Kritik bulgu (BlueKeep) veya geçerli kimlik (`cmk` doğrulandı) SSE üzerinden geldiğinde ekran başlığında ve terminal kartında yanıp sönen `pulse-critical` / `pulse-success` CSS animasyonları eklendi.
- [x] **7.3 İsteğe Bağlı Sesli Uyarı (Audio Chime):** Kullanıcı onaylı toggle butonu (`🔔 Alerts ON/OFF`) ile Web Audio API tabanlı, harici ses dosyası gerektirmeyen çift tonlu kritik uyarı ve başarı melodisi sentezlendi.
- [x] **7.4 Doğrulama:** SSE event akışı üzerinden pulse tetikleyicileri ve ses fonksiyonları test edildi.

---

## Geliştirme Günlüğü (Changelog)

### [2026-10-31] — Faz 1 - 7 Eksiksiz Olarak Tamamlandı
- **Faz 1:** `internal/server/connect_rdp.go` modülü yazıldı. `scan_detail.html` ve `estate.html` sayfalarına `.rdp` indirme ve `rdp://` URI bağlantıları eklendi.
- **Faz 2:** `internal/playbook/playbooks.go` genişletilerek PowerShell, Registry (.reg), Ansible ve Bash düzeltme kodları tanımlandı. `/api/v1/playbooks/{id}/script` uç noktası yazıldı. Arayüze sekmeli kod paneli ve panoya kopyalama entegre edildi.
- **Faz 3:** `internal/score/score.go` içerisine `EvaluateCompliancePosture` eklenerek CIS, PCI-DSS, NIST ve ISO-27001 uyumluluk hesaplama motoru oluşturuldu. `/api/v1/scans/{id}/compliance-posture` endpoint'i yazıldı. `scan_detail.html`, `reports.html` ve `compare.html` şablonlarına Chart.js Radar grafikleri eklendi.
- **Faz 4:** `scan_detail.html` üzerinde 4 sütunlu (Open, Confirmed, False Positive, Remediated) HTML5 Drag & Drop destekli Kanban panosu ve canlı triage güncellemesi kodlandı.
- **Faz 5:** `internal/estate/estate.go` içerisine `BuildBlastRadius` algoritması yazıldı. `/api/v1/estate/blast-radius` endpoint'i ve `/estate` sayfasında konsantrik SVG Saldırı Yolu Topoloji grafiği geliştirildi.
- **Faz 6:** `GalleryItem` hassas veri etiketleriyle donatıldı. `/api/v1/screenshots/{id}/inspect` uç noktası ve `gallery.html` üzerinde görsel OCR katmanı ve rozetler kodlandı.
- **Faz 7:** `dashboard.html` canlı terminaline filtreleme ve arama eklendi. Web Audio API ile harici dosyasız sentezlenen sesli uyarı (`🔔 Audio Alerts`) ve CSS `pulse-critical` / `pulse-success` görsel efektleri eklendi.
- **Test ve Derleme:** Tüm paketlerin testleri (`go test ./...`) eksiksiz geçti ve `bin/rdpshot` başarıyla derlendi.
