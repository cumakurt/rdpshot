# Proje Planı: rdpshot (Enterprise Gelişmiş RDP Keşif, Zafiyet ve Denetim Platformu)

## 1. Proje Vizyonu ve Mimari Hedefler
**rdpshot**, ağ altyapılarındaki Remote Desktop Protocol (RDP) servislerini güvenli, hızlı ve kapsamlı bir şekilde denetlemek için tasarlanmış kurumsal sınıf bir sızma testi ve zafiyet analiz aracıdır. Go dilinin eşzamanlılık gücüyle donatılmış olan sistem; hem komut satırı (CLI) üzerinden otomasyona uygun hem de modern bir Web Arayüzü (GUI) ile operasyonel yönetim sunar.

### Temel Yetenekler:
*   **Gelişmiş Hedef Yönetimi:** Tekil IP, CIDR blokları, dinamik port aralıkları ve harici dosyalardan (`txt`, `csv`) hedef okuma.
*   **Adaptif Hız Sınırlandırma (Rate Limiting):** Hedef sistemlerdeki kilitlenme (account lockout) mekanizmalarını ve güvenlik duvarı bloklarını önlemek için token-bucket tabanlı dinamik gecikme.
*   **Kalıcı Veri Yönetimi (Database):** Tüm tarama sonuçlarının, bulunan kimlik bilgniklerinin, zafiyetlerin ve ekran görüntüleri meta verilerinin SQLite / BoltDB üzerinde saklanması.
*   **Görsel Doğrulama ve Oturum Analizi:** Başarılı kimlik doğrulama sonrası RDP grafik kanalı üzerinden anlık ekran görüntüsü alma ve aktif oturum açmış kullanıcıları listeleme.
*   **Kapsamlı Zafiyet Tespiti:** BlueKeep (`CVE-2019-0708`), DejaBlue (`CVE-2019-1181/1182`), zayıf şifreleme ve NLA yapılandırma hatalarının tespiti.
*   **Çoklu Raporlama Formatı:** HTML, CSV ve PDF formatlarında otomatik, şık ve detaylı rapor üretimi.

---

## 2. Genişletilmiş Teknoloji ve Kütüphane Yığını

*   **Dil:** Go (Golang) — *Yüksek performans, düşük bellek ve güçlü eşzamanlılık.*
*   **Web Framework (GUI & API):** Fiber (Go web framework) — *Hızlı HTTP yönlendirmesi ve kolay WebSocket entegrasyonu.*
*   **Arayüz Teknolojileri:** TailwindCSS, HTMX ve Chart.js — *Hafif ve modern bir kullanıcı deneyimi için.*
*   **Veritabanı:** `mattn/go-sqlite3` veya saf Go tabanlı `modernc.org/sqlite` — *Gömülü (embedded) ve taşınabilir veri saklama.*
*   **Raporlama:**
    *   HTML: `html/template` (Dahili şablon motoru)
    *   PDF: `jung-kurt/gofpdf` veya `go-pdf/fpdf`
*   **Loglama ve Yapılandırma:** `uber-go/zap` (Yapılandırılmış loglama) ve `spf13/viper` (Konfigürasyon yönetimi).

---

## 3. Modüler Mimari Bileşenleri

### A. Target & Scope Manager (`/internal/target`)
*   IP, Hostname ve CIDR çözme.
*   Özel port listesi tanımlama (Varsayılan: `3389`).
*   Blacklist desteği (Taranmayacak hassas IP/Ağların hariç tutulması).

### B. Recon & Fingerprinting Engine (`/internal/scanner`)
*   TCP port açık/kapalı kontrolü.
*   RDP Transport Layer (COTP/X224) el sıkışma analizi.
*   NLA (Network Level Authentication) ve SSL/TLS sertifika analizi (Self-signed, geçerlilik süresi, kullanılan cipher suite'ler).

### C. Vulnerability Scanner (`/internal/vuln`)
*   **CVE-2019-0708 (BlueKeep):** Uzaktan Kod Çalıştırma (RCE) zafiyeti için güvenli kanal müzakere testi.
*   **CVE-2019-1181 / CVE-2019-1182 (DejaBlue):** İlgili RDS zafiyet imzalarının tespiti.
*   **Misconfiguration Checks:** Zayıf şifreleme protokolleri ve NLA zorunluluğunun olmaması.

### D. Credential & Brute-Force Engine (`/internal/brute`)
*   Worker Pool mimarisi ile paralel kimlik doğrulama testleri.
*   Dahili default wordlistler ve özel dosya yükleme desteği.
*   **Akıllı Durdurma:** Hedef başına maksimum başarısız deneme sınırı (Fail-safe).

### E. Session & Screenshot Grabber (`/internal/screenshot`)
*   Başarılı girişler sonrasında RDP grafik oturumuna geçiş.
*   Ekran görüntüsünün alınması ve `/outputs/screenshots/` dizinine `.png` olarak kaydedilmesi.
*   Aktif bağlı kullanıcı adlarının oturum katmanından okunması.

### F. Reporting Engine (`/internal/reporter`)
*   **HTML Raporu:** Grafiksel özetler, zafiyet seviyeleri (Critical, High, Medium, Low) ve ekran görüntüsü önizlemeleri.
*   **CSV Raporu:** SIEM entegrasyonları için satır bazlı ham veri dökümü.
*   **PDF Raporu:** Yönetici özetleri içeren profesyonel kurumsal rapor.

---

## 4. Web API ve WebSocket Uç Noktaları (REST API Specs)

*   `POST /api/v1/scans` — Yeni bir tarama görevi başlatır.
*   `GET /api/v1/scans` — Geçmiş taramaların listesini ve durumunu döndürür.
*   `GET /api/v1/scans/{id}` — Belirli bir taramanın detaylı sonuçlarını getirir.
*   `GET /api/v1/scans/{id}/report` — Belirtilen formatta (`html`, `csv`, `pdf`) rapor indirir.
*   `WS /ws/live` — Tarama ilerlemesini, canlı logları ve bulunan bulguları anlık olarak arayüze aktaran WebSocket kanalı.

---

## 5. Proje Dizin Yapısı

```text
rdpshot/
├── cmd/
│   ├── cli/
│   │   └── main.go
│   └── web/
│       └── main.go
├── internal/
│   ├── config/
│   ├── database/
│   ├── scanner/
│   ├── vuln/
│   ├── rdp/
│   ├── brute/
│   ├── screenshot/
│   ├── reporter/
│   └── api/
├── web/
│   ├── static/
│   │   ├── css/
│   │   └── js/
│   └── templates/
│       ├── dashboard.html
│       ├── scans.html
│       └── report_template.html
├── wordlists/
│   ├── default_users.txt
│   └── default_passwords.txt
├── outputs/
│   ├── reports/
│   └── screenshots/
├── Dockerfile
├── docker-compose.yml
├── go.mod
├── go.sum
└── plan.md




1. Ana Kontrol Paneli (Dashboard & Command Center) Promptu

Bu promptu arayüzün ana ekranını (Dashboard) tasarlamak için kullanabilirsiniz. Amaç; "Cyberpunk/Sleek Dark Mode" konseptinde, koyu tonlar, neon yeşil/mavi aksanlar ve kart bazlı modern bir yerleşim elde etmektir.

    Prompt:
    "Go-rdpshot adlı siber güvenlik aracım için TailwindCSS ve HTML kullanan modern, minimalist ama profesyonel bir Dashboard (Kontrol Paneli) arayüzü tasarla. Tasarım dili 'Cyber-Command Center' tarzında olmalı; koyu tema (Slate-950 arkaplan, Slate-900 kartlar), neon mavi (indigo-500) ve zümrüt yeşili (emerald-500) vurgu renkleri içermelidir.

    Sayfada şunlar yer almalı:

        Üst kısımda sistem durumunu gösteren özet kartları (Toplam Taranan Hedef, Aktif Zafiyetler, Başarılı Girişler, Alınan Ekran Görüntüleri). Bu kartlarda ikonlar ve canlı sayaçlar olsun.

        Sol tarafta hızlı tarama başlatma formu (Hedef IP/CIDR inputu, port seçimi, Wordlist seçme dropdown'ı ve şık bir 'Start Scan' butonu).

        Sağ tarafta ise gerçek zamanlı tarama ilerlemesini gösteren canlı bir terminal/log penceresi (Monospace font, koyu yeşil/beyaz yazılar).

        Tablolar ve kartlar hafif border'lara ve hover efektlerine sahip olsun. Kodları temiz, modüler ve responsive (mobil uyumlu) yaz."

2. Canlı Tarama ve İlerleme Ekranı (Live Scan & Progress) Promptu

Tarama çalışırken kullanıcının süreci görsel olarak takip edebilmesi, aktif thread'leri ve yüzde kaç bittiğini görebilmesi için.

    Prompt:
    "Go-rdpshot için bir tarama ilerleme ve canlı izleme ekranı (Live Scan View) kodla. Teknolojiler: TailwindCSS ve HTMX (veya Alpine.js).

    Tasarım öğeleri:

        Şık ve animasyonlu bir dairesel veya yatay Progress Bar (İlerleme Çubuğu). Yüzde ve geçen süre (Elapsed Time) dinamik görünmeli.

        'Anlık Aktif Workerlar' ve 'Bulunan Zafiyetler' için yan yana iki modern sekme veya grid alanı.

        Bulunan zafiyetlerin listelendiği şık bir tablo: Her satırda Hedef IP, Port, Tespit Edilen Zafiyet (örn: BlueKeep - Kırmızı Badge), NLA Durumu ve 'Detay Gör' butonu yer almalı.

        Tablo satırlarına tıklandığında veya hover yapıldığında hafif bir parlama efekti (glow effect) olmalı. Profesyonel bir SOC analistinin ekranı gibi hissettirmeli."

3. Ekran Görüntüsü ve Oturum Galerisi (Screenshot & Session Vault) Promptu

Başarılı giriş yapılan veya aktif oturum içeren hedeflerin ekran görüntülerinin sergileneceği modern galeri ekranı için.

    Prompt:
    "Go-rdpshot aracı için yakalanan RDP ekran görüntülerini ve aktif kullanıcı oturumlarını gösteren bir 'Visual Session Gallery' arayüzü tasarla (TailwindCSS).

    Tasarım detayları:

        Grid yapısında (responsive 3 veya 4 kolonlu) kartlar.

        Her kartın üst kısmında RDP ekran görüntüsünün yüksek kaliteli önizlemesi (Thumbnail). Üzerine gelindiğinde (hover) hafifçe büyüme (zoom-in) efekti ve 'Tam Ekran İncele' butonu çıkmalı.

        Kartın alt kısmında: Hedef IP, tespit edilen aktif kullanıcı adı (örn: Administrator), işletim sistemi tahmini ve ekran görüntüsünün alındığı zaman damgası net bir şekilde okunmalı.

        Üst kısımda IP'ye göre arama yapma ve kullanıcı adına göre filtreleme yapabilen modern, yuvarlak köşeli bir arama çubuğu (Search Bar) bulunsun."

4. Zafiyet Analizi ve Raporlama Ekranı (Vulnerability & Reporting Hub) Promptu

Bulunan zafiyetlerin (BlueKeep vb.) risk seviyelerine göre ayrıldığı ve PDF/HTML raporların tek tıkla indirildiği şık bir yönetim paneli.

    Prompt:
    "Go-rdpshot için 'Vulnerability Analysis & Automated Reporting' ekranı tasarla (TailwindCSS + Chart.js entegrasyonuna uygun alanlar).

    Tasarım öğeleri:

        Sol tarafta risk dağılımını gösteren şık bir pasta grafik (Pie Chart) alanı (Kritik - Kırmızı, Yüksek - Turuncu, Orta - Sarı, Düşük - Mavi).

        Sağ tarafta tespit edilen tüm CVE'lerin (örn: CVE-2019-0708 BlueKeep) detaylı listesi; zafiyet açıklaması, etkilenen host sayısı ve çözüm önerileri (Remediation).

        Sayfanın en üst veya en sağ köşesinde, kullanıcıların tek tıkla 'Export as PDF', 'Export as HTML' ve 'Export as CSV' yapabileceği, ikonlu, modern degrade (gradient) renkli indirme butonları.

        Butonlara tıklandığında şık bir yüklenme animasyonu (spinner) belirmeli. Arayüz son derece akıcı ve kurumsal görünmeli."

Tasarımın "Modern, Estetik, Benzersiz ve Kolay" Olması İçin Altın Kurallar (İpuçları):

    Renk Paleti: Klasik beyaz/gri kurumsal temalar yerine Tailwind Slate (Slate-900 / Zinc-900) koyu arkaplan, neon vurgular (indigo, emerald, rose) kullanın. Bu, araçlara profesyonel "Hacker/Cybersecurity" havası katar.

    Mikro Etkileşimler (Micro-interactions): Butonlara basıldığında küçülme (active:scale-95), kartlara hover yapıldığında hafif gölge artışı (hover:shadow-indigo-500/10) ekleyin.

    Boşluk (Whitespace): Bilgileri boğmamak için p-6 veya gap-6 gibi geniş boşluklar bırakın; okunabilirliği artırır.
