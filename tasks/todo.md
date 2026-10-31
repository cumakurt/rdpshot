# rdpshot — differentiating features

## Goal

Ship the audit-safe advanced capabilities that differentiate the product.
Out of scope: exploit/payload, LSASS/hash dump, lateral movement, C2, exfil.

## Checklist

- [x] Hardening / compliance score (API + reports UI)
- [x] Estate graph / risk map (`/estate`)
- [x] Client-trust / MitM posture checks
- [x] RD Gateway / RD Web / UDP 3389 discovery (detection)
- [x] Smart credential audit (priority + reuse)
- [x] Delta-driven retest
- [x] Policy-as-code
- [x] SIEM streaming (JSON/CEF)
- [x] Engagement workspace + evidence manifest hash
- [x] Pure-Go framebuffer (NLA + slow-path bitmap capture)
- [x] Tests, docs, README

## Next-wave (this pack)

- [x] Schema v4: host_notes, path/runtime options, MaxConcurrentScans, alerts
- [x] Fast-Path + PATBLT/SCRBLT/MEMBLT orders + fixture tests
- [x] CredSSP Kerberos offer when ccache present + findings
- [x] `/engagements` UI + nav wiring
- [x] `rdpshot policy check` CLI exit codes + README CI
- [x] Playbook catalog API + scan detail links
- [x] Concurrent scan queue + max runtime
- [x] Bulk triage API/UI + host notes
- [x] Logo/executive export, RBAC enforce, alert rules
- [x] Cert expiry panel, path posture, RD Gateway auth fingerprint

## Advanced auth (single / PTH)

- [x] `auth_mode` wordlist | single | pth on ScanOptions + loadCandidates
- [x] NTLM `ParseNTHash` / `BuildAuthenticateFromNTHash` + CredSSP hash path
- [x] CLI flags + API create/brute/schedule + secret redaction on GET
- [x] Dashboard / brute / schedules advanced auth panel
- [x] Tests + README
- [x] Shared advanced `auth_domain` for all modes (wordlist override via `DOMAIN\user`)
- [x] Single/PTH success → screenshot → immediate disconnect
- [x] Open RDP host → TLS pre-auth login-screen capture (FreeRDP /sec:tls) + OCR login_users; evidence card fallback; live desktop after verified login
- [x] Vuln catalog confirmation-first (BlueKeep only on confirmed MS_T120 DPUM; drop speculative DejaBlue/potential Critical)

## Enterprise Pack (v3: Faz 1 - 14)

- [x] Faz 1: Kurumsal Uyumluluk Standartları (CIS, PCI-DSS, NIST, ISO 27001)
- [x] Faz 2: Zayıf SSL/TLS ve Cipher Suite Güvenlik Denetimi
- [x] Faz 3: Harici Tarama Çıktısı İçe Aktarma (Nmap / Masscan)
- [x] Faz 4: MFA / PAM ve Güvenli Erişim Katmanı Tespiti
- [x] Faz 5: RDP UDP (MS-RDPEUDP / Port 3389 UDP) Keşif Denetimi
- [x] Faz 6: Gelişmiş Pass-the-Ticket (Kerberos / CCache) Desteği
- [x] Faz 7: Karşılaştırmalı Yönetici Özeti (Delta Comparison Executive PDF)
- [x] Faz 8: Web UI Tema Desteği (Dark / Light Theme Toggle)
- [x] Faz 9: RDP Honeypot & Deception Tespiti (Tuzak Sistem Analizi)
- [x] Faz 10: RDP Downgrade & MitM Saldırı Yüzeyi Denetimi
- [x] Faz 11: RDP Shadowing & Session Hijacking Posture Denetimi
- [x] Faz 12: Kurumsal SOAR & Webhook Bildirim Motoru (Slack, Teams, Discord, Webhook)
- [x] Faz 13: Active Directory / LDAP Hedef Keşif Motoru (Domain Auto-Discovery)
- [x] Faz 14: Saf Go RDPGFX (MS-RDPEGFX) Framebuffer

## Review

- CredSSP `HandshakeSession` sends TSCredentials; verify-only `Handshake` unchanged.
- `rdp.Capture` runs MCS → Client Info → License → Confirm Active → bitmap/orders (slow + fast path).
- AutoGrabber: FreeRDP (password `/from-stdin`, PTH `/pth`) → Go framebuffer → evidence card only if tooling missing.
- Kerberos without a usable ccache stays NTLM; smart-card is discovery-only (no PIN UI).
- Default `--max-concurrent-scans=2`; excess scans remain `pending` until a slot frees.

## Lab matrix 172.16.3.128 (2026-10-31)

- PASS: discovery, vuln (no false nla-not-required), auth±screens gate, single/wrong/domain/wordlist, reports html/csv/pdf, policy fail-by-design, API toggles.
- PASS: password+screens (~85KB real desktop).
- PASS: PTH auth without screens.
- LIMIT: PTH+screens — FreeRDP `/pth` connects (restricted admin) but desktop stays black on this host; blank rejected (no fake evidence card). Go MCS Capture still RST after CredSSP on this HYBRID host.

## Gallery fix (2026-10-30)

- [x] Rewrite gallery/scan screenshot paths via `screenshotViews` → `/files/screenshots/<base>`
- [x] Absolutize OutputsDir/DB on serve; ensure screenshots dir exists
- [x] Redeploy binary + restart with absolute `--db`/`--outputs` under this repo only

## Login-screen polish (2026-10-30)

- [x] After FreeRDP window maps: Escape back from Other-user + clear dummy `/u:rdpshot` so evidence is not polluted
- [x] OCR: bottom-left tile crop + 3× grayscale contrast + PSM 11 (recovers Yasemin/eda)
- [x] Stricter OCR junk / same-line crumb filtering
- [x] NLA HYBRID hosts remain detection-evidence only (correct; not a capture bug)

## Hosts list (2026-10-30)

- [x] Never show closed/filtered RDP endpoints in estate Hosts table/map or scan hosts API (open only)

## Login users OCR (2026-10-30)

- [x] Reject wallpaper/hostname/dummy crumbs; require real tile names (no Other-user-alone)
- [x] Backfill stored login_users via cmd/repair-login-users
- [x] Clear bogus rdp-login-users-exposed findings

## Gallery real frames only (2026-10-30)

- [x] Do not persist synthetic rdp-open detection evidence when Winlogon unreachable
- [x] Filter legacy rdp-open rows out of gallery/API screenshot views
- [x] Rescan confirmed: HYBRID hosts skip shot; TLS hosts keep rdp-login only

## Reports (2026-10-30)

- [x] Embed captured screenshots in HTML (data URI grid) and PDF (image pages)
- [x] Omit synthetic rdp-open cards from reports

## Auth fail-safe (2026-10-30)

- [x] max_auth_failures: default 5; 0 disables lockout limit (CLI + web + schedules + brute API)

## P0 + core P1 (2026-10-30)

- [x] Auth observability: Attempts/Failures/StoppedReason on ServiceInfo + scan log
- [x] CredSSP gate: skip password audit when !NLARequired; map ErrNLARequired → ErrCredSSPUnavailable
- [x] Schema v5 `auth_attempts` timeline (no secrets) + scan detail UI
- [x] OCR LoginUsersResult quality gate + `login_users_quality` evidence
- [x] Scan-wide OCR → wordlist prepend for NLA hosts
- [x] Executive one-pager: NLA %, auth audited/skipped cards (HTML/PDF)
- [x] Compare burn-down: FindingsRemediated + HardeningScoreDelta
- [x] `go test ./...` green

### Review

- TLS/RDP hosts: login-screen OCR + auth skip (`auth_path=skipped_no_credssp`); no candidate burn.
- HYBRID hosts: CredSSP audit + attempt timeline; login-screen capture skipped while NLA required.
- Deferred (still): extra Go GFX / RDPGFX orders.

## Next wave continued (2026-10-30)

- [x] SLA alerts: on_high, min_hardening_score, on_open_triage_critical (+ UI)
- [x] Evidence pack v2: hosts/findings/auth_attempts/score JSON, PACK_README, filter rdp-open
- [x] Kerberos Probe Status (kind/path) + nla-kerberos-offered capability finding
- [x] `go test ./...` for this wave

## Screenshot regression fix (2026-10-30)

- [x] Root cause: `captureOpenHostEvidence` early-returned on `NLARequired`, skipping FreeRDP `/sec:tls` Winlogon on HYBRID_EX hosts that still accept forced TLS
- [x] Removed NLARequired gate; grabber fail-fast remains
- [x] Live verify: `192.168.42.0/24` + `192.168.112.0/24` (+ known 52.x) → open=3 screens=3 (incl. 112.76 with Yasemin/eda)

## Orphan hosts after delete (2026-10-30)

- [x] Root cause: deleted scans left `hosts` rows; dashboard counted all hosts
- [x] DeleteScan also clears `auth_attempts`; wait for engine stop before delete
- [x] PurgeOrphanScanChildren on DB open + after delete; Summary joins existing scans only

## Scans Dashboard (2026-10-30)

- [x] `/scans` upgraded to Scans Dashboard (KPI cards, active jobs, filtered inventory)
- [x] Nav label + Command Center link updated
- [x] Client status/search filters in `app.js`
- [x] `buildScansDashboard` unit + template render tests

## Reports export scan selector (2026-10-30)

- [x] `/reports` scan dropdown: All + each scan
- [x] `GET /api/v1/reports/export?format=&scan=id|all`
- [x] Keep on-disk screenshot paths in reportData (fix web URL rewrite that broke embeds)
- [x] PDF/HTML embed captures; CSV adds `SCREENSHOT` rows with base64 image
- [x] Tests: reporter CSV + server export selector; live verify on :8722

## NLA host 172.16.3.128 analysis (2026-10-31)

- [x] Confirmed HYBRID_EX + TLS-only `HYBRID_REQUIRED_BY_SERVER` (no pre-auth tiles/OCR)
- [x] Scan verify: login-screen skip message; FreeRDP NLA logon previously OK for `cmk`
- [x] CredSSP hardening: early `clientNonce`, `KEY_EXCH`, bare NTLM AUTHENTICATE, CredSSP target-info enrich
- [x] UX: `login_screen_skip_reason` evidence + scan detail “NLA blocks tiles”
- [x] Live re-auth+desktop screenshot after VM recovers (`RDPSHOT_LIVE=1`)
- [x] CredSSP Seal: MD5 key derivation + KEY_EXCH wire (version/seq plaintext)
- [x] Pin TLS 1.2 for CredSSP auth/capture
- [x] FreeRDP grabber: `/sec:nla`, `/d:.`, stdin password pipe, reject blank frames
