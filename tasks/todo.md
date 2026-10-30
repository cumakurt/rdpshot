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

## Review

- CredSSP `HandshakeSession` sends TSCredentials; verify-only `Handshake` unchanged.
- `rdp.Capture` runs MCS → Client Info → License → Confirm Active → bitmap/orders (slow + fast path).
- AutoGrabber: FreeRDP → Go framebuffer → evidence card.
- Kerberos without a usable ccache stays NTLM; smart-card is discovery-only (no PIN UI).
- Default `--max-concurrent-scans=2`; excess scans remain `pending` until a slot frees.

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
