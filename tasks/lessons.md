# Lessons

## Scope

- Stay inside the current workspace (`rdpshot`). Never read, write, copy from, or point config at sibling projects (e.g. `cumo`) even if a process cwd or PNG path led there.
- If evidence appears to live elsewhere, treat that as a misconfigured serve cwd/outputs — fix paths inside this repo; do not operate on the other project.
- Prefer absolute `--db` / `--outputs` under this project so relative cwd cannot attach to another tree.

## CSP / UI

- Do not put page logic in inline `<script>` blocks that contain `//` comments: `html/template` strips those comments, CSP sha256 hashes from template source no longer match, and the browser silently blocks the script (UI stuck on "Loading…").
- Prefer `/static/js/app.js` for interactive pages (gallery, estate map, etc.).

## Login-screen capture

- FreeRDP 3 needs a non-empty `/u:` under xvfb or it never maps a window; that dummy lands on Winlogon’s “Other user” form. After the window appears, Escape + clear the field before `import`, or evidence shows `rdpshot` / `HOST\rdpshot`.
- HYBRID_REQUIRED_BY_SERVER means pre-auth Winlogon is unreachable — fail fast to the detection card; do not wait for a black Xvfb frame.
- Tesseract needs a bottom-left tile crop + upscale + contrast (PSM 11). A full-height left strip of wallpaper OCR’s as noise and misses Yasemin/eda.
- Never persist raw OCR tokens: reject hostnames (`KUBI-HYP-*`), dummy/`dpshot` crumbs, Capitalized 3-letter noise (`Pee`), and “Other user” alone (credential form without tiles). Only store real tile names (+ Other user when tiles exist).
- Do not fall back to synthetic `rdp-open` detection PNG cards for the gallery. If FreeRDP cannot reach Winlogon (HYBRID/NLA), skip the screenshot entirely.
- CredSSP password audits require NLA (`NLARequired`); skip them on TLS/RDP-only hosts. Login-screen capture must still *try* FreeRDP `/sec:tls` even when gather selected HYBRID — many hosts accept forced TLS Winlogon. Only the grabber fail-fast (HYBRID_REQUIRED / blank frame) should suppress the shot, not an NLARequired early return.
- Persist `login_screen=skipped` + `login_screen_skip_reason` when FreeRDP cannot reach Winlogon so the UI can show “NLA blocks tiles” instead of a bare dash.
- CredSSP against modern Windows (HYBRID_EX / TLS 1.2+): send `clientNonce` on the *first* TSRequest (v5+); advertise `NEGOTIATE_KEY_EXCH` and populate `EncryptedRandomSessionKey`; send AUTHENTICATE as bare NTLMSSP (FreeRDP “direct NTLM”); enrich target info with zeroed `MsvAvChannelBindings` + `TERMSRV/<target>` before the NTLMv2 proof. Omitting the early nonce yields `tls: internal_error`; omitting KEY_EXCH / bindings often yields `SEC_E_INVALID_TOKEN` (0x80090308).
- NTLM Seal for CredSSP is `Version||Checksum||Seq||RC4(msg)` with MD5(exported||magic) keys — not HMAC-MD5 and not RC4 over the whole signature. With KEY_EXCH, RC4 the message first, then the 8-byte checksum on the same handle (FreeRDP EncryptMessage).
- Pin TLS 1.2 (`MaxVersion` too): TLS 1.3 CredSSP often stalls after AUTHENTICATE/pubKeyAuth.
- FreeRDP `/from-stdin` under xvfb: empty domain must become `/d:.` (set-but-empty env breaks `:-` defaults); read password then `printf '%s\n' | xfreerdp` (background `&` drops stdin; `$(cat)` strips the newline). Reject blank captures; settle ≥6s after the window maps; retry once on blank. When FreeRDP tooling exists, do not store the evidence card as a “screenshot” — return an error instead.
- `rdpshot serve` often runs from `/usr/local/rdpshot` as root; source fixes are invisible until `sudo ./install.sh --force` and a serve restart.
- Aggressive lab CredSSP probing can knock a fragile VM offline (`no route to host`); gate live tests behind `RDPSHOT_LIVE=1`.
