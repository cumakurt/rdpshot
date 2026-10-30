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
