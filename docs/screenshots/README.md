# UI screenshots

Sample web-console captures used by the project [`README.md`](../../README.md).

These images come from an **authorized lab** session against private
(RFC1918) RDP hosts plus one local honeypot listener (`127.0.0.1`). They are
illustrative only — not production customer data.

| File | Page |
|---|---|
| `dashboard.jpg` | `/` Command Center |
| `scans.jpg` | `/scans` Scans Dashboard |
| `scan_detail.jpg` | `/scans/{id}` scan detail |
| `gallery.jpg` | `/gallery` Visual Session Vault |
| `reports.jpg` | `/reports` reporting hub |
| `schedules.jpg` | `/schedules` with first-run date/time picker |
| `estate.jpg` | `/estate` risk map |
| `engagements.jpg` | `/engagements` workspace |
| `compare.jpg` | `/compare` scan diff |
| `mitre.jpg` | `/mitre` MITRE ATT&CK heatmap |
| `decoy.jpg` | `/decoy` honeypot listener |

## Regenerating

With `rdpshot serve` listening on `127.0.0.1:8722` and Chromium installed,
capture each page at 1440 px width. Pages are captured at the listed viewport
height so the important content (charts, tables) fits without a full-page
stitch, which breaks sticky headers and lazily rendered Chart.js canvases:

```bash
OUT=docs/screenshots
capture() { # <path> <name> <height>
  chromium --headless=new --disable-gpu --hide-scrollbars --no-sandbox \
    --window-size=1440,"$3" --virtual-time-budget=6000 \
    --screenshot="$OUT/$2.png" "http://127.0.0.1:8722$1"
}
capture /               dashboard   900
capture /scans          scans      1500
capture /scans/SCAN_ID  scan_detail 1700
capture /gallery        gallery     900
capture /reports        reports    1400
capture /schedules      schedules  1560
capture /estate         estate     1600
capture /engagements    engagements 1350
capture '/compare?base=BASE_ID&against=AGAINST_ID' compare 1200
# /mitre needs "Load Heatmap" clicked (select a scan, then click the button)
capture /mitre          mitre      1250
capture /decoy          decoy      1201   # captured at 1920 px width
```

`/decoy` is captured at 1920 px width so all 13 event columns of the capture
table are legible.

Then convert to JPEG (README prefers JPG; `*.png` is gitignored):

```bash
python3 - <<'PY'
from pathlib import Path
from PIL import Image
out = Path('docs/screenshots')
for p in out.glob('*.png'):
    im = Image.open(p).convert('RGB')
    w, h = im.size
    if w > 1280:
        im = im.resize((1280, int(h * 1280 / w)), Image.Resampling.LANCZOS)
    im.save(p.with_suffix('.jpg'), 'JPEG', quality=84, optimize=True)
    p.unlink()
PY
```
