# UI screenshots

Sample web-console captures used by the project [`README.md`](../../README.md).

These images come from an **authorized lab** session against private
(RFC1918) RDP hosts. They are illustrative only — not production customer
data.

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

## Regenerating

With `rdpshot serve` listening on `127.0.0.1:8722` and Chromium installed:

```bash
OUT=docs/screenshots
chromium --headless=new --disable-gpu --hide-scrollbars --window-size=1440,900 \
  --screenshot="$OUT/dashboard.png" http://127.0.0.1:8722/
# repeat for /scans /gallery /reports /schedules /estate /engagements /compare
# then convert to JPEG (README prefers JPG; *.png is gitignored):
python3 - <<'PY'
from pathlib import Path
from PIL import Image
out = Path('docs/screenshots')
for p in out.glob('*.png'):
    im = Image.open(p).convert('RGB')
    w, h = im.size
    if w > 1280:
        im = im.resize((1280, int(h * 1280 / w)), Image.Resampling.LANCZOS)
    im.save(p.with_suffix('.jpg'), 'JPEG', quality=82, optimize=True)
    p.unlink()
PY
```
