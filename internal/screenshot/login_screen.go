package screenshot

import (
	"context"
	"fmt"
	"image"
	"image/png"
	"os"
	"path/filepath"
	"strings"
	"time"

	"rdpshot/internal/model"
)

// LoginScreenLabel is the screenshot username token for pre-auth Winlogon captures.
const LoginScreenLabel = "rdp-login"

// loginScreenDummyUser is offered to FreeRDP so it opens an X11 window without
// prompting for an interactive username. An empty password keeps the session
// on the Winlogon UI (no verified desktop).
const loginScreenDummyUser = "rdpshot"

// LoginScreenGrabber captures the Windows logon UI without verified credentials.
type LoginScreenGrabber interface {
	Available() error
	GrabLoginScreen(ctx context.Context, ep model.Endpoint) (model.Screenshot, error)
}

// GrabLoginScreen opens an unauthenticated TLS RDP session (/sec:tls), waits for
// the Winlogon UI, and captures the FreeRDP X11 window (falling back to root).
func (g *XFreeRDPGrabber) GrabLoginScreen(ctx context.Context, ep model.Endpoint) (model.Screenshot, error) {
	var shot model.Screenshot
	if err := g.Available(); err != nil {
		return shot, err
	}
	if err := os.MkdirAll(g.OutputDir, 0o700); err != nil {
		return shot, fmt.Errorf("screenshot: create output directory: %w", err)
	}

	now := time.Now().UTC()
	name := FileName(ep, LoginScreenLabel, now)
	outPath := filepath.Join(g.OutputDir, name)
	waitSeconds := g.WaitSeconds
	if waitSeconds < 10 {
		// Winlogon tiles need longer than an authenticated desktop paint.
		waitSeconds = 10
	}

	args := []string{"-a", "-s", "-screen 0 1024x768x24", "sh", "-c", loginScreenScript}
	env := append(os.Environ(),
		"RDSHOT_HOST="+ep.Address,
		fmt.Sprintf("RDSHOT_PORT=%d", ep.Port),
		"RDSHOT_USER="+loginScreenDummyUser,
		"RDSHOT_OUT="+outPath,
		fmt.Sprintf("RDSHOT_WAIT=%d", waitSeconds),
	)
	output, err := g.run(ctx, "xvfb-run", args, env, "")
	if err != nil {
		detail := strings.TrimSpace(string(output))
		if len(detail) > 300 {
			detail = detail[:300]
		}
		return shot, fmt.Errorf("screenshot: login-screen capture failed: %w (%s)", err, detail)
	}

	info, err := os.Stat(outPath)
	if err != nil {
		return shot, fmt.Errorf("screenshot: login-screen produced no image: %w", err)
	}
	if info.Size() == 0 {
		return shot, fmt.Errorf("screenshot: login-screen produced an empty image at %q", outPath)
	}
	w, h, blank, err := inspectCapturePNG(outPath)
	if err != nil {
		return shot, fmt.Errorf("screenshot: login-screen image unreadable: %w", err)
	}
	if blank {
		os.Remove(outPath)
		return shot, fmt.Errorf("screenshot: login-screen capture was blank (black frame)")
	}

	return model.Screenshot{
		Address:    ep.Address,
		Port:       ep.Port,
		Username:   LoginScreenLabel,
		FilePath:   outPath,
		Width:      w,
		Height:     h,
		CapturedAt: now,
	}, nil
}

// loginScreenScript forces TLS security (no CredSSP). A non-empty dummy
// username is required: FreeRDP 3 with an empty /u: prompts on stdin and never
// maps an X11 window under xvfb-run. That dummy often lands Winlogon on the
// "Other user" form with the tooling name pre-filled — after the window maps we
// Escape back toward the account-tile list and clear the username field so the
// PNG is not polluted. Hosts that answer HYBRID_REQUIRED_BY_SERVER cannot expose
// Winlogon without credentials — fail fast instead of a black frame.
const loginScreenScript = `
set -eu
log=$(mktemp)
trap 'rm -f "$log"; kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true' EXIT
xfreerdp /v:"$RDSHOT_HOST:$RDSHOT_PORT" /u:"$RDSHOT_USER" /p: /sec:tls \
  /cert:ignore /size:1024x768 /bpp:16 /network:lan >"$log" 2>&1 &
pid=$!
deadline=$((RDSHOT_WAIT + 5))
i=0
have_window=0
while [ "$i" -lt "$deadline" ]; do
  i=$((i + 1))
  if grep -q 'HYBRID_REQUIRED_BY_SERVER\|ERRCONNECT_HYBRID_REQUIRED' "$log" 2>/dev/null; then
    echo "server requires CredSSP/NLA (HYBRID); pre-auth login UI unreachable" >&2
    exit 4
  fi
  if ! kill -0 "$pid" 2>/dev/null; then
    # FreeRDP exited before mapping a window — surface the nego error.
    if grep -q 'HYBRID_REQUIRED_BY_SERVER\|ERRCONNECT_HYBRID_REQUIRED' "$log" 2>/dev/null; then
      echo "server requires CredSSP/NLA (HYBRID); pre-auth login UI unreachable" >&2
      exit 4
    fi
    echo "freerdp exited before login UI" >&2
    tail -n 20 "$log" >&2 || true
    exit 5
  fi
  if xwininfo -root -tree 2>/dev/null | grep -q 'FreeRDP'; then
    have_window=1
    break
  fi
  sleep 1
done
if [ "$have_window" -ne 1 ]; then
  echo "freerdp window never appeared" >&2
  tail -n 20 "$log" >&2 || true
  exit 5
fi
# Let Winlogon paint, then leave the dummy-user "Other user" form when possible.
sleep 2
wid=""
if command -v xdotool >/dev/null 2>&1; then
  wid=$(xdotool search --name "FreeRDP" 2>/dev/null | head -n1 || true)
fi
if [ -z "$wid" ]; then
  wid=$(xwininfo -root -tree 2>/dev/null | awk '/FreeRDP/{print $1; exit}' || true)
fi
if command -v xdotool >/dev/null 2>&1 && [ -n "$wid" ]; then
  xdotool windowactivate --sync "$wid" 2>/dev/null || true
  # Escape typically returns from Other-user credential entry to the tile list.
  xdotool key --window "$wid" Escape 2>/dev/null || true
  sleep 1
  xdotool key --window "$wid" Escape 2>/dev/null || true
  sleep 1
  # If still on Other user, clear the pre-filled dummy username so it is not
  # baked into evidence. Harmless on the tile list (no focused text field).
  xdotool windowactivate --sync "$wid" 2>/dev/null || true
  xdotool key --window "$wid" ctrl+a 2>/dev/null || true
  xdotool key --window "$wid" BackSpace 2>/dev/null || true
  sleep 1
fi
# Remaining settle time for tile animation after dismiss/clear.
settle=$((RDSHOT_WAIT - 5))
if [ "$settle" -lt 3 ]; then
  settle=3
fi
sleep "$settle"
if command -v import >/dev/null 2>&1; then
  if [ -n "$wid" ]; then
    import -window "$wid" "$RDSHOT_OUT"
  else
    import -window root "$RDSHOT_OUT"
  fi
elif command -v ffmpeg >/dev/null 2>&1; then
  ffmpeg -loglevel error -f x11grab -video_size 1024x768 -i "${DISPLAY:-:99}" -frames:v 1 "$RDSHOT_OUT"
else
  echo "no capture tool available" >&2
  exit 3
fi
`

// inspectCapturePNG reports dimensions and whether the frame is nearly blank.
func inspectCapturePNG(path string) (width, height int, blank bool, err error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, 0, false, err
	}
	defer f.Close()
	img, err := png.Decode(f)
	if err != nil {
		return 0, 0, false, err
	}
	b := img.Bounds()
	width, height = b.Dx(), b.Dy()
	if width == 0 || height == 0 {
		return width, height, true, nil
	}
	return width, height, isNearlyBlankImage(img), nil
}

func isNearlyBlankImage(img image.Image) bool {
	b := img.Bounds()
	total := b.Dx() * b.Dy()
	if total == 0 {
		return true
	}
	// Sparse sample grid — enough to reject solid black Xvfb roots quickly.
	stepX := b.Dx() / 32
	if stepX < 1 {
		stepX = 1
	}
	stepY := b.Dy() / 24
	if stepY < 1 {
		stepY = 1
	}
	lit := 0
	samples := 0
	for y := b.Min.Y; y < b.Max.Y; y += stepY {
		for x := b.Min.X; x < b.Max.X; x += stepX {
			samples++
			r, g, bl, _ := img.At(x, y).RGBA()
			// 16-bit channels; treat near-black as unpainted.
			if r > 0x1800 || g > 0x1800 || bl > 0x1800 {
				lit++
			}
		}
	}
	if samples == 0 {
		return true
	}
	return float64(lit)/float64(samples) < 0.02
}
