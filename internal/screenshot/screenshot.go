// Package screenshot captures remote desktop session images after a
// successful credential check. Prefer AutoGrabber: it uses FreeRDP under a
// headless X server when available, otherwise a pure-Go session-evidence PNG.
package screenshot

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"rdpshot/internal/model"
)

// ErrGrabberUnavailable means the host lacks the external capture tooling.
var ErrGrabberUnavailable = errors.New("screenshot: capture tooling unavailable")

// Grabber captures one session image for an authenticated endpoint.
type Grabber interface {
	// Available reports whether the capture tooling is installed.
	Available() error
	// Grab captures the session and returns the stored image metadata.
	Grab(ctx context.Context, ep model.Endpoint, cred model.Credential) (model.Screenshot, error)
}

// XFreeRDPGrabber captures screenshots using xfreerdp under xvfb-run together
// with ImageMagick's import or ffmpeg for the actual image grab.
//
// Requirements: FreeRDP 2+ (xfreerdp), xvfb-run, and either import (ImageMagick)
// or ffmpeg. The password is passed through stdin (xfreerdp /from-stdin) so it
// never appears in the process table.
type XFreeRDPGrabber struct {
	// OutputDir receives the captured images (created when missing).
	OutputDir string
	// WaitSeconds is how long the session is allowed to render before capture.
	WaitSeconds int

	lookPath func(file string) (string, error)
	run      func(ctx context.Context, name string, args []string, env []string, stdin string) ([]byte, error)
}

// NewXFreeRDPGrabber builds the default grabber writing into outputDir.
func NewXFreeRDPGrabber(outputDir string) *XFreeRDPGrabber {
	return &XFreeRDPGrabber{
		OutputDir:   outputDir,
		WaitSeconds: 12,
		lookPath:    exec.LookPath,
		run:         runCommand,
	}
}

func runCommand(ctx context.Context, name string, args []string, env []string, stdin string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = env
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	return cmd.CombinedOutput()
}

// Available reports whether all required external tools are present.
func (g *XFreeRDPGrabber) Available() error {
	missing := []string{}
	for _, tool := range []string{"xfreerdp", "xvfb-run"} {
		if _, err := g.lookPath(tool); err != nil {
			missing = append(missing, tool)
		}
	}
	if _, err := g.lookPath("import"); err != nil {
		if _, err := g.lookPath("ffmpeg"); err != nil {
			missing = append(missing, "import|ffmpeg")
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("%w: missing %s (install FreeRDP, Xvfb and ImageMagick or ffmpeg)",
			ErrGrabberUnavailable, strings.Join(missing, ", "))
	}
	return nil
}

// Grab runs the headless capture and returns the resulting image metadata.
func (g *XFreeRDPGrabber) Grab(ctx context.Context, ep model.Endpoint, cred model.Credential) (model.Screenshot, error) {
	var shot model.Screenshot
	if err := g.Available(); err != nil {
		return shot, err
	}
	if err := os.MkdirAll(g.OutputDir, 0o700); err != nil {
		return shot, fmt.Errorf("screenshot: create output directory: %w", err)
	}

	now := time.Now().UTC()
	name := FileName(ep, cred.Username, now)
	outPath := filepath.Join(g.OutputDir, name)
	waitSeconds := g.WaitSeconds
	if waitSeconds <= 0 {
		waitSeconds = 12
	}

	args := []string{"-a", "-s", "-screen 0 1024x768x24", "sh", "-c", captureScript}
	env := append(os.Environ(),
		"RDSHOT_HOST="+ep.Address,
		fmt.Sprintf("RDSHOT_PORT=%d", ep.Port),
		"RDSHOT_USER="+cred.Username,
		"RDSHOT_DOMAIN="+cred.Domain,
		"RDSHOT_OUT="+outPath,
		fmt.Sprintf("RDSHOT_WAIT=%d", waitSeconds),
	)
	stdin := ""
	if cred.Method == model.CredMethodKerberos {
		env = append(env, "RDSHOT_CCACHE="+strings.TrimSpace(cred.Secret))
	} else if cred.IsNTHash() {
		// FreeRDP /pth (restricted admin). Hash is passed via env into the
		// shell script so it does not appear on the Go process argv.
		env = append(env, "RDSHOT_NTHASH="+strings.TrimSpace(cred.Secret))
	} else {
		// FreeRDP /from-stdin expects a trailing newline after the password.
		stdin = cred.Secret + "\n"
	}
	output, err := g.run(ctx, "xvfb-run", args, env, stdin)
	if err != nil {
		detail := strings.TrimSpace(string(output))
		if len(detail) > 300 {
			detail = detail[:300]
		}
		return shot, fmt.Errorf("screenshot: capture failed: %w (%s)", err, detail)
	}

	info, err := os.Stat(outPath)
	if err != nil {
		return shot, fmt.Errorf("screenshot: capture produced no image: %w", err)
	}
	if info.Size() == 0 {
		return shot, fmt.Errorf("screenshot: capture produced an empty image at %q", outPath)
	}
	w, h, blank, err := inspectCapturePNG(outPath)
	if err != nil {
		_ = os.Remove(outPath)
		return shot, fmt.Errorf("screenshot: inspect capture: %w", err)
	}
	if blank {
		_ = os.Remove(outPath)
		return shot, fmt.Errorf("screenshot: capture was blank (black frame)")
	}

	shot = model.Screenshot{
		Address:    ep.Address,
		Port:       ep.Port,
		Username:   cred.Username,
		FilePath:   outPath,
		Width:      w,
		Height:     h,
		CapturedAt: now,
	}
	return shot, nil
}

// captureScript logs into the RDP session inside a headless X server, waits
// briefly for the desktop, grabs the FreeRDP window (falling back to the root
// window), then kills FreeRDP so the remote session disconnects immediately.
// Values arrive via environment variables (and the password on stdin) to avoid
// shell interpolation hazards.
const captureScript = `
set -eu
log=$(mktemp)
trap 'rm -f "$log"' EXIT
# Empty domain must still pass /d:. — otherwise FreeRDP prompts for Domain
# on stdin and consumes the /from-stdin password as the domain value.
# RDSHOT_DOMAIN is often set-but-empty by the parent, so :- defaults alone
# are not enough.
domain="$RDSHOT_DOMAIN"
if [ -z "$domain" ]; then
  domain=.
fi
if [ -n "${RDSHOT_CCACHE:-}" ]; then
  # Pass-the-ticket via Kerberos CCache file
  export KRB5CCNAME="$RDSHOT_CCACHE"
  xfreerdp /v:"$RDSHOT_HOST:$RDSHOT_PORT" /u:"$RDSHOT_USER" /d:"$domain" \
    /cert:ignore /sec:nla /size:1024x768 /bpp:24 >"$log" 2>&1 &
elif [ -n "${RDSHOT_NTHASH:-}" ]; then
  # Pass-the-hash via FreeRDP restricted-admin mode (/pth).
  xfreerdp /v:"$RDSHOT_HOST:$RDSHOT_PORT" /u:"$RDSHOT_USER" /d:"$domain" \
    /pth:"$RDSHOT_NTHASH" /cert:ignore /sec:nla /size:1024x768 /bpp:24 >"$log" 2>&1 &
else
  # Read the password before backgrounding: a bare "&" does not reliably keep
  # the parent pipe attached to xfreerdp's /from-stdin. $(cat) strips a trailing
  # newline, so always re-terminate when feeding FreeRDP.
  pass=$(cat)
  printf '%s\n' "$pass" | xfreerdp /v:"$RDSHOT_HOST:$RDSHOT_PORT" /u:"$RDSHOT_USER" /d:"$domain" \
    /cert:ignore /sec:nla /size:1024x768 /bpp:24 /from-stdin >"$log" 2>&1 &
fi
pid=$!
trap 'kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; rm -f "$log"' EXIT
have_window=0
for _ in $(seq 1 "$RDSHOT_WAIT"); do
  if xwininfo -root -tree 2>/dev/null | grep -q FreeRDP; then
    have_window=1
    break
  fi
  if ! kill -0 "$pid" 2>/dev/null; then
    echo "freerdp exited before a window appeared" >&2
    tail -n 20 "$log" >&2 || true
    exit 4
  fi
  sleep 1
done
if [ "$have_window" -ne 1 ]; then
  echo "freerdp window never appeared" >&2
  tail -n 20 "$log" >&2 || true
  exit 5
fi
# Desktop paint is slow under Xvfb; keep a generous settle after the window maps.
settle=$((RDSHOT_WAIT - 4))
if [ "$settle" -lt 6 ]; then
  settle=6
fi
sleep "$settle"
wid=""
if command -v xdotool >/dev/null 2>&1; then
  wid=$(xdotool search --name "FreeRDP" 2>/dev/null | head -n1 || true)
fi
if [ -z "$wid" ]; then
  wid=$(xwininfo -root -tree 2>/dev/null | awk '/FreeRDP/{print $1; exit}' || true)
fi
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

// FileName builds a safe, unique image name for one capture. The returned name
// never contains path separators, so it cannot escape the output directory.
func FileName(ep model.Endpoint, username string, at time.Time) string {
	return fmt.Sprintf("%s_%d_%s_%s.png",
		sanitize(ep.Address), ep.Port, sanitize(username), at.UTC().Format("20060102T150405Z"))
}

// sanitize keeps conservative filename characters and replaces everything
// else, including path separators and traversal sequences.
func sanitize(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "unknown"
	}
	var b strings.Builder
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	cleaned := strings.Trim(b.String(), "._")
	if cleaned == "" {
		return "unknown"
	}
	return cleaned
}
