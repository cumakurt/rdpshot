// Package screenshot captures remote desktop session images after a
// successful credential check. It drives an external FreeRDP client under a
// headless X server because a full RDP graphics client is out of scope here.
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
		WaitSeconds: 8,
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
		waitSeconds = 8
	}

	args := []string{"-a", "sh", "-c", captureScript}
	env := append(os.Environ(),
		"RDSHOT_HOST="+ep.Address,
		fmt.Sprintf("RDSHOT_PORT=%d", ep.Port),
		"RDSHOT_USER="+cred.Username,
		"RDSHOT_DOMAIN="+cred.Domain,
		"RDSHOT_OUT="+outPath,
		fmt.Sprintf("RDSHOT_WAIT=%d", waitSeconds),
	)
	output, err := g.run(ctx, "xvfb-run", args, env, cred.Secret)
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

	shot = model.Screenshot{
		Address:    ep.Address,
		Port:       ep.Port,
		Username:   cred.Username,
		FilePath:   outPath,
		CapturedAt: now,
	}
	return shot, nil
}

// captureScript renders the session inside a headless X server and grabs the
// root window. Environment variables carry every value so nothing is
// interpolated into the shell source (no quoting hazards), and the password
// arrives on stdin.
const captureScript = `
set -eu
xfreerdp /v:"$RDSHOT_HOST:$RDSHOT_PORT" /u:"$RDSHOT_USER" /d:"$RDSHOT_DOMAIN" \
  /cert:ignore /size:1024x768 /from-stdin >/dev/null 2>&1 &
pid=$!
sleep "$RDSHOT_WAIT"
if command -v import >/dev/null 2>&1; then
  import -window root "$RDSHOT_OUT"
elif command -v ffmpeg >/dev/null 2>&1; then
  ffmpeg -loglevel error -f x11grab -video_size 1024x768 -i "${DISPLAY:-:99}" -frames:v 1 "$RDSHOT_OUT"
else
  echo "no capture tool available" >&2
  exit 3
fi
kill "$pid" 2>/dev/null || true
wait "$pid" 2>/dev/null || true
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
