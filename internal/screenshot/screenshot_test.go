package screenshot

import (
	"context"
	"errors"
	"image"
	"image/png"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"rdpshot/internal/model"
)

func fakeGrabber(t *testing.T, outputDir string, available bool, capture bool) (*XFreeRDPGrabber, *captureRecorder) {
	t.Helper()
	rec := &captureRecorder{}
	grabber := NewXFreeRDPGrabber(outputDir)
	grabber.lookPath = func(file string) (string, error) {
		if !available {
			return "", errors.New("not found")
		}
		return "/usr/bin/" + file, nil
	}
	grabber.run = func(_ context.Context, name string, args []string, env []string, stdin string) ([]byte, error) {
		rec.name = name
		rec.args = args
		rec.env = env
		rec.stdin = stdin
		if capture {
			out := envValue(env, "RDSHOT_OUT")
			img := image.NewRGBA(image.Rect(0, 0, 64, 48))
			for y := 0; y < 48; y++ {
				for x := 0; x < 64; x++ {
					i := y*img.Stride + x*4
					img.Pix[i+0] = 40
					img.Pix[i+1] = 120
					img.Pix[i+2] = 180
					img.Pix[i+3] = 255
				}
			}
			f, err := os.Create(out)
			if err != nil {
				return nil, err
			}
			if err := png.Encode(f, img); err != nil {
				f.Close()
				return nil, err
			}
			f.Close()
		}
		return []byte("ok"), nil
	}
	return grabber, rec
}

type captureRecorder struct {
	name  string
	args  []string
	env   []string
	stdin string
}

func envValue(env []string, key string) string {
	// Prefer the last match: Grab appends overrides after os.Environ(), so an
	// ambient RDSHOT_* from the developer shell must not win.
	prefix := key + "="
	value := ""
	for _, entry := range env {
		if strings.HasPrefix(entry, prefix) {
			value = strings.TrimPrefix(entry, prefix)
		}
	}
	return value
}

func TestFileNameIsSafe(t *testing.T) {
	at := time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		address, user string
		want          string
	}{
		{"10.0.0.1", "Administrator", "10.0.0.1_3389_Administrator_20261029T120000Z.png"},
		{"../../etc/passwd", "..\\..\\win", "etc_passwd_3389_win_20261029T120000Z.png"},
		{"", "", "unknown_3389_unknown_20261029T120000Z.png"},
	}
	for _, tc := range cases {
		got := FileName(model.Endpoint{Address: tc.address, Port: 3389}, tc.user, at)
		if got != tc.want {
			t.Fatalf("FileName(%q,%q) = %q, want %q", tc.address, tc.user, got, tc.want)
		}
		if strings.Contains(got, "/") || strings.Contains(got, string(filepath.Separator)) {
			t.Fatalf("file name contains path separator: %q", got)
		}
	}
}

func TestSanitizeHandlesHostileValues(t *testing.T) {
	for _, in := range []string{"../..", "...", "///", "\x00", "用户"} {
		got := sanitize(in)
		if got == "" || strings.ContainsAny(got, "/\\") {
			t.Fatalf("sanitize(%q) = %q", in, got)
		}
	}
}

func TestGrabStoresImage(t *testing.T) {
	dir := t.TempDir()
	grabber, rec := fakeGrabber(t, dir, true, true)

	shot, err := grabber.Grab(context.Background(),
		model.Endpoint{Address: "10.0.0.9", Port: 3389},
		model.Credential{Username: "Administrator", Secret: "redacted", Domain: "LAB"})
	if err != nil {
		t.Fatalf("grab: %v", err)
	}
	if shot.Username != "Administrator" || shot.Port != 3389 {
		t.Fatalf("shot = %+v", shot)
	}
	if filepath.Dir(shot.FilePath) != dir {
		t.Fatalf("image escaped output dir: %s", shot.FilePath)
	}
	if rec.stdin != "redacted\n" {
		t.Fatalf("password stdin = %q, want trailing newline for FreeRDP /from-stdin", rec.stdin)
	}
	for _, arg := range rec.args {
		if strings.Contains(arg, "redacted") {
			t.Fatalf("password leaked into argv: %q", arg)
		}
	}
	if envValue(rec.env, "RDSHOT_HOST") != "10.0.0.9" {
		t.Fatalf("host env = %q", envValue(rec.env, "RDSHOT_HOST"))
	}
	joined := strings.Join(rec.args, " ")
	if !strings.Contains(joined, "-screen 0 1024x768x24") {
		t.Fatalf("xvfb geometry missing from args: %#v", rec.args)
	}
	scriptBody := ""
	for i, a := range rec.args {
		if a == "-c" && i+1 < len(rec.args) {
			scriptBody = rec.args[i+1]
		}
	}
	if !strings.Contains(scriptBody, "/sec:nla") {
		t.Fatalf("authenticated capture script missing /sec:nla: %q", scriptBody)
	}
	if !strings.Contains(scriptBody, `if [ -z "$domain" ]; then`) || !strings.Contains(scriptBody, `domain=.`) {
		t.Fatalf("authenticated capture script must default empty domain to .: %q", scriptBody)
	}
	if shot.Width != 64 || shot.Height != 48 {
		t.Fatalf("dimensions = %dx%d", shot.Width, shot.Height)
	}
}

func TestGrabRejectsBlankPNG(t *testing.T) {
	dir := t.TempDir()
	grabber, _ := fakeGrabber(t, dir, true, true)
	grabber.run = func(_ context.Context, name string, args []string, env []string, stdin string) ([]byte, error) {
		out := envValue(env, "RDSHOT_OUT")
		img := image.NewRGBA(image.Rect(0, 0, 64, 48))
		f, err := os.Create(out)
		if err != nil {
			return nil, err
		}
		if err := png.Encode(f, img); err != nil {
			f.Close()
			return nil, err
		}
		f.Close()
		return []byte("ok"), nil
	}
	_, err := grabber.Grab(context.Background(),
		model.Endpoint{Address: "10.0.0.9", Port: 3389},
		model.Credential{Username: "u", Secret: "p"})
	if err == nil || !strings.Contains(err.Error(), "blank") {
		t.Fatalf("err = %v, want blank-frame error", err)
	}
}

func TestGrabMissingTools(t *testing.T) {
	grabber, _ := fakeGrabber(t, t.TempDir(), false, false)
	_, err := grabber.Grab(context.Background(),
		model.Endpoint{Address: "10.0.0.9", Port: 3389},
		model.Credential{Username: "u", Secret: "p"})
	if !errors.Is(err, ErrGrabberUnavailable) {
		t.Fatalf("err = %v, want ErrGrabberUnavailable", err)
	}
}

func TestGrabDetectsMissingImage(t *testing.T) {
	grabber, _ := fakeGrabber(t, t.TempDir(), true, false)
	_, err := grabber.Grab(context.Background(),
		model.Endpoint{Address: "10.0.0.9", Port: 3389},
		model.Credential{Username: "u", Secret: "p"})
	if err == nil {
		t.Fatal("expected an error when no image was produced")
	}
}

func TestAvailableMissingCaptureTool(t *testing.T) {
	grabber := NewXFreeRDPGrabber(t.TempDir())
	grabber.lookPath = func(file string) (string, error) {
		if file == "xfreerdp" || file == "xvfb-run" {
			return "/usr/bin/" + file, nil
		}
		return "", errors.New("not found")
	}
	if err := grabber.Available(); !errors.Is(err, ErrGrabberUnavailable) {
		t.Fatalf("err = %v, want ErrGrabberUnavailable", err)
	}
}

func TestEvidenceGrabWritesPNG(t *testing.T) {
	dir := t.TempDir()
	grabber := NewEvidenceGrabber(dir)
	shot, err := grabber.Grab(context.Background(),
		model.Endpoint{Address: "10.0.0.9", Port: 3389},
		model.Credential{Username: "Administrator", Domain: "LAB", Method: "credssp", Secret: "x"})
	if err != nil {
		t.Fatalf("grab: %v", err)
	}
	if shot.Width != evidenceWidth || shot.Height != evidenceHeight {
		t.Fatalf("dimensions = %dx%d", shot.Width, shot.Height)
	}
	info, err := os.Stat(shot.FilePath)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Size() < 100 {
		t.Fatalf("evidence image too small: %d", info.Size())
	}
}

func TestAutoGrabberFallsBack(t *testing.T) {
	dir := t.TempDir()
	auto := NewAutoGrabber(dir, nil)
	auto.Primary = NewXFreeRDPGrabber(dir)
	auto.Primary.(*XFreeRDPGrabber).lookPath = func(string) (string, error) {
		return "", errors.New("missing")
	}
	// Force the Go framebuffer path to fail without dialing the network so the
	// evidence-card fallback is what this unit test exercises.
	auto.Secondary = stubGrabber{err: errors.New("framebuffer unavailable in test")}
	shot, err := auto.Grab(context.Background(),
		model.Endpoint{Address: "10.0.0.9", Port: 3389},
		model.Credential{Username: "u", Secret: "p"})
	if err != nil {
		t.Fatalf("grab: %v", err)
	}
	if filepath.Dir(shot.FilePath) != dir {
		t.Fatalf("path = %s", shot.FilePath)
	}
}

func TestAutoGrabberErrorsWhenLiveCaptureFails(t *testing.T) {
	dir := t.TempDir()
	auto := NewAutoGrabber(dir, nil)
	// FreeRDP tooling appears available, but Grab fails — must not store an
	// evidence card that claims tooling is missing.
	primary := NewXFreeRDPGrabber(dir)
	primary.lookPath = func(file string) (string, error) { return "/usr/bin/" + file, nil }
	primary.run = func(context.Context, string, []string, []string, string) ([]byte, error) {
		return nil, errors.New("blank frame")
	}
	auto.Primary = primary
	auto.Secondary = stubGrabber{err: errors.New("framebuffer unavailable in test")}
	_, err := auto.Grab(context.Background(),
		model.Endpoint{Address: "10.0.0.9", Port: 3389},
		model.Credential{Username: "u", Secret: "p"})
	if err == nil {
		t.Fatal("expected live-capture error, not evidence-card success")
	}
	if !strings.Contains(err.Error(), "freerdp") {
		t.Fatalf("err = %v, want freerdp context", err)
	}
}

type stubGrabber struct{ err error }

func (s stubGrabber) Available() error { return nil }
func (s stubGrabber) Grab(context.Context, model.Endpoint, model.Credential) (model.Screenshot, error) {
	return model.Screenshot{}, s.err
}

func TestGrabLoginScreenStoresImage(t *testing.T) {
	dir := t.TempDir()
	grabber, rec := fakeGrabber(t, dir, true, true)
	grabber.run = func(_ context.Context, name string, args []string, env []string, stdin string) ([]byte, error) {
		rec.name = name
		rec.args = args
		rec.env = env
		rec.stdin = stdin
		out := envValue(env, "RDSHOT_OUT")
		img := image.NewRGBA(image.Rect(0, 0, 64, 48))
		for y := 0; y < 48; y++ {
			for x := 0; x < 64; x++ {
				i := y*img.Stride + x*4
				img.Pix[i+0] = 40
				img.Pix[i+1] = 120
				img.Pix[i+2] = 180
				img.Pix[i+3] = 255
			}
		}
		f, err := os.Create(out)
		if err != nil {
			return nil, err
		}
		if err := png.Encode(f, img); err != nil {
			f.Close()
			return nil, err
		}
		f.Close()
		return []byte("ok"), nil
	}

	shot, err := grabber.GrabLoginScreen(context.Background(),
		model.Endpoint{Address: "192.168.112.76", Port: 3389})
	if err != nil {
		t.Fatalf("grab login screen: %v", err)
	}
	if shot.Username != LoginScreenLabel {
		t.Fatalf("username = %q, want %q", shot.Username, LoginScreenLabel)
	}
	if filepath.Dir(shot.FilePath) != dir {
		t.Fatalf("path = %s", shot.FilePath)
	}
	joined := strings.Join(rec.args, " ")
	if !strings.Contains(joined, "-screen 0 1024x768x24") {
		t.Fatalf("xvfb geometry missing from args: %#v", rec.args)
	}
	scriptBody := ""
	for i, a := range rec.args {
		if a == "-c" && i+1 < len(rec.args) {
			scriptBody = rec.args[i+1]
		}
	}
	if !strings.Contains(scriptBody, "/sec:tls") {
		t.Fatalf("login script missing /sec:tls: %q", scriptBody)
	}
	if !strings.Contains(scriptBody, ` /u:"$RDSHOT_USER"`) && !strings.Contains(scriptBody, `/u:"$RDSHOT_USER"`) {
		t.Fatalf("login script must pass dummy user: %q", scriptBody)
	}
	if !strings.Contains(scriptBody, "Escape") || !strings.Contains(scriptBody, "BackSpace") {
		t.Fatalf("login script must dismiss Other-user / clear dummy username: %q", scriptBody)
	}
	if strings.Contains(scriptBody, "/from-stdin") {
		t.Fatal("login-screen capture must not send a password on stdin")
	}
	if envValue(rec.env, "RDSHOT_USER") != loginScreenDummyUser {
		t.Fatalf("RDSHOT_USER = %q", envValue(rec.env, "RDSHOT_USER"))
	}
	if rec.stdin != "" {
		t.Fatalf("stdin = %q, want empty", rec.stdin)
	}
}

func TestGrabLoginScreenRejectsBlankPNG(t *testing.T) {
	dir := t.TempDir()
	grabber, _ := fakeGrabber(t, dir, true, true)
	// Overwrite the fake "png-bytes" with a real solid-black PNG after run.
	grabber.run = func(_ context.Context, name string, args []string, env []string, stdin string) ([]byte, error) {
		out := envValue(env, "RDSHOT_OUT")
		img := image.NewRGBA(image.Rect(0, 0, 64, 48))
		f, err := os.Create(out)
		if err != nil {
			return nil, err
		}
		if err := png.Encode(f, img); err != nil {
			f.Close()
			return nil, err
		}
		f.Close()
		return []byte("ok"), nil
	}
	_, err := grabber.GrabLoginScreen(context.Background(),
		model.Endpoint{Address: "10.0.0.9", Port: 3389})
	if err == nil || !strings.Contains(err.Error(), "blank") {
		t.Fatalf("err = %v, want blank-frame error", err)
	}
}

func TestGrabLoginScreenMissingTools(t *testing.T) {
	grabber, _ := fakeGrabber(t, t.TempDir(), false, false)
	_, err := grabber.GrabLoginScreen(context.Background(),
		model.Endpoint{Address: "10.0.0.9", Port: 3389})
	if !errors.Is(err, ErrGrabberUnavailable) {
		t.Fatalf("err = %v, want ErrGrabberUnavailable", err)
	}
}

func TestGrabOpenHostWritesPNG(t *testing.T) {
	dir := t.TempDir()
	grabber := NewEvidenceGrabber(dir)
	shot, err := grabber.GrabOpenHost(context.Background(),
		model.Endpoint{Address: "192.168.52.112", Port: 3389},
		&model.ServiceInfo{
			NLARequired: true,
			TLSVersion:  "TLS 1.2",
			OSGuess:     "Windows",
			Certificate: &model.CertificateInfo{Subject: "CN=rdp-host", SelfSigned: true},
		})
	if err != nil {
		t.Fatalf("grab open host: %v", err)
	}
	if shot.Username != OpenHostLabel {
		t.Fatalf("username label = %q", shot.Username)
	}
	info, err := os.Stat(shot.FilePath)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Size() < 100 {
		t.Fatalf("evidence image too small: %d", info.Size())
	}
}
