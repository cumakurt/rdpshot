package screenshot

import (
	"context"
	"errors"
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
			if err := os.WriteFile(out, []byte("png-bytes"), 0o600); err != nil {
				return nil, err
			}
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
	for _, entry := range env {
		if strings.HasPrefix(entry, key+"=") {
			return strings.TrimPrefix(entry, key+"=")
		}
	}
	return ""
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
	if rec.stdin != "redacted" {
		t.Fatal("password must be passed through stdin, never through argv")
	}
	for _, arg := range rec.args {
		if strings.Contains(arg, "redacted") {
			t.Fatalf("password leaked into argv: %q", arg)
		}
	}
	if envValue(rec.env, "RDSHOT_HOST") != "10.0.0.9" {
		t.Fatalf("host env = %q", envValue(rec.env, "RDSHOT_HOST"))
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
