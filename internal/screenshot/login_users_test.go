package screenshot

import (
	"context"
	"errors"
	"image"
	"image/png"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestParseLoginUsersOCR(t *testing.T) {
	text := `
Windows
Yasemin
eda
Other user
Password
Sign in
OK
Cancel
R
Q-
ie
debate
DFR\rdpshot
ENG
`
	got := ParseLoginUsersOCR(text)
	want := []string{"Yasemin", "eda", "Other user"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ParseLoginUsersOCR = %#v, want %#v", got, want)
	}
}

func TestParseLoginUsersOCRDedupes(t *testing.T) {
	got := ParseLoginUsersOCR("admin\nAdmin\nADMIN")
	if len(got) != 1 || got[0] != "admin" {
		t.Fatalf("got %#v", got)
	}
}

func TestParseLoginUsersOCRRejectsShortNoise(t *testing.T) {
	got := ParseLoginUsersOCR("a\nab\nOK\nrdpshot\nee\nAe")
	if len(got) != 0 {
		t.Fatalf("got %#v, want empty", got)
	}
}

func TestExtractLoginUsersOCRMissingTesseract(t *testing.T) {
	users, err := extractLoginUsersOCR(context.Background(), "/tmp/x.png",
		func(string) (string, error) { return "", errors.New("missing") },
		func(context.Context, string) (string, error) {
			t.Fatal("tesseract must not run when missing from PATH")
			return "", nil
		})
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if users != nil {
		t.Fatalf("users = %#v, want nil", users)
	}
}

func TestExtractLoginUsersOCRParsesOutput(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "full.png")
	img := image.NewRGBA(image.Rect(0, 0, 200, 100))
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := png.Encode(f, img); err != nil {
		t.Fatal(err)
	}
	f.Close()

	users, err := extractLoginUsersOCR(context.Background(), path,
		func(string) (string, error) { return "/usr/bin/tesseract", nil },
		func(_ context.Context, imagePath string) (string, error) {
			// Prepared OCR crop should be a different temp file under dir.
			if imagePath == path {
				t.Fatalf("expected prepared OCR crop, got original %s", imagePath)
			}
			return "Yasemin\neda\nOther user\n", nil
		})
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	want := []string{"Yasemin", "eda", "Other user"}
	if !reflect.DeepEqual(users, want) {
		t.Fatalf("users = %#v, want %#v", users, want)
	}
}

func TestParseLoginUsersOCRDropsLineNoise(t *testing.T) {
	got := ParseLoginUsersOCR("2) Yasemin ets\neda ee * Sen\nOther user e\n")
	want := []string{"Yasemin", "eda", "Other user"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

func TestParseLoginUsersOCRRejectsWallpaperNoise(t *testing.T) {
	text := "R\nQ-\nBek\nPee\neee\nDFR\\rdpshot\nKUBI-HYP-ADFR\nHow\ndo\nanother\nENG\ndpshot\nie\nser\n"
	got := ParseLoginUsersOCR(text)
	if len(got) != 0 {
		t.Fatalf("got %#v, want empty", got)
	}
}

func TestParseLoginUsersOCRIgnoresOtherUserAlone(t *testing.T) {
	got := ParseLoginUsersOCR("Other user\nPassword\nSign in\n")
	if got != nil && len(got) != 0 {
		t.Fatalf("got %#v, want empty (credential form, no tiles)", got)
	}
}

func TestPrepareLoginUsersOCRImageDimensions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "full.png")
	img := image.NewRGBA(image.Rect(0, 0, 1024, 768))
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := png.Encode(f, img); err != nil {
		t.Fatal(err)
	}
	f.Close()

	out, err := prepareLoginUsersOCRImage(path)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(out)
	rf, err := os.Open(out)
	if err != nil {
		t.Fatal(err)
	}
	defer rf.Close()
	got, err := png.Decode(rf)
	if err != nil {
		t.Fatal(err)
	}
	b := got.Bounds()
	// left 34% of 1024 ≈ 348, bottom 45% of 768 ≈ 346, ×3 scale.
	if b.Dx() < 900 || b.Dy() < 900 {
		t.Fatalf("prepared size = %dx%d, want upscaled tile crop", b.Dx(), b.Dy())
	}
}
