package screenshot

import (
	"bytes"
	"context"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"
)

const (
	maxLoginUsers = 8
	// Winlogon account tiles sit in the lower-left; a full-height left strip
	// is mostly wallpaper and defeats tesseract.
	loginTileLeftFrac = 0.34
	loginTileTopFrac  = 0.55
	loginTileOCRScale = 3
	// minLoginUsersQuality drops OCR results that are mostly junk crumbs.
	minLoginUsersQuality = 0.35
)

// LoginUsersResult is the OCR extraction outcome with a simple quality score.
type LoginUsersResult struct {
	Users         []string
	Quality       float64
	RawTokenCount int
}

// ExtractLoginUsersOCR runs tesseract on a preprocessed bottom-left crop of a
// login-screen PNG (Winlogon account tiles) and returns plausible usernames.
// Missing tesseract yields a zero result with a nil error.
func ExtractLoginUsersOCR(ctx context.Context, imagePath string) (LoginUsersResult, error) {
	return extractLoginUsersOCR(ctx, imagePath, exec.LookPath, runTesseract)
}

type lookPathFunc func(file string) (string, error)
type tesseractFunc func(ctx context.Context, imagePath string) (string, error)

func runTesseract(ctx context.Context, imagePath string) (string, error) {
	// PSM 11 = sparse text; with the upscaled grayscale tile crop it recovers
	// stacked account labels better than a single-block assumption.
	cmd := exec.CommandContext(ctx, "tesseract", imagePath, "stdout", "-l", "eng", "--psm", "11")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		detail := strings.TrimSpace(stderr.String())
		if detail == "" {
			detail = err.Error()
		}
		return "", fmt.Errorf("tesseract: %s", detail)
	}
	return stdout.String(), nil
}

func extractLoginUsersOCR(ctx context.Context, imagePath string, lookPath lookPathFunc, run tesseractFunc) (LoginUsersResult, error) {
	if _, err := lookPath("tesseract"); err != nil {
		return LoginUsersResult{}, nil
	}
	ocrPath := imagePath
	prepared, err := prepareLoginUsersOCRImage(imagePath)
	if err == nil && prepared != "" {
		defer os.Remove(prepared)
		ocrPath = prepared
	}
	text, err := run(ctx, ocrPath)
	if err != nil {
		return LoginUsersResult{}, err
	}
	return ApplyLoginUsersQualityGate(ParseLoginUsersOCRResult(text)), nil
}

// looksLikeHostname rejects machine / domain fragments OCR'd from "Sign in to:".
func looksLikeHostname(s string) bool {
	if strings.Count(s, "-") >= 2 {
		return true
	}
	if strings.Contains(s, ".") && strings.ContainsAny(s, ".-") {
		return true
	}
	upper, lower := 0, 0
	for _, r := range s {
		if unicode.IsUpper(r) {
			upper++
		}
		if unicode.IsLower(r) {
			lower++
		}
	}
	// ALL-CAPS tokens with a hyphen are almost always host labels, not people.
	return upper >= 4 && lower == 0 && strings.Contains(s, "-")
}

func looksLikeOCRCrumb(s string) bool {
	lower := strings.ToLower(s)
	if strings.Contains(lower, "rdpshot") || strings.Contains(lower, "dpshot") {
		return true
	}
	letters := make(map[rune]int)
	n := 0
	for _, r := range lower {
		if unicode.IsLetter(r) {
			letters[r]++
			n++
		}
	}
	if n >= 3 && len(letters) == 1 {
		return true // eee, aaa
	}
	vowels := 0
	for _, r := range lower {
		switch r {
		case 'a', 'e', 'i', 'o', 'u', 'y':
			vowels++
		}
	}
	// Short consonant soup (Sh, Bfr) without vowels is wallpaper noise.
	if n >= 3 && n <= 4 && vowels == 0 {
		return true
	}
	return false
}

// finalizeLoginUsers drops lone "Other user" (credential form, no tiles) and
// keeps only plausible account labels.
func finalizeLoginUsers(in []string) []string {
	var real []string
	hasOther := false
	for _, u := range in {
		if u == "Other user" {
			hasOther = true
			continue
		}
		real = append(real, u)
	}
	if len(real) == 0 {
		return nil
	}
	if hasOther {
		real = append(real, "Other user")
	}
	return real
}

// prepareLoginUsersOCRImage writes an upscaled, contrast-boosted crop of the
// Winlogon account-tile column for tesseract.
func prepareLoginUsersOCRImage(imagePath string) (string, error) {
	f, err := os.Open(imagePath)
	if err != nil {
		return "", err
	}
	defer f.Close()
	img, err := png.Decode(f)
	if err != nil {
		return "", err
	}
	b := img.Bounds()
	w, h := b.Dx(), b.Dy()
	if w < 64 || h < 64 {
		return "", fmt.Errorf("image too small")
	}
	left := b.Min.X
	right := b.Min.X + int(float64(w)*loginTileLeftFrac)
	if right-left < 80 {
		right = b.Min.X + w/3
	}
	top := b.Min.Y + int(float64(h)*loginTileTopFrac)
	if top >= b.Max.Y-40 {
		top = b.Min.Y + h/2
	}
	type subImager interface {
		SubImage(r image.Rectangle) image.Image
	}
	si, ok := img.(subImager)
	if !ok {
		return "", fmt.Errorf("image does not support SubImage")
	}
	crop := si.SubImage(image.Rect(left, top, right, b.Max.Y))
	scaled := upscaleGrayContrast(crop, loginTileOCRScale)

	out, err := os.CreateTemp(filepath.Dir(imagePath), "rdpshot-ocr-*.png")
	if err != nil {
		return "", err
	}
	path := out.Name()
	if err := png.Encode(out, scaled); err != nil {
		out.Close()
		os.Remove(path)
		return "", err
	}
	if err := out.Close(); err != nil {
		os.Remove(path)
		return "", err
	}
	return path, nil
}

// upscaleGrayContrast nearest-neighbor scales src, converts to grayscale, and
// stretches contrast so light Winlogon labels stand out for OCR.
func upscaleGrayContrast(src image.Image, scale int) *image.Gray {
	if scale < 1 {
		scale = 1
	}
	sb := src.Bounds()
	dw := sb.Dx() * scale
	dh := sb.Dy() * scale
	dst := image.NewGray(image.Rect(0, 0, dw, dh))
	for y := 0; y < dh; y++ {
		sy := sb.Min.Y + y/scale
		for x := 0; x < dw; x++ {
			sx := sb.Min.X + x/scale
			r, g, b, _ := src.At(sx, sy).RGBA()
			// Rec. 601 luma from 16-bit channels.
			y16 := (r*299 + g*587 + b*114) / 1000
			dst.SetGray(x, y, color.Gray{Y: uint8(y16 >> 8)})
		}
	}
	// Percentile-ish stretch using sampled min/max (skip pure extremes).
	minY, maxY := uint8(255), uint8(0)
	step := 4
	if dw < 64 {
		step = 1
	}
	for y := 0; y < dh; y += step {
		for x := 0; x < dw; x += step {
			v := dst.GrayAt(x, y).Y
			if v < minY {
				minY = v
			}
			if v > maxY {
				maxY = v
			}
		}
	}
	if maxY <= minY+8 {
		return dst
	}
	span := float64(maxY - minY)
	for y := 0; y < dh; y++ {
		for x := 0; x < dw; x++ {
			v := dst.GrayAt(x, y).Y
			n := uint8(float64(v-minY) / span * 255)
			dst.SetGray(x, y, color.Gray{Y: n})
		}
	}
	return dst
}

var (
	loginUserToken = regexp.MustCompile(`(?i)^[a-z][a-z0-9._-]{2,31}$`)
	otherUserLabel = regexp.MustCompile(`(?i)^other\s+user\b`)
	domainUser     = regexp.MustCompile(`(?i)^(?:[a-z0-9._-]{1,32}\\)?([a-z][a-z0-9._-]{2,31})$`)
)

// winlogonJunk are OCR tokens that are chrome / noise, not account tiles.
var winlogonJunk = map[string]struct{}{
	"ok": {}, "cancel": {}, "sign": {}, "in": {}, "sign-in": {}, "signin": {},
	"password": {}, "pin": {}, "welcome": {}, "windows": {}, "microsoft": {},
	"ease": {}, "access": {}, "power": {}, "shutdown": {}, "restart": {},
	"network": {}, "ethernet": {}, "wifi": {}, "connected": {}, "disconnected": {},
	"enter": {}, "your": {}, "credentials": {}, "domain": {}, "work": {},
	"school": {}, "account": {}, "local": {}, "user": {}, "users": {},
	"press": {}, "ctrl": {}, "alt": {}, "delete": {}, "login": {}, "logon": {},
	"rdpshot": {}, "detection": {}, "evidence": {}, "session": {},
	"eng": {}, "how": {}, "do": {}, "another": {}, "the": {}, "and": {},
	"for": {}, "you": {}, "are": {}, "not": {}, "this": {}, "that": {},
	"from": {}, "with": {}, "have": {}, "will": {}, "can": {}, "use": {},
	"other": {}, "ser": {}, "les": {}, "ees": {}, "ied": {}, "debate": {},
	"ao": {}, "ae": {}, "ea": {}, "ee": {}, "ne": {}, "pe": {},
	"ag": {}, "yo": {}, "is": {}, "on": {}, "to": {}, "us": {}, "ie": {},
	"sh": {}, "bek": {}, "dfr": {}, "kubi": {}, "hyp": {}, "adfr": {},
	"name": {}, "username": {}, "ets": {}, "sen": {}, "mer": {}, "dst": {},
	"ase": {}, "soy": {}, "patd": {}, "ate": {}, "pee": {}, "eee": {},
	"sa": {}, "se": {}, "dpshot": {}, "akkaya": {}, "com": {},
}

var leadingOCRNoise = regexp.MustCompile(`^[\d\)\(\]\[|>.~*\-—–]+`)

// ParseLoginUsersOCR extracts account-like labels from tesseract stdout.
func ParseLoginUsersOCR(text string) []string {
	return ParseLoginUsersOCRResult(text).Users
}

// ParseLoginUsersOCRResult extracts users and a quality score from OCR text.
func ParseLoginUsersOCRResult(text string) LoginUsersResult {
	seen := map[string]struct{}{}
	var out []string
	rawTokens := 0
	for _, rawLine := range strings.Split(text, "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" {
			continue
		}
		line = leadingOCRNoise.ReplaceAllString(line, "")
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if otherUserLabel.MatchString(line) {
			addLoginUser(&out, seen, "Other user")
			continue
		}
		compact := strings.Join(strings.Fields(line), " ")
		if name, ok := normalizeAccountLabel(compact); ok {
			rawTokens++
			addLoginUser(&out, seen, name)
			continue
		}
		var cands []string
		for _, field := range strings.Fields(line) {
			field = strings.Trim(field, ".,;:|[](){}<>\"'`*~")
			rawTokens += countOCRCandidateAttempts(field)
			if name, ok := normalizeAccountLabel(field); ok {
				cands = append(cands, name)
			}
		}
		for _, name := range preferAccountCandidates(cands) {
			addLoginUser(&out, seen, name)
		}
		if len(out) >= maxLoginUsers {
			break
		}
	}
	users := finalizeLoginUsers(out)
	accepted := 0
	for _, u := range users {
		if u != "Other user" {
			accepted++
		}
	}
	quality := 0.0
	if rawTokens > 0 {
		quality = float64(accepted) / float64(rawTokens)
	} else if accepted > 0 {
		quality = 1.0
	}
	if quality > 1 {
		quality = 1
	}
	return LoginUsersResult{Users: users, Quality: quality, RawTokenCount: rawTokens}
}

// ApplyLoginUsersQualityGate clears users when the OCR score is too low.
func ApplyLoginUsersQualityGate(res LoginUsersResult) LoginUsersResult {
	if res.Quality < minLoginUsersQuality {
		res.Users = nil
	}
	return res
}

func countOCRCandidateAttempts(field string) int {
	if field == "" {
		return 0
	}
	lower := strings.ToLower(strings.Trim(field, ".,;:|[](){}<>\"'`*~"))
	if lower == "" {
		return 0
	}
	if _, junk := winlogonJunk[lower]; junk {
		return 1
	}
	if looksLikeHostname(lower) || looksLikeOCRCrumb(lower) {
		return 1
	}
	if loginUserToken.MatchString(lower) || domainUser.MatchString(lower) {
		return 1
	}
	return 0
}

// preferAccountCandidates drops short lowercase OCR crumbs when a stronger
// Capitalized tile label is present on the same line (e.g. "Yasemin ets").
func preferAccountCandidates(cands []string) []string {
	if len(cands) <= 1 {
		return cands
	}
	hasStrong := false
	for _, c := range cands {
		if isStrongAccountLabel(c) {
			hasStrong = true
			break
		}
	}
	if !hasStrong {
		return cands
	}
	var out []string
	for _, c := range cands {
		if isStrongAccountLabel(c) || len(c) >= 4 {
			out = append(out, c)
		}
	}
	if len(out) == 0 {
		return cands
	}
	return out
}

func isStrongAccountLabel(s string) bool {
	if s == "Other user" {
		return true
	}
	r := []rune(s)
	return len(r) >= 4 && unicode.IsUpper(r[0])
}

func normalizeAccountLabel(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > 64 {
		return "", false
	}
	if otherUserLabel.MatchString(s) {
		return "Other user", true
	}
	// DOMAIN\user → user (drop our dummy capture identity).
	if m := domainUser.FindStringSubmatch(s); m != nil {
		s = m[1]
	}
	if strings.ContainsAny(s, `/\`) {
		return "", false
	}
	if looksLikeHostname(s) || looksLikeOCRCrumb(s) {
		return "", false
	}
	lower := strings.ToLower(s)
	if lower == loginScreenDummyUser {
		return "", false
	}
	if _, junk := winlogonJunk[lower]; junk {
		return "", false
	}
	if strings.Contains(lower, " ") {
		return "", false
	}
	if !loginUserToken.MatchString(s) {
		return "", false
	}
	letters := 0
	for _, r := range s {
		if unicode.IsLetter(r) {
			letters++
		}
	}
	// Require a real name-like token (Yasemin, eda, Administrator).
	if letters < 3 {
		return "", false
	}
	runes := []rune(s)
	// 3-letter OCR crumbs are often Capitalized noise (Pee, Bek); real short
	// local accounts on Winlogon tiles are typically lowercase (eda).
	if len(runes) == 3 && unicode.IsUpper(runes[0]) {
		return "", false
	}
	return s, true
}

func addLoginUser(out *[]string, seen map[string]struct{}, name string) {
	if len(*out) >= maxLoginUsers {
		return
	}
	key := strings.ToLower(name)
	if _, ok := seen[key]; ok {
		return
	}
	seen[key] = struct{}{}
	*out = append(*out, name)
}
