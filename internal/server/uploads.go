package server

import (
	"bufio"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"rdpshot/internal/brute"
)

// uploadsDirName is the subdirectory of OutputsDir holding per-scan uploads.
// Each scan gets a private directory so deleting the scan can remove exactly
// the files it owns.
const uploadsDirName = "uploads"

// formFile returns the first uploaded file of a multipart field, or nil.
func formFile(r *http.Request, field string) *multipart.FileHeader {
	if r.MultipartForm == nil {
		return nil
	}
	files := r.MultipartForm.File[field]
	if len(files) == 0 {
		return nil
	}
	return files[0]
}

// saveWordlistUpload copies one uploaded wordlist into the scan's private
// upload directory and returns its path. An empty path with a nil error means
// no file was supplied, so the caller can fall back to a server-side path.
func (s *Server) saveWordlistUpload(scanID, field string, file *multipart.FileHeader) (string, error) {
	if file == nil || file.Size == 0 {
		return "", nil
	}
	if s.cfg.OutputsDir == "" {
		return "", fmt.Errorf("file uploads are not configured")
	}
	if !safePathSegment(scanID) {
		return "", fmt.Errorf("invalid scan identifier")
	}
	if file.Size > maxWordlistUploadBytes {
		return "", fmt.Errorf("%s exceeds the %d MiB limit", field, maxWordlistUploadBytes>>20)
	}

	dir := filepath.Join(s.cfg.OutputsDir, uploadsDirName, scanID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("create upload directory: %w", err)
	}

	src, err := file.Open()
	if err != nil {
		return "", fmt.Errorf("open uploaded file: %w", err)
	}
	defer src.Close()

	tmp, err := os.CreateTemp(dir, ".upload-*")
	if err != nil {
		return "", fmt.Errorf("create upload file: %w", err)
	}
	tmpPath := tmp.Name()
	// The temporary file is gone after a successful rename; this is the
	// cleanup path for every error below.
	defer os.Remove(tmpPath)

	written, err := io.Copy(tmp, io.LimitReader(src, maxWordlistUploadBytes+1))
	if err != nil {
		tmp.Close()
		return "", fmt.Errorf("store uploaded file: %w", err)
	}
	if written > maxWordlistUploadBytes {
		tmp.Close()
		return "", fmt.Errorf("%s exceeds the %d MiB limit", field, maxWordlistUploadBytes>>20)
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return "", fmt.Errorf("restrict upload permissions: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return "", fmt.Errorf("close uploaded file: %w", err)
	}

	// Reject empty or unreadable wordlists now instead of failing the scan
	// later, when the operator has already queued it.
	if _, err := brute.LoadWordlist(tmpPath); err != nil {
		return "", fmt.Errorf("%s: %w", field, err)
	}

	path := filepath.Join(dir, field+".txt")
	if err := os.Rename(tmpPath, path); err != nil {
		return "", fmt.Errorf("finalise uploaded file: %w", err)
	}
	return path, nil
}

// readTargetsUpload parses an uploaded targets list into inline specs. The
// file itself is never kept as an @path reference, so the API cannot be used
// to read arbitrary server filesystem paths.
func readTargetsUpload(file *multipart.FileHeader) ([]string, error) {
	if file == nil || file.Size == 0 {
		return nil, nil
	}
	if file.Size > maxTargetsUploadBytes {
		return nil, fmt.Errorf("targets file exceeds the %d MiB limit", maxTargetsUploadBytes>>20)
	}
	src, err := file.Open()
	if err != nil {
		return nil, fmt.Errorf("open targets file: %w", err)
	}
	defer src.Close()

	scanner := bufio.NewScanner(io.LimitReader(src, maxTargetsUploadBytes+1))
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	var specs []string
	var total int64
	for scanner.Scan() {
		line := scanner.Bytes()
		total += int64(len(line)) + 1
		if total > maxTargetsUploadBytes {
			return nil, fmt.Errorf("targets file exceeds the %d MiB limit", maxTargetsUploadBytes>>20)
		}
		text := strings.TrimSpace(string(line))
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		if strings.HasPrefix(text, "@") {
			return nil, fmt.Errorf("nested target file specs are not accepted in uploads")
		}
		specs = append(specs, text)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read targets file: %w", err)
	}
	return specs, nil
}

// mergeTargetSpecs combines textarea and uploaded targets while preserving
// order and dropping exact duplicates.
func mergeTargetSpecs(parts ...[]string) []string {
	seen := map[string]bool{}
	var out []string
	for _, part := range parts {
		for _, spec := range part {
			spec = strings.TrimSpace(spec)
			if spec == "" || seen[spec] {
				continue
			}
			seen[spec] = true
			out = append(out, spec)
		}
	}
	return out
}

// removeScanUploads deletes the uploaded files of one scan. Removal is best
// effort: a leftover file must never block deleting the database record.
func (s *Server) removeScanUploads(scanID string) {
	if s.cfg.OutputsDir == "" || !safePathSegment(scanID) {
		return
	}
	dir := filepath.Join(s.cfg.OutputsDir, uploadsDirName, scanID)
	if err := os.RemoveAll(dir); err != nil {
		s.deps.Logger.Warn("remove scan uploads", "scan_id", scanID, "error", err.Error())
	}
}

// removeScanScreenshots deletes captured images that belong to a scan. Only
// files inside the configured screenshots directory are removed, so a crafted
// database path can never delete arbitrary files.
func (s *Server) removeScanScreenshots(paths []string) {
	if s.cfg.OutputsDir == "" {
		return
	}
	base := filepath.Join(s.cfg.OutputsDir, "screenshots")
	for _, path := range paths {
		if path == "" {
			continue
		}
		rel, err := filepath.Rel(base, path)
		if err != nil || !filepath.IsLocal(rel) || strings.Contains(rel, `\`) {
			continue
		}
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			s.deps.Logger.Warn("remove scan screenshot", "path", path, "error", err.Error())
		}
	}
}

// safePathSegment reports whether a value can be used as one path element
// without traversal or separator characters.
func safePathSegment(value string) bool {
	if value == "" || value == "." || value == ".." {
		return false
	}
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '-', r == '_':
		default:
			return false
		}
	}
	return true
}
