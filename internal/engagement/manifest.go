// Package engagement builds immutable evidence manifests with content hashes.
package engagement

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"time"

	"rdpshot/internal/model"
)

// FileEntry is one hashed artifact in the delivery pack.
type FileEntry struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
}

// Manifest is the signed-delivery checklist for an engagement pack.
type Manifest struct {
	Version        string      `json:"version"`
	Generated      time.Time   `json:"generated_at"`
	Engagement     string      `json:"engagement,omitempty"`
	ScanID         string      `json:"scan_id"`
	ScanName       string      `json:"scan_name"`
	Files          []FileEntry `json:"files"`
	ManifestSHA256 string      `json:"manifest_sha256"`
}

// BuildManifest hashes named file contents and returns a self-describing manifest.
func BuildManifest(scan model.Scan, files map[string][]byte) (Manifest, error) {
	m := Manifest{
		Version:    PackVersion,
		Generated:  time.Now().UTC(),
		Engagement: scan.Engagement,
		ScanID:     scan.ID,
		ScanName:   scan.Name,
	}
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		body := files[name]
		sum := sha256.Sum256(body)
		m.Files = append(m.Files, FileEntry{
			Path:   name,
			SHA256: hex.EncodeToString(sum[:]),
			Bytes:  int64(len(body)),
		})
	}
	// Hash the file list without the self hash field.
	type wire struct {
		Version    string      `json:"version"`
		Generated  time.Time   `json:"generated_at"`
		Engagement string      `json:"engagement,omitempty"`
		ScanID     string      `json:"scan_id"`
		ScanName   string      `json:"scan_name"`
		Files      []FileEntry `json:"files"`
	}
	raw, err := json.Marshal(wire{
		Version: m.Version, Generated: m.Generated, Engagement: m.Engagement,
		ScanID: m.ScanID, ScanName: m.ScanName, Files: m.Files,
	})
	if err != nil {
		return Manifest{}, err
	}
	sum := sha256.Sum256(raw)
	m.ManifestSHA256 = hex.EncodeToString(sum[:])
	return m, nil
}

// HashFile returns the SHA-256 of a filesystem path.
func HashFile(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

// FreezeScope captures the engagement target list at a point in time.
type FreezeScope struct {
	Engagement string    `json:"engagement"`
	FrozenAt   time.Time `json:"frozen_at"`
	Targets    []string  `json:"targets"`
	Ports      []uint16  `json:"ports,omitempty"`
	ScanID     string    `json:"scan_id,omitempty"`
	Note       string    `json:"note,omitempty"`
}

// ScopeKey returns the settings key for a frozen engagement scope.
func ScopeKey(engagement string) string {
	return fmt.Sprintf("engagement_scope:%s", engagement)
}
