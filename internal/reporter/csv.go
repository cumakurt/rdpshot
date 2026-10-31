package reporter

import (
	"encoding/base64"
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

// csvHeader returns a fresh header row. The field order is a public contract
// for SIEM pipelines that parse the dump by position.
func csvHeader() []string {
	return []string{
		"scan_id", "address", "port", "check_id", "title", "severity",
		"status", "cve", "cvss", "detected_at", "compliance", "evidence", "remediation",
	}
}

// screenshotCheckID marks capture inventory rows inside the findings CSV so
// SIEM pipelines can filter them while still receiving embedded image bytes.
const screenshotCheckID = "SCREENSHOT"

// CSV writes an RFC 4180 dump of findings followed by screenshot inventory
// rows. Screenshot rows reuse the findings column layout: check_id is
// SCREENSHOT, title is the caption, evidence is the on-disk path, and
// remediation carries the base64-encoded image so every export format is
// self-contained.
func CSV(w io.Writer, d Data) error {
	writer := csv.NewWriter(w)
	if err := writer.Write(csvHeader()); err != nil {
		return fmt.Errorf("write csv header: %w", err)
	}
	for _, f := range sortedFindings(d.Findings) {
		scanID := f.ScanID
		if scanID == "" {
			// Some producers leave the row-level scan ID unset; fall back to
			// the report's scan so the column is never empty.
			scanID = d.Scan.ID
		}
		var compParts []string
		for _, c := range f.Compliance {
			compParts = append(compParts, c.Standard+":"+c.Section)
		}
		record := []string{
			scanID,
			f.Address,
			strconv.FormatUint(uint64(f.Port), 10),
			f.CheckID,
			f.Title,
			string(f.Severity),
			string(f.Status),
			f.CVE,
			formatCVSS(f.CVSS),
			formatTime(f.DetectedAt),
			strings.Join(compParts, "; "),
			singleLine(f.Evidence),
			singleLine(f.Remediation),
		}
		if err := writer.Write(record); err != nil {
			return fmt.Errorf("write csv row for check %q: %w", f.CheckID, err)
		}
	}
	for _, sc := range reportScreens(d.Screens) {
		scanID := sc.ScanID
		if scanID == "" {
			scanID = d.Scan.ID
		}
		encoded, err := encodeScreenshotBase64(sc.FilePath)
		if err != nil {
			encoded = ""
		}
		record := []string{
			scanID,
			sc.Address,
			strconv.FormatUint(uint64(sc.Port), 10),
			screenshotCheckID,
			screenshotLabel(sc.Username),
			"info",
			"captured",
			"",
			"",
			formatTime(sc.CapturedAt),
			"",
			singleLine(strings.TrimSpace(sc.FilePath)),
			encoded,
		}
		if err := writer.Write(record); err != nil {
			return fmt.Errorf("write csv screenshot row for %s:%d: %w", sc.Address, sc.Port, err)
		}
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		return fmt.Errorf("flush csv output: %w", err)
	}
	return nil
}

func encodeScreenshotBase64(path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", fmt.Errorf("empty screenshot path")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	if len(data) == 0 {
		return "", fmt.Errorf("empty screenshot file")
	}
	return base64.StdEncoding.EncodeToString(data), nil
}
