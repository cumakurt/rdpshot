package reporter

import (
	"encoding/csv"
	"fmt"
	"io"
	"strconv"
)

// csvHeader returns a fresh header row. The field order is a public contract
// for SIEM pipelines that parse the dump by position.
func csvHeader() []string {
	return []string{
		"scan_id", "address", "port", "check_id", "title", "severity",
		"status", "cve", "cvss", "detected_at", "evidence", "remediation",
	}
}

// CSV writes an RFC 4180 findings dump for SIEM ingestion.
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
			singleLine(f.Evidence),
			singleLine(f.Remediation),
		}
		if err := writer.Write(record); err != nil {
			return fmt.Errorf("write csv row for check %q: %w", f.CheckID, err)
		}
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		return fmt.Errorf("flush csv output: %w", err)
	}
	return nil
}
