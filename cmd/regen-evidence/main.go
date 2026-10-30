// Command regen-evidence rewrites open-host detection PNGs from the local DB.
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"

	"rdpshot/internal/model"
	"rdpshot/internal/screenshot"
)

func main() {
	dbPath := "outputs/rdpshot.db"
	if len(os.Args) > 1 {
		dbPath = os.Args[1]
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		fatal(err)
	}
	defer db.Close()

	rows, err := db.Query(`
		SELECT s.address, s.port, s.file_path, COALESCE(h.service_json, '')
		FROM screenshots s
		LEFT JOIN hosts h ON h.id = s.host_id
		WHERE s.username = 'rdp-open'`)
	if err != nil {
		fatal(err)
	}
	defer rows.Close()

	n := 0
	for rows.Next() {
		var address, filePath, serviceJSON string
		var port int
		if err := rows.Scan(&address, &port, &filePath, &serviceJSON); err != nil {
			fatal(err)
		}
		var svc *model.ServiceInfo
		if serviceJSON != "" {
			svc = &model.ServiceInfo{}
			if err := json.Unmarshal([]byte(serviceJSON), svc); err != nil {
				fatal(fmt.Errorf("%s: %w", address, err))
			}
		}
		dir := filepath.Dir(filePath)
		grabber := screenshot.NewEvidenceGrabber(dir)
		shot, err := grabber.GrabOpenHost(context.Background(), model.Endpoint{
			Address: address,
			Port:    uint16(port),
		}, svc)
		if err != nil {
			fatal(err)
		}
		if err := replaceFile(shot.FilePath, filePath); err != nil {
			fatal(err)
		}
		fmt.Println(filePath)
		n++
	}
	if err := rows.Err(); err != nil {
		fatal(err)
	}
	fmt.Fprintf(os.Stderr, "regenerated %d detection evidence image(s)\n", n)
}

func replaceFile(src, dst string) error {
	if err := os.Rename(src, dst); err == nil {
		return nil
	}
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	if err := os.WriteFile(dst, data, 0o600); err != nil {
		return err
	}
	return os.Remove(src)
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "regen-evidence: %v\n", err)
	os.Exit(1)
}
