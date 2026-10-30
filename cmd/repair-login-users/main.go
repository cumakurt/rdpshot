// Command repair-login-users re-OCRs rdp-login screenshots and rewrites
// host.service.login_users for stored scans (clears wallpaper OCR garbage).
package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"rdpshot/internal/model"
	"rdpshot/internal/screenshot"
	"rdpshot/internal/store"
)

func main() {
	dbPath := "/home/cuma/projelerim/rdpshot/outputs/rdpshot.db"
	if len(os.Args) > 1 {
		dbPath = os.Args[1]
	}
	st, err := store.Open(dbPath)
	if err != nil {
		fatal(err)
	}
	defer st.Close()

	scans, err := st.ListScans(200)
	if err != nil {
		fatal(err)
	}
	ctx := context.Background()
	updated := 0
	cleared := 0
	for _, sc := range scans {
		hosts, err := st.ListHosts(sc.ID)
		if err != nil {
			fatal(err)
		}
		shots, err := st.ListScreenshots(sc.ID)
		if err != nil {
			fatal(err)
		}
		shotByHost := map[int64]model.Screenshot{}
		for _, s := range shots {
			if s.Username != screenshot.LoginScreenLabel {
				continue
			}
			if prev, ok := shotByHost[s.HostID]; ok {
				if s.CapturedAt.After(prev.CapturedAt) {
					shotByHost[s.HostID] = s
				}
				continue
			}
			shotByHost[s.HostID] = s
		}
		for i := range hosts {
			h := hosts[i]
			if h.Service == nil {
				continue
			}
			shot, hasShot := shotByHost[h.ID]
			var users []string
			if hasShot {
				path := shot.FilePath
				if path == "" || !filepath.IsAbs(path) {
					fmt.Fprintf(os.Stderr, "skip non-absolute shot path %q\n", path)
				} else if _, err := os.Stat(path); err != nil {
					fmt.Fprintf(os.Stderr, "missing shot %s: %v\n", path, err)
				} else {
					users, err = screenshot.ExtractLoginUsersOCR(ctx, path)
					if err != nil {
						fmt.Fprintf(os.Stderr, "OCR %s: %v\n", path, err)
						users = nil
					}
				}
			}
			prev := append([]string(nil), h.Service.LoginUsers...)
			needClearEvidence := len(users) == 0 && h.Service.Evidence != nil && h.Service.Evidence["login_users"] != ""
			if equalUsers(prev, users) && !needClearEvidence {
				continue
			}
			if len(users) > 0 {
				h.Service.LoginUsers = users
				if h.Service.Evidence == nil {
					h.Service.Evidence = map[string]string{}
				}
				h.Service.Evidence["login_users"] = strings.Join(users, ", ")
				h.Service.Evidence["login_screen"] = "ssl-tls"
				updated++
				fmt.Printf("set %s %s -> %v\n", sc.ID, h.Endpoint.Address, users)
			} else {
				h.Service.LoginUsers = nil
				if h.Service.Evidence != nil {
					delete(h.Service.Evidence, "login_users")
				}
				cleared++
				fmt.Printf("clear %s %s (was %v)\n", sc.ID, h.Endpoint.Address, prev)
			}
			h.UpdatedAt = time.Now().UTC()
			if _, err := st.UpsertHost(h); err != nil {
				fatal(err)
			}
		}
	}
	fmt.Printf("done updated=%d cleared=%d\n", updated, cleared)
}

func equalUsers(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "repair-login-users: %v\n", err)
	os.Exit(1)
}
