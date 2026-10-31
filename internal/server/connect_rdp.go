package server

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// handleDownloadRDPConfig generates a standard Windows Remote Desktop (.rdp) configuration file.
func (s *Server) handleDownloadRDPConfig(w http.ResponseWriter, r *http.Request) {
	address := strings.TrimSpace(r.URL.Query().Get("address"))
	if address == "" {
		s.writeAPIError(w, http.StatusBadRequest, "address parameter is required")
		return
	}
	portStr := strings.TrimSpace(r.URL.Query().Get("port"))
	port := 3389
	if portStr != "" {
		if p, err := strconv.Atoi(portStr); err == nil && p > 0 && p <= 65535 {
			port = p
		}
	}
	user := strings.TrimSpace(r.URL.Query().Get("user"))
	domain := strings.TrimSpace(r.URL.Query().Get("domain"))
	if domain != "" && user != "" && !strings.Contains(user, "\\") && !strings.Contains(user, "@") {
		user = domain + "\\" + user
	}
	enableNLA := 1
	if r.URL.Query().Get("nla") == "false" || r.URL.Query().Get("nla") == "0" {
		enableNLA = 0
	}

	fullAddress := fmt.Sprintf("%s:%d", address, port)
	rdpContent := fmt.Sprintf("full address:s:%s\r\n"+
		"username:s:%s\r\n"+
		"enablecredsspsupport:i:%d\r\n"+
		"authentication level:i:2\r\n"+
		"prompt for credentials:i:0\r\n"+
		"negotiate security layer:i:1\r\n"+
		"screen mode id:i:2\r\n"+
		"use multimon:i:0\r\n"+
		"desktopwidth:i:1280\r\n"+
		"desktopheight:i:800\r\n"+
		"session bpp:i:24\r\n"+
		"compression:i:1\r\n"+
		"keyboardhook:i:2\r\n"+
		"audiomode:i:0\r\n"+
		"redirectclipboard:i:1\r\n"+
		"redirectprinters:i:0\r\n"+
		"redirectcomports:i:0\r\n"+
		"redirectsmartcards:i:0\r\n"+
		"displayconnectionbar:i:1\r\n",
		fullAddress, user, enableNLA)

	filename := fmt.Sprintf("connect-%s-%d.rdp", strings.ReplaceAll(address, ":", "_"), port)
	w.Header().Set("Content-Type", "application/x-rdp")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(rdpContent))
}
