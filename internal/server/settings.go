package server

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"rdpshot/internal/brute"
)

// wordlistSettings is the JSON body of GET/PATCH /api/v1/settings/wordlists.
type wordlistSettings struct {
	UserWordlist     string `json:"user_wordlist"`
	PasswordWordlist string `json:"password_wordlist"`
}

// handleGetWordlistSettings returns the runtime default wordlist paths.
func (s *Server) handleGetWordlistSettings(w http.ResponseWriter, r *http.Request) {
	userPath, passwordPath := s.wordlistDefaults()
	s.writeJSON(w, http.StatusOK, wordlistSettings{
		UserWordlist:     userPath,
		PasswordWordlist: passwordPath,
	})
}

// handleUpdateWordlistSettings updates the runtime default wordlist paths used
// by the UI and by auth-enabled scans that do not upload a file.
func (s *Server) handleUpdateWordlistSettings(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
	var payload wordlistSettings
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		s.writeAPIError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	userPath := strings.TrimSpace(payload.UserWordlist)
	passwordPath := strings.TrimSpace(payload.PasswordWordlist)
	if userPath == "" || passwordPath == "" {
		s.writeAPIError(w, http.StatusBadRequest, "user_wordlist and password_wordlist are required")
		return
	}
	if err := validateWordlistPath(userPath); err != nil {
		s.writeAPIError(w, http.StatusBadRequest, "user_wordlist: "+err.Error())
		return
	}
	if err := validateWordlistPath(passwordPath); err != nil {
		s.writeAPIError(w, http.StatusBadRequest, "password_wordlist: "+err.Error())
		return
	}
	if _, err := brute.LoadWordlist(userPath); err != nil {
		s.writeAPIError(w, http.StatusBadRequest, "user_wordlist: "+err.Error())
		return
	}
	if _, err := brute.LoadWordlist(passwordPath); err != nil {
		s.writeAPIError(w, http.StatusBadRequest, "password_wordlist: "+err.Error())
		return
	}

	s.setWordlistDefaults(userPath, passwordPath)
	s.deps.Logger.Info("wordlist defaults updated",
		"user_wordlist", userPath, "password_wordlist", passwordPath)
	s.writeJSON(w, http.StatusOK, wordlistSettings{
		UserWordlist:     userPath,
		PasswordWordlist: passwordPath,
	})
}

func validateWordlistPath(path string) error {
	if utf8.RuneCountInString(path) > 512 {
		return errWordlistPathTooLong
	}
	cleaned := filepath.Clean(path)
	if cleaned == "." || cleaned == "" {
		return errWordlistPathInvalid
	}
	return nil
}

type wordlistPathError string

func (e wordlistPathError) Error() string { return string(e) }

const (
	errWordlistPathTooLong  wordlistPathError = "path is too long"
	errWordlistPathInvalid  wordlistPathError = "path is invalid"
)
