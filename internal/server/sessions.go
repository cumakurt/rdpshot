package server

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"time"

	"rdpshot/internal/model"
)

// session is an in-memory login session for a local portal user.
type session struct {
	Token    string
	UserID   string
	Username string
	Role     model.UserRole
	Expires  time.Time
}

func (s *Server) createSession(user model.User) string {
	var buf [24]byte
	_, _ = rand.Read(buf[:])
	token := hex.EncodeToString(buf[:])
	s.sessionsMu.Lock()
	defer s.sessionsMu.Unlock()
	if s.sessions == nil {
		s.sessions = make(map[string]*session)
	}
	s.sessions[token] = &session{
		Token:    token,
		UserID:   user.ID,
		Username: user.Username,
		Role:     user.Role,
		Expires:  time.Now().UTC().Add(12 * time.Hour),
	}
	return token
}

func (s *Server) revokeSessionsForUser(userID string) {
	s.sessionsMu.Lock()
	defer s.sessionsMu.Unlock()
	for token, sess := range s.sessions {
		if sess.UserID == userID {
			delete(s.sessions, token)
		}
	}
}

func (s *Server) sessionFromRequest(r *http.Request) *session {
	token := tokenFromRequest(r)
	if token == "" {
		if c, err := r.Cookie("rdpshot_session"); err == nil {
			token = c.Value
		}
	}
	if token == "" {
		return nil
	}
	s.sessionsMu.Lock()
	defer s.sessionsMu.Unlock()
	sess := s.sessions[token]
	if sess == nil {
		return nil
	}
	if time.Now().UTC().After(sess.Expires) {
		delete(s.sessions, token)
		return nil
	}
	return sess
}

func (s *Server) requireWrite(w http.ResponseWriter, r *http.Request) bool {
	if s.cfg.Token != "" {
		got := tokenFromRequest(r)
		want := sha256.Sum256([]byte(s.cfg.Token))
		hash := sha256.Sum256([]byte(got))
		if subtle.ConstantTimeCompare(hash[:], want[:]) == 1 {
			return true
		}
	}
	sess := s.sessionFromRequest(r)
	if sess != nil && sess.Role.CanWrite() {
		return true
	}
	n, err := s.deps.Store.UserCount()
	if err != nil || n == 0 {
		// No local users configured: preserve open localhost / token-only mode.
		return true
	}
	s.writeAPIError(w, http.StatusForbidden, "operator role required")
	return false
}
