package handlers

import (
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"time"
)

// randomToken returns a hex-encoded cryptographically random token.
func randomToken(byteLength int) (string, error) {
	buffer := make([]byte, byteLength)
	if _, err := rand.Read(buffer); err != nil {
		return "", fmt.Errorf("generating random token: %w", err)
	}
	return hex.EncodeToString(buffer), nil
}

// lookupSession returns the username owning a valid, unexpired session token.
// Expiry is checked in the query itself, so no caller can accidentally accept
// a stale token.
func (s *Server) lookupSession(token string) (string, bool) {
	if token == "" {
		return "", false
	}

	var username string
	err := s.db.QueryRow(
		"SELECT username FROM sessions WHERE token = ? AND expires > datetime('now')",
		token,
	).Scan(&username)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return "", false
	case err != nil:
		logf("looking up session: %v", err)
		return "", false
	}
	return username, true
}

// currentUser reports whether the request carries a valid session.
func (s *Server) currentUser(r *http.Request) (bool, string) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return false, ""
	}
	username, ok := s.lookupSession(cookie.Value)
	return ok, username
}

// startSession issues a fresh token for username and sets the session cookie.
// A new token is minted on every login, so a token observed before
// authentication cannot be reused afterwards (session fixation).
func (s *Server) startSession(w http.ResponseWriter, username string) error {
	token, err := randomToken(sessionTokenBytes)
	if err != nil {
		return err
	}

	expiresAt := time.Now().Add(s.cfg.SessionLifetime)
	if _, err := s.db.Exec(
		"INSERT INTO sessions (username, token, expires) VALUES (?, ?, ?)",
		username, token, expiresAt.UTC(),
	); err != nil {
		return fmt.Errorf("storing session: %w", err)
	}

	http.SetCookie(w, s.sessionCookie(token, expiresAt, int(s.cfg.SessionLifetime.Seconds())))
	return nil
}

// endSession deletes the session row and clears the cookie.
func (s *Server) endSession(w http.ResponseWriter, token string) {
	if token != "" {
		if _, err := s.db.Exec("DELETE FROM sessions WHERE token = ?", token); err != nil {
			logf("deleting session: %v", err)
		}
	}
	http.SetCookie(w, s.sessionCookie("", time.Unix(0, 0), -1))
}

// sessionCookie builds the session cookie with consistent security attributes.
// Path is set explicitly so that the logout cookie reliably matches the one
// login created.
func (s *Server) sessionCookie(value string, expires time.Time, maxAge int) *http.Cookie {
	return &http.Cookie{
		Name:     sessionCookieName,
		Value:    value,
		Path:     "/",
		Expires:  expires,
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   s.cfg.SecureCookies,
		SameSite: http.SameSiteLaxMode,
	}
}

// ensureCSRFToken returns the visitor's CSRF token, minting one if needed.
// The token lives in a cookie and is echoed into every form; a cross-site
// POST can neither read the cookie nor guess the value.
func (s *Server) ensureCSRFToken(w http.ResponseWriter, r *http.Request) string {
	if cookie, err := r.Cookie(csrfCookieName); err == nil && len(cookie.Value) == sessionTokenBytes*2 {
		return cookie.Value
	}

	token, err := randomToken(sessionTokenBytes)
	if err != nil {
		logf("generating CSRF token: %v", err)
		return ""
	}

	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.cfg.SecureCookies,
		SameSite: http.SameSiteLaxMode,
	})
	return token
}

// checkCSRF validates the submitted token against the cookie in constant time.
func (s *Server) checkCSRF(r *http.Request) bool {
	cookie, err := r.Cookie(csrfCookieName)
	if err != nil || cookie.Value == "" {
		return false
	}
	submitted := r.PostFormValue(csrfFieldName)
	if submitted == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(submitted)) == 1
}
