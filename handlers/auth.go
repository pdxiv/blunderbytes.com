package handlers

import (
	"database/sql"
	"errors"
	"net/http"

	"golang.org/x/crypto/bcrypt"
)

// dummyHash is compared against when the submitted username does not exist, so
// that a missing user costs the same time as a wrong password and cannot be
// distinguished by timing.
var dummyHash []byte

func init() {
	hash, err := bcrypt.GenerateFromPassword([]byte("not-a-real-password"), bcrypt.DefaultCost)
	if err != nil {
		panic("handlers: generating dummy bcrypt hash: " + err.Error())
	}
	dummyHash = hash
}

// handleLogin shows the login form and processes submissions.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		data := s.newTemplateData(w, r, "Login")
		s.render(w, http.StatusOK, "login", data)
	case http.MethodPost:
		s.processLogin(w, r)
	default:
		w.Header().Set("Allow", "GET, HEAD, POST")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) processLogin(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Malformed form submission", http.StatusBadRequest)
		return
	}
	if !s.checkCSRF(r) {
		http.Error(w, "Invalid or missing CSRF token", http.StatusForbidden)
		return
	}

	// Usernames are identifiers and are normalised. Passwords are passed to
	// bcrypt exactly as typed: filtering them would silently collapse distinct
	// passwords onto the same value.
	username := sanitizeUsername(r.PostFormValue("username"))
	password := r.PostFormValue("password")

	ipKey := "ip:" + clientIP(r)
	userKey := "user:" + username
	if s.logins.blocked(ipKey) || s.logins.blocked(userKey) {
		http.Error(w, "Too many login attempts. Try again later.", http.StatusTooManyRequests)
		return
	}

	hashedPassword, err := s.passwordHash(username)
	if err != nil {
		s.serverError(w, err)
		return
	}

	// Always run a comparison, even for an unknown user.
	compareAgainst := hashedPassword
	if compareAgainst == nil {
		compareAgainst = dummyHash
	}
	compareErr := bcrypt.CompareHashAndPassword(compareAgainst, []byte(password))

	if hashedPassword == nil || compareErr != nil {
		s.logins.fail(ipKey)
		s.logins.fail(userKey)
		data := s.newTemplateData(w, r, "Login")
		data.ErrorMessage = "Invalid login credentials."
		s.render(w, http.StatusUnauthorized, "login", data)
		return
	}

	s.logins.reset(ipKey)
	s.logins.reset(userKey)

	// Drop any session the visitor already carried before issuing a new one,
	// so a token planted before login cannot survive it.
	if cookie, err := r.Cookie(sessionCookieName); err == nil {
		s.endSession(w, cookie.Value)
	}

	if err := s.startSession(w, username); err != nil {
		s.serverError(w, err)
		return
	}

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// passwordHash returns the stored hash for username, or nil when no such user
// exists. A nil hash is not an error.
func (s *Server) passwordHash(username string) ([]byte, error) {
	if username == "" {
		return nil, nil
	}

	var hashedPassword []byte
	err := s.db.QueryRow(
		"SELECT hashed_password FROM users WHERE username = ?", username,
	).Scan(&hashedPassword)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return nil, nil
	case err != nil:
		return nil, err
	}
	return hashedPassword, nil
}

// handleLogout invalidates the session. It is POST-only with a CSRF check so
// that a third-party page cannot forcibly log the user out.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Malformed form submission", http.StatusBadRequest)
		return
	}
	if !s.checkCSRF(r) {
		http.Error(w, "Invalid or missing CSRF token", http.StatusForbidden)
		return
	}

	if cookie, err := r.Cookie(sessionCookieName); err == nil {
		s.endSession(w, cookie.Value)
	}

	http.Redirect(w, r, "/", http.StatusSeeOther)
}
