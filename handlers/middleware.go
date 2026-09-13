package handlers

import (
	"log"
	"net/http"
	"time"
)

// csrfFieldName is the hidden form field carrying the CSRF token.
const csrfFieldName = "csrf_token"

// logf is the package's logging entry point, kept in one place so output can
// be redirected in tests.
var logf = log.Printf

// requireSession rejects requests without a valid session. Browsers get a
// redirect to the login page; anything else gets a 401.
func (s *Server) requireSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ok, _ := s.currentUser(r); !ok {
			if r.Method == http.MethodGet || r.Method == http.MethodHead {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// statusRecorder captures the response status for the access log.
type statusRecorder struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (r *statusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	n, err := r.ResponseWriter.Write(b)
	r.bytes += n
	return n, err
}

// LogRequests writes one access-log line per request.
func LogRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		recorder := &statusRecorder{ResponseWriter: w}

		next.ServeHTTP(recorder, r)

		if recorder.status == 0 {
			recorder.status = http.StatusOK
		}
		logf("%s %s %s %d %dB %s",
			clientIP(r), r.Method, r.URL.Path,
			recorder.status, recorder.bytes, time.Since(started).Round(time.Millisecond))
	})
}

// SecurityHeaders sets conservative defaults. The content security policy
// allows inline styles and data: images because the page deliberately inlines
// both, but forbids scripts entirely; the site uses none.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := w.Header()
		header.Set("X-Content-Type-Options", "nosniff")
		header.Set("X-Frame-Options", "DENY")
		header.Set("Referrer-Policy", "same-origin")
		header.Set("Content-Security-Policy",
			"default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "+
				"script-src 'none'; object-src 'none'; base-uri 'none'; form-action 'self'; "+
				"frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}
