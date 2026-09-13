// Package handlers contains the HTTP layer: routing, session handling, and
// request handlers. All state is held on Server rather than in package-level
// variables, so a test can stand up an isolated instance.
package handlers

import (
	"bytes"
	"database/sql"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"time"

	"github.com/pdxiv/blunderbytes.com/v2/config"
)

const (
	sessionCookieName = "session_token"
	csrfCookieName    = "csrf_token"
	// sessionTokenBytes is the entropy of a session token before hex encoding.
	sessionTokenBytes = 32
	// imageCacheBudget caps memory held by encoded uploads.
	imageCacheBudget = 64 << 20
)

// Server holds every dependency the HTTP handlers need.
type Server struct {
	cfg       config.Config
	db        *sql.DB
	mux       *http.ServeMux
	templates map[string]*template.Template
	assets    *staticAssets
	images    *imageCache
	logins    *rateLimiter
}

// TemplateData is the view model shared by every page.
type TemplateData struct {
	Title        string
	IsLoggedIn   bool
	Username     string
	CSRFToken    string
	ErrorMessage string
	BlogEntries  []BlogEntry
	Pagination   Pagination
	Assets       *staticAssets
}

// BlogEntry is one rendered post.
type BlogEntry struct {
	ID        int
	Title     string
	Content   template.HTML
	Author    string
	CreatedAt time.Time
	ImageURI  template.URL
}

// Pagination describes the current position in the post list.
type Pagination struct {
	Page     int
	HasPrev  bool
	HasNext  bool
	PrevPage int
	NextPage int
}

// New builds a Server. It parses templates and encodes static assets up front
// so that a misconfigured deployment fails at startup rather than per request.
func New(cfg config.Config, database *sql.DB, templateFS, staticFiles fs.FS) (*Server, error) {
	templateSets := map[string][]string{
		"index":  {"templates/layout.html", "templates/navbar.html", "templates/index.html"},
		"login":  {"templates/layout.html", "templates/navbar.html", "templates/login.html"},
		"upload": {"templates/layout.html", "templates/navbar.html", "templates/upload.html"},
	}

	templates := make(map[string]*template.Template, len(templateSets))
	for name, paths := range templateSets {
		parsed, err := template.New(name).ParseFS(templateFS, paths...)
		if err != nil {
			return nil, fmt.Errorf("parsing templates for %q: %w", name, err)
		}
		templates[name] = parsed
	}

	staticFS, err := embeddedSubFS(staticFiles, "static")
	if err != nil {
		return nil, err
	}

	assets, err := loadStaticAssets(staticFS)
	if err != nil {
		return nil, err
	}

	server := &Server{
		cfg:       cfg,
		db:        database,
		mux:       http.NewServeMux(),
		templates: templates,
		assets:    assets,
		images:    newImageCache(imageCacheBudget),
		logins:    newRateLimiter(5, 15*time.Minute),
	}

	server.routes(staticFS)
	return server, nil
}

// routes registers every handler on the server's own mux. Nothing touches
// http.DefaultServeMux, so constructing two Servers in one process is safe.
func (s *Server) routes(staticFS fs.FS) {
	s.mux.HandleFunc("/", s.handleHome)
	s.mux.HandleFunc("/login", s.handleLogin)
	s.mux.HandleFunc("/logout", s.handleLogout)
	s.mux.Handle("/new", s.requireSession(http.HandlerFunc(s.handleNew)))
	s.mux.Handle("/upload", s.requireSession(http.HandlerFunc(s.handleUpload)))

	// Uploaded files stay available as ordinary URLs alongside the inlined
	// copies, so they can be linked from post text.
	s.mux.Handle("/uploads/", http.StripPrefix("/uploads/",
		http.FileServer(http.Dir(s.cfg.UploadsDir))))
	s.mux.Handle("/static/", http.StripPrefix("/static/",
		http.FileServer(http.FS(staticFS))))
}

// ServeHTTP makes Server an http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

// newTemplateData builds the data common to every page, including the CSRF
// token for the current visitor.
func (s *Server) newTemplateData(w http.ResponseWriter, r *http.Request, title string) TemplateData {
	isLoggedIn, username := s.currentUser(r)
	return TemplateData{
		Title:      title,
		IsLoggedIn: isLoggedIn,
		Username:   username,
		CSRFToken:  s.ensureCSRFToken(w, r),
		Assets:     s.assets,
	}
}

// render executes a template into a buffer before writing anything to the
// client, so a template failure produces a clean 500 rather than a truncated
// page with a 200 status.
func (s *Server) render(w http.ResponseWriter, status int, name string, data TemplateData) {
	tmpl, ok := s.templates[name]
	if !ok {
		s.serverError(w, fmt.Errorf("unknown template %q", name))
		return
	}

	var buffer bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buffer, "layout.html", data); err != nil {
		s.serverError(w, fmt.Errorf("executing template %q: %w", name, err))
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if _, err := buffer.WriteTo(w); err != nil {
		logf("writing response: %v", err)
	}
}

// serverError logs the detail and returns a generic message to the client.
func (s *Server) serverError(w http.ResponseWriter, err error) {
	logf("server error: %v", err)
	http.Error(w, "Internal Server Error", http.StatusInternalServerError)
}
