package handlers

import (
	"bytes"
	"database/sql"
	"html"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pdxiv/blunderbytes.com/v2/config"
	"github.com/pdxiv/blunderbytes.com/v2/db"
)

const (
	testUsername = "tester"
	testPassword = "correct horse battery staple $%&"
)

// pngBytes is a minimal valid 1x1 PNG, used wherever a real image is needed.
var pngBytes = []byte{
	0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a,
	0x00, 0x00, 0x00, 0x0d, 'I', 'H', 'D', 'R',
	0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
	0x08, 0x06, 0x00, 0x00, 0x00, 0x1f, 0x15, 0xc4,
	0x89, 0x00, 0x00, 0x00, 0x0a, 'I', 'D', 'A', 'T',
	0x78, 0x9c, 0x63, 0x00, 0x01, 0x00, 0x00, 0x05,
	0x00, 0x01, 0x0d, 0x0a, 0x2d, 0xb4, 0x00, 0x00,
	0x00, 0x00, 'I', 'E', 'N', 'D', 0xae, 0x42, 0x60, 0x82,
}

// newTestServer builds a Server backed by a temporary database and uploads
// directory. Templates and static files are read from the repository root.
func newTestServer(t *testing.T) (*Server, *sql.DB, string) {
	t.Helper()

	tempDir := t.TempDir()
	uploadsDir := filepath.Join(tempDir, "uploads")

	database, err := db.Open(db.Options{
		Path:              filepath.Join(tempDir, "test.db"),
		BootstrapUsername: testUsername,
		BootstrapPassword: testPassword,
	})
	if err != nil {
		t.Fatalf("opening test database: %v", err)
	}
	t.Cleanup(func() { database.Close() })

	cfg := config.Config{
		Addr:            ":0",
		DBPath:          filepath.Join(tempDir, "test.db"),
		UploadsDir:      uploadsDir,
		SessionLifetime: time.Hour,
		MaxUploadBytes:  1 << 20,
		PostsPerPage:    2,
		SecureCookies:   false,
	}

	repoRoot := os.DirFS("..")
	server, err := New(cfg, database, repoRoot, repoRoot)
	if err != nil {
		t.Fatalf("building server: %v", err)
	}

	return server, database, uploadsDir
}

// login performs a real login and returns the resulting cookies.
func login(t *testing.T, server *Server) []*http.Cookie {
	t.Helper()

	// Fetch the form first to obtain a CSRF token.
	formRequest := httptest.NewRequest(http.MethodGet, "/login", nil)
	formResponse := httptest.NewRecorder()
	server.ServeHTTP(formResponse, formRequest)

	cookies := formResponse.Result().Cookies()
	csrfToken := cookieValue(cookies, csrfCookieName)
	if csrfToken == "" {
		t.Fatal("login form did not set a CSRF cookie")
	}

	form := url.Values{
		"username":    {testUsername},
		"password":    {testPassword},
		csrfFieldName: {csrfToken},
	}
	request := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}

	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)

	if response.Code != http.StatusSeeOther {
		t.Fatalf("login returned %d, want %d: %s", response.Code, http.StatusSeeOther, response.Body)
	}

	return append(cookies, response.Result().Cookies()...)
}

func cookieValue(cookies []*http.Cookie, name string) string {
	for _, cookie := range cookies {
		if cookie.Name == name && cookie.Value != "" {
			return cookie.Value
		}
	}
	return ""
}

func TestUnknownPathIs404(t *testing.T) {
	server, _, _ := newTestServer(t)

	// "/" matches everything unrouted, so this used to render the home page.
	request := httptest.NewRequest(http.MethodGet, "/no-such-page", nil)
	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)

	if response.Code != http.StatusNotFound {
		t.Errorf("got %d, want %d", response.Code, http.StatusNotFound)
	}
}

func TestHomeRenders(t *testing.T) {
	server, _, _ := newTestServer(t)

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("got %d, want 200: %s", response.Code, response.Body)
	}
	if !strings.Contains(response.Body.String(), "No posts yet") {
		t.Error("expected the empty-state message")
	}
}

func TestPasswordIsNotMangledBeforeComparison(t *testing.T) {
	// The password contains spaces and symbols that the old sanitiser removed.
	server, _, _ := newTestServer(t)
	cookies := login(t, server)

	if cookieValue(cookies, sessionCookieName) == "" {
		t.Fatal("no session cookie was issued")
	}
}

func TestLoginRejectsPasswordThatOnlyMatchesAfterStripping(t *testing.T) {
	server, _, _ := newTestServer(t)

	formRequest := httptest.NewRequest(http.MethodGet, "/login", nil)
	formResponse := httptest.NewRecorder()
	server.ServeHTTP(formResponse, formRequest)
	cookies := formResponse.Result().Cookies()

	// Stripping spaces and symbols would have made this equal to the real one.
	form := url.Values{
		"username":    {testUsername},
		"password":    {"correcthorsebatterystaple"},
		csrfFieldName: {cookieValue(cookies, csrfCookieName)},
	}
	request := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}

	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)

	if response.Code != http.StatusUnauthorized {
		t.Errorf("got %d, want %d", response.Code, http.StatusUnauthorized)
	}
}

func TestLoginWithoutCSRFTokenIsRejected(t *testing.T) {
	server, _, _ := newTestServer(t)

	form := url.Values{"username": {testUsername}, "password": {testPassword}}
	request := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)

	if response.Code != http.StatusForbidden {
		t.Errorf("got %d, want %d", response.Code, http.StatusForbidden)
	}
}

func TestLoginIsRateLimited(t *testing.T) {
	server, _, _ := newTestServer(t)

	formRequest := httptest.NewRequest(http.MethodGet, "/login", nil)
	formResponse := httptest.NewRecorder()
	server.ServeHTTP(formResponse, formRequest)
	cookies := formResponse.Result().Cookies()
	csrfToken := cookieValue(cookies, csrfCookieName)

	var lastCode int
	for attempt := 0; attempt < 8; attempt++ {
		form := url.Values{
			"username":    {testUsername},
			"password":    {"wrong"},
			csrfFieldName: {csrfToken},
		}
		request := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.RemoteAddr = "192.0.2.10:1234"
		for _, cookie := range cookies {
			request.AddCookie(cookie)
		}

		response := httptest.NewRecorder()
		server.ServeHTTP(response, request)
		lastCode = response.Code
	}

	if lastCode != http.StatusTooManyRequests {
		t.Errorf("got %d after repeated failures, want %d", lastCode, http.StatusTooManyRequests)
	}
}

func TestSessionIsRotatedOnLogin(t *testing.T) {
	server, _, _ := newTestServer(t)

	first := cookieValue(login(t, server), sessionCookieName)
	second := cookieValue(login(t, server), sessionCookieName)

	if first == "" || second == "" {
		t.Fatal("expected session tokens")
	}
	if first == second {
		t.Error("login reused the previous session token")
	}
}

func TestSessionCookieHasSecurityAttributes(t *testing.T) {
	server, _, _ := newTestServer(t)
	server.cfg.SecureCookies = true

	var sessionCookie *http.Cookie
	for _, cookie := range login(t, server) {
		if cookie.Name == sessionCookieName && cookie.Value != "" {
			sessionCookie = cookie
		}
	}
	if sessionCookie == nil {
		t.Fatal("no session cookie")
	}

	if !sessionCookie.HttpOnly {
		t.Error("session cookie is not HttpOnly")
	}
	if !sessionCookie.Secure {
		t.Error("session cookie is not Secure")
	}
	if sessionCookie.SameSite != http.SameSiteLaxMode {
		t.Error("session cookie is not SameSite=Lax")
	}
	if sessionCookie.Path != "/" {
		t.Errorf("session cookie path is %q, want /", sessionCookie.Path)
	}
}

func TestExpiredSessionIsRejected(t *testing.T) {
	server, database, _ := newTestServer(t)
	cookies := login(t, server)
	token := cookieValue(cookies, sessionCookieName)

	if _, err := database.Exec(
		"UPDATE sessions SET expires = datetime('now', '-1 hour') WHERE token = ?", token,
	); err != nil {
		t.Fatalf("expiring session: %v", err)
	}

	if ok, _ := server.currentUser(requestWithCookies("/", cookies)); ok {
		t.Error("an expired session was accepted")
	}

	removed, err := db.DeleteExpiredSessions(database)
	if err != nil {
		t.Fatalf("sweeping sessions: %v", err)
	}
	if removed != 1 {
		t.Errorf("sweep removed %d rows, want 1", removed)
	}
}

func requestWithCookies(target string, cookies []*http.Cookie) *http.Request {
	request := httptest.NewRequest(http.MethodGet, target, nil)
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	return request
}

func TestNewRequiresLogin(t *testing.T) {
	server, _, _ := newTestServer(t)

	request := httptest.NewRequest(http.MethodGet, "/new", nil)
	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)

	if response.Code != http.StatusSeeOther {
		t.Errorf("got %d, want a redirect to /login", response.Code)
	}
}

// uploadRequest builds a multipart post request with the given image filename.
func uploadRequest(t *testing.T, cookies []*http.Cookie, filename, title string, imageData []byte) *http.Request {
	t.Helper()

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)

	if err := writer.WriteField(csrfFieldName, cookieValue(cookies, csrfCookieName)); err != nil {
		t.Fatal(err)
	}
	if err := writer.WriteField("title", title); err != nil {
		t.Fatal(err)
	}
	if err := writer.WriteField("content", "some **content**"); err != nil {
		t.Fatal(err)
	}

	part, err := writer.CreateFormFile("file", filename)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write(imageData); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodPost, "/upload", &body)
	request.Header.Set("Content-Type", writer.FormDataContentType())
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	return request
}

func TestUploadIgnoresClientFilenameAndCannotEscapeUploadsDir(t *testing.T) {
	server, _, uploadsDir := newTestServer(t)
	cookies := login(t, server)

	// "a/../../escaped.png" previously resolved outside the uploads directory.
	request := uploadRequest(t, cookies, "a/../../escaped.png", "Traversal", pngBytes)
	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)

	if response.Code != http.StatusSeeOther {
		t.Fatalf("upload returned %d: %s", response.Code, response.Body)
	}

	parent := filepath.Dir(filepath.Dir(uploadsDir))
	for _, candidate := range []string{
		filepath.Join(parent, "escaped.png"),
		filepath.Join(filepath.Dir(uploadsDir), "escaped.png"),
	} {
		if _, err := os.Stat(candidate); err == nil {
			t.Errorf("upload escaped to %s", candidate)
		}
	}

	entries, err := os.ReadDir(uploadsDir)
	if err != nil {
		t.Fatalf("reading uploads dir: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("got %d files in uploads dir, want 1", len(entries))
	}
	if name := entries[0].Name(); strings.ContainsAny(name, `/\`) || !strings.HasSuffix(name, ".png") {
		t.Errorf("stored filename %q is not a safe generated name", name)
	}
}

func TestUploadRejectsNonImageRegardlessOfDeclaredType(t *testing.T) {
	server, _, _ := newTestServer(t)
	cookies := login(t, server)

	// Content-Type in the multipart part claims PNG; the bytes are a script.
	request := uploadRequest(t, cookies, "payload.png",
		"Not an image", []byte("<?php system($_GET['c']); ?>"))
	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest {
		t.Errorf("got %d, want %d: %s", response.Code, http.StatusBadRequest, response.Body)
	}
}

func TestUploadRequiresCSRFToken(t *testing.T) {
	server, _, _ := newTestServer(t)
	cookies := login(t, server)

	// Strip the CSRF cookie so the submitted field cannot match.
	var sessionOnly []*http.Cookie
	for _, cookie := range cookies {
		if cookie.Name == sessionCookieName {
			sessionOnly = append(sessionOnly, cookie)
		}
	}

	request := uploadRequest(t, sessionOnly, "image.png", "No token", pngBytes)
	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)

	if response.Code != http.StatusForbidden {
		t.Errorf("got %d, want %d", response.Code, http.StatusForbidden)
	}
}

func TestUploadThenRenderRoundTrip(t *testing.T) {
	server, _, _ := newTestServer(t)
	cookies := login(t, server)

	request := uploadRequest(t, cookies, "whatever.png", "Røde lamper", pngBytes)
	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther {
		t.Fatalf("upload returned %d: %s", response.Code, response.Body)
	}

	homeResponse := httptest.NewRecorder()
	server.ServeHTTP(homeResponse, httptest.NewRequest(http.MethodGet, "/", nil))
	body := homeResponse.Body.String()

	if !strings.Contains(body, "Røde lamper") {
		t.Error("non-ASCII title did not survive the round trip")
	}
	if !strings.Contains(body, "<strong>content</strong>") {
		t.Error("markdown was not rendered")
	}
	if !strings.Contains(body, "data:image/png;base64,") {
		t.Error("image was not inlined with the correct MIME type")
	}
	if !strings.Contains(body, "by "+testUsername) {
		t.Error("author was not displayed")
	}
}

func TestPaginationSplitsPosts(t *testing.T) {
	server, database, _ := newTestServer(t)

	for index := 0; index < 5; index++ {
		if _, err := database.Exec(
			`INSERT INTO blogs (title, content, author, created_at)
			 VALUES (?, 'body', 'tester', datetime('now', ?))`,
			"post-"+string(rune('A'+index)), "-"+string(rune('0'+index))+" minutes",
		); err != nil {
			t.Fatalf("inserting post: %v", err)
		}
	}

	firstPage := httptest.NewRecorder()
	server.ServeHTTP(firstPage, httptest.NewRequest(http.MethodGet, "/", nil))
	if count := strings.Count(firstPage.Body.String(), "<article>"); count != 2 {
		t.Errorf("page 1 has %d posts, want 2 (PostsPerPage)", count)
	}
	if !strings.Contains(firstPage.Body.String(), "/?page=2") {
		t.Error("page 1 has no link to the next page")
	}

	lastPage := httptest.NewRecorder()
	server.ServeHTTP(lastPage, httptest.NewRequest(http.MethodGet, "/?page=3", nil))
	if count := strings.Count(lastPage.Body.String(), "<article>"); count != 1 {
		t.Errorf("page 3 has %d posts, want 1", count)
	}

	// Newest first: post-A was created most recently.
	if !strings.Contains(firstPage.Body.String(), "post-A") {
		t.Error("posts are not ordered newest first by created_at")
	}
}

func TestLogoutRequiresPostAndCSRF(t *testing.T) {
	server, _, _ := newTestServer(t)
	cookies := login(t, server)

	getResponse := httptest.NewRecorder()
	server.ServeHTTP(getResponse, requestWithCookies("/logout", cookies))
	if getResponse.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET /logout returned %d, want %d", getResponse.Code, http.StatusMethodNotAllowed)
	}

	form := url.Values{csrfFieldName: {cookieValue(cookies, csrfCookieName)}}
	request := httptest.NewRequest(http.MethodPost, "/logout", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}

	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther {
		t.Fatalf("logout returned %d", response.Code)
	}

	if ok, _ := server.currentUser(requestWithCookies("/", cookies)); ok {
		t.Error("session still valid after logout")
	}
}

func TestImageCacheReusesEncodingAndNoticesChanges(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "image.png")
	if err := os.WriteFile(path, pngBytes, 0o644); err != nil {
		t.Fatal(err)
	}

	cache := newImageCache(1 << 20)

	first, err := cache.get(path)
	if err != nil {
		t.Fatalf("first get: %v", err)
	}
	if !strings.HasPrefix(string(first), "data:image/png;base64,") {
		t.Errorf("got %q, want a PNG data URI", first[:40])
	}

	if len(cache.entries) != 1 {
		t.Errorf("cache holds %d entries, want 1", len(cache.entries))
	}

	second, err := cache.get(path)
	if err != nil {
		t.Fatalf("second get: %v", err)
	}
	if second != first {
		t.Error("cache returned a different result for an unchanged file")
	}

	// A rewrite with a new modification time must invalidate the entry.
	gifBytes := append([]byte("GIF89a"), bytes.Repeat([]byte{0}, 20)...)
	if err := os.WriteFile(path, gifBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, time.Now().Add(time.Second), time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}

	third, err := cache.get(path)
	if err != nil {
		t.Fatalf("third get: %v", err)
	}
	if !strings.HasPrefix(string(third), "data:image/gif;base64,") {
		t.Errorf("cache served a stale entry: %q", third[:40])
	}
}

func TestImageCacheEvictsWhenOverBudget(t *testing.T) {
	directory := t.TempDir()
	cache := newImageCache(len(pngBytes) * 3)

	for index := 0; index < 10; index++ {
		path := filepath.Join(directory, "image"+string(rune('0'+index))+".png")
		if err := os.WriteFile(path, pngBytes, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := cache.get(path); err != nil {
			t.Fatalf("get %s: %v", path, err)
		}
	}

	if cache.bytes > cache.maxBytes {
		t.Errorf("cache holds %d bytes, over the %d byte budget", cache.bytes, cache.maxBytes)
	}
	if len(cache.entries) != cache.order.Len() {
		t.Errorf("cache map (%d) and list (%d) disagree", len(cache.entries), cache.order.Len())
	}
}

func TestDetectImageMIMEIgnoresExtensionWhenBytesAreKnown(t *testing.T) {
	if got := detectImageMIME(pngBytes, "lies.jpg"); got != "image/png" {
		t.Errorf("got %q, want image/png", got)
	}
	if got := detectImageMIME([]byte("not an image at all"), "x.png"); got == "image/png" {
		t.Error("text was accepted as a PNG on the strength of its extension")
	}
}

func TestMissingImageDoesNotBreakThePage(t *testing.T) {
	server, database, _ := newTestServer(t)

	if _, err := database.Exec(
		`INSERT INTO blogs (title, content, author, image_path)
		 VALUES ('Orphan', 'body', 'tester', 'gone.png')`,
	); err != nil {
		t.Fatal(err)
	}

	response := httptest.NewRecorder()
	server.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/", nil))

	if response.Code != http.StatusOK {
		t.Fatalf("got %d, want 200", response.Code)
	}
	if !strings.Contains(response.Body.String(), "Orphan") {
		t.Error("post with a missing image was not rendered")
	}
}

func TestStaticAssetsComeFromTheEmbeddedFilesystem(t *testing.T) {
	server, _, _ := newTestServer(t)

	if server.assets.LogoDataURI == "" || server.assets.FaviconDataURI == "" {
		t.Fatal("assets were not loaded")
	}
	if server.assets.CSS == "" {
		t.Fatal("stylesheet was not loaded")
	}

	response := httptest.NewRecorder()
	server.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/", nil))

	// html/template renders "+" inside an attribute as the character
	// reference "&#43;", which browsers decode back to "+", so compare the
	// unescaped body.
	body := html.UnescapeString(response.Body.String())
	if !strings.Contains(body, string(server.assets.LogoDataURI)) {
		t.Error("logo data URI is not present in the rendered page")
	}
	if !strings.Contains(body, ".articles-container") {
		t.Error("stylesheet was not inlined")
	}
}

func TestSecurityHeadersAreSet(t *testing.T) {
	server, _, _ := newTestServer(t)
	handler := SecurityHeaders(server)

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/", nil))

	for header, want := range map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
	} {
		if got := response.Header().Get(header); got != want {
			t.Errorf("%s = %q, want %q", header, got, want)
		}
	}
	if !strings.Contains(response.Header().Get("Content-Security-Policy"), "script-src 'none'") {
		t.Error("CSP does not forbid scripts")
	}
}

// discardBody is used to drain response bodies in benchmarks.
var _ = io.Discard
