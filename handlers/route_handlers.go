package handlers

import (
	"crypto/rand"
	"database/sql"
	"embed"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

const SESSION_TOKEN_LENGTH = 16
const SESSION_TOKEN_LIFETIME_MINUTES = 60
const FILE_UPLOAD_MAX_SIZE_MB = 10
const BITS_IN_MEGABYTE = 20

type TemplateData struct {
	Title      string
	IsLoggedIn bool
	Username   string
}

var templates map[string]*template.Template
var db *sql.DB // This is the new global variable

func InitRoutes(templateFS embed.FS, staticFiles embed.FS, passedDB *sql.DB) {
	templates = make(map[string]*template.Template)
	db = passedDB

	// Iterate over the map to initialize each template.
	templateArguments := map[string][]string{
		"index":  {"templates/layout.html", "templates/index.html"},
		"login":  {"templates/layout.html", "templates/login.html"},
		"upload": {"templates/layout.html", "templates/upload.html"},
	}
	for tmplName, paths := range templateArguments {
		tmpl, err := template.ParseFS(templateFS, paths...)
		if err != nil {
			log.Fatalf("error parsing templates for %s: %v", tmplName, err)
		}
		templates[tmplName] = tmpl
	}

	// Serve static files
	staticFS, err := fs.Sub(staticFiles, "static")
	if err != nil {
		log.Fatal(err)
	}

	// Routes
	http.HandleFunc("/", HomeHandler)
	http.HandleFunc("/new", NewHandler)
	http.HandleFunc("/login", LoginHandler)
	http.HandleFunc("/logout", LogoutHandler)
	http.Handle("/upload", SessionAuthMiddleware(http.HandlerFunc(UploadHandler)))
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticFS))))

}

func renderTemplate(w http.ResponseWriter, tmplName string, data TemplateData) {
	tmpl, exists := templates[tmplName]
	if !exists {
		http.Error(w, "Template not found", http.StatusInternalServerError)
		return
	}

	err := tmpl.ExecuteTemplate(w, "layout.html", data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func isValidSessionToken(token string) bool {
	var sessionCount int
	err := db.QueryRow("SELECT COUNT(*) FROM sessions WHERE token = ? AND expires > datetime('now')", token).Scan(&sessionCount)
	if err != nil {
		log.Println("Error checking session token:", err)
		return false
	}
	return sessionCount > 0
}

func getUsernameBySessionToken(token string) (string, error) {
	var username string
	err := db.QueryRow("SELECT username FROM sessions WHERE token = ?", token).Scan(&username)
	if err != nil {
		log.Println("Error retrieving username by session token:", err)
		return "", err
	}
	return username, nil
}

func HomeHandler(w http.ResponseWriter, r *http.Request) {
	// Determine if the user is logged in by checking for a valid session cookie
	c, err := r.Cookie("session_token")
	var isLoggedIn bool
	var username string

	if err == nil {
		if isValidSessionToken(c.Value) {
			isLoggedIn = true
			// Get username from database based on session token
			username, err = getUsernameBySessionToken(c.Value)
			if err != nil {
				log.Println(err)
			}
		}
	} else {
		log.Println("Error retrieving session token:", err)
	}

	data := TemplateData{
		Title:      "Home",
		IsLoggedIn: isLoggedIn,
		Username:   username,
	}
	renderTemplate(w, "index", data)
}

func NewHandler(w http.ResponseWriter, r *http.Request) {
	data := TemplateData{
		Title: "New",
	}
	renderTemplate(w, "upload", data)
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		username := r.FormValue("username")
		password := r.FormValue("password")

		var hashedPassword []byte
		err := db.QueryRow("SELECT hashed_password FROM users WHERE username = ?", username).Scan(&hashedPassword)
		if err != nil {
			http.Error(w, "Invalid login credentials", http.StatusUnauthorized)
			return
		}

		if err = bcrypt.CompareHashAndPassword(hashedPassword, []byte(password)); err != nil {
			http.Error(w, "Invalid login credentials", http.StatusUnauthorized)
			return
		}

		// Create a new session token (a securely generated random string)
		b := make([]byte, SESSION_TOKEN_LENGTH)
		_, err = rand.Read(b)
		if err != nil {
			log.Println("Error generating random session token:", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		sessionToken := fmt.Sprintf("%x", b) // Convert to a hex string

		// Insert new session into the database with associated username
		expiresAt := time.Now().Add(SESSION_TOKEN_LIFETIME_MINUTES * time.Minute)
		_, err = db.Exec("INSERT INTO sessions (username, token, expires) VALUES (?, ?, ?)", username, sessionToken, expiresAt)
		if err != nil {
			log.Println("Error inserting session into database:", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Set session token as a cookie
		http.SetCookie(w, &http.Cookie{
			Name:     "session_token",
			Value:    sessionToken,
			Expires:  expiresAt,
			HttpOnly: true, // Helps mitigate the risk of client side script accessing the protected cookie
		})

		// Redirect or respond to the client as needed
		http.Redirect(w, r, "/", http.StatusSeeOther)
	} else {
		data := TemplateData{
			Title: "Login",
		}
		renderTemplate(w, "login", data)
	}
}

func UploadHandler(w http.ResponseWriter, r *http.Request) {

	// Parse the form data to retrieve the file
	err := r.ParseMultipartForm(FILE_UPLOAD_MAX_SIZE_MB << BITS_IN_MEGABYTE)
	if err != nil {
		http.Error(w, "Unable to parse form", http.StatusBadRequest)
		return
	}

	// Get title and content from the form
	title := r.FormValue("title")
	content := r.FormValue("content")

	// Get the file from the request
	file, _, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "Unable to get the file from form", http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Create the file in the server's file system
	dst, err := os.Create("/tmp/file.jpg")
	if err != nil {
		http.Error(w, "Unable to create the file", http.StatusInternalServerError)
		return
	}
	defer dst.Close()

	// Copy the uploaded file to the created file on the filesystem
	if _, err := io.Copy(dst, file); err != nil {
		http.Error(w, "Unable to copy the file", http.StatusInternalServerError)
		return
	}

	// Insert blog entry into SQLite database
	stmt, err := db.Prepare(`INSERT INTO blogs (title, content, author, image_path) VALUES (?, ?, ?, ?)`)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	_, err = stmt.Exec(title, content, "your_author_name", "./uploads/some_file_name.jpg")
	if err != nil {
		http.Error(w, "Database insert error", http.StatusInternalServerError)
		return
	}

	// Optionally, send a success response
	w.Write([]byte("File successfully uploaded"))

}

func SessionAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("session_token")
		if err != nil {
			// No cookie, redirect to login or send unauthorized response
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		// Validate the session token against the database
		if !isValidSessionToken(c.Value) {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// If the session token is valid, continue to the actual handler
		next.ServeHTTP(w, r)
	})
}

// LogoutHandler invalidates the user's session and clears the session cookie.
func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	// Retrieve the session token from the cookie

	// Set the cookie with a past expiration date to remove it
	http.SetCookie(w, &http.Cookie{
		Name:    "session_token",
		Value:   "",
		Expires: time.Unix(0, 0), // Set the cookie to expire immediately
		MaxAge:  -1,              // MaxAge < 0 means delete cookie now
		Path:    "/",             // Ensure the cookie is deleted for the entire site
	})

	// Redirect to home page or login page after logout
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}
