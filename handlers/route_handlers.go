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

func HomeHandler(w http.ResponseWriter, request *http.Request) {
	isLoggedIn, username := isValidSessionCookie(request)

	data := TemplateData{
		Title:      "Home",
		IsLoggedIn: isLoggedIn,
		Username:   username,
	}
	renderTemplate(w, "index", data)
}

func NewHandler(w http.ResponseWriter, request *http.Request) {
	isLoggedIn, username := isValidSessionCookie(request)

	data := TemplateData{
		Title:      "New",
		IsLoggedIn: isLoggedIn,
		Username:   username,
	}
	renderTemplate(w, "upload", data)
}

func LoginHandler(w http.ResponseWriter, request *http.Request) {

	if request.Method == http.MethodPost {
		username := request.FormValue("username")
		password := request.FormValue("password")

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
		http.Redirect(w, request, "/", http.StatusSeeOther)
	} else {
		isLoggedIn, username := isValidSessionCookie(request)

		data := TemplateData{
			Title:      "Login",
			IsLoggedIn: isLoggedIn,
			Username:   username,
		}

		renderTemplate(w, "login", data)
	}
}

func UploadHandler(w http.ResponseWriter, request *http.Request) {

	// Parse the form data to retrieve the file
	err := request.ParseMultipartForm(FILE_UPLOAD_MAX_SIZE_MB << BITS_IN_MEGABYTE)
	if err != nil {
		http.Error(w, "Unable to parse form", http.StatusBadRequest)
		return
	}

	// Get title and content from the form
	title := request.FormValue("title")
	content := request.FormValue("content")

	// Get the file from the request
	file, _, err := request.FormFile("file")
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

// Invalidate the user's session and clear the session cookie.
func LogoutHandler(w http.ResponseWriter, request *http.Request) {
	// Retrieve the session token from the cookie
	sessionCookie, err := request.Cookie("session_token")
	if err != nil {
		// If the session cookie is not found, redirect to the login page or home page
		http.Redirect(w, request, "/", http.StatusSeeOther)
		return
	}

	// Get the session token value
	sessionToken := sessionCookie.Value

	// Delete the session from the database
	_, err = db.Exec("DELETE FROM sessions WHERE token = ?", sessionToken)
	if err != nil {
		log.Printf("Error deleting session from database: %v", err)
	}

	// Set the cookie with a past expiration date to remove it
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    "",
		Expires:  time.Unix(0, 0), // Set the cookie to expire immediately
		MaxAge:   -1,              // MaxAge < 0 means delete cookie now
		Path:     "/",             // Ensure the cookie is deleted for the entire site
		HttpOnly: true,
	})

	// Redirect to home page or login page after logout
	http.Redirect(w, request, "/", http.StatusSeeOther)
}
