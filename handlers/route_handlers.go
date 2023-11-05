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
	"path/filepath"
	"strings"
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
		"index":  {"templates/layout.html", "templates/navbar.html", "templates/index.html"},
		"login":  {"templates/layout.html", "templates/navbar.html", "templates/login.html"},
		"upload": {"templates/layout.html", "templates/navbar.html", "templates/upload.html"},
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

	// Redirect user to login if not logged in.
	if !isLoggedIn {
		http.Redirect(w, request, "/login", http.StatusSeeOther)
		return
	}

	data := TemplateData{
		Title:      "New Blog Post",
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

	// Ensure only POST method is used
	if request.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Validate logged-in user
	isLoggedIn, username := isValidSessionCookie(request)
	if !isLoggedIn {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Parse the form data with a size limit
	err := request.ParseMultipartForm(FILE_UPLOAD_MAX_SIZE_MB << BITS_IN_MEGABYTE)
	if err != nil {
		http.Error(w, "The uploaded file is too large", http.StatusBadRequest)
		return
	}

	// Get title and content from the form and validate
	title := request.FormValue("title")
	content := request.FormValue("content")
	if title == "" || content == "" {
		http.Error(w, "Title and content must be provided", http.StatusBadRequest)
		return
	}

	// Get the file from the request
	file, header, err := request.FormFile("file")
	if err != nil {
		http.Error(w, "File is required", http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Validate the file type is an image
	if !strings.HasPrefix(header.Header.Get("Content-Type"), "image/") {
		http.Error(w, "Only image uploads are allowed", http.StatusBadRequest)
		return
	}

	// Create a directory for uploads if it doesn't exist
	uploadPath := "./uploads"
	if _, err := os.Stat(uploadPath); os.IsNotExist(err) {
		os.Mkdir(uploadPath, os.ModePerm)
	}

	// Generate a unique filename to prevent overwriting and directory traversal
	// problems. In a production system, you might want to check the file extension too.
	newFileName := fmt.Sprintf("%d-%s", time.Now().UnixNano(), header.Filename)
	newFilePath := filepath.Join(uploadPath, newFileName)

	// Create the file in the server's file system
	dst, err := os.Create(newFilePath)
	if err != nil {
		http.Error(w, "Unable to create the file on the server", http.StatusInternalServerError)
		return
	}
	defer dst.Close()

	// Copy the uploaded file to the created file on the filesystem
	if _, err := io.Copy(dst, file); err != nil {
		http.Error(w, "Unable to save the uploaded file", http.StatusInternalServerError)
		return
	}

	// Insert blog entry into the database with the new image path
	stmt, err := db.Prepare(`INSERT INTO blogs (title, content, author, image_path) VALUES (?, ?, ?, ?)`)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	_, err = stmt.Exec(title, content, username, newFilePath)
	if err != nil {
		http.Error(w, "Database insert error", http.StatusInternalServerError)
		return
	}

	// Redirect or respond to the client as needed
	http.Redirect(w, request, "/", http.StatusSeeOther)

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
