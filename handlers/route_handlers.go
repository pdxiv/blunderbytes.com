package handlers

import (
	"embed"
	"html/template"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/pdxiv/blunderbytes.com/v2/db"
	"golang.org/x/crypto/bcrypt"
)

var tmpl *template.Template

func InitRoutes(templateFS embed.FS, staticFiles embed.FS) {
	// Initialize tmpl variable
	var err error
	tmpl, err = template.ParseFS(templateFS, "templates/*.html")
	if err != nil {
		log.Fatal(err)
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
	http.Handle("/upload", SessionAuthMiddleware(http.HandlerFunc(UploadHandler)))
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticFS))))

}

func HomeHandler(w http.ResponseWriter, r *http.Request) {
	tmpl.ExecuteTemplate(w, "index.html", nil)
}

func NewHandler(w http.ResponseWriter, r *http.Request) {
	tmpl.ExecuteTemplate(w, "upload.html", nil)
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		username := r.FormValue("username")
		password := r.FormValue("password")

		// Verify user credentials here
		var hashedPassword []byte
		err := db.DB.QueryRow("SELECT hashed_password FROM users WHERE username = ?", username).Scan(&hashedPassword)
		if err != nil {
			http.Error(w, "Invalid login credentials", http.StatusUnauthorized)
			return
		}

		if err = bcrypt.CompareHashAndPassword(hashedPassword, []byte(password)); err != nil {
			http.Error(w, "Invalid login credentials", http.StatusUnauthorized)
			return
		}

		// Create a new session token (this could be a random string; here we use a basic example)
		sessionToken := "your_random_session_token"

		// Set session token as a cookie
		http.SetCookie(w, &http.Cookie{
			Name:    "session_token",
			Value:   sessionToken,
			Expires: time.Now().Add(60 * time.Minute),
		})

		// Redirect or respond to the client as needed
		http.Redirect(w, r, "/welcome", http.StatusSeeOther)
	} else {
		tmpl.ExecuteTemplate(w, "login.html", nil)
	}
}

func UploadHandler(w http.ResponseWriter, r *http.Request) {

	// Parse the form data to retrieve the file
	err := r.ParseMultipartForm(10 << 20) // limit to 10MB
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
	stmt, err := db.DB.Prepare(`INSERT INTO blogs (title, content, author, image_path) VALUES (?, ?, ?, ?)`)
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

		// Validate the session token (in a real-world app, you'd check this value on the server)
		if c.Value != "your_random_session_token" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// If the session token is valid, continue to the actual upload handler
		next.ServeHTTP(w, r)
	})
}
