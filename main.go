package main

import (
	"net/http"

	_ "github.com/mattn/go-sqlite3"
	"github.com/pdxiv/blunderbytes.com/v2/db"
	"github.com/pdxiv/blunderbytes.com/v2/handlers"
)

func main() {
	// Initialize database
	db.InitDatabase()
	defer db.DB.Close()

	// Routes
	http.HandleFunc("/", handlers.HomeHandler)
	http.HandleFunc("/new", handlers.NewHandler)
	http.HandleFunc("/login", handlers.LoginHandler)
	http.Handle("/upload", handlers.SessionAuthMiddleware(http.HandlerFunc(handlers.UploadHandler)))
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("./static"))))

	// Start server
	http.ListenAndServe(":8080", nil)
}
