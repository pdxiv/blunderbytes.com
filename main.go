package main

import (
	"embed"
	"net/http"

	_ "github.com/mattn/go-sqlite3"
	"github.com/pdxiv/blunderbytes.com/v2/db"
	"github.com/pdxiv/blunderbytes.com/v2/handlers"
)

//go:embed templates/*
var templateFS embed.FS

//go:embed static/*
var staticFiles embed.FS

func main() {
	// Initialize database
	db.InitDatabase()
	defer db.DB.Close()

	handlers.InitRoutes(templateFS, staticFiles, db.DB)

	// Start server
	http.ListenAndServe(":8080", nil)
}
