package db

import (
	"database/sql"
	"fmt"
	"log"

	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

var DB *sql.DB

func InitDatabase() {
	var err error
	// Initialize SQLite database
	DB, err = sql.Open("sqlite3", "./blog.db")
	if err != nil {
		panic(err)
	}

	// Create blogs table if it doesn't exist
	_, err = DB.Exec(`CREATE TABLE IF NOT EXISTS blogs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        content TEXT NOT NULL,
        author TEXT NOT NULL,
        image_path TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );`)
	if err != nil {
		log.Fatal(err)
	}

	// Create users table if it doesn't exist
	_, err = DB.Exec(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        hashed_password TEXT NOT NULL
    );`)
	if err != nil {
		log.Fatal(err)
	}

	// Check if there are any existing users
	var userCount int
	row := DB.QueryRow("SELECT COUNT(*) FROM users")
	err = row.Scan(&userCount)
	if err != nil {
		log.Fatal(err)
	}

	// If no users exist, insert an initial user
	if userCount == 0 {
		createInitialUser()
	}
}

func createInitialUser() {
	// Hash the initial password
	initialPassword := "initial_password_here"
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(initialPassword), bcrypt.DefaultCost)
	if err != nil {
		log.Fatal(err)
	}

	// Insert the initial user
	initialUsername := "initial_user"
	_, err = DB.Exec("INSERT INTO users (username, hashed_password) VALUES (?, ?)", initialUsername, hashedPassword)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Initial user created!")
}
