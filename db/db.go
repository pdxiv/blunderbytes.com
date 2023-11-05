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
		createUser("foo", "bar")
	}

	// Create sessions table if it doesn't exist
	_, err = DB.Exec(`CREATE TABLE IF NOT EXISTS sessions (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT NOT NULL,
		token TEXT NOT NULL,
		expires DATETIME NOT NULL
	);`)
	if err != nil {
		log.Fatal(err)
	}

}

func createUser(username string, password string) error {
	// Start a database transaction
	tx, err := DB.Begin()
	if err != nil {
		return fmt.Errorf("database begin transaction error: %w", err)
	}
	defer tx.Rollback()

	// Hash the initial password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("password hashing error: %w", err)
	}

	// Insert the initial user
	_, err = tx.Exec("INSERT INTO users (username, hashed_password) VALUES (?, ?)", username, hashedPassword)
	if err != nil {
		return fmt.Errorf("user creation error: %w", err)
	}

	// Commit the transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("database transaction commit error: %w", err)
	}
	log.Println("Successfully created user:", username)

	return nil
}
