// Package db owns the SQLite schema and connection lifecycle.
package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

// ErrNoBootstrapCredentials is returned when the users table is empty and no
// bootstrap credentials were supplied. Starting with a well-known default
// account would silently expose the site, so this is treated as fatal.
var ErrNoBootstrapCredentials = errors.New(
	"no users exist and no bootstrap credentials were provided: " +
		"set BLOG_ADMIN_USERNAME and BLOG_ADMIN_PASSWORD for the first start")

// Options configures Open.
type Options struct {
	Path              string
	BootstrapUsername string
	BootstrapPassword string
}

// Open opens the database, applies the schema, and ensures at least one user
// exists. The caller owns the returned handle and must Close it.
func Open(opts Options) (*sql.DB, error) {
	// _busy_timeout keeps concurrent writers from failing outright, and
	// foreign_keys/journal_mode are set per-connection by the driver.
	dsn := opts.Path + "?_busy_timeout=5000&_journal_mode=WAL&_foreign_keys=on"
	database, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, fmt.Errorf("opening database %q: %w", opts.Path, err)
	}

	if err := database.Ping(); err != nil {
		database.Close()
		return nil, fmt.Errorf("connecting to database %q: %w", opts.Path, err)
	}

	if err := applySchema(database); err != nil {
		database.Close()
		return nil, err
	}

	if err := ensureInitialUser(database, opts); err != nil {
		database.Close()
		return nil, err
	}

	return database, nil
}

func applySchema(database *sql.DB) error {
	statements := []string{
		`CREATE TABLE IF NOT EXISTS blogs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			title TEXT NOT NULL,
			content TEXT NOT NULL,
			author TEXT NOT NULL,
			image_path TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);`,
		`CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT UNIQUE NOT NULL,
			hashed_password TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS sessions (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT NOT NULL,
			token TEXT NOT NULL,
			expires DATETIME NOT NULL
		);`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_sessions_token ON sessions (token);`,
		`CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions (expires);`,
		`CREATE INDEX IF NOT EXISTS idx_blogs_created_at ON blogs (created_at DESC, id DESC);`,
	}

	for _, statement := range statements {
		if _, err := database.Exec(statement); err != nil {
			return fmt.Errorf("applying schema: %w", err)
		}
	}
	return nil
}

func ensureInitialUser(database *sql.DB, opts Options) error {
	var userCount int
	if err := database.QueryRow("SELECT COUNT(*) FROM users").Scan(&userCount); err != nil {
		return fmt.Errorf("counting users: %w", err)
	}
	if userCount > 0 {
		return nil
	}

	if opts.BootstrapUsername == "" || opts.BootstrapPassword == "" {
		return ErrNoBootstrapCredentials
	}

	if err := CreateUser(database, opts.BootstrapUsername, opts.BootstrapPassword); err != nil {
		return err
	}
	log.Printf("created initial user %q", opts.BootstrapUsername)
	return nil
}

// CreateUser hashes the password and inserts a new user.
func CreateUser(database *sql.DB, username, password string) error {
	if username == "" || password == "" {
		return errors.New("username and password must both be non-empty")
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hashing password: %w", err)
	}

	if _, err := database.Exec(
		"INSERT INTO users (username, hashed_password) VALUES (?, ?)",
		username, hashedPassword,
	); err != nil {
		return fmt.Errorf("creating user %q: %w", username, err)
	}
	return nil
}

// DeleteExpiredSessions removes session rows that are past their expiry, so the
// table does not grow without bound. It returns the number of rows removed.
func DeleteExpiredSessions(database *sql.DB) (int64, error) {
	result, err := database.Exec("DELETE FROM sessions WHERE expires <= datetime('now')")
	if err != nil {
		return 0, fmt.Errorf("deleting expired sessions: %w", err)
	}
	return result.RowsAffected()
}

// SweepExpiredSessions runs DeleteExpiredSessions on a ticker until ctx is done.
func SweepExpiredSessions(ctx context.Context, database *sql.DB, every time.Duration) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			removed, err := DeleteExpiredSessions(database)
			if err != nil {
				log.Printf("session sweep failed: %v", err)
				continue
			}
			if removed > 0 {
				log.Printf("session sweep removed %d expired session(s)", removed)
			}
		}
	}
}
