package db

import (
	"errors"
	"path/filepath"
	"testing"
)

func TestOpenRefusesToInventDefaultCredentials(t *testing.T) {
	// Silently creating a well-known "foo"/"bar" account would expose the site.
	_, err := Open(Options{Path: filepath.Join(t.TempDir(), "test.db")})

	if !errors.Is(err, ErrNoBootstrapCredentials) {
		t.Fatalf("got %v, want ErrNoBootstrapCredentials", err)
	}
}

func TestOpenCreatesBootstrapUserOnce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")
	opts := Options{Path: path, BootstrapUsername: "admin", BootstrapPassword: "secret"}

	database, err := Open(opts)
	if err != nil {
		t.Fatalf("first open: %v", err)
	}

	var count int
	if err := database.QueryRow("SELECT COUNT(*) FROM users").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("got %d users, want 1", count)
	}
	database.Close()

	// A second start with different credentials must not add another user.
	opts.BootstrapUsername = "someone-else"
	database, err = Open(opts)
	if err != nil {
		t.Fatalf("second open: %v", err)
	}
	defer database.Close()

	if err := database.QueryRow("SELECT COUNT(*) FROM users").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Errorf("got %d users after restart, want 1", count)
	}
}

func TestCreateUserRejectsEmptyCredentials(t *testing.T) {
	database, err := Open(Options{
		Path:              filepath.Join(t.TempDir(), "test.db"),
		BootstrapUsername: "admin",
		BootstrapPassword: "secret",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	if err := CreateUser(database, "", "secret"); err == nil {
		t.Error("empty username was accepted")
	}
	if err := CreateUser(database, "someone", ""); err == nil {
		t.Error("empty password was accepted")
	}
}

func TestDeleteExpiredSessionsOnlyRemovesExpiredRows(t *testing.T) {
	database, err := Open(Options{
		Path:              filepath.Join(t.TempDir(), "test.db"),
		BootstrapUsername: "admin",
		BootstrapPassword: "secret",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	if _, err := database.Exec(`
		INSERT INTO sessions (username, token, expires) VALUES
			('admin', 'live', datetime('now', '+1 hour')),
			('admin', 'stale', datetime('now', '-1 hour'))`); err != nil {
		t.Fatal(err)
	}

	removed, err := DeleteExpiredSessions(database)
	if err != nil {
		t.Fatal(err)
	}
	if removed != 1 {
		t.Errorf("removed %d rows, want 1", removed)
	}

	var remaining string
	if err := database.QueryRow("SELECT token FROM sessions").Scan(&remaining); err != nil {
		t.Fatal(err)
	}
	if remaining != "live" {
		t.Errorf("remaining token is %q, want \"live\"", remaining)
	}
}
