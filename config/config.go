// Package config loads runtime settings from the environment so that nothing
// operationally interesting (ports, paths, credentials) is baked into the binary.
package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

type Config struct {
	// Addr is the TCP address the HTTP server listens on.
	Addr string
	// DBPath is the location of the SQLite database file.
	DBPath string
	// UploadsDir is the directory uploaded images are written to.
	UploadsDir string
	// SessionLifetime is how long a session token stays valid after login.
	SessionLifetime time.Duration
	// MaxUploadBytes caps the size of a multipart upload.
	MaxUploadBytes int64
	// PostsPerPage is the number of blog entries rendered on one page.
	PostsPerPage int
	// SecureCookies marks session cookies Secure. Turn it off only when
	// serving plain HTTP on localhost during development.
	SecureCookies bool
	// BootstrapUsername and BootstrapPassword create the first user when the
	// users table is empty. They are ignored once a user exists.
	BootstrapUsername string
	BootstrapPassword string
}

// Load reads configuration from the environment, applying defaults.
func Load() (Config, error) {
	cfg := Config{
		Addr:              envString("BLOG_ADDR", ":8080"),
		DBPath:            envString("BLOG_DB_PATH", "./blog.db"),
		UploadsDir:        envString("BLOG_UPLOADS_DIR", "./uploads"),
		BootstrapUsername: os.Getenv("BLOG_ADMIN_USERNAME"),
		BootstrapPassword: os.Getenv("BLOG_ADMIN_PASSWORD"),
	}

	var err error
	if cfg.SessionLifetime, err = envDuration("BLOG_SESSION_LIFETIME", time.Hour); err != nil {
		return Config{}, err
	}
	uploadMB, err := envInt("BLOG_MAX_UPLOAD_MB", 10)
	if err != nil {
		return Config{}, err
	}
	if uploadMB <= 0 {
		return Config{}, fmt.Errorf("BLOG_MAX_UPLOAD_MB must be positive, got %d", uploadMB)
	}
	cfg.MaxUploadBytes = int64(uploadMB) << 20

	if cfg.PostsPerPage, err = envInt("BLOG_POSTS_PER_PAGE", 10); err != nil {
		return Config{}, err
	}
	if cfg.PostsPerPage <= 0 {
		return Config{}, fmt.Errorf("BLOG_POSTS_PER_PAGE must be positive, got %d", cfg.PostsPerPage)
	}

	if cfg.SecureCookies, err = envBool("BLOG_SECURE_COOKIES", true); err != nil {
		return Config{}, err
	}

	return cfg, nil
}

func envString(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func envInt(key string, fallback int) (int, error) {
	raw := os.Getenv(key)
	if raw == "" {
		return fallback, nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", key, err)
	}
	return value, nil
}

func envBool(key string, fallback bool) (bool, error) {
	raw := os.Getenv(key)
	if raw == "" {
		return fallback, nil
	}
	value, err := strconv.ParseBool(raw)
	if err != nil {
		return false, fmt.Errorf("%s: %w", key, err)
	}
	return value, nil
}

func envDuration(key string, fallback time.Duration) (time.Duration, error) {
	raw := os.Getenv(key)
	if raw == "" {
		return fallback, nil
	}
	value, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", key, err)
	}
	if value <= 0 {
		return 0, fmt.Errorf("%s must be positive, got %s", key, value)
	}
	return value, nil
}
