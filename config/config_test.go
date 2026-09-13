package config

import (
	"testing"
	"time"
)

func TestLoadDefaults(t *testing.T) {
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.Addr != ":8080" {
		t.Errorf("Addr = %q", cfg.Addr)
	}
	if cfg.SessionLifetime != time.Hour {
		t.Errorf("SessionLifetime = %s", cfg.SessionLifetime)
	}
	if cfg.MaxUploadBytes != 10<<20 {
		t.Errorf("MaxUploadBytes = %d", cfg.MaxUploadBytes)
	}
	if !cfg.SecureCookies {
		t.Error("SecureCookies should default to true")
	}
}

func TestLoadReadsEnvironment(t *testing.T) {
	t.Setenv("BLOG_ADDR", "127.0.0.1:9000")
	t.Setenv("BLOG_DB_PATH", "/tmp/other.db")
	t.Setenv("BLOG_SESSION_LIFETIME", "30m")
	t.Setenv("BLOG_MAX_UPLOAD_MB", "2")
	t.Setenv("BLOG_POSTS_PER_PAGE", "25")
	t.Setenv("BLOG_SECURE_COOKIES", "false")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.Addr != "127.0.0.1:9000" {
		t.Errorf("Addr = %q", cfg.Addr)
	}
	if cfg.DBPath != "/tmp/other.db" {
		t.Errorf("DBPath = %q", cfg.DBPath)
	}
	if cfg.SessionLifetime != 30*time.Minute {
		t.Errorf("SessionLifetime = %s", cfg.SessionLifetime)
	}
	if cfg.MaxUploadBytes != 2<<20 {
		t.Errorf("MaxUploadBytes = %d", cfg.MaxUploadBytes)
	}
	if cfg.PostsPerPage != 25 {
		t.Errorf("PostsPerPage = %d", cfg.PostsPerPage)
	}
	if cfg.SecureCookies {
		t.Error("SecureCookies should be false")
	}
}

func TestLoadRejectsBadValues(t *testing.T) {
	cases := map[string]string{
		"BLOG_MAX_UPLOAD_MB":    "0",
		"BLOG_POSTS_PER_PAGE":   "-1",
		"BLOG_SESSION_LIFETIME": "forever",
		"BLOG_SECURE_COOKIES":   "perhaps",
	}

	for key, value := range cases {
		t.Run(key, func(t *testing.T) {
			t.Setenv(key, value)
			if _, err := Load(); err == nil {
				t.Errorf("Load accepted %s=%q", key, value)
			}
		})
	}
}
