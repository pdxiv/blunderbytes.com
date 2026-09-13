package main

import (
	"context"
	"embed"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	_ "github.com/mattn/go-sqlite3"

	"github.com/pdxiv/blunderbytes.com/v2/config"
	"github.com/pdxiv/blunderbytes.com/v2/db"
	"github.com/pdxiv/blunderbytes.com/v2/handlers"
)

//go:embed templates/*
var templateFS embed.FS

//go:embed static/*
var staticFiles embed.FS

// sessionSweepInterval is how often expired session rows are deleted.
const sessionSweepInterval = 10 * time.Minute

func main() {
	if err := run(); err != nil {
		log.Fatalf("fatal: %v", err)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	database, err := db.Open(db.Options{
		Path:              cfg.DBPath,
		BootstrapUsername: cfg.BootstrapUsername,
		BootstrapPassword: cfg.BootstrapPassword,
	})
	if err != nil {
		return err
	}
	defer database.Close()

	server, err := handlers.New(cfg, database, templateFS, staticFiles)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go db.SweepExpiredSessions(ctx, database, sessionSweepInterval)

	httpServer := &http.Server{
		Addr:    cfg.Addr,
		Handler: handlers.LogRequests(handlers.SecurityHeaders(server)),
		// Timeouts bound how long a single slow or idle client can hold a
		// connection; without them a handful of clients can exhaust the server.
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       2 * time.Minute,
		WriteTimeout:      2 * time.Minute,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    1 << 20,
		ErrorLog:          log.Default(),
	}

	listenErrors := make(chan error, 1)
	go func() {
		log.Printf("listening on %s", cfg.Addr)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			listenErrors <- err
			return
		}
		listenErrors <- nil
	}()

	select {
	case err := <-listenErrors:
		return err
	case <-ctx.Done():
		log.Println("shutdown requested, draining connections")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		return err
	}

	log.Println("shutdown complete")
	return nil
}
