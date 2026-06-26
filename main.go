package main

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/dovocoder/reflag/internal/api"
	"github.com/dovocoder/reflag/internal/auth"
	"github.com/dovocoder/reflag/internal/config"
	"github.com/dovocoder/reflag/internal/middleware"
	"github.com/dovocoder/reflag/internal/models"
	"github.com/dovocoder/reflag/internal/store"
)

//go:embed all:web/dist
var webFS embed.FS

func main() {
	cfg := config.Load()

	// Initialize store
	st, err := store.New(cfg.DBPath)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer st.Close()

	// Seed default environments if none exist
	seedDefaultEnvironments(st)

	// Initialize auth service
	authSvc := auth.New(st, cfg.JWTSecret, cfg.OIDCIssuer, cfg.OIDCClientID, cfg.OIDCClientSec, cfg.OIDCRedirect)

	// Initialize API handlers
	handler := api.NewHandler(st, authSvc, cfg.SecretsKey)

	// Main mux
	mux := http.NewServeMux()

	// Register API routes
	handler.RegisterRoutes(mux)

	// Serve embedded frontend (SPA with fallback)
	distFS, err := fs.Sub(webFS, "web/dist")
	if err != nil {
		log.Fatalf("Failed to get sub filesystem: %v", err)
	}
	fileServer := http.FileServer(http.FS(distFS))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// SPA fallback: serve index.html for non-API, non-file routes
		if r.URL.Path != "/" && !strings.HasPrefix(r.URL.Path, "/api/") && !strings.HasPrefix(r.URL.Path, "/health") {
			cleanPath := strings.TrimPrefix(r.URL.Path, "/")
			if _, err := fs.Stat(distFS, cleanPath); err != nil {
				r.URL.Path = "/"
			}
		}
		fileServer.ServeHTTP(w, r)
	})

	// Build middleware chain: security headers → CORS → rate limit → CSRF → mux
	rateLimiter := middleware.NewRateLimiter(100, time.Minute)

	var finalHandler http.Handler = mux
	finalHandler = middleware.CSRFMiddleware(finalHandler)
	finalHandler = middleware.RateLimitMiddleware(rateLimiter, finalHandler)
	finalHandler = middleware.CORSMiddleware(finalHandler)
	finalHandler = middleware.SecurityHeadersMiddleware(finalHandler)

	// Create HTTP server
	srv := &http.Server{
		Addr:           ":" + cfg.Port,
		Handler:        finalHandler,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   30 * time.Second,
		IdleTimeout:   120 * time.Second,
		MaxHeaderBytes: 1 << 20, // 1MB max header
	}

	// Start server in goroutine
	go func() {
		log.Printf("[reflag] Server starting on :%s", cfg.Port)
		log.Printf("[reflag] Database: %s", cfg.DBPath)
		if cfg.OIDCIssuer != "" {
			log.Printf("[reflag] OIDC issuer: %s", cfg.OIDCIssuer)
		}
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server failed: %v", err)
		}
	}()

	// Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("[reflag] Shutting down...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}
	log.Println("[reflag] Server stopped")
}

// seedDefaultEnvironments creates default and production environments if none exist.
func seedDefaultEnvironments(st *store.Store) {
	envs, err := st.ListEnvironments()
	if err != nil {
		log.Printf("[reflag] Warning: failed to list environments: %v", err)
		return
	}
	if len(envs) > 0 {
		return
	}
	defaults := []struct{ key, name, desc string }{
		{"default", "Default", "Default environment"},
		{"production", "Production", "Production environment"},
	}
	for _, e := range defaults {
		env := &models.Environment{
			ID:          fmt.Sprintf("env-%s", e.key),
			Key:         e.key,
			Name:        e.name,
			Description: e.desc,
		}
		if err := st.CreateEnvironment(env); err != nil {
			log.Printf("[reflag] Warning: failed to seed environment %s: %v", e.key, err)
		} else {
			log.Printf("[reflag] Seeded environment: %s", e.key)
		}
	}
}
