package config

import (
	"fmt"
	"os"
	"strings"
)

// Config holds all application configuration values.
type Config struct {
	Port          string
	DBPath        string
	JWTSecret     string
	OIDCIssuer    string
	OIDCClientID  string
	OIDCClientSec string
	OIDCRedirect  string
	// Encryption key for secrets at rest (derived from JWT_SECRET or SECRETS_KEY)
	SecretsKey     string
	// Hardcoded admin credentials (env: ADMIN_EMAIL, ADMIN_PASSWORD)
	AdminEmail    string
	AdminPassword string
	IsProduction  bool
}

// Load reads configuration from environment variables with sensible defaults.
// Returns nil and an error if required configuration is missing in production.
func Load() (*Config, error) {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	dbPath := os.Getenv("DB_PATH")
	if dbPath == "" {
		dbPath = "reflag.db"
	}
	// Generate a warning if JWT_SECRET is not set in production
	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		// In dev, use a fixed but clearly insecure secret
		jwtSecret = "dev-only-not-secure-change-me-in-production"
	}
	isProd := strings.ToLower(os.Getenv("APP_ENV")) == "production"
	// In production, refuse to start with insecure secrets
	if isProd {
		if len(jwtSecret) < 32 {
			return nil, fmt.Errorf("JWT_SECRET must be at least 32 characters in production (got %d)", len(jwtSecret))
		}
		if jwtSecret == "dev-only-not-secure-change-me-in-production" {
			return nil, fmt.Errorf("JWT_SECRET must be set to a secure value in production")
		}
	}
	// Secrets encryption key — use SECRETS_KEY if set, otherwise derive from JWT_SECRET
	secretsKey := os.Getenv("SECRETS_KEY")
	if secretsKey == "" {
		secretsKey = jwtSecret
	}
	if isProd && len(secretsKey) < 32 {
		return nil, fmt.Errorf("SECRETS_KEY or JWT_SECRET must be at least 32 characters for secrets encryption in production")
	}
	return &Config{
		Port:          port,
		DBPath:        dbPath,
		JWTSecret:     jwtSecret,
		OIDCIssuer:    os.Getenv("OIDC_ISSUER"),
		OIDCClientID:  os.Getenv("OIDC_CLIENT_ID"),
		OIDCClientSec: os.Getenv("OIDC_CLIENT_SECRET"),
		OIDCRedirect:  os.Getenv("OIDC_REDIRECT_URL"),
		SecretsKey:     secretsKey,
		AdminEmail:    os.Getenv("ADMIN_EMAIL"),
		AdminPassword: os.Getenv("ADMIN_PASSWORD"),
		IsProduction:  isProd,
	}, nil
}
