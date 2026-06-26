package config

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"os"
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
	isProd := os.Getenv("APP_ENV") == "production"
	// Generate a random JWT secret in dev mode if not set
	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		if isProd {
			return nil, fmt.Errorf("JWT_SECRET must be set in production")
		}
		// Dev mode: generate a random per-session secret
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			return nil, fmt.Errorf("failed to generate dev JWT secret: %w", err)
		}
		jwtSecret = "dev:" + hex.EncodeToString(b)
		log.Printf("[reflag] Warning: JWT_SECRET not set — generated random dev secret")
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
