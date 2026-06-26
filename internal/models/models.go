package models

import (
	"encoding/json"
	"time"
)

// FlagType represents the type of a flag's value.
type FlagType string

const (
	FlagTypeBoolean FlagType = "boolean"
	FlagTypeString  FlagType = "string"
	FlagTypeNumber  FlagType = "number"
	FlagTypeObject  FlagType = "object"
	FlagTypeSecret  FlagType = "secret"
)

// FlagState represents whether a flag is on or off.
type FlagState string

const (
	StateEnabled  FlagState = "ENABLED"
	StateDisabled FlagState = "DISABLED"
)

// Environment represents a deployment environment (e.g., production, staging).
type Environment struct {
	ID          string    `json:"id"`
	Key         string    `json:"key"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// Flag represents a feature flag with configurations per environment.
type Flag struct {
	ID          string            `json:"id"`
	Key         string            `json:"key"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Type        FlagType          `json:"type"`
	Enabled     bool              `json:"enabled"`
	Version     int               `json:"version"`
	Variations  []Variation       `json:"variations"`
	Targeting   []TargetingRule   `json:"targeting_rules"`
	DefaultRule *DefaultRule      `json:"default_rule,omitempty"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
}

// Variation is one of the possible values a flag can resolve to.
type Variation struct {
	ID     string          `json:"id"`
	Value  json.RawMessage `json:"value"`
	Label  string          `json:"label"`
}

// TargetingRule defines conditional evaluation logic.
type TargetingRule struct {
	ID         string        `json:"id"`
	Name       string        `json:"name"`
	Conditions []Condition   `json:"conditions"`
	VariationID string      `json:"variation_id"`
}

// Condition is a single targeting criteria.
type Condition struct {
	ID       string `json:"id"`
	Attribute string `json:"attribute"`
	Operator string `json:"operator"`
	Values   []string `json:"values"`
}

// DefaultRule is the fallback when no targeting rules match.
type DefaultRule struct {
	VariationID string `json:"variation_id"`
	Percentage  map[string]int `json:"percentage,omitempty"`
}

// Segment represents a reusable group of targeting rules.
type Segment struct {
	ID          string    `json:"id"`
	Key         string    `json:"key"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Conditions  []Condition `json:"conditions"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// APIKey represents an API key for programmatic access.
type APIKey struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	KeyHash      string    `json:"-"` // SHA-256 hash, never serialized
	KeyPrefix    string    `json:"key_prefix"`
	EnvironmentID string   `json:"environment_id"`
	Scopes       []string  `json:"scopes"`
	LastUsedAt   *time.Time `json:"last_used_at,omitempty"`
	ExpiresAt    *time.Time `json:"expires_at,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
	Revoked      bool      `json:"revoked"`
}

// AuditLogEntry represents an entry in the audit log.
type AuditLogEntry struct {
	ID        string    `json:"id"`
	Actor     string    `json:"actor"` // user ID or API key ID
	Action    string    `json:"action"`
	Resource  string    `json:"resource"`
	ResourceID string   `json:"resource_id"`
	Details   string    `json:"details,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

// User represents an authenticated admin user (from OIDC or hardcoded admin).
type User struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Name  string `json:"name"`
	Role  string `json:"role"` // admin, owner, member, viewer
}

// Organization represents a tenant/workspace that owns flags, secrets, etc.
type Organization struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Slug        string    `json:"slug"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// OrgMember represents a user's membership in an organization with a role.
type OrgMember struct {
	ID             string    `json:"id"`
	UserID         string    `json:"user_id"`
	OrgID          string    `json:"org_id"`
	Role           string    `json:"role"` // owner, admin, member, viewer
	CreatedAt      time.Time `json:"created_at"`
	// Joined fields (populated by queries)
	UserName  string `json:"user_name,omitempty"`
	UserEmail string `json:"user_email,omitempty"`
}

// Secret represents an encrypted configuration secret (e.g., API tokens, passwords).
// The value is encrypted at rest with AES-256-GCM and only decrypted on read.
type Secret struct {
	ID            string    `json:"id"`
	Key           string    `json:"key"`
	Name          string    `json:"name"`
	Description   string    `json:"description"`
	EncryptedValue string   `json:"-"` // Never serialized to JSON
	EnvironmentID string    `json:"environment_id,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}
