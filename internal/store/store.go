package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/dovocoder/reflag/internal/models"
	"github.com/google/uuid"

	_ "modernc.org/sqlite"
)

// Store wraps the SQLite database for all persistence operations.
type Store struct {
	db *sql.DB
}

// New opens the SQLite database and runs migrations.
func New(dbPath string) (*Store, error) {
	db, err := sql.Open("sqlite", dbPath+"?_pragma=journal_mode(WAL)&_pragma=foreign_keys(on)&_pragma=busy_timeout(5000)&_pragma=wal_autocheckpoint(1000)")
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	db.SetMaxOpenConns(1) // SQLite concurrent write safety
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}
	// Restrict database file permissions to owner-only
	if dbPath != ":memory:" {
		_ = os.Chmod(dbPath, 0600)
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate() error {
	migrations := []string{
		`CREATE TABLE IF NOT EXISTS environments (
			id TEXT PRIMARY KEY,
			key TEXT UNIQUE NOT NULL,
			name TEXT NOT NULL,
			description TEXT DEFAULT '',
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS flags (
			id TEXT PRIMARY KEY,
			key TEXT UNIQUE NOT NULL,
			name TEXT NOT NULL,
			description TEXT DEFAULT '',
			type TEXT NOT NULL,
			enabled INTEGER NOT NULL DEFAULT 0,
			version INTEGER NOT NULL DEFAULT 1,
			data TEXT NOT NULL DEFAULT '{}',
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS flag_configs (
			id TEXT PRIMARY KEY,
			flag_id TEXT NOT NULL REFERENCES flags(id) ON DELETE CASCADE,
			environment_id TEXT NOT NULL REFERENCES environments(id) ON DELETE CASCADE,
			enabled INTEGER NOT NULL DEFAULT 0,
			data TEXT NOT NULL DEFAULT '{}',
			UNIQUE(flag_id, environment_id)
		)`,
		`CREATE TABLE IF NOT EXISTS segments (
			id TEXT PRIMARY KEY,
			key TEXT UNIQUE NOT NULL,
			name TEXT NOT NULL,
			description TEXT DEFAULT '',
			conditions TEXT NOT NULL DEFAULT '[]',
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS api_keys (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			key_hash TEXT UNIQUE NOT NULL,
			key_prefix TEXT NOT NULL,
			environment_id TEXT REFERENCES environments(id) ON DELETE SET NULL,
			scopes TEXT NOT NULL DEFAULT '[]',
			last_used_at DATETIME,
			expires_at DATETIME,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			revoked INTEGER NOT NULL DEFAULT 0
		)`,
		`CREATE TABLE IF NOT EXISTS audit_log (
			id TEXT PRIMARY KEY,
			actor TEXT NOT NULL,
			action TEXT NOT NULL,
			resource TEXT NOT NULL,
			resource_id TEXT NOT NULL DEFAULT '',
			details TEXT DEFAULT '',
			timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS users (
			id TEXT PRIMARY KEY,
			email TEXT UNIQUE NOT NULL,
			name TEXT NOT NULL,
			role TEXT NOT NULL DEFAULT 'member',
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS secrets (
			id TEXT PRIMARY KEY,
			key TEXT UNIQUE NOT NULL,
			name TEXT NOT NULL,
			description TEXT DEFAULT '',
			encrypted_value TEXT NOT NULL,
			environment_id TEXT REFERENCES environments(id) ON DELETE SET NULL,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS organizations (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			slug TEXT UNIQUE NOT NULL,
			description TEXT DEFAULT '',
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS org_members (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
			role TEXT NOT NULL DEFAULT 'member',
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(user_id, org_id)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_flags_key ON flags(key)`,
		`CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log(timestamp DESC)`,
		`CREATE INDEX IF NOT EXISTS idx_flag_configs_env ON flag_configs(environment_id)`,
	}
	for _, m := range migrations {
		if _, err := s.db.Exec(m); err != nil {
			return fmt.Errorf("migration step: %w", err)
		}
	}
	// Add version column if upgrading from older schema (check first)
	hasVersion := false
	rows, err := s.db.Query("PRAGMA table_info(flags)")
	if err == nil {
		for rows.Next() {
			var cid int
			var name, ctype string
			var notnull, pk int
			var dflt sql.NullString
			if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err == nil {
				if name == "version" {
					hasVersion = true
					break
				}
			}
		}
		rows.Close()
	}
	if !hasVersion {
		if _, err := s.db.Exec(`ALTER TABLE flags ADD COLUMN version INTEGER NOT NULL DEFAULT 1`); err != nil {
			return fmt.Errorf("alter flags table (add version): %w", err)
		}
	}
	// Add role column to users table for existing DBs
	if _, err := s.db.Exec(`ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'member'`); err != nil {
		// Column may already exist — only fail on other errors
		if !strings.Contains(err.Error(), "duplicate column") {
			return fmt.Errorf("alter users table (add role): %w", err)
		}
	}
	return nil
}

// --- Environments ---

func (s *Store) CreateEnvironment(env *models.Environment) error {
	_, err := s.db.Exec(`INSERT INTO environments (id, key, name, description) VALUES (?, ?, ?, ?)`,
		env.ID, env.Key, env.Name, env.Description)
	return err
}

func (s *Store) ListEnvironments() ([]models.Environment, error) {
	rows, err := s.db.Query(`SELECT id, key, name, description, created_at, updated_at FROM environments ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var envs []models.Environment
	for rows.Next() {
		var e models.Environment
		if err := rows.Scan(&e.ID, &e.Key, &e.Name, &e.Description, &e.CreatedAt, &e.UpdatedAt); err != nil {
			return nil, err
		}
		envs = append(envs, e)
	}
	return envs, nil
}

func (s *Store) GetEnvironment(id string) (*models.Environment, error) {
	var e models.Environment
	err := s.db.QueryRow(`SELECT id, key, name, description, created_at, updated_at FROM environments WHERE id = ?`, id).
		Scan(&e.ID, &e.Key, &e.Name, &e.Description, &e.CreatedAt, &e.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &e, err
}

func (s *Store) GetEnvironmentByKey(key string) (*models.Environment, error) {
	var e models.Environment
	err := s.db.QueryRow(`SELECT id, key, name, description, created_at, updated_at FROM environments WHERE key = ?`, key).
		Scan(&e.ID, &e.Key, &e.Name, &e.Description, &e.CreatedAt, &e.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &e, err
}

func (s *Store) DeleteEnvironment(id string) error {
	_, err := s.db.Exec(`DELETE FROM environments WHERE id = ?`, id)
	return err
}

// --- Flags ---

func (s *Store) CreateFlag(flag *models.Flag) error {
	data, err := json.Marshal(flagData{
		Variations:    flag.Variations,
		Targeting:     flag.Targeting,
		DefaultRule:  flag.DefaultRule,
	})
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`INSERT INTO flags (id, key, name, description, type, enabled, version, data) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		flag.ID, flag.Key, flag.Name, flag.Description, flag.Type, boolToInt(flag.Enabled), flag.Version, string(data))
	return err
}

func (s *Store) ListFlags() ([]models.Flag, error) {
	rows, err := s.db.Query(`SELECT id, key, name, description, type, enabled, version, data, created_at, updated_at FROM flags ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var flags []models.Flag
	for rows.Next() {
		f, err := scanFlag(rows)
		if err != nil {
			return nil, err
		}
		flags = append(flags, *f)
	}
	return flags, nil
}

func (s *Store) GetFlag(id string) (*models.Flag, error) {
	row := s.db.QueryRow(`SELECT id, key, name, description, type, enabled, version, data, created_at, updated_at FROM flags WHERE id = ?`, id)
	return scanFlag(row)
}

func (s *Store) GetFlagByKey(key string) (*models.Flag, error) {
	row := s.db.QueryRow(`SELECT id, key, name, description, type, enabled, version, data, created_at, updated_at FROM flags WHERE key = ?`, key)
	return scanFlag(row)
}

func (s *Store) UpdateFlag(flag *models.Flag) error {
	data, err := json.Marshal(flagData{
		Variations:   flag.Variations,
		Targeting:    flag.Targeting,
		DefaultRule:  flag.DefaultRule,
	})
	if err != nil {
		return err
	}
	// R8-M1: Optimistic concurrency control — only update if the version
	// in the DB matches what we read. Prevents lost updates from concurrent
	// requests. Returns ErrNoRows if version mismatch (caller checks rows affected).
	res, err := s.db.Exec(`UPDATE flags SET key=?, name=?, description=?, type=?, enabled=?, version=?, data=?, updated_at=CURRENT_TIMESTAMP WHERE id=? AND version=?`,
		flag.Key, flag.Name, flag.Description, flag.Type, boolToInt(flag.Enabled), flag.Version, string(data), flag.ID, flag.Version-1)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("concurrent modification detected")
	}
	return nil
}

func (s *Store) DeleteFlag(id string) error {
	_, err := s.db.Exec(`DELETE FROM flags WHERE id = ?`, id)
	return err
}

// --- Flag Configs (per-environment overrides) ---

func (s *Store) GetFlagConfig(flagID, envID string) (*models.Flag, error) {
	var f models.Flag
	var dataStr string
	var enabled int
	err := s.db.QueryRow(`SELECT f.id, f.key, f.name, f.description, f.type, fc.enabled, f.version, fc.data, f.created_at, f.updated_at
		FROM flags f JOIN flag_configs fc ON fc.flag_id = f.id WHERE fc.flag_id = ? AND fc.environment_id = ?`, flagID, envID).
		Scan(&f.ID, &f.Key, &f.Name, &f.Description, &f.Type, &enabled, &f.Version, &dataStr, &f.CreatedAt, &f.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	f.Enabled = enabled == 1
	var fd flagData
	if err := json.Unmarshal([]byte(dataStr), &fd); err != nil {
		return nil, err
	}
	f.Variations = fd.Variations
	f.Targeting = fd.Targeting
	f.DefaultRule = fd.DefaultRule
	return &f, nil
}

func (s *Store) UpsertFlagConfig(flagID, envID string, enabled bool, data json.RawMessage) error {
	// Use SQLite native upsert to handle race conditions
	id := generateID()
	_, err := s.db.Exec(`INSERT INTO flag_configs (id, flag_id, environment_id, enabled, data)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(flag_id, environment_id) DO UPDATE SET enabled=excluded.enabled, data=excluded.data, updated_at=CURRENT_TIMESTAMP`,
		id, flagID, envID, boolToInt(enabled), string(data))
	return err
}

// --- Segments ---

func (s *Store) CreateSegment(seg *models.Segment) error {
	conditions, err := json.Marshal(seg.Conditions)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`INSERT INTO segments (id, key, name, description, conditions) VALUES (?, ?, ?, ?, ?)`,
		seg.ID, seg.Key, seg.Name, seg.Description, string(conditions))
	return err
}

func (s *Store) ListSegments() ([]models.Segment, error) {
	rows, err := s.db.Query(`SELECT id, key, name, description, conditions, created_at, updated_at FROM segments ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var segs []models.Segment
	for rows.Next() {
		var s models.Segment
		var conditionsStr string
		if err := rows.Scan(&s.ID, &s.Key, &s.Name, &s.Description, &conditionsStr, &s.CreatedAt, &s.UpdatedAt); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(conditionsStr), &s.Conditions); err != nil {
			return nil, err
		}
		segs = append(segs, s)
	}
	return segs, nil
}

func (s *Store) DeleteSegment(id string) error {
	_, err := s.db.Exec(`DELETE FROM segments WHERE id = ?`, id)
	return err
}

// GetSegment returns a segment by ID (for existence checks).
func (s *Store) GetSegment(id string) (*models.Segment, error) {
	var seg models.Segment
	var conditionsStr string
	err := s.db.QueryRow(`SELECT id, key, name, description, conditions, created_at, updated_at FROM segments WHERE id = ?`, id).
		Scan(&seg.ID, &seg.Key, &seg.Name, &seg.Description, &conditionsStr, &seg.CreatedAt, &seg.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(conditionsStr), &seg.Conditions); err != nil {
		return nil, err
	}
	return &seg, nil
}

// --- API Keys ---

func (s *Store) CreateAPIKey(key *models.APIKey) error {
	scopes, err := json.Marshal(key.Scopes)
	if err != nil {
		return err
	}
	var expiresAt any
	if key.ExpiresAt != nil {
		expiresAt = key.ExpiresAt
	}
	var envID any
	if key.EnvironmentID != "" {
		envID = key.EnvironmentID
	}
	_, err = s.db.Exec(`INSERT INTO api_keys (id, name, key_hash, key_prefix, environment_id, scopes, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		key.ID, key.Name, key.KeyHash, key.KeyPrefix, envID, string(scopes), expiresAt)
	return err
}

func (s *Store) ListAPIKeys() ([]models.APIKey, error) {
	rows, err := s.db.Query(`SELECT id, name, key_prefix, environment_id, scopes, last_used_at, expires_at, created_at, revoked FROM api_keys ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var keys []models.APIKey
	for rows.Next() {
		var k models.APIKey
		var scopesStr string
		var lastUsed sql.NullTime
		var expires sql.NullTime
		var envID sql.NullString
		if err := rows.Scan(&k.ID, &k.Name, &k.KeyPrefix, &envID, &scopesStr, &lastUsed, &expires, &k.CreatedAt, &k.Revoked); err != nil {
			return nil, err
		}
		if envID.Valid {
			k.EnvironmentID = envID.String
		}
		if lastUsed.Valid {
			k.LastUsedAt = &lastUsed.Time
		}
		if expires.Valid {
			k.ExpiresAt = &expires.Time
		}
		if err := json.Unmarshal([]byte(scopesStr), &k.Scopes); err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	return keys, nil
}

func (s *Store) GetAPIKeyByHash(hash string) (*models.APIKey, error) {
	var k models.APIKey
	var scopesStr string
	var lastUsed sql.NullTime
	var expires sql.NullTime
	var envID sql.NullString
	err := s.db.QueryRow(`SELECT id, name, key_prefix, environment_id, scopes, last_used_at, expires_at, created_at, revoked FROM api_keys WHERE key_hash = ?`, hash).
		Scan(&k.ID, &k.Name, &k.KeyPrefix, &envID, &scopesStr, &lastUsed, &expires, &k.CreatedAt, &k.Revoked)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if envID.Valid {
		k.EnvironmentID = envID.String
	}
	if lastUsed.Valid {
		k.LastUsedAt = &lastUsed.Time
	}
	if expires.Valid {
		k.ExpiresAt = &expires.Time
	}
	if err := json.Unmarshal([]byte(scopesStr), &k.Scopes); err != nil {
		return nil, err
	}
	return &k, nil
}

func (s *Store) UpdateAPIKeyLastUsed(id string) error {
	_, err := s.db.Exec(`UPDATE api_keys SET last_used_at = CURRENT_TIMESTAMP WHERE id = ?`, id)
	return err
}

func (s *Store) RevokeAPIKey(id string) error {
	_, err := s.db.Exec(`UPDATE api_keys SET revoked = 1 WHERE id = ?`, id)
	return err
}

// GetAPIKeyByID returns an API key by ID (for existence checks).
func (s *Store) GetAPIKeyByID(id string) (*models.APIKey, error) {
	var k models.APIKey
	var scopesStr string
	var lastUsed sql.NullTime
	var expires sql.NullTime
	var envID sql.NullString
	err := s.db.QueryRow(`SELECT id, name, key_prefix, environment_id, scopes, last_used_at, expires_at, created_at, revoked FROM api_keys WHERE id = ?`, id).
		Scan(&k.ID, &k.Name, &k.KeyPrefix, &envID, &scopesStr, &lastUsed, &expires, &k.CreatedAt, &k.Revoked)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if envID.Valid {
		k.EnvironmentID = envID.String
	}
	if lastUsed.Valid {
		k.LastUsedAt = &lastUsed.Time
	}
	if expires.Valid {
		k.ExpiresAt = &expires.Time
	}
	if err := json.Unmarshal([]byte(scopesStr), &k.Scopes); err != nil {
		return nil, err
	}
	return &k, nil
}

// --- Audit Log ---

func (s *Store) CreateAuditEntry(entry *models.AuditLogEntry) error {
	_, err := s.db.Exec(`INSERT INTO audit_log (id, actor, action, resource, resource_id, details) VALUES (?, ?, ?, ?, ?, ?)`,
		entry.ID, entry.Actor, entry.Action, entry.Resource, entry.ResourceID, entry.Details)
	return err
}

func (s *Store) ListAuditEntries(limit, offset int) ([]models.AuditLogEntry, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}
	rows, err := s.db.Query(`SELECT id, actor, action, resource, resource_id, details, timestamp FROM audit_log ORDER BY timestamp DESC LIMIT ? OFFSET ?`, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var entries []models.AuditLogEntry
	for rows.Next() {
		var e models.AuditLogEntry
		if err := rows.Scan(&e.ID, &e.Actor, &e.Action, &e.Resource, &e.ResourceID, &e.Details, &e.Timestamp); err != nil {
			return nil, err
		}
		entries = append(entries, e)
	}
	return entries, nil
}

// --- Users ---

func (s *Store) GetOrCreateUser(email, name string) (*models.User, error) {
	// Try to find existing
	var u models.User
	err := s.db.QueryRow(`SELECT id, email, name, role FROM users WHERE email = ?`, email).Scan(&u.ID, &u.Email, &u.Name, &u.Role)
	if err == nil {
		return &u, nil
	}
	if err != sql.ErrNoRows {
		return nil, err
	}
	// Use INSERT ON CONFLICT to handle race condition (two concurrent logins for same email)
	u.ID = generateID()
	u.Email = email
	u.Name = name
	u.Role = "member"
	_, err = s.db.Exec(`INSERT INTO users (id, email, name, role) VALUES (?, ?, ?, ?) ON CONFLICT(email) DO NOTHING`, u.ID, u.Email, u.Name, u.Role)
	if err != nil {
		return nil, err
	}
	// Re-select to get the row (either ours or the winner of the race)
	err = s.db.QueryRow(`SELECT id, email, name, role FROM users WHERE email = ?`, email).Scan(&u.ID, &u.Email, &u.Name, &u.Role)
	if err != nil {
		return nil, err
	}
	return &u, nil
}

// --- Helpers ---

type flagData struct {
	Variations   []models.Variation     `json:"variations"`
	Targeting    []models.TargetingRule `json:"targeting_rules"`
	DefaultRule  *models.DefaultRule     `json:"default_rule,omitempty"`
}

type scanner interface {
	Scan(dest ...any) error
}

func scanFlag(row scanner) (*models.Flag, error) {
	var f models.Flag
	var dataStr string
	var enabled int
	if err := row.Scan(&f.ID, &f.Key, &f.Name, &f.Description, &f.Type, &enabled, &f.Version, &dataStr, &f.CreatedAt, &f.UpdatedAt); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	f.Enabled = enabled == 1
	var fd flagData
	if err := json.Unmarshal([]byte(dataStr), &fd); err != nil {
		return nil, err
	}
	f.Variations = fd.Variations
	f.Targeting = fd.Targeting
	f.DefaultRule = fd.DefaultRule
	return &f, nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func generateID() string {
	return uuid.New().String()
}

// --- Secrets ---

func (s *Store) CreateSecret(secret *models.Secret) error {
	// R8-H4: Use NULL for empty environment_id to avoid FK constraint failure
	var envID any
	if secret.EnvironmentID != "" {
		envID = secret.EnvironmentID
	}
	_, err := s.db.Exec(`INSERT INTO secrets (id, key, name, description, encrypted_value, environment_id) VALUES (?, ?, ?, ?, ?, ?)`,
		secret.ID, secret.Key, secret.Name, secret.Description, secret.EncryptedValue, envID)
	return err
}

func (s *Store) ListSecrets() ([]models.Secret, error) {
	rows, err := s.db.Query(`SELECT id, key, name, description, encrypted_value, environment_id, created_at, updated_at FROM secrets ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var secrets []models.Secret
	for rows.Next() {
		var sec models.Secret
		if err := rows.Scan(&sec.ID, &sec.Key, &sec.Name, &sec.Description, &sec.EncryptedValue, &sec.EnvironmentID, &sec.CreatedAt, &sec.UpdatedAt); err != nil {
			return nil, err
		}
		secrets = append(secrets, sec)
	}
	return secrets, nil
}

func (s *Store) GetSecret(id string) (*models.Secret, error) {
	var sec models.Secret
	err := s.db.QueryRow(`SELECT id, key, name, description, encrypted_value, environment_id, created_at, updated_at FROM secrets WHERE id = ?`, id).
		Scan(&sec.ID, &sec.Key, &sec.Name, &sec.Description, &sec.EncryptedValue, &sec.EnvironmentID, &sec.CreatedAt, &sec.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &sec, nil
}

func (s *Store) GetSecretByKey(key string) (*models.Secret, error) {
	var sec models.Secret
	err := s.db.QueryRow(`SELECT id, key, name, description, encrypted_value, environment_id, created_at, updated_at FROM secrets WHERE key = ?`, key).
		Scan(&sec.ID, &sec.Key, &sec.Name, &sec.Description, &sec.EncryptedValue, &sec.EnvironmentID, &sec.CreatedAt, &sec.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &sec, nil
}

func (s *Store) UpdateSecret(secret *models.Secret) error {
	// R8-H4: Use NULL for empty environment_id to avoid FK constraint failure
	var envID any
	if secret.EnvironmentID != "" {
		envID = secret.EnvironmentID
	}
	_, err := s.db.Exec(`UPDATE secrets SET key=?, name=?, description=?, encrypted_value=?, environment_id=?, updated_at=CURRENT_TIMESTAMP WHERE id=?`,
		secret.Key, secret.Name, secret.Description, secret.EncryptedValue, envID, secret.ID)
	return err
}

func (s *Store) DeleteSecret(id string) error {
	_, err := s.db.Exec(`DELETE FROM secrets WHERE id = ?`, id)
	return err
}

// --- Organizations ---

func (s *Store) CreateOrg(org *models.Organization) error {
	_, err := s.db.Exec(`INSERT INTO organizations (id, name, slug, description) VALUES (?, ?, ?, ?)`,
		org.ID, org.Name, org.Slug, org.Description)
	return err
}

func (s *Store) ListOrgs() ([]models.Organization, error) {
	rows, err := s.db.Query(`SELECT id, name, slug, description, created_at, updated_at FROM organizations ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var orgs []models.Organization
	for rows.Next() {
		var o models.Organization
		if err := rows.Scan(&o.ID, &o.Name, &o.Slug, &o.Description, &o.CreatedAt, &o.UpdatedAt); err != nil {
			return nil, err
		}
		orgs = append(orgs, o)
	}
	return orgs, nil
}

func (s *Store) GetOrg(id string) (*models.Organization, error) {
	var o models.Organization
	err := s.db.QueryRow(`SELECT id, name, slug, description, created_at, updated_at FROM organizations WHERE id = ?`, id).
		Scan(&o.ID, &o.Name, &o.Slug, &o.Description, &o.CreatedAt, &o.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &o, err
}

func (s *Store) DeleteOrg(id string) error {
	_, err := s.db.Exec(`DELETE FROM organizations WHERE id = ?`, id)
	return err
}

// --- Org Members ---

func (s *Store) AddOrgMember(member *models.OrgMember) error {
	_, err := s.db.Exec(`INSERT INTO org_members (id, user_id, org_id, role) VALUES (?, ?, ?, ?)`,
		member.ID, member.UserID, member.OrgID, member.Role)
	return err
}

func (s *Store) ListOrgMembers(orgID string) ([]models.OrgMember, error) {
	rows, err := s.db.Query(`SELECT om.id, om.user_id, om.org_id, om.role, om.created_at, u.name, u.email
		FROM org_members om JOIN users u ON u.id = om.user_id WHERE om.org_id = ? ORDER BY om.created_at`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var members []models.OrgMember
	for rows.Next() {
		var m models.OrgMember
		if err := rows.Scan(&m.ID, &m.UserID, &m.OrgID, &m.Role, &m.CreatedAt, &m.UserName, &m.UserEmail); err != nil {
			return nil, err
		}
		members = append(members, m)
	}
	return members, nil
}

// GetOrgMemberByID returns a single org member by member ID.
// Used for authz checks in update/remove operations.
func (s *Store) GetOrgMemberByID(memberID string) (*models.OrgMember, error) {
	var m models.OrgMember
	err := s.db.QueryRow(`SELECT id, user_id, org_id, role FROM org_members WHERE id = ?`, memberID).
		Scan(&m.ID, &m.UserID, &m.OrgID, &m.Role)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &m, nil
}

func (s *Store) UpdateOrgMemberRole(memberID, role string) error {
	_, err := s.db.Exec(`UPDATE org_members SET role = ? WHERE id = ?`, role, memberID)
	return err
}

func (s *Store) RemoveOrgMember(memberID string) error {
	_, err := s.db.Exec(`DELETE FROM org_members WHERE id = ?`, memberID)
	return err
}

func (s *Store) GetUserOrgRole(userID, orgID string) (string, error) {
	var role string
	err := s.db.QueryRow(`SELECT role FROM org_members WHERE user_id = ? AND org_id = ?`, userID, orgID).Scan(&role)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return role, err
}

func (s *Store) GetUserByEmail(email string) (*models.User, error) {
	var u models.User
	err := s.db.QueryRow(`SELECT id, email, name, role FROM users WHERE email = ?`, email).Scan(&u.ID, &u.Email, &u.Name, &u.Role)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &u, nil
}
