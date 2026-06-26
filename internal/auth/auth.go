package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/dovocoder/reflag/internal/middleware"
	"github.com/dovocoder/reflag/internal/models"
	"github.com/dovocoder/reflag/internal/store"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

const (
	// Context keys
	ContextKeyUser    = "user"
	ContextKeyAPIKey  = "apiKey"
	ContextKeyActor   = "actor"
)

// AuthService handles both OIDC (admin UI) and API key (programmatic) auth.
type AuthService struct {
	store     *store.Store
	jwtSecret string
	oidcIssuer    string
	oidcClientID  string
	oidcClientSec string
	oidcRedirect  string

	// Hardcoded admin credentials
	adminEmail      string
	adminPassHash   []byte // bcrypt hash

	// OIDC discovery cache
	mu            sync.Mutex
	discovery     *OIDCDiscovery
	discoveryExpiry time.Time

	// HTTP client with timeout for OIDC requests
	httpClient *http.Client
}

type OIDCDiscovery struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

type Claims struct {
	Email string `json:"email"`
	Name  string `json:"name"`
	Role  string `json:"role"`
	jwt.RegisteredClaims
}

func New(s *store.Store, jwtSecret, oidcIssuer, oidcClientID, oidcClientSec, oidcRedirect string) *AuthService {
	return &AuthService{
		store:         s,
		jwtSecret:     jwtSecret,
		oidcIssuer:    oidcIssuer,
		oidcClientID:  oidcClientID,
		oidcClientSec: oidcClientSec,
		oidcRedirect:  oidcRedirect,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// SetAdminCredentials configures the hardcoded admin account.
// The password is hashed with bcrypt at startup — plaintext is never retained.
func (a *AuthService) SetAdminCredentials(email, password string) error {
	if password == "" {
		return fmt.Errorf("admin password is required")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash admin password: %w", err)
	}
	a.adminEmail = email
	a.adminPassHash = hash
	return nil
}

// --- JWT ---

func (a *AuthService) GenerateJWT(user *models.User) (string, error) {
	role := user.Role
	if role == "" {
		role = "member"
	}
	claims := &Claims{
		Email: user.Email,
		Name:  user.Name,
		Role:  role,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   user.ID,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "reflag",
			Audience:  []string{"reflag"},
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(a.jwtSecret))
}

// LoginAdmin checks hardcoded admin credentials and returns a JWT.
func (a *AuthService) LoginAdmin(email, password string) (*models.User, string, error) {
	if a.adminEmail == "" || len(a.adminPassHash) == 0 {
		return nil, "", fmt.Errorf("admin login not configured")
	}
	// Constant-time email comparison
	emailMatch := subtle.ConstantTimeCompare([]byte(email), []byte(a.adminEmail)) == 1
	if !emailMatch {
		// Still run bcrypt to prevent timing attacks
		_ = bcrypt.CompareHashAndPassword(a.adminPassHash, []byte(password))
		return nil, "", fmt.Errorf("invalid credentials")
	}
	// bcrypt comparison (constant-time internally)
	if err := bcrypt.CompareHashAndPassword(a.adminPassHash, []byte(password)); err != nil {
		return nil, "", fmt.Errorf("invalid credentials")
	}
	user := &models.User{
		ID:    "admin",
		Email: a.adminEmail,
		Name:  "Administrator",
		Role:  "admin",
	}
	token, err := a.GenerateJWT(user)
	if err != nil {
		return nil, "", err
	}
	return user, token, nil
}

func (a *AuthService) ValidateJWT(tokenStr string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return []byte(a.jwtSecret), nil
	}, jwt.WithIssuer("reflag"), jwt.WithAudience("reflag"))
	if err != nil {
		return nil, err
	}
	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}
	return nil, fmt.Errorf("invalid token")
}

// --- API Keys ---

func GenerateAPIKey() (rawKey string, hash string, prefix string, err error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", "", "", err
	}
	rawKey = "rfk_" + hex.EncodeToString(bytes)
	hash = HashAPIKey(rawKey)
	prefix = rawKey[:12] + "..."
	return rawKey, hash, prefix, nil
}

func HashAPIKey(key string) string {
	h := sha256.Sum256([]byte(key))
	return hex.EncodeToString(h[:])
}

func (a *AuthService) ValidateAPIKey(key string) (*models.APIKey, error) {
	hash := HashAPIKey(key)
	apiKey, err := a.store.GetAPIKeyByHash(hash)
	if err != nil {
		return nil, err
	}
	if apiKey == nil {
		return nil, fmt.Errorf("invalid API key")
	}
	if apiKey.Revoked {
		return nil, fmt.Errorf("API key revoked")
	}
	if apiKey.ExpiresAt != nil && time.Now().After(*apiKey.ExpiresAt) {
		return nil, fmt.Errorf("API key expired")
	}
	// Update last used (fire and forget)
	go a.store.UpdateAPIKeyLastUsed(apiKey.ID)
	return apiKey, nil
}

// HasScope checks if the API key has a specific scope.
// Empty scopes means all access (backward compatibility).
func HasScope(ctx context.Context, scope string) bool {
	apiKey := APIKeyFromContext(ctx)
	if apiKey == nil {
		return false
	}
	if len(apiKey.Scopes) == 0 {
		return true // no scope restriction
	}
	for _, s := range apiKey.Scopes {
		if s == scope || s == "*" {
			return true
		}
	}
	return false
}

// RequireScope is middleware that checks the API key has the required scope.
func (a *AuthService) RequireScope(scope string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !HasScope(r.Context(), scope) {
				middleware.JSONError(w, http.StatusForbidden, fmt.Sprintf("API key missing required scope: %s", scope))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// --- OIDC ---

func (a *AuthService) GetDiscovery() (*OIDCDiscovery, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.discovery != nil && time.Now().Before(a.discoveryExpiry) {
		return a.discovery, nil
	}

	if a.oidcIssuer == "" {
		return nil, fmt.Errorf("OIDC issuer not configured")
	}

	discoveryURL := strings.TrimSuffix(a.oidcIssuer, "/") + "/.well-known/openid-configuration"
	resp, err := a.httpClient.Get(discoveryURL)
	if err != nil {
		return nil, fmt.Errorf("OIDC discovery failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OIDC discovery returned %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1MB max
	if err != nil {
		return nil, err
	}
	var d OIDCDiscovery
	if err := json.Unmarshal(body, &d); err != nil {
		return nil, err
	}
	a.discovery = &d
	a.discoveryExpiry = time.Now().Add(15 * time.Minute)
	return &d, nil
}

func (a *AuthService) GetAuthorizationURL(state string) (string, error) {
	d, err := a.GetDiscovery()
	if err != nil {
		return "", err
	}
	params := url.Values{
		"response_type": {"code"},
		"client_id":     {a.oidcClientID},
		"redirect_uri":  {a.oidcRedirect},
		"scope":         {"openid email profile"},
		"state":         {state},
	}
	return d.AuthorizationEndpoint + "?" + params.Encode(), nil
}

func (a *AuthService) ExchangeCode(code string) (*models.User, string, error) {
	d, err := a.GetDiscovery()
	if err != nil {
		return nil, "", err
	}

	data := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {a.oidcRedirect},
		"client_id":     {a.oidcClientID},
		"client_secret": {a.oidcClientSec},
	}
	resp, err := a.httpClient.PostForm(d.TokenEndpoint, data)
	if err != nil {
		return nil, "", fmt.Errorf("token exchange failed: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1MB max
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("token exchange returned %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		IDToken     string `json:"id_token"`
	}
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, "", err
	}

	// Fetch userinfo
	req, _ := http.NewRequest("GET", d.UserinfoEndpoint, nil)
	req.Header.Set("Authorization", "Bearer "+tokenResp.AccessToken)
	resp2, err := a.httpClient.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("userinfo fetch failed: %w", err)
	}
	defer resp2.Body.Close()
	body2, _ := io.ReadAll(io.LimitReader(resp2.Body, 1<<20)) // 1MB max
	if resp2.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("userinfo returned %d", resp2.StatusCode)
	}

	var info struct {
		Email string `json:"email"`
		Name  string `json:"name"`
		Sub   string `json:"sub"`
	}
	if err := json.Unmarshal(body2, &info); err != nil {
		return nil, "", err
	}

	user, err := a.store.GetOrCreateUser(info.Email, info.Name)
	if err != nil {
		return nil, "", err
	}

	jwtToken, err := a.GenerateJWT(user)
	if err != nil {
		return nil, "", err
	}

	return user, jwtToken, nil
}

// --- Middleware ---

type contextKey string

const (
	userKey      contextKey = "user"
	apiKeyKey    contextKey = "apiKey"
	rawAPIKeyKey contextKey = "rawAPIKey"
	actorKey     contextKey = "actor"
)

func UserFromContext(ctx context.Context) *models.User {
	if u, ok := ctx.Value(userKey).(*models.User); ok {
		return u
	}
	return nil
}

func APIKeyFromContext(ctx context.Context) *models.APIKey {
	if k, ok := ctx.Value(apiKeyKey).(*models.APIKey); ok {
		return k
	}
	return nil
}

func ActorFromContext(ctx context.Context) string {
	if a, ok := ctx.Value(actorKey).(string); ok {
		return a
	}
	return "unknown"
}

// RawAPIKeyFromContext returns the raw API key string from the context.
// Used for transport encryption of secret responses.
func RawAPIKeyFromContext(ctx context.Context) string {
	if k, ok := ctx.Value(rawAPIKeyKey).(string); ok {
		return k
	}
	return ""
}

// JWTMiddleware validates a JWT from the Authorization header.
func (a *AuthService) JWTMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			http.Error(w, `{"error":"missing or invalid authorization header"}`, http.StatusUnauthorized)
			return
		}
		tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
		// Don't treat API keys as JWTs
		if strings.HasPrefix(tokenStr, "rfk_") {
			http.Error(w, `{"error":"API key not accepted for admin endpoints"}`, http.StatusUnauthorized)
			return
		}
		claims, err := a.ValidateJWT(tokenStr)
		if err != nil {
			http.Error(w, `{"error":"invalid token"}`, http.StatusUnauthorized)
			return
		}
		user := &models.User{ID: claims.Subject, Email: claims.Email, Name: claims.Name, Role: claims.Role}
		ctx := context.WithValue(r.Context(), userKey, user)
		ctx = context.WithValue(ctx, actorKey, user.Email)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequireRole is middleware that checks the authenticated user has one of the allowed roles.
// Must be used after JWTMiddleware.
func (a *AuthService) RequireRole(allowedRoles ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user := UserFromContext(r.Context())
			if user == nil {
				middleware.JSONError(w, http.StatusUnauthorized, "authentication required")
				return
			}
			// Admin bypasses all role checks
			if user.Role == "admin" {
				next.ServeHTTP(w, r)
				return
			}
			for _, role := range allowedRoles {
				if user.Role == role {
					next.ServeHTTP(w, r)
					return
				}
			}
			middleware.JSONError(w, http.StatusForbidden, "insufficient permissions")
		})
	}
}

// APIKeyMiddleware validates an API key from X-API-Key header or Authorization: Bearer rfk_...
func (a *AuthService) APIKeyMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var key string
		if k := r.Header.Get("X-API-Key"); k != "" {
			key = k
		} else if authHeader := r.Header.Get("Authorization"); strings.HasPrefix(authHeader, "Bearer rfk_") {
			key = strings.TrimPrefix(authHeader, "Bearer ")
		}
		if key == "" {
			http.Error(w, `{"error":"missing API key"}`, http.StatusUnauthorized)
			return
		}
		apiKey, err := a.ValidateAPIKey(key)
		if err != nil {
			http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), apiKeyKey, apiKey)
		ctx = context.WithValue(ctx, rawAPIKeyKey, key)
		ctx = context.WithValue(ctx, actorKey, apiKey.ID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// AnyAuthMiddleware accepts either JWT or API key.
func (a *AuthService) AnyAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if strings.HasPrefix(authHeader, "Bearer rfk_") || r.Header.Get("X-API-Key") != "" {
			a.APIKeyMiddleware(next).ServeHTTP(w, r)
			return
		}
		if strings.HasPrefix(authHeader, "Bearer ") {
			a.JWTMiddleware(next).ServeHTTP(w, r)
			return
		}
		http.Error(w, `{"error":"authentication required"}`, http.StatusUnauthorized)
	})
}

// ValidateState verifies an OIDC state token using HMAC-SHA256.
// State = random_hex + "." + HMAC(random_hex, jwtSecret)
// This prevents CSRF in the OIDC flow without server-side session storage.
func (a *AuthService) ValidateState(state string) bool {
	parts := strings.SplitN(state, ".", 2)
	if len(parts) != 2 {
		return false
	}
	nonce, sig := parts[0], parts[1]
	expectedSig := a.signState(nonce)
	return subtle.ConstantTimeCompare([]byte(sig), []byte(expectedSig)) == 1
}

func (a *AuthService) signState(nonce string) string {
	h := hmac.New(sha256.New, []byte(a.jwtSecret))
	h.Write([]byte("oidc-state:"))
	h.Write([]byte(nonce))
	return hex.EncodeToString(h.Sum(nil))
}

// GenerateState generates a random OIDC state token with HMAC signature.
func (a *AuthService) GenerateState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	nonce := hex.EncodeToString(b)
	return nonce + "." + a.signState(nonce), nil
}
