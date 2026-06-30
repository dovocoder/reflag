package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dovocoder/reflag/internal/middleware"
	"github.com/dovocoder/reflag/internal/models"
	"github.com/dovocoder/reflag/internal/store"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// AuthService handles both OIDC (admin UI) and API key (programmatic) auth.
type AuthService struct {
	store         *store.Store
	jwtSecret     string
	oidcIssuer    string
	oidcClientID  string
	oidcClientSec string
	oidcRedirect  string

	// Hardcoded admin credentials
	adminEmail    string
	adminPassHash []byte // bcrypt hash

	// OIDC discovery cache
	mu              sync.Mutex
	discovery       *OIDCDiscovery
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
			ID:        uuid.New().String(),
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
	// Show only last 4 chars as display prefix to minimize key material exposure
	if len(rawKey) > 8 {
		prefix = "rfk_..." + rawKey[len(rawKey)-4:]
	} else {
		prefix = "rfk_..."
	}
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
		return nil, fmt.Errorf("invalid API key")
	}
	if apiKey == nil {
		return nil, fmt.Errorf("invalid API key")
	}
	if apiKey.Revoked {
		return nil, fmt.Errorf("invalid API key")
	}
	if apiKey.ExpiresAt != nil && time.Now().After(*apiKey.ExpiresAt) {
		return nil, fmt.Errorf("invalid API key")
	}
	// Update last used (fire and forget)
	go a.store.UpdateAPIKeyLastUsed(apiKey.ID)
	return apiKey, nil
}

// HasScope checks if the API key has a specific scope.
// Empty scopes means no access (default-deny).
func HasScope(ctx context.Context, scope string) bool {
	apiKey, ok := ctx.Value(apiKeyKey).(*models.APIKey)
	if !ok || apiKey == nil {
		return false
	}
	for _, s := range apiKey.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}

// RequireScope is middleware that checks the API key has the required scope.
// JWT-authenticated users (admin UI) bypass scope checks — they have full access.
func (a *AuthService) RequireScope(scope string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// JWT-authenticated users bypass scope checks
			if UserFromContext(r.Context()) != nil {
				next.ServeHTTP(w, r)
				return
			}
			if !HasScope(r.Context(), scope) {
				middleware.JSONError(w, http.StatusForbidden, fmt.Sprintf("API key missing required scope: %s", scope))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// --- OIDC ---

// IsOIDCConfigured returns true if the OIDC issuer and client credentials
// are set. This is a lightweight check that does NOT make network requests
// or set cookies — use it for availability checks (e.g. showing the OIDC
// button on the login page) instead of calling oidcStart.
func (a *AuthService) IsOIDCConfigured() bool {
	return a.oidcIssuer != "" && a.oidcClientID != "" && a.oidcRedirect != ""
}

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
	if d.Issuer != a.oidcIssuer {
		return nil, fmt.Errorf("OIDC discovery issuer mismatch: expected %q, got %q", a.oidcIssuer, d.Issuer)
	}
	a.discovery = &d
	a.discoveryExpiry = time.Now().Add(15 * time.Minute)
	return &d, nil
}

func (a *AuthService) GetAuthorizationURL(state string) (string, string, error) {
	d, err := a.GetDiscovery()
	if err != nil {
		return "", "", err
	}
	// PKCE: generate code_verifier and derive code_challenge
	verifier, err := generateCodeVerifier()
	if err != nil {
		return "", "", fmt.Errorf("failed to generate PKCE verifier: %w", err)
	}
	challenge := deriveCodeChallenge(verifier)
	params := url.Values{
		"response_type":         {"code"},
		"client_id":             {a.oidcClientID},
		"redirect_uri":          {a.oidcRedirect},
		"scope":                 {"openid email profile"},
		"state":                 {state},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	return d.AuthorizationEndpoint + "?" + params.Encode(), verifier, nil
}

// generateCodeVerifier creates a random PKCE code verifier (43-128 chars, RFC 7636).
func generateCodeVerifier() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// deriveCodeChallenge computes the S256 code challenge from a verifier (RFC 7636).
func deriveCodeChallenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

func (a *AuthService) ExchangeCode(code, codeVerifier string) (*models.User, string, error) {
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
	if codeVerifier != "" {
		data.Set("code_verifier", codeVerifier)
	}
	// R9-M1: PKCE verifier must be present — without it, the token exchange
	// is vulnerable to authorization code interception attacks (RFC 7636).
	if codeVerifier == "" {
		return nil, "", fmt.Errorf("PKCE verifier required for token exchange")
	}
	resp, err := a.httpClient.PostForm(d.TokenEndpoint, data)
	if err != nil {
		return nil, "", fmt.Errorf("token exchange failed: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1MB max
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("token exchange failed (status %d)", resp.StatusCode)
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		IDToken     string `json:"id_token"`
	}
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, "", err
	}

	// R10-M7: Require ID token — without it, there's no cryptographic
	// proof of identity. The userinfo endpoint alone is not sufficient
	// because the access token could be intercepted or leaked.
	if tokenResp.IDToken == "" {
		return nil, "", fmt.Errorf("OIDC provider did not return an ID token — cannot verify identity")
	}
	idTokenClaims, err := a.verifyIDToken(tokenResp.IDToken)
	if err != nil {
		return nil, "", fmt.Errorf("ID token verification failed: %w", err)
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

	// Use sub as the primary identity — email is mutable and can be reused.
	// sub is the cryptographically verified subject identifier from the IdP.
	// R9-H1: Actually use sub for user lookup, not just validation.
	if info.Sub == "" {
		return nil, "", fmt.Errorf("OIDC userinfo missing sub claim")
	}
	// R17-M?: Verify the userinfo subject matches the verified ID token subject
	// to prevent token substitution attacks.
	if info.Sub != idTokenClaims.Subject {
		return nil, "", fmt.Errorf("OIDC userinfo subject does not match ID token subject")
	}
	user, err := a.store.GetOrCreateUserBySub(idTokenClaims.Subject, info.Email, info.Name)
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

// JWTMiddleware validates a JWT from the Authorization header or reflag_token cookie.
func (a *AuthService) JWTMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var tokenStr string
		authHeader := r.Header.Get("Authorization")
		if strings.HasPrefix(authHeader, "Bearer ") {
			tokenStr = strings.TrimPrefix(authHeader, "Bearer ")
		} else if cookie, err := r.Cookie("reflag_token"); err == nil && cookie.Value != "" {
			tokenStr = cookie.Value
		}
		if tokenStr == "" {
			http.Error(w, `{"error":"missing or invalid authorization header"}`, http.StatusUnauthorized)
			return
		}
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
			http.Error(w, `{"error":"invalid API key"}`, http.StatusUnauthorized)
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

// GenerateState generates a random OIDC state token with HMAC signature and timestamp.
// Format: nonce.timestamp.signature
// State is valid for max 10 minutes (600 seconds) after generation.
func (a *AuthService) GenerateState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	nonce := hex.EncodeToString(b)
	ts := time.Now().Unix()
	sig := a.signState(nonce + "." + strconv.FormatInt(ts, 10))
	return nonce + "." + strconv.FormatInt(ts, 10) + "." + sig, nil
}

// ValidateState verifies an OIDC state token using HMAC-SHA256 and checks expiry.
// State = nonce.timestamp.signature — valid for max 10 minutes.
func (a *AuthService) ValidateState(state string) bool {
	parts := strings.SplitN(state, ".", 3)
	if len(parts) != 3 {
		return false
	}
	nonce, tsStr, sig := parts[0], parts[1], parts[2]
	expectedSig := a.signState(nonce + "." + tsStr)
	if subtle.ConstantTimeCompare([]byte(sig), []byte(expectedSig)) != 1 {
		return false
	}
	// Check timestamp — state expires after 10 minutes
	ts, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		return false
	}
	if time.Now().Unix()-ts > 600 {
		return false
	}
	return true
}

// verifyIDToken verifies the OIDC ID token signature and claims.
// Fetches the JWKS from the issuer's jwks_uri and validates the token.
// On success it returns the verified registered claims.
func (a *AuthService) verifyIDToken(idToken string) (*jwt.RegisteredClaims, error) {
	d, err := a.GetDiscovery()
	if err != nil {
		return nil, fmt.Errorf("discovery failed: %w", err)
	}
	// Parse the token without verification first to get the kid
	parsed, _, err := jwt.NewParser().ParseUnverified(idToken, &jwt.RegisteredClaims{})
	if err != nil {
		return nil, fmt.Errorf("failed to parse ID token: %w", err)
	}
	// Validate issuer and audience
	claims, ok := parsed.Claims.(*jwt.RegisteredClaims)
	if !ok {
		return nil, fmt.Errorf("unexpected claims type in ID token")
	}
	if claims.Issuer != a.oidcIssuer {
		return nil, fmt.Errorf("ID token issuer mismatch: expected %s, got %s", a.oidcIssuer, claims.Issuer)
	}
	if err := a.validateIDTokenAudience(claims); err != nil {
		return nil, err
	}
	if claims.ExpiresAt != nil && time.Now().After(claims.ExpiresAt.Time) {
		return nil, fmt.Errorf("ID token expired")
	}
	// R8-M2: Check not-before claim — reject tokens that are not yet valid
	if claims.NotBefore != nil && time.Now().Before(claims.NotBefore.Time) {
		return nil, fmt.Errorf("ID token not yet valid")
	}
	// Fetch JWKS and verify signature
	jwksResp, err := a.httpClient.Get(d.JWKSURI)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer jwksResp.Body.Close()
	jwksBody, err := io.ReadAll(io.LimitReader(jwksResp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("failed to read JWKS: %w", err)
	}
	var jwks struct {
		Keys []struct {
			Kty string `json:"kty"`
			Kid string `json:"kid"`
			Use string `json:"use"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(jwksBody, &jwks); err != nil {
		return nil, fmt.Errorf("failed to parse JWKS: %w", err)
	}
	// Find the signing key by kid
	kid := ""
	if header, ok := parsed.Header["kid"]; ok {
		if kidStr, ok := header.(string); ok {
			kid = kidStr
		}
	}
	if kid == "" {
		// R5-16: Reject tokens without kid when multiple keys exist in JWKS
		if len(jwks.Keys) != 1 {
			return nil, fmt.Errorf("ID token missing kid and multiple JWKS keys present")
		}
	}
	var signingKey *struct {
		Kty string `json:"kty"`
		Kid string `json:"kid"`
		Use string `json:"use"`
		N   string `json:"n"`
		E   string `json:"e"`
	}
	for i := range jwks.Keys {
		if jwks.Keys[i].Kid == kid || kid == "" {
			signingKey = &jwks.Keys[i]
			break
		}
	}
	if signingKey == nil {
		return nil, fmt.Errorf("signing key not found in JWKS for kid %s", kid)
	}
	// Verify the token signature using the JWKS key
	verified, err := jwt.Parse(idToken, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		// Construct RSA public key from n and e
		nBytes, err := base64.RawURLEncoding.DecodeString(signingKey.N)
		if err != nil {
			return nil, fmt.Errorf("failed to decode n: %w", err)
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(signingKey.E)
		if err != nil {
			return nil, fmt.Errorf("failed to decode e: %w", err)
		}
		e := 0
		for _, b := range eBytes {
			e = e<<8 + int(b)
		}
		pubKey := &rsa.PublicKey{
			N: new(big.Int).SetBytes(nBytes),
			E: e,
		}
		return pubKey, nil
	}, jwt.WithIssuer(a.oidcIssuer), jwt.WithAudience(a.oidcClientID))
	if err != nil {
		return nil, fmt.Errorf("ID token signature verification failed: %w", err)
	}
	verifiedClaims, ok := verified.Claims.(*jwt.RegisteredClaims)
	if !ok {
		return nil, fmt.Errorf("unexpected verified claims type in ID token")
	}
	return verifiedClaims, nil
}

// validateIDTokenAudience checks the audience claim of an ID token.
// Reflag's OIDC client is a public web client and expects a single audience
// equal to its client_id; multiple audiences are rejected as a defense-in-depth
// measure against token confusion attacks.
func (a *AuthService) validateIDTokenAudience(claims *jwt.RegisteredClaims) error {
	if len(claims.Audience) != 1 || claims.Audience[0] != a.oidcClientID {
		return fmt.Errorf("ID token audience invalid: expected %q, got %v", a.oidcClientID, claims.Audience)
	}
	return nil
}

func (a *AuthService) signState(nonce string) string {
	h := hmac.New(sha256.New, []byte(a.jwtSecret))
	h.Write([]byte("oidc-state:"))
	h.Write([]byte(nonce))
	return hex.EncodeToString(h.Sum(nil))
}
