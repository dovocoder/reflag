package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/dovocoder/reflag/internal/auth"
	"github.com/dovocoder/reflag/internal/crypto"
	"github.com/dovocoder/reflag/internal/middleware"
	"github.com/dovocoder/reflag/internal/models"
	"github.com/dovocoder/reflag/internal/openfeature"
	"github.com/dovocoder/reflag/internal/store"
	"github.com/google/uuid"
)

const (
	testJWTSecret  = "super-secret-32-byte-jwt-key-demo"
	testSecretsKey = "super-secret-32-byte-secrets-key-de"
	testAdminPass  = "adminpass123"
	testAdminEmail = "admin@example.com"
)

type testEnv struct {
	handler *Handler
	store   *store.Store
	auth    *auth.AuthService
	server  *httptest.Server
	envID   string
	keyRaw  string
}

func setupTestHandler(t *testing.T) *testEnv {
	t.Helper()
	f, err := os.CreateTemp("", "reflag-test-*.db")
	if err != nil {
		t.Fatalf("create temp db: %v", err)
	}
	_ = f.Close()
	t.Cleanup(func() { _ = os.Remove(f.Name()) })

	st, err := store.New(f.Name())
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	authSvc := auth.New(st, testJWTSecret, "", "", "", "")
	if err := authSvc.SetAdminCredentials(testAdminEmail, testAdminPass); err != nil {
		t.Fatalf("set admin credentials: %v", err)
	}
	h := NewHandler(st, authSvc, testSecretsKey)
	limiter := middleware.NewRateLimiter(1000, time.Minute)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux, limiter)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	t.Cleanup(func() { _ = st.Close() })

	env := &models.Environment{ID: uuid.New().String(), Key: "production", Name: "Production"}
	if err := st.CreateEnvironment(env); err != nil {
		t.Fatalf("create environment: %v", err)
	}

	encVal, err := crypto.Encrypt("postgres://secret", crypto.DeriveKey(testSecretsKey))
	if err != nil {
		t.Fatalf("encrypt secret: %v", err)
	}
	secret := &models.Secret{
		ID:             uuid.New().String(),
		Key:            "DB_URL",
		Name:           "Database URL",
		EncryptedValue: encVal,
		EnvironmentID:  env.ID,
		Version:        1,
	}
	if err := st.CreateSecret(secret); err != nil {
		t.Fatalf("create secret: %v", err)
	}

	flag := &models.Flag{
		ID:      uuid.New().String(),
		Key:     "payment-key",
		Name:    "Payment Key",
		Type:    models.FlagTypeString,
		Enabled: true,
		Version: 1,
		Variations: []models.Variation{
			{ID: "var-true", Label: "Production", Value: json.RawMessage(`{"$secret":"DB_URL"}`)},
		},
		DefaultRule: &models.DefaultRule{VariationID: "var-true"},
	}
	if err := st.CreateFlag(flag); err != nil {
		t.Fatalf("create flag: %v", err)
	}

	rawKey, hash, prefix, err := auth.GenerateAPIKey()
	if err != nil {
		t.Fatalf("generate api key: %v", err)
	}
	apiKey := &models.APIKey{
		ID:            uuid.New().String(),
		Name:          "production-eval",
		KeyHash:       hash,
		KeyPrefix:     prefix,
		EnvironmentID: env.ID,
		Scopes:        []string{"evaluate"},
	}
	if err := st.CreateAPIKey(apiKey); err != nil {
		t.Fatalf("create api key: %v", err)
	}

	return &testEnv{handler: h, store: st, auth: authSvc, server: srv, envID: env.ID, keyRaw: rawKey}
}

func (te *testEnv) evaluate(t *testing.T, header, value string, body map[string]any) openfeature.ResolutionDetail {
	t.Helper()
	payload, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", te.server.URL+"/api/v1/flags/evaluate", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	if header != "" {
		req.Header.Set(header, value)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status %d", resp.StatusCode)
	}
	var detail openfeature.ResolutionDetail
	if err := json.NewDecoder(resp.Body).Decode(&detail); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return detail
}

func TestResolveSecretRefsAuthorization(t *testing.T) {
	te := setupTestHandler(t)

	t.Run("environment-scoped API key resolves secret", func(t *testing.T) {
		detail := te.evaluate(t, "X-API-Key", te.keyRaw, map[string]any{
			"flagKey":     "payment-key",
			"environment": "production",
		})
		if detail.Reason == openfeature.ReasonError {
			t.Fatalf("expected resolution, got error: %s - %s", detail.ErrorCode, detail.ErrorMessage)
		}
		if detail.Value != "postgres://secret" {
			t.Fatalf("unexpected resolved value: %v", detail.Value)
		}
	})

	t.Run("admin JWT resolves secret", func(t *testing.T) {
		adminUser := &models.User{ID: "admin", Email: testAdminEmail, Name: "Admin", Role: "admin"}
		token, err := te.auth.GenerateJWT(adminUser)
		if err != nil {
			t.Fatalf("generate admin jwt: %v", err)
		}
		detail := te.evaluate(t, "Authorization", "Bearer "+token, map[string]any{
			"flagKey":     "payment-key",
			"environment": "production",
		})
		if detail.Reason == openfeature.ReasonError {
			t.Fatalf("expected resolution, got error: %s - %s", detail.ErrorCode, detail.ErrorMessage)
		}
		if detail.Value != "postgres://secret" {
			t.Fatalf("unexpected resolved value: %v", detail.Value)
		}
	})

	t.Run("member JWT is blocked from resolving secrets", func(t *testing.T) {
		memberUser := &models.User{ID: "member-1", Email: "member@example.com", Name: "Member", Role: "member"}
		token, err := te.auth.GenerateJWT(memberUser)
		if err != nil {
			t.Fatalf("generate member jwt: %v", err)
		}
		detail := te.evaluate(t, "Authorization", "Bearer "+token, map[string]any{
			"flagKey": "payment-key",
		})
		if detail.Reason != openfeature.ReasonError {
			t.Fatalf("expected error reason, got %s", detail.Reason)
		}
		if detail.ErrorCode != openfeature.ErrSecretResolution {
			t.Fatalf("expected %s, got %s", openfeature.ErrSecretResolution, detail.ErrorCode)
		}
	})

	t.Run("unscoped API key cannot resolve secrets", func(t *testing.T) {
		rawKey, hash, prefix, err := auth.GenerateAPIKey()
		if err != nil {
			t.Fatalf("generate api key: %v", err)
		}
		apiKey := &models.APIKey{
			ID:        uuid.New().String(),
			Name:      "unscoped-eval",
			KeyHash:   hash,
			KeyPrefix: prefix,
			Scopes:    []string{"evaluate"},
		}
		if err := te.store.CreateAPIKey(apiKey); err != nil {
			t.Fatalf("create api key: %v", err)
		}
		detail := te.evaluate(t, "X-API-Key", rawKey, map[string]any{
			"flagKey": "payment-key",
		})
		if detail.Reason != openfeature.ReasonError {
			t.Fatalf("expected error reason, got %s", detail.Reason)
		}
	})
}

func TestOrganizationRBAC(t *testing.T) {
	t.Helper()
	te := setupTestHandler(t)

	// Create an OIDC-like member user and an org where they are a viewer.
	viewer, err := te.store.GetOrCreateUser("viewer@example.com", "Viewer")
	if err != nil {
		t.Fatalf("create viewer: %v", err)
	}
	org := &models.Organization{ID: uuid.New().String(), Name: "Acme", Slug: "acme"}
	if err := te.store.CreateOrg(org); err != nil {
		t.Fatalf("create org: %v", err)
	}
	if err := te.store.AddOrgMember(&models.OrgMember{ID: uuid.New().String(), UserID: viewer.ID, OrgID: org.ID, Role: "viewer"}); err != nil {
		t.Fatalf("add viewer: %v", err)
	}

	viewerToken, err := te.auth.GenerateJWT(viewer)
	if err != nil {
		t.Fatalf("generate viewer jwt: %v", err)
	}

	// Viewer should be able to list their orgs.
	req, _ := http.NewRequest("GET", te.server.URL+"/api/organizations", nil)
	req.Header.Set("Authorization", "Bearer "+viewerToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("list orgs: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 listing orgs, got %d", resp.StatusCode)
	}
	var orgs []models.Organization
	if err := json.NewDecoder(resp.Body).Decode(&orgs); err != nil {
		t.Fatalf("decode orgs: %v", err)
	}
	if len(orgs) != 1 || orgs[0].ID != org.ID {
		t.Fatalf("expected viewer to see exactly their org, got %+v", orgs)
	}

	// Viewer should NOT be able to delete the org.
	delReq, _ := http.NewRequest("DELETE", te.server.URL+"/api/organizations/"+org.ID, nil)
	delReq.Header.Set("Authorization", "Bearer "+viewerToken)
	delResp, err := http.DefaultClient.Do(delReq)
	if err != nil {
		t.Fatalf("delete org: %v", err)
	}
	defer delResp.Body.Close()
	if delResp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 deleting org as viewer, got %d", delResp.StatusCode)
	}
}
