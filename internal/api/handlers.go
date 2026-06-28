package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/dovocoder/reflag/internal/auth"
	"github.com/dovocoder/reflag/internal/crypto"
	"github.com/dovocoder/reflag/internal/middleware"
	"github.com/dovocoder/reflag/internal/models"
	"github.com/dovocoder/reflag/internal/openfeature"
	"github.com/dovocoder/reflag/internal/store"
	"github.com/google/uuid"
)

type Handler struct {
	store     *store.Store
	auth      *auth.AuthService
	secretsKey []byte
}

func NewHandler(s *store.Store, a *auth.AuthService, secretsKey string) *Handler {
	return &Handler{
		store:      s,
		auth:       a,
		secretsKey: crypto.DeriveKey(secretsKey),
	}
}

// RegisterRoutes sets up all API routes on the given mux.
func (h *Handler) RegisterRoutes(mux *http.ServeMux, loginLimiter *middleware.RateLimiter) {
	// Public routes (no auth)
	mux.HandleFunc("GET /health", h.health)
	// Login and OIDC callback have stricter rate limiting
	mux.Handle("POST /api/auth/login", middleware.RateLimitMiddleware(loginLimiter, http.HandlerFunc(h.adminLogin)))
	mux.HandleFunc("POST /api/auth/oidc/start", h.oidcStart)
	mux.Handle("POST /api/auth/oidc/callback", middleware.RateLimitMiddleware(loginLimiter, http.HandlerFunc(h.oidcCallback)))
	mux.HandleFunc("POST /api/auth/logout", h.logout)

	// Evaluation routes (API key or JWT) — OpenFeature HTTP API
	// R7-M6: Enforce scope-based authorization on eval/resolve routes
	evalMux := http.NewServeMux()
	evalMux.Handle("POST /api/v1/flags/evaluate", h.auth.RequireScope("evaluate")(http.HandlerFunc(h.evaluateFlag)))
	evalMux.Handle("POST /api/v1/flags/{key}/evaluate", h.auth.RequireScope("evaluate")(http.HandlerFunc(h.evaluateFlagByKey)))
	// Type-specific evaluation endpoints
	evalMux.Handle("POST /api/v1/flags/boolean", h.auth.RequireScope("evaluate")(http.HandlerFunc(h.evaluateBoolean)))
	evalMux.Handle("POST /api/v1/flags/string", h.auth.RequireScope("evaluate")(http.HandlerFunc(h.evaluateString)))
	evalMux.Handle("POST /api/v1/flags/number", h.auth.RequireScope("evaluate")(http.HandlerFunc(h.evaluateNumber)))
	evalMux.Handle("POST /api/v1/flags/object", h.auth.RequireScope("evaluate")(http.HandlerFunc(h.evaluateObject)))
	evalMux.Handle("POST /api/v1/flags/{key}/boolean", h.auth.RequireScope("evaluate")(http.HandlerFunc(h.evaluateBoolean)))
	evalMux.Handle("POST /api/v1/flags/{key}/string", h.auth.RequireScope("evaluate")(http.HandlerFunc(h.evaluateString)))
	evalMux.Handle("POST /api/v1/flags/{key}/number", h.auth.RequireScope("evaluate")(http.HandlerFunc(h.evaluateNumber)))
	evalMux.Handle("POST /api/v1/flags/{key}/object", h.auth.RequireScope("evaluate")(http.HandlerFunc(h.evaluateObject)))
	evalMux.Handle("GET /api/v1/flags", h.auth.RequireScope("read")(http.HandlerFunc(h.listFlagsForClient)))
	mux.Handle("/api/v1/flags", h.auth.AnyAuthMiddleware(evalMux))
	mux.Handle("/api/v1/flags/", h.auth.AnyAuthMiddleware(evalMux))

	// Secrets resolve routes (API key only — encrypted response)
	resolveMux := http.NewServeMux()
	resolveMux.Handle("POST /api/v1/secrets/{key}/resolve", h.auth.RequireScope("resolve")(http.HandlerFunc(h.resolveSecret)))
	resolveMux.Handle("POST /api/v1/secrets/resolve", h.auth.RequireScope("resolve")(http.HandlerFunc(h.resolveAllSecrets)))
	mux.Handle("/api/v1/secrets/", h.auth.APIKeyMiddleware(resolveMux))

	// Admin routes (JWT only) — require admin or owner role for all management operations
	// OIDC-provisioned users get "member" role and can only access /api/v1/ evaluation + resolve endpoints
	adminMux := http.NewServeMux()
	adminMux.HandleFunc("GET /api/flags", h.listFlags)
	adminMux.HandleFunc("POST /api/flags", h.createFlag)
	adminMux.HandleFunc("GET /api/flags/{id}", h.getFlag)
	adminMux.HandleFunc("PUT /api/flags/{id}", h.updateFlag)
	adminMux.HandleFunc("DELETE /api/flags/{id}", h.deleteFlag)

	adminMux.HandleFunc("GET /api/environments", h.listEnvironments)
	adminMux.HandleFunc("POST /api/environments", h.createEnvironment)
	adminMux.HandleFunc("DELETE /api/environments/{id}", h.deleteEnvironment)

	adminMux.HandleFunc("GET /api/segments", h.listSegments)
	adminMux.HandleFunc("POST /api/segments", h.createSegment)
	adminMux.HandleFunc("DELETE /api/segments/{id}", h.deleteSegment)

	adminMux.HandleFunc("GET /api/api-keys", h.listAPIKeys)
	adminMux.HandleFunc("POST /api/api-keys", h.createAPIKey)
	adminMux.HandleFunc("DELETE /api/api-keys/{id}", h.revokeAPIKey)

	adminMux.HandleFunc("GET /api/audit", h.listAuditEntries)

	// Organizations
	adminMux.HandleFunc("GET /api/organizations", h.listOrgs)
	adminMux.HandleFunc("POST /api/organizations", h.createOrg)
	adminMux.HandleFunc("DELETE /api/organizations/{id}", h.deleteOrg)
	adminMux.HandleFunc("GET /api/organizations/{id}/members", h.listOrgMembers)
	adminMux.HandleFunc("POST /api/organizations/{id}/members", h.addOrgMember)
	adminMux.HandleFunc("PUT /api/organizations/members/{memberId}", h.updateOrgMemberRole)
	adminMux.HandleFunc("DELETE /api/organizations/members/{memberId}", h.removeOrgMember)

	// Secrets
	adminMux.HandleFunc("GET /api/secrets", h.listSecrets)
	adminMux.HandleFunc("POST /api/secrets", h.createSecret)
	adminMux.HandleFunc("GET /api/secrets/{id}", h.getSecret)
	adminMux.HandleFunc("PUT /api/secrets/{id}", h.updateSecret)
	adminMux.HandleFunc("DELETE /api/secrets/{id}", h.deleteSecret)

	// All admin routes require JWT + admin/owner role
	mux.Handle("/api/", h.auth.JWTMiddleware(h.auth.RequireRole("admin", "owner")(adminMux)))
}

// --- Health ---

func (h *Handler) health(w http.ResponseWriter, r *http.Request) {
	middleware.JSONResponse(w, http.StatusOK, map[string]string{"status": "ok"})
}

// --- OIDC Auth ---

func (h *Handler) oidcStart(w http.ResponseWriter, r *http.Request) {
	state, err := h.auth.GenerateState()
	if err != nil {
		middleware.JSONError(w, http.StatusInternalServerError, "failed to generate state")
		return
	}
	authURL, verifier, err := h.auth.GetAuthorizationURL(state)
	if err != nil {
		middleware.JSONError(w, http.StatusBadRequest, "failed to start OIDC flow")
		return
	}
	// Set SameSite=Lax cookie for state validation
	isTLS := r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
	http.SetCookie(w, &http.Cookie{
		Name:     "reflag_oidc_state",
		Value:     state,
		Path:     "/",
		MaxAge:   600, // 10 minutes
		HttpOnly:  true,
		SameSite:  http.SameSiteLaxMode,
		Secure:    isTLS,
	})
	// Set SameSite=Lax cookie for PKCE verifier
	http.SetCookie(w, &http.Cookie{
		Name:     "reflag_pkce_verifier",
		Value:     verifier,
		Path:     "/",
		MaxAge:   600,
		HttpOnly:  true,
		SameSite:  http.SameSiteLaxMode,
		Secure:    isTLS,
	})
	middleware.JSONResponse(w, http.StatusOK, map[string]string{
		"authorization_url": authURL,
		"state":            state,
	})
}

func (h *Handler) oidcCallback(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Code  string `json:"code"`
		State string `json:"state"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		middleware.JSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	// Validate state to prevent CSRF/OAuth code injection
	if req.State == "" {
		middleware.JSONError(w, http.StatusBadRequest, "state is required")
		return
	}
	// R9-M4: Validate authorization code is present
	if req.Code == "" {
		middleware.JSONError(w, http.StatusBadRequest, "code is required")
		return
	}
	cookieState, err := r.Cookie("reflag_oidc_state")
	if err != nil || cookieState.Value == "" {
		middleware.JSONError(w, http.StatusBadRequest, "missing state cookie")
		return
	}
	if !h.auth.ValidateState(req.State) || req.State != cookieState.Value {
		h.audit("unknown", "LOGIN_FAILED", "user", "", "invalid OIDC state")
		middleware.JSONError(w, http.StatusForbidden, "invalid state")
		return
	}
	// Clear the state and PKCE cookies
	http.SetCookie(w, &http.Cookie{
		Name:   "reflag_oidc_state",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})
	http.SetCookie(w, &http.Cookie{
		Name:   "reflag_pkce_verifier",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})
	// Retrieve PKCE verifier from cookie
	var codeVerifier string
	if pkceCookie, err := r.Cookie("reflag_pkce_verifier"); err == nil {
		codeVerifier = pkceCookie.Value
	}
	user, token, err := h.auth.ExchangeCode(req.Code, codeVerifier)
	if err != nil {
		h.audit("unknown", "LOGIN_FAILED", "user", "", "OIDC exchange failed")
		// Don't leak internal error details to the client
		middleware.JSONError(w, http.StatusUnauthorized, "OIDC authentication failed")
		return
	}
	h.audit(user.Email, "LOGIN", "user", user.ID, "OIDC login")
	// Set JWT as HttpOnly cookie for browser-based XSS protection
	isTLS := r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
	http.SetCookie(w, &http.Cookie{
		Name:     "reflag_token",
		Value:     token,
		Path:     "/",
		MaxAge:   86400, // 24 hours
		HttpOnly:  true,
		SameSite:  http.SameSiteLaxMode,
		Secure:    isTLS,
	})
	middleware.JSONResponse(w, http.StatusOK, map[string]any{
		"token": token,
		"user":  user,
	})
}

// --- Flag Evaluation (OpenFeature HTTP API compliant) ---

func (h *Handler) evaluateFlag(w http.ResponseWriter, r *http.Request) {
	var req openfeature.EvaluationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		middleware.JSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.FlagKey == "" {
		middleware.JSONError(w, http.StatusBadRequest, "flagKey is required")
		return
	}
	detail := h.evaluateFlagInternal(w, r, req)
	middleware.JSONResponse(w, http.StatusOK, detail)
}

func (h *Handler) evaluateFlagByKey(w http.ResponseWriter, r *http.Request) {
	flagKey := r.PathValue("key")
	var req struct {
		DefaultValue any                    `json:"defaultValue"`
		Environment  string                 `json:"environment,omitempty"`
		Context      openfeature.EvaluationContext `json:"context,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		middleware.JSONResponse(w, http.StatusOK, openfeature.ResolutionDetail{
			Value:        nil,
			Reason:       openfeature.ReasonError,
			ErrorCode:    openfeature.ErrParseError,
			ErrorMessage: "invalid request body",
		})
		return
	}
	detail := h.evaluateFlagInternal(w, r, openfeature.EvaluationRequest{
		FlagKey:      flagKey,
		DefaultValue: req.DefaultValue,
		Environment:  req.Environment,
		Context:      req.Context,
	})
	middleware.JSONResponse(w, http.StatusOK, detail)
}

// evaluateFlagType evaluates a flag with type validation.
// Used by /boolean, /string, /number, /object endpoints.
func (h *Handler) evaluateFlagType(w http.ResponseWriter, r *http.Request, expectedType models.FlagType) {
	var req openfeature.EvaluationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		middleware.JSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.FlagKey == "" {
		// Try path value
		req.FlagKey = r.PathValue("key")
	}

	flag, err := h.store.GetFlagByKey(req.FlagKey)
	if err != nil {
		middleware.JSONResponse(w, http.StatusOK, openfeature.ResolutionDetail{
			Value:        req.DefaultValue,
			Reason:       openfeature.ReasonError,
			ErrorCode:    openfeature.ErrProviderFatal,
			ErrorMessage: "database error",
		})
		return
	}
	if flag == nil {
		middleware.JSONResponse(w, http.StatusOK, openfeature.ResolutionDetail{
			Value:        req.DefaultValue,
			Reason:       openfeature.ReasonError,
			ErrorCode:    openfeature.ErrFlagNotFound,
			ErrorMessage: "flag not found",
		})
		return
	}

	// R5-4: Reject if flag type doesn't match the endpoint type
	// R7-M5: Also reject if flag type is empty (unconfigured flag)
	if flag.Type == "" {
		middleware.JSONResponse(w, http.StatusOK, openfeature.ResolutionDetail{
			Value:        req.DefaultValue,
			Reason:       openfeature.ReasonError,
			ErrorCode:    openfeature.ErrParseError,
			ErrorMessage: "flag has no type configured",
		})
		return
	}
	if flag.Type != expectedType {
		middleware.JSONResponse(w, http.StatusOK, openfeature.ResolutionDetail{
			Value:        req.DefaultValue,
			Reason:       openfeature.ReasonError,
			ErrorCode:    openfeature.ErrTypeMismatch,
			ErrorMessage: "flag type does not match requested type",
		})
		return
	}

	// Check for environment-specific config
	if req.Environment != "" {
		env, _ := h.store.GetEnvironmentByKey(req.Environment)
		if env != nil {
			// R5-7: Enforce API key environment scoping
			if ak := auth.APIKeyFromContext(r.Context()); ak != nil && ak.EnvironmentID != "" {
				if ak.EnvironmentID != env.ID {
					middleware.JSONResponse(w, http.StatusOK, openfeature.ResolutionDetail{
						Value:        req.DefaultValue,
						Reason:       openfeature.ReasonError,
						ErrorCode:    openfeature.ErrFlagNotFound,
						ErrorMessage: "flag not found",
					})
					return
				}
			}
			if envFlag, _ := h.store.GetFlagConfig(flag.ID, env.ID); envFlag != nil {
				flag = envFlag
			}
		}
	}

	detail := openfeature.EvaluateWithType(flag, req.Environment, req.Context, expectedType)
	detail = h.resolveSecretRefs(r, flag, detail)
	// Re-validate type after secret resolution (secret value may have different type)
	if detail.Reason != openfeature.ReasonError && detail.Value != nil {
		if !openfeature.ValidateType(detail.Value, expectedType) {
			detail.Value = req.DefaultValue
			detail.Reason = openfeature.ReasonError
			detail.ErrorCode = openfeature.ErrTypeMismatch
			detail.ErrorMessage = "type mismatch after secret resolution"
		}
	}

	// On error, return the defaultValue from the request
	if detail.Reason == openfeature.ReasonError {
		detail.Value = req.DefaultValue
	}

	middleware.JSONResponse(w, http.StatusOK, detail)
}

func (h *Handler) evaluateBoolean(w http.ResponseWriter, r *http.Request) {
	h.evaluateFlagType(w, r, models.FlagTypeBoolean)
}

func (h *Handler) evaluateString(w http.ResponseWriter, r *http.Request) {
	h.evaluateFlagType(w, r, models.FlagTypeString)
}

func (h *Handler) evaluateNumber(w http.ResponseWriter, r *http.Request) {
	h.evaluateFlagType(w, r, models.FlagTypeNumber)
}

func (h *Handler) evaluateObject(w http.ResponseWriter, r *http.Request) {
	h.evaluateFlagType(w, r, models.FlagTypeObject)
}

// evaluateFlagInternal handles the core evaluation logic shared by all endpoints.
func (h *Handler) evaluateFlagInternal(w http.ResponseWriter, r *http.Request, req openfeature.EvaluationRequest) openfeature.ResolutionDetail {
	flag, err := h.store.GetFlagByKey(req.FlagKey)
	if err != nil {
		return openfeature.ResolutionDetail{
			Value:        req.DefaultValue,
			Reason:       openfeature.ReasonError,
			ErrorCode:    openfeature.ErrProviderFatal,
			ErrorMessage: "database error",
		}
	}
	if flag == nil {
		return openfeature.ResolutionDetail{
			Value:        req.DefaultValue,
			Reason:       openfeature.ReasonError,
			ErrorCode:    openfeature.ErrFlagNotFound,
			ErrorMessage: "flag not found",
		}
	}

	// Check for environment-specific config
	if req.Environment != "" {
		env, _ := h.store.GetEnvironmentByKey(req.Environment)
		if env != nil {
			// R5-7: Enforce API key environment scoping
			if ak := auth.APIKeyFromContext(r.Context()); ak != nil && ak.EnvironmentID != "" {
				if ak.EnvironmentID != env.ID {
					return openfeature.ResolutionDetail{
						Value:        req.DefaultValue,
						Reason:       openfeature.ReasonError,
						ErrorCode:    openfeature.ErrFlagNotFound,
						ErrorMessage: "flag not found",
					}
				}
			}
			if envFlag, _ := h.store.GetFlagConfig(flag.ID, env.ID); envFlag != nil {
				flag = envFlag
			}
		}
	}

	detail := openfeature.Evaluate(flag, req.Environment, req.Context)
	detail = h.resolveSecretRefs(r, flag, detail)

	// On error, return the defaultValue from the request
	if detail.Reason == openfeature.ReasonError {
		detail.Value = req.DefaultValue
	}

	return detail
}

func (h *Handler) listFlagsForClient(w http.ResponseWriter, r *http.Request) {
	flags, err := h.store.ListFlags()
	if err != nil {
		middleware.JSONError(w, http.StatusInternalServerError, "database error")
		return
	}
	// Return minimal data for client SDKs — strip secret reference values
	// to prevent leaking secret key names to API consumers
	type clientFlag struct {
		Key     string `json:"key"`
		Enabled bool   `json:"enabled"`
		Type    string `json:"type"`
	}
	// R5-12: Filter by API key environment and hide secret-type flags from API callers
	ak := auth.APIKeyFromContext(r.Context())
	result := make([]clientFlag, 0, len(flags))
	for _, f := range flags {
		// Hide secret-type flags from API key callers
		if ak != nil && f.Type == "secret" {
			continue
		}
		// R7-M1: Hide disabled flags from API key callers — they always return
		// the default variation and shouldn't clutter the client's flag list
		if ak != nil && !f.Enabled {
			continue
		}
		result = append(result, clientFlag{
			Key: f.Key, Enabled: f.Enabled, Type: string(f.Type),
		})
	}
	middleware.JSONResponse(w, http.StatusOK, result)
}

// --- Flags CRUD ---

func (h *Handler) listFlags(w http.ResponseWriter, r *http.Request) {
	flags, err := h.store.ListFlags()
	if err != nil {
		middleware.JSONError(w, http.StatusInternalServerError, "database error")
		return
	}
	if flags == nil {
		flags = []models.Flag{}
	}
	middleware.JSONResponse(w, http.StatusOK, flags)
}

func (h *Handler) createFlag(w http.ResponseWriter, r *http.Request) {
	var flag models.Flag
	if err := json.NewDecoder(r.Body).Decode(&flag); err != nil {
		middleware.JSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if flag.Key == "" {
		middleware.JSONError(w, http.StatusBadRequest, "key is required")
		return
	}
	if !isValidFlagKey(flag.Key) {
		middleware.JSONError(w, http.StatusBadRequest, "key must be alphanumeric with dashes/underscores, max 128 chars")
		return
	}
	// R8-H1/H2/H3/M5: Validate flag configuration consistency
	if msg := validateFlagConfig(&flag); msg != "" {
		middleware.JSONError(w, http.StatusBadRequest, msg)
		return
	}
	if len(flag.Name) > 256 {
		middleware.JSONError(w, http.StatusBadRequest, "name too long (max 256 chars)")
		return
	}
	flag.ID = uuid.New().String()
	if flag.Version == 0 {
		flag.Version = 1
	}
	if err := h.store.CreateFlag(&flag); err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			middleware.JSONError(w, http.StatusConflict, "flag key already exists")
			return
		}
		middleware.JSONError(w, http.StatusInternalServerError, "failed to create flag")
		return
	}
	h.audit(auth.ActorFromContext(r.Context()), "CREATE", "flag", flag.ID, flag.Key)
	middleware.JSONResponse(w, http.StatusCreated, flag)
}

func (h *Handler) getFlag(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	flag, err := h.store.GetFlag(id)
	if err != nil || flag == nil {
		middleware.JSONError(w, http.StatusNotFound, "flag not found")
		return
	}
	middleware.JSONResponse(w, http.StatusOK, flag)
}

func (h *Handler) updateFlag(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	existing, err := h.store.GetFlag(id)
	if err != nil || existing == nil {
		middleware.JSONError(w, http.StatusNotFound, "flag not found")
		return
	}
	var flag models.Flag
	if err := json.NewDecoder(r.Body).Decode(&flag); err != nil {
		middleware.JSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	// PATCH semantics: only update fields that are explicitly provided
	if flag.Key != "" {
		if !isValidFlagKey(flag.Key) {
			middleware.JSONError(w, http.StatusBadRequest, "key must be alphanumeric with dashes/underscores, max 128 chars")
			return
		}
		existing.Key = flag.Key
	}
	if flag.Name != "" {
		if len(flag.Name) > 256 {
			middleware.JSONError(w, http.StatusBadRequest, "name too long (max 256 chars)")
			return
		}
		existing.Name = flag.Name
	}
	if flag.Description != "" {
		existing.Description = flag.Description
	}
	if flag.Type != "" {
		// R7-M4: Prevent flag type changes after creation — changing type
		// would break existing evaluation clients and invalidate cached results
		if existing.Type != "" && flag.Type != existing.Type {
			middleware.JSONError(w, http.StatusBadRequest, "flag type cannot be changed after creation")
			return
		}
		existing.Type = flag.Type
	}
	if flag.Variations != nil {
		existing.Variations = flag.Variations
	}
	if flag.Targeting != nil {
		existing.Targeting = flag.Targeting
	}
	if flag.DefaultRule != nil {
		existing.DefaultRule = flag.DefaultRule
	}
	// Enabled is a bool — can't distinguish "false" from "not set"
	// So we accept the client's value (PUT semantics for booleans)
	existing.Enabled = flag.Enabled
	existing.ID = id
	// Auto-increment version (never allow user-controlled version regression)
	existing.Version = existing.Version + 1
	// R8-H1/H2/H3/M5: Validate flag configuration consistency after merge
	if msg := validateFlagConfig(existing); msg != "" {
		middleware.JSONError(w, http.StatusBadRequest, msg)
		return
	}
	if err := h.store.UpdateFlag(existing); err != nil {
		if strings.Contains(err.Error(), "concurrent modification") {
			middleware.JSONError(w, http.StatusConflict, "flag was modified by another request — please retry")
			return
		}
		middleware.JSONError(w, http.StatusInternalServerError, "failed to update flag")
		return
	}
	h.audit(auth.ActorFromContext(r.Context()), "UPDATE", "flag", id, existing.Key)
	middleware.JSONResponse(w, http.StatusOK, existing)
}

func (h *Handler) deleteFlag(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	// R7-L1: Check existence before delete to return proper 404
	existing, err := h.store.GetFlag(id)
	if err != nil || existing == nil {
		middleware.JSONError(w, http.StatusNotFound, "flag not found")
		return
	}
	if err := h.store.DeleteFlag(id); err != nil {
		middleware.JSONError(w, http.StatusInternalServerError, "failed to delete flag")
		return
	}
	h.audit(auth.ActorFromContext(r.Context()), "DELETE", "flag", id, "")
	w.WriteHeader(http.StatusNoContent)
}

// --- Environments ---

func (h *Handler) listEnvironments(w http.ResponseWriter, r *http.Request) {
	envs, err := h.store.ListEnvironments()
	if err != nil {
		middleware.JSONError(w, http.StatusInternalServerError, "database error")
		return
	}
	if envs == nil {
		envs = []models.Environment{}
	}
	middleware.JSONResponse(w, http.StatusOK, envs)
}

func (h *Handler) createEnvironment(w http.ResponseWriter, r *http.Request) {
	var env models.Environment
	if err := json.NewDecoder(r.Body).Decode(&env); err != nil {
		middleware.JSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if env.Key == "" {
		middleware.JSONError(w, http.StatusBadRequest, "key is required")
		return
	}
	if !isValidKey(env.Key) {
		middleware.JSONError(w, http.StatusBadRequest, "key must be alphanumeric with dashes/underscores, max 128 chars")
		return
	}
	if len(env.Name) > 256 {
		middleware.JSONError(w, http.StatusBadRequest, "name too long (max 256 chars)")
		return
	}
	env.ID = uuid.New().String()
	if err := h.store.CreateEnvironment(&env); err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			middleware.JSONError(w, http.StatusConflict, "environment key already exists")
			return
		}
		middleware.JSONError(w, http.StatusInternalServerError, "failed to create environment")
		return
	}
	h.audit(auth.ActorFromContext(r.Context()), "CREATE", "environment", env.ID, env.Key)
	middleware.JSONResponse(w, http.StatusCreated, env)
}

func (h *Handler) deleteEnvironment(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	// R7-L1: Check existence before delete
	existing, err := h.store.GetEnvironment(id)
	if err != nil || existing == nil {
		middleware.JSONError(w, http.StatusNotFound, "environment not found")
		return
	}
	if err := h.store.DeleteEnvironment(id); err != nil {
		middleware.JSONError(w, http.StatusInternalServerError, "failed to delete environment")
		return
	}
	h.audit(auth.ActorFromContext(r.Context()), "DELETE", "environment", id, "")
	w.WriteHeader(http.StatusNoContent)
}

// --- Segments ---

func (h *Handler) listSegments(w http.ResponseWriter, r *http.Request) {
	segs, err := h.store.ListSegments()
	if err != nil {
		middleware.JSONError(w, http.StatusInternalServerError, "database error")
		return
	}
	if segs == nil {
		segs = []models.Segment{}
	}
	middleware.JSONResponse(w, http.StatusOK, segs)
}

func (h *Handler) createSegment(w http.ResponseWriter, r *http.Request) {
	var seg models.Segment
	if err := json.NewDecoder(r.Body).Decode(&seg); err != nil {
		middleware.JSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if seg.Key == "" {
		middleware.JSONError(w, http.StatusBadRequest, "key is required")
		return
	}
	if !isValidKey(seg.Key) {
		middleware.JSONError(w, http.StatusBadRequest, "key must be alphanumeric with dashes/underscores, max 128 chars")
		return
	}
	if len(seg.Name) > 256 {
		middleware.JSONError(w, http.StatusBadRequest, "name too long (max 256 chars)")
		return
	}
	seg.ID = uuid.New().String()
	if err := h.store.CreateSegment(&seg); err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			middleware.JSONError(w, http.StatusConflict, "segment key already exists")
			return
		}
		middleware.JSONError(w, http.StatusInternalServerError, "failed to create segment")
		return
	}
	h.audit(auth.ActorFromContext(r.Context()), "CREATE", "segment", seg.ID, seg.Key)
	middleware.JSONResponse(w, http.StatusCreated, seg)
}

func (h *Handler) deleteSegment(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	// R7-L1: Check existence before delete
	existing, err := h.store.GetSegment(id)
	if err != nil || existing == nil {
		middleware.JSONError(w, http.StatusNotFound, "segment not found")
		return
	}
	if err := h.store.DeleteSegment(id); err != nil {
		middleware.JSONError(w, http.StatusInternalServerError, "failed to delete segment")
		return
	}
	h.audit(auth.ActorFromContext(r.Context()), "DELETE", "segment", id, "")
	w.WriteHeader(http.StatusNoContent)
}

// --- API Keys ---

func (h *Handler) listAPIKeys(w http.ResponseWriter, r *http.Request) {
	keys, err := h.store.ListAPIKeys()
	if err != nil {
		middleware.JSONError(w, http.StatusInternalServerError, "database error")
		return
	}
	if keys == nil {
		keys = []models.APIKey{}
	}
	middleware.JSONResponse(w, http.StatusOK, keys)
}

func (h *Handler) createAPIKey(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name          string   `json:"name"`
		EnvironmentID string   `json:"environment_id"`
		Scopes        []string `json:"scopes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		middleware.JSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Name == "" {
		middleware.JSONError(w, http.StatusBadRequest, "name is required")
		return
	}
	if len(req.Name) > 128 {
		middleware.JSONError(w, http.StatusBadRequest, "name too long (max 128 chars)")
		return
	}
	// Validate scopes — only allow known scope values
	validScopes := map[string]bool{"evaluate": true, "resolve": true, "read": true, "write": true}
	for _, sc := range req.Scopes {
		if !validScopes[sc] {
			middleware.JSONError(w, http.StatusBadRequest, fmt.Sprintf("invalid scope %q — allowed: evaluate, resolve, read, write", sc))
			return
		}
	}
	// Validate environment_id exists if provided
	if req.EnvironmentID != "" {
		env, _ := h.store.GetEnvironment(req.EnvironmentID)
		if env == nil {
			// Try by key
			env, _ = h.store.GetEnvironmentByKey(req.EnvironmentID)
			if env == nil {
				middleware.JSONError(w, http.StatusBadRequest, "environment_id does not reference an existing environment")
				return
			}
			req.EnvironmentID = env.ID
		}
	}
	rawKey, hash, prefix, err := auth.GenerateAPIKey()
	if err != nil {
		middleware.JSONError(w, http.StatusInternalServerError, "failed to generate API key")
		return
	}
	if req.Scopes == nil {
		req.Scopes = []string{}
	}
	apiKey := &models.APIKey{
		ID:           uuid.New().String(),
		Name:         req.Name,
		KeyHash:      hash,
		KeyPrefix:    prefix,
		EnvironmentID: req.EnvironmentID,
		Scopes:       req.Scopes,
	}
	if err := h.store.CreateAPIKey(apiKey); err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			middleware.JSONError(w, http.StatusConflict, "API key already exists")
			return
		}
		middleware.JSONError(w, http.StatusInternalServerError, "failed to create API key")
		return
	}
	h.audit(auth.ActorFromContext(r.Context()), "CREATE", "api_key", apiKey.ID, req.Name)
	// Return the raw key only on creation
	middleware.JSONResponse(w, http.StatusCreated, map[string]any{
		"id":           apiKey.ID,
		"name":         apiKey.Name,
		"key":          rawKey,
		"key_prefix":   prefix,
		"environment_id": req.EnvironmentID,
		"scopes":       req.Scopes,
		"created_at":   apiKey.CreatedAt,
	})
}

func (h *Handler) revokeAPIKey(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	// R7-L1: Check existence before revoke
	existing, err := h.store.GetAPIKeyByID(id)
	if err != nil || existing == nil {
		middleware.JSONError(w, http.StatusNotFound, "API key not found")
		return
	}
	if err := h.store.RevokeAPIKey(id); err != nil {
		middleware.JSONError(w, http.StatusInternalServerError, "failed to revoke API key")
		return
	}
	h.audit(auth.ActorFromContext(r.Context()), "REVOKE", "api_key", id, "")
	w.WriteHeader(http.StatusNoContent)
}

// --- Audit Log ---

func (h *Handler) listAuditEntries(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	entries, err := h.store.ListAuditEntries(limit, offset)
	if err != nil {
		middleware.JSONError(w, http.StatusInternalServerError, "database error")
		return
	}
	if entries == nil {
		entries = []models.AuditLogEntry{}
	}
	middleware.JSONResponse(w, http.StatusOK, entries)
}

// --- Admin Login (hardcoded credentials) ---

func (h *Handler) adminLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		middleware.JSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	user, token, err := h.auth.LoginAdmin(req.Email, req.Password)
	if err != nil {
		h.audit(req.Email, "LOGIN_FAILED", "user", "admin", "invalid credentials")
		// Still return generic error to prevent email enumeration
		middleware.JSONError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	h.audit(user.Email, "LOGIN", "user", user.ID, "admin login")
	// Set JWT as HttpOnly cookie for browser-based XSS protection
	isTLS := r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
	http.SetCookie(w, &http.Cookie{
		Name:     "reflag_token",
		Value:     token,
		Path:     "/",
		MaxAge:   86400, // 24 hours
		HttpOnly:  true,
		SameSite:  http.SameSiteLaxMode,
		Secure:    isTLS,
	})
	middleware.JSONResponse(w, http.StatusOK, map[string]any{
		"token": token,
		"user":  user,
	})
}

func (h *Handler) logout(w http.ResponseWriter, r *http.Request) {
	isTLS := r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
	http.SetCookie(w, &http.Cookie{
		Name:     "reflag_token",
		Value:     "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly:  true,
		SameSite:  http.SameSiteLaxMode,
		Secure:    isTLS,
	})
	middleware.JSONResponse(w, http.StatusOK, map[string]string{"status": "logged out"})
}

// --- Organizations ---

func (h *Handler) listOrgs(w http.ResponseWriter, r *http.Request) {
	orgs, err := h.store.ListOrgs()
	if err != nil {
		middleware.JSONError(w, http.StatusInternalServerError, "database error")
		return
	}
	if orgs == nil {
		orgs = []models.Organization{}
	}
	middleware.JSONResponse(w, http.StatusOK, orgs)
}

func (h *Handler) createOrg(w http.ResponseWriter, r *http.Request) {
	var org models.Organization
	if err := json.NewDecoder(r.Body).Decode(&org); err != nil {
		middleware.JSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if org.Name == "" || org.Slug == "" {
		middleware.JSONError(w, http.StatusBadRequest, "name and slug are required")
		return
	}
	if len(org.Name) > 256 {
		middleware.JSONError(w, http.StatusBadRequest, "name too long (max 256 chars)")
		return
	}
	if !isValidKey(org.Slug) {
		middleware.JSONError(w, http.StatusBadRequest, "slug must be alphanumeric with dashes/underscores, max 128 chars")
		return
	}
	org.ID = uuid.New().String()
	if err := h.store.CreateOrg(&org); err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			middleware.JSONError(w, http.StatusConflict, "slug already exists")
			return
		}
		middleware.JSONError(w, http.StatusInternalServerError, "failed to create org")
		return
	}
	// Make the creator an owner (if they exist in the users table)
	user := auth.UserFromContext(r.Context())
	if user != nil && user.ID != "admin" {
		member := &models.OrgMember{
			ID:     uuid.New().String(),
			UserID: user.ID,
			OrgID:  org.ID,
			Role:   "owner",
		}
		_ = h.store.AddOrgMember(member)
	}
	h.audit(auth.ActorFromContext(r.Context()), "CREATE", "organization", org.ID, org.Name)
	middleware.JSONResponse(w, http.StatusCreated, org)
}

func (h *Handler) deleteOrg(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	// R7-L1: Check existence before delete
	existing, err := h.store.GetOrg(id)
	if err != nil || existing == nil {
		middleware.JSONError(w, http.StatusNotFound, "organization not found")
		return
	}
	if err := h.store.DeleteOrg(id); err != nil {
		middleware.JSONError(w, http.StatusInternalServerError, "failed to delete org")
		return
	}
	h.audit(auth.ActorFromContext(r.Context()), "DELETE", "organization", id, "")
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) listOrgMembers(w http.ResponseWriter, r *http.Request) {
	orgID := r.PathValue("id")
	members, err := h.store.ListOrgMembers(orgID)
	if err != nil {
		middleware.JSONError(w, http.StatusInternalServerError, "database error")
		return
	}
	if members == nil {
		members = []models.OrgMember{}
	}
	middleware.JSONResponse(w, http.StatusOK, members)
}

func (h *Handler) addOrgMember(w http.ResponseWriter, r *http.Request) {
	orgID := r.PathValue("id")
	// Check that the authenticated user is admin/owner of this org (or hardcoded admin)
	user := auth.UserFromContext(r.Context())
	if user != nil && user.ID != "admin" {
		role, err := h.store.GetUserOrgRole(user.ID, orgID)
		if err != nil || (role != "owner" && role != "admin") {
			middleware.JSONError(w, http.StatusForbidden, "insufficient permissions — must be org admin or owner")
			return
		}
	}
	var req struct {
		Email string `json:"email"`
		Role  string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		middleware.JSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Email == "" {
		middleware.JSONError(w, http.StatusBadRequest, "email is required")
		return
	}
	if req.Role == "" {
		req.Role = "member"
	}
	if !isValidRole(req.Role) {
		middleware.JSONError(w, http.StatusBadRequest, "invalid role — must be owner, admin, member, or viewer")
		return
	}
	// Find user by email
	user, err := h.store.GetUserByEmail(req.Email)
	if err != nil || user == nil {
		middleware.JSONError(w, http.StatusNotFound, "user not found — they must log in via OIDC first")
		return
	}
	member := &models.OrgMember{
		ID:     uuid.New().String(),
		UserID: user.ID,
		OrgID:  orgID,
		Role:   req.Role,
	}
	if err := h.store.AddOrgMember(member); err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			middleware.JSONError(w, http.StatusConflict, "user already a member")
			return
		}
		middleware.JSONError(w, http.StatusInternalServerError, "failed to add member")
		return
	}
	h.audit(auth.ActorFromContext(r.Context()), "ADD_MEMBER", "organization", orgID, req.Email)
	member.UserName = user.Name
	member.UserEmail = user.Email
	middleware.JSONResponse(w, http.StatusCreated, member)
}

func (h *Handler) updateOrgMemberRole(w http.ResponseWriter, r *http.Request) {
	memberID := r.PathValue("memberId")
	// R7-H1: Always verify the member exists (regardless of admin role)
	member, err := h.store.GetOrgMemberByID(memberID)
	if err != nil || member == nil {
		middleware.JSONError(w, http.StatusNotFound, "member not found")
		return
	}
	// Check that the authenticated user is admin/owner of the member's org (or hardcoded admin)
	user := auth.UserFromContext(r.Context())
	if user != nil && user.ID != "admin" {
		role, err := h.store.GetUserOrgRole(user.ID, member.OrgID)
		if err != nil || (role != "owner" && role != "admin") {
			middleware.JSONError(w, http.StatusForbidden, "insufficient permissions — must be org admin or owner")
			return
		}
	}
	var req struct {
		Role string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		middleware.JSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Role == "" {
		middleware.JSONError(w, http.StatusBadRequest, "role is required")
		return
	}
	if !isValidRole(req.Role) {
		middleware.JSONError(w, http.StatusBadRequest, "invalid role — must be owner, admin, member, or viewer")
		return
	}
	if err := h.store.UpdateOrgMemberRole(memberID, req.Role); err != nil {
		middleware.JSONError(w, http.StatusInternalServerError, "failed to update role")
		return
	}
	h.audit(auth.ActorFromContext(r.Context()), "UPDATE_ROLE", "org_member", memberID, req.Role)
	middleware.JSONResponse(w, http.StatusOK, map[string]string{"status": "updated", "role": req.Role})
}

func (h *Handler) removeOrgMember(w http.ResponseWriter, r *http.Request) {
	memberID := r.PathValue("memberId")
	// R7-H1: Always verify the member exists (regardless of admin role)
	member, err := h.store.GetOrgMemberByID(memberID)
	if err != nil || member == nil {
		middleware.JSONError(w, http.StatusNotFound, "member not found")
		return
	}
	// Check that the authenticated user is admin/owner of the member's org (or hardcoded admin)
	user := auth.UserFromContext(r.Context())
	if user != nil && user.ID != "admin" {
		role, err := h.store.GetUserOrgRole(user.ID, member.OrgID)
		if err != nil || (role != "owner" && role != "admin") {
			middleware.JSONError(w, http.StatusForbidden, "insufficient permissions — must be org admin or owner")
			return
		}
	}
	if err := h.store.RemoveOrgMember(memberID); err != nil {
		middleware.JSONError(w, http.StatusInternalServerError, "failed to remove member")
		return
	}
	h.audit(auth.ActorFromContext(r.Context()), "REMOVE_MEMBER", "org_member", memberID, "")
	w.WriteHeader(http.StatusNoContent)
}

// --- Helpers ---

// isValidFlagType checks if a flag type is a recognized OpenFeature type.
var validFlagTypes = map[models.FlagType]bool{
	models.FlagTypeBoolean: true,
	models.FlagTypeString:  true,
	models.FlagTypeNumber:  true,
	models.FlagTypeObject:  true,
	models.FlagTypeSecret:  true,
}

func isValidFlagType(t models.FlagType) bool {
	return validFlagTypes[t]
}

// validateFlagConfig validates the internal consistency of a flag's configuration.
// Checks: type is known, at least one variation, variation IDs are unique,
// and all rule/default variation_id references point to existing variations.
func validateFlagConfig(flag *models.Flag) string {
	if !isValidFlagType(flag.Type) {
		return fmt.Sprintf("invalid flag type %q — must be one of: boolean, string, number, object, secret", flag.Type)
	}
	if len(flag.Variations) == 0 {
		return "flag must have at least one variation"
	}
	// Check variation ID uniqueness
	seen := make(map[string]bool, len(flag.Variations))
	for _, v := range flag.Variations {
		if v.ID == "" {
			return "variation ID cannot be empty"
		}
		if seen[v.ID] {
			return fmt.Sprintf("duplicate variation ID: %s", v.ID)
		}
		seen[v.ID] = true
	}
	// Validate default_rule references an existing variation
	if flag.DefaultRule != nil && flag.DefaultRule.VariationID != "" {
		if !seen[flag.DefaultRule.VariationID] {
			return fmt.Sprintf("default_rule references unknown variation: %s", flag.DefaultRule.VariationID)
		}
	}
	// R9-H2: Validate percentage map keys reference existing variations
	if flag.DefaultRule != nil && len(flag.DefaultRule.Percentage) > 0 {
		for varID := range flag.DefaultRule.Percentage {
			if !seen[varID] {
				return fmt.Sprintf("percentage references unknown variation: %s", varID)
			}
		}
	}
	// Validate targeting rules reference existing variations
	for _, rule := range flag.Targeting {
		if rule.VariationID != "" && !seen[rule.VariationID] {
			return fmt.Sprintf("targeting rule %q references unknown variation: %s", rule.Name, rule.VariationID)
		}
	}
	return ""
}

// isValidFlagKey validates that a flag key contains only safe characters.
func isValidFlagKey(key string) bool {
	if len(key) == 0 || len(key) > 128 {
		return false
	}
	for _, c := range key {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return true
}

// isValidKey validates a general-purpose identifier (env key, segment key, org slug, secret key).
// Allows alphanumeric, dashes, underscores, dots — max 128 chars. No path traversal chars.
func isValidKey(key string) bool {
	if len(key) == 0 || len(key) > 128 {
		return false
	}
	for _, c := range key {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// isValidRole checks if a role is one of the allowed values.
var validRoles = map[string]bool{
	"owner":  true,
	"admin":  true,
	"member": true,
	"viewer": true,
}

func isValidRole(role string) bool {
	return validRoles[role]
}

func (h *Handler) audit(actor, action, resource, resourceID, details string) {
	// Sanitize user-controlled fields to prevent log injection
	actor = sanitizeAuditField(actor)
	resourceID = sanitizeAuditField(resourceID)
	details = sanitizeAuditField(details)
	entry := &models.AuditLogEntry{
		ID:         uuid.New().String(),
		Actor:      actor,
		Action:     action,
		Resource:   resource,
		ResourceID: resourceID,
		Details:    details,
	}
	_ = h.store.CreateAuditEntry(entry)
}

// sanitizeAuditField strips newlines and truncates to prevent log injection.
func sanitizeAuditField(s string) string {
	s = strings.ReplaceAll(s, "\n", "")
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.ReplaceAll(s, "	", " ")
	if len(s) > 500 {
		s = s[:500]
	}
	return s
}

// resolveSecretRefs checks if the evaluated value is a secret reference
// ({"$secret": "KEY"}) and resolves it to the decrypted secret value.
// Non-secret values are returned as-is.
func (h *Handler) resolveSecretRefs(r *http.Request, flag *models.Flag, detail openfeature.ResolutionDetail) openfeature.ResolutionDetail {
	if detail.Value == nil || detail.Reason == openfeature.ReasonError {
		return detail
	}
	m, ok := detail.Value.(map[string]any)
	if !ok {
		return detail
	}
	secretKey, hasRef := m["$secret"]
	if !hasRef {
		return detail
	}
	keyStr, ok := secretKey.(string)
	if !ok {
		detail.Reason = openfeature.ReasonError
		detail.ErrorCode = openfeature.ErrSecretResolution
		detail.ErrorMessage = "$secret value must be a string"
		return detail
	}
	secret, err := h.store.GetSecretByKey(keyStr)
	if err != nil || secret == nil {
		detail.Reason = openfeature.ReasonError
		detail.ErrorCode = openfeature.ErrSecretNotFound
		detail.ErrorMessage = "secret not found"
		return detail
	}
	// Enforce API key environment scoping on secret resolution
	if apiKey := auth.APIKeyFromContext(r.Context()); apiKey != nil && apiKey.EnvironmentID != "" {
		if secret.EnvironmentID != apiKey.EnvironmentID {
			detail.Reason = openfeature.ReasonError
			detail.ErrorCode = openfeature.ErrSecretNotFound
			detail.ErrorMessage = "secret not found"
			return detail
		}
	}
	decrypted, err := crypto.Decrypt(secret.EncryptedValue, h.secretsKey)
	if err != nil {
		detail.Reason = openfeature.ReasonError
		detail.ErrorCode = openfeature.ErrSecretResolution
		detail.ErrorMessage = "failed to decrypt secret"
		return detail
	}
	detail.Value = decrypted
	return detail
}

// --- Secrets ---

func (h *Handler) listSecrets(w http.ResponseWriter, r *http.Request) {
	secrets, err := h.store.ListSecrets()
	if err != nil {
		middleware.JSONError(w, http.StatusInternalServerError, "database error")
		return
	}
	if secrets == nil {
		secrets = []models.Secret{}
	}
	middleware.JSONResponse(w, http.StatusOK, secrets)
}

func (h *Handler) createSecret(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Key           string `json:"key"`
		Name          string `json:"name"`
		Description   string `json:"description"`
		Value         string `json:"value"`
		EnvironmentID string `json:"environment_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		middleware.JSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Key == "" {
		middleware.JSONError(w, http.StatusBadRequest, "key is required")
		return
	}
	if !isValidKey(req.Key) {
		middleware.JSONError(w, http.StatusBadRequest, "key must be alphanumeric with dashes/underscores, max 128 chars")
		return
	}
	if len(req.Name) > 256 {
		middleware.JSONError(w, http.StatusBadRequest, "name too long (max 256 chars)")
		return
	}
	if req.Value == "" {
		middleware.JSONError(w, http.StatusBadRequest, "value is required")
		return
	}
	if len(req.Value) > 65536 {
		middleware.JSONError(w, http.StatusBadRequest, "value too long (max 64KB)")
		return
	}
	// Validate environment_id if provided
	if req.EnvironmentID != "" {
		env, _ := h.store.GetEnvironment(req.EnvironmentID)
		if env == nil {
			env, _ = h.store.GetEnvironmentByKey(req.EnvironmentID)
			if env == nil {
				middleware.JSONError(w, http.StatusBadRequest, "environment_id does not reference an existing environment")
				return
			}
			req.EnvironmentID = env.ID
		}
	}

	encrypted, err := crypto.Encrypt(req.Value, h.secretsKey)
	if err != nil {
		middleware.JSONError(w, http.StatusInternalServerError, "encryption failed")
		return
	}

	secret := &models.Secret{
		ID:             uuid.New().String(),
		Key:            req.Key,
		Name:           req.Name,
		Description:    req.Description,
		EncryptedValue: encrypted,
		EnvironmentID:  req.EnvironmentID,
	}
	if err := h.store.CreateSecret(secret); err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			middleware.JSONError(w, http.StatusConflict, "secret key already exists")
			return
		}
		middleware.JSONError(w, http.StatusInternalServerError, "failed to create secret")
		return
	}
	h.audit(auth.ActorFromContext(r.Context()), "CREATE", "secret", secret.ID, secret.Key)
	// Return without the value
	middleware.JSONResponse(w, http.StatusCreated, map[string]any{
		"id":             secret.ID,
		"key":            secret.Key,
		"name":           secret.Name,
		"description":    secret.Description,
		"environment_id":  secret.EnvironmentID,
		"created_at":     secret.CreatedAt,
	})
}

func (h *Handler) getSecret(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	secret, err := h.store.GetSecret(id)
	if err != nil || secret == nil {
		middleware.JSONError(w, http.StatusNotFound, "secret not found")
		return
	}
	// Decrypt value for admin view
	decrypted, err := crypto.Decrypt(secret.EncryptedValue, h.secretsKey)
	if err != nil {
		middleware.JSONError(w, http.StatusInternalServerError, "decryption failed")
		return
	}
	middleware.JSONResponse(w, http.StatusOK, map[string]any{
		"id":            secret.ID,
		"key":           secret.Key,
		"name":          secret.Name,
		"description":   secret.Description,
		"value":         decrypted,
		"environment_id": secret.EnvironmentID,
		"created_at":    secret.CreatedAt,
		"updated_at":    secret.UpdatedAt,
	})
}

func (h *Handler) updateSecret(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	existing, err := h.store.GetSecret(id)
	if err != nil || existing == nil {
		middleware.JSONError(w, http.StatusNotFound, "secret not found")
		return
	}
	var req struct {
		Key           string `json:"key"`
		Name          string `json:"name"`
		Description   string `json:"description"`
		Value         string `json:"value"`
		EnvironmentID string `json:"environment_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		middleware.JSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// PATCH semantics: only update fields that are provided (non-empty)
	if req.Key != "" {
		if !isValidKey(req.Key) {
			middleware.JSONError(w, http.StatusBadRequest, "key must be alphanumeric with dashes/underscores, max 128 chars")
			return
		}
		existing.Key = req.Key
	}
	if req.Name != "" {
		if len(req.Name) > 256 {
			middleware.JSONError(w, http.StatusBadRequest, "name too long (max 256 chars)")
			return
		}
		existing.Name = req.Name
	}
	if req.Description != "" {
		existing.Description = req.Description
	}
	if req.Value != "" {
		if len(req.Value) > 65536 {
			middleware.JSONError(w, http.StatusBadRequest, "value too long (max 64KB)")
			return
		}
		encrypted, err := crypto.Encrypt(req.Value, h.secretsKey)
		if err != nil {
			middleware.JSONError(w, http.StatusInternalServerError, "encryption failed")
			return
		}
		existing.EncryptedValue = encrypted
	}
	if req.EnvironmentID != "" {
		// Validate environment_id exists
		env, _ := h.store.GetEnvironment(req.EnvironmentID)
		if env == nil {
			env, _ = h.store.GetEnvironmentByKey(req.EnvironmentID)
			if env == nil {
				middleware.JSONError(w, http.StatusBadRequest, "environment_id does not reference an existing environment")
				return
			}
			req.EnvironmentID = env.ID
		}
		existing.EnvironmentID = req.EnvironmentID
	}

	if err := h.store.UpdateSecret(existing); err != nil {
		middleware.JSONError(w, http.StatusInternalServerError, "failed to update secret")
		return
	}
	h.audit(auth.ActorFromContext(r.Context()), "UPDATE", "secret", id, existing.Key)
	middleware.JSONResponse(w, http.StatusOK, map[string]any{
		"id":            existing.ID,
		"key":           existing.Key,
		"name":          existing.Name,
		"description":   existing.Description,
		"environment_id": existing.EnvironmentID,
		"updated_at":    existing.UpdatedAt,
	})
}

func (h *Handler) deleteSecret(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	// R7-L1: Check existence before delete
	existing, err := h.store.GetSecret(id)
	if err != nil || existing == nil {
		middleware.JSONError(w, http.StatusNotFound, "secret not found")
		return
	}
	if err := h.store.DeleteSecret(id); err != nil {
		middleware.JSONError(w, http.StatusInternalServerError, "failed to delete secret")
		return
	}
	h.audit(auth.ActorFromContext(r.Context()), "DELETE", "secret", id, "")
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) resolveSecret(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("key")
	secret, err := h.store.GetSecretByKey(key)
	if err != nil || secret == nil {
		middleware.JSONResponse(w, http.StatusNotFound, map[string]any{
			"errorCode":    "SECRET_NOT_FOUND",
			"errorMessage": "secret not found",
		})
		return
	}
	// Scope by API key's environment if set
	apiKey := auth.APIKeyFromContext(r.Context())
	if apiKey != nil && apiKey.EnvironmentID != "" && secret.EnvironmentID != apiKey.EnvironmentID {
		middleware.JSONResponse(w, http.StatusNotFound, map[string]any{
			"errorCode":    "SECRET_NOT_FOUND",
			"errorMessage": "secret not found",
		})
		return
	}
	decrypted, err := crypto.Decrypt(secret.EncryptedValue, h.secretsKey)
	if err != nil {
		middleware.JSONError(w, http.StatusInternalServerError, "decryption failed")
		return
	}
	h.audit(auth.ActorFromContext(r.Context()), "RESOLVE", "secret", secret.ID, secret.Key)
	h.writeEncrypted(w, r, map[string]any{
		"key":   secret.Key,
		"value": decrypted,
	})
}

func (h *Handler) resolveAllSecrets(w http.ResponseWriter, r *http.Request) {
	apiKey := auth.APIKeyFromContext(r.Context())
	// Default-deny: require environment scoping on API keys
	if apiKey == nil || apiKey.EnvironmentID == "" {
		middleware.JSONError(w, http.StatusForbidden, "API key must be scoped to an environment")
		return
	}
	secrets, err := h.store.ListSecrets()
	if err != nil {
		middleware.JSONError(w, http.StatusInternalServerError, "database error")
		return
	}
	result := make(map[string]string)
	for _, s := range secrets {
		// Scope secrets by API key's environment ID
		if s.EnvironmentID != apiKey.EnvironmentID {
			continue
		}
		decrypted, err := crypto.Decrypt(s.EncryptedValue, h.secretsKey)
		if err != nil {
			continue
		}
		result[s.Key] = decrypted
	}
	// R9-M5: Batch audit — single entry instead of one per secret
	h.audit(auth.ActorFromContext(r.Context()), "RESOLVE_ALL", "secrets", "", fmt.Sprintf("resolved %d secrets", len(result)))
	h.writeEncrypted(w, r, result)
}

// writeEncrypted encrypts the response body using a transport key derived
// from the API key. The response contains the encrypted payload and metadata.
// Falls back to plain JSON if no API key is available (shouldn't happen for resolve endpoints).
func (h *Handler) writeEncrypted(w http.ResponseWriter, r *http.Request, data any) {
	rawKey := auth.RawAPIKeyFromContext(r.Context())
	if rawKey == "" {
		// No API key in context — shouldn't happen, but fall back to plain JSON
		middleware.JSONResponse(w, http.StatusOK, data)
		return
	}

	transportKey := crypto.DeriveTransportKey(rawKey)

	plaintext, err := json.Marshal(data)
	if err != nil {
		middleware.JSONError(w, http.StatusInternalServerError, "failed to marshal response")
		return
	}

	encrypted, err := crypto.EncryptPayload(plaintext, transportKey)
	if err != nil {
		middleware.JSONError(w, http.StatusInternalServerError, "failed to encrypt response")
		return
	}

	middleware.JSONResponse(w, http.StatusOK, map[string]any{
		"encrypted": true,
		"payload":   encrypted,
	})
}
