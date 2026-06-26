package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/dovocoder/reflag/internal/auth"
	"github.com/dovocoder/reflag/internal/middleware"
	"github.com/dovocoder/reflag/internal/models"
	"github.com/dovocoder/reflag/internal/openfeature"
	"github.com/dovocoder/reflag/internal/store"
	"github.com/google/uuid"
)

type Handler struct {
	store *store.Store
	auth  *auth.AuthService
}

func NewHandler(s *store.Store, a *auth.AuthService) *Handler {
	return &Handler{store: s, auth: a}
}

// RegisterRoutes sets up all API routes on the given mux.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	// Public routes (no auth)
	mux.HandleFunc("GET /health", h.health)
	mux.HandleFunc("POST /api/auth/oidc/start", h.oidcStart)
	mux.HandleFunc("POST /api/auth/oidc/callback", h.oidcCallback)

	// Evaluation route (API key or JWT)
	evalMux := http.NewServeMux()
	evalMux.HandleFunc("POST /api/v1/flags/evaluate", h.evaluateFlag)
	evalMux.HandleFunc("POST /api/v1/flags/{key}/evaluate", h.evaluateFlagByKey)
	evalMux.HandleFunc("GET /api/v1/flags", h.listFlagsForClient)
	mux.Handle("/api/v1/", h.auth.AnyAuthMiddleware(evalMux))

	// Admin routes (JWT only)
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
	mux.Handle("/api/", h.auth.JWTMiddleware(adminMux))
}

// --- Health ---

func (h *Handler) health(w http.ResponseWriter, r *http.Request) {
	middleware.JSONResponse(w, http.StatusOK, map[string]string{"status": "ok"})
}

// --- OIDC Auth ---

func (h *Handler) oidcStart(w http.ResponseWriter, r *http.Request) {
	state, err := auth.GenerateState()
	if err != nil {
		middleware.JSONError(w, http.StatusInternalServerError, "failed to generate state")
		return
	}
	authURL, err := h.auth.GetAuthorizationURL(state)
	if err != nil {
		middleware.JSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	middleware.JSONResponse(w, http.StatusOK, map[string]string{
		"authorization_url": authURL,
		"state":            state,
	})
}

func (h *Handler) oidcCallback(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		middleware.JSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	user, token, err := h.auth.ExchangeCode(req.Code)
	if err != nil {
		middleware.JSONError(w, http.StatusUnauthorized, err.Error())
		return
	}
	h.audit(auth.ActorFromContext(r.Context()), "LOGIN", "user", user.ID, "")
	middleware.JSONResponse(w, http.StatusOK, map[string]any{
		"token": token,
		"user":  user,
	})
}

// --- Flag Evaluation (OpenFeature compatible) ---

func (h *Handler) evaluateFlag(w http.ResponseWriter, r *http.Request) {
	var req struct {
		FlagKey string                       `json:"flagKey"`
		EnvKey  string                       `json:"environment"`
		Context openfeature.ResolutionContext `json:"context"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		middleware.JSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	flag, err := h.store.GetFlagByKey(req.FlagKey)
	if err != nil {
		middleware.JSONError(w, http.StatusInternalServerError, "database error")
		return
	}
	if flag == nil {
		middleware.JSONResponse(w, http.StatusNotFound, map[string]any{
			"errorCode":   openfeature.ReasonNotFound,
			"errorMessage": "flag not found",
		})
		return
	}
	// Check for environment-specific config
	if req.EnvKey != "" {
		env, _ := h.store.GetEnvironmentByKey(req.EnvKey)
		if env != nil {
			if envFlag, _ := h.store.GetFlagConfig(flag.ID, env.ID); envFlag != nil {
				flag = envFlag
			}
		}
	}
	detail := openfeature.Evaluate(flag, req.EnvKey, req.Context)
	middleware.JSONResponse(w, http.StatusOK, detail)
}

func (h *Handler) evaluateFlagByKey(w http.ResponseWriter, r *http.Request) {
	flagKey := r.PathValue("key")
	var req struct {
		EnvKey  string                        `json:"environment"`
		Context openfeature.ResolutionContext `json:"context"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)

	flag, err := h.store.GetFlagByKey(flagKey)
	if err != nil || flag == nil {
		middleware.JSONResponse(w, http.StatusNotFound, map[string]any{
			"errorCode":   openfeature.ReasonNotFound,
			"errorMessage": "flag not found",
		})
		return
	}
	if req.EnvKey != "" {
		env, _ := h.store.GetEnvironmentByKey(req.EnvKey)
		if env != nil {
			if envFlag, _ := h.store.GetFlagConfig(flag.ID, env.ID); envFlag != nil {
				flag = envFlag
			}
		}
	}
	detail := openfeature.Evaluate(flag, req.EnvKey, req.Context)
	middleware.JSONResponse(w, http.StatusOK, detail)
}

func (h *Handler) listFlagsForClient(w http.ResponseWriter, r *http.Request) {
	flags, err := h.store.ListFlags()
	if err != nil {
		middleware.JSONError(w, http.StatusInternalServerError, "database error")
		return
	}
	// Return minimal data for client SDKs
	type clientFlag struct {
		Key      string          `json:"key"`
		Enabled  bool            `json:"enabled"`
		Type     string          `json:"type"`
		Variations []models.Variation `json:"variations"`
	}
	result := make([]clientFlag, 0, len(flags))
	for _, f := range flags {
		result = append(result, clientFlag{
			Key: f.Key, Enabled: f.Enabled, Type: string(f.Type), Variations: f.Variations,
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
	flag.ID = uuid.New().String()
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
	flag.ID = id
	if err := h.store.UpdateFlag(&flag); err != nil {
		middleware.JSONError(w, http.StatusInternalServerError, "failed to update flag")
		return
	}
	h.audit(auth.ActorFromContext(r.Context()), "UPDATE", "flag", id, flag.Key)
	middleware.JSONResponse(w, http.StatusOK, flag)
}

func (h *Handler) deleteFlag(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
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
	env.ID = uuid.New().String()
	if err := h.store.CreateEnvironment(&env); err != nil {
		middleware.JSONError(w, http.StatusInternalServerError, "failed to create environment")
		return
	}
	h.audit(auth.ActorFromContext(r.Context()), "CREATE", "environment", env.ID, env.Key)
	middleware.JSONResponse(w, http.StatusCreated, env)
}

func (h *Handler) deleteEnvironment(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
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
	seg.ID = uuid.New().String()
	if err := h.store.CreateSegment(&seg); err != nil {
		middleware.JSONError(w, http.StatusInternalServerError, "failed to create segment")
		return
	}
	h.audit(auth.ActorFromContext(r.Context()), "CREATE", "segment", seg.ID, seg.Key)
	middleware.JSONResponse(w, http.StatusCreated, seg)
}

func (h *Handler) deleteSegment(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
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

// --- Helpers ---

func (h *Handler) audit(actor, action, resource, resourceID, details string) {
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
