package middleware

import (
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// JSONResponse writes a JSON response with the given status code.
// Sets Cache-Control: no-store to prevent caching of API responses
// which may contain sensitive data (flag values, secrets, etc.).
func JSONResponse(w http.ResponseWriter, code int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(data)
}

// RecoveryMiddleware recovers from panics in handlers, preventing server crashes.
// Logs the panic and returns a 500 without leaking internal details.
func RecoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				JSONError(w, http.StatusInternalServerError, "internal server error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// JSONError writes a JSON error response.
func JSONError(w http.ResponseWriter, code int, message string) {
	JSONResponse(w, code, map[string]string{"error": message})
}

// allowedOrigins is a set of CORS origins that are allowed to make
// credentialed requests. Configured via CORS_ORIGINS env var (comma-separated).
var allowedOrigins sync.Map

func init() {
	if env := os.Getenv("CORS_ORIGINS"); env != "" {
		for _, o := range strings.Split(env, ",") {
			allowedOrigins.Store(strings.TrimSpace(o), true)
		}
	}
}

// isOriginAllowed checks if the given origin is in the allowed set.
// In development (no CORS_ORIGINS configured AND not production), allows localhost.
func isOriginAllowed(origin string) bool {
	if origin == "" {
		return false
	}
	_, ok := allowedOrigins.Load(origin)
	if ok {
		return true
	}
	// Dev fallback: allow localhost origins only when not in production
	if os.Getenv("APP_ENV") != "production" {
		_, hasConfig := allowedOrigins.Load("__configured__")
		if !hasConfig {
			if strings.HasPrefix(origin, "http://localhost") || strings.HasPrefix(origin, "http://127.0.0.1") {
				return true
			}
		}
	}
	return false
}

// CORSMiddleware adds CORS headers for development.
func CORSMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if isOriginAllowed(origin) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Vary", "Origin")
		}
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// SecurityHeadersMiddleware adds security headers to all responses.
func SecurityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		h.Set("X-XSS-Protection", "0") // Modern browsers use built-in XSS protection
		h.Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
		h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		// CSP — allow inline styles for Vite/shadcn, but block external resources
		if isAPIPath(r.URL.Path) {
			h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		} else {
			h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'")
		}
		next.ServeHTTP(w, r)
	})
}

func isAPIPath(path string) bool {
	return strings.HasPrefix(path, "/api/")
}

// RateLimiter implements a simple sliding-window rate limiter per IP.
type RateLimiter struct {
	mu       sync.Mutex
	store    map[string]*rateBucket
	rps      int
	window   time.Duration
	stopChan chan struct{}
}

type rateBucket struct {
	count       int
	windowStart time.Time
}

func NewRateLimiter(rps int, window time.Duration) *RateLimiter {
	rl := &RateLimiter{
		store:    make(map[string]*rateBucket),
		rps:      rps,
		window:   window,
		stopChan: make(chan struct{}),
	}
	// Periodic cleanup to prevent memory exhaustion from spoofed IPs
	go rl.cleanup()
	return rl
}

func (rl *RateLimiter) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			rl.mu.Lock()
			now := time.Now()
			for ip, bucket := range rl.store {
				if now.Sub(bucket.windowStart) > rl.window*2 {
					delete(rl.store, ip)
				}
			}
			rl.mu.Unlock()
		case <-rl.stopChan:
			return
		}
	}
}

func (rl *RateLimiter) Stop() {
	close(rl.stopChan)
}

func (rl *RateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	// Cap the number of tracked IPs to prevent memory exhaustion
	const maxIPs = 100000
	if len(rl.store) >= maxIPs {
		// Evict oldest entries
		now := time.Now()
		for ip, bucket := range rl.store {
			if now.Sub(bucket.windowStart) > rl.window {
				delete(rl.store, ip)
			}
		}
		// If still too many, clear all (DoS mitigation)
		if len(rl.store) >= maxIPs {
			rl.store = make(map[string]*rateBucket)
		}
	}

	now := time.Now()
	bucket, exists := rl.store[ip]
	if !exists || now.Sub(bucket.windowStart) > rl.window {
		rl.store[ip] = &rateBucket{count: 1, windowStart: now}
		return true
	}
	if bucket.count >= rl.rps {
		return false
	}
	bucket.count++
	return true
}

// trustedProxies is a set of proxy IPs that are trusted to provide
// accurate X-Forwarded-For headers. Configured via TRUSTED_PROXIES env var.
var trustedProxies sync.Map

func init() {
	if env := os.Getenv("TRUSTED_PROXIES"); env != "" {
		for _, p := range strings.Split(env, ",") {
			trustedProxies.Store(strings.TrimSpace(p), true)
		}
	}
}

func isTrustedProxy(ip string) bool {
	_, ok := trustedProxies.Load(ip)
	return ok
}

// clientIP extracts the client IP, trusting X-Forwarded-For only
// from configured trusted proxies.
func clientIP(r *http.Request) string {
	ip := r.RemoteAddr
	if idx := strings.LastIndex(ip, ":"); idx != -1 {
		ip = ip[:idx]
	}
	// Only trust X-Forwarded-For from trusted proxies
	if isTrustedProxy(ip) {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			return strings.TrimSpace(parts[0])
		}
	}
	return ip
}

// RateLimitMiddleware limits requests per IP address.
func RateLimitMiddleware(limiter *RateLimiter, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := clientIP(r)
		if !limiter.Allow(ip) {
			JSONError(w, http.StatusTooManyRequests, "rate limit exceeded")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// RequestLogger logs each request in structured format.
func RequestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &statusWriter{ResponseWriter: w, status: 200}
		next.ServeHTTP(rw, r)
		// Skip health check logging to reduce noise
		if r.URL.Path != "/health" {
			log.Printf("%s %s %d %s", r.Method, r.URL.Path, rw.status, time.Since(start))
		}
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

// CSRFMiddleware validates CSRF tokens for state-changing requests.
// Uses the Origin header validation pattern.
func CSRFMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" || r.Method == "HEAD" || r.Method == "OPTIONS" {
			next.ServeHTTP(w, r)
			return
		}
		// API key requests bypass CSRF (they're not browser-based)
		// Only bypass for API-key-specific paths (/api/v1/) to prevent
		// CSRF bypass on JWT-authenticated admin routes via dummy X-API-Key header
		if r.Header.Get("X-API-Key") != "" && strings.HasPrefix(r.URL.Path, "/api/v1/") {
			next.ServeHTTP(w, r)
			return
		}
		// Public auth endpoints bypass CSRF (login, OIDC callback)
		path := r.URL.Path
		if path == "/api/auth/login" || path == "/api/auth/oidc/start" || path == "/api/auth/oidc/callback" {
			next.ServeHTTP(w, r)
			return
		}
		// For JWT-based requests (browser), require Origin header
		origin := r.Header.Get("Origin")
		if origin == "" {
			// No Origin header — could be a non-browser client.
			// Check Referer as fallback.
			referer := r.Header.Get("Referer")
			if referer == "" {
				// No Origin or Referer — block to prevent CSRF
				JSONError(w, http.StatusForbidden, "CSRF check failed: missing Origin header")
				return
			}
			origin = referer
		}
		if !isSameOrigin(origin, r) {
			JSONError(w, http.StatusForbidden, "CSRF check failed")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func isSameOrigin(origin string, r *http.Request) bool {
	// Parse origin URL and compare only host (ignoring path/trailing slash)
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	return u.Host == r.Host
}

// MaxBodySize limits the size of request bodies to prevent DoS.
const MaxBodySize = 1 << 20 // 1MB

// MaxBodyMiddleware wraps the request body in a MaxBytesReader.
func MaxBodyMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, MaxBodySize)
		next.ServeHTTP(w, r)
	})
}
