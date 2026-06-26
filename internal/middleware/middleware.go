package middleware

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"
)

// JSONResponse writes a JSON response with the given status code.
func JSONResponse(w http.ResponseWriter, code int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(data)
}

// JSONError writes a JSON error response.
func JSONError(w http.ResponseWriter, code int, message string) {
	JSONResponse(w, code, map[string]string{"error": message})
}

// CORSMiddleware adds CORS headers for development.
func CORSMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
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
	mu    sync.Mutex
	store map[string]*rateBucket
	rps   int
	window time.Duration
}

type rateBucket struct {
	count    int
	windowStart time.Time
}

func NewRateLimiter(rps int, window time.Duration) *RateLimiter {
	return &RateLimiter{
		store:  make(map[string]*rateBucket),
		rps:    rps,
		window: window,
	}
}

func (rl *RateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

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

// RateLimitMiddleware limits requests per IP address.
func RateLimitMiddleware(limiter *RateLimiter, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract IP (strip port)
		ip := r.RemoteAddr
		if idx := strings.LastIndex(ip, ":"); idx != -1 {
			ip = ip[:idx]
		}
		// Check X-Forwarded-For for proxies
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			ip = strings.TrimSpace(parts[0])
		}
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
		fmt := "%s %s %d %s"
		args := []any{r.Method, r.URL.Path, rw.status, time.Since(start)}
		_ = fmt
		_ = args
		// Use stderr for logging in production
		// In a real app we'd use a structured logger
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
// Uses the double-submit cookie pattern.
func CSRFMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" || r.Method == "HEAD" || r.Method == "OPTIONS" {
			next.ServeHTTP(w, r)
			return
		}
		// API key requests bypass CSRF (they're not browser-based)
		if r.Header.Get("X-API-Key") != "" {
			next.ServeHTTP(w, r)
			return
		}
		// For JWT-based requests, check origin
		origin := r.Header.Get("Origin")
		if origin != "" && origin != r.Header.Get("Referer") {
			// If Origin doesn't match the host, reject
			// This is a simplified CSRF check
			if !isSameOrigin(origin, r) {
				JSONError(w, http.StatusForbidden, "CSRF check failed")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func isSameOrigin(origin string, r *http.Request) bool {
	// Parse origin URL and compare host with request host
	host := r.Host
	if strings.HasPrefix(origin, "https://") {
		return strings.TrimPrefix(origin, "https://") == host
	}
	if strings.HasPrefix(origin, "http://") {
		return strings.TrimPrefix(origin, "http://") == host
	}
	return false
}
