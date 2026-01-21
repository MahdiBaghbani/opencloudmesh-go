// Package ratelimit provides rate limiting using the cache subsystem.
package ratelimit

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache"
)

var (
	ErrRateLimited = errors.New("rate limit exceeded")
)

// Config defines rate limiting parameters.
type Config struct {
	// RequestsPerWindow is the maximum requests allowed per window.
	RequestsPerWindow int64

	// Window is the time window for rate limiting.
	Window time.Duration

	// KeyPrefix is prepended to all rate limit keys.
	KeyPrefix string
}

// DefaultConfig returns sensible rate limiting defaults.
func DefaultConfig() *Config {
	return &Config{
		RequestsPerWindow: 100,
		Window:            time.Minute,
		KeyPrefix:         "ratelimit:",
	}
}

// Limiter provides rate limiting using a cache backend.
type Limiter struct {
	cache  cache.Counter
	config *Config
}

// New creates a new rate limiter.
func New(c cache.Counter, cfg *Config) *Limiter {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	return &Limiter{
		cache:  c,
		config: cfg,
	}
}

// Result contains the rate limit check result.
type Result struct {
	Allowed   bool
	Remaining int64
	ResetAt   time.Time
}

// Allow checks if a request is allowed for the given key.
// Returns the result with remaining quota and reset time.
func (l *Limiter) Allow(ctx context.Context, key string) (*Result, error) {
	fullKey := l.config.KeyPrefix + key

	// Increment the counter
	count, err := l.cache.Increment(ctx, fullKey, 1, l.config.Window)
	if err != nil {
		return nil, err
	}

	remaining := l.config.RequestsPerWindow - count
	if remaining < 0 {
		remaining = 0
	}

	return &Result{
		Allowed:   count <= l.config.RequestsPerWindow,
		Remaining: remaining,
		ResetAt:   time.Now().Add(l.config.Window),
	}, nil
}

// Check checks the rate limit without incrementing.
func (l *Limiter) Check(ctx context.Context, key string) (*Result, error) {
	fullKey := l.config.KeyPrefix + key

	count, err := l.cache.GetCount(ctx, fullKey)
	if err != nil {
		return nil, err
	}

	remaining := l.config.RequestsPerWindow - count
	if remaining < 0 {
		remaining = 0
	}

	return &Result{
		Allowed:   count < l.config.RequestsPerWindow,
		Remaining: remaining,
		ResetAt:   time.Now().Add(l.config.Window),
	}, nil
}

// Reset clears the rate limit for a key.
func (l *Limiter) Reset(ctx context.Context, key string) error {
	fullKey := l.config.KeyPrefix + key
	return l.cache.Reset(ctx, fullKey)
}

// KeyFromRequest extracts a rate limit key from an HTTP request.
// Uses X-Forwarded-For if present, otherwise RemoteAddr.
func KeyFromRequest(r *http.Request) string {
	// Check for forwarded header (behind proxy)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Take the first IP in the chain
		for i := 0; i < len(xff); i++ {
			if xff[i] == ',' {
				return xff[:i]
			}
		}
		return xff
	}

	// Fall back to RemoteAddr (strip port)
	addr := r.RemoteAddr
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			return addr[:i]
		}
	}
	return addr
}

// Middleware returns an HTTP middleware that applies rate limiting.
func (l *Limiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := KeyFromRequest(r)
		result, err := l.Allow(r.Context(), key)
		if err != nil {
			// On error, allow the request but log it
			next.ServeHTTP(w, r)
			return
		}

		// Set rate limit headers
		w.Header().Set("X-RateLimit-Limit", fmt.Sprintf("%d", l.config.RequestsPerWindow))
		w.Header().Set("X-RateLimit-Remaining", fmt.Sprintf("%d", result.Remaining))
		w.Header().Set("X-RateLimit-Reset", fmt.Sprintf("%d", result.ResetAt.Unix()))

		if !result.Allowed {
			w.Header().Set("Retry-After", fmt.Sprintf("%d", int(time.Until(result.ResetAt).Seconds())))
			w.WriteHeader(http.StatusTooManyRequests)
			w.Write([]byte(`{"error":"rate_limit_exceeded","message":"too many requests"}`))
			return
		}

		next.ServeHTTP(w, r)
	})
}
