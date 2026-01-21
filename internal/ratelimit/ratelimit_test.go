package ratelimit_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache/memory"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/ratelimit"
)

func TestLimiter_Allow(t *testing.T) {
	cache := memory.New(time.Minute, 0)
	defer cache.Close()

	cfg := &ratelimit.Config{
		RequestsPerWindow: 5,
		Window:            time.Minute,
		KeyPrefix:         "test:",
	}
	limiter := ratelimit.New(cache, cfg)
	ctx := context.Background()

	// First 5 requests should be allowed
	for i := 0; i < 5; i++ {
		result, err := limiter.Allow(ctx, "client1")
		if err != nil {
			t.Fatalf("Allow failed: %v", err)
		}
		if !result.Allowed {
			t.Errorf("request %d should be allowed", i+1)
		}
		expectedRemaining := int64(4 - i)
		if result.Remaining != expectedRemaining {
			t.Errorf("request %d: expected remaining %d, got %d", i+1, expectedRemaining, result.Remaining)
		}
	}

	// 6th request should be denied
	result, err := limiter.Allow(ctx, "client1")
	if err != nil {
		t.Fatalf("Allow failed: %v", err)
	}
	if result.Allowed {
		t.Error("6th request should be denied")
	}
	if result.Remaining != 0 {
		t.Errorf("expected remaining 0, got %d", result.Remaining)
	}
}

func TestLimiter_DifferentKeys(t *testing.T) {
	cache := memory.New(time.Minute, 0)
	defer cache.Close()

	cfg := &ratelimit.Config{
		RequestsPerWindow: 2,
		Window:            time.Minute,
		KeyPrefix:         "test:",
	}
	limiter := ratelimit.New(cache, cfg)
	ctx := context.Background()

	// Exhaust client1's quota
	limiter.Allow(ctx, "client1")
	limiter.Allow(ctx, "client1")
	result, _ := limiter.Allow(ctx, "client1")
	if result.Allowed {
		t.Error("client1 should be rate limited")
	}

	// client2 should still have quota
	result, _ = limiter.Allow(ctx, "client2")
	if !result.Allowed {
		t.Error("client2 should be allowed")
	}
}

func TestLimiter_Check(t *testing.T) {
	cache := memory.New(time.Minute, 0)
	defer cache.Close()

	cfg := &ratelimit.Config{
		RequestsPerWindow: 5,
		Window:            time.Minute,
		KeyPrefix:         "test:",
	}
	limiter := ratelimit.New(cache, cfg)
	ctx := context.Background()

	// Check without any requests
	result, err := limiter.Check(ctx, "client1")
	if err != nil {
		t.Fatalf("Check failed: %v", err)
	}
	if !result.Allowed {
		t.Error("should be allowed before any requests")
	}
	if result.Remaining != 5 {
		t.Errorf("expected remaining 5, got %d", result.Remaining)
	}

	// Make some requests
	limiter.Allow(ctx, "client1")
	limiter.Allow(ctx, "client1")

	// Check should not increment
	result, _ = limiter.Check(ctx, "client1")
	if result.Remaining != 3 {
		t.Errorf("expected remaining 3, got %d", result.Remaining)
	}

	// Check again - should be same
	result, _ = limiter.Check(ctx, "client1")
	if result.Remaining != 3 {
		t.Errorf("Check should not decrement, expected 3, got %d", result.Remaining)
	}
}

func TestLimiter_Reset(t *testing.T) {
	cache := memory.New(time.Minute, 0)
	defer cache.Close()

	cfg := &ratelimit.Config{
		RequestsPerWindow: 2,
		Window:            time.Minute,
		KeyPrefix:         "test:",
	}
	limiter := ratelimit.New(cache, cfg)
	ctx := context.Background()

	// Exhaust quota
	limiter.Allow(ctx, "client1")
	limiter.Allow(ctx, "client1")

	// Reset
	if err := limiter.Reset(ctx, "client1"); err != nil {
		t.Fatalf("Reset failed: %v", err)
	}

	// Should be allowed again
	result, _ := limiter.Allow(ctx, "client1")
	if !result.Allowed {
		t.Error("should be allowed after reset")
	}
}

func TestKeyFromRequest(t *testing.T) {
	tests := []struct {
		name     string
		xff      string
		remote   string
		expected string
	}{
		{
			name:     "no headers",
			remote:   "192.168.1.1:12345",
			expected: "192.168.1.1",
		},
		{
			name:     "X-Forwarded-For single",
			xff:      "10.0.0.1",
			remote:   "192.168.1.1:12345",
			expected: "10.0.0.1",
		},
		{
			name:     "X-Forwarded-For multiple",
			xff:      "10.0.0.1, 10.0.0.2, 10.0.0.3",
			remote:   "192.168.1.1:12345",
			expected: "10.0.0.1",
		},
		{
			name:     "IPv6 remote",
			remote:   "[::1]:12345",
			expected: "[::1]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = tt.remote
			if tt.xff != "" {
				req.Header.Set("X-Forwarded-For", tt.xff)
			}

			key := ratelimit.KeyFromRequest(req)
			if key != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, key)
			}
		})
	}
}

func TestLimiter_Middleware(t *testing.T) {
	cache := memory.New(time.Minute, 0)
	defer cache.Close()

	cfg := &ratelimit.Config{
		RequestsPerWindow: 2,
		Window:            time.Minute,
		KeyPrefix:         "test:",
	}
	limiter := ratelimit.New(cache, cfg)

	// Create a simple handler
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	// Wrap with rate limiter
	wrapped := limiter.Middleware(handler)

	// First two requests should succeed
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		w := httptest.NewRecorder()

		wrapped.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("request %d: expected 200, got %d", i+1, w.Code)
		}

		// Check rate limit headers
		if w.Header().Get("X-RateLimit-Limit") != "2" {
			t.Errorf("missing or incorrect X-RateLimit-Limit header")
		}
	}

	// Third request should be rate limited
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	w := httptest.NewRecorder()

	wrapped.ServeHTTP(w, req)

	if w.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429, got %d", w.Code)
	}
	if w.Header().Get("Retry-After") == "" {
		t.Error("missing Retry-After header")
	}
}
