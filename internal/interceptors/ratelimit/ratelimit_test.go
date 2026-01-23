package ratelimit

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/interceptors"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/deps"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/realip"
)

// mockCounter implements cache.Counter for testing.
type mockCounter struct {
	counts   map[string]int64
	resetAt  time.Time
	errOnInc error
}

func newMockCounter() *mockCounter {
	return &mockCounter{
		counts:  make(map[string]int64),
		resetAt: time.Now().Add(60 * time.Second),
	}
}

func (m *mockCounter) Increment(ctx context.Context, key string, delta int64, ttl time.Duration) (int64, time.Time, error) {
	if m.errOnInc != nil {
		return 0, time.Time{}, m.errOnInc
	}
	m.counts[key] += delta
	return m.counts[key], m.resetAt, nil
}

func (m *mockCounter) GetCount(ctx context.Context, key string) (int64, error) {
	return m.counts[key], nil
}

func (m *mockCounter) Reset(ctx context.Context, key string) error {
	delete(m.counts, key)
	return nil
}

// mockCache wraps mockCounter to implement cache.CacheWithCounter.
type mockCache struct {
	counter *mockCounter
}

func (m *mockCache) Get(ctx context.Context, key string) ([]byte, error) {
	return nil, cache.ErrNotFound
}

func (m *mockCache) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	return nil
}

func (m *mockCache) Delete(ctx context.Context, key string) error {
	return nil
}

func (m *mockCache) Exists(ctx context.Context, key string) (bool, error) {
	return false, nil
}

func (m *mockCache) Close() error {
	return nil
}

func (m *mockCache) Increment(ctx context.Context, key string, delta int64, ttl time.Duration) (int64, time.Time, error) {
	return m.counter.Increment(ctx, key, delta, ttl)
}

func (m *mockCache) GetCount(ctx context.Context, key string) (int64, error) {
	return m.counter.GetCount(ctx, key)
}

func (m *mockCache) Reset(ctx context.Context, key string) error {
	return m.counter.Reset(ctx, key)
}

func TestInit_RegistersInterceptor(t *testing.T) {
	// The init() function should have registered the ratelimit interceptor
	fn, ok := interceptors.Get("ratelimit")
	if !ok {
		t.Fatal("expected ratelimit interceptor to be registered")
	}
	if fn == nil {
		t.Fatal("expected non-nil interceptor constructor")
	}
}

func TestConfigApplyDefaults(t *testing.T) {
	tests := []struct {
		name     string
		input    Config
		expected Config
	}{
		{
			name:  "empty config gets defaults",
			input: Config{},
			expected: Config{
				RequestsPerWindow: 100,
				WindowSeconds:     60,
			},
		},
		{
			name: "partial config gets partial defaults",
			input: Config{
				RequestsPerWindow: 50,
			},
			expected: Config{
				RequestsPerWindow: 50,
				WindowSeconds:     60,
			},
		},
		{
			name: "full config unchanged",
			input: Config{
				RequestsPerWindow: 200,
				WindowSeconds:     120,
			},
			expected: Config{
				RequestsPerWindow: 200,
				WindowSeconds:     120,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := tt.input
			c.ApplyDefaults()
			if c.RequestsPerWindow != tt.expected.RequestsPerWindow {
				t.Errorf("RequestsPerWindow = %d, want %d", c.RequestsPerWindow, tt.expected.RequestsPerWindow)
			}
			if c.WindowSeconds != tt.expected.WindowSeconds {
				t.Errorf("WindowSeconds = %d, want %d", c.WindowSeconds, tt.expected.WindowSeconds)
			}
		})
	}
}

func TestLimiter_AllowsRequestsUnderLimit(t *testing.T) {
	counter := newMockCounter()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	limiter := &Limiter{
		cache:   counter,
		keyFunc: func(r *http.Request) string { return "test-ip" },
		limit:   5,
		window:  60 * time.Second,
		log:     logger,
	}

	handler := limiter.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))

	// First 5 requests should succeed
	for i := 1; i <= 5; i++ {
		req := httptest.NewRequest("GET", "/test", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("request %d: expected status 200, got %d", i, rec.Code)
		}
	}
}

func TestLimiter_BlocksRequestsOverLimit(t *testing.T) {
	counter := newMockCounter()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	limiter := &Limiter{
		cache:   counter,
		keyFunc: func(r *http.Request) string { return "test-ip" },
		limit:   2,
		window:  60 * time.Second,
		log:     logger,
	}

	handler := limiter.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))

	// First 2 requests should succeed
	for i := 1; i <= 2; i++ {
		req := httptest.NewRequest("GET", "/test", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("request %d: expected status 200, got %d", i, rec.Code)
		}
	}

	// Third request should be rate limited
	req := httptest.NewRequest("GET", "/test", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("request 3: expected status 429, got %d", rec.Code)
	}

	// Check Retry-After header is present and positive
	retryAfter := rec.Header().Get("Retry-After")
	if retryAfter == "" {
		t.Error("expected Retry-After header to be set")
	} else {
		val, err := strconv.Atoi(retryAfter)
		if err != nil {
			t.Errorf("Retry-After should be an integer: %v", err)
		} else if val < 1 {
			t.Errorf("Retry-After should be at least 1, got %d", val)
		}
	}

	// Check error envelope format
	var envelope struct {
		Error struct {
			Code       string `json:"code"`
			ReasonCode string `json:"reason_code"`
			Message    string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&envelope); err != nil {
		t.Errorf("failed to decode error envelope: %v", err)
	}
	if envelope.Error.ReasonCode != "rate_limited" {
		t.Errorf("expected reason_code 'rate_limited', got '%s'", envelope.Error.ReasonCode)
	}
}

func TestLimiter_DifferentKeysTrackedSeparately(t *testing.T) {
	counter := newMockCounter()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Key function returns X-Test-Key header
	limiter := &Limiter{
		cache:   counter,
		keyFunc: func(r *http.Request) string { return r.Header.Get("X-Test-Key") },
		limit:   2,
		window:  60 * time.Second,
		log:     logger,
	}

	handler := limiter.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// 2 requests from client A should succeed
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("X-Test-Key", "client-a")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("client-a request %d: expected 200, got %d", i+1, rec.Code)
		}
	}

	// 3rd request from client A should be blocked
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Test-Key", "client-a")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("client-a request 3: expected 429, got %d", rec.Code)
	}

	// But client B should still be allowed
	req = httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Test-Key", "client-b")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("client-b request 1: expected 200, got %d", rec.Code)
	}
}

func TestLimiter_AllowsOnCacheError(t *testing.T) {
	counter := newMockCounter()
	counter.errOnInc = context.DeadlineExceeded // Simulate cache error
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	limiter := &Limiter{
		cache:   counter,
		keyFunc: func(r *http.Request) string { return "test-ip" },
		limit:   1,
		window:  60 * time.Second,
		log:     logger,
	}

	handler := limiter.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))

	// Request should be allowed even though cache fails
	req := httptest.NewRequest("GET", "/test", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200 on cache error (fail open), got %d", rec.Code)
	}
}

func TestWithKeyFunc(t *testing.T) {
	counter := newMockCounter()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	original := &Limiter{
		cache:   counter,
		keyFunc: func(r *http.Request) string { return "original" },
		limit:   10,
		window:  60 * time.Second,
		log:     logger,
	}

	customKeyFunc := func(r *http.Request) string { return "custom" }
	modified := original.WithKeyFunc(customKeyFunc)

	// Original should be unchanged
	req := httptest.NewRequest("GET", "/test", nil)
	if original.keyFunc(req) != "original" {
		t.Error("original keyFunc should not be modified")
	}

	// Modified should use new keyFunc
	if modified.keyFunc(req) != "custom" {
		t.Error("modified keyFunc should return 'custom'")
	}

	// Other fields should be copied
	if modified.limit != original.limit {
		t.Error("limit should be copied")
	}
	if modified.window != original.window {
		t.Error("window should be copied")
	}
}

func TestNew_WithDeps(t *testing.T) {
	// Setup deps with mock cache and realip
	deps.ResetDeps()
	counter := newMockCounter()
	mockCacheInstance := &mockCache{counter: counter}
	realIPExtractor := realip.NewTrustedProxies(nil)

	deps.SetDeps(&deps.Deps{
		Cache:  mockCacheInstance,
		RealIP: realIPExtractor,
	})
	defer deps.ResetDeps()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Create interceptor via New
	conf := map[string]any{
		"requests_per_window": int64(10),
		"window_seconds":      30,
	}
	middleware, err := New(conf, logger)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	if middleware == nil {
		t.Fatal("expected non-nil middleware")
	}

	// Test the middleware works
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "192.168.1.100:12345"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}
}
