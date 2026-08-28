// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package ratelimit

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache"
	tshttp "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/http"
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

func (m *mockCounter) Increment(_ context.Context, key string, delta int64, _ time.Duration) (int64, time.Time, error) {
	if m.errOnInc != nil {
		return 0, time.Time{}, m.errOnInc
	}

	m.counts[key] += delta

	return m.counts[key], m.resetAt, nil
}

func (m *mockCounter) GetCount(_ context.Context, key string) (int64, error) {
	return m.counts[key], nil
}

func (m *mockCounter) Reset(_ context.Context, key string) error {
	delete(m.counts, key)

	return nil
}

// mockCache wraps mockCounter to implement cache.CacheWithCounter.
type mockCache struct {
	counter *mockCounter
}

func (m *mockCache) Get(_ context.Context, _ string) ([]byte, error) {
	return nil, cache.ErrNotFound
}

func (m *mockCache) Set(_ context.Context, _ string, _ []byte, _ time.Duration) error {
	return nil
}

func (m *mockCache) Delete(_ context.Context, _ string) error {
	return nil
}

func (m *mockCache) Exists(_ context.Context, _ string) (bool, error) {
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

func TestLimiter_AllowsRequestsUnderLimit(t *testing.T) {
	t.Parallel()

	counter := newMockCounter()
	logger := slog.New(slog.DiscardHandler)

	limiter := &Limiter{
		cache:   counter,
		keyFunc: func(_ *http.Request) string { return "test-ip" },
		limit:   5,
		window:  60 * time.Second,
		log:     logger,
	}

	handler := limiter.Wrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		tshttp.MustWrite(t, w, []byte("ok"))
	}))

	// First 5 requests should succeed
	for i := 1; i <= 5; i++ {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("request %d: expected status 200, got %d", i, rec.Code)
		}
	}
}

func TestLimiter_BlocksRequestsOverLimit(t *testing.T) {
	t.Parallel()

	counter := newMockCounter()
	logger := slog.New(slog.DiscardHandler)

	limiter := &Limiter{
		cache:   counter,
		keyFunc: func(_ *http.Request) string { return "test-ip" },
		limit:   2,
		window:  60 * time.Second,
		log:     logger,
	}

	handler := limiter.Wrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		tshttp.MustWrite(t, w, []byte("ok"))
	}))

	// First 2 requests should succeed
	for i := 1; i <= 2; i++ {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("request %d: expected status 200, got %d", i, rec.Code)
		}
	}

	// Third request should be rate limited
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
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
			ReasonCode string `json:"reasonCode"`
			Message    string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&envelope); err != nil {
		t.Errorf("failed to decode error envelope: %v", err)
	}

	if envelope.Error.ReasonCode != "rate_limited" {
		t.Errorf("expected reasonCode 'rate_limited', got '%s'", envelope.Error.ReasonCode)
	}
}

func TestLimiter_DifferentKeysTrackedSeparately(t *testing.T) {
	t.Parallel()

	counter := newMockCounter()
	logger := slog.New(slog.DiscardHandler)

	// Key function returns X-Test-Key header
	limiter := &Limiter{
		cache:   counter,
		keyFunc: func(r *http.Request) string { return r.Header.Get("X-Test-Key") },
		limit:   2,
		window:  60 * time.Second,
		log:     logger,
	}

	handler := limiter.Wrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// 2 requests from client A should succeed
	for i := range 2 {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
		req.Header.Set("X-Test-Key", "client-a")

		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("client-a request %d: expected 200, got %d", i+1, rec.Code)
		}
	}

	// 3rd request from client A should be blocked
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
	req.Header.Set("X-Test-Key", "client-a")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("client-a request 3: expected 429, got %d", rec.Code)
	}

	// But client B should still be allowed
	req = httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
	req.Header.Set("X-Test-Key", "client-b")

	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("client-b request 1: expected 200, got %d", rec.Code)
	}
}

func TestLimiter_FailsClosedOnCacheError(t *testing.T) {
	t.Parallel()

	counter := newMockCounter()
	counter.errOnInc = context.DeadlineExceeded // Simulate cache error
	logger := slog.New(slog.DiscardHandler)

	limiter := &Limiter{
		cache:   counter,
		keyFunc: func(_ *http.Request) string { return "test-ip" },
		limit:   1,
		window:  60 * time.Second,
		log:     logger,
	}

	handler := limiter.Wrap(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		tshttp.MustWrite(t, w, []byte("ok"))
	}))

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("expected status 503 on cache error (fail closed), got %d", rec.Code)
	}

	if strings.Contains(rec.Body.String(), context.DeadlineExceeded.Error()) {
		t.Errorf("response leaked cache error: %s", rec.Body.String())
	}
}

func TestWithKeyFunc(t *testing.T) {
	t.Parallel()

	counter := newMockCounter()
	logger := slog.New(slog.DiscardHandler)

	original := &Limiter{
		cache:   counter,
		keyFunc: func(_ *http.Request) string { return "original" },
		limit:   10,
		window:  60 * time.Second,
		log:     logger,
	}

	customKeyFunc := func(_ *http.Request) string { return "custom" }
	modified := original.WithKeyFunc(customKeyFunc)

	// Original should be unchanged
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
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
