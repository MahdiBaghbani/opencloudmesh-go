// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package ratelimit

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/realip"
)

func TestNew_CreatesMiddleware(t *testing.T) {
	t.Parallel()

	mock := &mockCache{counter: newMockCounter()}
	realIP := realip.NewTrustedProxies(nil)
	in := Inputs{
		Cache:   mock,
		KeyFunc: realIP.GetClientIPString,
	}

	middleware, err := New(in, map[string]any{
		"requests_per_window": int64(10),
		"window_seconds":      60,
	}, slog.Default())
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	if middleware == nil {
		t.Fatal("expected non-nil middleware")
	}
}

func TestNew_FailsWithoutCache(t *testing.T) {
	t.Parallel()

	realIP := realip.NewTrustedProxies(nil)
	in := Inputs{KeyFunc: realIP.GetClientIPString}

	_, err := New(in, map[string]any{}, slog.Default())
	if err == nil {
		t.Fatal("expected error when Cache is nil")
	}

	if !errors.Is(err, ErrMissingCache) {
		t.Fatalf("expected ErrMissingCache, got: %v", err)
	}
}

func TestNew_FailsWithoutKeyFunc(t *testing.T) {
	t.Parallel()

	mock := &mockCache{counter: newMockCounter()}
	in := Inputs{Cache: mock}

	_, err := New(in, map[string]any{}, slog.Default())
	if err == nil {
		t.Fatal("expected error when KeyFunc is nil")
	}

	if !errors.Is(err, ErrMissingKeyFunc) {
		t.Fatalf("expected ErrMissingKeyFunc, got: %v", err)
	}
}

func TestConfigApplyDefaults(t *testing.T) {
	t.Parallel()

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
			t.Parallel()

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

func TestNew_WithInputs(t *testing.T) {
	t.Parallel()

	counter := newMockCounter()
	mockCacheInstance := &mockCache{counter: counter}
	realIPExtractor := realip.NewTrustedProxies(nil)

	in := Inputs{
		Cache:   mockCacheInstance,
		KeyFunc: realIPExtractor.GetClientIPString,
	}

	logger := slog.New(slog.DiscardHandler)

	conf := map[string]any{
		"requests_per_window": int64(10),
		"window_seconds":      30,
	}

	middleware, err := New(in, conf, logger)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	if middleware == nil {
		t.Fatal("expected non-nil middleware")
	}

	// Test the middleware works
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
	req.RemoteAddr = "192.168.1.100:12345"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}
}

func TestNewFromNamedProfile_NestedScanPublicStartPublic(t *testing.T) {
	t.Parallel()

	mock := &mockCache{counter: newMockCounter()}
	realIP := realip.NewTrustedProxies(nil)
	in := Inputs{
		Cache:   mock,
		KeyFunc: realIP.GetClientIPString,
	}

	interceptorsCfg := map[string]map[string]any{
		"ratelimit": {
			"profiles": map[string]any{
				"scan_public": map[string]any{
					"start_public": map[string]any{
						"requests_per_window": int64(10),
						"window_seconds":      60,
					},
				},
			},
		},
	}

	middleware, err := NewFromNamedProfile(in, interceptorsCfg, "scan_public", "start_public", slog.Default())
	if err != nil {
		t.Fatalf("NewFromNamedProfile() = %v, want nil", err)
	}

	if middleware == nil {
		t.Fatal("expected non-nil middleware")
	}

	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	for i := 1; i <= 10; i++ {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
		req.RemoteAddr = "192.168.1.100:12345"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("middleware request %d: expected status 200, got %d", i, rec.Code)
		}
	}

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
	req.RemoteAddr = "192.168.1.100:12345"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("middleware request 11: expected status 429, got %d", rec.Code)
	}
}
