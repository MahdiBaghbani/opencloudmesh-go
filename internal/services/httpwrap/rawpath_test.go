package httpwrap

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClearRawPath(t *testing.T) {
	// Track what RawPath the inner handler sees
	var seenRawPath string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenRawPath = r.URL.RawPath
		w.WriteHeader(http.StatusOK)
	})

	handler := ClearRawPath(inner)

	// Create request with RawPath set (simulating percent-encoded segments)
	req := httptest.NewRequest("GET", "/path/with%2Fencoded", nil)
	req.URL.RawPath = "/path/with%2Fencoded"

	// Verify RawPath is set before wrapping
	if req.URL.RawPath == "" {
		t.Fatal("test setup error: RawPath should be set")
	}

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// Verify inner handler saw empty RawPath
	if seenRawPath != "" {
		t.Errorf("expected empty RawPath in inner handler, got %q", seenRawPath)
	}

	// Verify response came through
	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}
}

func TestClearRawPath_PreservesOtherURLFields(t *testing.T) {
	var seenPath, seenQuery string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenPath = r.URL.Path
		seenQuery = r.URL.RawQuery
		w.WriteHeader(http.StatusOK)
	})

	handler := ClearRawPath(inner)

	req := httptest.NewRequest("GET", "/test/path?foo=bar", nil)
	req.URL.RawPath = "/test/path"

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if seenPath != "/test/path" {
		t.Errorf("expected Path /test/path, got %q", seenPath)
	}
	if seenQuery != "foo=bar" {
		t.Errorf("expected RawQuery foo=bar, got %q", seenQuery)
	}
}
