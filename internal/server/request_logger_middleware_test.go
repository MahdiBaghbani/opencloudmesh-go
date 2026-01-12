package server

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5/middleware"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/appctx"
)

// recordingHandler captures slog records for testing without JSON parsing.
type recordingHandler struct {
	records []slog.Record
	attrs   map[string]any
	groups  []string
}

func newRecordingHandler() *recordingHandler {
	return &recordingHandler{
		attrs: make(map[string]any),
	}
}

func (h *recordingHandler) Enabled(_ context.Context, _ slog.Level) bool {
	return true
}

func (h *recordingHandler) Handle(_ context.Context, r slog.Record) error {
	h.records = append(h.records, r)
	return nil
}

func (h *recordingHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	nh := &recordingHandler{
		records: h.records,
		attrs:   make(map[string]any),
		groups:  h.groups,
	}
	for k, v := range h.attrs {
		nh.attrs[k] = v
	}
	for _, a := range attrs {
		nh.attrs[a.Key] = a.Value.Any()
	}
	return nh
}

func (h *recordingHandler) WithGroup(name string) slog.Handler {
	nh := &recordingHandler{
		records: h.records,
		attrs:   make(map[string]any),
		groups:  append(h.groups, name),
	}
	for k, v := range h.attrs {
		nh.attrs[k] = v
	}
	return nh
}

// getAttr returns an attribute value from the handler's With attrs.
func (h *recordingHandler) getAttr(key string) (any, bool) {
	v, ok := h.attrs[key]
	return v, ok
}

func TestRequestLoggerMiddleware_AttachesRequiredFields(t *testing.T) {
	handler := newRecordingHandler()
	logger := slog.New(handler)
	tp := NewTrustedProxies([]string{"127.0.0.0/8"})

	var capturedLogger *slog.Logger
	var capturedHandler *recordingHandler

	// Create a handler that captures the request-scoped logger
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedLogger = appctx.GetLogger(r.Context())
		// The logger's handler should be a recordingHandler with attrs
		if rh, ok := capturedLogger.Handler().(*recordingHandler); ok {
			capturedHandler = rh
		}
		w.WriteHeader(http.StatusOK)
	})

	// Wrap with RequestID and RequestLoggerMiddleware
	chain := middleware.RequestID(RequestLoggerMiddleware(logger, tp)(nextHandler))

	req := httptest.NewRequest("GET", "/test/path", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	rr := httptest.NewRecorder()

	chain.ServeHTTP(rr, req)

	if capturedLogger == nil {
		t.Fatal("expected logger to be attached to context")
	}

	if capturedHandler == nil {
		t.Fatal("expected recording handler to capture attributes")
	}

	// Verify required fields are attached
	requiredFields := []string{"request_id", "method", "path", "client_ip"}
	for _, field := range requiredFields {
		if _, ok := capturedHandler.getAttr(field); !ok {
			t.Errorf("missing required field %q in logger", field)
		}
	}

	// Verify request_id is non-empty (middleware.RequestID ran first)
	if reqID, ok := capturedHandler.getAttr("request_id"); ok {
		if reqID == "" {
			t.Error("request_id should not be empty")
		}
	}

	// Verify method and path values
	if method, ok := capturedHandler.getAttr("method"); ok {
		if method != "GET" {
			t.Errorf("expected method 'GET', got %v", method)
		}
	}

	if path, ok := capturedHandler.getAttr("path"); ok {
		if path != "/test/path" {
			t.Errorf("expected path '/test/path', got %v", path)
		}
	}

	// Verify client_ip is populated via TrustedProxies
	if clientIP, ok := capturedHandler.getAttr("client_ip"); ok {
		if clientIP != "127.0.0.1" {
			t.Errorf("expected client_ip '127.0.0.1', got %v", clientIP)
		}
	}
}

func TestRequestLoggerMiddleware_ClientIPFromXForwardedFor(t *testing.T) {
	handler := newRecordingHandler()
	logger := slog.New(handler)
	// Trust localhost so X-Forwarded-For is honored
	tp := NewTrustedProxies([]string{"127.0.0.0/8"})

	var capturedHandler *recordingHandler

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedLogger := appctx.GetLogger(r.Context())
		if rh, ok := capturedLogger.Handler().(*recordingHandler); ok {
			capturedHandler = rh
		}
		w.WriteHeader(http.StatusOK)
	})

	chain := middleware.RequestID(RequestLoggerMiddleware(logger, tp)(nextHandler))

	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("X-Forwarded-For", "203.0.113.42")
	rr := httptest.NewRecorder()

	chain.ServeHTTP(rr, req)

	if capturedHandler == nil {
		t.Fatal("expected recording handler")
	}

	// Should use the X-Forwarded-For IP since request comes from trusted proxy
	if clientIP, ok := capturedHandler.getAttr("client_ip"); ok {
		if clientIP != "203.0.113.42" {
			t.Errorf("expected client_ip '203.0.113.42' from X-Forwarded-For, got %v", clientIP)
		}
	}
}

func TestRequestLoggerMiddleware_NilTrustedProxies(t *testing.T) {
	handler := newRecordingHandler()
	logger := slog.New(handler)

	var capturedHandler *recordingHandler

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedLogger := appctx.GetLogger(r.Context())
		if rh, ok := capturedLogger.Handler().(*recordingHandler); ok {
			capturedHandler = rh
		}
		w.WriteHeader(http.StatusOK)
	})

	// Pass nil trustedProxies
	chain := middleware.RequestID(RequestLoggerMiddleware(logger, nil)(nextHandler))

	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	rr := httptest.NewRecorder()

	chain.ServeHTTP(rr, req)

	if capturedHandler == nil {
		t.Fatal("expected recording handler")
	}

	// Should fallback to "unknown" when trustedProxies is nil
	if clientIP, ok := capturedHandler.getAttr("client_ip"); ok {
		if clientIP != "unknown" {
			t.Errorf("expected client_ip 'unknown' when trustedProxies is nil, got %v", clientIP)
		}
	}
}

func TestRequestLoggerMiddleware_PathOnly_NoQueryString(t *testing.T) {
	handler := newRecordingHandler()
	logger := slog.New(handler)
	tp := NewTrustedProxies([]string{"127.0.0.0/8"})

	var capturedHandler *recordingHandler

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedLogger := appctx.GetLogger(r.Context())
		if rh, ok := capturedLogger.Handler().(*recordingHandler); ok {
			capturedHandler = rh
		}
		w.WriteHeader(http.StatusOK)
	})

	chain := middleware.RequestID(RequestLoggerMiddleware(logger, tp)(nextHandler))

	// Request with query string
	req := httptest.NewRequest("GET", "/test/path?secret=value&token=abc", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	rr := httptest.NewRecorder()

	chain.ServeHTTP(rr, req)

	if capturedHandler == nil {
		t.Fatal("expected recording handler")
	}

	// Path should NOT include query string
	if path, ok := capturedHandler.getAttr("path"); ok {
		if path != "/test/path" {
			t.Errorf("expected path '/test/path' without query string, got %v", path)
		}
	}
}
