package middleware

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/realip"
)

// accessLogRecorder captures access log records with all their attributes.
type accessLogRecorder struct {
	mu      sync.Mutex
	records []accessLogRecord
	level   slog.Level
}

type accessLogRecord struct {
	message string
	level   slog.Level
	attrs   map[string]any
}

func newAccessLogRecorder(level slog.Level) *accessLogRecorder {
	return &accessLogRecorder{
		level: level,
	}
}

func (r *accessLogRecorder) Enabled(_ context.Context, level slog.Level) bool {
	return level >= r.level
}

func (r *accessLogRecorder) Handle(_ context.Context, rec slog.Record) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	attrs := make(map[string]any)
	rec.Attrs(func(a slog.Attr) bool {
		attrs[a.Key] = a.Value.Any()
		return true
	})

	r.records = append(r.records, accessLogRecord{
		message: rec.Message,
		level:   rec.Level,
		attrs:   attrs,
	})
	return nil
}

func (r *accessLogRecorder) WithAttrs(attrs []slog.Attr) slog.Handler {
	// For access log testing, we need to capture WithAttrs calls
	// because the logger is enriched before the log call
	return &accessLogRecorderWithAttrs{
		parent:      r,
		parentAttrs: attrs,
	}
}

func (r *accessLogRecorder) WithGroup(name string) slog.Handler {
	return r
}

func (r *accessLogRecorder) getRecords() []accessLogRecord {
	r.mu.Lock()
	defer r.mu.Unlock()
	result := make([]accessLogRecord, len(r.records))
	copy(result, r.records)
	return result
}

// accessLogRecorderWithAttrs captures logs with pre-attached attrs.
type accessLogRecorderWithAttrs struct {
	parent      *accessLogRecorder
	parentAttrs []slog.Attr
}

func (r *accessLogRecorderWithAttrs) Enabled(ctx context.Context, level slog.Level) bool {
	return r.parent.Enabled(ctx, level)
}

func (r *accessLogRecorderWithAttrs) Handle(_ context.Context, rec slog.Record) error {
	r.parent.mu.Lock()
	defer r.parent.mu.Unlock()

	attrs := make(map[string]any)
	// Add parent attrs first
	for _, a := range r.parentAttrs {
		attrs[a.Key] = a.Value.Any()
	}
	// Add record attrs
	rec.Attrs(func(a slog.Attr) bool {
		attrs[a.Key] = a.Value.Any()
		return true
	})

	r.parent.records = append(r.parent.records, accessLogRecord{
		message: rec.Message,
		level:   rec.Level,
		attrs:   attrs,
	})
	return nil
}

func (r *accessLogRecorderWithAttrs) WithAttrs(attrs []slog.Attr) slog.Handler {
	newAttrs := make([]slog.Attr, len(r.parentAttrs)+len(attrs))
	copy(newAttrs, r.parentAttrs)
	copy(newAttrs[len(r.parentAttrs):], attrs)
	return &accessLogRecorderWithAttrs{
		parent:      r.parent,
		parentAttrs: newAttrs,
	}
}

func (r *accessLogRecorderWithAttrs) WithGroup(name string) slog.Handler {
	return r
}

func TestAccessLogMiddleware_Has7RequiredFields(t *testing.T) {
	recorder := newAccessLogRecorder(slog.LevelInfo)
	logger := slog.New(recorder)
	tp := realip.NewTrustedProxies([]string{"127.0.0.0/8"})

	// Create a simple handler
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("hello"))
	})

	// Build the middleware chain as in routes.go
	r := chi.NewRouter()
	r.Use(chimw.RequestID)
	r.Use(RequestLoggerMiddleware(logger, tp))
	r.Use(AccessLogMiddleware(logger, tp))
	r.Use(chimw.Recoverer)
	r.Get("/test", handler)

	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	rr := httptest.NewRecorder()

	r.ServeHTTP(rr, req)

	records := recorder.getRecords()
	if len(records) == 0 {
		t.Fatal("expected at least one log record")
	}

	// Find the "request" log entry
	var accessLog *accessLogRecord
	for i := range records {
		if records[i].message == "request" {
			accessLog = &records[i]
			break
		}
	}

	if accessLog == nil {
		t.Fatal("expected 'request' access log entry")
	}

	// Verify all 7 required fields are present
	requiredFields := []string{
		"request_id",
		"method",
		"path",
		"client_ip",
		"status",
		"bytes",
		"duration_ms",
	}

	for _, field := range requiredFields {
		if _, ok := accessLog.attrs[field]; !ok {
			t.Errorf("missing required access log field %q", field)
		}
	}

	// Verify there are no duplicate keys by counting
	// (the map already deduplicates, so we just check count)
	if len(accessLog.attrs) < 7 {
		t.Errorf("expected at least 7 fields in access log, got %d", len(accessLog.attrs))
	}

	// Verify specific values
	if accessLog.attrs["method"] != "GET" {
		t.Errorf("expected method 'GET', got %v", accessLog.attrs["method"])
	}
	if accessLog.attrs["path"] != "/test" {
		t.Errorf("expected path '/test', got %v", accessLog.attrs["path"])
	}
	// Status comes as int64 from slog Value
	if status, ok := accessLog.attrs["status"].(int64); !ok || status != 200 {
		t.Errorf("expected status 200, got %v (type %T)", accessLog.attrs["status"], accessLog.attrs["status"])
	}
}

func TestAccessLogMiddleware_FallbackWhenContextLoggerMissing(t *testing.T) {
	recorder := newAccessLogRecorder(slog.LevelInfo)
	logger := slog.New(recorder)
	tp := realip.NewTrustedProxies([]string{"127.0.0.0/8"})

	// Create a handler
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Build chain WITHOUT RequestLoggerMiddleware to test fallback
	r := chi.NewRouter()
	r.Use(chimw.RequestID)
	// Skip RequestLoggerMiddleware to trigger fallback
	r.Use(AccessLogMiddleware(logger, tp))
	r.Use(chimw.Recoverer)
	r.Get("/fallback-test", handler)

	req := httptest.NewRequest("POST", "/fallback-test", nil)
	req.RemoteAddr = "127.0.0.1:54321"
	rr := httptest.NewRecorder()

	r.ServeHTTP(rr, req)

	records := recorder.getRecords()
	if len(records) == 0 {
		t.Fatal("expected at least one log record")
	}

	// Find the "request" log entry
	var accessLog *accessLogRecord
	for i := range records {
		if records[i].message == "request" {
			accessLog = &records[i]
			break
		}
	}

	if accessLog == nil {
		t.Fatal("expected 'request' access log entry even without RequestLoggerMiddleware")
	}

	// Verify fallback populated the required fields
	requiredFields := []string{"request_id", "method", "path", "client_ip", "status", "bytes", "duration_ms"}
	for _, field := range requiredFields {
		if _, ok := accessLog.attrs[field]; !ok {
			t.Errorf("fallback: missing required access log field %q", field)
		}
	}

	// Verify values from fallback computation
	if accessLog.attrs["method"] != "POST" {
		t.Errorf("fallback: expected method 'POST', got %v", accessLog.attrs["method"])
	}
	if accessLog.attrs["path"] != "/fallback-test" {
		t.Errorf("fallback: expected path '/fallback-test', got %v", accessLog.attrs["path"])
	}
}

func TestAccessLogMiddleware_PanicProducesStatus500(t *testing.T) {
	recorder := newAccessLogRecorder(slog.LevelInfo)
	logger := slog.New(recorder)
	tp := realip.NewTrustedProxies([]string{"127.0.0.0/8"})

	// Create a handler that panics
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("test panic")
	})

	// Build the middleware chain as in routes.go
	// Order: RequestID -> RequestLoggerMiddleware -> AccessLogMiddleware -> Recoverer
	r := chi.NewRouter()
	r.Use(chimw.RequestID)
	r.Use(RequestLoggerMiddleware(logger, tp))
	r.Use(AccessLogMiddleware(logger, tp))
	r.Use(chimw.Recoverer)
	r.Get("/panic-test", handler)

	req := httptest.NewRequest("GET", "/panic-test", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	rr := httptest.NewRecorder()

	r.ServeHTTP(rr, req)

	// Verify the response is 500
	if rr.Code != http.StatusInternalServerError {
		t.Errorf("expected HTTP 500, got %d", rr.Code)
	}

	records := recorder.getRecords()
	if len(records) == 0 {
		t.Fatal("expected at least one log record after panic")
	}

	// Find the "request" log entry
	var accessLog *accessLogRecord
	for i := range records {
		if records[i].message == "request" {
			accessLog = &records[i]
			break
		}
	}

	if accessLog == nil {
		t.Fatal("expected 'request' access log entry after panic")
	}

	// Verify the access log captured status 500
	statusVal, ok := accessLog.attrs["status"]
	if !ok {
		t.Fatal("expected 'status' field in access log")
	}
	status, ok := statusVal.(int64)
	if !ok || status != 500 {
		t.Errorf("expected status 500 for panic, got %v (type %T)", statusVal, statusVal)
	}
}

func TestLogLevelFiltering_DebugNotEmittedAtInfoLevel(t *testing.T) {
	// Create a recorder at INFO level
	recorder := newAccessLogRecorder(slog.LevelInfo)
	logger := slog.New(recorder)

	// Log at different levels
	logger.Debug("debug message")
	logger.Info("info message")
	logger.Warn("warn message")

	records := recorder.getRecords()

	// Should only have info and warn, not debug
	if len(records) != 2 {
		t.Errorf("expected 2 records (info, warn), got %d", len(records))
	}

	for _, rec := range records {
		if rec.level == slog.LevelDebug {
			t.Error("debug message should not be emitted at info level")
		}
	}

	// Verify info and warn are present
	var hasInfo, hasWarn bool
	for _, rec := range records {
		if rec.message == "info message" {
			hasInfo = true
		}
		if rec.message == "warn message" {
			hasWarn = true
		}
	}

	if !hasInfo {
		t.Error("expected info message to be logged")
	}
	if !hasWarn {
		t.Error("expected warn message to be logged")
	}
}

func TestLogLevelFiltering_DebugEmittedAtDebugLevel(t *testing.T) {
	// Create a recorder at DEBUG level
	recorder := newAccessLogRecorder(slog.LevelDebug)
	logger := slog.New(recorder)

	// Log at different levels
	logger.Debug("debug message")
	logger.Info("info message")

	records := recorder.getRecords()

	// Should have both debug and info
	if len(records) != 2 {
		t.Errorf("expected 2 records (debug, info), got %d", len(records))
	}

	var hasDebug, hasInfo bool
	for _, rec := range records {
		if rec.message == "debug message" {
			hasDebug = true
		}
		if rec.message == "info message" {
			hasInfo = true
		}
	}

	if !hasDebug {
		t.Error("expected debug message to be logged at debug level")
	}
	if !hasInfo {
		t.Error("expected info message to be logged at debug level")
	}
}
