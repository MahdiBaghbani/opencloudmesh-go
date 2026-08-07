// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package sessiongate

import (
	"context"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/appctx"
	httpmw "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/middleware"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/realip"
	tshttp "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/http"
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
	maps.Copy(nh.attrs, h.attrs)

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
	maps.Copy(nh.attrs, h.attrs)

	return nh
}

func (h *recordingHandler) getAttr(key string) (any, bool) {
	v, ok := h.attrs[key]
	return v, ok
}

// testSessionRepo is a simple session repo for testing that returns a predefined session.
type testSessionRepo struct {
	session *identity.Session
}

func (r *testSessionRepo) Create(_ context.Context, _ string, _ time.Duration) (*identity.Session, error) {
	return r.session, nil
}

func (r *testSessionRepo) Get(_ context.Context, token string) (*identity.Session, error) {
	if r.session != nil && r.session.Token == token {
		return r.session, nil
	}

	return nil, identity.ErrSessionNotFound
}

func (r *testSessionRepo) Delete(_ context.Context, _ string) error {
	return nil
}

func (r *testSessionRepo) DeleteByUser(_ context.Context, _ string) error {
	return nil
}

func (r *testSessionRepo) DeleteExpired(_ context.Context) (int, error) {
	return 0, nil
}

// testPartyRepo is a simple party repo for testing.
type testPartyRepo struct {
	users map[string]*identity.User
}

func newTestPartyRepo() *testPartyRepo {
	return &testPartyRepo{
		users: make(map[string]*identity.User),
	}
}

func (r *testPartyRepo) Create(_ context.Context, user *identity.User) error {
	r.users[user.ID] = user
	return nil
}

func (r *testPartyRepo) Get(_ context.Context, id string) (*identity.User, error) {
	if u, ok := r.users[id]; ok {
		return u, nil
	}

	return nil, identity.ErrUserNotFound
}

func (r *testPartyRepo) GetByUsername(_ context.Context, username string) (*identity.User, error) {
	for _, u := range r.users {
		if u.Username == username {
			return u, nil
		}
	}

	return nil, identity.ErrUserNotFound
}

func (r *testPartyRepo) GetByEmail(_ context.Context, _ string) (*identity.User, error) {
	return nil, identity.ErrUserNotFound
}

func (r *testPartyRepo) Update(_ context.Context, user *identity.User) error {
	r.users[user.ID] = user
	return nil
}

func (r *testPartyRepo) Delete(_ context.Context, id string) error {
	delete(r.users, id)
	return nil
}

func (r *testPartyRepo) List(_ context.Context, _ string) ([]*identity.User, error) {
	result := make([]*identity.User, 0, len(r.users))
	for _, u := range r.users {
		result = append(result, u)
	}

	return result, nil
}

func (r *testPartyRepo) DeleteExpired(_ context.Context) (int, error) {
	return 0, nil
}

func TestAuthGate_EnrichesLoggerWithUserID(t *testing.T) {
	recorder := newRecordingHandler()
	logger := slog.New(recorder)
	tp := realip.NewTrustedProxies([]string{"127.0.0.0/8"})

	// Create test user
	testUserID := "user-123"
	testUser := &identity.User{
		ID:       testUserID,
		Username: "testuser",
		Email:    "test@example.com",
		Role:     identity.RoleUser,
	}

	// Create party repo and add user
	partyRepo := newTestPartyRepo()
	partyRepo.users[testUserID] = testUser

	// Create session repo with predefined session
	testSessionToken := "valid-session-token"
	sessionRepo := &testSessionRepo{
		session: &identity.Session{
			Token:     testSessionToken,
			UserID:    testUserID,
			CreatedAt: time.Now(),
			ExpiresAt: time.Now().Add(1 * time.Hour),
		},
	}

	// Track the captured user_id from the handler's logger
	var (
		capturedUserID  string
		capturedHandler *recordingHandler
	)

	// Create a handler that captures the enriched logger
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerLogger := appctx.GetLogger(r.Context())
		if rh, ok := handlerLogger.Handler().(*recordingHandler); ok {
			capturedHandler = rh
			if uid, exists := rh.getAttr("user_id"); exists {
				userID, ok := uid.(string)
				if !ok {
					t.Fatal("expected user_id string attribute")
				}

				capturedUserID = userID
			}
		}

		handlerLogger.Info("handler executed")
		w.WriteHeader(http.StatusOK)
	})

	// Build the middleware chain
	r := chi.NewRouter()
	r.Use(chimw.RequestID)
	r.Use(httpmw.RequestLoggerMiddleware(logger, tp))
	r.Use(NewAuthGate(AuthGateConfig{
		RequireAuth: func(path string) bool {
			return path == "/api/protected"
		},
		Log:         logger,
		SessionRepo: sessionRepo,
		PartyRepo:   partyRepo,
	}))
	r.Get("/api/protected", testHandler)

	// Make request with valid session
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/protected", nil)
	req.AddCookie(&http.Cookie{Name: "session", Value: testSessionToken}) //nolint:gosec // test fixture: fixed session cookie token on a local test request, not a real credential
	req.RemoteAddr = "127.0.0.1:12345"
	rr := httptest.NewRecorder()

	r.ServeHTTP(rr, req)

	// Verify request succeeded
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	// Verify user_id was attached to the handler's logger
	if capturedHandler == nil {
		t.Fatal("expected to capture recording handler")
	}

	if capturedUserID != testUserID {
		t.Errorf("expected user_id %q in handler logger, got %q", testUserID, capturedUserID)
	}
}

func TestAuthGate_NoUserIDForPublicEndpoints(t *testing.T) {
	recorder := newRecordingHandler()
	logger := slog.New(recorder)
	tp := realip.NewTrustedProxies([]string{"127.0.0.0/8"})

	var hasUserID bool

	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerLogger := appctx.GetLogger(r.Context())
		if rh, ok := handlerLogger.Handler().(*recordingHandler); ok {
			_, hasUserID = rh.getAttr("user_id")
		}

		w.WriteHeader(http.StatusOK)
	})

	r := chi.NewRouter()
	r.Use(chimw.RequestID)
	r.Use(httpmw.RequestLoggerMiddleware(logger, tp))
	r.Use(NewAuthGate(AuthGateConfig{
		RequireAuth: func(_ string) bool {
			return false // all paths are public for this test
		},
		Log:         logger,
		SessionRepo: &testSessionRepo{},
		PartyRepo:   newTestPartyRepo(),
	}))
	r.Get("/.well-known/ocm", testHandler) // Public endpoint

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/.well-known/ocm", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	rr := httptest.NewRecorder()

	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	// Public endpoints should NOT have user_id in logger
	if hasUserID {
		t.Error("expected no user_id in logger for public endpoint")
	}
}

func TestAuthGate_NilRepos_PublicEndpointSucceeds(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(nil, &slog.HandlerOptions{Level: slog.LevelError}))

	testHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		tshttp.MustWrite(t, w, []byte("ok"))
	})

	r := chi.NewRouter()
	r.Use(NewAuthGate(AuthGateConfig{
		RequireAuth: func(_ string) bool {
			return false // all paths are public
		},
		Log:         logger,
		SessionRepo: nil, // nil is safe when RequireAuth returns false
		PartyRepo:   nil, // nil is safe when RequireAuth returns false
	}))
	r.Get("/public", testHandler)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/public", nil)
	rr := httptest.NewRecorder()

	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 for public endpoint with nil repos, got %d", rr.Code)
	}
}

func TestAuthGate_RedirectsUIRequestsToLogin(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(nil, &slog.HandlerOptions{Level: slog.LevelError}))

	testHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	r := chi.NewRouter()
	r.Use(NewAuthGate(AuthGateConfig{
		RequireAuth: func(_ string) bool {
			return true
		},
		Log:         logger,
		SessionRepo: &testSessionRepo{},
		PartyRepo:   newTestPartyRepo(),
		BasePath:    "/ocm",
	}))
	r.Get("/ocm/ui/inbox", testHandler)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/ocm/ui/inbox?foo=bar", nil)
	rr := httptest.NewRecorder()

	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("expected 302 redirect, got %d", rr.Code)
	}

	location := rr.Header().Get("Location")
	if location == "" {
		t.Fatal("expected Location header to be set")
	}

	parsed, err := url.Parse(location)
	if err != nil {
		t.Fatalf("failed to parse redirect URL: %v", err)
	}

	if parsed.Path != "/ocm/ui/login" {
		t.Fatalf("expected login path /ocm/ui/login, got %q", parsed.Path)
	}

	redirect := parsed.Query().Get("redirect")
	if redirect != "/ocm/ui/inbox?foo=bar" {
		t.Fatalf("expected redirect to preserve original path, got %q", redirect)
	}
}

func TestNormalizeBasePath(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{"empty", "", "", false},
		{"simple", "/ocm", "/ocm", false},
		{"nested", "/apps/ocm", "/apps/ocm", false},
		{"trailing slash trimmed once", "/ui/", "/ui", false},
		{"no leading slash rejected", "ui", "", true},
		{"double slash rejected", "//evil", "", true},
		{"parent segment rejected", "/ocm/../x", "", true},
		{"backslash rejected", "/\\evil", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := normalizeBasePath(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %q", got)
				}

				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestAuthGate_InvalidBasePathFallsBackToEmpty(t *testing.T) {
	recorder := newRecordingHandler()
	logger := slog.New(recorder)

	protected := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	r := chi.NewRouter()
	r.Use(NewAuthGate(AuthGateConfig{
		RequireAuth: func(path string) bool {
			return path == "/ui/inbox"
		},
		Log:         logger,
		SessionRepo: &testSessionRepo{},
		PartyRepo:   newTestPartyRepo(),
		BasePath:    "//evil",
	}))
	r.Get("/ui/inbox", protected)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/ui/inbox", nil)
	rr := httptest.NewRecorder()

	// Must not panic; invalid base path falls back to "" so the UI prefix
	// resolves to "/ui" (the empty-base-path behavior).
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("expected 302 redirect, got %d", rr.Code)
	}

	parsed, err := url.Parse(rr.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}

	if parsed.Path != "/ui/login" {
		t.Fatalf("expected login path /ui/login (empty base fallback), got %q", parsed.Path)
	}

	// Bind the warning to the invalid-base-path event by exact message marker
	// (repo convention: match on the message, not just the level), and verify
	// the structured attrs tie the record to this specific failure.
	var sawWarning bool

	for _, rec := range recorder.records {
		if rec.Level != slog.LevelWarn {
			continue
		}

		if rec.Message != "invalid auth gate base path; falling back to empty" {
			continue
		}

		sawWarning = true

		var (
			gotBasePath  string
			gotError     string
			sawBasePath  bool
			sawErrorAttr bool
		)

		rec.Attrs(func(a slog.Attr) bool {
			switch a.Key {
			case "base_path":
				gotBasePath = a.Value.String()
				sawBasePath = true
			case "error":
				gotError = a.Value.String()
				sawErrorAttr = true
			}

			return true
		})

		if !sawBasePath {
			t.Error("expected base_path attr in invalid base path warning")
		} else if gotBasePath != "//evil" {
			t.Errorf("expected base_path %q, got %q", "//evil", gotBasePath)
		}

		if !sawErrorAttr {
			t.Error("expected error attr in invalid base path warning")
		} else if gotError == "" {
			t.Error("expected non-empty error attr in invalid base path warning")
		}

		break
	}

	if !sawWarning {
		t.Fatalf("expected a warning with message %q to be logged for invalid base path",
			"invalid auth gate base path; falling back to empty")
	}
}
