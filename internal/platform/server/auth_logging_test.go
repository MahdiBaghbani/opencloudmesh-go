package server

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/appctx"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/deps"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/realip"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/identity"
)

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

func (r *testPartyRepo) Update(_ context.Context, user *identity.User) error {
	r.users[user.ID] = user
	return nil
}

func (r *testPartyRepo) Delete(_ context.Context, id string) error {
	delete(r.users, id)
	return nil
}

func (r *testPartyRepo) List(_ context.Context, _ string) ([]*identity.User, error) {
	var result []*identity.User
	for _, u := range r.users {
		result = append(result, u)
	}
	return result, nil
}

func (r *testPartyRepo) DeleteExpired(_ context.Context) (int, error) {
	return 0, nil
}

func TestAuthMiddleware_EnrichesLoggerWithUserID(t *testing.T) {
	// Create a recording handler to capture logger attributes
	recorder := newRecordingHandler()
	logger := slog.New(recorder)

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

	// Create server
	cfg := config.StrictConfig()
	cfg.ExternalBasePath = ""
	tp := realip.NewTrustedProxies([]string{"127.0.0.0/8"})

	// Set up SharedDeps for auth middleware with RealIP
	deps.ResetDeps()
	deps.SetDeps(&deps.Deps{
		SessionRepo: sessionRepo,
		PartyRepo:   partyRepo,
		RealIP:      tp,
	})
	defer deps.ResetDeps()

	srv := &Server{
		cfg:    cfg,
		logger: logger,
	}

	// Track the captured user_id from the handler's logger
	var capturedUserID string
	var capturedHandler *recordingHandler

	// Create a handler that captures the enriched logger
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get the logger from context - should have user_id attached
		handlerLogger := appctx.GetLogger(r.Context())
		if rh, ok := handlerLogger.Handler().(*recordingHandler); ok {
			capturedHandler = rh
			if uid, exists := rh.getAttr("user_id"); exists {
				capturedUserID = uid.(string)
			}
		}

		// Also test that the logger works by logging something
		handlerLogger.Info("handler executed")
		w.WriteHeader(http.StatusOK)
	})

	// Build the middleware chain
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(RequestLoggerMiddleware(logger, tp))
	r.Use(srv.authMiddleware)
	r.Get("/api/protected", testHandler) // /api/* requires auth

	// Make request with valid session
	req := httptest.NewRequest("GET", "/api/protected", nil)
	req.AddCookie(&http.Cookie{Name: "session", Value: testSessionToken})
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

func TestAuthMiddleware_NoUserIDForPublicEndpoints(t *testing.T) {
	recorder := newRecordingHandler()
	logger := slog.New(recorder)

	cfg := config.StrictConfig()
	cfg.ExternalBasePath = ""
	tp := realip.NewTrustedProxies([]string{"127.0.0.0/8"})

	// Set up SharedDeps for auth middleware with RealIP
	deps.ResetDeps()
	deps.SetDeps(&deps.Deps{
		SessionRepo: &testSessionRepo{},
		PartyRepo:   newTestPartyRepo(),
		RealIP:      tp,
	})
	defer deps.ResetDeps()

	srv := &Server{
		cfg:    cfg,
		logger: logger,
	}

	var hasUserID bool

	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerLogger := appctx.GetLogger(r.Context())
		if rh, ok := handlerLogger.Handler().(*recordingHandler); ok {
			_, hasUserID = rh.getAttr("user_id")
		}
		w.WriteHeader(http.StatusOK)
	})

	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(RequestLoggerMiddleware(logger, tp))
	r.Use(srv.authMiddleware)
	r.Get("/.well-known/ocm", testHandler) // Public endpoint

	req := httptest.NewRequest("GET", "/.well-known/ocm", nil)
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
