package webdav

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	sharesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/token"
)

var errNotFound = errors.New("not found")

type mockOutgoingShareRepo struct {
	shares map[string]*sharesoutgoing.OutgoingShare
}

func newMockOutgoingShareRepo() *mockOutgoingShareRepo {
	return &mockOutgoingShareRepo{shares: make(map[string]*sharesoutgoing.OutgoingShare)}
}

func (m *mockOutgoingShareRepo) Create(ctx context.Context, share *sharesoutgoing.OutgoingShare) error {
	m.shares[share.ShareID] = share
	return nil
}

func (m *mockOutgoingShareRepo) GetByID(ctx context.Context, shareID string) (*sharesoutgoing.OutgoingShare, error) {
	if s, ok := m.shares[shareID]; ok {
		return s, nil
	}
	return nil, errNotFound
}

func (m *mockOutgoingShareRepo) GetByProviderID(ctx context.Context, providerID string) (*sharesoutgoing.OutgoingShare, error) {
	for _, s := range m.shares {
		if s.ProviderID == providerID {
			return s, nil
		}
	}
	return nil, errNotFound
}

func (m *mockOutgoingShareRepo) GetByWebDAVID(ctx context.Context, webdavID string) (*sharesoutgoing.OutgoingShare, error) {
	for _, s := range m.shares {
		if s.WebDAVID == webdavID {
			return s, nil
		}
	}
	return nil, errNotFound
}

func (m *mockOutgoingShareRepo) GetBySharedSecret(ctx context.Context, sharedSecret string) (*sharesoutgoing.OutgoingShare, error) {
	for _, s := range m.shares {
		if s.SharedSecret == sharedSecret {
			return s, nil
		}
	}
	return nil, errNotFound
}

func (m *mockOutgoingShareRepo) List(ctx context.Context) ([]*sharesoutgoing.OutgoingShare, error) {
	result := make([]*sharesoutgoing.OutgoingShare, 0, len(m.shares))
	for _, s := range m.shares {
		result = append(result, s)
	}
	return result, nil
}

func (m *mockOutgoingShareRepo) Update(ctx context.Context, share *sharesoutgoing.OutgoingShare) error {
	m.shares[share.ShareID] = share
	return nil
}

type mockTokenStore struct {
	tokens map[string]*token.IssuedToken
}

func newMockTokenStore() *mockTokenStore {
	return &mockTokenStore{tokens: make(map[string]*token.IssuedToken)}
}

func (m *mockTokenStore) Store(ctx context.Context, t *token.IssuedToken) error {
	m.tokens[t.AccessToken] = t
	return nil
}

func (m *mockTokenStore) Get(ctx context.Context, accessToken string) (*token.IssuedToken, error) {
	t, ok := m.tokens[accessToken]
	if !ok {
		return nil, token.ErrTokenNotFound
	}
	if t.IsExpired() {
		return nil, token.ErrTokenExpired
	}
	return t, nil
}

func (m *mockTokenStore) Delete(ctx context.Context, accessToken string) error {
	delete(m.tokens, accessToken)
	return nil
}

func (m *mockTokenStore) CleanExpired(ctx context.Context) error {
	return nil
}

const testWebDAVID = "11111111-1111-1111-1111-111111111111"

func unexpiredTestToken(accessToken, shareID string) *token.IssuedToken {
	return &token.IssuedToken{
		AccessToken: accessToken,
		ShareID:     shareID,
		ExpiresAt:   time.Now().Add(time.Hour),
	}
}

func seedShare(repo *mockOutgoingShareRepo, shareID string) *sharesoutgoing.OutgoingShare {
	share := &sharesoutgoing.OutgoingShare{
		ShareID:      shareID,
		SharedSecret: "secret123",
		WebDAVID:     testWebDAVID,
		ReceiverHost: "receiver.example.com",
	}
	_ = repo.Create(context.Background(), share)
	return share
}

func TestValidateCredential_ExchangedTokenSucceeds(t *testing.T) {
	repo := newMockOutgoingShareRepo()
	tokenStore := newMockTokenStore()
	share := seedShare(repo, "share-1")

	ctx := context.Background()
	_ = tokenStore.Store(ctx, unexpiredTestToken("exchanged-token-123", share.ShareID))

	handler := NewHandler(repo, tokenStore, nil)

	authorized := handler.validateCredential(ctx, share, "exchanged-token-123")
	if !authorized {
		t.Error("expected authorization to succeed with valid exchanged token")
	}
}

func TestValidateCredential_RejectsSharedSecret(t *testing.T) {
	repo := newMockOutgoingShareRepo()
	tokenStore := newMockTokenStore()
	share := seedShare(repo, "share-1")

	handler := NewHandler(repo, tokenStore, nil)

	authorized := handler.validateCredential(context.Background(), share, share.SharedSecret)
	if authorized {
		t.Error("expected shared-secret authorization to fail")
	}
}

func TestValidateCredential_RejectsWrongShareBinding(t *testing.T) {
	repo := newMockOutgoingShareRepo()
	tokenStore := newMockTokenStore()
	share := seedShare(repo, "share-1")

	ctx := context.Background()
	_ = tokenStore.Store(ctx, unexpiredTestToken("bound-to-other-share", "other-share"))

	handler := NewHandler(repo, tokenStore, nil)

	authorized := handler.validateCredential(ctx, share, "bound-to-other-share")
	if authorized {
		t.Error("expected authorization to fail for wrong share binding")
	}
}

func TestValidateCredential_RejectsUnknownToken(t *testing.T) {
	repo := newMockOutgoingShareRepo()
	tokenStore := newMockTokenStore()
	share := seedShare(repo, "share-1")

	handler := NewHandler(repo, tokenStore, nil)

	authorized := handler.validateCredential(context.Background(), share, "unknown-token")
	if authorized {
		t.Error("expected authorization to fail for unknown token")
	}
}

func TestExtractCredential_BearerOnly(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/webdav/ocm/"+testWebDAVID, nil)
	req.Header.Set("Authorization", "Bearer my-token")

	cred := extractCredential(req)
	if cred == nil || cred.Token != "my-token" {
		t.Fatalf("expected Bearer token, got %+v", cred)
	}
}

func TestExtractCredential_RejectsBasic(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/webdav/ocm/"+testWebDAVID, nil)
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")

	if extractCredential(req) != nil {
		t.Error("expected nil for Basic auth")
	}
}

func TestExtractCredential_RejectsDigest(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/webdav/ocm/"+testWebDAVID, nil)
	req.Header.Set("Authorization", "Digest username=alice")

	if extractCredential(req) != nil {
		t.Error("expected nil for Digest auth")
	}
}

func assertBearerWWWAuthenticate(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	challenge := w.Header().Get("WWW-Authenticate")
	if challenge != `Bearer realm="OCM WebDAV"` {
		t.Errorf("WWW-Authenticate = %q, want Bearer-only challenge", challenge)
	}
	if strings.Contains(challenge, "Basic") {
		t.Errorf("WWW-Authenticate must not advertise Basic, got %q", challenge)
	}
}

func TestServeHTTP_MissingAuthBearerOnlyChallenge(t *testing.T) {
	repo := newMockOutgoingShareRepo()
	_ = seedShare(repo, "share-1")
	handler := NewHandler(repo, newMockTokenStore(), nil)

	req := httptest.NewRequest(http.MethodGet, "/webdav/ocm/"+testWebDAVID, nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
	assertBearerWWWAuthenticate(t, w)
}

func TestServeHTTP_BearerWithValidExchangedTokenSucceeds(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "hello.txt")
	if err := os.WriteFile(filePath, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}

	repo := newMockOutgoingShareRepo()
	share := seedShare(repo, "share-1")
	share.LocalPath = filePath
	_ = repo.Update(context.Background(), share)

	tokenStore := newMockTokenStore()
	_ = tokenStore.Store(context.Background(), unexpiredTestToken("valid-token", share.ShareID))

	handler := NewHandler(repo, tokenStore, nil)
	req := httptest.NewRequest(http.MethodGet, "/webdav/ocm/"+testWebDAVID+"/hello.txt", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestServeHTTP_BearerWithInvalidTokenFails401(t *testing.T) {
	repo := newMockOutgoingShareRepo()
	_ = seedShare(repo, "share-1")
	handler := NewHandler(repo, newMockTokenStore(), nil)

	req := httptest.NewRequest(http.MethodGet, "/webdav/ocm/"+testWebDAVID, nil)
	req.Header.Set("Authorization", "Bearer invalid-token")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
	assertBearerWWWAuthenticate(t, w)
}

func TestServeHTTP_BearerWithExpiredTokenFails401(t *testing.T) {
	repo := newMockOutgoingShareRepo()
	_ = seedShare(repo, "share-1")
	tokenStore := newMockTokenStore()
	_ = tokenStore.Store(context.Background(), &token.IssuedToken{
		AccessToken: "expired-token",
		ShareID:     "share-1",
		ExpiresAt:   time.Now().Add(-time.Hour),
	})

	handler := NewHandler(repo, tokenStore, nil)
	req := httptest.NewRequest(http.MethodGet, "/webdav/ocm/"+testWebDAVID, nil)
	req.Header.Set("Authorization", "Bearer expired-token")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for expired token, got %d", w.Code)
	}
	assertBearerWWWAuthenticate(t, w)
}

func TestServeHTTP_BasicAuthRejected401(t *testing.T) {
	repo := newMockOutgoingShareRepo()
	share := seedShare(repo, "share-1")
	tokenStore := newMockTokenStore()
	_ = tokenStore.Store(context.Background(), unexpiredTestToken(share.SharedSecret, share.ShareID))

	handler := NewHandler(repo, tokenStore, nil)
	req := httptest.NewRequest(http.MethodGet, "/webdav/ocm/"+testWebDAVID, nil)
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for Basic auth, got %d", w.Code)
	}
	assertBearerWWWAuthenticate(t, w)
}
