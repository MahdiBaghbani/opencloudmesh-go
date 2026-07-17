package ocm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	inboundsignature "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/inbound/signature"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/policy"
	sharesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/token"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/jwks"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/sigalg"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/localidentity"
	tslocalid "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/localidentity"
)

type ocmTestPeerDiscovery struct{}

func (ocmTestPeerDiscovery) IsSigningCapable(context.Context, string) (bool, error) {
	return false, nil
}

func (ocmTestPeerDiscovery) ResolveVerificationKey(_ context.Context, keyID string) (sigalg.ResolvedPublicKey, error) {
	return sigalg.ResolvedPublicKey{}, fmt.Errorf("jwks lookup for %q: %w", keyID, jwks.ErrKeyNotFound)
}

type serviceTestPeerDiscovery struct {
	publicKeys map[string]sigalg.ResolvedPublicKey
}

func (pd *serviceTestPeerDiscovery) IsSigningCapable(context.Context, string) (bool, error) {
	return false, nil
}

func (pd *serviceTestPeerDiscovery) ResolveVerificationKey(_ context.Context, keyID string) (sigalg.ResolvedPublicKey, error) {
	if key, ok := pd.publicKeys[keyID]; ok {
		return key, nil
	}
	return sigalg.ResolvedPublicKey{}, fmt.Errorf("jwks lookup for %q: %w", keyID, jwks.ErrKeyNotFound)
}

type identityCapturingTokenStore struct {
	inner    token.TokenStore
	captured *inboundsignature.PeerIdentity
}

func (s *identityCapturingTokenStore) Store(ctx context.Context, issued *token.IssuedToken) error {
	s.captured = inboundsignature.GetPeerIdentity(ctx)
	return s.inner.Store(ctx, issued)
}

func (s *identityCapturingTokenStore) Get(ctx context.Context, accessToken string) (*token.IssuedToken, error) {
	return s.inner.Get(ctx, accessToken)
}

func (s *identityCapturingTokenStore) Delete(ctx context.Context, accessToken string) error {
	return s.inner.Delete(ctx, accessToken)
}

func (s *identityCapturingTokenStore) CleanExpired(ctx context.Context) error {
	return s.inner.CleanExpired(ctx)
}

func setupSignedTokenServiceInputs(
	t *testing.T,
	pd inboundsignature.PeerDiscovery,
) (Inputs, *identityCapturingTokenStore, *sharesoutgoing.MemoryOutgoingShareRepo) {
	t.Helper()

	cfg := config.DevConfig()
	cfg.Signature.InboundMode = "strict"
	cfg.Signature.AllowMismatch = false

	in := testInputs(cfg)
	runtimePolicy := policy.NewRuntimePolicy(cfg, nil)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	innerStore := token.NewMemoryTokenStore()
	spyStore := &identityCapturingTokenStore{inner: innerStore}
	shareRepo := sharesoutgoing.NewMemoryOutgoingShareRepo()

	in.OpenCloudMeshPolicy = policy.NewOpenCloudMeshPolicy(cfg)
	in.OutgoingShareRepo = shareRepo
	in.TokenStore = spyStore
	in.SignatureMiddleware = inboundsignature.NewSignatureMiddleware(
		runtimePolicy,
		nil,
		pd,
		in.LocalIdentity.Origin,
		cfg.Signature,
		logger,
	)
	return in, spyStore, shareRepo
}

func testInputs(cfg *config.Config) Inputs {
	id, err := localidentity.Derive(cfg.PublicOrigin, cfg.ExternalBasePath)
	if err != nil {
		panic("testInputs: " + err.Error())
	}
	return Inputs{
		OpenCloudMeshPolicy: policy.NewOpenCloudMeshPolicy(cfg),
		LocalIdentity:       id,
		TokenExchangePath:   "token",
	}
}

func setupTestInputs() Inputs {
	cfg := config.DevConfig()
	return testInputs(cfg)
}

func setupTestInputsWithSignature(t *testing.T) Inputs {
	t.Helper()

	cfg := config.DevConfig()
	in := testInputs(cfg)
	runtimePolicy := policy.NewRuntimePolicy(cfg, nil)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	signatureMiddleware := inboundsignature.NewSignatureMiddleware(
		runtimePolicy,
		nil,
		ocmTestPeerDiscovery{},
		in.LocalIdentity.Origin,
		cfg.Signature,
		logger,
	)
	in.OutgoingShareRepo = sharesoutgoing.NewMemoryOutgoingShareRepo()
	in.SignatureMiddleware = signatureMiddleware
	return in
}

func TestNew_SucceedsWithEmptyInputs(t *testing.T) {
	m := map[string]any{}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	svc, err := New(Inputs{}, m, log)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if svc == nil {
		t.Fatal("expected non-nil service")
	}
}

func TestNew_SucceedsWithInputs(t *testing.T) {
	m := map[string]any{}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	svc, err := New(setupTestInputs(), m, log)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if svc == nil {
		t.Fatal("expected non-nil service")
	}
}

func TestService_Prefix(t *testing.T) {
	m := map[string]any{}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	svc, err := New(setupTestInputs(), m, log)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if svc.Prefix() != "ocm" {
		t.Errorf("expected prefix 'ocm', got %q", svc.Prefix())
	}
}

func TestService_Handler(t *testing.T) {
	m := map[string]any{}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	svc, err := New(setupTestInputs(), m, log)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if svc.Handler() == nil {
		t.Error("expected non-nil Handler")
	}
}

func TestService_Close(t *testing.T) {
	m := map[string]any{}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	svc, err := New(setupTestInputs(), m, log)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if err := svc.Close(); err != nil {
		t.Errorf("unexpected error on Close: %v", err)
	}
}

func TestService_RoutingSmoke(t *testing.T) {
	m := map[string]any{}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	svc, err := New(setupTestInputs(), m, log)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	tests := []struct {
		name string
		path string
	}{
		{"shares", "/shares"},
		{"notifications", "/notifications"},
		{"invite-accepted", "/invite-accepted"},
		{"token", "/token"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			w := httptest.NewRecorder()
			svc.Handler().ServeHTTP(w, req)

			if w.Code != http.StatusMethodNotAllowed {
				t.Errorf("GET %s: expected status 405, got %d", tt.path, w.Code)
			}
		})
	}
}

func TestService_NotificationsRequireVerifiedSignature(t *testing.T) {
	m := map[string]any{}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	svc, err := New(setupTestInputsWithSignature(t), m, log)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest(
		http.MethodPost,
		"/notifications",
		bytes.NewBufferString(`{"notificationType":"SHARE_ACCEPTED","resourceType":"file","providerId":"provider-123"}`),
	)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	svc.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected unsigned notification to be rejected, got %d: %s", w.Code, w.Body.String())
	}
}

func TestService_SharesRequireVerifiedSignature(t *testing.T) {
	m := map[string]any{}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	svc, err := New(setupTestInputsWithSignature(t), m, log)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest(
		http.MethodPost,
		"/shares",
		bytes.NewBufferString(`{"shareWith":"user@remote.example","name":"test","providerId":"provider-123","owner":"owner@remote.example","sender":"sender@remote.example","shareType":"user","resourceType":"file","protocol":{"name":"webdav","options":{"sharedSecret":"secret"}}}`),
	)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	svc.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected unsigned share to be rejected, got %d: %s", w.Code, w.Body.String())
	}
}

func TestService_InviteAcceptedRequireVerifiedSignature(t *testing.T) {
	m := map[string]any{}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	svc, err := New(setupTestInputsWithSignature(t), m, log)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest(
		http.MethodPost,
		"/invite-accepted",
		bytes.NewBufferString(`{"recipientProvider":"remote.example","token":"invite-token","userID":"user-1","email":"user@remote.example","name":"Remote User"}`),
	)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	svc.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected unsigned invite-accepted to be rejected, got %d: %s", w.Code, w.Body.String())
	}
}

func TestService_SignedTokenExchangePropagatesVerifiedIdentity(t *testing.T) {
	const clientHost = "receiver.example.com"
	const sharedSecret = "signed-token-secret"

	km := crypto.NewKeyManager("", "https://"+clientHost)
	if err := km.LoadOrGenerate(); err != nil {
		t.Fatalf("load key manager: %v", err)
	}
	signer := crypto.NewRFC9421Signer(km)

	pd := &serviceTestPeerDiscovery{
		publicKeys: map[string]sigalg.ResolvedPublicKey{
			km.GetKeyID(): {
				KeyID:     km.GetKeyID(),
				Algorithm: sigalg.Ed25519,
				PublicKey: km.GetSigningKey().PublicKey,
				JWKKty:    "OKP",
				JWKCrv:    "Ed25519",
			},
		},
	}

	inputs, spyStore, shareRepo := setupSignedTokenServiceInputs(t, pd)
	if err := shareRepo.Create(context.Background(), &sharesoutgoing.OutgoingShare{
		ProviderID:   "provider-signed-token",
		WebDAVID:     "webdav-signed-token",
		SharedSecret: sharedSecret,
		ReceiverHost: clientHost,
		LocalPath:    "/tmp/signed-token.txt",
	}); err != nil {
		t.Fatalf("create outgoing share: %v", err)
	}

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	svc, err := New(inputs, map[string]any{}, log)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	form := "grant_type=ocm_share&client_id=" + clientHost + "&code=" + sharedSecret
	body := []byte(form)
	origin := config.DevConfig().PublicOrigin
	req := httptest.NewRequest(http.MethodPost, origin+"/token", bytes.NewReader(body))
	req.Host = "localhost:9200"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := signer.SignRequest(req, body); err != nil {
		t.Fatalf("sign request: %v", err)
	}

	w := httptest.NewRecorder()
	svc.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected signed token exchange to succeed, got %d: %s", w.Code, w.Body.String())
	}

	var resp token.TokenResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode token response: %v", err)
	}
	if resp.AccessToken == "" {
		t.Fatal("expected non-empty access_token")
	}

	if spyStore.captured == nil {
		t.Fatal("expected token store to observe authenticated peer identity")
	}
	if !spyStore.captured.Authenticated {
		t.Fatal("expected authenticated peer identity from signature middleware")
	}
	if spyStore.captured.AuthorityForCompare != clientHost {
		t.Fatalf("AuthorityForCompare = %q, want %q", spyStore.captured.AuthorityForCompare, clientHost)
	}
}

func TestService_TokenRequireVerifiedSignature(t *testing.T) {
	m := map[string]any{}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	svc, err := New(setupTestInputsWithSignature(t), m, log)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	form := "grant_type=ocm_share&client_id=receiver.example.com&code=secret-code"
	req := httptest.NewRequest(
		http.MethodPost,
		"/token",
		bytes.NewBufferString(form),
	)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	svc.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected unsigned token exchange to be rejected, got %d: %s", w.Code, w.Body.String())
	}
}

// Shares, invite, and token routes require a declared peer (HTTP 400 when
// missing). Signature-only routes return 401 for unsigned requests instead.
func TestService_AndPeerRoutesRejectMissingDeclaredPeer(t *testing.T) {
	m := map[string]any{}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	svc, err := New(setupTestInputsWithSignature(t), m, log)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cases := []struct {
		name        string
		path        string
		contentType string
		body        string
	}{
		{
			name:        "shares",
			path:        "/shares",
			contentType: "application/json",
			body:        `{}`,
		},
		{
			name:        "invite-accepted",
			path:        "/invite-accepted",
			contentType: "application/json",
			body:        `{"token":"invite-token","userID":"user-1"}`,
		},
		{
			name:        "token",
			path:        "/token",
			contentType: "application/x-www-form-urlencoded",
			body:        "grant_type=ocm_share&code=secret-code",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, tc.path, bytes.NewBufferString(tc.body))
			req.Header.Set("Content-Type", tc.contentType)
			w := httptest.NewRecorder()
			svc.Handler().ServeHTTP(w, req)

			if w.Code != http.StatusBadRequest {
				t.Fatalf("expected 400 declared-peer fail-closed on %s (AndPeer wiring), got %d: %s",
					tc.name, w.Code, w.Body.String())
			}
			body := w.Body.String()
			if !strings.Contains(body, "declared peer") && !strings.Contains(body, "invalid declared peer") {
				t.Fatalf("%s body = %q, want declared-peer error", tc.name, body)
			}
		})
	}
}

func TestService_NotificationsStaySignatureOnly(t *testing.T) {
	m := map[string]any{}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	svc, err := New(setupTestInputsWithSignature(t), m, log)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Notifications use a nil declared-peer resolver (signature-only).
	req := httptest.NewRequest(http.MethodPost, "/notifications", bytes.NewBufferString(`{}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	svc.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("notifications must stay signature-only (401), got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "signature required") {
		t.Fatalf("body = %q, want signature required", w.Body.String())
	}
}

func TestNew_WarnsOnUnusedConfigKeys(t *testing.T) {
	var logBuf testLogBuffer
	log := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelWarn}))

	m := map[string]any{
		"unknown_key": "value",
	}

	_, err := New(setupTestInputs(), m, log)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !logBuf.contains("unused config keys") {
		t.Error("expected warning about unused config keys")
	}
}

func TestNew_EvaluatorOwnsTokenExchangeEnablement(t *testing.T) {
	tokenExchangeEnabled := true
	cfg := &config.Config{
		PublicOrigin: "https://example.com",
		TokenExchange: config.TokenExchangeConfig{
			Enabled: &tokenExchangeEnabled,
			Path:    "token",
		},
	}
	in := testInputs(cfg)

	m := map[string]any{
		"token_exchange": map[string]any{
			"enabled": false,
		},
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	svc, err := New(in, m, log)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/token", nil)
	w := httptest.NewRecorder()
	svc.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected token route to stay mounted (405 on GET), got %d", w.Code)
	}
}

func TestNew_RawConfigDoesNotBackfillTokenExchangeEnablement(t *testing.T) {
	tokenExchangeEnabled := true
	cfg := &config.Config{
		PublicOrigin: "https://example.com",
		TokenExchange: config.TokenExchangeConfig{
			Enabled: &tokenExchangeEnabled,
			Path:    "token",
		},
	}
	in := Inputs{
		LocalIdentity:     tslocalid.MustTestIdentity(t, cfg.PublicOrigin, cfg.ExternalBasePath),
		TokenExchangePath: "token",
	}

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	svc, err := New(in, map[string]any{}, log)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/token", nil)
	w := httptest.NewRecorder()
	svc.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusNotImplemented {
		t.Fatalf("expected disabled token exchange without canonical policy, got %d", w.Code)
	}
}

type testLogBuffer struct {
	data []byte
}

func (b *testLogBuffer) Write(p []byte) (n int, err error) {
	b.data = append(b.data, p...)
	return len(p), nil
}

func (b *testLogBuffer) contains(s string) bool {
	return len(b.data) > 0 && searchString(string(b.data), s)
}

func searchString(haystack, needle string) bool {
	for i := 0; i <= len(haystack)-len(needle); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
