package ocm

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	inboundsignature "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/inbound/signature"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/policy"
	sharesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/localidentity"
	tslocalid "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/localidentity"
)

type ocmTestPeerDiscovery struct{}

func (ocmTestPeerDiscovery) IsSigningCapable(context.Context, string) (bool, error) {
	return false, nil
}

func (ocmTestPeerDiscovery) GetPublicKey(context.Context, string) (string, error) {
	return "", nil
}

func testInputs(cfg *config.Config) Inputs {
	id, err := localidentity.Derive(cfg.PublicOrigin, cfg.ExternalBasePath)
	if err != nil {
		panic("testInputs: " + err.Error())
	}
	return Inputs{
		OpenCloudMeshPolicy: policy.NewOpenCloudMeshPolicy(cfg),
		RuntimePolicy:       policy.NewRuntimePolicy(cfg, nil),
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
		logger,
	)
	in.RuntimePolicy = runtimePolicy
	in.OutgoingShareRepo = sharesoutgoing.NewMemoryOutgoingShareRepo()
	in.SignatureMiddleware = signatureMiddleware
	return in
}

func TestNew_FailsWithoutRequiredInputs(t *testing.T) {
	m := map[string]any{}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	_, err := New(Inputs{}, m, log)
	if err == nil {
		t.Fatal("expected error when required inputs are missing")
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

func TestService_Unprotected(t *testing.T) {
	m := map[string]any{}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	svc, err := New(setupTestInputs(), m, log)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	unprotected := svc.Unprotected()
	if len(unprotected) != 4 {
		t.Fatalf("expected 4 unprotected paths, got %d: %v", len(unprotected), unprotected)
	}

	expectedPaths := map[string]bool{
		"/shares":          false,
		"/notifications":   false,
		"/invite-accepted": false,
		"/token":           false,
	}
	for _, p := range unprotected {
		if _, ok := expectedPaths[p]; ok {
			expectedPaths[p] = true
		}
	}
	for p, found := range expectedPaths {
		if !found {
			t.Errorf("expected unprotected path %q not found", p)
		}
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

func TestService_NotificationsFollowInboundSignaturePolicy(t *testing.T) {
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

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected unsigned notification to reach the handler under lenient inbound policy, got %d: %s", w.Code, w.Body.String())
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
		RuntimePolicy:     policy.NewRuntimePolicy(cfg, nil),
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
