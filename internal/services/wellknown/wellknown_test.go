package wellknown

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery/resolve"
	inboundsignature "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/inbound/signature"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/peercompat"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/policy"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/sigalg"
)

func nextcloudDiscoveryResolveInputs(t *testing.T) resolve.ResolveInputs {
	t.Helper()
	contract, err := peercompat.NewCompiledContract(
		nil,
		[]peercompat.ProfileMapping{{Pattern: "nc.example.com", Profile: "nextcloud"}},
	)
	if err != nil {
		t.Fatalf("NewCompiledContract() unexpected error: %v", err)
	}
	return resolve.ResolveInputs{PeerContract: contract}
}

func withPeerIdentity(req *http.Request, peer string) *http.Request {
	return req.WithContext(context.WithValue(req.Context(), inboundsignature.PeerIdentityKey, &inboundsignature.PeerIdentity{
		AuthorityForCompare: peer,
	}))
}

func TestNew_SucceedsWithResolveInputs(t *testing.T) {
	m := map[string]any{
		"ocmprovider": map[string]any{
			"endpoint": "https://example.com",
		},
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	svc, err := New(Inputs{Resolve: resolve.ResolveInputs{}}, m, log)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if svc.Prefix() != "" {
		t.Errorf("expected empty prefix, got %q", svc.Prefix())
	}
}

func TestNew_WarnsOnUnusedConfigKeys(t *testing.T) {
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))

	m := map[string]any{
		"unknown_key": "value",
		"ocmprovider": map[string]any{
			"endpoint": "https://example.com",
		},
	}

	_, err := New(Inputs{Resolve: resolve.ResolveInputs{}}, m, log)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNew_RejectsInvalidOCMProviderConfig(t *testing.T) {
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	m := map[string]any{
		"ocmprovider": "not-a-map",
	}

	_, err := New(Inputs{Resolve: resolve.ResolveInputs{}}, m, log)
	if err == nil {
		t.Error("expected error for invalid ocmprovider config type")
	}
}

func TestService_HandlerReturnsValidResponse(t *testing.T) {
	m := map[string]any{
		"ocmprovider": map[string]any{
			"endpoint": "https://example.com",
		},
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	svc, err := New(Inputs{Resolve: resolve.ResolveInputs{}}, m, log)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/.well-known/ocm", nil)
	w := httptest.NewRecorder()
	svc.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestService_Close(t *testing.T) {
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	m := map[string]any{
		"ocmprovider": map[string]any{
			"endpoint": "https://example.com",
		},
	}

	svc, err := New(Inputs{Resolve: resolve.ResolveInputs{}}, m, log)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if err := svc.Close(); err != nil {
		t.Errorf("unexpected error on Close: %v", err)
	}
}

func TestService_TrailingSlashAliases(t *testing.T) {
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	m := map[string]any{
		"ocmprovider": map[string]any{
			"endpoint": "https://example.com",
		},
	}

	svc, err := New(Inputs{Resolve: resolve.ResolveInputs{}}, m, log)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/.well-known/ocm/", nil)
	w := httptest.NewRecorder()
	svc.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("path /.well-known/ocm/: expected 200, got %d", w.Code)
	}
}

func TestService_PercentEncodedPath(t *testing.T) {
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	m := map[string]any{
		"ocmprovider": map[string]any{
			"endpoint": "https://example.com",
		},
	}

	svc, err := New(Inputs{Resolve: resolve.ResolveInputs{}}, m, log)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/.well-known/ocm", nil)
	req.URL.RawPath = "/.well-known%2Focm"
	w := httptest.NewRecorder()
	svc.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for percent-encoded path, got %d", w.Code)
	}
}

func TestService_APIVersionOverride(t *testing.T) {
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	m := map[string]any{
		"ocmprovider": map[string]any{
			"endpoint": "https://example.com",
			"api_version_overrides": []map[string]any{
				{
					"profile":             "nextcloud",
					"user_agent_contains": "Nextcloud Server Crawler",
					"api_version":         "1.1",
				},
			},
		},
	}

	svc, err := New(Inputs{Resolve: nextcloudDiscoveryResolveInputs(t)}, m, log)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/.well-known/ocm", nil)
	req = withPeerIdentity(req, "nc.example.com")
	req.Header.Set("User-Agent", "Nextcloud Server Crawler/1.0")
	w := httptest.NewRecorder()
	svc.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var disc spec.Discovery
	if err := json.Unmarshal(w.Body.Bytes(), &disc); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if disc.APIVersion != "1.1" {
		t.Fatalf("expected apiVersion 1.1 for matched peer override, got %q", disc.APIVersion)
	}
}

func TestService_APIVersionOverride_UserAgentOnlyDoesNotActivate(t *testing.T) {
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	m := map[string]any{
		"ocmprovider": map[string]any{
			"endpoint": "https://example.com",
			"api_version_overrides": []map[string]any{
				{
					"profile":             "nextcloud",
					"user_agent_contains": "Nextcloud Server Crawler",
					"api_version":         "1.1",
				},
			},
		},
	}

	svc, err := New(Inputs{Resolve: nextcloudDiscoveryResolveInputs(t)}, m, log)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/.well-known/ocm", nil)
	req.Header.Set("User-Agent", "Nextcloud Server Crawler/1.0")
	w := httptest.NewRecorder()
	svc.Handler().ServeHTTP(w, req)

	var disc spec.Discovery
	if err := json.Unmarshal(w.Body.Bytes(), &disc); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if disc.APIVersion != "1.2.2" {
		t.Fatalf("expected default apiVersion without peer identity, got %q", disc.APIVersion)
	}
}

func TestService_APIVersionOverride_WithoutProfileBindingDoesNotActivate(t *testing.T) {
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	m := map[string]any{
		"ocmprovider": map[string]any{
			"endpoint": "https://example.com",
			"api_version_overrides": []map[string]any{
				{
					"user_agent_contains": "Nextcloud Server Crawler",
					"api_version":         "1.1",
				},
			},
		},
	}

	svc, err := New(Inputs{Resolve: nextcloudDiscoveryResolveInputs(t)}, m, log)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/.well-known/ocm", nil)
	req = withPeerIdentity(req, "nc.example.com")
	req.Header.Set("User-Agent", "Nextcloud Server Crawler/1.0")
	w := httptest.NewRecorder()
	svc.Handler().ServeHTTP(w, req)

	var disc spec.Discovery
	if err := json.Unmarshal(w.Body.Bytes(), &disc); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if disc.APIVersion != "1.2.2" {
		t.Fatalf("expected default apiVersion without profile binding, got %q", disc.APIVersion)
	}
}

func TestService_APIVersionOverride_NoMatchUsesDefault(t *testing.T) {
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	m := map[string]any{
		"ocmprovider": map[string]any{
			"endpoint": "https://example.com",
			"api_version_overrides": []map[string]any{
				{
					"profile":             "nextcloud",
					"user_agent_contains": "Nextcloud Server Crawler",
					"api_version":         "1.1",
				},
			},
		},
	}

	svc, err := New(Inputs{Resolve: nextcloudDiscoveryResolveInputs(t)}, m, log)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/.well-known/ocm", nil)
	req = withPeerIdentity(req, "nc.example.com")
	req.Header.Set("User-Agent", "SomeOtherClient/1.0")
	w := httptest.NewRecorder()
	svc.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var disc spec.Discovery
	if err := json.Unmarshal(w.Body.Bytes(), &disc); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if disc.APIVersion != "1.2.2" {
		t.Fatalf("expected default apiVersion 1.2.2, got %q", disc.APIVersion)
	}
}

func TestService_APIVersionOverride_NoOverridesUsesDefault(t *testing.T) {
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	m := map[string]any{
		"ocmprovider": map[string]any{
			"endpoint": "https://example.com",
		},
	}

	svc, err := New(Inputs{Resolve: resolve.ResolveInputs{}}, m, log)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/.well-known/ocm", nil)
	w := httptest.NewRecorder()
	svc.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var disc spec.Discovery
	if err := json.Unmarshal(w.Body.Bytes(), &disc); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if disc.APIVersion != "1.2.2" {
		t.Fatalf("expected default apiVersion 1.2.2, got %q", disc.APIVersion)
	}
}

type mockPeerDiscovery struct {
	publicKeys map[string]sigalg.ResolvedPublicKey
}

func (m *mockPeerDiscovery) IsSigningCapable(ctx context.Context, host string) (bool, error) {
	return false, nil
}

func (m *mockPeerDiscovery) ResolveVerificationKey(ctx context.Context, keyID string) (sigalg.ResolvedPublicKey, error) {
	if key, ok := m.publicKeys[keyID]; ok {
		return key, nil
	}
	return sigalg.ResolvedPublicKey{}, context.Canceled
}

func resolvedKeyFromManager(km *crypto.KeyManager) sigalg.ResolvedPublicKey {
	return sigalg.ResolvedPublicKey{
		KeyID:     km.GetKeyID(),
		Algorithm: sigalg.Ed25519,
		PublicKey: km.GetSigningKey().PublicKey,
		JWKKty:    "OKP",
		JWKCrv:    "Ed25519",
	}
}

func signatureMiddlewareWithInboundMode(
	t *testing.T,
	inboundMode string,
	contract *peercompat.CompiledContract,
	pd inboundsignature.PeerDiscovery,
) *inboundsignature.SignatureMiddleware {
	t.Helper()
	base := config.DevConfig()
	base.Signature = config.SignatureConfig{InboundMode: inboundMode}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	return inboundsignature.NewSignatureMiddleware(
		policy.NewRuntimePolicy(base, nil),
		contract,
		pd,
		"https://receiver.example.com",
		base.Signature,
		log,
	)
}

func TestService_APIVersionOverride_ThroughSignatureMiddleware(t *testing.T) {
	km := crypto.NewKeyManager("", "https://nc.example.com")
	if err := km.LoadOrGenerate(); err != nil {
		t.Fatal(err)
	}
	signer := crypto.NewRFC9421Signer(km)

	resolveInputs := nextcloudDiscoveryResolveInputs(t)
	pd := &mockPeerDiscovery{
		publicKeys: map[string]sigalg.ResolvedPublicKey{
			km.GetKeyID(): resolvedKeyFromManager(km),
		},
	}

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	m := map[string]any{
		"ocmprovider": map[string]any{
			"endpoint": "https://example.com",
			"api_version_overrides": []map[string]any{
				{
					"profile":             "nextcloud",
					"user_agent_contains": "Nextcloud Server Crawler",
					"api_version":         "1.1",
				},
			},
		},
	}

	for _, tc := range []struct {
		name               string
		inboundMode        string
		signedAPIVersion   string
		unsignedAPIVersion string
	}{
		{
			name:               "off",
			inboundMode:        "off",
			signedAPIVersion:   "1.1",
			unsignedAPIVersion: "1.2.2",
		},
		{
			name:               "lenient",
			inboundMode:        "lenient",
			signedAPIVersion:   "1.1",
			unsignedAPIVersion: "1.2.2",
		},
		{
			name:               "strict",
			inboundMode:        "strict",
			signedAPIVersion:   "1.1",
			unsignedAPIVersion: "1.2.2",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mw := signatureMiddlewareWithInboundMode(
				t,
				tc.inboundMode,
				resolveInputs.PeerContract,
				pd,
			)

			svc, err := New(Inputs{
				Resolve:             resolveInputs,
				SignatureMiddleware: mw,
			}, m, log)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			t.Run("signed matched peer activates override", func(t *testing.T) {
				req := httptest.NewRequest(
					http.MethodGet,
					"https://receiver.example.com/.well-known/ocm",
					nil,
				)
				req.Host = "receiver.example.com"
				req.Header.Set("User-Agent", "Nextcloud Server Crawler/1.0")
				if err := signer.SignRequest(req, nil); err != nil {
					t.Fatalf("SignRequest: %v", err)
				}

				w := httptest.NewRecorder()
				svc.Handler().ServeHTTP(w, req)

				if w.Code != http.StatusOK {
					t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
				}

				var disc spec.Discovery
				if err := json.Unmarshal(w.Body.Bytes(), &disc); err != nil {
					t.Fatalf("failed to decode response: %v", err)
				}
				if disc.APIVersion != tc.signedAPIVersion {
					t.Fatalf(
						"expected apiVersion %s for signed matched peer in %s mode, got %q",
						tc.signedAPIVersion,
						tc.name,
						disc.APIVersion,
					)
				}
			})

			t.Run("unsigned request returns canonical response", func(t *testing.T) {
				req := httptest.NewRequest(http.MethodGet, "/.well-known/ocm", nil)
				w := httptest.NewRecorder()
				svc.Handler().ServeHTTP(w, req)

				if w.Code != http.StatusOK {
					t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
				}

				var disc spec.Discovery
				if err := json.Unmarshal(w.Body.Bytes(), &disc); err != nil {
					t.Fatalf("failed to decode response: %v", err)
				}
				if disc.APIVersion != tc.unsignedAPIVersion {
					t.Fatalf(
						"expected default apiVersion %s without override, got %q",
						tc.unsignedAPIVersion,
						disc.APIVersion,
					)
				}
			})
		})
	}
}
