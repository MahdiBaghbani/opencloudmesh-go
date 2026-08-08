// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package wellknown

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery/resolve"
	inboundsignature "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/inbound/signature"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/sigalg"
)

func signatureMiddlewareForTest(
	t *testing.T,
	pd inboundsignature.PeerDiscovery,
) *inboundsignature.SignatureMiddleware {
	t.Helper()

	sigCfg := config.DefaultSignatureConfig()
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	return inboundsignature.NewSignatureMiddleware(
		pd,
		"https://receiver.example.com",
		sigCfg,
		log,
	)
}
func TestNew_SucceedsWithResolveInputs(t *testing.T) {
	t.Parallel()

	m := map[string]any{
		"ocmprovider": map[string]any{},
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	svc, err := New(Inputs{Resolve: handlerResolveInputs(t, "")}, m, log)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if svc.Prefix() != "" {
		t.Errorf("expected empty prefix, got %q", svc.Prefix())
	}
}

func TestNew_WarnsOnUnusedConfigKeys(t *testing.T) {
	t.Parallel()

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))

	m := map[string]any{
		"unknown_key": "value",
		"ocmprovider": map[string]any{},
	}

	_, err := New(Inputs{Resolve: handlerResolveInputs(t, "")}, m, log)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
}

func TestNew_RejectsUnknownOCMProviderKeys(t *testing.T) {
	t.Parallel()

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	m := map[string]any{
		"ocmprovider": map[string]any{
			"definitely_unknown_key_xyz": "value",
		},
	}

	_, err := New(Inputs{Resolve: resolve.ResolveInputs{}}, m, log)
	if err == nil {
		t.Fatal("expected error for unknown ocmprovider key")
	}

	if !strings.Contains(err.Error(), "unused config keys") {
		t.Fatalf("expected unused config keys error, got %v", err)
	}
}

func TestNew_RejectsInvalidProviderConfig(t *testing.T) {
	t.Parallel()

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
	t.Parallel()

	m := map[string]any{
		"ocmprovider": map[string]any{},
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	svc, err := New(Inputs{Resolve: handlerResolveInputs(t, "")}, m, log)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/.well-known/ocm", nil)
	w := httptest.NewRecorder()
	svc.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestService_Close(t *testing.T) {
	t.Parallel()

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	m := map[string]any{
		"ocmprovider": map[string]any{},
	}

	svc, err := New(Inputs{Resolve: handlerResolveInputs(t, "")}, m, log)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if err := svc.Close(); err != nil {
		t.Errorf("unexpected error on Close: %v", err)
	}
}

func TestService_TrailingSlashPath(t *testing.T) {
	t.Parallel()

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	m := map[string]any{
		"ocmprovider": map[string]any{},
	}

	svc, err := New(Inputs{Resolve: handlerResolveInputs(t, "")}, m, log)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/.well-known/ocm/", nil)
	w := httptest.NewRecorder()
	svc.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("path /.well-known/ocm/: expected 200, got %d", w.Code)
	}
}

func TestService_PercentEncodedPath(t *testing.T) {
	t.Parallel()

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	m := map[string]any{
		"ocmprovider": map[string]any{},
	}

	svc, err := New(Inputs{Resolve: handlerResolveInputs(t, "")}, m, log)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/.well-known/ocm", nil)
	req.URL.RawPath = "/.well-known%2Focm"
	w := httptest.NewRecorder()
	svc.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for percent-encoded path, got %d", w.Code)
	}
}

func TestService_APIVersionPinned(t *testing.T) {
	t.Parallel()

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	m := map[string]any{
		"ocmprovider": map[string]any{},
	}

	svc, err := New(Inputs{Resolve: handlerResolveInputs(t, "")}, m, log)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/.well-known/ocm", nil)
	w := httptest.NewRecorder()
	svc.Handler().ServeHTTP(w, req)

	var disc spec.Discovery
	if err := json.Unmarshal(w.Body.Bytes(), &disc); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if disc.APIVersion != "1.4.0" {
		t.Fatalf("expected pinned apiVersion 1.4.0, got %q", disc.APIVersion)
	}
}

type mockPeerDiscovery struct {
	publicKeys map[string]sigalg.ResolvedPublicKey
}

func (m *mockPeerDiscovery) ResolveVerificationKey(_ context.Context, keyID string) (sigalg.ResolvedPublicKey, error) {
	if key, ok := m.publicKeys[keyID]; ok {
		return key, nil
	}

	return sigalg.ResolvedPublicKey{}, context.Canceled
}

func resolvedKeyFromManager(km *crypto.KeyManager) sigalg.ResolvedPublicKey {
	return sigalg.ResolvedPublicKey{
		KeyID:     km.GetKeyID(),
		PublicKey: km.GetSigningKey().PublicKey,
		JWKKty:    "OKP",
		JWKCrv:    "Ed25519",
		JWKAlg:    "Ed25519",
	}
}

func TestDiscoveryGET_VerifiesSignatureIfPresent(t *testing.T) {
	t.Parallel()

	km := crypto.NewKeyManager("", "https://nc.example.com")
	if err := km.LoadOrGenerate(); err != nil {
		t.Fatal(err)
	}

	signer := crypto.NewRFC9421Signer(km)

	resolveInputs := handlerResolveInputs(t, "")
	pd := &mockPeerDiscovery{
		publicKeys: map[string]sigalg.ResolvedPublicKey{
			km.GetKeyID(): resolvedKeyFromManager(km),
		},
	}
	mw := signatureMiddlewareForTest(t, pd)

	var captured *inboundsignature.PeerIdentity

	signedHandler := mw.VerifyOCMRequestIfPresent()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured = inboundsignature.GetPeerIdentity(r.Context())

		w.WriteHeader(http.StatusOK)
	}))

	signedReq := httptest.NewRequestWithContext(context.Background(),
		http.MethodGet,
		"https://receiver.example.com/.well-known/ocm",
		nil,
	)
	signedReq.Host = "receiver.example.com"
	signedReq.Header.Set("User-Agent", "Nextcloud Server Crawler/1.0")

	if err := signer.SignRequest(signedReq, nil); err != nil {
		t.Fatalf("SignRequest: %v", err)
	}

	signedW := httptest.NewRecorder()
	signedHandler.ServeHTTP(signedW, signedReq)

	if signedW.Code != http.StatusOK {
		t.Fatalf("signed discovery middleware returned %d: %s", signedW.Code, signedW.Body.String())
	}

	if captured == nil {
		t.Fatal("signed discovery did not populate peer identity")
	}

	if !captured.Authenticated {
		t.Fatal("signed discovery peer identity is not authenticated")
	}

	if captured.AuthorityForCompare != "nc.example.com" {
		t.Fatalf("AuthorityForCompare = %q, want %q", captured.AuthorityForCompare, "nc.example.com")
	}

	m := map[string]any{
		"ocmprovider": map[string]any{},
	}

	svc, err := New(Inputs{
		Resolve:             resolveInputs,
		SignatureMiddleware: mw,
	}, m, testLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	unsignedReq := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/.well-known/ocm", nil)
	unsignedW := httptest.NewRecorder()
	svc.Handler().ServeHTTP(unsignedW, unsignedReq)

	if unsignedW.Code != http.StatusOK {
		t.Fatalf("unsigned discovery returned %d: %s", unsignedW.Code, unsignedW.Body.String())
	}

	var disc spec.Discovery
	if err := json.Unmarshal(unsignedW.Body.Bytes(), &disc); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if disc.APIVersion != "1.4.0" {
		t.Fatalf("apiVersion = %q, want 1.4.0", disc.APIVersion)
	}
}
