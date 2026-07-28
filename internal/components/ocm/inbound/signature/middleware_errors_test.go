package signature_test

import (
	"bytes"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/jwks"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/sigalg"
)

// TestSignatureMiddleware_StrictMode_RejectsPeerIdentityMismatch checks that a
// verified signature whose keyId authority disagrees with the declared peer
// returns 403.
func TestSignatureMiddleware_StrictMode_RejectsPeerIdentityMismatch(t *testing.T) { //nolint:dupl // intentional: parallel signature middleware error tests share setup but assert different peer mismatch paths
	km := crypto.NewKeyManager("", "https://sender.example.com")
	if err := km.LoadOrGenerate(); err != nil {
		t.Fatal(err)
	}

	signer := crypto.NewRFC9421Signer(km)

	cfg := defaultSigTestConfig()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	pd := &mockPeerDiscovery{
		publicKeys: map[string]sigalg.ResolvedPublicKey{
			km.GetKeyID(): resolvedKeyFromManager(km),
		},
	}

	mw := newTestSignatureMiddleware(cfg, pd, "https://receiver.example.com", logger)

	peerResolver := func(_ *http.Request, _ []byte) (string, error) {
		return "attacker.example.com", nil
	}

	handler := mw.VerifyOCMRequestRequireSignatureAndPeer(peerResolver)(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Fatal("handler should not run on peer identity mismatch")
	}))

	body := []byte(`{"sender":"user@attacker.example.com"}`)
	req := httptest.NewRequest(http.MethodPost, "https://receiver.example.com/ocm/shares", bytes.NewReader(body))
	req.Host = "receiver.example.com"
	req.Header.Set("Content-Type", "application/json")

	if err := signer.SignRequest(req, body); err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 peer identity mismatch, got %d: %s", w.Code, w.Body.String())
	}
}

func TestSignatureMiddleware_StrictMode_RejectsPublicKeyLookupFailure(t *testing.T) {
	km := crypto.NewKeyManager("", "https://sender.example.com")
	if err := km.LoadOrGenerate(); err != nil {
		t.Fatal(err)
	}

	signer := crypto.NewRFC9421Signer(km)

	cfg := defaultSigTestConfig()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	pd := &mockPeerDiscovery{
		publicKeyErrors: map[string]error{
			km.GetKeyID(): fmt.Errorf("discovery unavailable"),
		},
	}

	mw := newTestSignatureMiddleware(cfg, pd, "https://receiver.example.com", logger)

	handler := mw.VerifyOCMRequestIfPresent()(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Fatal("handler should not run when public key lookup fails")
	}))

	body := []byte(`{"test":"data"}`)
	req := httptest.NewRequest(http.MethodPost, "https://receiver.example.com/ocm/shares", bytes.NewReader(body))
	req.Host = "receiver.example.com"
	req.Header.Set("Content-Type", "application/json")

	if err := signer.SignRequest(req, body); err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadGateway {
		t.Fatalf("expected 502 on public key lookup failure, got %d: %s", w.Code, w.Body.String())
	}

	if got := strings.TrimSpace(w.Body.String()); got != "signature key lookup failed" {
		t.Fatalf("body = %q, want signature key lookup failed", got)
	}
}
func TestSignatureMiddleware_StrictMode_RejectsKeyNotFound(t *testing.T) {
	km := crypto.NewKeyManager("", "https://sender.example.com")
	if err := km.LoadOrGenerate(); err != nil {
		t.Fatal(err)
	}

	signer := crypto.NewRFC9421Signer(km)

	cfg := defaultSigTestConfig()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	pd := &mockPeerDiscovery{
		publicKeyErrors: map[string]error{
			km.GetKeyID(): fmt.Errorf("jwks lookup: %w", jwks.ErrKeyNotFound),
		},
	}

	mw := newTestSignatureMiddleware(cfg, pd, "https://receiver.example.com", logger)

	handler := mw.VerifyOCMRequestIfPresent()(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Fatal("handler should not run when key is missing")
	}))

	body := []byte(`{"test":"data"}`)
	req := httptest.NewRequest(http.MethodPost, "https://receiver.example.com/ocm/shares", bytes.NewReader(body))
	req.Host = "receiver.example.com"
	req.Header.Set("Content-Type", "application/json")

	if err := signer.SignRequest(req, body); err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 on key not found, got %d: %s", w.Code, w.Body.String())
	}

	if got := strings.TrimSpace(w.Body.String()); got != "signature key not found" {
		t.Fatalf("body = %q, want signature key not found", got)
	}
}
func TestSignatureMiddleware_StrictMode_RejectsAlgorithmNotAllowed(t *testing.T) {
	km := crypto.NewKeyManager("", "https://sender.example.com")
	if err := km.LoadOrGenerate(); err != nil {
		t.Fatal(err)
	}

	signer := crypto.NewRFC9421Signer(km)

	cfg := &config.SignatureConfig{
		AllowedAlgorithms: []string{"rsa-v1_5-sha256"},
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	pd := &mockPeerDiscovery{
		publicKeys: map[string]sigalg.ResolvedPublicKey{
			km.GetKeyID(): resolvedKeyFromManager(km),
		},
	}

	mw := newTestSignatureMiddleware(cfg, pd, "https://receiver.example.com", logger)
	handler := mw.VerifyOCMRequestIfPresent()(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Fatal("handler should not run when algorithm is rejected")
	}))

	body := []byte(`{"test":"data"}`)
	req := httptest.NewRequest(http.MethodPost, "https://receiver.example.com/ocm/shares", bytes.NewReader(body))
	req.Host = "receiver.example.com"
	req.Header.Set("Content-Type", "application/json")

	if err := signer.SignRequest(req, body); err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", w.Code, w.Body.String())
	}

	if got := strings.TrimSpace(w.Body.String()); got != "signature algorithm rejected" {
		t.Fatalf("body = %q, want signature algorithm rejected", got)
	}
}
func TestSignatureMiddleware_StrictMode_RejectsInvalidSignatureBody(t *testing.T) {
	kmSender := crypto.NewKeyManager("", "https://sender.example.com")
	if err := kmSender.LoadOrGenerate(); err != nil {
		t.Fatal(err)
	}

	kmAttacker := crypto.NewKeyManager("", "https://attacker.example.com")
	if err := kmAttacker.LoadOrGenerate(); err != nil {
		t.Fatal(err)
	}

	signer := crypto.NewRFC9421Signer(kmSender)

	cfg := defaultSigTestConfig()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	pd := &mockPeerDiscovery{
		publicKeys: map[string]sigalg.ResolvedPublicKey{
			kmSender.GetKeyID(): resolvedKeyFromManager(kmAttacker),
		},
	}

	mw := newTestSignatureMiddleware(cfg, pd, "https://receiver.example.com", logger)
	handler := mw.VerifyOCMRequestIfPresent()(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Fatal("handler should not run on crypto fail")
	}))

	body := []byte(`{"test":"data"}`)
	req := httptest.NewRequest(http.MethodPost, "https://receiver.example.com/ocm/shares", bytes.NewReader(body))
	req.Host = "receiver.example.com"
	req.Header.Set("Content-Type", "application/json")

	if err := signer.SignRequest(req, body); err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", w.Code, w.Body.String())
	}

	if got := strings.TrimSpace(w.Body.String()); got != "signature verification failed" {
		t.Fatalf("body = %q, want signature verification failed", got)
	}
}
func TestSignatureMiddleware_DeclaredPeerResolverError_FailClosed(t *testing.T) {
	cfg := defaultSigTestConfig()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	pd := &mockPeerDiscovery{}
	mw := newTestSignatureMiddleware(cfg, pd, "https://receiver.example.com", logger)

	peerResolver := func(_ *http.Request, _ []byte) (string, error) {
		return "", fmt.Errorf("malformed sender field")
	}
	handler := mw.VerifyOCMRequestRequireSignatureAndPeer(peerResolver)(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Fatal("handler should not run on declared peer resolver error")
	}))

	req := httptest.NewRequest(http.MethodPost, "/ocm/shares", bytes.NewBufferString(`{"sender":"bad"}`))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 on declared peer resolver error, got %d: %s", w.Code, w.Body.String())
	}
}
func TestSignatureMiddleware_DeclaredPeerResolverEmpty_FailClosed(t *testing.T) {
	cfg := defaultSigTestConfig()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	pd := &mockPeerDiscovery{}
	mw := newTestSignatureMiddleware(cfg, pd, "https://receiver.example.com", logger)

	peerResolver := func(_ *http.Request, _ []byte) (string, error) {
		return "  ", nil
	}
	handler := mw.VerifyOCMRequestRequireSignatureAndPeer(peerResolver)(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Fatal("handler should not run on empty declared peer")
	}))

	req := httptest.NewRequest(http.MethodPost, "/ocm/shares", bytes.NewBufferString(`{}`))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 on empty declared peer, got %d: %s", w.Code, w.Body.String())
	}
}
func TestSignatureMiddleware_RequireDeclaredPeer_NilResolver(t *testing.T) {
	cfg := defaultSigTestConfig()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	pd := &mockPeerDiscovery{}
	mw := newTestSignatureMiddleware(cfg, pd, "https://receiver.example.com", logger)

	handler := mw.VerifyOCMRequestRequireSignatureAndPeer(nil)(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Fatal("handler should not run")
	}))

	req := httptest.NewRequest(http.MethodPost, "/ocm/shares", bytes.NewBufferString(`{}`))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 when requireDeclaredPeer has nil resolver, got %d", w.Code)
	}
}
func TestSignatureMiddleware_MismatchNormalizeError_FailClosed(t *testing.T) { //nolint:dupl // intentional: parallel signature middleware error tests share setup but assert different peer mismatch paths
	km := crypto.NewKeyManager("", "https://sender.example.com")
	if err := km.LoadOrGenerate(); err != nil {
		t.Fatal(err)
	}

	signer := crypto.NewRFC9421Signer(km)

	cfg := defaultSigTestConfig()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	pd := &mockPeerDiscovery{
		publicKeys: map[string]sigalg.ResolvedPublicKey{
			km.GetKeyID(): resolvedKeyFromManager(km),
		},
	}
	mw := newTestSignatureMiddleware(cfg, pd, "https://receiver.example.com", logger)

	// Declared peer with a path fails authority normalization.
	peerResolver := func(_ *http.Request, _ []byte) (string, error) {
		return "sender.example.com/evil", nil
	}
	handler := mw.VerifyOCMRequestRequireSignatureAndPeer(peerResolver)(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Fatal("handler should not run on mismatch normalize error")
	}))

	body := []byte(`{"sender":"user@sender.example.com"}`)
	req := httptest.NewRequest(http.MethodPost, "https://receiver.example.com/ocm/shares", bytes.NewReader(body))
	req.Host = "receiver.example.com"
	req.Header.Set("Content-Type", "application/json")

	if err := signer.SignRequest(req, body); err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 on declared-peer normalize error, got %d: %s", w.Code, w.Body.String())
	}
}
