package crypto_test

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/crypto"
)

// mockPeerDiscovery implements crypto.PeerDiscovery for testing.
type mockPeerDiscovery struct {
	signingCapable map[string]bool
	publicKeysPEM  map[string]string // keyID -> PEM string
}

func (m *mockPeerDiscovery) IsSigningCapable(ctx context.Context, host string) (bool, error) {
	return m.signingCapable[host], nil
}

func (m *mockPeerDiscovery) GetPublicKey(ctx context.Context, keyID string) (string, error) {
	if pem, ok := m.publicKeysPEM[keyID]; ok {
		return pem, nil
	}
	return "", nil
}

func TestSignatureMiddleware_OffMode(t *testing.T) {
	cfg := &config.SignatureConfig{InboundMode: "off"}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	pd := &mockPeerDiscovery{}

	mw := crypto.NewSignatureMiddleware(cfg, pd, logger)

	handler := mw.VerifyOCMRequest(nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("POST", "/ocm/shares", bytes.NewBufferString(`{"test":"data"}`))
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("off mode should pass all requests, got status %d", w.Code)
	}
}

func TestSignatureMiddleware_StrictMode_RejectsUnsigned(t *testing.T) {
	cfg := &config.SignatureConfig{InboundMode: "strict"}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	pd := &mockPeerDiscovery{}

	mw := crypto.NewSignatureMiddleware(cfg, pd, logger)

	handler := mw.VerifyOCMRequest(nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("POST", "/ocm/shares", bytes.NewBufferString(`{"test":"data"}`))
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("strict mode should reject unsigned requests, got status %d", w.Code)
	}
}

func TestSignatureMiddleware_StrictMode_AcceptsSigned(t *testing.T) {
	// Create a key manager and signer
	km := crypto.NewKeyManager("", "https://sender.example.com")
	km.LoadOrGenerate()
	signer := crypto.NewRFC9421Signer(km)

	cfg := &config.SignatureConfig{InboundMode: "strict"}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	pd := &mockPeerDiscovery{
		publicKeysPEM: map[string]string{
			km.GetKeyID(): km.GetPublicKeyPEM(),
		},
	}

	mw := crypto.NewSignatureMiddleware(cfg, pd, logger)

	handler := mw.VerifyOCMRequest(nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check peer identity was set
		pi := crypto.GetPeerIdentity(r.Context())
		if pi == nil || !pi.Authenticated {
			t.Error("expected authenticated peer identity")
		}
		w.WriteHeader(http.StatusOK)
	}))

	body := []byte(`{"test":"data"}`)
	req := httptest.NewRequest("POST", "https://receiver.example.com/ocm/shares", bytes.NewReader(body))
	req.Host = "receiver.example.com"
	req.Header.Set("Content-Type", "application/json")

	// Sign the request
	if err := signer.SignRequest(req, body); err != nil {
		t.Fatalf("failed to sign request: %v", err)
	}

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("strict mode should accept signed requests, got status %d, body: %s", w.Code, w.Body.String())
	}
}

func TestSignatureMiddleware_LenientMode_AcceptsUnsignedFromNonCapable(t *testing.T) {
	cfg := &config.SignatureConfig{InboundMode: "lenient"}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	// Peer is NOT signing-capable
	pd := &mockPeerDiscovery{
		signingCapable: map[string]bool{"sender.example.com": false},
	}

	mw := crypto.NewSignatureMiddleware(cfg, pd, logger)

	// Peer resolver returns the sender host from request body
	peerResolver := func(r *http.Request, body []byte) (string, error) {
		return "sender.example.com", nil
	}

	handler := mw.VerifyOCMRequest(peerResolver)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	body := []byte(`{"sender":"user@sender.example.com"}`)
	req := httptest.NewRequest("POST", "/ocm/shares", bytes.NewReader(body))
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("lenient mode should accept unsigned from non-capable peer, got status %d", w.Code)
	}
}

func TestSignatureMiddleware_LenientMode_RejectsUnsignedFromCapable(t *testing.T) {
	cfg := &config.SignatureConfig{InboundMode: "lenient"}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	// Peer IS signing-capable
	pd := &mockPeerDiscovery{
		signingCapable: map[string]bool{"sender.example.com": true},
	}

	mw := crypto.NewSignatureMiddleware(cfg, pd, logger)

	// Peer resolver returns the sender host
	peerResolver := func(r *http.Request, body []byte) (string, error) {
		return "sender.example.com", nil
	}

	handler := mw.VerifyOCMRequest(peerResolver)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	body := []byte(`{"sender":"user@sender.example.com"}`)
	req := httptest.NewRequest("POST", "/ocm/shares", bytes.NewReader(body))
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("lenient mode should reject unsigned from signing-capable peer, got status %d", w.Code)
	}
}

func TestSignatureMiddleware_RejectsInvalidSignature(t *testing.T) {
	// Create two different key managers
	kmSender := crypto.NewKeyManager("", "https://sender.example.com")
	kmSender.LoadOrGenerate()

	kmAttacker := crypto.NewKeyManager("", "https://attacker.example.com")
	kmAttacker.LoadOrGenerate()

	signer := crypto.NewRFC9421Signer(kmSender)

	cfg := &config.SignatureConfig{InboundMode: "strict"}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	// Return the wrong public key
	pd := &mockPeerDiscovery{
		publicKeysPEM: map[string]string{
			kmSender.GetKeyID(): kmAttacker.GetPublicKeyPEM(), // Wrong key!
		},
	}

	mw := crypto.NewSignatureMiddleware(cfg, pd, logger)

	handler := mw.VerifyOCMRequest(nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	body := []byte(`{"test":"data"}`)
	req := httptest.NewRequest("POST", "https://receiver.example.com/ocm/shares", bytes.NewReader(body))
	req.Host = "receiver.example.com"
	req.Header.Set("Content-Type", "application/json")
	signer.SignRequest(req, body)

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("should reject invalid signature, got status %d", w.Code)
	}
}

func TestGetPeerIdentity(t *testing.T) {
	// Without peer identity
	ctx := context.Background()
	pi := crypto.GetPeerIdentity(ctx)
	if pi != nil {
		t.Error("expected nil peer identity for empty context")
	}

	// With peer identity
	ctx = context.WithValue(ctx, crypto.PeerIdentityKey, &crypto.PeerIdentity{
		Host:          "example.com",
		Authenticated: true,
		KeyID:         "https://example.com#key1",
	})
	pi = crypto.GetPeerIdentity(ctx)
	if pi == nil {
		t.Fatal("expected peer identity")
	}
	if pi.Host != "example.com" {
		t.Errorf("expected host 'example.com', got %q", pi.Host)
	}
	if !pi.Authenticated {
		t.Error("expected authenticated=true")
	}
}
