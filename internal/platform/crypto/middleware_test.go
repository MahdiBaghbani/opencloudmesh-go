package crypto_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto"
)

func TestSignatureMiddleware_OffMode(t *testing.T) {
	cfg := &config.SignatureConfig{InboundMode: "off"}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	pd := &mockPeerDiscovery{}

	mw := crypto.NewSignatureMiddleware(runtimePolicyFromSignature(cfg), nil, pd, "https://receiver.example.com", logger)

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

func TestSignatureMiddleware_OffMode_RequireSignaturePasses(t *testing.T) {
	cfg := &config.SignatureConfig{InboundMode: "off"}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	pd := &mockPeerDiscovery{}

	mw := crypto.NewSignatureMiddleware(runtimePolicyFromSignature(cfg), nil, pd, "https://receiver.example.com", logger)

	handler := mw.VerifyOCMRequestRequireSignature(nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("POST", "/ocm/notifications", bytes.NewBufferString(`{"providerId":"abc"}`))
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("off mode should skip signature enforcement, got status %d", w.Code)
	}
}

func TestSignatureMiddleware_StrictMode_RejectsUnsigned(t *testing.T) {
	cfg := &config.SignatureConfig{InboundMode: "strict"}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	pd := &mockPeerDiscovery{}

	mw := crypto.NewSignatureMiddleware(runtimePolicyFromSignature(cfg), nil, pd, "https://receiver.example.com", logger)

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

func TestSignatureMiddleware_LenientMode_RequireSignatureRejectsUnsigned(t *testing.T) {
	cfg := &config.SignatureConfig{InboundMode: "lenient"}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	pd := &mockPeerDiscovery{}

	mw := crypto.NewSignatureMiddleware(runtimePolicyFromSignature(cfg), nil, pd, "https://receiver.example.com", logger)

	handler := mw.VerifyOCMRequestRequireSignature(nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("POST", "/ocm/notifications", bytes.NewBufferString(`{"providerId":"abc"}`))
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("lenient require-signature mode should reject unsigned requests, got status %d", w.Code)
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

	mw := crypto.NewSignatureMiddleware(runtimePolicyFromSignature(cfg), nil, pd, "https://receiver.example.com", logger)

	handler := mw.VerifyOCMRequest(nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check peer identity was set
		pi := crypto.GetPeerIdentity(r.Context())
		if pi == nil || !pi.Authenticated {
			t.Error("expected authenticated peer identity")
		}
		if pi.Authority == "" {
			t.Error("expected non-empty Authority")
		}
		if pi.AuthorityForCompare == "" {
			t.Error("expected non-empty AuthorityForCompare")
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

	mw := crypto.NewSignatureMiddleware(runtimePolicyFromSignature(cfg), nil, pd, "https://receiver.example.com", logger)

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

	mw := crypto.NewSignatureMiddleware(runtimePolicyFromSignature(cfg), nil, pd, "https://receiver.example.com", logger)

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

	mw := crypto.NewSignatureMiddleware(runtimePolicyFromSignature(cfg), nil, pd, "https://receiver.example.com", logger)

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

// TestSignatureMiddleware_DefaultPortEquivalence proves scheme-aware comparison:
// a keyId with explicit :443 matches a declared peer without :443 when scheme is https.
func TestSignatureMiddleware_DefaultPortEquivalence(t *testing.T) {
	// Use explicit :443 in the sender's external origin so the keyId includes it.
	km := crypto.NewKeyManager("", "https://sender.example.com:443")
	km.LoadOrGenerate()
	signer := crypto.NewRFC9421Signer(km)

	cfg := &config.SignatureConfig{InboundMode: "strict", AllowMismatch: false}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	pd := &mockPeerDiscovery{
		publicKeysPEM: map[string]string{
			km.GetKeyID(): km.GetPublicKeyPEM(),
		},
	}

	mw := crypto.NewSignatureMiddleware(runtimePolicyFromSignature(cfg), nil, pd, "https://receiver.example.com", logger)

	// Peer resolver returns "sender.example.com" (without :443).
	// The keyId will contain :443 explicitly.
	// Scheme-aware comparison must treat them as equivalent.
	peerResolver := func(r *http.Request, body []byte) (string, error) {
		return "sender.example.com", nil
	}

	handler := mw.VerifyOCMRequest(peerResolver)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pi := crypto.GetPeerIdentity(r.Context())
		if pi == nil || !pi.Authenticated {
			t.Error("expected authenticated peer identity")
		}
		// AuthorityForCompare should have :443 stripped (default for https)
		if pi.AuthorityForCompare != "sender.example.com" {
			t.Errorf("expected AuthorityForCompare 'sender.example.com', got %q", pi.AuthorityForCompare)
		}
		w.WriteHeader(http.StatusOK)
	}))

	body := []byte(`{"sender":"user@sender.example.com"}`)
	req := httptest.NewRequest("POST", "https://receiver.example.com/ocm/shares", bytes.NewReader(body))
	req.Host = "receiver.example.com"
	req.Header.Set("Content-Type", "application/json")

	if err := signer.SignRequest(req, body); err != nil {
		t.Fatalf("failed to sign request: %v", err)
	}

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("default port equivalence: expected 200, got %d, body: %s", w.Code, w.Body.String())
	}
}

// TestSignatureMiddleware_EmptyPublicOrigin_NoHTTPSDefault proves that an empty
// publicOrigin leaves localScheme empty (not forced to "https"). With an empty
// scheme, declared-peer normalization preserves the explicit :443 port, so a
// declared peer of "sender.example.com:443" is not collapsed to the bare
// "sender.example.com" authority. If the scheme were forced to "https", :443
// would be stripped, changing the unverified peer's AuthorityForCompare.
func TestSignatureMiddleware_EmptyPublicOrigin_NoHTTPSDefault(t *testing.T) {
	cfg := &config.SignatureConfig{InboundMode: "lenient"}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	// Non-capable peer so the unsigned request takes the unverified-peer path.
	pd := &mockPeerDiscovery{
		signingCapable: map[string]bool{"sender.example.com:443": false},
	}

	mw := crypto.NewSignatureMiddleware(runtimePolicyFromSignature(cfg), nil, pd, "", logger)

	peerResolver := func(r *http.Request, body []byte) (string, error) {
		return "sender.example.com:443", nil
	}

	handler := mw.VerifyOCMRequest(peerResolver)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pi := crypto.GetPeerIdentity(r.Context())
		if pi == nil {
			t.Fatal("expected peer identity")
		}
		// Empty scheme must preserve :443 (not strip it as https would).
		if pi.AuthorityForCompare != "sender.example.com:443" {
			t.Errorf("expected AuthorityForCompare 'sender.example.com:443' (empty scheme keeps :443), got %q", pi.AuthorityForCompare)
		}
		w.WriteHeader(http.StatusOK)
	}))

	body := []byte(`{"sender":"user@sender.example.com"}`)
	req := httptest.NewRequest("POST", "/ocm/shares", bytes.NewReader(body))
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d, body: %s", w.Code, w.Body.String())
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
		Authority:           "example.com",
		AuthorityForCompare: "example.com",
		Authenticated:       true,
		KeyID:               "https://example.com#key1",
	})
	pi = crypto.GetPeerIdentity(ctx)
	if pi == nil {
		t.Fatal("expected peer identity")
	}
	if pi.Authority != "example.com" {
		t.Errorf("expected authority 'example.com', got %q", pi.Authority)
	}
	if pi.AuthorityForCompare != "example.com" {
		t.Errorf("expected authority_for_compare 'example.com', got %q", pi.AuthorityForCompare)
	}
	if !pi.Authenticated {
		t.Error("expected authenticated=true")
	}
}

// TestSignatureMiddleware_StrictMode_RejectsMalformedSignatureMaterial checks
// that the strict middleware returns 401 for incomplete or malformed signature
// material rather than passing the request through.
func TestSignatureMiddleware_StrictMode_RejectsMalformedSignatureMaterial(t *testing.T) {
	cfg := &config.SignatureConfig{InboundMode: "strict"}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	pd := &mockPeerDiscovery{
		publicKeysPEM: map[string]string{},
	}

	mw := crypto.NewSignatureMiddleware(
		runtimePolicyFromSignature(cfg),
		nil,
		pd,
		"https://receiver.example.com",
		logger,
	)

	// A syntactically valid but wrong 64-byte signature in RFC 9421 format.
	zeroSig := base64.StdEncoding.EncodeToString(make([]byte, 64))

	tests := []struct {
		name           string
		signatureInput string
		signature      string
		wantStatus     int
	}{
		{
			name:           "signature-input only, no signature header",
			signatureInput: `sig1=("@method");created=1234567890;keyid="https://example.com#key1";alg="ed25519"`,
			signature:      "",
			wantStatus:     http.StatusUnauthorized,
		},
		{
			name:           "signature header only, no signature-input",
			signatureInput: "",
			signature:      fmt.Sprintf("sig1=:%s:", zeroSig),
			wantStatus:     http.StatusUnauthorized,
		},
		{
			name:           "empty keyid in signature params",
			signatureInput: `sig1=("@method");created=1234567890;keyid="";alg="ed25519"`,
			signature:      fmt.Sprintf("sig1=:%s:", zeroSig),
			wantStatus:     http.StatusUnauthorized,
		},
		{
			name:           "invalid base64 in signature value",
			signatureInput: `sig1=("@method");created=1234567890;keyid="https://example.com#key1";alg="ed25519"`,
			signature:      "sig1=:not!valid!base64!!!:",
			wantStatus:     http.StatusUnauthorized,
		},
		{
			name:           "malformed keyid missing closing quote",
			signatureInput: `sig1=("@method");created=1234567890;keyid="https://example.com#key1`,
			signature:      fmt.Sprintf("sig1=:%s:", zeroSig),
			wantStatus:     http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := mw.VerifyOCMRequest(nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))

			req := httptest.NewRequest("POST", "/ocm/shares", bytes.NewBufferString(`{"test":"data"}`))
			if tt.signatureInput != "" {
				req.Header.Set("Signature-Input", tt.signatureInput)
			}
			if tt.signature != "" {
				req.Header.Set("Signature", tt.signature)
			}

			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			if w.Code != tt.wantStatus {
				t.Errorf("expected status %d, got %d (body: %s)",
					tt.wantStatus, w.Code, w.Body.String())
			}
		})
	}
}
