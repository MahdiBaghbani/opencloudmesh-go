package signature_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery"
	sig "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/inbound/signature"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/peercompat"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/peerorigin"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache/loader"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/jwks"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/sigalg"
	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
)

func defaultSigTestConfig() *config.SignatureConfig {
	cfg := config.DefaultSignatureConfig()
	return &cfg
}

func TestSignatureMiddleware_StrictMode_RejectsUnsigned(t *testing.T) {
	cfg := defaultSigTestConfig()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	pd := &mockPeerDiscovery{}

	mw := newTestSignatureMiddleware(cfg, nil, pd, "https://receiver.example.com", logger)

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

	cfg := defaultSigTestConfig()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	pd := &mockPeerDiscovery{
		publicKeys: map[string]sigalg.ResolvedPublicKey{
			km.GetKeyID(): resolvedKeyFromManager(km),
		},
	}

	mw := newTestSignatureMiddleware(cfg, nil, pd, "https://receiver.example.com", logger)

	handler := mw.VerifyOCMRequest(nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check peer identity was set
		pi := sig.GetPeerIdentity(r.Context())
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

func TestSignatureMiddleware_RejectsInvalidSignature(t *testing.T) {
	// Create two different key managers
	kmSender := crypto.NewKeyManager("", "https://sender.example.com")
	kmSender.LoadOrGenerate()

	kmAttacker := crypto.NewKeyManager("", "https://attacker.example.com")
	kmAttacker.LoadOrGenerate()

	signer := crypto.NewRFC9421Signer(kmSender)

	cfg := defaultSigTestConfig()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	// Return the wrong public key
	pd := &mockPeerDiscovery{
		publicKeys: map[string]sigalg.ResolvedPublicKey{
			kmSender.GetKeyID(): resolvedKeyFromManager(kmAttacker), // Wrong key!
		},
	}

	mw := newTestSignatureMiddleware(cfg, nil, pd, "https://receiver.example.com", logger)

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

	cfg := defaultSigTestConfig()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	pd := &mockPeerDiscovery{
		publicKeys: map[string]sigalg.ResolvedPublicKey{
			km.GetKeyID(): resolvedKeyFromManager(km),
		},
	}

	mw := newTestSignatureMiddleware(cfg, nil, pd, "https://receiver.example.com", logger)

	// Peer resolver returns "sender.example.com" (without :443).
	// The keyId will contain :443 explicitly.
	// Scheme-aware comparison must treat them as equivalent.
	peerResolver := func(r *http.Request, body []byte) (string, error) {
		return "sender.example.com", nil
	}

	handler := mw.VerifyOCMRequest(peerResolver)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pi := sig.GetPeerIdentity(r.Context())
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
	cfg := defaultSigTestConfig()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	pd := &mockPeerDiscovery{
		signingCapable: map[string]bool{"sender.example.com:443": true},
	}
	contract, err := peercompat.NewCompiledContract(
		map[string]*peercompat.Profile{
			"compat": {
				Name:                 "compat",
				AllowUnsignedInbound: true,
			},
		},
		[]peercompat.ProfileMapping{
			{Pattern: "sender.example.com", Profile: "compat"},
		},
	)
	if err != nil {
		t.Fatalf("NewCompiledContract: %v", err)
	}

	mw := newTestSignatureMiddleware(cfg, contract, pd, "", logger)

	peerResolver := func(r *http.Request, body []byte) (string, error) {
		return "sender.example.com:443", nil
	}

	handler := mw.VerifyOCMRequest(peerResolver)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pi := sig.GetPeerIdentity(r.Context())
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
	pi := sig.GetPeerIdentity(ctx)
	if pi != nil {
		t.Error("expected nil peer identity for empty context")
	}

	// With peer identity
	ctx = context.WithValue(ctx, sig.PeerIdentityKey, &sig.PeerIdentity{
		Authority:           "example.com",
		AuthorityForCompare: "example.com",
		Authenticated:       true,
		KeyID:               "https://example.com#key1",
	})
	pi = sig.GetPeerIdentity(ctx)
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

// TestSignatureMiddleware_StrictMode_RejectsPeerIdentityMismatch checks that a
// verified signature whose keyId authority disagrees with the declared peer
// returns 403 when peer-profile mismatch allowance is not granted.
func TestSignatureMiddleware_StrictMode_RejectsPeerIdentityMismatch(t *testing.T) {
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

	mw := newTestSignatureMiddleware(cfg, nil, pd, "https://receiver.example.com", logger)

	peerResolver := func(r *http.Request, body []byte) (string, error) {
		return "attacker.example.com", nil
	}

	handler := mw.VerifyOCMRequest(peerResolver)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not run on peer identity mismatch")
	}))

	body := []byte(`{"sender":"user@attacker.example.com"}`)
	req := httptest.NewRequest("POST", "https://receiver.example.com/ocm/shares", bytes.NewReader(body))
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

// TestSignatureMiddleware_StrictMode_RejectsMalformedSignatureMaterial checks
// that the strict middleware returns 401 for incomplete or malformed signature
// material rather than passing the request through.
func TestSignatureMiddleware_StrictMode_RejectsMalformedSignatureMaterial(t *testing.T) {
	cfg := defaultSigTestConfig()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	pd := &mockPeerDiscovery{
		publicKeys: map[string]sigalg.ResolvedPublicKey{},
	}

	mw := newTestSignatureMiddleware(
		cfg,
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
			signatureInput: `ocm=("@method");created=1234567890;keyid="example.com#key1";alg="ed25519"`,
			signature:      "",
			wantStatus:     http.StatusUnauthorized,
		},
		{
			name:           "signature header only, no signature-input",
			signatureInput: "",
			signature:      fmt.Sprintf("ocm=:%s:", zeroSig),
			wantStatus:     http.StatusUnauthorized,
		},
		{
			name:           "empty keyid in signature params",
			signatureInput: `ocm=("@method");created=1234567890;keyid="";alg="ed25519"`,
			signature:      fmt.Sprintf("ocm=:%s:", zeroSig),
			wantStatus:     http.StatusUnauthorized,
		},
		{
			name:           "invalid base64 in signature value",
			signatureInput: `ocm=("@method");created=1234567890;keyid="example.com#key1";alg="ed25519"`,
			signature:      "ocm=:not!valid!base64!!!:",
			wantStatus:     http.StatusUnauthorized,
		},
		{
			name:           "malformed keyid missing closing quote",
			signatureInput: `ocm=("@method");created=1234567890;keyid="example.com#key1`,
			signature:      fmt.Sprintf("ocm=:%s:", zeroSig),
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

func TestSignatureMiddleware_UsesSignatureConfigLabel(t *testing.T) {
	km := crypto.NewKeyManager("", "https://sender.example.com")
	if err := km.LoadOrGenerate(); err != nil {
		t.Fatal(err)
	}

	sigCfg := &config.SignatureConfig{
		Label: "peerlabel",
	}
	signer := crypto.NewRFC9421SignerWithOptions(
		km,
		crypto.RFC9421OptionsFromConfig(*sigCfg),
	)

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	pd := &mockPeerDiscovery{
		publicKeys: map[string]sigalg.ResolvedPublicKey{
			km.GetKeyID(): resolvedKeyFromManager(km),
		},
	}
	mw := newTestSignatureMiddleware(sigCfg, nil, pd, "https://receiver.example.com", logger)

	handler := mw.VerifyOCMRequest(nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	body := []byte(`{"test":"data"}`)
	req := httptest.NewRequest("POST", "/ocm/shares", bytes.NewReader(body))
	if err := signer.SignRequest(req, body); err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected signed request with configured label to pass, got %d: %s", w.Code, w.Body.String())
	}

	defaultSigner := crypto.NewRFC9421Signer(km)
	defaultReq := httptest.NewRequest("POST", "/ocm/shares", bytes.NewReader(body))
	if err := defaultSigner.SignRequest(defaultReq, body); err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, defaultReq)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected default ocm label to fail against peerlabel verifier, got %d", w.Code)
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

	mw := newTestSignatureMiddleware(cfg, nil, pd, "https://receiver.example.com", logger)

	handler := mw.VerifyOCMRequest(nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not run when public key lookup fails")
	}))

	body := []byte(`{"test":"data"}`)
	req := httptest.NewRequest("POST", "https://receiver.example.com/ocm/shares", bytes.NewReader(body))
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

	mw := newTestSignatureMiddleware(cfg, nil, pd, "https://receiver.example.com", logger)

	handler := mw.VerifyOCMRequest(nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not run when key is missing")
	}))

	body := []byte(`{"test":"data"}`)
	req := httptest.NewRequest("POST", "https://receiver.example.com/ocm/shares", bytes.NewReader(body))
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

	mw := newTestSignatureMiddleware(cfg, nil, pd, "https://receiver.example.com", logger)
	handler := mw.VerifyOCMRequest(nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not run when algorithm is rejected")
	}))

	body := []byte(`{"test":"data"}`)
	req := httptest.NewRequest("POST", "https://receiver.example.com/ocm/shares", bytes.NewReader(body))
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

	mw := newTestSignatureMiddleware(cfg, nil, pd, "https://receiver.example.com", logger)
	handler := mw.VerifyOCMRequest(nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not run on crypto fail")
	}))

	body := []byte(`{"test":"data"}`)
	req := httptest.NewRequest("POST", "https://receiver.example.com/ocm/shares", bytes.NewReader(body))
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

func TestSignatureMiddleware_StrictMode_AcceptsOmitAlgECDSAP256(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyID := "sender.example.com#ec1"
	cfg := defaultSigTestConfig()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	pd := &mockPeerDiscovery{
		publicKeys: map[string]sigalg.ResolvedPublicKey{
			keyID: {
				KeyID: keyID, Algorithm: sigalg.ECDSAP256SHA256, PublicKey: &priv.PublicKey,
				JWKKty: "EC", JWKCrv: "P-256", JWKAlg: "ES256",
			},
		},
	}
	mw := newTestSignatureMiddleware(cfg, nil, pd, "https://receiver.example.com", logger)
	handler := mw.VerifyOCMRequest(nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	body := []byte(`{"test":"data"}`)
	req := httptest.NewRequest("POST", "https://receiver.example.com/ocm/shares", bytes.NewReader(body))
	req.Host = "receiver.example.com"
	req.Header.Set("Content-Type", "application/json")
	now := time.Now().UTC()
	req.Header.Set("Date", now.Format("Mon, 02 Jan 2006 15:04:05 GMT"))
	digest := base64.StdEncoding.EncodeToString(sigalg.SumSHA256(body))
	req.Header.Set("Content-Digest", "sha-256=:"+digest+":")
	req.Header.Set("Content-Length", fmt.Sprintf("%d", len(body)))

	created := now.Unix()
	components := []string{"@method", "@target-uri", "content-digest", "content-length", "date"}
	sigInput := fmt.Sprintf(
		`ocm=("@method" "@target-uri" "content-digest" "content-length" "date");created=%d;keyid=%q`,
		created, keyID,
	)
	paramsRaw := strings.TrimPrefix(sigInput, "ocm=")
	sigBase, err := crypto.BuildSignatureBase(req, components)
	if err != nil {
		t.Fatal(err)
	}
	fullBase := sigBase + `"@signature-params": ` + paramsRaw
	sum := sha256.Sum256([]byte(fullBase))
	r, s, err := ecdsa.Sign(rand.Reader, priv, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	raw, err := sigalg.EncodeECDSARawRS(r, s, 32)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Signature-Input", sigInput)
	req.Header.Set("Signature", fmt.Sprintf("ocm=:%s:", base64.StdEncoding.EncodeToString(raw)))

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for omit-alg ECDSA, got %d: %s", w.Code, w.Body.String())
	}
}

func TestSignatureMiddleware_StrictMode_RejectsBadContentDigestAfterVerifiedSignature(t *testing.T) {
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

	mw := newTestSignatureMiddleware(cfg, nil, pd, "https://receiver.example.com", logger)

	handler := mw.VerifyOCMRequest(nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not run when content digest verification fails")
	}))

	signedBody := []byte(`{"test":"data"}`)
	req := httptest.NewRequest("POST", "https://receiver.example.com/ocm/shares", bytes.NewReader(signedBody))
	req.Host = "receiver.example.com"
	req.Header.Set("Content-Type", "application/json")
	if err := signer.SignRequest(req, signedBody); err != nil {
		t.Fatal(err)
	}

	tamperedBody := []byte(`{"test":"tampered"}`)
	req.Body = io.NopCloser(bytes.NewReader(tamperedBody))
	req.ContentLength = int64(len(tamperedBody))

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 on content digest mismatch, got %d: %s", w.Code, w.Body.String())
	}
}

func TestSignatureMiddleware_DeclaredPeerResolverError_FailClosed(t *testing.T) {
	cfg := defaultSigTestConfig()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	pd := &mockPeerDiscovery{}
	mw := newTestSignatureMiddleware(cfg, nil, pd, "https://receiver.example.com", logger)

	peerResolver := func(r *http.Request, body []byte) (string, error) {
		return "", fmt.Errorf("malformed sender field")
	}
	handler := mw.VerifyOCMRequest(peerResolver)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not run on declared peer resolver error")
	}))

	req := httptest.NewRequest("POST", "/ocm/shares", bytes.NewBufferString(`{"sender":"bad"}`))
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
	mw := newTestSignatureMiddleware(cfg, nil, pd, "https://receiver.example.com", logger)

	peerResolver := func(r *http.Request, body []byte) (string, error) {
		return "  ", nil
	}
	handler := mw.VerifyOCMRequest(peerResolver)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not run on empty declared peer")
	}))

	req := httptest.NewRequest("POST", "/ocm/shares", bytes.NewBufferString(`{}`))
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
	mw := newTestSignatureMiddleware(cfg, nil, pd, "https://receiver.example.com", logger)

	handler := mw.VerifyOCMRequestRequireSignatureAndPeer(nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not run")
	}))

	req := httptest.NewRequest("POST", "/ocm/shares", bytes.NewBufferString(`{}`))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 when requireDeclaredPeer has nil resolver, got %d", w.Code)
	}
}

func TestSignatureMiddleware_MismatchNormalizeError_FailClosed(t *testing.T) {
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
	mw := newTestSignatureMiddleware(cfg, nil, pd, "https://receiver.example.com", logger)

	// Declared peer with a path fails authority normalization.
	peerResolver := func(r *http.Request, body []byte) (string, error) {
		return "sender.example.com/evil", nil
	}
	handler := mw.VerifyOCMRequest(peerResolver)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not run on mismatch normalize error")
	}))

	body := []byte(`{"sender":"user@sender.example.com"}`)
	req := httptest.NewRequest("POST", "https://receiver.example.com/ocm/shares", bytes.NewReader(body))
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

func TestSignatureMiddleware_VerifiedPathfulKeyID_Returns401(t *testing.T) {
	km := crypto.NewKeyManager("", "https://sender.example.com")
	if err := km.LoadOrGenerate(); err != nil {
		t.Fatal(err)
	}
	pathfulKid := "sender.example.com/ocm#key1"
	cfg := defaultSigTestConfig()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	pd := &mockPeerDiscovery{
		publicKeys: map[string]sigalg.ResolvedPublicKey{
			pathfulKid: resolvedKeyFromManager(km),
		},
	}
	mw := newTestSignatureMiddleware(cfg, nil, pd, "https://receiver.example.com", logger)

	handler := mw.VerifyOCMRequest(nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not run on pathful keyId after verify")
	}))

	body := []byte(`{"test":"data"}`)
	req := httptest.NewRequest("POST", "https://receiver.example.com/ocm/shares", bytes.NewReader(body))
	req.Host = "receiver.example.com"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Date", time.Now().UTC().Format(http.TimeFormat))
	digest := "sha-256=:" + base64.StdEncoding.EncodeToString(sigalg.SumSHA256(body)) + ":"
	req.Header.Set("Content-Digest", digest)
	req.Header.Set("Content-Length", fmt.Sprintf("%d", len(body)))

	created := time.Now().Unix()
	components := []string{"@method", "@target-uri", "content-digest", "content-length", "date"}
	sigInput := fmt.Sprintf(
		`ocm=("@method" "@target-uri" "content-digest" "content-length" "date");created=%d;keyid=%q;alg="ed25519"`,
		created, pathfulKid,
	)
	req.Header.Set("Signature-Input", sigInput)
	paramsRaw := strings.TrimPrefix(sigInput, "ocm=")
	base, err := crypto.BuildSignatureBase(req, components)
	if err != nil {
		t.Fatal(err)
	}
	fullBase := base + fmt.Sprintf("\"@signature-params\": %s", paramsRaw)
	sigBytes, err := km.Sign([]byte(fullBase))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Signature", fmt.Sprintf("ocm=:%s:", base64.StdEncoding.EncodeToString(sigBytes)))

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for pathful keyId after verify, got %d: %s", w.Code, w.Body.String())
	}
}

func TestSignatureMiddleware_VerifiedUnnormalizableKeyID_Returns401(t *testing.T) {
	// keyId "[]#key1" is rejected during authority normalization.
	km := crypto.NewKeyManager("", "https://sender.example.com")
	if err := km.LoadOrGenerate(); err != nil {
		t.Fatal(err)
	}
	badKid := "[]#key1"
	cfg := defaultSigTestConfig()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	pd := &mockPeerDiscovery{
		publicKeys: map[string]sigalg.ResolvedPublicKey{
			badKid: resolvedKeyFromManager(km),
		},
	}
	mw := newTestSignatureMiddleware(cfg, nil, pd, "https://receiver.example.com", logger)

	handler := mw.VerifyOCMRequest(nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not run when keyId authority cannot be normalized")
	}))

	body := []byte(`{"test":"data"}`)
	req := httptest.NewRequest("POST", "https://receiver.example.com/ocm/shares", bytes.NewReader(body))
	req.Host = "receiver.example.com"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Date", time.Now().UTC().Format(http.TimeFormat))
	digest := "sha-256=:" + base64.StdEncoding.EncodeToString(sigalg.SumSHA256(body)) + ":"
	req.Header.Set("Content-Digest", digest)
	req.Header.Set("Content-Length", fmt.Sprintf("%d", len(body)))

	created := time.Now().Unix()
	components := []string{"@method", "@target-uri", "content-digest", "content-length", "date"}
	sigInput := fmt.Sprintf(
		`ocm=("@method" "@target-uri" "content-digest" "content-length" "date");created=%d;keyid=%q;alg="ed25519"`,
		created, badKid,
	)
	req.Header.Set("Signature-Input", sigInput)
	paramsRaw := strings.TrimPrefix(sigInput, "ocm=")
	base, err := crypto.BuildSignatureBase(req, components)
	if err != nil {
		t.Fatal(err)
	}
	fullBase := base + fmt.Sprintf("\"@signature-params\": %s", paramsRaw)
	sigBytes, err := km.Sign([]byte(fullBase))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Signature", fmt.Sprintf("ocm=:%s:", base64.StdEncoding.EncodeToString(sigBytes)))

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 when authorityForCompareFromKid fails, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "invalid signature keyId") {
		t.Fatalf("body = %q, want invalid signature keyId", w.Body.String())
	}
}

// ECDSA P-256 with Signature-Input alg omitted, resolved via live JWKS.
func TestSignatureMiddleware_StrictMode_OmitAlgECDSAP256_JWKSPeerChain(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	x := base64.RawURLEncoding.EncodeToString(padCoordMiddleware(priv.X.Bytes(), 32))
	y := base64.RawURLEncoding.EncodeToString(padCoordMiddleware(priv.Y.Bytes(), 32))

	var keyID string
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case jwks.WellKnownPath:
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(jwks.Set{Keys: []jwks.Key{{
				Kty: "EC", Kid: keyID, Use: "sig", Crv: "P-256", X: x, Y: y,
			}}})
		case "/.well-known/ocm":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"enabled":      true,
				"apiVersion":   "1.4.0",
				"endPoint":     srv.URL + "/ocm",
				"capabilities": []string{"http-sig"},
				"criteria":     []string{"must-use-http-sig"},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	_, authority, err := jwks.AuthorityFromBaseURL(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	keyID = authority + "#ec1"

	contract, err := peercompat.NewCompiledContract(
		map[string]*peercompat.Profile{
			"local-http": {Name: "local-http", AllowHTTP: true},
		},
		[]peercompat.ProfileMapping{{Pattern: "*", Profile: "local-http"}},
	)
	if err != nil {
		t.Fatalf("NewCompiledContract: %v", err)
	}

	outboundCfg := &config.OutboundHTTPConfig{
		SSRF:               config.SSRFConfig{Mode: "off"},
		MaxResponseBytes:   1 << 20,
		InsecureSkipVerify: false,
	}
	rawClient := httpclient.New(outboundCfg, nil)
	discClient := discovery.NewClient(rawClient, nil)
	adapter := discovery.NewPeerDiscoveryAdapter(discClient, rawClient)
	adapter.SetPeerOrigin(peerorigin.NewResolver(true))

	cfg := defaultSigTestConfig()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mw := newTestSignatureMiddleware(cfg, contract, adapter, "https://receiver.example.com", logger)
	handler := mw.VerifyOCMRequest(nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	body := []byte(`{"test":"data"}`)
	req := httptest.NewRequest("POST", "https://receiver.example.com/ocm/shares", bytes.NewReader(body))
	req.Host = "receiver.example.com"
	req.Header.Set("Content-Type", "application/json")
	now := time.Now().UTC()
	req.Header.Set("Date", now.Format("Mon, 02 Jan 2006 15:04:05 GMT"))
	digest := base64.StdEncoding.EncodeToString(sigalg.SumSHA256(body))
	req.Header.Set("Content-Digest", "sha-256=:"+digest+":")
	req.Header.Set("Content-Length", fmt.Sprintf("%d", len(body)))

	components := []string{"@method", "@target-uri", "content-digest", "content-length", "date"}
	sigInput := fmt.Sprintf(
		`ocm=("@method" "@target-uri" "content-digest" "content-length" "date");created=%d;keyid=%q`,
		now.Unix(), keyID,
	)
	paramsRaw := strings.TrimPrefix(sigInput, "ocm=")
	sigBase, err := crypto.BuildSignatureBase(req, components)
	if err != nil {
		t.Fatal(err)
	}
	fullBase := sigBase + `"@signature-params": ` + paramsRaw
	sum := sha256.Sum256([]byte(fullBase))
	r, s, err := ecdsa.Sign(rand.Reader, priv, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	raw, err := sigalg.EncodeECDSARawRS(r, s, 32)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Signature-Input", sigInput)
	req.Header.Set("Signature", fmt.Sprintf("ocm=:%s:", base64.StdEncoding.EncodeToString(raw)))

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for JWKS->peer->middleware omit-alg ECDSA chain, got %d: %s", w.Code, w.Body.String())
	}
}

func padCoordMiddleware(b []byte, size int) []byte {
	if len(b) >= size {
		return b
	}
	out := make([]byte, size)
	copy(out[size-len(b):], b)
	return out
}

func TestSignatureMiddleware_IfPresent_StrictMode_AllowsUnsigned(t *testing.T) {
	cfg := defaultSigTestConfig()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	pd := &mockPeerDiscovery{}

	mw := newTestSignatureMiddleware(cfg, nil, pd, "https://receiver.example.com", logger)
	handler := mw.VerifyOCMRequestIfPresent()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if sig.GetPeerIdentity(r.Context()) != nil {
			t.Error("expected no peer identity for unsigned discovery request")
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/.well-known/ocm", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for unsigned discovery request, got %d", w.Code)
	}
}

func TestSignatureMiddleware_IfPresent_StrictMode_AcceptsSigned(t *testing.T) {
	km := crypto.NewKeyManager("", "https://nc.example.com")
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

	mw := newTestSignatureMiddleware(cfg, nil, pd, "https://receiver.example.com", logger)
	handler := mw.VerifyOCMRequestIfPresent()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pi := sig.GetPeerIdentity(r.Context())
		if pi == nil || !pi.Authenticated {
			t.Fatal("expected authenticated peer identity")
		}
		if pi.AuthorityForCompare != "nc.example.com" {
			t.Fatalf("AuthorityForCompare = %q, want nc.example.com", pi.AuthorityForCompare)
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "https://receiver.example.com/.well-known/ocm", nil)
	req.Host = "receiver.example.com"
	if err := signer.SignRequest(req, nil); err != nil {
		t.Fatalf("SignRequest: %v", err)
	}

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for signed discovery request, got %d: %s", w.Code, w.Body.String())
	}
}

func TestSignatureMiddleware_IfPresent_RejectsInvalidSignature(t *testing.T) {
	cfg := defaultSigTestConfig()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	pd := &mockPeerDiscovery{}

	mw := newTestSignatureMiddleware(cfg, nil, pd, "https://receiver.example.com", logger)
	handler := mw.VerifyOCMRequestIfPresent()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not run for invalid signature")
	}))

	req := httptest.NewRequest(http.MethodGet, "/.well-known/ocm", nil)
	req.Header.Set("Signature-Input", `ocm=("@method" "@target-uri");created=1;keyid="https://nc.example.com#main-key"`)
	req.Header.Set("Signature", "ocm=:invalid:")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for invalid signature, got %d", w.Code)
	}
}
