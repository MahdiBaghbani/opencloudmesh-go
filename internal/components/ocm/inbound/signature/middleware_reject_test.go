package signature_test

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	sig "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/inbound/signature"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/sigalg"
)

func TestSignatureMiddleware_StrictMode_RejectsUnsigned(t *testing.T) {
	cfg := defaultSigTestConfig()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	pd := &mockPeerDiscovery{}

	mw := newStrictSignatureMiddleware(cfg, pd, "https://receiver.example.com", logger)

	peerResolver := func(r *http.Request, body []byte) (string, error) {
		return "sender.example.com", nil
	}
	handler := mw.VerifyOCMRequestRequireSignatureAndPeer(peerResolver)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/ocm/shares", bytes.NewBufferString(`{"test":"data"}`))
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("strict mode should reject unsigned requests, got status %d", w.Code)
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

	mw := newTestSignatureMiddleware(cfg, pd, "https://receiver.example.com", logger)

	handler := mw.VerifyOCMRequestIfPresent()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	body := []byte(`{"test":"data"}`)
	req := httptest.NewRequest(http.MethodPost, "https://receiver.example.com/ocm/shares", bytes.NewReader(body))
	req.Host = "receiver.example.com"
	req.Header.Set("Content-Type", "application/json")
	signer.SignRequest(req, body)

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("should reject invalid signature, got status %d", w.Code)
	}
}

// TestSignatureMiddleware_StrictMode_RejectsMalformedSignatureMaterial checks
// that the strict middleware returns 401 for malformed signature material rather
// than passing the request through.
func TestSignatureMiddleware_StrictMode_RejectsMalformedSignatureMaterial(t *testing.T) {
	cfg := defaultSigTestConfig()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	pd := &mockPeerDiscovery{
		publicKeys: map[string]sigalg.ResolvedPublicKey{},
	}

	mw := newStrictSignatureMiddleware(
		cfg,
		pd,
		"https://receiver.example.com",
		logger,
	)

	// A syntactically valid but wrong 64-byte signature in RFC 9421 format.
	zeroSig := base64.StdEncoding.EncodeToString(make([]byte, 64))

	peerResolver := func(r *http.Request, body []byte) (string, error) {
		return "sender.example.com", nil
	}

	tests := []struct {
		name           string
		signatureInput string
		signature      string
	}{
		{
			name:           "empty keyid in signature params",
			signatureInput: `ocm=("@method");created=1234567890;keyid="";alg="ed25519";tag="ocm"`,
			signature:      fmt.Sprintf("ocm=:%s:", zeroSig),
		},
		{
			name:           "invalid base64 in signature value",
			signatureInput: `ocm=("@method");created=1234567890;keyid="example.com#key1";alg="ed25519";tag="ocm"`,
			signature:      "ocm=:not!valid!base64!!!:",
		},
		{
			name:           "malformed keyid missing closing quote",
			signatureInput: `ocm=("@method");created=1234567890;keyid="example.com#key1;alg="ed25519";tag="ocm"`,
			signature:      fmt.Sprintf("ocm=:%s:", zeroSig),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := mw.VerifyOCMRequestRequireSignatureAndPeer(peerResolver)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))

			req := httptest.NewRequest(http.MethodPost, "/ocm/shares", bytes.NewBufferString(`{"test":"data"}`))
			if tt.signatureInput != "" {
				req.Header.Set("Signature-Input", tt.signatureInput)
			}

			if tt.signature != "" {
				req.Header.Set("Signature", tt.signature)
			}

			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			if w.Code != http.StatusUnauthorized {
				t.Errorf("expected status 401, got %d (body: %s)",
					w.Code, w.Body.String())
			}
		})
	}
}

// TestSignatureMiddleware_IfPresent_DistinguishesMalformedOCMFromUnsigned
// proves that a malformed or partial OCM signature attempt is rejected even
// on the optional path, while a genuine unsigned request is still allowed.
func TestSignatureMiddleware_IfPresent_DistinguishesMalformedOCMFromUnsigned(t *testing.T) {
	cfg := defaultSigTestConfig()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	pd := &mockPeerDiscovery{}

	mw := newTestSignatureMiddleware(cfg, pd, "https://receiver.example.com", logger)
	mw.SetLocalHTTPSigPolicy(true, true)

	zeroSig := base64.StdEncoding.EncodeToString(make([]byte, 64))

	tests := []struct {
		name           string
		signatureInput string
		signature      string
		wantCode       int
		wantBody       string
	}{
		{
			name:           "genuine unsigned request",
			signatureInput: "",
			signature:      "",
			wantCode:       http.StatusOK,
			wantBody:       "",
		},
		{
			name:           "partial OCM signature input missing signature",
			signatureInput: `ocm=("@method");created=1234567890;keyid="example.com#key1";alg="ed25519";tag="ocm"`,
			signature:      "",
			wantCode:       http.StatusUnauthorized,
			wantBody:       "signature verification failed",
		},
		{
			name:           "partial OCM signature missing signature input",
			signatureInput: "",
			signature:      fmt.Sprintf("ocm=:%s:", zeroSig),
			wantCode:       http.StatusUnauthorized,
			wantBody:       "signature verification failed",
		},
		{
			name:           "partial OCM tag missing closing quote",
			signatureInput: `ocm=("@method");created=1234567890;keyid="example.com#key1";alg="ed25519";tag="ocm`,
			signature:      fmt.Sprintf("ocm=:%s:", zeroSig),
			wantCode:       http.StatusUnauthorized,
			wantBody:       "signature verification failed",
		},
		{
			name:           "unquoted OCM tag",
			signatureInput: `ocm=("@method");created=1234567890;keyid="example.com#key1";alg="ed25519";tag=ocm`,
			signature:      fmt.Sprintf("ocm=:%s:", zeroSig),
			wantCode:       http.StatusUnauthorized,
			wantBody:       "signature verification failed",
		},
		{
			name:           "foreign signature treated as unsigned",
			signatureInput: `proxy=("@method" "@target-uri");created=1;keyid="proxy.example.com#key1";tag="proxy"`,
			signature:      "proxy=:AAAA:",
			wantCode:       http.StatusOK,
			wantBody:       "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := mw.VerifyOCMRequestIfPresent()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tt.wantCode != http.StatusOK {
					t.Fatal("handler should not run for rejected request")
				}

				w.WriteHeader(http.StatusOK)
			}))

			req := httptest.NewRequest(http.MethodGet, "/.well-known/ocm", nil)
			if tt.signatureInput != "" {
				req.Header.Set("Signature-Input", tt.signatureInput)
			}

			if tt.signature != "" {
				req.Header.Set("Signature", tt.signature)
			}

			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			if w.Code != tt.wantCode {
				t.Errorf("want status %d, got %d (body: %s)", tt.wantCode, w.Code, w.Body.String())
			}

			if tt.wantBody != "" && strings.TrimSpace(w.Body.String()) != tt.wantBody {
				t.Errorf("want body %q, got %q", tt.wantBody, w.Body.String())
			}
		})
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

	mw := newTestSignatureMiddleware(cfg, pd, "https://receiver.example.com", logger)

	handler := mw.VerifyOCMRequestIfPresent()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not run when content digest verification fails")
	}))

	signedBody := []byte(`{"test":"data"}`)
	req := httptest.NewRequest(http.MethodPost, "https://receiver.example.com/ocm/shares", bytes.NewReader(signedBody))
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
func TestSignatureMiddleware_IfPresent_RejectsInvalidSignature(t *testing.T) {
	cfg := defaultSigTestConfig()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	pd := &mockPeerDiscovery{}

	mw := newTestSignatureMiddleware(cfg, pd, "https://receiver.example.com", logger)
	handler := mw.VerifyOCMRequestIfPresent()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not run for invalid signature")
	}))

	req := httptest.NewRequest(http.MethodGet, "/.well-known/ocm", nil)
	req.Header.Set("Signature-Input", `ocm=("@method" "@target-uri");created=1;keyid="https://nc.example.com#main-key";tag="ocm"`)
	req.Header.Set("Signature", "ocm=:invalid:")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for invalid signature, got %d", w.Code)
	}
}
func TestSignatureMiddleware_RequireSignatureAndPeer_Advertised_UnsignedRejects(t *testing.T) {
	cfg := defaultSigTestConfig()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	pd := &mockPeerDiscovery{}
	mw := newTestSignatureMiddleware(cfg, pd, "https://receiver.example.com", logger)
	mw.SetLocalHTTPSigPolicy(true, true)

	peerResolver := func(r *http.Request, body []byte) (string, error) {
		return "sender.example.com", nil
	}
	handler := mw.VerifyOCMRequestRequireSignatureAndPeer(peerResolver)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not run when advertised unsigned request is rejected")
	}))

	body := []byte(`{"test":"data"}`)
	req := httptest.NewRequest(http.MethodPost, "/ocm/shares", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for advertised unsigned request, got %d: %s", w.Code, w.Body.String())
	}

	if strings.TrimSpace(w.Body.String()) != "signature required" {
		t.Fatalf("body = %q, want signature required", w.Body.String())
	}
}
func newStrictSignatureMiddleware(
	cfg *config.SignatureConfig,
	pd sig.PeerDiscovery,
	publicOrigin string,
	logger *slog.Logger,
) *sig.SignatureMiddleware {
	mw := newTestSignatureMiddleware(cfg, pd, publicOrigin, logger)
	mw.SetLocalHTTPSigPolicy(true, true)

	return mw
}
