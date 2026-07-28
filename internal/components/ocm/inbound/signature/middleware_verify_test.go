package signature_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery"
	sig "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/inbound/signature"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/peerorigin"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache/loader"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/jwks"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/sigalg"
	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
)

func TestSignatureMiddleware_StrictMode_AcceptsSigned(t *testing.T) {
	// Create a key manager and signer
	km := crypto.NewKeyManager("", "https://sender.example.com")
	if err := km.LoadOrGenerate(); err != nil {
		t.Fatalf("LoadOrGenerate: %v", err)
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
	req := httptest.NewRequest(http.MethodPost, "https://receiver.example.com/ocm/shares", bytes.NewReader(body))
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

// TestSignatureMiddleware_DefaultPortEquivalence proves scheme-aware comparison:
// a keyId with explicit :443 matches a declared peer without :443 when scheme is https.
func TestSignatureMiddleware_DefaultPortEquivalence(t *testing.T) {
	// Use explicit :443 in the sender's external origin so the keyId includes it.
	km := crypto.NewKeyManager("", "https://sender.example.com:443")
	if err := km.LoadOrGenerate(); err != nil {
		t.Fatalf("LoadOrGenerate: %v", err)
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

	// Peer resolver returns "sender.example.com" (without :443).
	// The keyId will contain :443 explicitly.
	// Scheme-aware comparison must treat them as equivalent.
	peerResolver := func(_ *http.Request, _ []byte) (string, error) {
		return "sender.example.com", nil
	}

	handler := mw.VerifyOCMRequestRequireSignatureAndPeer(peerResolver)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	req := httptest.NewRequest(http.MethodPost, "https://receiver.example.com/ocm/shares", bytes.NewReader(body))
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
	mw := newTestSignatureMiddleware(sigCfg, pd, "https://receiver.example.com", logger)

	handler := mw.VerifyOCMRequestIfPresent()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pi := sig.GetPeerIdentity(r.Context())
		if pi == nil || !pi.Authenticated {
			t.Error("expected authenticated peer identity")
		}

		if pi.AuthorityForCompare != "sender.example.com" {
			t.Errorf("AuthorityForCompare = %q, want sender.example.com", pi.AuthorityForCompare)
		}

		w.WriteHeader(http.StatusOK)
	}))

	body := []byte(`{"test":"data"}`)

	req := httptest.NewRequest(http.MethodPost, "/ocm/shares", bytes.NewReader(body))
	if err := signer.SignRequest(req, body); err != nil {
		t.Fatal(err)
	}

	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected signed request with configured label to pass, got %d: %s", w.Code, w.Body.String())
	}

	defaultSigner := crypto.NewRFC9421Signer(km)

	defaultReq := httptest.NewRequest(http.MethodPost, "/ocm/shares", bytes.NewReader(body))
	if err := defaultSigner.SignRequest(defaultReq, body); err != nil {
		t.Fatal(err)
	}

	w = httptest.NewRecorder()
	handler.ServeHTTP(w, defaultReq)

	if w.Code != http.StatusOK {
		t.Fatalf("expected default ocm label with tag to verify label-free, got %d", w.Code)
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
	mw := newTestSignatureMiddleware(cfg, pd, "https://receiver.example.com", logger)
	handler := mw.VerifyOCMRequestIfPresent()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	body := []byte(`{"test":"data"}`)
	req := httptest.NewRequest(http.MethodPost, "https://receiver.example.com/ocm/shares", bytes.NewReader(body))
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
		`ocm=("@method" "@target-uri" "content-digest" "content-length" "date");created=%d;keyid=%q;tag="ocm"`,
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

// ECDSA P-256 with Signature-Input alg omitted, resolved via live JWKS.
func TestSignatureMiddleware_StrictMode_OmitAlgECDSAP256_JWKSPeerChain(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	x := base64.RawURLEncoding.EncodeToString(padCoordMiddleware(priv.X.Bytes(), 32))
	y := base64.RawURLEncoding.EncodeToString(padCoordMiddleware(priv.Y.Bytes(), 32))

	var (
		keyID string
		srv   *httptest.Server
	)

	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case jwks.WellKnownPath:
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(jwks.Set{Keys: []jwks.Key{{ //nolint:errcheck // test mock handler: JSON encode
				Kty: "EC", Kid: keyID, Use: "sig", Crv: "P-256", X: x, Y: y,
			}}})
		case "/.well-known/ocm":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck // test mock handler: JSON encode
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

	outboundCfg := &config.OutboundHTTPConfig{
		SSRF:               config.SSRFConfig{Mode: "off"},
		MaxResponseBytes:   1 << 20,
		InsecureSkipVerify: false,
	}
	rawClient := httpclient.New(outboundCfg, nil)
	adapter := discovery.NewPeerDiscoveryAdapter(rawClient)
	adapter.SetPeerOrigin(peerorigin.NewResolver(true))

	cfg := defaultSigTestConfig()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	mw := newTestSignatureMiddleware(cfg, adapter, "https://receiver.example.com", logger)
	handler := mw.VerifyOCMRequestIfPresent()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	body := []byte(`{"test":"data"}`)
	req := httptest.NewRequest(http.MethodPost, "https://receiver.example.com/ocm/shares", bytes.NewReader(body))
	req.Host = "receiver.example.com"
	req.Header.Set("Content-Type", "application/json")

	now := time.Now().UTC()
	req.Header.Set("Date", now.Format("Mon, 02 Jan 2006 15:04:05 GMT"))

	digest := base64.StdEncoding.EncodeToString(sigalg.SumSHA256(body))
	req.Header.Set("Content-Digest", "sha-256=:"+digest+":")
	req.Header.Set("Content-Length", fmt.Sprintf("%d", len(body)))

	components := []string{"@method", "@target-uri", "content-digest", "content-length", "date"}
	sigInput := fmt.Sprintf(
		`ocm=("@method" "@target-uri" "content-digest" "content-length" "date");created=%d;keyid=%q;tag="ocm"`,
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

	mw := newTestSignatureMiddleware(cfg, pd, "https://receiver.example.com", logger)
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
func padCoordMiddleware(b []byte, size int) []byte {
	if len(b) >= size {
		return b
	}

	out := make([]byte, size)
	copy(out[size-len(b):], b)

	return out
}
