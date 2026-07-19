package discovery

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/peerorigin"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/jwks"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/keyid"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/sigalg"
	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
)

func TestPeerDiscoveryAdapter_GetPublicKeyFromJWKS(t *testing.T) {
	var srv *httptest.Server
	var km *crypto.KeyManager

	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case jwks.WellKnownPath:
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(km.JWKS())
		case "/.well-known/ocm":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(Discovery{
				Enabled:    true,
				APIVersion: "1.4.0",
				EndPoint:   srv.URL + "/ocm",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	km = crypto.NewKeyManager("", srv.URL)
	if err := km.LoadOrGenerate(); err != nil {
		t.Fatal(err)
	}

	outboundCfg := &config.OutboundHTTPConfig{
		SSRF:               config.SSRFConfig{Mode: "off"},
		MaxResponseBytes:   1 << 20,
		InsecureSkipVerify: false,
	}
	rawClient := httpclient.New(outboundCfg, nil)
	adapter := NewPeerDiscoveryAdapter(rawClient)
	adapter.SetPeerOrigin(peerorigin.NewResolver(true))

	keyID := km.GetKeyID()
	parsed, err := keyid.ParseKid(keyID)
	if err != nil {
		t.Fatalf("ParseKid(%q): %v", keyID, err)
	}
	if parsed.Scheme != "" {
		t.Fatalf("expected canonical host#fragment kid, got scheme %q in %q", parsed.Scheme, keyID)
	}

	resolved, err := adapter.ResolveVerificationKey(context.Background(), keyID)
	if err != nil {
		t.Fatalf("ResolveVerificationKey: %v", err)
	}
	if resolved.Algorithm != "ed25519" {
		t.Fatalf("Algorithm = %q", resolved.Algorithm)
	}
	pub, ok := resolved.PublicKey.(ed25519.PublicKey)
	if !ok {
		t.Fatalf("PublicKey type %T", resolved.PublicKey)
	}
	if !pub.Equal(km.GetSigningKey().PublicKey) {
		t.Fatal("JWKS public key mismatch")
	}
}

func TestPeerDiscoveryAdapter_ResolveVerificationKey_ECP256OmitAlg(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	x := base64.RawURLEncoding.EncodeToString(padCoord(priv.X.Bytes(), 32))
	y := base64.RawURLEncoding.EncodeToString(padCoord(priv.Y.Bytes(), 32))

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
			_ = json.NewEncoder(w).Encode(Discovery{
				Enabled:    true,
				APIVersion: "1.4.0",
				EndPoint:   srv.URL + "/ocm",
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
	adapter := NewPeerDiscoveryAdapter(rawClient)
	adapter.SetPeerOrigin(peerorigin.NewResolver(true))

	resolved, err := adapter.ResolveVerificationKey(context.Background(), keyID)
	if err != nil {
		t.Fatalf("ResolveVerificationKey: %v", err)
	}
	if resolved.Algorithm != sigalg.ECDSAP256SHA256 {
		t.Fatalf("Algorithm = %q, want %s", resolved.Algorithm, sigalg.ECDSAP256SHA256)
	}
	if _, ok := resolved.PublicKey.(*ecdsa.PublicKey); !ok {
		t.Fatalf("PublicKey type %T", resolved.PublicKey)
	}
}

func TestPeerDiscoveryAdapter_ResolveVerificationKey_SchemeFromPeerContract(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	var keyID string
	var sawScheme string
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != jwks.WellKnownPath {
			http.NotFound(w, r)
			return
		}
		if r.TLS == nil {
			sawScheme = "http"
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks.SetFromEd25519PublicKey(keyID, pub))
	}))
	defer srv.Close()

	_, authority, err := jwks.AuthorityFromBaseURL(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	// Host#fragment kids follow the dev-mode HTTP transport policy.
	keyID = authority + "#key1"

	outboundCfg := &config.OutboundHTTPConfig{
		SSRF:               config.SSRFConfig{Mode: "off"},
		MaxResponseBytes:   1 << 20,
		InsecureSkipVerify: false,
	}
	rawClient := httpclient.New(outboundCfg, nil)
	adapter := NewPeerDiscoveryAdapter(rawClient)
	adapter.SetPeerOrigin(peerorigin.NewResolver(true))

	resolved, err := adapter.ResolveVerificationKey(context.Background(), keyID)
	if err != nil {
		t.Fatalf("ResolveVerificationKey: %v", err)
	}
	if resolved.Algorithm != sigalg.Ed25519 {
		t.Fatalf("Algorithm = %q", resolved.Algorithm)
	}
	if sawScheme != "http" {
		t.Fatalf("JWKS transport = %q, want http in dev mode for host#fragment kid", sawScheme)
	}
}

func TestPeerDiscoveryAdapter_ResolveVerificationKey_PreservesExplicitHTTPSKid(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	var keyID string
	var sawScheme string
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != jwks.WellKnownPath {
			http.NotFound(w, r)
			return
		}
		if r.TLS != nil {
			sawScheme = "https"
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks.SetFromEd25519PublicKey(keyID, pub))
	}))
	defer srv.Close()

	_, authority, err := jwks.AuthorityFromBaseURL(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	keyID = "https://" + authority + "#key1"

	outboundCfg := &config.OutboundHTTPConfig{
		SSRF:               config.SSRFConfig{Mode: "off"},
		MaxResponseBytes:   1 << 20,
		InsecureSkipVerify: true,
	}
	rawClient := httpclient.New(outboundCfg, nil)
	adapter := NewPeerDiscoveryAdapter(rawClient)
	adapter.SetPeerOrigin(peerorigin.NewResolver(true))

	resolved, err := adapter.ResolveVerificationKey(context.Background(), keyID)
	if err != nil {
		t.Fatalf("ResolveVerificationKey: %v", err)
	}
	if resolved.Algorithm != sigalg.Ed25519 {
		t.Fatalf("Algorithm = %q", resolved.Algorithm)
	}
	if sawScheme != "https" {
		t.Fatalf("JWKS transport = %q, want https for absolute https kid", sawScheme)
	}
}

func TestPeerDiscoveryAdapter_RejectsDisallowedAbsoluteURIKid(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != jwks.WellKnownPath {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwks.SetFromEd25519PublicKey("ignored#key1", pub))
	}))
	defer srv.Close()

	_, authority, err := jwks.AuthorityFromBaseURL(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	// http absolute kid while the resolver has no dev-mode HTTP gate.
	keyID := "http://" + authority + "#key1"

	outboundCfg := &config.OutboundHTTPConfig{
		SSRF:               config.SSRFConfig{Mode: "off"},
		MaxResponseBytes:   1 << 20,
		InsecureSkipVerify: false,
	}
	rawClient := httpclient.New(outboundCfg, nil)
	adapter := NewPeerDiscoveryAdapter(rawClient)
	adapter.SetPeerOrigin(peerorigin.NewResolver(false))

	_, err = adapter.ResolveVerificationKey(context.Background(), keyID)
	if err == nil {
		t.Fatal("expected absolute http keyId to be rejected when AllowHTTP is false")
	}
}

func padCoord(b []byte, size int) []byte {
	if len(b) >= size {
		return b
	}
	out := make([]byte, size)
	copy(out[size-len(b):], b)
	return out
}

func TestPeerDiscoveryAdapter_GetPublicKey_JWKSErrors(t *testing.T) {
	peerOrigin := peerorigin.NewResolver(true)

	outboundCfg := &config.OutboundHTTPConfig{
		SSRF:               config.SSRFConfig{Mode: "off"},
		MaxResponseBytes:   1 << 20,
		InsecureSkipVerify: false,
	}
	rawClient := httpclient.New(outboundCfg, nil)

	t.Run("jwks 404", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == jwks.WellKnownPath {
				http.NotFound(w, r)
				return
			}
			http.NotFound(w, r)
		}))
		defer srv.Close()

		km := crypto.NewKeyManager("", srv.URL)
		if err := km.LoadOrGenerate(); err != nil {
			t.Fatal(err)
		}

		adapter := NewPeerDiscoveryAdapter(rawClient)
		adapter.SetPeerOrigin(peerOrigin)

		_, err := adapter.ResolveVerificationKey(context.Background(), km.GetKeyID())
		if err == nil {
			t.Fatal("expected jwks lookup error for 404")
		}
	})

	t.Run("invalid jwks JSON", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == jwks.WellKnownPath {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"keys":[`))
				return
			}
			http.NotFound(w, r)
		}))
		defer srv.Close()

		km := crypto.NewKeyManager("", srv.URL)
		if err := km.LoadOrGenerate(); err != nil {
			t.Fatal(err)
		}

		adapter := NewPeerDiscoveryAdapter(rawClient)
		adapter.SetPeerOrigin(peerOrigin)

		_, err := adapter.ResolveVerificationKey(context.Background(), km.GetKeyID())
		if err == nil {
			t.Fatal("expected jwks decode error")
		}
	})

	t.Run("missing kid", func(t *testing.T) {
		var srv *httptest.Server
		otherKM := crypto.NewKeyManager("", "https://other.example.com")
		if err := otherKM.LoadOrGenerate(); err != nil {
			t.Fatal(err)
		}

		srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == jwks.WellKnownPath {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(otherKM.JWKS())
				return
			}
			http.NotFound(w, r)
		}))
		defer srv.Close()

		km := crypto.NewKeyManager("", srv.URL)
		if err := km.LoadOrGenerate(); err != nil {
			t.Fatal(err)
		}

		adapter := NewPeerDiscoveryAdapter(rawClient)
		adapter.SetPeerOrigin(peerOrigin)

		_, err := adapter.ResolveVerificationKey(context.Background(), km.GetKeyID())
		if err == nil {
			t.Fatal("expected missing kid error")
		}
	})
}
