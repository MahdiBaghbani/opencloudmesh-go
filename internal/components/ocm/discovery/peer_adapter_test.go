// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package discovery

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/peerorigin"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/jwks"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/keyid"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/sigalg"
	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
	tshttp "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/http"
)

func TestPeerDiscoveryAdapter_GetPublicKeyFromJWKS(t *testing.T) {
	var (
		srv     *httptest.Server
		km      *crypto.KeyManager
		jwksURI string
	)

	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ocm/jwks":
			w.Header().Set("Content-Type", "application/json")
			tshttp.MustEncodeJSON(t, w, km.JWKS())
		case "/.well-known/ocm":
			w.Header().Set("Content-Type", "application/json")
			tshttp.MustEncodeJSON(t, w, spec.Discovery{
				Enabled:    true,
				APIVersion: "1.4.0",
				EndPoint:   srv.URL + "/ocm",
				JwksUri:    jwksURI,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	jwksURI = srv.URL + "/ocm/jwks"

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
	discClient := NewClient(rawClient, nil)
	adapter := NewPeerDiscoveryAdapter(rawClient, discClient)
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

	if resolved.JWKAlg != "Ed25519" {
		t.Fatalf("JWKAlg = %q, want Ed25519", resolved.JWKAlg)
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

	var (
		keyID   string
		srv     *httptest.Server
		jwksURI string
	)

	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ocm/jwks":
			w.Header().Set("Content-Type", "application/json")
			tshttp.MustEncodeJSON(t, w, jwks.Set{Keys: []jwks.Key{{
				Kty: "EC", Kid: keyID, Use: "sig", Crv: "P-256", X: x, Y: y,
			}}})
		case "/.well-known/ocm":
			w.Header().Set("Content-Type", "application/json")
			tshttp.MustEncodeJSON(t, w, spec.Discovery{
				Enabled:    true,
				APIVersion: "1.4.0",
				EndPoint:   srv.URL + "/ocm",
				JwksUri:    jwksURI,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	jwksURI = srv.URL + "/ocm/jwks"

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
	discClient := NewClient(rawClient, nil)
	adapter := NewPeerDiscoveryAdapter(rawClient, discClient)
	adapter.SetPeerOrigin(peerorigin.NewResolver(true))

	_, err = adapter.ResolveVerificationKey(context.Background(), keyID)
	if err == nil {
		t.Fatal("ResolveVerificationKey: expected error for JWK missing alg, got nil")
	}

	if !errors.Is(err, sigalg.ErrMissingAlgorithm) {
		t.Fatalf("ResolveVerificationKey error = %v, want ErrMissingAlgorithm", err)
	}
}

func TestPeerDiscoveryAdapter_ResolveVerificationKey_SchemeFromPeerContract(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	var (
		keyID     string
		sawScheme string
		srv       *httptest.Server
		jwksURI   string
	)

	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ocm/jwks":
			if r.TLS == nil {
				sawScheme = "http"
			}

			w.Header().Set("Content-Type", "application/json")
			tshttp.MustEncodeJSON(t, w, jwks.SetFromEd25519PublicKey(keyID, pub))
		case "/.well-known/ocm":
			w.Header().Set("Content-Type", "application/json")
			tshttp.MustEncodeJSON(t, w, spec.Discovery{
				Enabled:    true,
				APIVersion: "1.4.0",
				EndPoint:   srv.URL + "/ocm",
				JwksUri:    jwksURI,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	jwksURI = srv.URL + "/ocm/jwks"

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
	discClient := NewClient(rawClient, nil)
	adapter := NewPeerDiscoveryAdapter(rawClient, discClient)
	adapter.SetPeerOrigin(peerorigin.NewResolver(true))

	resolved, err := adapter.ResolveVerificationKey(context.Background(), keyID)
	if err != nil {
		t.Fatalf("ResolveVerificationKey: %v", err)
	}

	alg, err := sigalg.ResolveAlgorithm("", resolved.JWKKty, resolved.JWKCrv, resolved.JWKAlg)
	if err != nil {
		t.Fatalf("ResolveAlgorithm: %v", err)
	}

	if alg != sigalg.Ed25519 {
		t.Fatalf("resolved algorithm = %q, want %q", alg, sigalg.Ed25519)
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

	var (
		keyID     string
		sawScheme string
		srv       *httptest.Server
		jwksURI   string
	)

	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ocm/jwks":
			if r.TLS != nil {
				sawScheme = "https"
			}

			w.Header().Set("Content-Type", "application/json")
			tshttp.MustEncodeJSON(t, w, jwks.SetFromEd25519PublicKey(keyID, pub))
		case "/.well-known/ocm":
			w.Header().Set("Content-Type", "application/json")
			tshttp.MustEncodeJSON(t, w, spec.Discovery{
				Enabled:    true,
				APIVersion: "1.4.0",
				EndPoint:   srv.URL + "/ocm",
				JwksUri:    jwksURI,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	jwksURI = srv.URL + "/ocm/jwks"

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
	discClient := NewClient(rawClient, nil)
	adapter := NewPeerDiscoveryAdapter(rawClient, discClient)
	adapter.SetPeerOrigin(peerorigin.NewResolver(true))

	resolved, err := adapter.ResolveVerificationKey(context.Background(), keyID)
	if err != nil {
		t.Fatalf("ResolveVerificationKey: %v", err)
	}

	alg, err := sigalg.ResolveAlgorithm("", resolved.JWKKty, resolved.JWKCrv, resolved.JWKAlg)
	if err != nil {
		t.Fatalf("ResolveAlgorithm: %v", err)
	}

	if alg != sigalg.Ed25519 {
		t.Fatalf("resolved algorithm = %q, want %q", alg, sigalg.Ed25519)
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

	jwkPath := "/ocm/jwks"

	var (
		jwksURI string
		srv     *httptest.Server
	)

	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case jwkPath:
			w.Header().Set("Content-Type", "application/json")
			tshttp.MustEncodeJSON(t, w, jwks.SetFromEd25519PublicKey("ignored#key1", pub))
		case "/.well-known/ocm":
			w.Header().Set("Content-Type", "application/json")
			tshttp.MustEncodeJSON(t, w, spec.Discovery{
				Enabled:    true,
				APIVersion: "1.4.0",
				EndPoint:   srv.URL + "/ocm",
				JwksUri:    jwksURI,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	jwksURI = srv.URL + jwkPath

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
	discClient := NewClient(rawClient, nil)
	adapter := NewPeerDiscoveryAdapter(rawClient, discClient)
	adapter.SetPeerOrigin(peerorigin.NewResolver(false))

	_, err = adapter.ResolveVerificationKey(context.Background(), keyID)
	if err == nil {
		t.Fatal("expected absolute http keyId to be rejected when AllowHTTP is false")
	}
}

// TestNewPeerDiscoveryAdapter_JWKSResolverOptionsAreBoundedAndNonZero pins the
// production adapter constructor to a bounded, non-zero JWKS cache and fetch
// policy so this path never regresses to unbounded fetch.
func TestNewPeerDiscoveryAdapter_JWKSResolverOptionsAreBoundedAndNonZero(t *testing.T) {
	outboundCfg := &config.OutboundHTTPConfig{
		SSRF:               config.SSRFConfig{Mode: "off"},
		MaxResponseBytes:   1 << 20,
		InsecureSkipVerify: false,
	}
	rawClient := httpclient.New(outboundCfg, nil)
	discClient := NewClient(rawClient, nil)
	adapter := NewPeerDiscoveryAdapter(rawClient, discClient)

	opts, ok := adapter.JWKSResolverOptions()
	if !ok {
		t.Fatal("expected adapter to have a JWKS resolver")
	}

	if opts.TTL <= 0 {
		t.Errorf("JWKSResolverOptions().TTL = %v, want > 0", opts.TTL)
	}

	if opts.MinRefetchInterval <= 0 {
		t.Errorf("JWKSResolverOptions().MinRefetchInterval = %v, want > 0", opts.MinRefetchInterval)
	}

	if opts.NegativeCacheTTL <= 0 {
		t.Errorf("JWKSResolverOptions().NegativeCacheTTL = %v, want > 0", opts.NegativeCacheTTL)
	}

	if opts.MaxResponseBytes <= 0 {
		t.Errorf("JWKSResolverOptions().MaxResponseBytes = %v, want > 0", opts.MaxResponseBytes)
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

// newJWKSErrorPeer starts a mock peer whose discovery document points at its
// own JWKS path; the JWKS path itself is served by jwksHandler.
func newJWKSErrorPeer(t *testing.T, jwksHandler http.HandlerFunc) *httptest.Server {
	t.Helper()

	var srv *httptest.Server

	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ocm/jwks":
			jwksHandler(w, r)
		case "/.well-known/ocm":
			w.Header().Set("Content-Type", "application/json")
			tshttp.MustEncodeJSON(t, w, spec.Discovery{
				Enabled:    true,
				APIVersion: "1.4.0",
				EndPoint:   srv.URL + "/ocm",
				JwksUri:    srv.URL + "/ocm/jwks",
			})
		default:
			http.NotFound(w, r)
		}
	}))

	return srv
}

// newLoadedKeyManager creates a key manager for the peer URL and loads or
// generates its key material.
func newLoadedKeyManager(t *testing.T, peerURL string) *crypto.KeyManager {
	t.Helper()

	km := crypto.NewKeyManager("", peerURL)
	if err := km.LoadOrGenerate(); err != nil {
		t.Fatal(err)
	}

	return km
}

// expectResolveKeyError asserts that resolving the manager's key against the
// adapter fails.
func expectResolveKeyError(t *testing.T, adapter *PeerDiscoveryAdapter, km *crypto.KeyManager, msg string) {
	t.Helper()

	_, err := adapter.ResolveVerificationKey(context.Background(), km.GetKeyID())
	if err == nil {
		t.Fatal(msg)
	}
}

func TestPeerDiscoveryAdapter_GetPublicKey_JWKSErrors(t *testing.T) {
	peerOrigin := peerorigin.NewResolver(true)

	outboundCfg := &config.OutboundHTTPConfig{
		SSRF:               config.SSRFConfig{Mode: "off"},
		MaxResponseBytes:   1 << 20,
		InsecureSkipVerify: false,
	}
	rawClient := httpclient.New(outboundCfg, nil)
	discClient := NewClient(rawClient, nil)

	t.Run("jwks 404", func(t *testing.T) {
		srv := newJWKSErrorPeer(t, http.NotFound)
		defer srv.Close()

		km := newLoadedKeyManager(t, srv.URL)
		adapter := NewPeerDiscoveryAdapter(rawClient, discClient)
		adapter.SetPeerOrigin(peerOrigin)

		expectResolveKeyError(t, adapter, km, "expected jwks lookup error for 404")
	})

	t.Run("invalid jwks JSON", func(t *testing.T) {
		srv := newJWKSErrorPeer(t, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")

			if _, err := w.Write([]byte(`{"keys":[`)); err != nil {
				t.Errorf("write response: %v", err)
			}
		})
		defer srv.Close()

		km := newLoadedKeyManager(t, srv.URL)
		adapter := NewPeerDiscoveryAdapter(rawClient, discClient)
		adapter.SetPeerOrigin(peerOrigin)

		expectResolveKeyError(t, adapter, km, "expected jwks decode error")
	})

	t.Run("missing kid", func(t *testing.T) {
		otherKM := newLoadedKeyManager(t, "https://other.example.com")

		srv := newJWKSErrorPeer(t, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			tshttp.MustEncodeJSON(t, w, otherKM.JWKS())
		})
		defer srv.Close()

		km := newLoadedKeyManager(t, srv.URL)
		adapter := NewPeerDiscoveryAdapter(rawClient, discClient)
		adapter.SetPeerOrigin(peerOrigin)

		expectResolveKeyError(t, adapter, km, "expected missing kid error")
	})
}

func TestPeerDiscoveryAdapter_ResolveVerificationKey_MissingJwksUri(t *testing.T) {
	var srv *httptest.Server

	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/ocm" {
			http.NotFound(w, r)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		tshttp.MustEncodeJSON(t, w, spec.Discovery{
			Enabled:    true,
			APIVersion: "1.4.0",
			EndPoint:   srv.URL + "/ocm",
		})
	}))
	defer srv.Close()

	outboundCfg := &config.OutboundHTTPConfig{
		SSRF:               config.SSRFConfig{Mode: "off"},
		MaxResponseBytes:   1 << 20,
		InsecureSkipVerify: false,
	}
	rawClient := httpclient.New(outboundCfg, nil)
	discClient := NewClient(rawClient, nil)
	adapter := NewPeerDiscoveryAdapter(rawClient, discClient)
	adapter.SetPeerOrigin(peerorigin.NewResolver(true))

	_, authority, err := jwks.AuthorityFromBaseURL(srv.URL)
	if err != nil {
		t.Fatal(err)
	}

	keyID := authority + "#key1"

	_, err = adapter.ResolveVerificationKey(context.Background(), keyID)
	if err == nil {
		t.Fatal("expected error when discovery lacks jwksUri")
	}

	if strings.Contains(err.Error(), "no jwksUri advertised") {
		return
	}

	t.Fatalf("error = %v, want no jwksUri advertised", err)
}

func TestPeerDiscoveryAdapter_ResolveVerificationKey_BlocksInvalidAdvertisedJwksUri(t *testing.T) {
	cases := []struct {
		name    string
		jwksURI string
		wantErr string
	}{
		{"cross-authority", "https://other.example.com/ocm/jwks", "jwksUri authority must match discovery origin"},
		{"credential-bearing", "", "jwksUri must not contain credentials"},
		{"fragment-bearing", "", "jwksUri must not contain a fragment"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var (
				jwksURI string
				srv     *httptest.Server
			)

			srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/.well-known/ocm" {
					http.NotFound(w, r)
					return
				}

				w.Header().Set("Content-Type", "application/json")
				tshttp.MustEncodeJSON(t, w, spec.Discovery{
					Enabled:    true,
					APIVersion: "1.4.0",
					EndPoint:   srv.URL + "/ocm",
					JwksUri:    jwksURI,
				})
			}))
			defer srv.Close()

			switch tc.name {
			case "credential-bearing":
				jwksURI = strings.Replace(srv.URL, "://", "://user:pass@", 1) + "/ocm/jwks"
			case "fragment-bearing":
				jwksURI = srv.URL + "/ocm/jwks#key-1"
			default:
				jwksURI = tc.jwksURI
			}

			outboundCfg := &config.OutboundHTTPConfig{
				SSRF:               config.SSRFConfig{Mode: "off"},
				MaxResponseBytes:   1 << 20,
				InsecureSkipVerify: false,
			}
			rawClient := httpclient.New(outboundCfg, nil)
			discClient := NewClient(rawClient, nil)
			adapter := NewPeerDiscoveryAdapter(rawClient, discClient)
			adapter.SetPeerOrigin(peerorigin.NewResolver(true))

			_, authority, err := jwks.AuthorityFromBaseURL(srv.URL)
			if err != nil {
				t.Fatal(err)
			}

			keyID := authority + "#key1"

			_, err = adapter.ResolveVerificationKey(context.Background(), keyID)
			if err == nil {
				t.Fatalf("expected error for %s advertised jwksUri", tc.name)
			}

			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %v, want substring %q", err, tc.wantErr)
			}
		})
	}
}

func TestPeerDiscoveryAdapter_ResolveVerificationKey_BlocksHTTPSDowngradeRedirect(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	var (
		jwksURI string
		srv     *httptest.Server
	)

	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ocm/jwks":
			w.Header().Set("Location", strings.Replace(srv.URL, "https://", "http://", 1)+"/ocm/jwks")
			w.WriteHeader(http.StatusFound)
		case "/.well-known/ocm":
			w.Header().Set("Content-Type", "application/json")
			tshttp.MustEncodeJSON(t, w, spec.Discovery{
				Enabled:    true,
				APIVersion: "1.4.0",
				EndPoint:   srv.URL + "/ocm",
				JwksUri:    jwksURI,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	jwksURI = srv.URL + "/ocm/jwks"

	outboundCfg := &config.OutboundHTTPConfig{
		SSRF:               config.SSRFConfig{Mode: "off"},
		MaxResponseBytes:   1 << 20,
		InsecureSkipVerify: true,
	}
	rawClient := httpclient.New(outboundCfg, nil)
	discClient := NewClient(rawClient, nil)
	adapter := NewPeerDiscoveryAdapter(rawClient, discClient)
	adapter.SetPeerOrigin(peerorigin.NewResolver(false))

	_, authority, err := jwks.AuthorityFromBaseURL(srv.URL)
	if err != nil {
		t.Fatal(err)
	}

	keyID := authority + "#key1"

	// Silence unused pub warning.
	_ = pub

	_, err = adapter.ResolveVerificationKey(context.Background(), keyID)
	if err == nil {
		t.Fatal("expected error for HTTPS-to-HTTP downgrade redirect")
	}

	if !errors.Is(err, httpclient.ErrRedirectDowngrade) {
		t.Fatalf("error = %v, want errors.Is(..., httpclient.ErrRedirectDowngrade)", err)
	}
}

func TestPeerDiscoveryAdapter_ResolveVerificationKey_BlocksCrossHostRedirect(t *testing.T) {
	var (
		jwksURI string
		srv     *httptest.Server
	)

	redirectLocation := ""

	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ocm/jwks":
			w.Header().Set("Location", redirectLocation)
			w.WriteHeader(http.StatusFound)
		case "/.well-known/ocm":
			w.Header().Set("Content-Type", "application/json")
			tshttp.MustEncodeJSON(t, w, spec.Discovery{
				Enabled:    true,
				APIVersion: "1.4.0",
				EndPoint:   srv.URL + "/ocm",
				JwksUri:    jwksURI,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	u, parseErr := url.Parse(srv.URL)
	if parseErr != nil {
		t.Fatalf("parse test server URL: %v", parseErr)
	}

	otherPort, portErr := strconv.Atoi(u.Port())
	if portErr != nil {
		t.Fatalf("parse test server port: %v", portErr)
	}

	redirectLocation = "http://" + net.JoinHostPort(u.Hostname(), strconv.Itoa(otherPort+1)) + "/ocm/jwks"
	jwksURI = srv.URL + "/ocm/jwks"

	outboundCfg := &config.OutboundHTTPConfig{
		SSRF:               config.SSRFConfig{Mode: "off"},
		MaxResponseBytes:   1 << 20,
		InsecureSkipVerify: false,
	}
	rawClient := httpclient.New(outboundCfg, nil)
	discClient := NewClient(rawClient, nil)
	adapter := NewPeerDiscoveryAdapter(rawClient, discClient)
	adapter.SetPeerOrigin(peerorigin.NewResolver(true))

	_, authority, err := jwks.AuthorityFromBaseURL(srv.URL)
	if err != nil {
		t.Fatal(err)
	}

	keyID := authority + "#key1"

	_, err = adapter.ResolveVerificationKey(context.Background(), keyID)
	if err == nil {
		t.Fatal("expected error for cross-host redirect")
	}

	if !errors.Is(err, httpclient.ErrRedirectNotSameHost) {
		t.Fatalf("error = %v, want errors.Is(..., httpclient.ErrRedirectNotSameHost)", err)
	}
}
