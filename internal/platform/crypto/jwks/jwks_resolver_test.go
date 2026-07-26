package jwks_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/jwks"
)

func TestResolver_Resolve(t *testing.T) {
	pub, _ := mustEd25519KeyPair(t)
	set := jwks.SetFromEd25519PublicKey(testJWKSKey1, pub)

	srv := httptest.NewServer(jwksJSONHandler(set))
	defer srv.Close()

	scheme, authority := mustSchemeAuthority(t, srv.URL)

	resolver, err := jwks.NewResolver(srv.Client())
	if err != nil {
		t.Fatal(err)
	}

	got, err := resolver.Resolve(context.Background(), scheme, authority, testJWKSKey1)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	if !pub.Equal(got.PublicKey.(ed25519.PublicKey)) {
		t.Fatal("key mismatch")
	}
}

type recordingDoer struct {
	lastURL string
	body    []byte
}

func (d *recordingDoer) Do(req *http.Request) (*http.Response, error) {
	d.lastURL = req.URL.String()

	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewReader(d.body)),
		Header:     make(http.Header),
		Request:    req,
	}, nil
}

func TestResolver_ResolveKeyID_CanonicalizesAuthority(t *testing.T) {
	pub, _ := mustEd25519KeyPair(t)
	set := jwks.SetFromEd25519PublicKey(testJWKSKey1, pub)

	body, err := json.Marshal(set)
	if err != nil {
		t.Fatal(err)
	}

	doer := &recordingDoer{body: body}

	resolver, err := jwks.NewResolver(doer)
	if err != nil {
		t.Fatal(err)
	}

	got, err := resolver.ResolveKeyID(context.Background(), "", "example.com:443#key1")
	if err != nil {
		t.Fatalf("ResolveKeyID default-port: %v", err)
	}

	if !pub.Equal(got.PublicKey.(ed25519.PublicKey)) {
		t.Fatal("key mismatch")
	}

	if doer.lastURL != "https://example.com/.well-known/jwks.json" {
		t.Fatalf("fetch URL = %q, want canonical https without :443", doer.lastURL)
	}

	doer.lastURL = ""

	got, err = resolver.ResolveKeyID(context.Background(), "https", "http://Example.COM:80/ocm#key1")
	if err != nil {
		t.Fatalf("ResolveKeyID absolute http: %v", err)
	}

	if !pub.Equal(got.PublicKey.(ed25519.PublicKey)) {
		t.Fatal("absolute URI key mismatch")
	}

	if doer.lastURL != "http://example.com/.well-known/jwks.json" {
		t.Fatalf("absolute URI fetch URL = %q, want http scheme from kid", doer.lastURL)
	}
}

func TestResolver_Resolve_MissingKid(t *testing.T) {
	pub, _ := mustEd25519KeyPair(t)
	set := jwks.SetFromEd25519PublicKey(testJWKSKey1, pub)

	srv := httptest.NewServer(jwksJSONHandler(set))
	defer srv.Close()

	scheme, authority := mustSchemeAuthority(t, srv.URL)

	resolver, err := jwks.NewResolver(srv.Client())
	if err != nil {
		t.Fatal(err)
	}

	_, err = resolver.Resolve(context.Background(), scheme, authority, "example.com#missing")
	if !errors.Is(err, jwks.ErrKeyNotFound) {
		t.Fatalf("Resolve() error = %v, want ErrKeyNotFound", err)
	}
}

func TestNewResolver_NilClient(t *testing.T) {
	_, err := jwks.NewResolver(nil)
	if !errors.Is(err, jwks.ErrNilHTTPClient) {
		t.Fatalf("NewResolver(nil) = %v, want ErrNilHTTPClient", err)
	}

	_, err = jwks.NewResolverWithTTL(nil, time.Minute)
	if !errors.Is(err, jwks.ErrNilHTTPClient) {
		t.Fatalf("NewResolverWithTTL(nil) = %v, want ErrNilHTTPClient", err)
	}
}
