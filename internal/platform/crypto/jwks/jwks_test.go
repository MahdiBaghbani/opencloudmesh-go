package jwks_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/jwks"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/sigalg"
)

func TestSetFromEd25519PublicKey_Find(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	set := jwks.SetFromEd25519PublicKey("example.com#key1", pub)
	got, err := set.Find("example.com#key1")
	if err != nil {
		t.Fatalf("Find: %v", err)
	}
	if got.Algorithm != sigalg.Ed25519 {
		t.Fatalf("Algorithm = %q", got.Algorithm)
	}
	if !pub.Equal(got.PublicKey.(ed25519.PublicKey)) {
		t.Fatal("public key mismatch")
	}
}

func TestFetchURL(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	set := jwks.SetFromEd25519PublicKey("example.com#key1", pub)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != jwks.WellKnownPath {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(set)
	}))
	defer srv.Close()

	got, err := jwks.FetchURL(context.Background(), srv.Client(), srv.URL+jwks.WellKnownPath)
	if err != nil {
		t.Fatalf("FetchURL: %v", err)
	}
	key, err := got.Find("example.com#key1")
	if err != nil {
		t.Fatalf("Find: %v", err)
	}
	if !pub.Equal(key.PublicKey.(ed25519.PublicKey)) {
		t.Fatal("key mismatch")
	}
}

func TestAuthorityFromBaseURL_NormalizesHostAndDefaultPort(t *testing.T) {
	scheme, authority, err := jwks.AuthorityFromBaseURL("https://Example.COM:443/ocm/path?q=1")
	if err != nil {
		t.Fatalf("AuthorityFromBaseURL: %v", err)
	}
	if scheme != "https" {
		t.Fatalf("scheme = %q, want https", scheme)
	}
	if authority != "example.com" {
		t.Fatalf("authority = %q, want example.com", authority)
	}

	scheme, authority, err = jwks.AuthorityFromBaseURL("http://Example.COM:80/")
	if err != nil {
		t.Fatalf("AuthorityFromBaseURL http: %v", err)
	}
	if scheme != "http" || authority != "example.com" {
		t.Fatalf("http default port = %s %q, want http example.com", scheme, authority)
	}
}

func TestResolver_Resolve(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	set := jwks.SetFromEd25519PublicKey("example.com#key1", pub)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(set)
	}))
	defer srv.Close()

	scheme, authority, err := jwks.AuthorityFromBaseURL(srv.URL)
	if err != nil {
		t.Fatal(err)
	}

	resolver, err := jwks.NewResolver(srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	got, err := resolver.Resolve(context.Background(), scheme, authority, "example.com#key1")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !pub.Equal(got.PublicKey.(ed25519.PublicKey)) {
		t.Fatal("key mismatch")
	}
}

type recordingDoer struct {
	lastURL string
	inner   *http.Client
	body    []byte
}

func (d *recordingDoer) Do(req *http.Request) (*http.Response, error) {
	d.lastURL = req.URL.String()
	if d.body != nil {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewReader(d.body)),
			Header:     make(http.Header),
			Request:    req,
		}, nil
	}
	return d.inner.Do(req)
}

func TestResolver_ResolveKeyID_CanonicalizesAuthority(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	set := jwks.SetFromEd25519PublicKey("example.com#key1", pub)
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

func TestURLForAuthority(t *testing.T) {
	got := jwks.URLForAuthority("https", "example.com")
	want := "https://example.com/.well-known/jwks.json"
	if got != want {
		t.Fatalf("URLForAuthority = %q, want %q", got, want)
	}
}

func TestFetchURL_Errors(t *testing.T) {
	t.Run("404", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.NotFound(w, r)
		}))
		defer srv.Close()

		_, err := jwks.FetchURL(context.Background(), srv.Client(), srv.URL+jwks.WellKnownPath)
		if err == nil || !strings.Contains(err.Error(), "status 404") {
			t.Fatalf("FetchURL() error = %v, want status 404", err)
		}
	})

	t.Run("invalid JSON", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"keys":[`))
		}))
		defer srv.Close()

		_, err := jwks.FetchURL(context.Background(), srv.Client(), srv.URL+jwks.WellKnownPath)
		if err == nil || !strings.Contains(err.Error(), "decode JSON") {
			t.Fatalf("FetchURL() error = %v, want decode JSON failure", err)
		}
	})

	t.Run("empty key set", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"keys":[]}`))
		}))
		defer srv.Close()

		_, err := jwks.FetchURL(context.Background(), srv.Client(), srv.URL+jwks.WellKnownPath)
		if err == nil || !strings.Contains(err.Error(), "empty key set") {
			t.Fatalf("FetchURL() error = %v, want empty key set", err)
		}
	})

	t.Run("nil client", func(t *testing.T) {
		_, err := jwks.FetchURL(context.Background(), nil, "https://example.com/.well-known/jwks.json")
		if !errors.Is(err, jwks.ErrNilHTTPClient) {
			t.Fatalf("FetchURL() error = %v, want ErrNilHTTPClient", err)
		}
	})

	t.Run("response too large", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(bytes.Repeat([]byte("a"), 64))
		}))
		defer srv.Close()

		_, err := jwks.FetchURLLimited(context.Background(), srv.Client(), srv.URL+jwks.WellKnownPath, 32)
		if !errors.Is(err, jwks.ErrResponseTooLarge) {
			t.Fatalf("FetchURLLimited() error = %v, want ErrResponseTooLarge", err)
		}
	})
}

func TestResolver_Resolve_MissingKid(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	set := jwks.SetFromEd25519PublicKey("example.com#key1", pub)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(set)
	}))
	defer srv.Close()

	scheme, authority, err := jwks.AuthorityFromBaseURL(srv.URL)
	if err != nil {
		t.Fatal(err)
	}

	resolver, err := jwks.NewResolver(srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	_, err = resolver.Resolve(context.Background(), scheme, authority, "example.com#missing")
	if !errors.Is(err, jwks.ErrKeyNotFound) {
		t.Fatalf("Resolve() error = %v, want ErrKeyNotFound", err)
	}
}

func TestFind_MissingKid(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	set := jwks.SetFromEd25519PublicKey("example.com#key1", pub)
	_, err = set.Find("example.com#missing")
	if !errors.Is(err, jwks.ErrKeyNotFound) {
		t.Fatalf("Find() error = %v, want ErrKeyNotFound", err)
	}
}

func TestResolver_RefreshesOnTTLExpiry(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	set := jwks.SetFromEd25519PublicKey("example.com#key1", pub)

	var fetches atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetches.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(set)
	}))
	defer srv.Close()

	scheme, authority, err := jwks.AuthorityFromBaseURL(srv.URL)
	if err != nil {
		t.Fatal(err)
	}

	resolver, err := jwks.NewResolverWithTTL(srv.Client(), 10*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := resolver.Resolve(ctx, scheme, authority, "example.com#key1"); err != nil {
		t.Fatalf("first Resolve: %v", err)
	}
	time.Sleep(15 * time.Millisecond)
	if _, err := resolver.Resolve(ctx, scheme, authority, "example.com#key1"); err != nil {
		t.Fatalf("second Resolve after TTL: %v", err)
	}
	if got := fetches.Load(); got != 2 {
		t.Fatalf("fetch count = %d, want 2 after TTL expiry", got)
	}
}

func TestResolver_RefetchesOnKidMiss(t *testing.T) {
	key1Pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	key2Pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	var version atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if version.Load() == 0 {
			_ = json.NewEncoder(w).Encode(jwks.SetFromEd25519PublicKey("example.com#key1", key1Pub))
			return
		}
		_ = json.NewEncoder(w).Encode(jwks.SetFromEd25519PublicKey("example.com#key2", key2Pub))
	}))
	defer srv.Close()

	scheme, authority, err := jwks.AuthorityFromBaseURL(srv.URL)
	if err != nil {
		t.Fatal(err)
	}

	resolver, err := jwks.NewResolverWithOptions(srv.Client(), jwks.ResolverOptions{
		TTL:                time.Hour,
		MinRefetchInterval: -1,
		NegativeCacheTTL:   -1,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	if _, err := resolver.Resolve(ctx, scheme, authority, "example.com#key1"); err != nil {
		t.Fatalf("Resolve key1: %v", err)
	}

	version.Store(1)
	got, err := resolver.Resolve(ctx, scheme, authority, "example.com#key2")
	if err != nil {
		t.Fatalf("Resolve key2 after rotation: %v", err)
	}
	if !key2Pub.Equal(got.PublicKey.(ed25519.PublicKey)) {
		t.Fatal("expected rotated key2 public key")
	}
}

func TestResolver_Resolve_KidMissRefreshFetchFailure(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	set := jwks.SetFromEd25519PublicKey("example.com#key1", pub)

	var fetches atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fetches.Add(1) == 1 {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(set)
			return
		}
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	scheme, authority, err := jwks.AuthorityFromBaseURL(srv.URL)
	if err != nil {
		t.Fatal(err)
	}

	resolver, err := jwks.NewResolverWithOptions(srv.Client(), jwks.ResolverOptions{
		TTL:                time.Hour,
		MinRefetchInterval: -1,
		NegativeCacheTTL:   -1,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	if _, err := resolver.Resolve(ctx, scheme, authority, "example.com#key1"); err != nil {
		t.Fatalf("initial Resolve: %v", err)
	}

	_, err = resolver.Resolve(ctx, scheme, authority, "example.com#missing")
	if err == nil {
		t.Fatal("Resolve() error = nil, want refresh fetch failure")
	}
	if strings.Contains(err.Error(), "not found") {
		t.Fatalf("Resolve() error = %v, want refresh fetch error not stale kid miss", err)
	}
	if !strings.Contains(err.Error(), "status 503") {
		t.Fatalf("Resolve() error = %v, want status 503 from refresh fetch", err)
	}
}

func TestFind_AmbiguousKid(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	set := jwks.Set{Keys: []jwks.Key{
		jwks.Ed25519Key("example.com#key1", pub),
		jwks.Ed25519Key("example.com#key1", pub),
	}}
	_, err = set.Find("example.com#key1")
	if !errors.Is(err, jwks.ErrAmbiguousKid) {
		t.Fatalf("Find() error = %v, want ErrAmbiguousKid", err)
	}
}

func TestFind_UseSigAndEnc(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	sigKey := jwks.Ed25519Key("example.com#key1", pub)
	if sigKey.Use != "sig" {
		t.Fatalf("Ed25519Key Use = %q, want sig", sigKey.Use)
	}
	got, err := jwks.Set{Keys: []jwks.Key{sigKey}}.Find("example.com#key1")
	if err != nil {
		t.Fatalf("use=sig Find: %v", err)
	}
	if got.Algorithm != sigalg.Ed25519 {
		t.Fatalf("Algorithm = %q", got.Algorithm)
	}

	encOnly := jwks.Ed25519Key("example.com#key1", pub)
	encOnly.Use = "enc"
	_, err = jwks.Set{Keys: []jwks.Key{encOnly}}.Find("example.com#key1")
	if !errors.Is(err, jwks.ErrKeyNotFound) {
		t.Fatalf("use=enc Find error = %v, want ErrKeyNotFound", err)
	}

	emptyUse := jwks.Ed25519Key("example.com#key1", pub)
	emptyUse.Use = ""
	if _, err := (jwks.Set{Keys: []jwks.Key{emptyUse}}).Find("example.com#key1"); err != nil {
		t.Fatalf("empty use Find: %v", err)
	}
}

func TestFind_ECP256AndRSA(t *testing.T) {
	ecPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	x := base64.RawURLEncoding.EncodeToString(padCoord(ecPriv.X.Bytes(), 32))
	y := base64.RawURLEncoding.EncodeToString(padCoord(ecPriv.Y.Bytes(), 32))
	ecSet := jwks.Set{Keys: []jwks.Key{{
		Kty: "EC", Kid: "example.com#ec1", Use: "sig", Alg: "ES256", Crv: "P-256", X: x, Y: y,
	}}}
	got, err := ecSet.Find("example.com#ec1")
	if err != nil {
		t.Fatalf("EC Find: %v", err)
	}
	if got.Algorithm != sigalg.ECDSAP256SHA256 {
		t.Fatalf("EC Algorithm = %q", got.Algorithm)
	}
	if _, ok := got.PublicKey.(*ecdsa.PublicKey); !ok {
		t.Fatalf("EC PublicKey type %T", got.PublicKey)
	}

	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	n := base64.RawURLEncoding.EncodeToString(rsaPriv.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(rsaPriv.E)).Bytes())
	rsaNoAlg := jwks.Set{Keys: []jwks.Key{{
		Kty: "RSA", Kid: "example.com#rsa1", Use: "sig", N: n, E: e,
	}}}
	got, err = rsaNoAlg.Find("example.com#rsa1")
	if err != nil {
		t.Fatalf("RSA Find: %v", err)
	}
	if got.Algorithm != "" {
		t.Fatalf("RSA without alg Algorithm = %q, want empty", got.Algorithm)
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

func TestResolver_CooldownBlocksForcedRefetchForNewKid(t *testing.T) {
	key1Pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	key2Pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	var version atomic.Int32
	var fetches atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetches.Add(1)
		w.Header().Set("Content-Type", "application/json")
		if version.Load() == 0 {
			_ = json.NewEncoder(w).Encode(jwks.SetFromEd25519PublicKey("example.com#key1", key1Pub))
			return
		}
		_ = json.NewEncoder(w).Encode(jwks.SetFromEd25519PublicKey("example.com#key2", key2Pub))
	}))
	defer srv.Close()

	scheme, authority, err := jwks.AuthorityFromBaseURL(srv.URL)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Unix(1_700_000_000, 0)
	resolver, err := jwks.NewResolverWithOptions(srv.Client(), jwks.ResolverOptions{
		TTL:                time.Hour,
		MinRefetchInterval: time.Minute,
		NegativeCacheTTL:   -1,
		Now:                func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := resolver.Resolve(ctx, scheme, authority, "example.com#key1"); err != nil {
		t.Fatalf("Resolve key1: %v", err)
	}
	if got := fetches.Load(); got != 1 {
		t.Fatalf("fetches after key1 = %d, want 1", got)
	}

	version.Store(1)
	_, err = resolver.Resolve(ctx, scheme, authority, "example.com#key2")
	if !errors.Is(err, jwks.ErrKeyNotFound) {
		t.Fatalf("Resolve new kid during cooldown = %v, want ErrKeyNotFound", err)
	}
	if got := fetches.Load(); got != 1 {
		t.Fatalf("fetches during cooldown = %d, want 1 (no forced refetch)", got)
	}

	now = now.Add(time.Minute)
	got, err := resolver.Resolve(ctx, scheme, authority, "example.com#key2")
	if err != nil {
		t.Fatalf("Resolve key2 after cooldown: %v", err)
	}
	if !key2Pub.Equal(got.PublicKey.(ed25519.PublicKey)) {
		t.Fatal("expected rotated key2 after cooldown")
	}
	if gotFetches := fetches.Load(); gotFetches != 2 {
		t.Fatalf("fetches after cooldown = %d, want 2", gotFetches)
	}
}

func TestResolver_NegativeCacheSkipsRefetch(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	set := jwks.SetFromEd25519PublicKey("example.com#key1", pub)

	var fetches atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetches.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(set)
	}))
	defer srv.Close()

	scheme, authority, err := jwks.AuthorityFromBaseURL(srv.URL)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Unix(1_700_000_000, 0)
	resolver, err := jwks.NewResolverWithOptions(srv.Client(), jwks.ResolverOptions{
		TTL:                time.Hour,
		MinRefetchInterval: -1,
		NegativeCacheTTL:   time.Minute,
		Now:                func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := resolver.Resolve(ctx, scheme, authority, "example.com#key1"); err != nil {
		t.Fatalf("Resolve key1: %v", err)
	}
	baseFetches := fetches.Load()

	_, err = resolver.Resolve(ctx, scheme, authority, "example.com#missing")
	if !errors.Is(err, jwks.ErrKeyNotFound) {
		t.Fatalf("first miss = %v, want ErrKeyNotFound", err)
	}
	afterMiss := fetches.Load()
	if afterMiss <= baseFetches {
		t.Fatalf("expected forced refetch on first miss, fetches=%d base=%d", afterMiss, baseFetches)
	}

	_, err = resolver.Resolve(ctx, scheme, authority, "example.com#missing")
	if !errors.Is(err, jwks.ErrKeyNotFound) {
		t.Fatalf("negative-cached miss = %v, want ErrKeyNotFound", err)
	}
	if fetches.Load() != afterMiss {
		t.Fatalf("negative cache should skip refetch, fetches=%d want %d", fetches.Load(), afterMiss)
	}
}

func TestResolver_SingleflightCoalescesConcurrentFetches(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	set := jwks.SetFromEd25519PublicKey("example.com#key1", pub)

	started := make(chan struct{})
	var startOnce sync.Once
	release := make(chan struct{})
	var fetches atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetches.Add(1)
		startOnce.Do(func() { close(started) })
		<-release
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(set)
	}))
	defer srv.Close()

	scheme, authority, err := jwks.AuthorityFromBaseURL(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	resolver, err := jwks.NewResolverWithOptions(srv.Client(), jwks.ResolverOptions{
		TTL:                time.Hour,
		MinRefetchInterval: -1,
		NegativeCacheTTL:   -1,
	})
	if err != nil {
		t.Fatal(err)
	}

	errCh := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() {
			_, err := resolver.Resolve(context.Background(), scheme, authority, "example.com#key1")
			errCh <- err
		}()
	}
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for JWKS fetch to start")
	}
	close(release)
	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil {
			t.Fatalf("Resolve: %v", err)
		}
	}
	if got := fetches.Load(); got != 1 {
		t.Fatalf("fetches = %d, want 1 (singleflight)", got)
	}
}
