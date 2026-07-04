package jwks_test

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/jwks"
)

func TestSetFromEd25519PublicKey_FindEd25519(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	set := jwks.SetFromEd25519PublicKey("example.com#key1", pub)
	got, err := set.FindEd25519("example.com#key1")
	if err != nil {
		t.Fatalf("FindEd25519: %v", err)
	}
	if !pub.Equal(got) {
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
	key, err := got.FindEd25519("example.com#key1")
	if err != nil {
		t.Fatalf("FindEd25519: %v", err)
	}
	if !pub.Equal(key) {
		t.Fatal("key mismatch")
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

	resolver := jwks.NewResolver(srv.Client())
	got, err := resolver.Resolve(context.Background(), scheme, authority, "example.com#key1")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !pub.Equal(got) {
		t.Fatal("key mismatch")
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

	resolver := jwks.NewResolver(srv.Client())
	_, err = resolver.Resolve(context.Background(), scheme, authority, "example.com#missing")
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("Resolve() error = %v, want kid not found", err)
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

	resolver := jwks.NewResolverWithTTL(srv.Client(), 10*time.Millisecond)
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

	resolver := jwks.NewResolver(srv.Client())
	ctx := context.Background()

	if _, err := resolver.Resolve(ctx, scheme, authority, "example.com#key1"); err != nil {
		t.Fatalf("Resolve key1: %v", err)
	}

	version.Store(1)
	got, err := resolver.Resolve(ctx, scheme, authority, "example.com#key2")
	if err != nil {
		t.Fatalf("Resolve key2 after rotation: %v", err)
	}
	if !key2Pub.Equal(got) {
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

	resolver := jwks.NewResolver(srv.Client())
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
