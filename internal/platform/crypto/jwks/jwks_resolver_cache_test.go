// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package jwks_test

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	tshttp "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/http"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/jwks"
)

func TestResolver_RefreshesOnTTLExpiry(t *testing.T) {
	t.Parallel()
	pub, _ := mustEd25519KeyPair(t)
	set := jwks.SetFromEd25519PublicKey(testJWKSKey1, pub)

	var fetches atomic.Int32

	srv := httptest.NewServer(jwksJSONHandlerWithBefore(set, func() { fetches.Add(1) }))
	defer srv.Close()

	jwksURL := srv.URL + "/jwks"

	resolver, err := jwks.NewResolverWithTTL(srv.Client(), 10*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	if _, err := resolver.ResolveURL(ctx, jwksURL, testJWKSKey1); err != nil {
		t.Fatalf("first ResolveURL: %v", err)
	}

	time.Sleep(15 * time.Millisecond)

	if _, err := resolver.ResolveURL(ctx, jwksURL, testJWKSKey1); err != nil {
		t.Fatalf("second ResolveURL after TTL: %v", err)
	}

	if got := fetches.Load(); got != 2 {
		t.Fatalf("fetch count = %d, want 2 after TTL expiry", got)
	}
}

func TestResolver_RefetchesOnKidMiss(t *testing.T) {
	t.Parallel()
	key1Pub, key2Pub := mustTwoEd25519PublicKeys(t)

	var version atomic.Int32

	srv := httptest.NewServer(twoKeyRotationHandler(&version, key1Pub, key2Pub))
	defer srv.Close()

	jwksURL := srv.URL + "/jwks"

	resolver, err := jwks.NewResolverWithOptions(srv.Client(), jwks.ResolverOptions{
		TTL:                time.Hour,
		MinRefetchInterval: -1,
		NegativeCacheTTL:   -1,
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()

	if _, rerr := resolver.ResolveURL(ctx, jwksURL, testJWKSKey1); rerr != nil {
		t.Fatalf("ResolveURL key1: %v", rerr)
	}

	version.Store(1)

	got, err := resolver.ResolveURL(ctx, jwksURL, testJWKSKey2)
	if err != nil {
		t.Fatalf("ResolveURL key2 after rotation: %v", err)
	}

	gotPub, ok := got.PublicKey.(ed25519.PublicKey)
	if !ok {
		t.Fatal("expected ed25519 public key")
	}

	if !key2Pub.Equal(gotPub) {
		t.Fatal("expected rotated key2 public key")
	}
}

func TestResolver_Resolve_KidMissRefreshFetchFailure(t *testing.T) {
	t.Parallel()
	pub, _ := mustEd25519KeyPair(t)
	set := jwks.SetFromEd25519PublicKey(testJWKSKey1, pub)

	var fetches atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if fetches.Add(1) == 1 {
			w.Header().Set("Content-Type", "application/json")
			tshttp.WriteJSON(w, set)

			return
		}

		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	jwksURL := srv.URL + "/jwks"

	resolver, err := jwks.NewResolverWithOptions(srv.Client(), jwks.ResolverOptions{
		TTL:                time.Hour,
		MinRefetchInterval: -1,
		NegativeCacheTTL:   -1,
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()

	if _, rerr := resolver.ResolveURL(ctx, jwksURL, testJWKSKey1); rerr != nil {
		t.Fatalf("initial ResolveURL: %v", rerr)
	}

	_, err = resolver.ResolveURL(ctx, jwksURL, "example.com#missing")
	if err == nil {
		t.Fatal("ResolveURL() error = nil, want refresh fetch failure")
	}

	if strings.Contains(err.Error(), "not found") {
		t.Fatalf("ResolveURL() error = %v, want refresh fetch error not stale kid miss", err)
	}

	if !strings.Contains(err.Error(), "status 503") {
		t.Fatalf("ResolveURL() error = %v, want status 503 from refresh fetch", err)
	}
}

func TestResolver_CooldownBlocksForcedRefetchForNewKid(t *testing.T) {
	t.Parallel()
	key1Pub, key2Pub := mustTwoEd25519PublicKeys(t)

	var (
		version atomic.Int32
		fetches atomic.Int32
	)

	handler := twoKeyRotationHandler(&version, key1Pub, key2Pub)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetches.Add(1)
		handler(w, r)
	}))
	defer srv.Close()

	jwksURL := srv.URL + "/jwks"

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
	if _, rerr := resolver.ResolveURL(ctx, jwksURL, testJWKSKey1); rerr != nil {
		t.Fatalf("ResolveURL key1: %v", rerr)
	}

	if got := fetches.Load(); got != 1 {
		t.Fatalf("fetches after key1 = %d, want 1", got)
	}

	version.Store(1)

	_, err = resolver.ResolveURL(ctx, jwksURL, testJWKSKey2)
	if !errors.Is(err, jwks.ErrKeyNotFound) {
		t.Fatalf("ResolveURL new kid during cooldown = %v, want ErrKeyNotFound", err)
	}

	if got := fetches.Load(); got != 1 {
		t.Fatalf("fetches during cooldown = %d, want 1 (no forced refetch)", got)
	}

	now = now.Add(time.Minute)

	got, err := resolver.ResolveURL(ctx, jwksURL, testJWKSKey2)
	if err != nil {
		t.Fatalf("ResolveURL key2 after cooldown: %v", err)
	}

	gotPub, ok := got.PublicKey.(ed25519.PublicKey)
	if !ok {
		t.Fatal("expected ed25519 public key")
	}

	if !key2Pub.Equal(gotPub) {
		t.Fatal("expected rotated key2 after cooldown")
	}

	if gotFetches := fetches.Load(); gotFetches != 2 {
		t.Fatalf("fetches after cooldown = %d, want 2", gotFetches)
	}
}

func TestResolver_NegativeCacheSkipsRefetch(t *testing.T) {
	t.Parallel()
	pub, _ := mustEd25519KeyPair(t)
	set := jwks.SetFromEd25519PublicKey(testJWKSKey1, pub)

	var fetches atomic.Int32

	srv := httptest.NewServer(jwksJSONHandlerWithBefore(set, func() { fetches.Add(1) }))
	defer srv.Close()

	jwksURL := srv.URL + "/jwks"

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
	if _, rerr := resolver.ResolveURL(ctx, jwksURL, testJWKSKey1); rerr != nil {
		t.Fatalf("ResolveURL key1: %v", rerr)
	}

	baseFetches := fetches.Load()

	_, err = resolver.ResolveURL(ctx, jwksURL, "example.com#missing")
	if !errors.Is(err, jwks.ErrKeyNotFound) {
		t.Fatalf("first miss = %v, want ErrKeyNotFound", err)
	}

	afterMiss := fetches.Load()
	if afterMiss <= baseFetches {
		t.Fatalf("expected forced refetch on first miss, fetches=%d base=%d", afterMiss, baseFetches)
	}

	_, err = resolver.ResolveURL(ctx, jwksURL, "example.com#missing")
	if !errors.Is(err, jwks.ErrKeyNotFound) {
		t.Fatalf("negative-cached miss = %v, want ErrKeyNotFound", err)
	}

	if fetches.Load() != afterMiss {
		t.Fatalf("negative cache should skip refetch, fetches=%d want %d", fetches.Load(), afterMiss)
	}
}

func TestResolver_SingleflightCoalescesConcurrentFetches(t *testing.T) {
	t.Parallel()
	pub, _ := mustEd25519KeyPair(t)
	set := jwks.SetFromEd25519PublicKey(testJWKSKey1, pub)

	started := make(chan struct{})

	var startOnce sync.Once

	release := make(chan struct{})

	var fetches atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fetches.Add(1)
		startOnce.Do(func() { close(started) })
		<-release
		w.Header().Set("Content-Type", "application/json")
		tshttp.WriteJSON(w, set)
	}))
	defer srv.Close()

	jwksURL := srv.URL + "/jwks"

	resolver, err := jwks.NewResolverWithOptions(srv.Client(), jwks.ResolverOptions{
		TTL:                time.Hour,
		MinRefetchInterval: -1,
		NegativeCacheTTL:   -1,
	})
	if err != nil {
		t.Fatal(err)
	}

	errCh := make(chan error, 2)

	for range 2 {
		go func() {
			_, err := resolver.ResolveURL(context.Background(), jwksURL, testJWKSKey1)
			errCh <- err
		}()
	}

	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for JWKS fetch to start")
	}

	close(release)

	for range 2 {
		if err := <-errCh; err != nil {
			t.Fatalf("ResolveURL: %v", err)
		}
	}

	if got := fetches.Load(); got != 1 {
		t.Fatalf("fetches = %d, want 1 (singleflight)", got)
	}
}
