// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package jwks_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/jwks"
)

type countingDoer struct {
	body  []byte
	mu    sync.Mutex
	calls map[string]int
}

func (d *countingDoer) Do(req *http.Request) (*http.Response, error) {
	d.mu.Lock()
	d.calls[req.URL.String()]++
	d.mu.Unlock()

	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewReader(d.body)),
		Header:     make(http.Header),
		Request:    req,
	}, nil
}

func (d *countingDoer) callCount(url string) int {
	d.mu.Lock()
	defer d.mu.Unlock()

	return d.calls[url]
}

func (d *countingDoer) totalCalls() int {
	d.mu.Lock()
	defer d.mu.Unlock()

	total := 0
	for _, n := range d.calls {
		total += n
	}

	return total
}

func mustCountingDoer(t *testing.T) *countingDoer {
	t.Helper()

	pub, _ := mustEd25519KeyPair(t)
	set := jwks.SetFromEd25519PublicKey(testJWKSKey1, pub)

	body, err := json.Marshal(set)
	if err != nil {
		t.Fatal(err)
	}

	return &countingDoer{body: body, calls: map[string]int{}}
}

func TestResolver_CacheEvictsOldestURLBeyondCap(t *testing.T) {
	t.Parallel()
	doer := mustCountingDoer(t)

	resolver, err := jwks.NewResolverWithOptions(doer, jwks.ResolverOptions{TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}

	urlAt := func(i int) string {
		return fmt.Sprintf("https://peer-%d.example.com/jwks", i)
	}

	ctx := context.Background()
	for i := 0; i <= jwks.DefaultMaxCacheEntries; i++ {
		if _, err := resolver.ResolveURL(ctx, urlAt(i), testJWKSKey1); err != nil {
			t.Fatalf("ResolveURL %d: %v", i, err)
		}
	}

	// The first URL was evicted once the cap was exceeded; resolving it again
	// must refetch.
	if _, err := resolver.ResolveURL(ctx, urlAt(0), testJWKSKey1); err != nil {
		t.Fatalf("re-resolve evicted URL: %v", err)
	}

	if got := doer.callCount(urlAt(0)); got != 2 {
		t.Fatalf("fetches for evicted URL = %d, want 2", got)
	}

	// The most recent URL survives; resolving it again must hit the cache.
	if _, err := resolver.ResolveURL(ctx, urlAt(jwks.DefaultMaxCacheEntries), testJWKSKey1); err != nil {
		t.Fatalf("re-resolve cached URL: %v", err)
	}

	if got := doer.callCount(urlAt(jwks.DefaultMaxCacheEntries)); got != 1 {
		t.Fatalf("fetches for cached URL = %d, want 1", got)
	}
}

func TestResolver_NegativeCacheEvictsBeyondCap(t *testing.T) {
	t.Parallel()
	doer := mustCountingDoer(t)

	resolver, err := jwks.NewResolverWithOptions(doer, jwks.ResolverOptions{
		TTL:                time.Hour,
		MinRefetchInterval: -1,
		NegativeCacheTTL:   time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}

	const jwksURL = "https://peer.example.com/jwks"

	missingAt := func(i int) string {
		return fmt.Sprintf("example.com#missing-%d", i)
	}

	ctx := context.Background()
	if _, err := resolver.ResolveURL(ctx, jwksURL, testJWKSKey1); err != nil {
		t.Fatalf("ResolveURL key1: %v", err)
	}

	for i := 0; i <= jwks.DefaultMaxNegativeEntries; i++ {
		if _, err := resolver.ResolveURL(ctx, jwksURL, missingAt(i)); !errors.Is(err, jwks.ErrKeyNotFound) {
			t.Fatalf("ResolveURL %s = %v, want ErrKeyNotFound", missingAt(i), err)
		}
	}

	baseCalls := doer.totalCalls()

	// The oldest negative entry was evicted beyond the cap, so its repeat
	// miss forces a refetch.
	if _, err := resolver.ResolveURL(ctx, jwksURL, missingAt(0)); !errors.Is(err, jwks.ErrKeyNotFound) {
		t.Fatalf("repeat of evicted miss = %v, want ErrKeyNotFound", err)
	}

	if got := doer.totalCalls(); got != baseCalls+1 {
		t.Fatalf("fetches after evicted miss = %d, want %d", got, baseCalls+1)
	}

	// The newest negative entry survives; its repeat miss must not refetch.
	if _, err := resolver.ResolveURL(ctx, jwksURL, missingAt(jwks.DefaultMaxNegativeEntries)); !errors.Is(err, jwks.ErrKeyNotFound) {
		t.Fatalf("repeat of cached miss = %v, want ErrKeyNotFound", err)
	}

	if got := doer.totalCalls(); got != baseCalls+1 {
		t.Fatalf("fetches after cached miss = %d, want %d", got, baseCalls+1)
	}
}

func TestResolver_ExpiredCacheReadDoesNotPromote(t *testing.T) {
	t.Parallel()

	// Polling an expired URL must not refresh LRU recency. Otherwise a stale
	// entry stays hot after a failed refetch and younger live entries evict.

	flip := &flipDoer{ok: mustCountingDoer(t)}
	now := time.Unix(1_700_000_000, 0)

	resolver, err := jwks.NewResolverWithOptions(flip, jwks.ResolverOptions{
		TTL:                100 * time.Second,
		MinRefetchInterval: -1,
		NegativeCacheTTL:   -1,
		Now:                func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}

	urlAt := func(i int) string {
		return fmt.Sprintf("https://peer-%d.example.com/jwks", i)
	}

	ctx := context.Background()
	if _, err := resolver.ResolveURL(ctx, urlAt(0), testJWKSKey1); err != nil {
		t.Fatalf("ResolveURL keep: %v", err)
	}

	now = now.Add(50 * time.Second)

	for i := 1; i < jwks.DefaultMaxCacheEntries; i++ {
		if _, err := resolver.ResolveURL(ctx, urlAt(i), testJWKSKey1); err != nil {
			t.Fatalf("ResolveURL %d: %v", i, err)
		}
	}

	now = now.Add(60 * time.Second)
	flip.fail = true

	if _, err := resolver.ResolveURL(ctx, urlAt(0), testJWKSKey1); err == nil {
		t.Fatal("ResolveURL expired keep: want fetch error")
	}

	flip.fail = false

	newURL := urlAt(jwks.DefaultMaxCacheEntries)
	if _, err := resolver.ResolveURL(ctx, newURL, testJWKSKey1); err != nil {
		t.Fatalf("ResolveURL filler: %v", err)
	}

	liveURL := urlAt(1)
	before := flip.ok.callCount(liveURL)

	if _, err := resolver.ResolveURL(ctx, liveURL, testJWKSKey1); err != nil {
		t.Fatalf("ResolveURL live: %v", err)
	}

	if got := flip.ok.callCount(liveURL); got != before {
		t.Fatalf(
			"fetches for live URL = %d, want %d (expired keep must not stay promoted and force live eviction)",
			got,
			before,
		)
	}
}

type flipDoer struct {
	ok   *countingDoer
	fail bool
}

func (d *flipDoer) Do(req *http.Request) (*http.Response, error) {
	if d.fail {
		return nil, errors.New("jwks: injected fetch failure")
	}

	return d.ok.Do(req)
}

func TestResolver_ConcurrentResolve(t *testing.T) {
	t.Parallel()
	doer := mustCountingDoer(t)

	resolver, err := jwks.NewResolverWithOptions(doer, jwks.ResolverOptions{
		TTL:                time.Hour,
		MinRefetchInterval: time.Millisecond,
		NegativeCacheTTL:   time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup

	for g := range 8 {
		wg.Add(1)

		go func() {
			defer wg.Done()

			for i := range 25 {
				jwksURL := fmt.Sprintf("https://peer-%d.example.com/jwks", (g+i)%4)

				if _, err := resolver.ResolveURL(context.Background(), jwksURL, testJWKSKey1); err != nil {
					t.Errorf("ResolveURL %s: %v", jwksURL, err)
				}

				// Misses exercise the negative cache and the forced-refetch
				// path concurrently with cache hits.
				if _, err := resolver.ResolveURL(context.Background(), jwksURL, "example.com#missing"); !errors.Is(err, jwks.ErrKeyNotFound) {
					t.Errorf("ResolveURL missing kid %s: %v, want ErrKeyNotFound", jwksURL, err)
				}
			}
		}()
	}

	wg.Wait()
}
