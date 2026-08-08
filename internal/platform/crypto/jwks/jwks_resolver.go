// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package jwks

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/sigalg"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/hostport"
)

// ResolveURL fetches the JWKS at the explicit advertised URL and returns the
// key whose kid exactly equals the keyID signature parameter.
func (r *Resolver) ResolveURL(
	ctx context.Context,
	jwksURL, kid string,
) (sigalg.ResolvedPublicKey, error) {
	if r.negativeHit(jwksURL, kid) {
		return sigalg.ResolvedPublicKey{}, fmt.Errorf("jwks: key %q not found: %w", kid, ErrKeyNotFound)
	}

	set, _, err := r.loadSet(ctx, jwksURL, false)
	if err != nil {
		return sigalg.ResolvedPublicKey{}, err
	}

	pub, err := set.ResolveExactKeyID(kid)
	if err == nil {
		return pub, nil
	}

	if !errors.Is(err, ErrKeyNotFound) {
		return sigalg.ResolvedPublicKey{}, err
	}

	// Re-fetch once on kid miss so rotated keys can be picked up.
	// minRefetchInterval may reuse the cached document instead.
	set, fresh, refreshErr := r.loadSet(ctx, jwksURL, true)
	if refreshErr != nil {
		return sigalg.ResolvedPublicKey{}, refreshErr
	}

	pub, err = set.ResolveExactKeyID(kid)
	if errors.Is(err, ErrKeyNotFound) && fresh {
		r.rememberNegative(jwksURL, kid)
	}

	return pub, err
}

func (r *Resolver) loadSet(ctx context.Context, jwksURL string, forceRefresh bool) (Set, bool, error) {
	now := r.now()
	if set, ok := r.cachedSet(jwksURL, forceRefresh, now); ok {
		return set, false, nil
	}

	type result struct {
		set   Set
		fresh bool
	}

	v, err, _ := r.group.Do(jwksURL, func() (any, error) {
		now := r.now()
		if set, ok := r.cachedSet(jwksURL, forceRefresh, now); ok {
			return result{set: set, fresh: false}, nil
		}

		set, err := FetchURLLimited(ctx, r.client, jwksURL, r.maxResponseBytes)
		if err != nil {
			return nil, err
		}

		fetchedAt := r.now()
		r.mu.Lock()
		r.cache.Set(jwksURL, cacheEntry{set: set, fetchedAt: fetchedAt})
		r.mu.Unlock()

		return result{set: set, fresh: true}, nil
	})
	if err != nil {
		return Set{}, false, err
	}

	out, ok := v.(result)
	if !ok {
		return Set{}, false, errors.New("jwks: unexpected cache value type")
	}

	return out.set, out.fresh, nil
}

func (r *Resolver) cachedSet(jwksURL string, forceRefresh bool, now time.Time) (Set, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Peek so a TTL miss cannot promote a stale entry and keep it from
	// eviction under polling.
	entry, ok := r.cache.Peek(jwksURL)
	if !ok {
		return Set{}, false
	}

	if !forceRefresh {
		if now.Sub(entry.fetchedAt) < r.ttl {
			_, _ = r.cache.Get(jwksURL)

			return entry.set, true
		}

		r.cache.Delete(jwksURL)

		return Set{}, false
	}

	if r.minRefetchInterval > 0 && now.Sub(entry.fetchedAt) < r.minRefetchInterval {
		_, _ = r.cache.Get(jwksURL)

		return entry.set, true
	}

	return Set{}, false
}

func negativeKey(jwksURL, kid string) string {
	return jwksURL + "\x00" + kid
}

func (r *Resolver) negativeHit(jwksURL, kid string) bool {
	if r.negativeTTL <= 0 {
		return false
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	key := negativeKey(jwksURL, kid)

	until, ok := r.negative.Peek(key)
	if !ok {
		return false
	}

	if !r.now().Before(until) {
		r.negative.Delete(key)

		return false
	}

	_, _ = r.negative.Get(key)

	return true
}

func (r *Resolver) rememberNegative(jwksURL, kid string) {
	if r.negativeTTL <= 0 {
		return
	}

	r.mu.Lock()
	r.negative.Set(negativeKey(jwksURL, kid), r.now().Add(r.negativeTTL))
	r.mu.Unlock()
}

// AuthorityFromBaseURL extracts scheme and hostport-normalized authority from
// an absolute base URL (path and query are ignored).
func AuthorityFromBaseURL(baseURL string) (scheme, authority string, err error) {
	u, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil {
		return "", "", err
	}

	scheme = strings.ToLower(u.Scheme)
	if scheme == "" || u.Host == "" {
		return "", "", fmt.Errorf("jwks: invalid base URL %q", baseURL)
	}

	authority, err = hostport.Normalize(u.Host, scheme)
	if err != nil {
		return "", "", fmt.Errorf("jwks: normalize authority from %q: %w", baseURL, err)
	}

	return scheme, authority, nil
}
