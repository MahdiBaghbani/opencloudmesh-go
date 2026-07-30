// Package jwks publishes and resolves public keys in RFC 7517 format.
package jwks

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/keyid"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/sigalg"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/hostport"
)

const (
	// DefaultCacheTTL is how long a fetched JWKS document is reused before refresh.
	DefaultCacheTTL = 1 * time.Minute
	// DefaultMinRefetchInterval caps forced refetch frequency after a kid miss.
	DefaultMinRefetchInterval = 30 * time.Second
	// DefaultNegativeCacheTTL is how long a kid miss is remembered per JWKS URL.
	DefaultNegativeCacheTTL = 30 * time.Second
)

// Key is a single RFC 7517 JSON Web Key entry.
type Key struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use,omitempty"`
	Alg string `json:"alg,omitempty"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
}

// Set is a JSON Web Key Set.
type Set struct {
	Keys []Key `json:"keys"`
}

// Ed25519Key builds a JWKS key entry from an Ed25519 public key.
// The produced JWK includes the required alg parameter per OCM signing
// requirements: every JWK must carry kid and alg, and alg is authoritative.
// See https://github.com/cs3org/OCM-API/blob/6a0586183cbef10ecae9dedc42561806447eb2f5/IETF-OCM.md#L876-L887
func Ed25519Key(kid string, pub ed25519.PublicKey) Key {
	return Key{
		Kty: "OKP",
		Crv: "Ed25519",
		Kid: kid,
		Use: "sig",
		Alg: "Ed25519",
		X:   encodeBase64URL(pub),
	}
}

// SetFromEd25519PublicKey returns a single-key JWKS for the given kid.
func SetFromEd25519PublicKey(kid string, pub ed25519.PublicKey) Set {
	return Set{Keys: []Key{Ed25519Key(kid, pub)}}
}

// MarshalJSON encodes the JWKS set.
func (s Set) MarshalJSON() ([]byte, error) {
	if s.Keys == nil {
		s.Keys = []Key{}
	}

	return json.Marshal(struct {
		Keys []Key `json:"keys"`
	}{Keys: s.Keys})
}

// ErrKeyNotFound indicates the JWKS document does not contain the requested kid.
var ErrKeyNotFound = errors.New("jwks: key not found")

// ErrAmbiguousKid indicates more than one JWKS entry matched the requested kid.
var ErrAmbiguousKid = errors.New("jwks: ambiguous kid")

// ErrNilHTTPClient indicates JWKS fetch was attempted without an HTTP client.
var ErrNilHTTPClient = errors.New("jwks: nil HTTP client")

// ErrResponseTooLarge indicates the JWKS response exceeded the configured size limit.
var ErrResponseTooLarge = errors.New("jwks: response too large")

// Find resolves a public key by JWKS kid into a ResolvedPublicKey.
//
// Find is a compatibility wrapper around ResolveExactKeyID: the OCM contract
// requires the keyid signature parameter to equal the JWK kid, so lookup is
// exact.
func (s Set) Find(kid string) (sigalg.ResolvedPublicKey, error) {
	return s.ResolveExactKeyID(kid)
}

// ResolveExactKeyID resolves a public key by exact keyID equality against
// each JWK kid in the set, per the OCM requirement that the keyid signature
// parameter equal the corresponding JWK kid. A keyID that is not byte-for-byte
// equal to a set kid is rejected with ErrKeyNotFound; no normalization or
// fuzzy matching is applied. Duplicate exact-kid matches are rejected. Keys
// with use set to a value other than "sig" are ignored for verification
// lookup.
// See https://github.com/cs3org/OCM-API/blob/6a0586183cbef10ecae9dedc42561806447eb2f5/IETF-OCM.md#L846-L848
// See https://github.com/cs3org/OCM-API/blob/6a0586183cbef10ecae9dedc42561806447eb2f5/IETF-OCM.md#L928-L933
func (s Set) ResolveExactKeyID(keyID string) (sigalg.ResolvedPublicKey, error) {
	var matches []Key

	for _, key := range s.Keys {
		if !keyid.KidEqualsExact(keyID, key.Kid) {
			continue
		}

		if key.Use != "" && !strings.EqualFold(key.Use, "sig") {
			continue
		}

		matches = append(matches, key)
	}

	if len(matches) == 0 {
		return sigalg.ResolvedPublicKey{}, fmt.Errorf("jwks: key %q not found: %w", keyID, ErrKeyNotFound)
	}

	if len(matches) > 1 {
		return sigalg.ResolvedPublicKey{}, fmt.Errorf("jwks: ambiguous kid %q (%d matches): %w", keyID, len(matches), ErrAmbiguousKid)
	}

	key := matches[0]

	// Validate the JWK alg before parsing key material. The JWK alg is the
	// authority; missing, unsupported, or incompatible values must be
	// rejected before the key is handed to the verifier.
	// See https://github.com/cs3org/OCM-API/blob/6a0586183cbef10ecae9dedc42561806447eb2f5/IETF-OCM.md#L876-L914
	alg, err := sigalg.DeriveFromJWK(key.Kty, key.Crv, key.Alg)
	if err != nil {
		return sigalg.ResolvedPublicKey{}, err
	}

	pub, err := sigalg.PublicKeyFromJWKFields(sigalg.JWKPublicKeyFields{
		Kty: key.Kty,
		Crv: key.Crv,
		Alg: key.Alg,
		X:   key.X,
		Y:   key.Y,
		N:   key.N,
		E:   key.E,
	})
	if err != nil {
		return sigalg.ResolvedPublicKey{}, err
	}

	return sigalg.ResolvedPublicKey{
		KeyID:     key.Kid,
		Algorithm: alg,
		PublicKey: pub,
		JWKKty:    key.Kty,
		JWKCrv:    key.Crv,
		JWKAlg:    key.Alg,
	}, nil
}

// HTTPDoer performs outbound HTTP requests for JWKS fetch.
type HTTPDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type cacheEntry struct {
	set       Set
	fetchedAt time.Time
}

// ResolverOptions configures remote JWKS cache and fetch policy.
// Zero TTL / MinRefetchInterval / NegativeCacheTTL / MaxResponseBytes select
// package defaults. Negative durations disable min-refetch cooldown or
// negative-kid caching.
type ResolverOptions struct {
	TTL                time.Duration
	MinRefetchInterval time.Duration
	NegativeCacheTTL   time.Duration
	MaxResponseBytes   int64
	Now                func() time.Time
}

// Resolver fetches and caches remote JWKS documents.
type Resolver struct {
	mu                 sync.RWMutex
	cache              map[string]cacheEntry
	negative           map[string]time.Time
	lastFetchAt        map[string]time.Time
	client             HTTPDoer
	ttl                time.Duration
	minRefetchInterval time.Duration
	negativeTTL        time.Duration
	maxResponseBytes   int64
	now                func() time.Time
	group              singleflight.Group
}

// NewResolver creates a JWKS resolver backed by client.
func NewResolver(client HTTPDoer) (*Resolver, error) {
	return NewResolverWithOptions(client, ResolverOptions{})
}

// NewResolverWithTTL creates a JWKS resolver with an explicit cache TTL.
func NewResolverWithTTL(client HTTPDoer, ttl time.Duration) (*Resolver, error) {
	return NewResolverWithOptions(client, ResolverOptions{TTL: ttl})
}

// EffectiveOptions returns the cache and fetch policy actually enforced by
// this resolver, after zero-value inputs from NewResolverWithOptions have
// been replaced by package defaults. Callers use this to assert that
// production wiring stays bounded (non-zero TTL, MinRefetchInterval,
// NegativeCacheTTL, and MaxResponseBytes); unbounded fetch is a config bug,
// not a supported mode.
func (r *Resolver) EffectiveOptions() ResolverOptions {
	return ResolverOptions{
		TTL:                r.ttl,
		MinRefetchInterval: r.minRefetchInterval,
		NegativeCacheTTL:   r.negativeTTL,
		MaxResponseBytes:   r.maxResponseBytes,
	}
}

// NewResolverWithOptions creates a JWKS resolver with explicit policy options.
func NewResolverWithOptions(client HTTPDoer, opts ResolverOptions) (*Resolver, error) {
	if client == nil {
		return nil, ErrNilHTTPClient
	}

	ttl := opts.TTL
	if ttl <= 0 {
		ttl = DefaultCacheTTL
	}

	minRefetch := opts.MinRefetchInterval
	if minRefetch == 0 {
		minRefetch = DefaultMinRefetchInterval
	}

	if minRefetch < 0 {
		minRefetch = 0
	}

	negTTL := opts.NegativeCacheTTL
	if negTTL == 0 {
		negTTL = DefaultNegativeCacheTTL
	}

	if negTTL < 0 {
		negTTL = 0
	}

	maxBytes := opts.MaxResponseBytes
	if maxBytes <= 0 {
		maxBytes = int64(config.DefaultMaxResponseBytes)
	}

	now := opts.Now
	if now == nil {
		now = time.Now
	}

	return &Resolver{
		cache:              map[string]cacheEntry{},
		negative:           map[string]time.Time{},
		lastFetchAt:        map[string]time.Time{},
		client:             client,
		ttl:                ttl,
		minRefetchInterval: minRefetch,
		negativeTTL:        negTTL,
		maxResponseBytes:   maxBytes,
		now:                now,
	}, nil
}

// FetchURL retrieves a JWKS document from an absolute URL.
func FetchURL(ctx context.Context, client HTTPDoer, jwksURL string) (Set, error) {
	return FetchURLLimited(ctx, client, jwksURL, int64(config.DefaultMaxResponseBytes))
}

// FetchURLLimited retrieves a JWKS document with an explicit response size cap.
func FetchURLLimited(ctx context.Context, client HTTPDoer, jwksURL string, maxBytes int64) (Set, error) {
	if client == nil {
		return Set{}, ErrNilHTTPClient
	}

	if maxBytes <= 0 {
		maxBytes = int64(config.DefaultMaxResponseBytes)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURL, nil)
	if err != nil {
		return Set{}, err
	}

	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return Set{}, fmt.Errorf("jwks: fetch %s: %w", jwksURL, err)
	}
	defer func() {
		//nolint:errcheck // best-effort cleanup; error is not actionable
		resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return Set{}, fmt.Errorf("jwks: fetch %s: status %d", jwksURL, resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return Set{}, fmt.Errorf("jwks: read body: %w", err)
	}

	if int64(len(body)) > maxBytes {
		return Set{}, fmt.Errorf("jwks: fetch %s: %w", jwksURL, ErrResponseTooLarge)
	}

	var set Set
	if err := json.Unmarshal(body, &set); err != nil {
		return Set{}, fmt.Errorf("jwks: decode JSON: %w", err)
	}

	if len(set.Keys) == 0 {
		return Set{}, fmt.Errorf("jwks: empty key set from %s", jwksURL)
	}

	return set, nil
}

// ResolveURL fetches the JWKS at the explicit advertised URL and returns the
// key whose kid exactly equals the keyID signature parameter. Fetches go
// through the resolver's bounded cache with the configured TTL, min-refetch
// interval, and negative-cache behavior.
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
		r.cache[jwksURL] = cacheEntry{set: set, fetchedAt: fetchedAt}
		r.lastFetchAt[jwksURL] = fetchedAt
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
	r.mu.RLock()
	entry, ok := r.cache[jwksURL]
	lastFetch, haveFetch := r.lastFetchAt[jwksURL]
	r.mu.RUnlock()

	if !ok {
		return Set{}, false
	}

	if !forceRefresh {
		if now.Sub(entry.fetchedAt) < r.ttl {
			return entry.set, true
		}

		return Set{}, false
	}

	if r.minRefetchInterval > 0 && haveFetch && now.Sub(lastFetch) < r.minRefetchInterval {
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

	r.mu.RLock()
	defer r.mu.RUnlock()

	until, ok := r.negative[negativeKey(jwksURL, kid)]

	return ok && r.now().Before(until)
}

func (r *Resolver) rememberNegative(jwksURL, kid string) {
	if r.negativeTTL <= 0 {
		return
	}

	r.mu.Lock()
	r.negative[negativeKey(jwksURL, kid)] = r.now().Add(r.negativeTTL)
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

func encodeBase64URL(raw []byte) string {
	return encodeBase64URLStd(raw)
}
