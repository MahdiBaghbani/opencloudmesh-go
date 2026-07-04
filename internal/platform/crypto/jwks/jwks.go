// Package jwks publishes and resolves Ed25519 public keys in RFC 7517 format.
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

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/keyid"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/sigalg"
)

const (
	WellKnownPath = "/.well-known/jwks.json"
	// DefaultCacheTTL is how long a fetched JWKS document is reused before refresh.
	DefaultCacheTTL = 5 * time.Minute
)

// Key is a single RFC 7517 JSON Web Key entry.
type Key struct {
	Kty string `json:"kty"`
	Crv string `json:"crv,omitempty"`
	Kid string `json:"kid"`
	X   string `json:"x,omitempty"`
}

// Set is a JSON Web Key Set.
type Set struct {
	Keys []Key `json:"keys"`
}

// Ed25519Key builds a JWKS key entry from an Ed25519 public key.
func Ed25519Key(kid string, pub ed25519.PublicKey) Key {
	return Key{
		Kty: "OKP",
		Crv: "Ed25519",
		Kid: kid,
		X:   encodeBase64URL(pub),
	}
}

// SetFromEd25519PublicKey returns a single-key JWKS for the given kid.
func SetFromEd25519PublicKey(kid string, pub ed25519.PublicKey) Set {
	return Set{Keys: []Key{Ed25519Key(kid, pub)}}
}

// MarshalJSON encodes the JWKS set.
func (s Set) MarshalJSON() ([]byte, error) {
	type alias Set
	if s.Keys == nil {
		s.Keys = []Key{}
	}
	return json.Marshal(alias(s))
}

// FindEd25519 resolves an Ed25519 public key by JWKS kid.
func (s Set) FindEd25519(kid string) (ed25519.PublicKey, error) {
	for _, key := range s.Keys {
		if !keyid.KidMatches(kid, key.Kid) {
			continue
		}
		pub, err := sigalg.PublicKeyFromJWK(key.Kty, key.Crv, key.X)
		if err != nil {
			return nil, err
		}
		edPub, ok := pub.(ed25519.PublicKey)
		if !ok {
			return nil, fmt.Errorf("jwks: key %q is not Ed25519", key.Kid)
		}
		return edPub, nil
	}
	return nil, fmt.Errorf("jwks: key %q not found: %w", kid, ErrKeyNotFound)
}

// ErrKeyNotFound indicates the JWKS document does not contain the requested kid.
var ErrKeyNotFound = errors.New("jwks: key not found")

// HTTPDoer performs outbound HTTP requests for JWKS fetch.
type HTTPDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type cacheEntry struct {
	set       Set
	fetchedAt time.Time
}

// Resolver fetches and caches remote JWKS documents.
type Resolver struct {
	mu     sync.RWMutex
	cache  map[string]cacheEntry
	client HTTPDoer
	ttl    time.Duration
	now    func() time.Time
}

// NewResolver creates a JWKS resolver backed by client.
func NewResolver(client HTTPDoer) *Resolver {
	return NewResolverWithTTL(client, DefaultCacheTTL)
}

// NewResolverWithTTL creates a JWKS resolver with an explicit cache TTL.
func NewResolverWithTTL(client HTTPDoer, ttl time.Duration) *Resolver {
	if client == nil {
		client = http.DefaultClient
	}
	if ttl <= 0 {
		ttl = DefaultCacheTTL
	}
	return &Resolver{
		cache:  map[string]cacheEntry{},
		client: client,
		ttl:    ttl,
		now:    time.Now,
	}
}

// FetchURL retrieves a JWKS document from an absolute URL.
func FetchURL(ctx context.Context, client HTTPDoer, jwksURL string) (Set, error) {
	if client == nil {
		client = http.DefaultClient
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
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return Set{}, fmt.Errorf("jwks: fetch %s: status %d", jwksURL, resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return Set{}, fmt.Errorf("jwks: read body: %w", err)
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

// URLForAuthority builds the well-known JWKS URL for an authority.
func URLForAuthority(scheme, authority string) string {
	if scheme == "" {
		scheme = "https"
	}
	return scheme + "://" + authority + WellKnownPath
}

// Resolve fetches JWKS for authority using scheme and returns the Ed25519 key
// matching kid.
func (r *Resolver) Resolve(
	ctx context.Context,
	scheme, authority, kid string,
) (ed25519.PublicKey, error) {
	jwksURL := URLForAuthority(scheme, authority)

	set, err := r.loadSet(ctx, jwksURL, false)
	if err != nil {
		return nil, err
	}

	pub, err := set.FindEd25519(kid)
	if err == nil {
		return pub, nil
	}
	if !errors.Is(err, ErrKeyNotFound) {
		return nil, err
	}

	// Re-fetch once on kid miss so rotated keys can be picked up without restart.
	set, refreshErr := r.loadSet(ctx, jwksURL, true)
	if refreshErr != nil {
		return nil, refreshErr
	}
	return set.FindEd25519(kid)
}

func (r *Resolver) loadSet(ctx context.Context, jwksURL string, forceRefresh bool) (Set, error) {
	if !forceRefresh {
		r.mu.RLock()
		entry, ok := r.cache[jwksURL]
		r.mu.RUnlock()
		if ok && r.now().Sub(entry.fetchedAt) < r.ttl {
			return entry.set, nil
		}
	}

	set, err := FetchURL(ctx, r.client, jwksURL)
	if err != nil {
		return Set{}, err
	}

	r.mu.Lock()
	r.cache[jwksURL] = cacheEntry{set: set, fetchedAt: r.now()}
	r.mu.Unlock()

	return set, nil
}

// ResolveKeyID resolves a signature keyid parameter to an Ed25519 public key.
func (r *Resolver) ResolveKeyID(
	ctx context.Context,
	defaultScheme, keyID string,
) (ed25519.PublicKey, error) {
	parsed, err := keyid.ParseKid(keyID)
	if err != nil {
		return nil, err
	}

	scheme := defaultScheme
	if scheme == "" {
		scheme = "https"
	}

	return r.Resolve(ctx, scheme, parsed.Authority, keyID)
}

// AuthorityFromBaseURL extracts scheme and authority from an absolute base URL.
func AuthorityFromBaseURL(baseURL string) (scheme, authority string, err error) {
	u, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil {
		return "", "", err
	}
	if u.Scheme == "" || u.Host == "" {
		return "", "", fmt.Errorf("jwks: invalid base URL %q", baseURL)
	}
	return strings.ToLower(u.Scheme), strings.ToLower(u.Host), nil
}

func encodeBase64URL(raw []byte) string {
	return encodeBase64URLStd(raw)
}
