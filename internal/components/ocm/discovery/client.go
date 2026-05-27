package discovery

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/peercompat"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache"
	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
)

// ErrDiscoveryDisabled is returned when the discovery client is nil or disabled.
var ErrDiscoveryDisabled = errors.New("discovery client not configured")

// Client fetches and caches remote OCM discovery documents. Discovers via /.well-known/ocm and /ocm-provider fallback.
type Client struct {
	httpClient   *httpclient.Client
	cache        cache.Cache
	cacheTTL     time.Duration
	peerContract *peercompat.CompiledContract
}

// NewClient creates a discovery client. Nil cache is replaced with default in-memory cache.
func NewClient(httpClient *httpclient.Client, c cache.Cache) *Client {
	if c == nil {
		c = cache.NewDefault()
	}
	return &Client{
		httpClient: httpClient,
		cache:      c,
		cacheTTL:   cache.TTLDiscovery,
	}
}

// IsNoopCache reports whether the cache wired into this client is a *cache.NoopCache.
// Use in tests to verify SkipDiscoveryCache wiring without exposing the cache instance.
// Returns false when the client itself is nil.
func (c *Client) IsNoopCache() bool {
	if c == nil {
		return false
	}
	_, ok := c.cache.(*cache.NoopCache)
	return ok
}

// SetPeerContract wires the compiled peer contract so discovery normalization can
// apply explicit peer-scoped compatibility fallbacks.
func (c *Client) SetPeerContract(peerContract *peercompat.CompiledContract) {
	if c == nil {
		return
	}
	c.peerContract = peerContract
}

// Discover fetches the discovery document for a remote OCM server. Uses cache when available.
//
// Raw response bytes are cached so that re-normalization on every cache read reflects
// the current peer contract rather than the contract active at fetch time.
func (c *Client) Discover(ctx context.Context, baseURL string) (*Discovery, error) {
	baseURL = strings.TrimSuffix(baseURL, "/")
	cacheKey := "discovery:" + baseURL
	if data, err := c.cache.Get(ctx, cacheKey); err == nil {
		disc, err := c.normalizeDiscovery(data, baseURL)
		if err == nil {
			return &disc, nil
		}
	}

	rawBytes, disc, err := c.fetchDiscovery(ctx, baseURL+"/.well-known/ocm")
	if err != nil {
		rawBytes, disc, err = c.fetchDiscovery(ctx, baseURL+"/ocm-provider")
		if err != nil {
			return nil, fmt.Errorf("failed to discover OCM at %s: %w", baseURL, err)
		}
	}
	c.cache.Set(ctx, cacheKey, rawBytes, c.cacheTTL)

	return disc, nil
}

func (c *Client) fetchDiscovery(ctx context.Context, discoveryURL string) ([]byte, *Discovery, error) {
	data, resp, err := c.httpClient.GetJSON(ctx, discoveryURL)
	if err != nil {
		return nil, nil, err
	}

	if resp.StatusCode != 200 {
		return nil, nil, fmt.Errorf("discovery returned status %d", resp.StatusCode)
	}

	disc, err := c.normalizeDiscovery(data, discoveryURL)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid discovery JSON: %w", err)
	}

	if !disc.Enabled {
		return nil, nil, fmt.Errorf("OCM is disabled at %s", discoveryURL)
	}

	return data, &disc, nil
}

type rawDiscoveryEnvelope struct {
	Discovery
	LegacyPublicKey *legacyDiscoveryPublicKey `json:"publicKey,omitempty"`
}

type legacyDiscoveryPublicKey struct {
	KeyID        string `json:"keyId"`
	PublicKeyPem string `json:"publicKeyPem"`
}

func (c *Client) normalizeDiscovery(data []byte, baseURL string) (Discovery, error) {
	var raw rawDiscoveryEnvelope
	if err := json.Unmarshal(data, &raw); err != nil {
		return Discovery{}, err
	}

	disc := raw.Discovery
	if len(disc.PublicKeys) > 0 || raw.LegacyPublicKey == nil {
		return disc, nil
	}

	decision := c.resolveLegacyDiscoveryPublicKey(baseURL)
	if !decision.Allow {
		return disc, nil
	}
	if raw.LegacyPublicKey.KeyID == "" || raw.LegacyPublicKey.PublicKeyPem == "" {
		return disc, nil
	}

	disc.PublicKeys = []PublicKey{{
		KeyID:        raw.LegacyPublicKey.KeyID,
		PublicKeyPem: raw.LegacyPublicKey.PublicKeyPem,
		Algorithm:    "rsa",
	}}
	return disc, nil
}

func (c *Client) resolveLegacyDiscoveryPublicKey(baseURL string) peercompat.LegacyDiscoveryDecision {
	decision := peercompat.LegacyDiscoveryDecision{
		Allow:      false,
		ReasonCode: "legacy_discovery_public_key_reject",
	}
	if c == nil || c.peerContract == nil {
		return decision
	}

	parsed, err := url.Parse(baseURL)
	if err != nil || parsed.Host == "" {
		return decision
	}

	return c.peerContract.LegacyDiscoveryPublicKeyDecisionForPeer(parsed.Host)
}
