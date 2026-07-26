package discovery

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache"
	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
)

// ErrDiscoveryDisabled is returned when the discovery client is nil or disabled.
var ErrDiscoveryDisabled = errors.New("discovery client not configured")

// ErrDiscoveryNotFound is returned when the discovery endpoint responds with HTTP 404.
var ErrDiscoveryNotFound = errors.New("discovery endpoint not found")

// ErrInvalidDiscoveryJSON is returned when a discovery document is malformed JSON
// or fails semantic validation (for example unsupported apiVersion under policy,
// non-absolute or cross-authority endpoints, capability/endpoint inconsistency,
// malformed protocol roles).
var ErrInvalidDiscoveryJSON = errors.New("invalid discovery json")

// ErrOCMDisabled is returned when the remote discovery document reports enabled=false.
var ErrOCMDisabled = errors.New("ocm disabled at provider")

// Client fetches and caches remote OCM discovery documents via /.well-known/ocm.
type Client struct {
	httpClient    *httpclient.Client
	cache         cache.Cache
	cacheTTL      time.Duration
	versionPolicy *VersionPolicy
	logger        *slog.Logger
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

// SetVersionPolicy configures inbound peer apiVersion accept/reject policy.
func (c *Client) SetVersionPolicy(p *VersionPolicy) {
	if c == nil {
		return
	}

	c.versionPolicy = p
}

// SetLogger configures the logger used for fresh-fetch discovery warnings.
func (c *Client) SetLogger(l *slog.Logger) {
	if c == nil {
		return
	}

	c.logger = l
}

// IsNoopCache reports whether the cache wired into this client is a *cache.NoopCache.
// Use in tests to verify SkipDiscoveryCache wiring without accessing the cache
// implementation directly.
// Returns false when the client itself is nil.
func (c *Client) IsNoopCache() bool {
	if c == nil {
		return false
	}

	_, ok := c.cache.(*cache.NoopCache)

	return ok
}

// Discover fetches the discovery document for a remote OCM server. Uses cache when available.
//
// Raw response bytes are cached so normalization runs on every cache read.
func (c *Client) Discover(ctx context.Context, baseURL string) (*spec.Discovery, error) {
	baseURL = strings.TrimSuffix(baseURL, "/")

	cacheKey := "discovery:" + baseURL
	if data, err := c.cache.Get(ctx, cacheKey); err == nil {
		disc, err := c.normalizeDiscovery(data, discoveryOriginFromURL(baseURL), false)
		if err == nil {
			return &disc, nil
		}

		_ = c.cache.Delete(ctx, cacheKey)
	}

	rawBytes, disc, err := c.fetchDiscovery(ctx, baseURL+"/.well-known/ocm")
	if err != nil {
		return nil, fmt.Errorf("failed to discover OCM at %s: %w", baseURL, err)
	}

	c.cache.Set(ctx, cacheKey, rawBytes, c.cacheTTL)

	return disc, nil
}

func (c *Client) fetchDiscovery(ctx context.Context, discoveryURL string) ([]byte, *spec.Discovery, error) {
	data, resp, err := c.httpClient.GetJSON(ctx, discoveryURL)
	if err != nil {
		return nil, nil, err
	}

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusNotFound {
			return nil, nil, fmt.Errorf("discovery returned status %d: %w", resp.StatusCode, ErrDiscoveryNotFound)
		}

		return nil, nil, fmt.Errorf("discovery returned status %d", resp.StatusCode)
	}

	disc, err := c.normalizeDiscovery(data, discoveryOriginFromURL(discoveryURL), true)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrInvalidDiscoveryJSON, err)
	}

	if !disc.Enabled {
		return nil, nil, fmt.Errorf("%w at %s", ErrOCMDisabled, discoveryURL)
	}

	return data, &disc, nil
}

func (c *Client) normalizeDiscovery(data []byte, discoveryOrigin string, freshFetch bool) (spec.Discovery, error) {
	var disc spec.Discovery
	if err := json.Unmarshal(data, &disc); err != nil {
		return spec.Discovery{}, err
	}

	if disc.InviteAcceptDialog != "" {
		resolveBase := disc.EndPoint
		if resolveBase == "" {
			resolveBase = discoveryOrigin
		}

		disc.InviteAcceptDialog = spec.ResolveInviteAcceptDialog(resolveBase, disc.InviteAcceptDialog)
	}

	if disc.Enabled {
		policy := c.versionPolicy
		if policy == nil {
			policy = NewVersionPolicy()
		}

		if err := validateDiscovery(&disc, discoveryOrigin, policy); err != nil {
			return spec.Discovery{}, err
		}

		if freshFetch {
			logger := c.logger
			if logger == nil {
				logger = slog.Default()
			}

			for _, w := range disc.Warnings {
				logger.Warn("discovery warning", "warning", w)
			}
		}
	}

	return disc, nil
}
