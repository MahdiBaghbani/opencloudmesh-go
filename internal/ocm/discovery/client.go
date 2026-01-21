package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/cache"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/httpclient"
)

// Client fetches and caches remote OCM discovery documents.
type Client struct {
	httpClient *httpclient.Client
	cache      cache.Cache
	cacheTTL   time.Duration
}

// NewClient creates a new discovery client.
// If cache is nil, it is silently replaced with the default cache (in-memory).
// This ensures discovery always caches results and callers cannot accidentally
// create an uncached client.
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

// Discover fetches the discovery document for a remote OCM server.
// Uses cache if available and not expired.
func (c *Client) Discover(ctx context.Context, baseURL string) (*Discovery, error) {
	// Normalize the base URL
	baseURL = strings.TrimSuffix(baseURL, "/")

	// Check cache first (cache is always non-nil after NewClient)
	cacheKey := "discovery:" + baseURL
	if data, err := c.cache.Get(ctx, cacheKey); err == nil {
		var disc Discovery
		if err := json.Unmarshal(data, &disc); err == nil {
			return &disc, nil
		}
	}

	// Try /.well-known/ocm first (RFC 8615)
	disc, err := c.fetchDiscovery(ctx, baseURL+"/.well-known/ocm")
	if err != nil {
		// Fall back to legacy /ocm-provider
		disc, err = c.fetchDiscovery(ctx, baseURL+"/ocm-provider")
		if err != nil {
			return nil, fmt.Errorf("failed to discover OCM at %s: %w", baseURL, err)
		}
	}

	// Cache the result
	if data, err := json.Marshal(disc); err == nil {
		c.cache.Set(ctx, cacheKey, data, c.cacheTTL)
	}

	return disc, nil
}

// fetchDiscovery fetches a discovery document from a specific URL.
func (c *Client) fetchDiscovery(ctx context.Context, discoveryURL string) (*Discovery, error) {
	data, resp, err := c.httpClient.GetJSON(ctx, discoveryURL)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("discovery returned status %d", resp.StatusCode)
	}

	var disc Discovery
	if err := json.Unmarshal(data, &disc); err != nil {
		return nil, fmt.Errorf("invalid discovery JSON: %w", err)
	}

	if !disc.Enabled {
		return nil, fmt.Errorf("OCM is disabled at %s", discoveryURL)
	}

	return &disc, nil
}

// Note: Helper methods (GetEndpoint, GetWebDAVPath, HasCapability, HasCriteria,
// GetPublicKey, BuildWebDAVURL) are defined on spec.Discovery and available
// through the type alias.
