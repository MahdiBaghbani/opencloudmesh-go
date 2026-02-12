package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache"
	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
)

// Client fetches and caches remote OCM discovery documents. Discovers via /.well-known/ocm and /ocm-provider fallback.
type Client struct {
	httpClient *httpclient.Client
	cache      cache.Cache
	cacheTTL   time.Duration
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

// Discover fetches the discovery document for a remote OCM server. Uses cache when available.
func (c *Client) Discover(ctx context.Context, baseURL string) (*Discovery, error) {
	baseURL = strings.TrimSuffix(baseURL, "/")
	cacheKey := "discovery:" + baseURL
	if data, err := c.cache.Get(ctx, cacheKey); err == nil {
		var disc Discovery
		if err := json.Unmarshal(data, &disc); err == nil {
			return &disc, nil
		}
	}

	disc, err := c.fetchDiscovery(ctx, baseURL+"/.well-known/ocm")
	if err != nil {
		disc, err = c.fetchDiscovery(ctx, baseURL+"/ocm-provider")
		if err != nil {
			return nil, fmt.Errorf("failed to discover OCM at %s: %w", baseURL, err)
		}
	}
	if data, err := json.Marshal(disc); err == nil {
		c.cache.Set(ctx, cacheKey, data, c.cacheTTL)
	}

	return disc, nil
}

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
