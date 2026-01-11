package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/cache"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/httpclient"
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

// GetEndpoint returns the OCM endpoint from a discovery document.
func (d *Discovery) GetEndpoint() string {
	return d.EndPoint
}

// GetWebDAVPath returns the WebDAV path for file resources.
func (d *Discovery) GetWebDAVPath() string {
	for _, rt := range d.ResourceTypes {
		if rt.Name == "file" {
			if path, ok := rt.Protocols["webdav"]; ok {
				return path
			}
		}
	}
	return ""
}

// HasCapability checks if the discovery advertises a capability.
func (d *Discovery) HasCapability(cap string) bool {
	for _, c := range d.Capabilities {
		if c == cap {
			return true
		}
	}
	return false
}

// HasCriteria checks if the discovery requires a specific criteria token.
func (d *Discovery) HasCriteria(token string) bool {
	for _, c := range d.Criteria {
		if c == token {
			return true
		}
	}
	return false
}

// GetPublicKey returns the first public key, if any.
func (d *Discovery) GetPublicKey(keyID string) *PublicKey {
	for i, pk := range d.PublicKeys {
		if pk.KeyID == keyID {
			return &d.PublicKeys[i]
		}
	}
	return nil
}

// BuildWebDAVURL constructs a full WebDAV URL for accessing a shared file.
func (d *Discovery) BuildWebDAVURL(webdavID string) (string, error) {
	webdavPath := d.GetWebDAVPath()
	if webdavPath == "" {
		return "", fmt.Errorf("no WebDAV path in discovery")
	}

	// Parse the endpoint to get the base URL
	endpoint, err := url.Parse(d.EndPoint)
	if err != nil {
		return "", fmt.Errorf("invalid endpoint URL: %w", err)
	}

	// Build the full WebDAV URL
	webdavURL := fmt.Sprintf("%s://%s%s%s",
		endpoint.Scheme,
		endpoint.Host,
		strings.TrimSuffix(webdavPath, "/"),
		"/"+webdavID)

	return webdavURL, nil
}
