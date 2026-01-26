// Package client provides a safe outbound HTTP client with SSRF protections.
package client

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
)

var (
	ErrSSRFBlocked         = errors.New("request blocked by SSRF protection")
	ErrTooManyRedirects    = errors.New("too many redirects")
	ErrResponseTooLarge    = errors.New("response body too large")
	ErrInvalidURL          = errors.New("invalid URL")
	ErrRedirectBlocked     = errors.New("redirect blocked by policy")
	ErrSignedNoRedirect    = errors.New("signed requests cannot follow redirects")
	ErrRedirectNotSameHost = errors.New("redirect to different host blocked")
	ErrRedirectDowngrade   = errors.New("redirect from https to http blocked")
	ErrHostUnresolvable    = errors.New("host could not be resolved")
)

// RequestOptions controls per-request behavior.
type RequestOptions struct {
	// IsSigned indicates this is a signed request that must not follow redirects.
	IsSigned bool
}

// Resolver abstracts DNS resolution for testing.
type Resolver interface {
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
}

// Client is a safe HTTP client with SSRF protections and bounded behavior.
type Client struct {
	cfg        *config.OutboundHTTPConfig
	httpClient *http.Client
	resolver   Resolver // for context-aware DNS in SSRF checks; nil uses net.DefaultResolver
}

// New creates a new safe HTTP client.
// The client ignores proxy environment variables (HTTP_PROXY, HTTPS_PROXY, NO_PROXY).
func New(cfg *config.OutboundHTTPConfig) *Client {
	if cfg == nil {
		cfg = &config.OutboundHTTPConfig{
			SSRFMode:           "strict",
			TimeoutMS:          10000,
			ConnectTimeoutMS:   2000,
			MaxRedirects:       1,
			MaxResponseBytes:   1048576,
			InsecureSkipVerify: false,
		}
	}

	c := &Client{cfg: cfg}

	// Create dialer with SSRF protection
	dialer := &net.Dialer{
		Timeout: time.Duration(cfg.ConnectTimeoutMS) * time.Millisecond,
	}

	transport := &http.Transport{
		// Explicitly ignore proxy environment variables
		Proxy: nil,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// Check SSRF before dialing (addr is host:port from net.SplitHostPort)
			if cfg.SSRFMode == "strict" {
				if err := c.checkSSRF(ctx, addr); err != nil {
					return nil, err
				}
			}
			return dialer.DialContext(ctx, network, addr)
		},
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: cfg.InsecureSkipVerify,
		},
		MaxIdleConns:       10,
		IdleConnTimeout:    30 * time.Second,
		DisableCompression: false,
		DisableKeepAlives:  false,
	}

	// Default redirect policy - unsigned requests with constraints
	c.httpClient = &http.Client{
		Transport: transport,
		Timeout:   time.Duration(cfg.TimeoutMS) * time.Millisecond,
		// Default: no automatic redirect following - we handle it manually
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	return c
}

// SetResolver sets a custom DNS resolver (for testing).
func (c *Client) SetResolver(r Resolver) {
	c.resolver = r
}

// getResolver returns the resolver, defaulting to net.DefaultResolver.
func (c *Client) getResolver() Resolver {
	if c.resolver != nil {
		return c.resolver
	}
	return net.DefaultResolver
}

// checkSSRF validates that the address is not a private/loopback address.
// The addr is in host:port format from the dialer.
func (c *Client) checkSSRF(ctx context.Context, addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		// No port, use the whole thing as host
		host = addr
	}

	return c.checkSSRFHost(ctx, host)
}

// checkSSRFHost validates that the host is not a private/loopback address.
// Handles IPv6 bracket notation (e.g., "[::1]").
// Uses context-aware DNS resolution so cancellation is respected.
func (c *Client) checkSSRFHost(ctx context.Context, host string) error {
	// Strip IPv6 brackets if present
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = host[1 : len(host)-1]
	}

	// Check for localhost names
	lowerHost := strings.ToLower(host)
	if lowerHost == "localhost" || lowerHost == "localhost.localdomain" {
		return fmt.Errorf("%w: localhost is blocked", ErrSSRFBlocked)
	}

	// Try to parse as IP first (avoids DNS lookup for IP literals)
	if ip := net.ParseIP(host); ip != nil {
		if !c.isAllowedIP(ip) {
			return fmt.Errorf("%w: IP %s is blocked", ErrSSRFBlocked, ip)
		}
		return nil
	}

	// Resolve the hostname to IP addresses using context-aware resolver
	ipAddrs, err := c.getResolver().LookupIPAddr(ctx, host)
	if err != nil {
		// Cannot resolve - fail closed (block the request)
		return fmt.Errorf("%w: %s: %v", ErrHostUnresolvable, host, err)
	}

	for _, ipAddr := range ipAddrs {
		if !c.isAllowedIP(ipAddr.IP) {
			return fmt.Errorf("%w: %s resolves to blocked IP %s", ErrSSRFBlocked, host, ipAddr.IP)
		}
	}

	return nil
}

// isAllowedIP checks if an IP address is allowed (not private/loopback/link-local).
func (c *Client) isAllowedIP(ip net.IP) bool {
	// Block loopback
	if ip.IsLoopback() {
		return false
	}

	// Block private ranges
	if ip.IsPrivate() {
		return false
	}

	// Block link-local
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return false
	}

	// Block unspecified (0.0.0.0, ::)
	if ip.IsUnspecified() {
		return false
	}

	// Block multicast
	if ip.IsMulticast() {
		return false
	}

	return true
}

// Get performs a GET request with safety protections.
// Unsigned requests may follow redirects under strict constraints.
func (c *Client) Get(ctx context.Context, urlStr string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidURL, err)
	}
	return c.DoWithOptions(req, RequestOptions{IsSigned: false})
}

// Do performs an HTTP request with safety protections.
// This is the standard interface - treats requests as unsigned (may follow redirects).
func (c *Client) Do(req *http.Request) (*http.Response, error) {
	return c.DoWithOptions(req, RequestOptions{IsSigned: false})
}

// DoSigned performs a signed HTTP request that must not follow redirects.
// Any 3xx response is treated as an error.
func (c *Client) DoSigned(req *http.Request) (*http.Response, error) {
	return c.DoWithOptions(req, RequestOptions{IsSigned: true})
}

// DoWithOptions performs an HTTP request with explicit options.
func (c *Client) DoWithOptions(req *http.Request, opts RequestOptions) (*http.Response, error) {
	ctx := req.Context()

	// Pre-flight SSRF check using Hostname() (not Host which includes port)
	if c.cfg.SSRFMode == "strict" {
		if err := c.checkSSRFHost(ctx, req.URL.Hostname()); err != nil {
			return nil, err
		}
	}

	// Detect signed request via RFC 9421 headers (centralized enforcement)
	isSigned := opts.IsSigned || hasSignatureHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	// Handle redirects based on signing status
	if isRedirect(resp.StatusCode) {
		if isSigned {
			// Signed requests must not follow redirects
			resp.Body.Close()
			return nil, fmt.Errorf("%w: received %d", ErrSignedNoRedirect, resp.StatusCode)
		}

		// Unsigned: follow redirect under strict constraints
		return c.followRedirect(req, resp, 0)
	}

	return resp, nil
}

// hasSignatureHeaders detects RFC 9421 signature headers.
func hasSignatureHeaders(req *http.Request) bool {
	return req.Header.Get("Signature") != "" || req.Header.Get("Signature-Input") != ""
}

// followRedirect follows a single redirect with strict constraints.
func (c *Client) followRedirect(origReq *http.Request, resp *http.Response, depth int) (*http.Response, error) {
	defer resp.Body.Close()
	ctx := origReq.Context()

	// Check redirect limit (default 1 for unsigned)
	maxRedirects := c.cfg.MaxRedirects
	if maxRedirects <= 0 {
		maxRedirects = 1
	}
	if depth >= maxRedirects {
		return nil, fmt.Errorf("%w: exceeded limit of %d", ErrTooManyRedirects, maxRedirects)
	}

	// Get redirect location
	location := resp.Header.Get("Location")
	if location == "" {
		return nil, fmt.Errorf("%w: no Location header", ErrRedirectBlocked)
	}

	// Parse redirect URL
	redirectURL, err := url.Parse(location)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid Location: %v", ErrRedirectBlocked, err)
	}

	// Resolve relative URLs
	redirectURL = origReq.URL.ResolveReference(redirectURL)

	// Constraint: https -> https only (no downgrade); http -> https is allowed
	if origReq.URL.Scheme == "https" && redirectURL.Scheme != "https" {
		return nil, fmt.Errorf("%w: %s -> %s", ErrRedirectDowngrade, origReq.URL.Scheme, redirectURL.Scheme)
	}

	// Constraint: same host only (hostname + effective port must match)
	if !isSameHost(origReq.URL, redirectURL) {
		return nil, fmt.Errorf("%w: %s -> %s", ErrRedirectNotSameHost, origReq.URL.Host, redirectURL.Host)
	}

	// SSRF check on redirect target using Hostname() (not Host)
	if c.cfg.SSRFMode == "strict" {
		if err := c.checkSSRFHost(ctx, redirectURL.Hostname()); err != nil {
			return nil, err
		}
	}

	// Create new request for redirect
	newReq, err := http.NewRequestWithContext(ctx, origReq.Method, redirectURL.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRedirectBlocked, err)
	}

	// Copy safe headers (not auth headers for security)
	copyRedirectHeaders(origReq, newReq)

	// Execute redirect request
	newResp, err := c.httpClient.Do(newReq)
	if err != nil {
		return nil, err
	}

	// If another redirect, recurse (with depth check)
	if isRedirect(newResp.StatusCode) {
		return c.followRedirect(newReq, newResp, depth+1)
	}

	return newResp, nil
}

// isSameHost checks if two URLs have the same host (hostname + effective port).
// Uses url.URL.Hostname() and url.URL.Port() for IPv6-safe comparisons.
// Effective port: missing port = scheme default (http=80, https=443).
// Explicit default port is equivalent to missing (https://example.com:443 == https://example.com).
func isSameHost(a, b *url.URL) bool {
	// Hostname comparison (case-insensitive)
	if !strings.EqualFold(a.Hostname(), b.Hostname()) {
		return false
	}

	// Effective port comparison
	portA := effectivePort(a)
	portB := effectivePort(b)
	return portA == portB
}

// effectivePort returns the effective port for a URL.
// Missing port = scheme default. Explicit default port = same as missing.
func effectivePort(u *url.URL) string {
	port := u.Port()
	if port == "" {
		return defaultPort(u.Scheme)
	}
	// Normalize explicit default ports to empty (treated as default)
	if port == defaultPort(u.Scheme) {
		return defaultPort(u.Scheme)
	}
	return port
}

// defaultPort returns the default port for a scheme.
func defaultPort(scheme string) string {
	switch strings.ToLower(scheme) {
	case "http":
		return "80"
	case "https":
		return "443"
	default:
		return ""
	}
}

// copyRedirectHeaders copies safe headers for redirects.
func copyRedirectHeaders(src, dst *http.Request) {
	// Copy User-Agent and Accept headers, but not Authorization
	if ua := src.Header.Get("User-Agent"); ua != "" {
		dst.Header.Set("User-Agent", ua)
	}
	if accept := src.Header.Get("Accept"); accept != "" {
		dst.Header.Set("Accept", accept)
	}
}

// isRedirect returns true if the status code is a redirect.
func isRedirect(code int) bool {
	return code == http.StatusMovedPermanently ||
		code == http.StatusFound ||
		code == http.StatusSeeOther ||
		code == http.StatusTemporaryRedirect ||
		code == http.StatusPermanentRedirect
}

// GetJSON performs a GET request and reads the response body with size limit.
func (c *Client) GetJSON(ctx context.Context, urlStr string) ([]byte, *http.Response, error) {
	resp, err := c.Get(ctx, urlStr)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	// Read with size limit
	limitedReader := io.LimitReader(resp.Body, c.cfg.MaxResponseBytes+1)
	body, err := io.ReadAll(limitedReader)
	if err != nil {
		return nil, resp, err
	}

	if int64(len(body)) > c.cfg.MaxResponseBytes {
		return nil, resp, ErrResponseTooLarge
	}

	return body, resp, nil
}

// IsSSRFError returns true if the error is an SSRF blocking error.
func IsSSRFError(err error) bool {
	return errors.Is(err, ErrSSRFBlocked) || errors.Is(err, ErrHostUnresolvable)
}

// IsRedirectError returns true if the error is a redirect-related error.
func IsRedirectError(err error) bool {
	return errors.Is(err, ErrRedirectBlocked) ||
		errors.Is(err, ErrSignedNoRedirect) ||
		errors.Is(err, ErrRedirectNotSameHost) ||
		errors.Is(err, ErrRedirectDowngrade) ||
		errors.Is(err, ErrTooManyRedirects)
}

// ContextClient wraps Client to provide a context-first Do method.
// This adapts the Client to interfaces that expect Do(ctx, req) signature.
type ContextClient struct {
	client *Client
}

// NewContextClient creates a ContextClient adapter.
func NewContextClient(c *Client) *ContextClient {
	return &ContextClient{client: c}
}

// Do performs an HTTP request, using the provided context.
func (c *ContextClient) Do(ctx context.Context, req *http.Request) (*http.Response, error) {
	req = req.WithContext(ctx)
	return c.client.Do(req)
}

// DoSigned performs a signed HTTP request that rejects redirects.
func (c *ContextClient) DoSigned(ctx context.Context, req *http.Request) (*http.Response, error) {
	req = req.WithContext(ctx)
	return c.client.DoSigned(req)
}
