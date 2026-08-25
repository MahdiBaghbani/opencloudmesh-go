// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

// Package client provides a safe outbound HTTP client with SSRF protections.
package client

import (
	"context"
	"crypto/x509"
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
	// ErrSSRFBlocked reports an SSRF-blocked outbound request.
	ErrSSRFBlocked = errors.New("request blocked by SSRF protection")
	// ErrTooManyRedirects reports excessive HTTP redirects.
	ErrTooManyRedirects = errors.New("too many redirects")
	// ErrResponseTooLarge reports an oversized response body.
	ErrResponseTooLarge = errors.New("response body too large")
	// ErrInvalidURL reports an invalid outbound URL.
	ErrInvalidURL = errors.New("invalid URL")
	// ErrRedirectBlocked reports a redirect blocked by policy.
	ErrRedirectBlocked = errors.New("redirect blocked by policy")
	// ErrSignedNoRedirect reports a redirect attempt on a signed request.
	ErrSignedNoRedirect = errors.New("signed requests cannot follow redirects")
	// ErrRedirectNotSameHost reports a cross-host redirect.
	ErrRedirectNotSameHost = errors.New("redirect to different host blocked")
	// ErrRedirectDowngrade reports an HTTPS-to-HTTP redirect.
	ErrRedirectDowngrade = errors.New("redirect from https to http blocked")
	// ErrHostUnresolvable reports an unresolvable outbound host.
	ErrHostUnresolvable = errors.New("host could not be resolved")
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
	cfg               *config.OutboundHTTPConfig
	httpClient        *http.Client
	resolver          Resolver // for context-aware DNS in SSRF checks; nil uses net.DefaultResolver
	trustedProxyHosts map[string]struct{}
	dialHosts         map[string]string // test-only hostname -> dial IP; production leaves this nil
}

// New creates a new safe HTTP client.
// Proxy selection precedence:
//   - cfg.ProxyURL set: all requests route through this explicit proxy; env vars ignored.
//   - cfg.ProxyURL empty and cfg.UseEnvFallback (use_env_fallback) true:
//     HTTP_PROXY, HTTPS_PROXY, and NO_PROXY env vars are read once at New() time
//     and honored for all requests. To pick up env changes, recreate the client.
//   - cfg.ProxyURL empty and cfg.UseEnvFallback false: requests go direct; env
//     proxy vars are ignored.
//
// Destination SSRF checks always apply in strict mode regardless of proxy routing.
// rootCAs is optional; nil uses the system certificate pool.
func New(cfg *config.OutboundHTTPConfig, rootCAs *x509.CertPool) *Client {
	if cfg == nil {
		strict := config.OutboundHTTPConfigStrict()
		cfg = &strict
	}

	c := &Client{cfg: cfg}

	// Proxy selection and trusted-host extraction (precedence: explicit
	// ProxyURL > env fallback > direct). See transport.go for details.
	proxyFunc, trustedHosts := buildProxyFunc(cfg)
	c.trustedProxyHosts = trustedHosts

	// No automatic redirect following - handled manually in DoWithOptions.
	c.httpClient = &http.Client{
		Transport: c.newTransport(rootCAs, proxyFunc),
		Timeout:   time.Duration(cfg.TimeoutMS) * time.Millisecond,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	return c
}

// SetResolver sets a custom DNS resolver (for testing).
func (c *Client) SetResolver(r Resolver) {
	c.resolver = r
}

// SetDialHosts installs a test-only hostname-to-IP dial map.
// Production clients leave this unset. Mapped hostnames are dialed at the
// mapped IP. SSRF evaluates the advertised hostname, not the mapped
// address, so this is not a private-target allow list and is not a DNS
// resolver hook.
func (c *Client) SetDialHosts(hosts map[string]string) {
	if len(hosts) == 0 {
		c.dialHosts = nil

		return
	}

	copied := make(map[string]string, len(hosts))
	for host, ip := range hosts {
		copied[strings.ToLower(host)] = ip
	}

	c.dialHosts = copied
}

// Get performs a GET request with safety protections.
// Unsigned requests may follow redirects under strict constraints.
func (c *Client) Get(ctx context.Context, urlStr string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, nil)
	if err != nil {
		//nolint:errorlint // inner err intentionally formatted with %v (not wrapped) to keep it out of the error chain; outer sentinel wrapped via %w
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

	// Pre-flight SSRF check on the full URL (hostname + effective port).
	if c.isStrictMode() {
		if err := c.checkSSRFURL(ctx, req.URL); err != nil {
			return nil, err
		}
	}

	isSigned := opts.IsSigned || hasSignatureHeaders(req)

	//nolint:gosec // request URL is preflighted by checkSSRFURL in strict mode before Do()
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http: send http request: %w", err)
	}

	if isRedirect(resp.StatusCode) {
		if isSigned {
			//nolint:errcheck // best-effort cleanup; error is not actionable
			resp.Body.Close()

			return nil, fmt.Errorf("%w: received %d", ErrSignedNoRedirect, resp.StatusCode)
		}

		return c.followRedirect(req, resp, 0)
	}

	return resp, nil
}

// hasSignatureHeaders detects RFC 9421 signature headers.
func hasSignatureHeaders(req *http.Request) bool {
	return req.Header.Get("Signature") != "" || req.Header.Get("Signature-Input") != ""
}

// MaxResponseBytes returns the configured outbound response size limit.
func (c *Client) MaxResponseBytes() int64 {
	if c == nil || c.cfg == nil {
		return 0
	}

	return c.cfg.MaxResponseBytes
}

// GetJSON performs a GET request and reads the response body with size limit.
func (c *Client) GetJSON(ctx context.Context, urlStr string) ([]byte, *http.Response, error) {
	resp, err := c.Get(ctx, urlStr)
	if err != nil {
		return nil, nil, err
	}
	defer func() {
		//nolint:errcheck // best-effort cleanup; error is not actionable
		resp.Body.Close()
	}()

	limitedReader := io.LimitReader(resp.Body, c.cfg.MaxResponseBytes+1)

	body, err := io.ReadAll(limitedReader)
	if err != nil {
		return nil, resp, fmt.Errorf("http: read response body: %w", err)
	}

	if int64(len(body)) > c.cfg.MaxResponseBytes {
		return nil, resp, ErrResponseTooLarge
	}

	return body, resp, nil
}

// getResolver returns the resolver, defaulting to net.DefaultResolver.
func (c *Client) getResolver() Resolver {
	if c.resolver != nil {
		return c.resolver
	}

	return net.DefaultResolver
}

// isStrictMode reports whether SSRF enforcement is active.
func (c *Client) isStrictMode() bool {
	return c.cfg.SSRF.Mode == "strict"
}

// followRedirect follows a single redirect with strict constraints.
func (c *Client) followRedirect(origReq *http.Request, resp *http.Response, depth int) (*http.Response, error) {
	defer func() {
		//nolint:errcheck // best-effort cleanup; error is not actionable
		resp.Body.Close()
	}()

	ctx := origReq.Context()

	maxRedirects := c.cfg.MaxRedirects
	if maxRedirects <= 0 {
		maxRedirects = 1
	}

	if depth >= maxRedirects {
		return nil, fmt.Errorf("%w: exceeded limit of %d", ErrTooManyRedirects, maxRedirects)
	}

	location := resp.Header.Get("Location")
	if location == "" {
		return nil, fmt.Errorf("%w: no Location header", ErrRedirectBlocked)
	}

	redirectURL, err := url.Parse(location)
	if err != nil {
		//nolint:errorlint // inner err intentionally formatted with %v (not wrapped) to keep it out of the error chain; outer sentinel wrapped via %w
		return nil, fmt.Errorf("%w: invalid Location: %v", ErrRedirectBlocked, err)
	}

	redirectURL = origReq.URL.ResolveReference(redirectURL)

	// No HTTPS -> HTTP downgrade; http -> https is allowed.
	if origReq.URL.Scheme == schemeHTTPS && redirectURL.Scheme != schemeHTTPS {
		return nil, fmt.Errorf("%w: %s -> %s", ErrRedirectDowngrade, origReq.URL.Scheme, redirectURL.Scheme)
	}

	// Same-host constraint: hostname + effective port must match.
	if !isSameHost(origReq.URL, redirectURL) {
		return nil, fmt.Errorf("%w: %s -> %s", ErrRedirectNotSameHost, origReq.URL.Host, redirectURL.Host)
	}

	// SSRF revalidation on redirect target (defense-in-depth; same-host is
	// already enforced above). Catches DNS rebinding and enforces route policy.
	if c.isStrictMode() {
		if ssrfErr := c.checkSSRFURL(ctx, redirectURL); ssrfErr != nil {
			return nil, ssrfErr
		}
	}

	//nolint:gosec // redirect URL is same-host validated and re-checked by checkSSRFURL in strict mode before Do()
	newReq, err := http.NewRequestWithContext(ctx, origReq.Method, redirectURL.String(), nil)
	if err != nil {
		//nolint:errorlint // inner err intentionally formatted with %v (not wrapped) to keep it out of the error chain; outer sentinel wrapped via %w
		return nil, fmt.Errorf("%w: %v", ErrRedirectBlocked, err)
	}

	copyRedirectHeaders(origReq, newReq)

	//nolint:gosec // redirect target is same-host validated and re-checked by checkSSRFURL in strict mode before Do()
	newResp, err := c.httpClient.Do(newReq)
	if err != nil {
		return nil, fmt.Errorf("http: send redirect request: %w", err)
	}

	if isRedirect(newResp.StatusCode) {
		return c.followRedirect(newReq, newResp, depth+1)
	}

	return newResp, nil
}

// IsSSRFError returns true if the error is an SSRF blocking error.
func IsSSRFError(err error) bool {
	return errors.Is(err, ErrSSRFBlocked)
}

// IsHostUnresolvable returns true when strict-mode DNS lookup failed closed.
func IsHostUnresolvable(err error) bool {
	return errors.Is(err, ErrHostUnresolvable)
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

// MaxResponseBytes returns the configured outbound response size limit.
func (c *ContextClient) MaxResponseBytes() int64 {
	if c == nil || c.client == nil {
		return 0
	}

	return c.client.MaxResponseBytes()
}
