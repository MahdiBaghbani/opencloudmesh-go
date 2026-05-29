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
	cfg               *config.OutboundHTTPConfig
	httpClient        *http.Client
	resolver          Resolver // for context-aware DNS in SSRF checks; nil uses net.DefaultResolver
	trustedProxyHosts map[string]struct{}
}

// New creates a new safe HTTP client.
// Proxy selection precedence:
//   - cfg.ProxyURL set: all requests route through this explicit proxy; env vars ignored.
//   - cfg.ProxyURL empty and cfg.ProxyEnvFallback true: HTTP_PROXY, HTTPS_PROXY, and
//     NO_PROXY env vars are read once at New() time and honored for all requests.
//     To pick up env changes, recreate the client.
//   - cfg.ProxyURL empty and cfg.ProxyEnvFallback false: requests go direct; env
//     proxy vars are ignored.
//
// Destination SSRF checks always apply in strict mode regardless of proxy routing.
// rootCAs is optional; nil uses the system certificate pool.
func New(cfg *config.OutboundHTTPConfig, rootCAs *x509.CertPool) *Client {
	if cfg == nil {
		cfg = &config.OutboundHTTPConfig{
			SSRF:               config.SSRFConfig{Mode: "strict"},
			TimeoutMS:          10000,
			ConnectTimeoutMS:   2000,
			MaxRedirects:       1,
			MaxResponseBytes:   1048576,
			InsecureSkipVerify: false,
		}
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

// isStrictMode reports whether SSRF enforcement is active.
// cfg.SSRF.Mode is the authoritative source. When it is empty, the derived
// shim cfg.SSRFMode is consulted as a fallback for programmatic callers that
// set only the top-level field directly.
func (c *Client) isStrictMode() bool {
	if c.cfg.SSRF.Mode != "" {
		return c.cfg.SSRF.Mode == "strict"
	}
	return c.cfg.SSRFMode == "strict"
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

	// Pre-flight SSRF check on the full URL (hostname + effective port).
	if c.isStrictMode() {
		if err := c.checkSSRFURL(ctx, req.URL); err != nil {
			return nil, err
		}
	}

	isSigned := opts.IsSigned || hasSignatureHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	if isRedirect(resp.StatusCode) {
		if isSigned {
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

// followRedirect follows a single redirect with strict constraints.
func (c *Client) followRedirect(origReq *http.Request, resp *http.Response, depth int) (*http.Response, error) {
	defer resp.Body.Close()
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
		return nil, fmt.Errorf("%w: invalid Location: %v", ErrRedirectBlocked, err)
	}

	redirectURL = origReq.URL.ResolveReference(redirectURL)

	// No HTTPS -> HTTP downgrade; http -> https is allowed.
	if origReq.URL.Scheme == "https" && redirectURL.Scheme != "https" {
		return nil, fmt.Errorf("%w: %s -> %s", ErrRedirectDowngrade, origReq.URL.Scheme, redirectURL.Scheme)
	}

	// Same-host constraint: hostname + effective port must match.
	if !isSameHost(origReq.URL, redirectURL) {
		return nil, fmt.Errorf("%w: %s -> %s", ErrRedirectNotSameHost, origReq.URL.Host, redirectURL.Host)
	}

	// SSRF revalidation on redirect target (defense-in-depth; same-host is
	// already enforced above). Catches DNS rebinding and enforces route policy.
	if c.isStrictMode() {
		if err := c.checkSSRFURL(ctx, redirectURL); err != nil {
			return nil, err
		}
	}

	newReq, err := http.NewRequestWithContext(ctx, origReq.Method, redirectURL.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRedirectBlocked, err)
	}

	copyRedirectHeaders(origReq, newReq)

	newResp, err := c.httpClient.Do(newReq)
	if err != nil {
		return nil, err
	}

	if isRedirect(newResp.StatusCode) {
		return c.followRedirect(newReq, newResp, depth+1)
	}

	return newResp, nil
}

// GetJSON performs a GET request and reads the response body with size limit.
func (c *Client) GetJSON(ctx context.Context, urlStr string) ([]byte, *http.Response, error) {
	resp, err := c.Get(ctx, urlStr)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

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
