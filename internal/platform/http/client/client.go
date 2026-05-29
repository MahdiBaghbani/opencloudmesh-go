// Package client provides a safe outbound HTTP client with SSRF protections.
package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/http/httpproxy"

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

	// Build the trusted proxy host set and the request-aware proxy function.
	// Precedence: explicit ProxyURL > env fallback > direct (nil proxy).
	//
	// trustedProxyHosts is used at dial time to skip the SSRF check only for
	// dials that go to an operator-trusted proxy host. All other dials -
	// including direct connections when NO_PROXY routes around an env proxy -
	// are still checked. Destination SSRF is also enforced unconditionally by
	// the preflight check in DoWithOptions and the redirect check in
	// followRedirect; the dial check is defense-in-depth for the direct-dial
	// case.
	trustedHosts := map[string]struct{}{}
	var proxyFunc func(*http.Request) (*url.URL, error)

	switch {
	case cfg.ProxyURL != "":
		// Explicit proxy wins; env vars are ignored even if ProxyEnvFallback is set.
		if p, err := url.Parse(cfg.ProxyURL); err == nil {
			proxyFunc = http.ProxyURL(p)
			trustedHosts[strings.ToLower(p.Hostname())] = struct{}{}
		}
	case cfg.ProxyEnvFallback:
		// Snapshot the proxy configuration from the environment at New() time.
		// Both routing and trusted-host extraction use the same snapshot so
		// their behavior is consistent for the lifetime of this client.
		// To pick up env changes (proxy or NO_PROXY), recreate the client.
		envCfg := httpproxy.FromEnvironment()
		envProxyFn := envCfg.ProxyFunc()
		proxyFunc = func(req *http.Request) (*url.URL, error) {
			return envProxyFn(req.URL)
		}
		for _, key := range []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"} {
			if raw := os.Getenv(key); raw != "" {
				p, err := url.Parse(raw)
				if err != nil || p.Hostname() == "" {
					// Scheme-less values like "proxy:3128" parse with the
					// hostname in the scheme field; add http:// to match
					// the fallback in httpproxy's own parseProxy.
					p, err = url.Parse("http://" + raw)
				}
				if err == nil && p.Hostname() != "" {
					trustedHosts[strings.ToLower(p.Hostname())] = struct{}{}
				}
			}
		}
	}
	// default (neither branch): nil proxyFunc blocks all env proxies.

	c.trustedProxyHosts = trustedHosts

	dialer := &net.Dialer{
		Timeout: time.Duration(cfg.ConnectTimeoutMS) * time.Millisecond,
	}

	transport := &http.Transport{
		Proxy: proxyFunc,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// In strict mode: skip the SSRF check only when dialing a trusted
			// proxy host (operator-controlled). All other dials - direct
			// connections including those caused by NO_PROXY - are checked.
			if c.isStrictMode() {
				host, _, _ := net.SplitHostPort(addr)
				if host == "" {
					host = addr
				}
				if _, trusted := c.trustedProxyHosts[strings.ToLower(host)]; !trusted {
					if err := c.checkSSRF(ctx, addr); err != nil {
						return nil, err
					}
				}
			}
			return dialer.DialContext(ctx, network, addr)
		},
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: cfg.InsecureSkipVerify,
			RootCAs:            rootCAs,
		},
		MaxIdleConns:       10,
		IdleConnTimeout:    30 * time.Second,
		DisableCompression: false,
		DisableKeepAlives:  false,
	}

	// No automatic redirect following - handled manually in DoWithOptions.
	c.httpClient = &http.Client{
		Transport: transport,
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

// activeRoutePolicy returns the named active route policy, or nil if none is
// configured. Returns nil when RoutePolicy is empty or the name is not found.
func (c *Client) activeRoutePolicy() *config.SSRFRoutePolicyConfig {
	name := c.cfg.SSRF.RoutePolicy
	if name == "" || c.cfg.SSRF.RoutePolicies == nil {
		return nil
	}
	p, ok := c.cfg.SSRF.RoutePolicies[name]
	if !ok {
		return nil
	}
	return &p
}

// checkSSRFURL runs a preflight SSRF check for a URL target.
// Derives the effective port from scheme defaults when the URL omits a port.
// Fails closed when the effective port cannot be derived (unknown scheme).
func (c *Client) checkSSRFURL(ctx context.Context, u *url.URL) error {
	port := effectivePort(u)
	if port == "" {
		return fmt.Errorf("%w: cannot derive effective port for scheme %q", ErrSSRFBlocked, u.Scheme)
	}
	return c.checkSSRFHostPort(ctx, u.Hostname(), port)
}

// checkSSRF validates that the address is not a blocked destination.
// The addr is in host:port format from the dialer.
func (c *Client) checkSSRF(ctx context.Context, addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
		port = ""
	}
	return c.checkSSRFHostPort(ctx, host, port)
}

// checkSSRFHostPort is the core SSRF enforcement function.
//
// Public destinations pass unconditionally. Private destinations require an
// active route policy where all three checks pass together: hostname suffix,
// resolved IP/CIDR, and destination port (all-records semantics: fail closed
// if any resolved address fails policy).
func (c *Client) checkSSRFHostPort(ctx context.Context, host, port string) error {
	// Strip IPv6 brackets if present.
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = host[1 : len(host)-1]
	}

	lowerHost := strings.ToLower(host)
	if lowerHost == "localhost" || lowerHost == "localhost.localdomain" {
		return fmt.Errorf("%w: localhost is blocked", ErrSSRFBlocked)
	}

	policy := c.activeRoutePolicy()

	// IP literal: check allow_ip_literals then CIDR and port rules.
	if ip := net.ParseIP(host); ip != nil {
		return c.checkIPWithPolicy(ip, port, policy)
	}

	// Hostname: resolve all A and AAAA records (all-records semantics).
	// Fail closed if any private IP fails policy.
	ipAddrs, err := c.getResolver().LookupIPAddr(ctx, host)
	if err != nil {
		return fmt.Errorf("%w: %s: %v", ErrHostUnresolvable, host, err)
	}

	// Evaluate host suffix match once; it applies to every private IP result.
	hostAllowed := hostMatchesSuffix(lowerHost, policy)

	for _, ipAddr := range ipAddrs {
		ip := ipAddr.IP
		if c.isAllowedIP(ip) {
			continue // public IP: always allowed
		}
		// Private IP: all three checks must pass together.
		if policy == nil {
			return fmt.Errorf("%w: %s resolves to private IP %s and no active route policy is configured",
				ErrSSRFBlocked, host, ip)
		}
		if !hostAllowed {
			return fmt.Errorf("%w: %s resolves to private IP %s and host suffix is not in allowed list",
				ErrSSRFBlocked, host, ip)
		}
		if !ipMatchesCIDRs(ip, policy) {
			return fmt.Errorf("%w: %s resolves to IP %s not in allowed private CIDRs",
				ErrSSRFBlocked, host, ip)
		}
		if !portAllowed(port, policy) {
			return fmt.Errorf("%w: destination port %s is not in allowed ports",
				ErrSSRFBlocked, port)
		}
	}

	return nil
}

// checkIPWithPolicy validates a private IP literal against the active route policy.
// Public IPs are always allowed. Private IPs require allow_ip_literals=true
// plus matching CIDR and port rules.
func (c *Client) checkIPWithPolicy(ip net.IP, port string, policy *config.SSRFRoutePolicyConfig) error {
	if c.isAllowedIP(ip) {
		return nil
	}
	if policy == nil || !policy.AllowIPLiterals {
		return fmt.Errorf("%w: IP %s is blocked (allow_ip_literals=false)", ErrSSRFBlocked, ip)
	}
	if !ipMatchesCIDRs(ip, policy) {
		return fmt.Errorf("%w: IP %s not in allowed private CIDRs", ErrSSRFBlocked, ip)
	}
	if !portAllowed(port, policy) {
		return fmt.Errorf("%w: destination port %s is not in allowed ports", ErrSSRFBlocked, port)
	}
	return nil
}

// isAllowedIP reports whether the IP is a public address.
// Returns false for loopback, private, link-local, unspecified, and multicast.
func (c *Client) isAllowedIP(ip net.IP) bool {
	return !ip.IsLoopback() &&
		!ip.IsPrivate() &&
		!ip.IsLinkLocalUnicast() &&
		!ip.IsLinkLocalMulticast() &&
		!ip.IsUnspecified() &&
		!ip.IsMulticast()
}

// hostMatchesSuffix reports whether host matches any allowed private host suffix
// in the route policy. Empty entries are skipped. A single leading dot in a
// suffix entry (e.g. ".internal") is stripped before comparison so that
// operators using the common "dot-TLD" notation get the expected behavior.
func hostMatchesSuffix(host string, policy *config.SSRFRoutePolicyConfig) bool {
	if policy == nil {
		return false
	}
	for _, suffix := range policy.AllowPrivateHostSuffixes {
		sfx := strings.ToLower(strings.TrimSpace(suffix))
		sfx = strings.TrimPrefix(sfx, ".") // normalize exactly one leading dot
		if sfx == "" {
			continue
		}
		if host == sfx || strings.HasSuffix(host, "."+sfx) {
			return true
		}
	}
	return false
}

// ipMatchesCIDRs reports whether ip falls within any allowed private CIDR in
// the route policy. Malformed CIDR entries are silently skipped.
func ipMatchesCIDRs(ip net.IP, policy *config.SSRFRoutePolicyConfig) bool {
	if policy == nil {
		return false
	}
	for _, cidr := range policy.AllowPrivateCIDRs {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// portAllowed reports whether the destination port is explicitly permitted by
// the route policy. Private-route evaluation fails closed when the policy is
// nil, the AllowedPorts list is empty, or the port string cannot be parsed.
func portAllowed(port string, policy *config.SSRFRoutePolicyConfig) bool {
	if policy == nil || len(policy.AllowedPorts) == 0 {
		return false
	}
	n, err := strconv.Atoi(port)
	if err != nil {
		return false
	}
	for _, p := range policy.AllowedPorts {
		if p == n {
			return true
		}
	}
	return false
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
