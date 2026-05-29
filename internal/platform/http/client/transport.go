// Package client provides a safe outbound HTTP client with SSRF protections.
// See client.go for the concrete implementation.
//
// This file holds the proxy selection and transport/dialer construction used by
// New in client.go. buildProxyFunc is a pure helper that snapshots proxy
// configuration; newTransport and ssrfCheckedDial assemble the SSRF-aware
// http.Transport for a Client.

package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"golang.org/x/net/http/httpproxy"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
)

// buildProxyFunc builds the request-aware proxy function and the set of trusted
// proxy hosts from the outbound config.
//
// Precedence: explicit ProxyURL > env fallback > direct (nil proxy).
//
// trustedProxyHosts is used at dial time to skip the SSRF check only for
// dials that go to an operator-trusted proxy host. All other dials -
// including direct connections when NO_PROXY routes around an env proxy -
// are still checked. Destination SSRF is also enforced unconditionally by
// the preflight check in DoWithOptions and the redirect check in
// followRedirect; the dial check is defense-in-depth for the direct-dial
// case.
func buildProxyFunc(cfg *config.OutboundHTTPConfig) (func(*http.Request) (*url.URL, error), map[string]struct{}) {
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

	return proxyFunc, trustedHosts
}

// newTransport builds the SSRF-aware HTTP transport for this client using the
// supplied root CAs and proxy function.
func (c *Client) newTransport(rootCAs *x509.CertPool, proxyFunc func(*http.Request) (*url.URL, error)) *http.Transport {
	dialer := &net.Dialer{
		Timeout: time.Duration(c.cfg.ConnectTimeoutMS) * time.Millisecond,
	}

	return &http.Transport{
		Proxy:       proxyFunc,
		DialContext: c.ssrfCheckedDial(dialer),
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: c.cfg.InsecureSkipVerify,
			RootCAs:            rootCAs,
		},
		MaxIdleConns:       10,
		IdleConnTimeout:    30 * time.Second,
		DisableCompression: false,
		DisableKeepAlives:  false,
	}
}

// ssrfCheckedDial returns a DialContext that enforces SSRF protection before
// dialing.
//
// In strict mode: skip the SSRF check only when dialing a trusted proxy host
// (operator-controlled). All other dials - direct connections including those
// caused by NO_PROXY - are checked.
func (c *Client) ssrfCheckedDial(dialer *net.Dialer) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
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
	}
}
