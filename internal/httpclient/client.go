// Package httpclient provides a safe HTTP client with SSRF protections.
package httpclient

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/config"
)

var (
	ErrSSRFBlocked       = errors.New("request blocked by SSRF protection")
	ErrTooManyRedirects  = errors.New("too many redirects")
	ErrResponseTooLarge  = errors.New("response body too large")
	ErrInvalidURL        = errors.New("invalid URL")
)

// Client is a safe HTTP client with SSRF protections and bounded behavior.
type Client struct {
	cfg        *config.OutboundHTTPConfig
	httpClient *http.Client
}

// New creates a new safe HTTP client.
func New(cfg *config.OutboundHTTPConfig) *Client {
	if cfg == nil {
		cfg = &config.OutboundHTTPConfig{
			SSRFMode:           "strict",
			TimeoutMS:          10000,
			ConnectTimeoutMS:   2000,
			MaxRedirects:       3,
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
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// Check SSRF before dialing
			if cfg.SSRFMode == "strict" {
				if err := c.checkSSRF(addr); err != nil {
					return nil, err
				}
			}
			return dialer.DialContext(ctx, network, addr)
		},
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: cfg.InsecureSkipVerify,
		},
		MaxIdleConns:        10,
		IdleConnTimeout:     30 * time.Second,
		DisableCompression:  false,
		DisableKeepAlives:   false,
	}

	c.httpClient = &http.Client{
		Transport: transport,
		Timeout:   time.Duration(cfg.TimeoutMS) * time.Millisecond,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= cfg.MaxRedirects {
				return ErrTooManyRedirects
			}
			// Check SSRF on redirects too
			if cfg.SSRFMode == "strict" {
				if err := c.checkSSRFURL(req.URL.Host); err != nil {
					return err
				}
			}
			return nil
		},
	}

	return c
}

// checkSSRF validates that the address is not a private/loopback address.
func (c *Client) checkSSRF(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		// No port, use the whole thing as host
		host = addr
	}

	return c.checkSSRFURL(host)
}

// checkSSRFURL validates that the host is not a private/loopback address.
func (c *Client) checkSSRFURL(host string) error {
	// Check for localhost names
	lowerHost := strings.ToLower(host)
	if lowerHost == "localhost" || lowerHost == "localhost.localdomain" {
		return fmt.Errorf("%w: localhost is blocked", ErrSSRFBlocked)
	}

	// Resolve the hostname to IP addresses
	ips, err := net.LookupIP(host)
	if err != nil {
		// If we can't resolve, allow it (might be a valid external host)
		// The connection will fail anyway if it's not resolvable
		return nil
	}

	for _, ip := range ips {
		if !c.isAllowedIP(ip) {
			return fmt.Errorf("%w: %s resolves to blocked IP %s", ErrSSRFBlocked, host, ip)
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
func (c *Client) Get(ctx context.Context, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidURL, err)
	}
	return c.Do(req)
}

// Do performs an HTTP request with safety protections.
func (c *Client) Do(req *http.Request) (*http.Response, error) {
	// Pre-flight SSRF check
	if c.cfg.SSRFMode == "strict" {
		if err := c.checkSSRFURL(req.URL.Host); err != nil {
			return nil, err
		}
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

// GetJSON performs a GET request and reads the response body with size limit.
// The caller is responsible for closing the response body.
func (c *Client) GetJSON(ctx context.Context, url string) ([]byte, *http.Response, error) {
	resp, err := c.Get(ctx, url)
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
	return errors.Is(err, ErrSSRFBlocked)
}
