// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 OpenCloudMesh Authors

// Package access provides remote file access for incoming OCM shares.
package access

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/peercompat"
	tokenoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/token/outgoing"
	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/hostport"
)

// Share status constants (duplicated to avoid cycle).
const (
	ShareStatusAccepted = "accepted"
)

// Error codes for remote access.
var (
	ErrTokenExchangeRequired = errors.New("token exchange required but not performed")
	ErrTokenExchangeFailed   = errors.New("token exchange failed")
	ErrRemoteAccessFailed    = errors.New("remote access failed")
	ErrShareNotAccepted      = errors.New("share not accepted")
)

// ShareInfo contains the minimal share information needed for access.
// This avoids importing the shares package directly.
type ShareInfo struct {
	Status             string
	SenderHost         string
	SharedSecret       string
	WebDAVID           string
	WebDAVURIAbsolute  string
	MustExchangeToken  bool
}

// RemoteAccessor is the interface for remote share access, used by handlers.
// Extracted from Client to allow test mocks.
type RemoteAccessor interface {
	Access(ctx context.Context, opts AccessOptions) (*AccessResult, error)
}

// Client handles accessing files from remote OCM shares.
type Client struct {
	httpClient      *httpclient.ContextClient
	discoveryClient *discovery.Client
	tokenClient     *tokenoutgoing.Client
	profileRegistry *peercompat.ProfileRegistry
}

// NewClient creates a new remote access client.
// profileRegistry may be nil; when nil, Basic auth fallback is disabled.
func NewClient(
	httpClient *httpclient.ContextClient,
	discoveryClient *discovery.Client,
	tokenClient *tokenoutgoing.Client,
	profileRegistry *peercompat.ProfileRegistry,
) *Client {
	return &Client{
		httpClient:      httpClient,
		discoveryClient: discoveryClient,
		tokenClient:     tokenClient,
		profileRegistry: profileRegistry,
	}
}

// AccessOptions contains options for accessing a remote share.
type AccessOptions struct {
	// Share is the share info to access
	Share *ShareInfo

	// Method is the HTTP method (GET, PROPFIND, etc.)
	Method string

	// SubPath is an optional sub-path within the share
	SubPath string
}

// AccessResult contains the result of accessing a remote share.
type AccessResult struct {
	// Response is the HTTP response from the remote server
	Response *http.Response

	// TokenExchanged indicates whether token exchange was performed
	TokenExchanged bool

	// AccessToken is the exchanged token (if any)
	AccessToken string

	// MethodUsed describes which auth method succeeded (e.g. "bearer", "basic:token:")
	MethodUsed string
}

// basicAuthPattern defines one Basic auth credential layout to try.
type basicAuthPattern struct {
	key      string // profile-level key, e.g. "token:", "id:token"
	username func(token, webdavID string) string
	password func(token, webdavID string) string
}

// orderedBasicPatterns is the fixed order of Basic auth fallback patterns.
// Mirrors the inbound ladder in the WebDAV handler (extractCredential).
var orderedBasicPatterns = []basicAuthPattern{
	{key: "token:", username: func(t, _ string) string { return t }, password: func(_, _ string) string { return "" }},
	{key: "token:token", username: func(t, _ string) string { return t }, password: func(t, _ string) string { return t }},
	{key: ":token", username: func(_, _ string) string { return "" }, password: func(t, _ string) string { return t }},
	{key: "id:token", username: func(_, id string) string { return id }, password: func(t, _ string) string { return t }},
}

// Access accesses a file from a remote share.
// If MustExchangeToken is set, performs token exchange first.
// On Bearer 401/403, falls back to Basic auth patterns gated by the peer profile.
func (c *Client) Access(ctx context.Context, opts AccessOptions) (*AccessResult, error) {
	share := opts.Share

	// Verify share is accepted
	if share.Status != ShareStatusAccepted {
		return nil, ErrShareNotAccepted
	}

	// Determine the access token to use
	var accessToken string
	var tokenExchanged bool

	if share.MustExchangeToken {
		// Token exchange is required
		if c.tokenClient == nil {
			return nil, ErrTokenExchangeRequired
		}

		// Discover the sender's token endpoint.
		// SenderHost is bare host:port from OCM address parsing; Discover
		// expects a full URL. OCM federation mandates HTTPS.
		// TODO(issue): support HTTP for dev/local testing via profiles.
		disc, err := c.discoveryClient.Discover(ctx, senderBaseURL(share.SenderHost))
		if err != nil {
			return nil, peercompat.NewClassifiedError(
				peercompat.ReasonDiscoveryFailed,
				"failed to discover sender",
				err,
			)
		}

		// Verify sender advertises token exchange
		if !disc.HasCapability("exchange-token") {
			return nil, peercompat.NewClassifiedError(
				peercompat.ReasonPeerCapabilityMissing,
				"sender does not advertise exchange-token capability",
				nil,
			)
		}

		if disc.TokenEndPoint == "" {
			return nil, peercompat.NewClassifiedError(
				peercompat.ReasonPeerCapabilityMissing,
				"sender has no tokenEndPoint",
				nil,
			)
		}

		// Perform token exchange
		result, err := c.tokenClient.Exchange(ctx, tokenoutgoing.ExchangeRequest{
			TokenEndPoint: disc.TokenEndPoint,
			PeerDomain:    share.SenderHost,
			SharedSecret:  share.SharedSecret,
		})
		if err != nil {
			return nil, err
		}

		accessToken = result.AccessToken
		tokenExchanged = true
	} else {
		// Use shared secret directly
		accessToken = share.SharedSecret
	}

	// Build WebDAV URL
	webdavURL, err := c.buildWebDAVURL(ctx, share, opts.SubPath)
	if err != nil {
		return nil, err
	}

	// Try Bearer first
	req, err := http.NewRequestWithContext(ctx, opts.Method, webdavURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := c.httpClient.Do(ctx, req)
	if err != nil {
		return nil, peercompat.NewClassifiedError(
			peercompat.ReasonNetworkError,
			"WebDAV request failed",
			err,
		)
	}

	// Bearer succeeded (not 401/403) -- return immediately
	if resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusForbidden {
		return &AccessResult{
			Response:       resp,
			TokenExchanged: tokenExchanged,
			AccessToken:    accessToken,
			MethodUsed:     "bearer",
		}, nil
	}

	// Bearer was rejected -- try Basic auth patterns if profile registry is available
	resp.Body.Close()

	return c.tryBasicPatterns(ctx, opts, webdavURL, accessToken, tokenExchanged)
}

// tryBasicPatterns iterates the Basic auth patterns allowed by the peer profile.
// Returns the first successful result or ErrRemoteAccessFailed.
func (c *Client) tryBasicPatterns(
	ctx context.Context,
	opts AccessOptions,
	webdavURL string,
	accessToken string,
	tokenExchanged bool,
) (*AccessResult, error) {
	if c.profileRegistry == nil {
		return nil, ErrRemoteAccessFailed
	}

	profile := c.profileRegistry.GetProfile(opts.Share.SenderHost)

	for _, pat := range orderedBasicPatterns {
		if !profile.IsBasicAuthPatternAllowed(pat.key) {
			continue
		}

		req, err := http.NewRequestWithContext(ctx, opts.Method, webdavURL, nil)
		if err != nil {
			continue
		}

		user := pat.username(accessToken, opts.Share.WebDAVID)
		pass := pat.password(accessToken, opts.Share.WebDAVID)
		cred := base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
		req.Header.Set("Authorization", "Basic "+cred)

		resp, err := c.httpClient.Do(ctx, req)
		if err != nil {
			// Network error on this pattern -- try next
			continue
		}

		if resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusForbidden {
			return &AccessResult{
				Response:       resp,
				TokenExchanged: tokenExchanged,
				AccessToken:    accessToken,
				MethodUsed:     "basic:" + pat.key,
			}, nil
		}

		// This pattern was also rejected -- close body and try next
		resp.Body.Close()
	}

	return nil, ErrRemoteAccessFailed
}

// FetchFile fetches a file from a remote share and returns its content.
func (c *Client) FetchFile(ctx context.Context, share *ShareInfo) (io.ReadCloser, error) {
	result, err := c.Access(ctx, AccessOptions{
		Share:  share,
		Method: http.MethodGet,
	})
	if err != nil {
		return nil, err
	}

	if result.Response.StatusCode != http.StatusOK {
		result.Response.Body.Close()
		return nil, peercompat.NewClassifiedError(
			peercompat.ReasonRemoteError,
			"remote server returned error",
			errors.New(result.Response.Status),
		)
	}

	return result.Response.Body, nil
}

// buildWebDAVURL constructs the WebDAV URL for a share.
// When an absolute URI is present, it is validated against the sender host
// to prevent SSRF. On mismatch or parse failure, falls through to discovery.
func (c *Client) buildWebDAVURL(ctx context.Context, share *ShareInfo, subPath string) (string, error) {
	if share.WebDAVURIAbsolute != "" {
		if c.isAbsoluteURIHostValid(share.WebDAVURIAbsolute, share.SenderHost) {
			u := share.WebDAVURIAbsolute
			if subPath != "" {
				u += "/" + subPath
			}
			return u, nil
		}
		// Host mismatch or parse error -- fall through to discovery
	}

	// Discover the sender's WebDAV path
	disc, err := c.discoveryClient.Discover(ctx, senderBaseURL(share.SenderHost))
	if err != nil {
		return "", peercompat.NewClassifiedError(
			peercompat.ReasonDiscoveryFailed,
			"failed to discover sender",
			err,
		)
	}

	// Build URL from discovery
	webdavURL, err := disc.BuildWebDAVURL(share.WebDAVID)
	if err != nil {
		return "", peercompat.NewClassifiedError(
			peercompat.ReasonProtocolMismatch,
			"failed to build WebDAV URL",
			err,
		)
	}

	if subPath != "" {
		webdavURL += "/" + subPath
	}

	return webdavURL, nil
}

// isAbsoluteURIHostValid checks whether the host in an absolute WebDAV URI
// matches the expected sender host. Uses scheme-aware normalization ("https")
// to strip default ports before comparing.
func (c *Client) isAbsoluteURIHostValid(absoluteURI, senderHost string) bool {
	parsed, err := url.Parse(absoluteURI)
	if err != nil || parsed.Host == "" {
		return false
	}

	normalizedURI, err := hostport.Normalize(parsed.Host, "https")
	if err != nil {
		return false
	}

	normalizedSender, err := hostport.Normalize(senderHost, "https")
	if err != nil {
		return false
	}

	return normalizedURI == normalizedSender
}

// senderBaseURL turns a bare host[:port] into a full base URL for discovery.
// If the value already contains a scheme it is returned as-is (unit tests
// pass srv.URL which includes http://). OCM federation mandates HTTPS;
// supporting HTTP for dev/local testing is tracked as a future improvement.
func senderBaseURL(host string) string {
	if strings.Contains(host, "://") {
		return host
	}
	return "https://" + host
}
