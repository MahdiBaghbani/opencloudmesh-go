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

// Share status constants; duplicated here to avoid import cycles.
const (
	ShareStatusAccepted = "accepted"
)

var (
	ErrTokenExchangeRequired = errors.New("token exchange required but not performed")
	ErrTokenExchangeFailed   = errors.New("token exchange failed")
	ErrRemoteAccessFailed    = errors.New("remote access failed")
	ErrShareNotAccepted      = errors.New("share not accepted")
)

// ShareInfo holds the minimal share fields needed for remote access (avoids import cycles).
type ShareInfo struct {
	Status             string
	SenderHost         string
	SharedSecret       string
	WebDAVID           string
	WebDAVURIAbsolute  string
	MustExchangeToken  bool
}

// RemoteAccessor is the interface for remote share access; extracted for mocks.
type RemoteAccessor interface {
	Access(ctx context.Context, opts AccessOptions) (*AccessResult, error)
}

// Client accesses files from remote OCM shares (WebDAV, token exchange, Basic fallback).
type Client struct {
	httpClient      *httpclient.ContextClient
	discoveryClient *discovery.Client
	tokenClient     *tokenoutgoing.Client
	profileRegistry *peercompat.ProfileRegistry
}

// NewClient returns a Client; nil profileRegistry disables Basic auth fallback.
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

type AccessOptions struct {
	Share   *ShareInfo
	Method  string // GET, PROPFIND, etc.
	SubPath string
}

type AccessResult struct {
	Response       *http.Response
	TokenExchanged bool
	AccessToken    string
	MethodUsed     string // e.g. "bearer", "basic:token:"
}

type basicAuthPattern struct {
	key      string // profile-level key, e.g. "token:", "id:token"
	username func(token, webdavID string) string
	password func(token, webdavID string) string
}

// orderedBasicPatterns matches WebDAV handler extractCredential order.
var orderedBasicPatterns = []basicAuthPattern{
	{key: "token:", username: func(t, _ string) string { return t }, password: func(_, _ string) string { return "" }},
	{key: "token:token", username: func(t, _ string) string { return t }, password: func(t, _ string) string { return t }},
	{key: ":token", username: func(_, _ string) string { return "" }, password: func(t, _ string) string { return t }},
	{key: "id:token", username: func(_, id string) string { return id }, password: func(t, _ string) string { return t }},
}

// Access fetches a remote share; performs token exchange if MustExchangeToken; on Bearer 401/403 tries Basic patterns.
func (c *Client) Access(ctx context.Context, opts AccessOptions) (*AccessResult, error) {
	share := opts.Share
	if share.Status != ShareStatusAccepted {
		return nil, ErrShareNotAccepted
	}

	// Determine the access token to use
	var accessToken string
	var tokenExchanged bool

	if share.MustExchangeToken {
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
		accessToken = share.SharedSecret
	}
	webdavURL, err := c.buildWebDAVURL(ctx, share, opts.SubPath)
	if err != nil {
		return nil, err
	}

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
	if resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusForbidden {
		return &AccessResult{
			Response:       resp,
			TokenExchanged: tokenExchanged,
			AccessToken:    accessToken,
			MethodUsed:     "bearer",
		}, nil
	}
	resp.Body.Close()

	return c.tryBasicPatterns(ctx, opts, webdavURL, accessToken, tokenExchanged)
}

// tryBasicPatterns tries Basic auth patterns in order; returns first success or ErrRemoteAccessFailed.
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
		resp.Body.Close()
	}

	return nil, ErrRemoteAccessFailed
}

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

// buildWebDAVURL returns the WebDAV URL; validates absolute URI host against sender to prevent SSRF.
func (c *Client) buildWebDAVURL(ctx context.Context, share *ShareInfo, subPath string) (string, error) {
	if share.WebDAVURIAbsolute != "" {
		if c.isAbsoluteURIHostValid(share.WebDAVURIAbsolute, share.SenderHost) {
			u := share.WebDAVURIAbsolute
			if subPath != "" {
				u += "/" + subPath
			}
			return u, nil
		}
	}
	disc, err := c.discoveryClient.Discover(ctx, senderBaseURL(share.SenderHost))
	if err != nil {
		return "", peercompat.NewClassifiedError(
			peercompat.ReasonDiscoveryFailed,
			"failed to discover sender",
			err,
		)
	}
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

// isAbsoluteURIHostValid compares absolute URI host to sender host via scheme-aware normalization.
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

// senderBaseURL returns "https://" + host for bare host[:port]; passes through values with scheme (e.g. srv.URL).
func senderBaseURL(host string) string {
	if strings.Contains(host, "://") {
		return host
	}
	return "https://" + host
}
