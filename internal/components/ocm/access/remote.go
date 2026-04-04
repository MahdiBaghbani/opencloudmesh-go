// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 OpenCloudMesh Authors

// Package access provides remote file access for incoming OCM shares.
package access

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/peercompat"
	tokenoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/token/outgoing"
	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
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
	Status                string
	SenderHost            string
	OwnerHost             string // resource-hosting server; falls back to SenderHost when empty
	SharedSecret          string
	WebDAVID              string
	WebDAVURIAbsolute     string
	MustExchangeToken     bool
	SenderExchangeCapable bool
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
	peerContract    *peercompat.CompiledContract
}

// NewClient returns a Client; panics if discoveryClient is nil. A nil peer
// contract keeps legacy nil-dependency behavior and disables Basic fallback.
func NewClient(
	httpClient *httpclient.ContextClient,
	discoveryClient *discovery.Client,
	tokenClient *tokenoutgoing.Client,
	peerContract *peercompat.CompiledContract,
) *Client {
	if discoveryClient == nil {
		panic("access.NewClient: discoveryClient must not be nil")
	}
	return &Client{
		httpClient:      httpClient,
		discoveryClient: discoveryClient,
		tokenClient:     tokenClient,
		peerContract:    peerContract,
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

// accessHostForDiscovery returns OwnerHost when set, falling back to SenderHost.
func accessHostForDiscovery(share *ShareInfo) string {
	if share.OwnerHost != "" {
		return share.OwnerHost
	}
	return share.SenderHost
}

// Access fetches a remote share using the best available auth method.
// When the share requires token exchange, code flow is mandatory.
// When the owner supports exchange but the share does not mandate it,
// code flow is attempted opportunistically with a legacy-bearer fallback.
// Any Bearer 401/403 triggers a Basic auth pattern ladder.
func (c *Client) Access(ctx context.Context, opts AccessOptions) (*AccessResult, error) {
	share := opts.Share
	if share.Status != ShareStatusAccepted {
		return nil, ErrShareNotAccepted
	}

	var accessToken string
	var tokenExchanged bool

	discoveryHost := accessHostForDiscovery(share)

	if share.MustExchangeToken {
		result, err := c.doTokenExchange(ctx, share, discoveryHost)
		if err != nil {
			return nil, err
		}
		accessToken = result.AccessToken
		tokenExchanged = true
	} else if share.SenderExchangeCapable {
		// Owner supports exchange but this share does not mandate it.
		// Attempt code flow; fall back to legacy bearer on failure.
		result, err := c.doTokenExchange(ctx, share, discoveryHost)
		if err == nil {
			accessToken = result.AccessToken
			tokenExchanged = true
		} else {
			accessToken = share.SharedSecret
		}
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

func (c *Client) doTokenExchange(ctx context.Context, share *ShareInfo, discoveryHost string) (*tokenoutgoing.ExchangeResult, error) {
	if c.tokenClient == nil {
		return nil, ErrTokenExchangeRequired
	}

	origin := c.resolvePeerOrigin(discoveryHost)
	disc, err := c.discoveryClient.Discover(ctx, origin.baseURL)
	if err != nil {
		return nil, peercompat.NewClassifiedError(
			peercompat.ReasonDiscoveryFailed,
			"failed to discover owner",
			err,
		)
	}
	if !disc.HasCapability("exchange-token") {
		return nil, peercompat.NewClassifiedError(
			peercompat.ReasonPeerCapabilityMissing,
			"owner does not advertise exchange-token capability",
			nil,
		)
	}
	if disc.TokenEndPoint == "" {
		return nil, peercompat.NewClassifiedError(
			peercompat.ReasonPeerCapabilityMissing,
			"owner has no tokenEndPoint",
			nil,
		)
	}
	return c.tokenClient.Exchange(ctx, tokenoutgoing.ExchangeRequest{
		TokenEndPoint: disc.TokenEndPoint,
		PeerDomain:    origin.peerDomain,
		SharedSecret:  share.SharedSecret,
	})
}

// tryBasicPatterns tries Basic auth patterns in order; returns first success or ErrRemoteAccessFailed.
func (c *Client) tryBasicPatterns(
	ctx context.Context,
	opts AccessOptions,
	webdavURL string,
	accessToken string,
	tokenExchanged bool,
) (*AccessResult, error) {
	if c.peerContract == nil {
		return nil, fmt.Errorf("%w: no peer contract for Basic auth fallback", ErrRemoteAccessFailed)
	}

	peerDomain := accessHostForDiscovery(opts.Share)

	for _, pat := range orderedBasicPatterns {
		if !c.peerContract.IsBasicAuthPatternAllowedForPeer(peerDomain, pat.key) {
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

	return nil, fmt.Errorf("%w: all Basic auth patterns exhausted", ErrRemoteAccessFailed)
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

// buildWebDAVURL returns the WebDAV URL; validates absolute URI host against owner to prevent SSRF.
func (c *Client) buildWebDAVURL(ctx context.Context, share *ShareInfo, subPath string) (string, error) {
	host := accessHostForDiscovery(share)
	if share.WebDAVURIAbsolute != "" {
		if c.isAbsoluteURIHostValid(share.WebDAVURIAbsolute, host) {
			u := share.WebDAVURIAbsolute
			if subPath != "" {
				u += "/" + subPath
			}
			return u, nil
		}
	}
	origin := c.resolvePeerOrigin(host)
	disc, err := c.discoveryClient.Discover(ctx, origin.baseURL)
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
	return c.peerContract.IsPeerAbsoluteURIAllowed(absoluteURI, senderHost)
}

type resolvedPeerOrigin struct {
	baseURL    string
	peerDomain string
}

func (c *Client) resolvePeerOrigin(host string) resolvedPeerOrigin {
	decision := c.peerContract.ResolvePeerOrigin(host)
	return resolvedPeerOrigin{
		baseURL:    decision.BaseURL,
		peerDomain: decision.PeerDomain,
	}
}
