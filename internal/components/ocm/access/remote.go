// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 OpenCloudMesh Authors

// Package access provides remote file access for incoming OCM shares.
package access

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/peerorigin"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/reason"
	tokenoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/token/outgoing"
	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
)

// Share status constants; duplicated here to avoid import cycles.
const (
	ShareStatusAccepted = "accepted"
)

const methodUsedBearer = "bearer"

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
	MustExchangeToken     bool
	SenderExchangeCapable bool
}

// RemoteAccessor is the interface for remote share access; extracted for mocks.
type RemoteAccessor interface {
	Access(ctx context.Context, opts AccessOptions) (*AccessResult, error)
}

// Client accesses files from remote OCM shares via exchanged Bearer tokens.
type Client struct {
	httpClient      *httpclient.ContextClient
	discoveryClient *discovery.Client
	tokenClient     *tokenoutgoing.Client
	peerOrigin      *peerorigin.Resolver
}

// NewClient returns a Client; panics if discoveryClient is nil. A nil peer
// origin resolver preserves nil-dependency origin resolution behavior.
func NewClient(
	httpClient *httpclient.ContextClient,
	discoveryClient *discovery.Client,
	tokenClient *tokenoutgoing.Client,
	peerOrigin *peerorigin.Resolver,
) *Client {
	if discoveryClient == nil {
		panic("access.NewClient: discoveryClient must not be nil")
	}
	return &Client{
		httpClient:      httpClient,
		discoveryClient: discoveryClient,
		tokenClient:     tokenClient,
		peerOrigin:      peerOrigin,
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
	MethodUsed     string
}

// accessHostForDiscovery returns OwnerHost when set, falling back to SenderHost.
func accessHostForDiscovery(share *ShareInfo) string {
	if share.OwnerHost != "" {
		return share.OwnerHost
	}
	return share.SenderHost
}

// Access exchanges for an access token, then fetches the remote share with Bearer auth.
func (c *Client) Access(ctx context.Context, opts AccessOptions) (*AccessResult, error) {
	share := opts.Share
	if share.Status != ShareStatusAccepted {
		return nil, ErrShareNotAccepted
	}

	discoveryHost := accessHostForDiscovery(share)
	exchangeResult, err := c.doTokenExchange(ctx, share, discoveryHost)
	if err != nil {
		return nil, err
	}
	accessToken := exchangeResult.AccessToken

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
		return nil, reason.NewClassifiedError(
			reason.ReasonNetworkError,
			"WebDAV request failed",
			err,
		)
	}

	return &AccessResult{
		Response:       resp,
		TokenExchanged: true,
		AccessToken:    accessToken,
		MethodUsed:     methodUsedBearer,
	}, nil
}

func (c *Client) doTokenExchange(ctx context.Context, share *ShareInfo, discoveryHost string) (*tokenoutgoing.ExchangeResult, error) {
	if c.tokenClient == nil {
		return nil, ErrTokenExchangeRequired
	}

	origin := c.resolvePeerOrigin(discoveryHost)
	disc, err := c.discoveryClient.Discover(ctx, origin.baseURL)
	if err != nil {
		return nil, reason.NewClassifiedError(
			reason.ReasonDiscoveryFailed,
			"failed to discover owner",
			err,
		)
	}
	if !disc.HasCapability("exchange-token") {
		return nil, reason.NewClassifiedError(
			reason.ReasonPeerCapabilityMissing,
			"owner does not advertise exchange-token capability",
			nil,
		)
	}
	if disc.TokenEndPoint == "" {
		return nil, reason.NewClassifiedError(
			reason.ReasonPeerCapabilityMissing,
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
		return nil, reason.NewClassifiedError(
			reason.ReasonRemoteError,
			"remote server returned error",
			errors.New(result.Response.Status),
		)
	}

	return result.Response.Body, nil
}

// buildWebDAVURL returns the WebDAV URL; validates absolute URI host against owner to prevent SSRF.
func (c *Client) buildWebDAVURL(ctx context.Context, share *ShareInfo, subPath string) (string, error) {
	host := accessHostForDiscovery(share)
	if isAbsoluteWebDAVURI(share.WebDAVID) {
		if c.isAbsoluteURIHostValid(share.WebDAVID, host) {
			u := share.WebDAVID
			if subPath != "" {
				u += "/" + subPath
			}
			return u, nil
		}
	}
	origin := c.resolvePeerOrigin(host)
	disc, err := c.discoveryClient.Discover(ctx, origin.baseURL)
	if err != nil {
		return "", reason.NewClassifiedError(
			reason.ReasonDiscoveryFailed,
			"failed to discover sender",
			err,
		)
	}
	webdavURL, err := disc.BuildWebDAVURL(share.WebDAVID)
	if err != nil {
		return "", reason.NewClassifiedError(
			reason.ReasonProtocolMismatch,
			"failed to build WebDAV URL",
			err,
		)
	}

	if subPath != "" {
		webdavURL += "/" + subPath
	}

	return webdavURL, nil
}

func isAbsoluteWebDAVURI(uri string) bool {
	u, err := url.Parse(uri)
	if err != nil {
		return false
	}
	return u.IsAbs()
}

// isAbsoluteURIHostValid compares absolute URI host to sender host via scheme-aware normalization.
func (c *Client) isAbsoluteURIHostValid(absoluteURI, senderHost string) bool {
	return c.peerOrigin.IsAbsoluteURIAllowed(absoluteURI, senderHost)
}

type resolvedPeerOrigin struct {
	baseURL    string
	peerDomain string
}

func (c *Client) resolvePeerOrigin(host string) resolvedPeerOrigin {
	decision := c.peerOrigin.Resolve(host)
	return resolvedPeerOrigin{
		baseURL:    decision.BaseURL,
		peerDomain: decision.PeerDomain,
	}
}
