// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 OpenCloudMesh Authors

// Package access provides remote file access for incoming OCM shares.
package access

import (
	"context"
	"errors"
	"io"
	"net/http"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/federation"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/httpclient"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/ocm/discovery"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/ocm/token"
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

// Client handles accessing files from remote OCM shares.
type Client struct {
	httpClient      *httpclient.ContextClient
	discoveryClient *discovery.Client
	tokenClient     *token.Client
	profileRegistry *federation.ProfileRegistry
}

// NewClient creates a new remote access client.
func NewClient(
	httpClient *httpclient.ContextClient,
	discoveryClient *discovery.Client,
	tokenClient *token.Client,
	profileRegistry *federation.ProfileRegistry,
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
}

// Access accesses a file from a remote share.
// If MustExchangeToken is set, performs token exchange first.
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

		// Discover the sender's token endpoint
		disc, err := c.discoveryClient.Discover(ctx, share.SenderHost)
		if err != nil {
			return nil, federation.NewClassifiedError(
				federation.ReasonDiscoveryFailed,
				"failed to discover sender",
				err,
			)
		}

		// Verify sender advertises token exchange
		if !disc.HasCapability("exchange-token") {
			return nil, federation.NewClassifiedError(
				federation.ReasonPeerCapabilityMissing,
				"sender does not advertise exchange-token capability",
				nil,
			)
		}

		if disc.TokenEndPoint == "" {
			return nil, federation.NewClassifiedError(
				federation.ReasonPeerCapabilityMissing,
				"sender has no tokenEndPoint",
				nil,
			)
		}

		// Perform token exchange
		result, err := c.tokenClient.Exchange(ctx, token.ExchangeRequest{
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

	// Create request
	req, err := http.NewRequestWithContext(ctx, opts.Method, webdavURL, nil)
	if err != nil {
		return nil, err
	}

	// Add bearer token
	req.Header.Set("Authorization", "Bearer "+accessToken)

	// Execute request
	resp, err := c.httpClient.Do(ctx, req)
	if err != nil {
		return nil, federation.NewClassifiedError(
			federation.ReasonNetworkError,
			"WebDAV request failed",
			err,
		)
	}

	return &AccessResult{
		Response:       resp,
		TokenExchanged: tokenExchanged,
		AccessToken:    accessToken,
	}, nil
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
		return nil, federation.NewClassifiedError(
			federation.ReasonRemoteError,
			"remote server returned error",
			errors.New(result.Response.Status),
		)
	}

	return result.Response.Body, nil
}

// buildWebDAVURL constructs the WebDAV URL for a share.
func (c *Client) buildWebDAVURL(ctx context.Context, share *ShareInfo, subPath string) (string, error) {
	// If we have an absolute URI, use it directly
	if share.WebDAVURIAbsolute != "" {
		url := share.WebDAVURIAbsolute
		if subPath != "" {
			url += "/" + subPath
		}
		return url, nil
	}

	// Otherwise, discover the sender's WebDAV path
	disc, err := c.discoveryClient.Discover(ctx, share.SenderHost)
	if err != nil {
		return "", federation.NewClassifiedError(
			federation.ReasonDiscoveryFailed,
			"failed to discover sender",
			err,
		)
	}

	// Build URL from discovery
	webdavURL, err := disc.BuildWebDAVURL(share.WebDAVID)
	if err != nil {
		return "", federation.NewClassifiedError(
			federation.ReasonProtocolMismatch,
			"failed to build WebDAV URL",
			err,
		)
	}

	if subPath != "" {
		webdavURL += "/" + subPath
	}

	return webdavURL, nil
}
