// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

// Package access provides remote file access for incoming OCM shares.
package access

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"slices"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/peerorigin"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/reason"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	tokenoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/token/outgoing"
	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
)

// Share status constants; duplicated here to avoid import cycles.
const (
	ShareStatusAccepted = "accepted"
)

// Protocol labels for shares. Only WebDAV is supported for remote access;
// ProtocolWebapp may appear on stored shares but the access plane rejects it.
const (
	ProtocolWebDAV = "webdav"
	ProtocolWebapp = "webapp"
)

// Access authorization modes returned by DecideAccessAuth.
const (
	AccessModeTokenExchange        = "token-exchange"
	AccessModeSharedSecret         = "shared-secret"
	AccessModeFailClosed           = "fail-closed"
	AccessModeExchangeThenFallback = "exchange-then-fallback"
)

var (
	// ErrTokenExchangeRequired reports a required token exchange that was not performed.
	ErrTokenExchangeRequired = errors.New("token exchange required but not performed")
	// ErrTokenExchangeFailed reports a failed token exchange.
	ErrTokenExchangeFailed = errors.New("token exchange failed")
	// ErrRemoteAccessFailed reports a failed remote file access attempt.
	ErrRemoteAccessFailed = errors.New("remote access failed")
	// ErrShareNotAccepted reports access to a share that is not accepted.
	ErrShareNotAccepted = errors.New("share not accepted")
	// ErrProtocolRequired reports a non-WebDAV access protocol request.
	ErrProtocolRequired = errors.New("access protocol must be webdav")
)

// ShareInfo holds the minimal share fields needed for remote access (avoids import cycles).
type ShareInfo struct {
	Status            string
	SenderHost        string
	OwnerHost         string // resource-hosting server; falls back to SenderHost when empty
	SharedSecret      string
	ProtocolName      string
	Requirements      []string
	WebDAVID          string
	WebappURI         string
	WebappTargets     []string
	WebappPermissions []string
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

// AccessOptions holds the parameters for a remote access request.
type AccessOptions struct {
	Share    *ShareInfo
	Protocol string // "webdav"; must be set explicitly
	Method   string // GET, PROPFIND, etc.
	SubPath  string
}

// AccessResult holds the HTTP response and access token from a remote access request.
type AccessResult struct {
	Response    *http.Response
	AccessToken string
}

// AccessAuthDecision is the result of DecideAccessAuth.
type AccessAuthDecision struct {
	Mode       string
	HTTPStatus int
}

// accessHostForDiscovery returns OwnerHost when set, falling back to SenderHost.
func accessHostForDiscovery(share *ShareInfo) string {
	if share.OwnerHost != "" {
		return share.OwnerHost
	}

	return share.SenderHost
}

// DecideAccessAuth implements the access-plane decision table.
// The caller must have already prefetched discovery; a nil share or document fails closed.
func (c *Client) DecideAccessAuth(opts AccessOptions, disc *spec.Discovery) (AccessAuthDecision, error) {
	if opts.Share == nil {
		return failClosedAccessDecision(
			reason.ReasonProtocolMismatch,
			"access share is required",
			nil,
		)
	}

	if opts.Protocol != ProtocolWebDAV {
		return failClosedAccessDecision(
			reason.ReasonProtocolMismatch,
			"access protocol must be webdav",
			ErrProtocolRequired,
		)
	}

	if disc == nil {
		return failClosedAccessDecision(
			reason.ReasonDiscoveryFailed,
			"discovery unavailable",
			nil,
		)
	}

	return c.decideWebDAVAuth(opts, disc)
}

func failClosedAccessDecision(reasonCode, message string, cause error) (AccessAuthDecision, error) {
	return AccessAuthDecision{
		Mode:       AccessModeFailClosed,
		HTTPStatus: http.StatusForbidden,
	}, reason.NewClassifiedError(reasonCode, message, cause)
}

func (c *Client) decideWebDAVAuth(opts AccessOptions, disc *spec.Discovery) (AccessAuthDecision, error) {
	requires := hasRequirement(opts.Share.Requirements, spec.RequirementMustExchangeToken)
	capable := disc.SupportsTokenExchange()

	if requires {
		if !capable {
			return failClosedAccessDecision(
				reason.ReasonPeerCapabilityMissing,
				"peer does not advertise "+spec.CapabilityExchangeToken+" or tokenEndPoint",
				nil,
			)
		}

		if err := c.checkSignaturePolicy(disc); err != nil {
			return failClosedAccessDecision(
				reason.ReasonSignatureRequired,
				"peer requires HTTP request signatures that are unsupported",
				err,
			)
		}

		return AccessAuthDecision{Mode: AccessModeTokenExchange, HTTPStatus: http.StatusOK}, nil
	}

	// When must-exchange-token is omitted but the peer advertises token
	// exchange, the receiver MAY attempt exchange first and MUST fall back to
	// legacy shared-secret access if exchange fails.
	// See https://github.com/cs3org/OCM-API/blob/6a0586183cbef10ecae9dedc42561806447eb2f5/IETF-OCM.md#L1594-L1597
	if capable {
		return AccessAuthDecision{Mode: AccessModeExchangeThenFallback, HTTPStatus: http.StatusOK}, nil
	}

	return AccessAuthDecision{Mode: AccessModeSharedSecret, HTTPStatus: http.StatusOK}, nil
}

func hasRequirement(reqs []string, target string) bool {
	return slices.Contains(reqs, target)
}

// Access authorizes and performs the remote access request. It performs exactly
// one discovery per call and uses that prefetched document for the authorization
// decision, URL construction, and token exchange.
func (c *Client) Access(ctx context.Context, opts AccessOptions) (*AccessResult, error) {
	if opts.Share == nil {
		return nil, reason.NewClassifiedError(
			reason.ReasonProtocolMismatch,
			"access share is required",
			nil,
		)
	}

	share := opts.Share
	if share.Status != ShareStatusAccepted {
		return nil, ErrShareNotAccepted
	}

	if opts.Protocol != ProtocolWebDAV {
		return nil, reason.NewClassifiedError(
			reason.ReasonProtocolMismatch,
			"access protocol must be webdav",
			ErrProtocolRequired,
		)
	}

	discoveryHost := accessHostForDiscovery(share)
	origin := c.resolvePeerOrigin(discoveryHost)

	disc, err := c.discoveryClient.Discover(ctx, origin.baseURL)
	if err != nil {
		return nil, reason.NewClassifiedError(
			reason.ReasonDiscoveryFailed,
			"failed to discover owner",
			err,
		)
	}

	decision, err := c.DecideAccessAuth(opts, disc)
	if err != nil {
		return nil, err
	}

	switch decision.Mode {
	case AccessModeTokenExchange:
		return c.accessTokenExchange(ctx, share, opts, disc)
	case AccessModeSharedSecret:
		return c.accessSharedSecret(ctx, share, opts, disc)
	case AccessModeExchangeThenFallback:
		// Attempt token exchange first; on any failure fall back to the
		// legacy shared-secret bearer. Legacy shared secrets are retained for
		// backwards compatibility; implementers SHOULD prefer short-lived
		// tokens when available.
		// See https://github.com/cs3org/OCM-API/blob/6a0586183cbef10ecae9dedc42561806447eb2f5/IETF-OCM.md#L1594-L1597
		// See https://github.com/cs3org/OCM-API/blob/6a0586183cbef10ecae9dedc42561806447eb2f5/IETF-OCM.md#L1998-L2002
		result, err := c.accessTokenExchange(ctx, share, opts, disc)
		if err == nil {
			return result, nil
		}
		// On exchange failure the exchange error is discarded, not wrapped or
		// retained in the returned error chain. Only a safe fixed warning is
		// logged; fallback then proceeds with a fresh shared-secret access result.
		slog.WarnContext(ctx, "optional token exchange failed; falling back to legacy shared-secret access")

		return c.accessSharedSecret(ctx, share, opts, disc)
	default:
		return nil, reason.NewClassifiedError(
			reason.ReasonPeerCapabilityMissing,
			"access denied",
			nil,
		)
	}
}

func (c *Client) accessTokenExchange(ctx context.Context, share *ShareInfo, opts AccessOptions, disc *spec.Discovery) (*AccessResult, error) {
	if err := c.checkSignaturePolicy(disc); err != nil {
		return nil, err
	}

	if c.tokenClient == nil {
		return nil, ErrTokenExchangeRequired
	}

	exchangeResult, err := c.tokenClient.Exchange(ctx, tokenoutgoing.ExchangeRequest{
		TokenEndPoint: disc.TokenEndPoint,
		SharedSecret:  share.SharedSecret,
	}, disc)
	if err != nil {
		return nil, fmt.Errorf("ocm: exchange access token: %w", err)
	}

	accessToken := exchangeResult.AccessToken

	webdavURL, err := c.buildWebDAVURL(share, opts.SubPath, disc)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, opts.Method, webdavURL, nil)
	if err != nil {
		return nil, fmt.Errorf("ocm: build webdav request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := c.httpClient.Do(ctx, req)
	if err != nil {
		if resp != nil {
			//nolint:errcheck // best-effort cleanup; error is not actionable
			resp.Body.Close()
		}

		return nil, reason.NewClassifiedError(
			reason.ReasonNetworkError,
			"WebDAV request failed",
			err,
		)
	}

	return &AccessResult{
		Response:    resp,
		AccessToken: accessToken,
	}, nil
}

func (c *Client) accessSharedSecret(ctx context.Context, share *ShareInfo, opts AccessOptions, disc *spec.Discovery) (*AccessResult, error) {
	webdavURL, err := c.buildWebDAVURL(share, opts.SubPath, disc)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, opts.Method, webdavURL, nil)
	if err != nil {
		return nil, fmt.Errorf("ocm: build webdav request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+share.SharedSecret)

	resp, err := c.httpClient.Do(ctx, req)
	if err != nil {
		if resp != nil {
			//nolint:errcheck // best-effort cleanup; error is not actionable
			resp.Body.Close()
		}

		return nil, reason.NewClassifiedError(
			reason.ReasonNetworkError,
			"WebDAV request failed",
			err,
		)
	}

	return &AccessResult{
		Response:    resp,
		AccessToken: share.SharedSecret,
	}, nil
}

func (c *Client) checkSignaturePolicy(disc *spec.Discovery) error {
	if disc.RequiresHTTPSig() && !disc.IsHTTPSigCapable() {
		return reason.NewClassifiedError(
			reason.ReasonSignatureRequired,
			"peer requires signatures but does not advertise "+spec.CapabilityHTTPSig+" capability",
			nil,
		)
	}

	return nil
}

// FetchFile fetches a shared file's body via WebDAV GET, returning the response reader.
func (c *Client) FetchFile(ctx context.Context, share *ShareInfo) (io.ReadCloser, error) {
	result, err := c.Access(ctx, AccessOptions{
		Share:    share,
		Protocol: ProtocolWebDAV,
		Method:   http.MethodGet,
	})
	if err != nil {
		return nil, err
	}

	if result.Response.StatusCode != http.StatusOK {
		//nolint:errcheck // best-effort cleanup; error is not actionable
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
func (c *Client) buildWebDAVURL(share *ShareInfo, subPath string, disc *spec.Discovery) (string, error) {
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
	baseURL string
}

func (c *Client) resolvePeerOrigin(host string) resolvedPeerOrigin {
	decision := c.peerOrigin.Resolve(host)

	return resolvedPeerOrigin{
		baseURL: decision.BaseURL,
	}
}
