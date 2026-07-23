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
	"strings"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/peerorigin"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/reason"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	tokenoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/token/outgoing"
	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/localidentity"
)

// Share status constants; duplicated here to avoid import cycles.
const (
	ShareStatusAccepted = "accepted"
)

// Protocol selectors for the access plane. The caller must choose one;
// there is no implicit webapp-or-webdav fallback.
const (
	ProtocolWebDAV = "webdav"
	ProtocolWebapp = "webapp"
)

// Access authorization modes returned by DecideAccessAuth.
const (
	AccessModeTokenExchange  = "token-exchange"
	AccessModeSharedSecret   = "shared-secret"
	AccessModeWebappCodeFlow = "webapp-code-flow"
	AccessModeFailClosed     = "fail-closed"
)

var (
	ErrTokenExchangeRequired = errors.New("token exchange required but not performed")
	ErrTokenExchangeFailed   = errors.New("token exchange failed")
	ErrRemoteAccessFailed    = errors.New("remote access failed")
	ErrShareNotAccepted      = errors.New("share not accepted")
	ErrProtocolRequired      = errors.New("access protocol must be set to webdav or webapp")
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
	httpClient           *httpclient.ContextClient
	discoveryClient      *discovery.Client
	tokenClient          *tokenoutgoing.Client
	peerOrigin           *peerorigin.Resolver
	localIdentity        localidentity.Identity
	webappReceiveTargets []string
	webappRedirectPath   string
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

// SetLocalIdentity configures the local identity used to build receiver-side
// webapp URLs such as expired_session_redirect_uri.
func (c *Client) SetLocalIdentity(id localidentity.Identity) {
	c.localIdentity = id
}

// SetWebappReceiveTargets configures the local webapp-receive targets used for
// the target-intersection check during webapp access.
func (c *Client) SetWebappReceiveTargets(targets []string) {
	c.webappReceiveTargets = targets
}

// SetWebappRedirectPath configures the path appended to the local endpoint base
// when building expired_session_redirect_uri. Defaults to /ocm/webapp when empty.
func (c *Client) SetWebappRedirectPath(path string) {
	c.webappRedirectPath = path
}

type AccessOptions struct {
	Share    *ShareInfo
	Protocol string // "webdav" or "webapp"; must be set explicitly
	Method   string // GET, PROPFIND, etc.
	SubPath  string
}

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
	if opts.Protocol != ProtocolWebDAV && opts.Protocol != ProtocolWebapp {
		return failClosedAccessDecision(
			reason.ReasonProtocolMismatch,
			"access protocol must be webdav or webapp",
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

	switch opts.Protocol {
	case ProtocolWebapp:
		return c.decideWebappAuth(opts, disc)
	default:
		return c.decideWebDAVAuth(opts, disc)
	}
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

	return AccessAuthDecision{Mode: AccessModeSharedSecret, HTTPStatus: http.StatusOK}, nil
}

func (c *Client) decideWebappAuth(opts AccessOptions, disc *spec.Discovery) (AccessAuthDecision, error) {
	share := opts.Share
	if share.WebappURI == "" || len(share.WebappTargets) == 0 || share.SharedSecret == "" {
		return failClosedAccessDecision(
			reason.ReasonProtocolMismatch,
			"webapp share missing required fields",
			nil,
		)
	}
	if !hasRequirement(share.Requirements, spec.RequirementMustExchangeToken) {
		return failClosedAccessDecision(
			reason.ReasonProtocolMismatch,
			"webapp access requires must-exchange-token",
			nil,
		)
	}
	if !disc.SupportsTokenExchange() {
		return failClosedAccessDecision(
			reason.ReasonPeerCapabilityMissing,
			"peer does not support token exchange",
			nil,
		)
	}
	if err := c.checkSignaturePolicy(disc); err != nil {
		return failClosedAccessDecision(
			reason.ReasonSignatureRequired,
			err.Error(),
			err,
		)
	}
	if len(c.webappReceiveTargets) == 0 || len(intersectTargets(share.WebappTargets, c.webappReceiveTargets)) == 0 {
		return failClosedAccessDecision(
			reason.ReasonProtocolMismatch,
			"no supported webapp target intersection",
			nil,
		)
	}
	return AccessAuthDecision{Mode: AccessModeWebappCodeFlow, HTTPStatus: http.StatusOK}, nil
}

func hasRequirement(reqs []string, target string) bool {
	for _, r := range reqs {
		if r == target {
			return true
		}
	}
	return false
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

	if opts.Protocol != ProtocolWebDAV && opts.Protocol != ProtocolWebapp {
		return nil, reason.NewClassifiedError(
			reason.ReasonProtocolMismatch,
			"access protocol must be webdav or webapp",
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
	case AccessModeWebappCodeFlow:
		return c.accessWebappCodeFlow(ctx, share, opts, disc)
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
	})
	if err != nil {
		return nil, err
	}
	accessToken := exchangeResult.AccessToken

	webdavURL, err := c.buildWebDAVURL(ctx, share, opts.SubPath, disc)
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
		Response:    resp,
		AccessToken: accessToken,
	}, nil
}

func (c *Client) accessSharedSecret(ctx context.Context, share *ShareInfo, opts AccessOptions, disc *spec.Discovery) (*AccessResult, error) {
	webdavURL, err := c.buildWebDAVURL(ctx, share, opts.SubPath, disc)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, opts.Method, webdavURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+share.SharedSecret)

	resp, err := c.httpClient.Do(ctx, req)
	if err != nil {
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

func (c *Client) accessWebappCodeFlow(ctx context.Context, share *ShareInfo, opts AccessOptions, disc *spec.Discovery) (*AccessResult, error) {
	if c.tokenClient == nil {
		return nil, ErrTokenExchangeRequired
	}

	exchangeResult, err := c.tokenClient.Exchange(ctx, tokenoutgoing.ExchangeRequest{
		TokenEndPoint: disc.TokenEndPoint,
		SharedSecret:  share.SharedSecret,
	})
	if err != nil {
		return nil, err
	}

	return c.doWebappFormPost(ctx, share, exchangeResult.AccessToken)
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

func (c *Client) doWebappFormPost(ctx context.Context, share *ShareInfo, accessToken string) (*AccessResult, error) {
	redirectURI, err := c.buildExpiredSessionRedirectURI()
	if err != nil {
		return nil, err
	}

	form := url.Values{}
	form.Set("access_token", accessToken)
	form.Set("expired_session_redirect_uri", redirectURI)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, share.WebappURI, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(ctx, req)
	if err != nil {
		return nil, reason.NewClassifiedError(
			reason.ReasonNetworkError,
			"webapp form POST failed",
			err,
		)
	}

	return &AccessResult{
		Response:    resp,
		AccessToken: accessToken,
	}, nil
}

func (c *Client) buildExpiredSessionRedirectURI() (string, error) {
	if c.localIdentity.Origin == "" {
		return "", reason.NewClassifiedError(
			reason.ReasonProtocolMismatch,
			"local identity origin required for webapp redirect URI",
			nil,
		)
	}
	path := c.webappRedirectPath
	if path == "" {
		path = "/ocm/webapp"
	}
	base := c.localIdentity.Origin
	if c.localIdentity.ExternalBasePath != "" {
		base = c.localIdentity.EndpointBase
	}
	return base + path, nil
}

func intersectTargets(a, b []string) []string {
	set := make(map[string]struct{}, len(b))
	for _, t := range b {
		set[t] = struct{}{}
	}
	result := make([]string, 0, len(a))
	for _, t := range a {
		if _, ok := set[t]; ok {
			result = append(result, t)
		}
	}
	return result
}

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
func (c *Client) buildWebDAVURL(ctx context.Context, share *ShareInfo, subPath string, disc *spec.Discovery) (string, error) {
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
