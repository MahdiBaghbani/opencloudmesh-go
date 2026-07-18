// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 OpenCloudMesh Authors

package outgoing

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/outboundsigning"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/reason"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/token"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/instanceid"
)

// Client performs OCM token exchange against peer token endpoints.
type Client struct {
	httpClient      *httpclient.ContextClient
	discoveryClient *discovery.Client
	signer          RequestSigner
	outboundPolicy  *outboundsigning.OutboundPolicy
	myClientID      string // normalized Sending Server authority for client_id
}

// RequestSigner signs HTTP requests for RFC 9421.
type RequestSigner interface {
	Sign(req *http.Request) error
}

// ExchangeRequest holds token exchange parameters.
type ExchangeRequest struct {
	TokenEndPoint string // receiver-advertised tokenEndPoint from discovery
	PeerDomain    string // receiver authority for profile lookup
	SharedSecret  string // authorization code (sharedSecret) to exchange
}

// ExchangeResult holds the exchange result.
type ExchangeResult struct {
	AccessToken  string
	TokenType    string
	ExpiresIn    int
	QuirkApplied string // deprecated; strict contract never applies quirks
}

// NewClient builds a token exchange client. Panics if discoveryClient is nil.
// myClientID must be the normalized Sending Server authority used as client_id.
func NewClient(
	httpClient *httpclient.ContextClient,
	discoveryClient *discovery.Client,
	signer RequestSigner,
	outboundPolicy *outboundsigning.OutboundPolicy,
	myClientID string,
) *Client {
	if discoveryClient == nil {
		panic("tokenoutgoing.NewClient: discoveryClient must not be nil")
	}
	return &Client{
		httpClient:      httpClient,
		discoveryClient: discoveryClient,
		signer:          signer,
		outboundPolicy:  outboundPolicy,
		myClientID:      myClientID,
	}
}

// Exchange performs signed form-urlencoded token exchange with authorization_code.
func (c *Client) Exchange(ctx context.Context, req ExchangeRequest) (*ExchangeResult, error) {
	var disc *discovery.Discovery
	if c.outboundPolicy != nil && c.discoveryClient != nil {
		peerBaseURL, baseErr := instanceid.NormalizePublicOrigin(req.TokenEndPoint)
		if baseErr != nil {
			return nil, reason.NewClassifiedError(
				reason.ReasonDiscoveryFailed,
				"failed to derive rediscovery origin for token exchange",
				baseErr,
			)
		}
		d, discErr := c.discoveryClient.Discover(ctx, peerBaseURL)
		if discErr != nil {
			return nil, reason.NewClassifiedError(
				reason.ReasonDiscoveryFailed,
				"failed to rediscover peer for token exchange",
				discErr,
			)
		}
		disc = d
	}

	if c.outboundPolicy != nil {
		decision := c.outboundPolicy.ShouldSign(
			outboundsigning.EndpointTokenExchange,
			req.PeerDomain,
			disc,
			c.signer != nil,
		)
		if decision.Error != nil {
			return nil, reason.NewClassifiedError(
				reason.ReasonSignatureRequired,
				decision.Reason,
				decision.Error,
			)
		}
		if !decision.ShouldSign {
			reasonCode := reason.ReasonSignatureRequired
			message := "token exchange requires signing"
			cause := fmt.Errorf("unsigned token exchange is not supported")
			if disc != nil && !disc.HasCapability("exchange-token") {
				reasonCode = reason.ReasonPeerCapabilityMissing
				message = decision.Reason
				cause = fmt.Errorf("peer does not advertise exchange-token capability")
			}
			return nil, reason.NewClassifiedError(reasonCode, message, cause)
		}
	}

	if c.signer == nil {
		return nil, reason.NewClassifiedError(
			reason.ReasonSignatureRequired,
			"token exchange requires signing",
			fmt.Errorf("no signer configured"),
		)
	}

	httpReq, err := c.buildFormRequest(ctx, req, token.GrantTypeAuthorizationCode)
	if err != nil {
		return nil, err
	}
	if err := c.signer.Sign(httpReq); err != nil {
		return nil, reason.NewClassifiedError(
			reason.ReasonSignatureInvalid,
			"failed to sign request",
			err,
		)
	}

	return c.doRequest(ctx, httpReq)
}

// buildFormRequest builds a form-urlencoded POST to the receiver tokenEndPoint.
func (c *Client) buildFormRequest(ctx context.Context, req ExchangeRequest, grantType string) (*http.Request, error) {
	form := url.Values{}
	form.Set("grant_type", grantType)
	form.Set("client_id", c.myClientID)
	form.Set("code", req.SharedSecret)

	httpReq, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		req.TokenEndPoint,
		strings.NewReader(form.Encode()),
	)
	if err != nil {
		return nil, err
	}

	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	httpReq.Header.Set("Accept", "application/json")

	return httpReq, nil
}

// doRequest sends the request and parses the token response.
func (c *Client) doRequest(ctx context.Context, req *http.Request) (*ExchangeResult, error) {
	resp, err := c.httpClient.Do(ctx, req)
	if err != nil {
		return nil, reason.NewClassifiedError(
			reason.ReasonNetworkError,
			"token exchange request failed",
			err,
		)
	}
	defer resp.Body.Close()

	maxBytes := int64(config.DefaultMaxResponseBytes)
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return nil, reason.NewClassifiedError(
			reason.ReasonNetworkError,
			"failed to read response",
			err,
		)
	}
	if int64(len(body)) > maxBytes {
		return nil, reason.NewClassifiedError(
			reason.ReasonTokenInvalidFormat,
			"token response too large",
			httpclient.ErrResponseTooLarge,
		)
	}

	if resp.StatusCode >= 400 {
		var oauthErr token.OAuthError
		if json.Unmarshal(body, &oauthErr) == nil && oauthErr.Error != "" {
			return nil, c.classifyOAuthError(oauthErr)
		}
		if resp.StatusCode == http.StatusUnauthorized && req.Header.Get("Signature") != "" {
			return nil, reason.NewClassifiedError(
				reason.ReasonSignatureRequired,
				fmt.Sprintf("token exchange failed with status %d", resp.StatusCode),
				nil,
			)
		}
		return nil, reason.NewClassifiedError(
			reason.ReasonTokenExchangeFailed,
			fmt.Sprintf("token exchange failed with status %d", resp.StatusCode),
			nil,
		)
	}

	mediaType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return nil, reason.NewClassifiedError(
			reason.ReasonTokenInvalidFormat,
			"token response must be application/json",
			fmt.Errorf("content-type %q", resp.Header.Get("Content-Type")),
		)
	}

	var tokenResp token.TokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, reason.NewClassifiedError(
			reason.ReasonTokenInvalidFormat,
			"failed to parse token response",
			err,
		)
	}

	if tokenResp.AccessToken == "" {
		return nil, reason.NewClassifiedError(
			reason.ReasonTokenInvalidFormat,
			"access_token is required",
			nil,
		)
	}
	if !strings.EqualFold(tokenResp.TokenType, "Bearer") {
		return nil, reason.NewClassifiedError(
			reason.ReasonTokenInvalidFormat,
			"token_type must be Bearer",
			fmt.Errorf("got %q", tokenResp.TokenType),
		)
	}
	if tokenResp.ExpiresIn <= 0 {
		return nil, reason.NewClassifiedError(
			reason.ReasonTokenInvalidFormat,
			"expires_in must be positive",
			fmt.Errorf("got %d", tokenResp.ExpiresIn),
		)
	}

	return &ExchangeResult{
		AccessToken: tokenResp.AccessToken,
		TokenType:   tokenResp.TokenType,
		ExpiresIn:   tokenResp.ExpiresIn,
	}, nil
}

// classifyOAuthError maps OAuth error codes to reason codes.
func (c *Client) classifyOAuthError(oauthErr token.OAuthError) error {
	var reasonCode string
	switch oauthErr.Error {
	case token.ErrorInvalidGrant:
		reasonCode = reason.ReasonTokenExchangeFailed
	case token.ErrorInvalidClient:
		reasonCode = reason.ReasonTokenExchangeFailed
	case token.ErrorUnauthorized:
		reasonCode = reason.ReasonSignatureRequired
	default:
		reasonCode = reason.ReasonTokenExchangeFailed
	}

	return reason.NewClassifiedError(
		reasonCode,
		oauthErr.ErrorDescription,
		nil,
	)
}
