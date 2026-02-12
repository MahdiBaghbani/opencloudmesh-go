// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 OpenCloudMesh Authors

package outgoing

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/outboundsigning"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/peercompat"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/token"
	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
)

// Client performs OCM token exchange against peer token endpoints.
type Client struct {
	httpClient     *httpclient.ContextClient
	signer         RequestSigner
	outboundPolicy *outboundsigning.OutboundPolicy
	myClientID     string // This instance's FQDN for client_id
}

// RequestSigner signs HTTP requests for RFC 9421.
type RequestSigner interface {
	Sign(req *http.Request) error
}

// ExchangeRequest holds token exchange parameters.
type ExchangeRequest struct {
	TokenEndPoint string // The peer's tokenEndPoint from discovery
	PeerDomain    string // The peer's domain (for profile lookup)
	SharedSecret  string // The code/sharedSecret to exchange
}

// ExchangeResult holds the exchange result.
type ExchangeResult struct {
	AccessToken  string
	TokenType    string
	ExpiresIn    int
	QuirkApplied string // Name of quirk applied, if any
}

// NewClient builds a token exchange client.
func NewClient(
	httpClient *httpclient.ContextClient,
	signer RequestSigner,
	outboundPolicy *outboundsigning.OutboundPolicy,
	myClientID string,
) *Client {
	return &Client{
		httpClient:     httpClient,
		signer:         signer,
		outboundPolicy: outboundPolicy,
		myClientID:     myClientID,
	}
}

// Exchange performs token exchange with the peer; OutboundPolicy controls signing.
func (c *Client) Exchange(ctx context.Context, req ExchangeRequest) (*ExchangeResult, error) {
	var shouldSign bool
	var profile *peercompat.Profile

	if c.outboundPolicy != nil {
		decision := c.outboundPolicy.ShouldSign(
			outboundsigning.EndpointTokenExchange,
			req.PeerDomain,
			nil, // No discovery doc for token exchange signing decision
			c.signer != nil,
		)
		if decision.Error != nil {
			return nil, peercompat.NewClassifiedError(
				peercompat.ReasonSignatureRequired,
				decision.Reason,
				decision.Error,
			)
		}
		shouldSign = decision.ShouldSign

		if c.outboundPolicy.ProfileRegistry != nil {
			profile = c.outboundPolicy.ProfileRegistry.GetProfile(req.PeerDomain)
		}
	}

	grantType := token.GrantTypeAuthorizationCode
	if profile != nil {
		grantType = profile.GetTokenExchangeGrantType()
	}

	if !shouldSign {
		return c.exchangeUnsigned(ctx, req, grantType)
	}

	result, err := c.exchangeSigned(ctx, req, grantType, false)
	if err == nil {
		return result, nil
	}

	reasonCode := peercompat.ClassifyError(err)

	if profile != nil && c.outboundPolicy != nil {
		if profile.HasQuirk("accept_plain_token") &&
			(reasonCode == peercompat.ReasonSignatureRequired ||
				reasonCode == peercompat.ReasonSignatureInvalid ||
				reasonCode == peercompat.ReasonKeyNotFound) {
			result, err = c.exchangeUnsigned(ctx, req, grantType)
			if err == nil {
				result.QuirkApplied = "accept_plain_token"
				return result, nil
			}
		}
		if profile.HasQuirk("send_token_in_body") &&
			(reasonCode == peercompat.ReasonTokenExchangeFailed ||
				reasonCode == peercompat.ReasonProtocolMismatch) {
			result, err = c.exchangeJSON(ctx, req, grantType, shouldSign)
			if err == nil {
				result.QuirkApplied = "send_token_in_body"
				return result, nil
			}
		}
	}
	return nil, peercompat.NewClassifiedError(reasonCode, "token exchange failed", err)
}

// exchangeSigned sends a signed token exchange request.
func (c *Client) exchangeSigned(ctx context.Context, req ExchangeRequest, grantType string, useJSON bool) (*ExchangeResult, error) {
	var httpReq *http.Request
	var err error

	if useJSON {
		httpReq, err = c.buildJSONRequest(ctx, req, grantType)
	} else {
		httpReq, err = c.buildFormRequest(ctx, req, grantType)
	}
	if err != nil {
		return nil, err
	}

	if c.signer != nil {
		if err := c.signer.Sign(httpReq); err != nil {
			return nil, peercompat.NewClassifiedError(
				peercompat.ReasonSignatureInvalid,
				"failed to sign request",
				err,
			)
		}
	}

	return c.doRequest(ctx, httpReq)
}

// exchangeUnsigned sends an unsigned token exchange request.
func (c *Client) exchangeUnsigned(ctx context.Context, req ExchangeRequest, grantType string) (*ExchangeResult, error) {
	httpReq, err := c.buildFormRequest(ctx, req, grantType)
	if err != nil {
		return nil, err
	}

	return c.doRequest(ctx, httpReq)
}

// exchangeJSON sends a JSON-body token request (Nextcloud send_token_in_body quirk).
func (c *Client) exchangeJSON(ctx context.Context, req ExchangeRequest, grantType string, signed bool) (*ExchangeResult, error) {
	httpReq, err := c.buildJSONRequest(ctx, req, grantType)
	if err != nil {
		return nil, err
	}

	if signed && c.signer != nil {
		if err := c.signer.Sign(httpReq); err != nil {
			return nil, peercompat.NewClassifiedError(
				peercompat.ReasonSignatureInvalid,
				"failed to sign request",
				err,
			)
		}
	}

	return c.doRequest(ctx, httpReq)
}

// buildFormRequest builds a form-urlencoded POST.
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

// buildJSONRequest builds a JSON-body POST (Nextcloud quirk).
func (c *Client) buildJSONRequest(ctx context.Context, req ExchangeRequest, grantType string) (*http.Request, error) {
	body := token.TokenRequest{
		GrantType: grantType,
		ClientID:  c.myClientID,
		Code:      req.SharedSecret,
	}

	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		req.TokenEndPoint,
		bytes.NewReader(bodyBytes),
	)
	if err != nil {
		return nil, err
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")

	return httpReq, nil
}

// doRequest sends the request and parses the token response.
func (c *Client) doRequest(ctx context.Context, req *http.Request) (*ExchangeResult, error) {
	resp, err := c.httpClient.Do(ctx, req)
	if err != nil {
		return nil, peercompat.NewClassifiedError(
			peercompat.ReasonNetworkError,
			"token exchange request failed",
			err,
		)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, peercompat.NewClassifiedError(
			peercompat.ReasonNetworkError,
			"failed to read response",
			err,
		)
	}

	if resp.StatusCode >= 400 {
		var oauthErr token.OAuthError
		if json.Unmarshal(body, &oauthErr) == nil && oauthErr.Error != "" {
			return nil, c.classifyOAuthError(oauthErr, resp.StatusCode)
		}
		return nil, peercompat.NewClassifiedError(
			peercompat.ReasonTokenExchangeFailed,
			fmt.Sprintf("token exchange failed with status %d", resp.StatusCode),
			nil,
		)
	}

	var tokenResp token.TokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, peercompat.NewClassifiedError(
			peercompat.ReasonTokenInvalidFormat,
			"failed to parse token response",
			err,
		)
	}

	return &ExchangeResult{
		AccessToken: tokenResp.AccessToken,
		TokenType:   tokenResp.TokenType,
		ExpiresIn:   tokenResp.ExpiresIn,
	}, nil
}

// classifyOAuthError maps OAuth error codes to peercompat reason codes.
func (c *Client) classifyOAuthError(oauthErr token.OAuthError, statusCode int) error {
	var reasonCode string
	switch oauthErr.Error {
	case token.ErrorInvalidGrant:
		reasonCode = peercompat.ReasonTokenExchangeFailed
	case token.ErrorInvalidClient:
		reasonCode = peercompat.ReasonTokenExchangeFailed
	case token.ErrorUnauthorized:
		reasonCode = peercompat.ReasonSignatureRequired
	default:
		reasonCode = peercompat.ReasonTokenExchangeFailed
	}

	return peercompat.NewClassifiedError(
		reasonCode,
		oauthErr.ErrorDescription,
		nil,
	)
}
