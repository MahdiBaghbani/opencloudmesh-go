// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 OpenCloudMesh Authors

package token

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
	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
)

// Client is an OCM token exchange client.
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

// NewClient creates a new token exchange client.
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

// ExchangeRequest contains parameters for a token exchange.
type ExchangeRequest struct {
	TokenEndPoint string // The peer's tokenEndPoint from discovery
	PeerDomain    string // The peer's domain (for profile lookup)
	SharedSecret  string // The code/sharedSecret to exchange
}

// ExchangeResult contains the result of a token exchange.
type ExchangeResult struct {
	AccessToken  string
	TokenType    string
	ExpiresIn    int
	QuirkApplied string // Name of quirk applied, if any
}

// Exchange performs a token exchange with the peer.
// Uses the centralized OutboundPolicy to determine signing behavior.
func (c *Client) Exchange(ctx context.Context, req ExchangeRequest) (*ExchangeResult, error) {
	// Use OutboundPolicy to determine if we should sign
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

		// Get profile for quirks
		if c.outboundPolicy.ProfileRegistry != nil {
			profile = c.outboundPolicy.ProfileRegistry.GetProfile(req.PeerDomain)
		}
	}

	// If not signing, try unsigned directly
	if !shouldSign {
		return c.exchangeUnsigned(ctx, req)
	}

	// Step 1: Try signed (form-urlencoded) attempt
	result, err := c.exchangeSigned(ctx, req, false)
	if err == nil {
		return result, nil
	}

	// Step 2: Classify the error
	reasonCode := peercompat.ClassifyError(err)

	// Step 3: Check if we can apply quirks (only when policy allows relaxation)
	if profile != nil && c.outboundPolicy != nil {
		// Check for accept_plain_token quirk (unsigned request)
		if profile.HasQuirk("accept_plain_token") &&
			(reasonCode == peercompat.ReasonSignatureRequired ||
				reasonCode == peercompat.ReasonSignatureInvalid ||
				reasonCode == peercompat.ReasonKeyNotFound) {
			// Try unsigned
			result, err = c.exchangeUnsigned(ctx, req)
			if err == nil {
				result.QuirkApplied = "accept_plain_token"
				return result, nil
			}
		}

		// Check for send_token_in_body quirk (JSON body)
		if profile.HasQuirk("send_token_in_body") &&
			(reasonCode == peercompat.ReasonTokenExchangeFailed ||
				reasonCode == peercompat.ReasonProtocolMismatch) {
			// Try JSON body
			result, err = c.exchangeJSON(ctx, req, shouldSign)
			if err == nil {
				result.QuirkApplied = "send_token_in_body"
				return result, nil
			}
		}
	}

	// Return original error
	return nil, peercompat.NewClassifiedError(reasonCode, "token exchange failed", err)
}

// exchangeSigned performs a signed token exchange request.
func (c *Client) exchangeSigned(ctx context.Context, req ExchangeRequest, useJSON bool) (*ExchangeResult, error) {
	var httpReq *http.Request
	var err error

	if useJSON {
		httpReq, err = c.buildJSONRequest(ctx, req)
	} else {
		httpReq, err = c.buildFormRequest(ctx, req)
	}
	if err != nil {
		return nil, err
	}

	// Sign the request
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

// exchangeUnsigned performs an unsigned token exchange request.
func (c *Client) exchangeUnsigned(ctx context.Context, req ExchangeRequest) (*ExchangeResult, error) {
	httpReq, err := c.buildFormRequest(ctx, req)
	if err != nil {
		return nil, err
	}

	return c.doRequest(ctx, httpReq)
}

// exchangeJSON performs a JSON-body token exchange request (Nextcloud quirk).
func (c *Client) exchangeJSON(ctx context.Context, req ExchangeRequest, signed bool) (*ExchangeResult, error) {
	httpReq, err := c.buildJSONRequest(ctx, req)
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

// buildFormRequest builds a form-urlencoded token request.
func (c *Client) buildFormRequest(ctx context.Context, req ExchangeRequest) (*http.Request, error) {
	form := url.Values{}
	form.Set("grant_type", GrantTypeOCMShare)
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

// buildJSONRequest builds a JSON-body token request (Nextcloud quirk).
func (c *Client) buildJSONRequest(ctx context.Context, req ExchangeRequest) (*http.Request, error) {
	body := TokenRequest{
		GrantType: GrantTypeOCMShare,
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

// doRequest executes the HTTP request and parses the response.
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

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1MB limit
	if err != nil {
		return nil, peercompat.NewClassifiedError(
			peercompat.ReasonNetworkError,
			"failed to read response",
			err,
		)
	}

	// Check for error response
	if resp.StatusCode >= 400 {
		var oauthErr OAuthError
		if json.Unmarshal(body, &oauthErr) == nil && oauthErr.Error != "" {
			return nil, c.classifyOAuthError(oauthErr, resp.StatusCode)
		}
		return nil, peercompat.NewClassifiedError(
			peercompat.ReasonTokenExchangeFailed,
			fmt.Sprintf("token exchange failed with status %d", resp.StatusCode),
			nil,
		)
	}

	// Parse success response
	var tokenResp TokenResponse
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

// classifyOAuthError maps OAuth error codes to reason codes.
func (c *Client) classifyOAuthError(oauthErr OAuthError, statusCode int) error {
	var reasonCode string
	switch oauthErr.Error {
	case ErrorInvalidGrant:
		reasonCode = peercompat.ReasonTokenExchangeFailed
	case ErrorInvalidClient:
		reasonCode = peercompat.ReasonTokenExchangeFailed
	case ErrorUnauthorized:
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
