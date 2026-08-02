// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

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

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/reason"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/token"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
)

// Client performs OCM token exchange against peer token endpoints.
type Client struct {
	httpClient *httpclient.ContextClient
	signer     RequestSigner
	myClientID string // normalized Sending Server authority for client_id
}

// RequestSigner signs HTTP requests for RFC 9421.
type RequestSigner interface {
	Sign(req *http.Request) error
}

// ExchangeRequest holds token exchange parameters.
type ExchangeRequest struct {
	TokenEndPoint string // Sending Server tokenEndPoint from peer discovery
	SharedSecret  string // authorization code (sharedSecret) to exchange
}

// ExchangeResult holds the exchange result.
type ExchangeResult struct {
	AccessToken string
	TokenType   string
	ExpiresIn   int
}

// NewClient builds a token exchange client.
// myClientID must be the normalized Sending Server authority used as client_id.
func NewClient(
	httpClient *httpclient.ContextClient,
	signer RequestSigner,
	myClientID string,
) *Client {
	return &Client{
		httpClient: httpClient,
		signer:     signer,
		myClientID: myClientID,
	}
}

// Exchange performs form-urlencoded token exchange with authorization_code.
// The Receiving Server (this client) MUST sign the token request when using
// http-sig; see https://github.com/cs3org/OCM-API/blob/6a0586183cbef10ecae9dedc42561806447eb2f5/IETF-OCM.md#L1532-L1533.
// ocmgo signs conditionally when the peer Sending Server advertises http-sig,
// per the applicability rules at https://github.com/cs3org/OCM-API/blob/6a0586183cbef10ecae9dedc42561806447eb2f5/IETF-OCM.md#L808-L823,
// applied via c.signer.Sign here.
func (c *Client) Exchange(ctx context.Context, req ExchangeRequest, disc *spec.Discovery) (*ExchangeResult, error) {
	httpReq, err := c.buildFormRequest(ctx, req, token.GrantTypeAuthorizationCode)
	if err != nil {
		return nil, err
	}

	if disc.IsHTTPSigCapable() {
		if c.signer == nil {
			return nil, reason.NewClassifiedError(
				reason.ReasonSignatureRequired,
				"token exchange requires signing",
				fmt.Errorf("no signer configured"),
			)
		}

		if err := c.signer.Sign(httpReq); err != nil {
			return nil, reason.NewClassifiedError(
				reason.ReasonSignatureInvalid,
				"failed to sign request",
				err,
			)
		}
	}

	return c.doRequest(ctx, httpReq)
}

// buildFormRequest builds a form-urlencoded POST to the Sending Server tokenEndPoint.
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
	defer func() {
		//nolint:errcheck // best-effort cleanup; error is not actionable
		resp.Body.Close()
	}()

	body, err := c.readResponseBody(resp)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode >= 400 {
		return c.buildErrorResult(resp, body, req)
	}

	return c.parseTokenResult(body, resp.Header.Get("Content-Type"))
}

func (c *Client) readResponseBody(resp *http.Response) ([]byte, error) {
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

	return body, nil
}

func (c *Client) buildErrorResult(resp *http.Response, body []byte, req *http.Request) (*ExchangeResult, error) { //nolint:unparam // error-classification helper: ExchangeResult is nil on every error path by design; signature mirrors parseTokenResult for symmetric dispatch
	// Auth failures (401/403) must fail closed and not be retried.
	// Keep them distinct so callers can distinguish missing credentials
	// from a rejected signature or an explicit denial.
	switch resp.StatusCode {
	case http.StatusForbidden:
		return nil, reason.NewClassifiedError(
			reason.ReasonTokenForbidden,
			"token exchange failed with status 403",
			nil,
		)
	case http.StatusUnauthorized:
		if req.Header.Get("Signature") == "" {
			return nil, reason.NewClassifiedError(
				reason.ReasonTokenUnauthorized,
				"token exchange failed with status 401",
				nil,
			)
		}
		// Signed request was rejected; prefer the OAuth error detail if
		// the peer supplied one, otherwise fall back to signature required.
		var oauthErr token.OAuthError
		if json.Unmarshal(body, &oauthErr) == nil && oauthErr.Error != "" {
			return nil, c.classifyOAuthError(oauthErr)
		}

		return nil, reason.NewClassifiedError(
			reason.ReasonSignatureRequired,
			fmt.Sprintf("token exchange failed with status %d", resp.StatusCode),
			nil,
		)
	default:
		var oauthErr token.OAuthError
		if json.Unmarshal(body, &oauthErr) == nil && oauthErr.Error != "" {
			return nil, c.classifyOAuthError(oauthErr)
		}

		return nil, reason.NewClassifiedError(
			reason.ReasonTokenExchangeFailed,
			fmt.Sprintf("token exchange failed with status %d", resp.StatusCode),
			nil,
		)
	}
}

func (c *Client) parseTokenResult(body []byte, contentType string) (*ExchangeResult, error) {
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil || mediaType != "application/json" {
		return nil, reason.NewClassifiedError(
			reason.ReasonTokenInvalidFormat,
			"token response must be application/json",
			fmt.Errorf("content-type %q", contentType),
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

	if err := validateTokenResponse(tokenResp); err != nil {
		return nil, err
	}

	return &ExchangeResult{
		AccessToken: tokenResp.AccessToken,
		TokenType:   tokenResp.TokenType,
		ExpiresIn:   tokenResp.ExpiresIn,
	}, nil
}

func validateTokenResponse(tokenResp token.TokenResponse) error {
	if tokenResp.AccessToken == "" {
		return reason.NewClassifiedError(
			reason.ReasonTokenInvalidFormat,
			"access_token is required",
			nil,
		)
	}

	if !strings.EqualFold(tokenResp.TokenType, "Bearer") {
		return reason.NewClassifiedError(
			reason.ReasonTokenInvalidFormat,
			"token_type must be Bearer",
			fmt.Errorf("got %q", tokenResp.TokenType),
		)
	}

	if tokenResp.ExpiresIn <= 0 {
		return reason.NewClassifiedError(
			reason.ReasonTokenInvalidFormat,
			"expires_in must be positive",
			fmt.Errorf("got %d", tokenResp.ExpiresIn),
		)
	}

	return nil
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
