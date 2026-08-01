// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package incoming

import (
	"encoding/json"
	"mime"
	"net/http"
	"time"

	inboundsignature "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/inbound/signature"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/policy"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/token"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/appctx"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/hostport"
)

// Handler serves POST /ocm/token (token exchange).
type Handler struct {
	outgoingRepo outgoing.OutgoingShareRepo
	tokenStore   token.TokenStore
	tokenTTL     time.Duration
	settings     *TokenExchangeSettings
	codeFlow     *policy.CodeFlow
	localScheme  string // "http" or "https", derived from PublicOrigin
}

// NewHandler builds a token handler. Settings must have ApplyDefaults() called (done by cfg.Decode).
// publicOrigin is used for scheme-aware client_id comparison (e.g. host vs host:443).
func NewHandler(outgoingRepo outgoing.OutgoingShareRepo, tokenStore token.TokenStore, settings *TokenExchangeSettings, codeFlow *policy.CodeFlow, publicOrigin string) *Handler {
	localScheme := config.PublicSchemeFromOrigin(publicOrigin)

	return &Handler{
		outgoingRepo: outgoingRepo,
		tokenStore:   tokenStore,
		tokenTTL:     token.DefaultTokenTTL,
		settings:     settings,
		codeFlow:     codeFlow,
		localScheme:  localScheme,
	}
}

// HandleToken serves POST /ocm/token.
// The Receiving Server signs the token request; as the Sending Server, ocmgo
// verifies any present signature and gates unsigned admission on must-use-http-sig
// through the mounted signature middleware.
// See https://github.com/cs3org/OCM-API/blob/6a0586183cbef10ecae9dedc42561806447eb2f5/IETF-OCM.md#L1532-L1533
// Invalid requests receive HTTP 400 with an OAuth 2.0 error code; see
// https://github.com/cs3org/OCM-API/blob/6a0586183cbef10ecae9dedc42561806447eb2f5/IETF-OCM.md#L1566-L1576.
// Signature applicability is conditional on the peer advertising http-sig; unsigned
// requests are admitted only when ocmgo does not advertise must-use-http-sig.
// See https://github.com/cs3org/OCM-API/blob/6a0586183cbef10ecae9dedc42561806447eb2f5/IETF-OCM.md#L808-L823
func (h *Handler) HandleToken(w http.ResponseWriter, r *http.Request) {
	req, ok := h.parseTokenRequest(w, r)
	if !ok {
		return
	}

	share, ok := h.lookupAndVerifyShare(w, r, req)
	if !ok {
		return
	}

	h.issueTokenResponse(w, r, req, share)
}

// sendOAuthError sends an OAuth-style error response.
// ocmgo emits invalid_request, invalid_client, invalid_grant, and
// unsupported_grant_type per https://github.com/cs3org/OCM-API/blob/6a0586183cbef10ecae9dedc42561806447eb2f5/IETF-OCM.md#L1566-L1576.
// ErrorUnauthorized ("unauthorized_client") is defined in
// internal/components/ocm/spec/token_exchange.go and reserved for future
// per-client grant-authorization enforcement; there is no current emission
// path because OCM permits all authenticated receivers to use authorization_code.
func (h *Handler) sendOAuthError(w http.ResponseWriter, status int, errCode, errDesc string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	//nolint:errcheck,errchkjson // response already committed after WriteHeader; write error cannot be recovered or meaningfully handled; payload encodes to fixed JSON, so encode error is always nil
	_ = json.NewEncoder(w).Encode(token.OAuthError{
		Error:            errCode,
		ErrorDescription: errDesc,
	})
}

func (h *Handler) parseTokenRequest(w http.ResponseWriter, r *http.Request) (token.TokenRequest, bool) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)

		return token.TokenRequest{}, false
	}

	capable := h.codeFlow != nil
	if h.settings == nil || !capable {
		h.sendOAuthError(w, http.StatusNotImplemented, "not_implemented", "token exchange is disabled")

		return token.TokenRequest{}, false
	}

	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/x-www-form-urlencoded" {
		h.sendOAuthError(w, http.StatusBadRequest, token.ErrorInvalidRequest, "unsupported content type")

		return token.TokenRequest{}, false
	}

	if err := r.ParseForm(); err != nil {
		h.sendOAuthError(w, http.StatusBadRequest, token.ErrorInvalidRequest, "failed to parse form body")

		return token.TokenRequest{}, false
	}

	var req token.TokenRequest

	req.GrantType = r.FormValue("grant_type")
	req.ClientID = r.FormValue("client_id")
	req.Code = r.FormValue("code")

	if req.GrantType == "" {
		h.sendOAuthError(w, http.StatusBadRequest, token.ErrorInvalidRequest, "grant_type is required")

		return token.TokenRequest{}, false
	}

	if req.GrantType != token.GrantTypeAuthorizationCode {
		h.sendOAuthError(w, http.StatusBadRequest, token.ErrorUnsupportedGrantType, "unsupported grant_type")

		return token.TokenRequest{}, false
	}

	if req.ClientID == "" {
		h.sendOAuthError(w, http.StatusBadRequest, token.ErrorInvalidRequest, "client_id is required")

		return token.TokenRequest{}, false
	}

	if req.Code == "" {
		h.sendOAuthError(w, http.StatusBadRequest, token.ErrorInvalidRequest, "code is required")

		return token.TokenRequest{}, false
	}

	if h.outgoingRepo == nil {
		appctx.GetLogger(r.Context()).Error("token exchange attempted but outgoing share repo not configured")
		h.sendOAuthError(w, http.StatusInternalServerError, token.ErrorInvalidRequest, "token exchange not available")

		return token.TokenRequest{}, false
	}

	return req, true
}

func (h *Handler) lookupAndVerifyShare(w http.ResponseWriter, r *http.Request, req token.TokenRequest) (*outgoing.OutgoingShare, bool) {
	ctx := r.Context()
	log := appctx.GetLogger(ctx)

	share, err := h.outgoingRepo.GetBySharedSecret(ctx, req.Code)
	if err != nil {
		log.Warn("token exchange for unknown secret", "client_id", req.ClientID)
		h.sendOAuthError(w, http.StatusBadRequest, token.ErrorInvalidGrant, "invalid code")

		return nil, false
	}

	normalizedReceiver, errReceiver := hostport.Normalize(share.ReceiverHost, h.localScheme)
	normalizedClient, errClient := hostport.Normalize(req.ClientID, h.localScheme)

	if errReceiver != nil || errClient != nil {
		log.Warn("token exchange client_id normalization failed",
			"receiver_err", errReceiver,
			"client_err", errClient)
		h.sendOAuthError(w, http.StatusBadRequest, token.ErrorInvalidClient, "invalid client_id")

		return nil, false
	}

	if normalizedReceiver != normalizedClient {
		log.Warn("token exchange client mismatch",
			"expected", share.ReceiverHost,
			"got", req.ClientID)
		h.sendOAuthError(w, http.StatusBadRequest, token.ErrorInvalidClient, "client_id mismatch")

		return nil, false
	}

	peerIdentity := inboundsignature.GetPeerIdentity(ctx)
	if peerIdentity != nil && peerIdentity.Authenticated {
		if peerIdentity.AuthorityForCompare != normalizedReceiver {
			log.Warn("token exchange verified identity mismatch",
				"expected", normalizedReceiver,
				"got", peerIdentity.AuthorityForCompare)
			h.sendOAuthError(w, http.StatusBadRequest, token.ErrorInvalidClient, "client_id mismatch")

			return nil, false
		}
	}

	return share, true
}

func (h *Handler) issueTokenResponse(w http.ResponseWriter, r *http.Request, req token.TokenRequest, share *outgoing.OutgoingShare) {
	ctx := r.Context()
	log := appctx.GetLogger(ctx)

	if h.tokenTTL <= 0 {
		log.Error("token exchange misconfigured: non-positive token TTL")
		h.sendOAuthError(w, http.StatusInternalServerError, token.ErrorInvalidRequest, "token exchange not available")

		return
	}

	accessToken, err := token.GenerateAccessToken()
	if err != nil {
		log.Error("failed to generate access token", "error", err)
		h.sendOAuthError(w, http.StatusInternalServerError, token.ErrorInvalidRequest, "token generation failed")

		return
	}

	now := time.Now()
	issuedToken := &token.IssuedToken{
		AccessToken: accessToken,
		ShareID:     share.ShareID,
		ClientID:    req.ClientID,
		IssuedAt:    now,
		ExpiresAt:   now.Add(h.tokenTTL),
	}

	if err := h.tokenStore.Store(ctx, issuedToken); err != nil {
		log.Error("failed to store token", "error", err)
		h.sendOAuthError(w, http.StatusInternalServerError, token.ErrorInvalidRequest, "token storage failed")

		return
	}

	log.Info("token issued",
		"share_id", share.ShareID,
		"client_id", req.ClientID,
		"expires_in", int(h.tokenTTL.Seconds()))

	resp := token.TokenResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   int(h.tokenTTL.Seconds()),
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")

	if err := json.NewEncoder(w).Encode(resp); err != nil {
		log.Error("failed to encode token response", "error", err)
	}
}
