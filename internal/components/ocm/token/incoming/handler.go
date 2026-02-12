package incoming

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/token"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/appctx"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/hostport"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/logutil"
)

// Handler serves POST /ocm/token (token exchange).
type Handler struct {
	outgoingRepo outgoing.OutgoingShareRepo
	tokenStore   token.TokenStore
	tokenTTL     time.Duration
	settings     *TokenExchangeSettings
	logger       *slog.Logger
	localScheme  string // "http" or "https", derived from PublicOrigin
}

// NewHandler builds a token handler. Settings must have ApplyDefaults() called (done by cfg.Decode).
// publicOrigin is used for scheme-aware client_id comparison (e.g. host vs host:443).
func NewHandler(outgoingRepo outgoing.OutgoingShareRepo, tokenStore token.TokenStore, settings *TokenExchangeSettings, publicOrigin string, logger *slog.Logger) *Handler {
	logger = logutil.NoopIfNil(logger)

	// Parse localScheme from PublicOrigin (validated at config load time, cannot fail)
	localScheme := "https"
	if u, err := url.Parse(publicOrigin); err == nil && u.Scheme != "" {
		localScheme = strings.ToLower(u.Scheme)
	}

	return &Handler{
		outgoingRepo: outgoingRepo,
		tokenStore:   tokenStore,
		tokenTTL:     token.DefaultTokenTTL,
		settings:     settings,
		logger:       logger,
		localScheme:  localScheme,
	}
}

// HandleToken serves POST /ocm/token.
func (h *Handler) HandleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if h.settings == nil || !h.settings.Enabled {
		h.sendOAuthError(w, http.StatusNotImplemented, "not_implemented", "token exchange is disabled")
		return
	}

	// Get request-scoped logger with request correlation fields
	log := appctx.GetLogger(r.Context())

	// Parse request - support both form-urlencoded (spec) and JSON (Nextcloud interop)
	var req token.TokenRequest
	ct := r.Header.Get("Content-Type")

	if strings.HasPrefix(ct, "application/json") {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			h.sendOAuthError(w, http.StatusBadRequest, token.ErrorInvalidRequest, "failed to parse JSON body")
			return
		}
	} else {
		if err := r.ParseForm(); err != nil {
			h.sendOAuthError(w, http.StatusBadRequest, token.ErrorInvalidRequest, "failed to parse form body")
			return
		}
		req.GrantType = r.FormValue("grant_type")
		req.ClientID = r.FormValue("client_id")
		req.Code = r.FormValue("code")
	}

	if req.GrantType == "" {
		h.sendOAuthError(w, http.StatusBadRequest, token.ErrorInvalidRequest, "grant_type is required")
		return
	}
	if req.GrantType != token.GrantTypeAuthorizationCode && req.GrantType != token.GrantTypeOCMShare {
		h.sendOAuthError(w, http.StatusBadRequest, token.ErrorInvalidGrant, "unsupported grant_type")
		return
	}
	if req.ClientID == "" {
		h.sendOAuthError(w, http.StatusBadRequest, token.ErrorInvalidRequest, "client_id is required")
		return
	}
	if req.Code == "" {
		h.sendOAuthError(w, http.StatusBadRequest, token.ErrorInvalidRequest, "code is required")
		return
	}

	ctx := r.Context()

	if h.outgoingRepo == nil {
		log.Error("token exchange attempted but outgoing share repo not configured")
		h.sendOAuthError(w, http.StatusInternalServerError, token.ErrorInvalidRequest, "token exchange not available")
		return
	}

	// code is the sharedSecret from the share
	share, err := h.outgoingRepo.GetBySharedSecret(ctx, req.Code)
	if err != nil {
		// Note: Do not log the code (secret). Only log client_id for correlation.
		log.Warn("token exchange for unknown secret", "client_id", req.ClientID)
		h.sendOAuthError(w, http.StatusBadRequest, token.ErrorInvalidGrant, "invalid code")
		return
	}

	// Verify client_id matches the receiver using scheme-aware normalization.
	// Default ports are equivalent: example.com == example.com:443 for https.
	normalizedReceiver, errReceiver := hostport.Normalize(share.ReceiverHost, h.localScheme)
	normalizedClient, errClient := hostport.Normalize(req.ClientID, h.localScheme)

	if errReceiver != nil || errClient != nil {
		log.Warn("token exchange client_id normalization failed, falling back to raw comparison",
			"receiver_err", errReceiver,
			"client_err", errClient)
		normalizedReceiver = share.ReceiverHost
		normalizedClient = req.ClientID
	}

	if normalizedReceiver != normalizedClient {
		log.Warn("token exchange client mismatch",
			"expected", share.ReceiverHost,
			"got", req.ClientID)
		h.sendOAuthError(w, http.StatusBadRequest, token.ErrorInvalidClient, "client_id mismatch")
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
	json.NewEncoder(w).Encode(resp)
}

// sendOAuthError sends an OAuth-style error response.
func (h *Handler) sendOAuthError(w http.ResponseWriter, status int, errCode, errDesc string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(token.OAuthError{
		Error:            errCode,
		ErrorDescription: errDesc,
	})
}
