// Package shares implements the session-gated outgoing share handler.
// Handles POST /api/shares/outgoing for creating shares to remote receivers.
package shares

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/api"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/federation"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/address"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto"
	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
)

// Handler handles outgoing share creation.
type Handler struct {
	repo            shares.OutgoingShareRepo
	discoveryClient *discovery.Client
	httpClient      httpclient.HTTPClient
	signer          *crypto.RFC9421Signer
	outboundPolicy  *federation.OutboundPolicy
	cfg             *config.Config
	localProvider   string // raw host[:port] for owner/sender identity
	currentUser     func(context.Context) (*identity.User, error)
	logger          *slog.Logger
	allowedPaths    []string
}

// NewHandler creates a new outgoing shares handler.
func NewHandler(
	repo shares.OutgoingShareRepo,
	discClient *discovery.Client,
	httpClient httpclient.HTTPClient,
	signer *crypto.RFC9421Signer,
	outboundPolicy *federation.OutboundPolicy,
	cfg *config.Config,
	localProvider string,
	currentUser func(context.Context) (*identity.User, error),
	logger *slog.Logger,
) *Handler {
	return &Handler{
		repo:            repo,
		discoveryClient: discClient,
		httpClient:      httpClient,
		signer:          signer,
		outboundPolicy:  outboundPolicy,
		cfg:             cfg,
		localProvider:   localProvider,
		currentUser:     currentUser,
		logger:          logger,
		allowedPaths:    []string{"/tmp", os.TempDir()},
	}
}

// SetAllowedPaths sets the allowed path prefixes for file sharing.
func (h *Handler) SetAllowedPaths(paths []string) {
	h.allowedPaths = paths
}

// HandleCreate handles POST /api/shares/outgoing.
func (h *Handler) HandleCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Resolve session user for owner/sender identity (E1=B, Q6=A)
	user, err := h.currentUser(r.Context())
	if err != nil {
		api.WriteUnauthorized(w, api.ReasonUnauthenticated, "authentication required")
		return
	}

	var req shares.OutgoingShareRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.WriteBadRequest(w, api.ReasonBadRequest, "failed to parse request")
		return
	}

	if req.ReceiverDomain == "" {
		api.WriteBadRequest(w, api.ReasonMissingField, "receiverDomain is required")
		return
	}
	if req.ShareWith == "" {
		api.WriteBadRequest(w, api.ReasonMissingField, "shareWith is required")
		return
	}
	if req.LocalPath == "" {
		api.WriteBadRequest(w, api.ReasonMissingField, "localPath is required")
		return
	}
	if len(req.Permissions) == 0 {
		api.WriteBadRequest(w, api.ReasonMissingField, "permissions is required")
		return
	}

	cleanPath, err := h.validateLocalPath(req.LocalPath)
	if err != nil {
		api.WriteBadRequest(w, api.ReasonInvalidField, err.Error())
		return
	}

	stat, err := os.Stat(cleanPath)
	if err != nil {
		api.WriteBadRequest(w, api.ReasonInvalidField, "file does not exist")
		return
	}

	resourceType := req.ResourceType
	if resourceType == "" {
		if stat.IsDir() {
			resourceType = "folder"
		} else {
			resourceType = "file"
		}
	}

	name := req.Name
	if name == "" {
		name = filepath.Base(cleanPath)
	}

	providerID, _ := uuid.NewV7()
	webdavID, _ := uuid.NewV7()
	sharedSecret := generateSharedSecret()

	// Build owner/sender using session user identity (E1=B, Reva-style base64)
	owner := address.FormatOutgoing(user.ID, h.localProvider)
	sender := address.FormatOutgoing(user.ID, h.localProvider)

	mustExchangeToken := h.cfg.TokenExchange.Enabled != nil && *h.cfg.TokenExchange.Enabled

	share := &shares.OutgoingShare{
		ProviderID:        providerID.String(),
		WebDAVID:          webdavID.String(),
		SharedSecret:      sharedSecret,
		LocalPath:         cleanPath,
		ReceiverHost:      req.ReceiverDomain,
		ShareWith:         req.ShareWith,
		Name:              name,
		ResourceType:      resourceType,
		ShareType:         "user",
		Permissions:       req.Permissions,
		Owner:             owner,
		Sender:            sender,
		Status:            "pending",
		MustExchangeToken: mustExchangeToken,
	}

	if err := h.repo.Create(r.Context(), share); err != nil {
		h.logger.Error("failed to store outgoing share", "error", err)
		api.WriteInternalError(w, "failed to create share")
		return
	}

	if h.discoveryClient == nil {
		h.logger.Error("discovery client not configured")
		api.WriteInternalError(w, "discovery client not configured")
		return
	}

	receiverBaseURL := "https://" + req.ReceiverDomain
	disc, err := h.discoveryClient.Discover(r.Context(), receiverBaseURL)
	if err != nil {
		share.Status = "failed"
		share.Error = fmt.Sprintf("discovery failed: %v", err)
		h.repo.Update(r.Context(), share)
		h.logger.Warn("receiver discovery failed", "receiver", req.ReceiverDomain, "error", err)
		api.WriteError(w, http.StatusBadGateway, api.ReasonPeerUnreachable, "could not discover receiver")
		return
	}

	share.ReceiverEndPoint = disc.EndPoint

	webdavProto := &shares.WebDAVProtocol{
		URI:          share.WebDAVID,
		SharedSecret: sharedSecret,
		Permissions:  req.Permissions,
	}
	if mustExchangeToken {
		webdavProto.Requirements = []string{shares.RequirementMustExchangeToken}
	}

	payload := shares.NewShareRequest{
		ShareWith:    req.ShareWith,
		Name:         name,
		ProviderID:   share.ProviderID,
		Owner:        owner,
		Sender:       sender,
		ShareType:    "user",
		ResourceType: resourceType,
		Protocol: shares.Protocol{
			Name:   "multi",
			WebDAV: webdavProto,
		},
	}

	if err := h.sendShareToReceiver(r.Context(), disc.EndPoint, payload, disc); err != nil {
		share.Status = "failed"
		share.Error = fmt.Sprintf("send failed: %v", err)
		h.repo.Update(r.Context(), share)
		h.logger.Warn("failed to send share to receiver", "receiver", req.ReceiverDomain, "error", err)
		api.WriteError(w, http.StatusBadGateway, api.ReasonPeerUnreachable, err.Error())
		return
	}

	now := time.Now()
	share.Status = "sent"
	share.SentAt = &now
	h.repo.Update(r.Context(), share)

	h.logger.Info("outgoing share created and sent",
		"share_id", share.ShareID,
		"provider_id", share.ProviderID,
		"receiver", req.ReceiverDomain)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{
		"shareId":    share.ShareID,
		"providerId": share.ProviderID,
		"webdavId":   share.WebDAVID,
		"status":     share.Status,
	})
}

// validateLocalPath validates and sanitizes a local file path.
func (h *Handler) validateLocalPath(path string) (string, error) {
	cleanPath := filepath.Clean(path)

	if !filepath.IsAbs(cleanPath) {
		return "", fmt.Errorf("path must be absolute")
	}

	if strings.Contains(cleanPath, "..") {
		return "", fmt.Errorf("path traversal not allowed")
	}

	allowed := false
	for _, prefix := range h.allowedPaths {
		if strings.HasPrefix(cleanPath, prefix) {
			allowed = true
			break
		}
	}

	if !allowed {
		return "", fmt.Errorf("path not in allowed directories")
	}

	return cleanPath, nil
}

// sendShareToReceiver sends the share payload to the receiver.
func (h *Handler) sendShareToReceiver(ctx context.Context, endPoint string, payload shares.NewShareRequest, disc *discovery.Discovery) error {
	sharesURL, err := url.JoinPath(endPoint, "shares")
	if err != nil {
		return fmt.Errorf("failed to build shares URL: %w", err)
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to encode payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, sharesURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	if h.outboundPolicy != nil {
		peerURL, parseErr := url.Parse(endPoint)
		var peerDomain string
		if parseErr != nil || peerURL.Host == "" {
			peerDomain = endPoint
		} else {
			peerDomain = peerURL.Host
		}
		decision := h.outboundPolicy.ShouldSign(
			federation.EndpointShares,
			peerDomain,
			disc,
			h.signer != nil,
		)
		if decision.Error != nil {
			return fmt.Errorf("outbound signing policy error: %w", decision.Error)
		}
		if decision.ShouldSign && h.signer != nil {
			if err := h.signer.SignRequest(req, body); err != nil {
				return fmt.Errorf("failed to sign request: %w", err)
			}
		}
	} else if h.signer != nil && disc.HasCapability("http-sig") && len(disc.PublicKeys) > 0 {
		if err := h.signer.SignRequest(req, body); err != nil {
			return fmt.Errorf("failed to sign request: %w", err)
		}
	}

	resp, err := h.httpClient.Do(ctx, req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("receiver returned status %d: %s", resp.StatusCode, string(respBody))
	}

	return nil
}

// generateSharedSecret generates a random shared secret.
func generateSharedSecret() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}
