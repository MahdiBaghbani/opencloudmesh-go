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

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/instanceid"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/federation"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery"
	"github.com/google/uuid"
)

// HTTPClient interface for outbound requests.
type HTTPClient interface {
	Do(ctx context.Context, req *http.Request) (*http.Response, error)
}

// OutgoingHandler handles outgoing share creation.
type OutgoingHandler struct {
	repo            OutgoingShareRepo
	discoveryClient *discovery.Client
	httpClient      HTTPClient
	signer          *crypto.RFC9421Signer
	outboundPolicy  *federation.OutboundPolicy
	cfg             *config.Config
	logger          *slog.Logger
	allowedPaths    []string // Path prefixes allowed for sharing
}

// NewOutgoingHandler creates a new outgoing handler.
func NewOutgoingHandler(
	repo OutgoingShareRepo,
	discClient *discovery.Client,
	httpClient HTTPClient,
	signer *crypto.RFC9421Signer,
	outboundPolicy *federation.OutboundPolicy,
	cfg *config.Config,
	logger *slog.Logger,
) *OutgoingHandler {
	return &OutgoingHandler{
		repo:            repo,
		discoveryClient: discClient,
		httpClient:      httpClient,
		signer:          signer,
		outboundPolicy:  outboundPolicy,
		cfg:             cfg,
		logger:          logger,
		allowedPaths:    []string{"/tmp", os.TempDir()}, // Default: only temp dirs
	}
}

// SetAllowedPaths sets the allowed path prefixes for file sharing.
func (h *OutgoingHandler) SetAllowedPaths(paths []string) {
	h.allowedPaths = paths
}

// HandleCreate handles POST /api/shares/outgoing.
func (h *OutgoingHandler) HandleCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req OutgoingShareRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.sendError(w, http.StatusBadRequest, "invalid_json", "failed to parse request")
		return
	}

	// Validate required fields
	if req.ReceiverDomain == "" {
		h.sendError(w, http.StatusBadRequest, "missing_field", "receiverDomain is required")
		return
	}
	if req.ShareWith == "" {
		h.sendError(w, http.StatusBadRequest, "missing_field", "shareWith is required")
		return
	}
	if req.LocalPath == "" {
		h.sendError(w, http.StatusBadRequest, "missing_field", "localPath is required")
		return
	}
	if len(req.Permissions) == 0 {
		h.sendError(w, http.StatusBadRequest, "missing_field", "permissions is required")
		return
	}

	// Validate and sanitize local path
	cleanPath, err := h.validateLocalPath(req.LocalPath)
	if err != nil {
		h.sendError(w, http.StatusBadRequest, "invalid_path", err.Error())
		return
	}

	// Check file exists
	stat, err := os.Stat(cleanPath)
	if err != nil {
		h.sendError(w, http.StatusBadRequest, "file_not_found", "file does not exist")
		return
	}

	// Determine resource type
	resourceType := req.ResourceType
	if resourceType == "" {
		if stat.IsDir() {
			resourceType = "folder"
		} else {
			resourceType = "file"
		}
	}

	// Determine share name
	name := req.Name
	if name == "" {
		name = filepath.Base(cleanPath)
	}

	// Generate IDs and secret
	providerID, _ := uuid.NewV7()
	webdavID, _ := uuid.NewV7()
	sharedSecret := generateSharedSecret()

	// Build sender identity
	senderHost, err := instanceid.ProviderFQDN(h.cfg.ExternalOrigin)
	if err != nil {
		h.logger.Error("failed to derive sender host", "error", err)
		h.sendError(w, http.StatusInternalServerError, "config_error", "invalid external origin")
		return
	}
	owner := "owner@" + senderHost  // Placeholder - should come from auth
	sender := "sender@" + senderHost // Placeholder - should come from auth

	// Determine if we require token exchange for this share.
	// When enabled, we advertise must-exchange-token and enforce it on /webdav/ocm/*.
	mustExchangeToken := h.cfg.TokenExchange.Enabled != nil && *h.cfg.TokenExchange.Enabled

	// Create outgoing share record
	share := &OutgoingShare{
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

	// Store locally
	if err := h.repo.Create(r.Context(), share); err != nil {
		h.logger.Error("failed to store outgoing share", "error", err)
		h.sendError(w, http.StatusInternalServerError, "storage_error", "failed to create share")
		return
	}

	// Discover receiver endpoint
	receiverBaseURL := "https://" + req.ReceiverDomain
	disc, err := h.discoveryClient.Discover(r.Context(), receiverBaseURL)
	if err != nil {
		share.Status = "failed"
		share.Error = fmt.Sprintf("discovery failed: %v", err)
		h.repo.Update(r.Context(), share)
		h.logger.Warn("receiver discovery failed", "receiver", req.ReceiverDomain, "error", err)
		h.sendError(w, http.StatusBadGateway, "discovery_failed", "could not discover receiver")
		return
	}

	share.ReceiverEndPoint = disc.EndPoint

	// Build WebDAV protocol options
	webdavProto := &WebDAVProtocol{
		URI:          share.WebDAVID,
		SharedSecret: sharedSecret,
		Permissions:  req.Permissions,
	}
	// Advertise must-exchange-token requirement if enabled
	if mustExchangeToken {
		webdavProto.Requirements = []string{RequirementMustExchangeToken}
	}

	// Build share payload for receiver
	payload := NewShareRequest{
		ShareWith:    req.ShareWith,
		Name:         name,
		ProviderID:   share.ProviderID,
		Owner:        owner,
		Sender:       sender,
		ShareType:    "user",
		ResourceType: resourceType,
		Protocol: Protocol{
			Name:   "multi",
			WebDAV: webdavProto,
		},
	}

	// POST to receiver
	if err := h.sendShareToReceiver(r.Context(), disc.EndPoint, payload, disc); err != nil {
		share.Status = "failed"
		share.Error = fmt.Sprintf("send failed: %v", err)
		h.repo.Update(r.Context(), share)
		h.logger.Warn("failed to send share to receiver", "receiver", req.ReceiverDomain, "error", err)
		h.sendError(w, http.StatusBadGateway, "send_failed", err.Error())
		return
	}

	// Update status
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
func (h *OutgoingHandler) validateLocalPath(path string) (string, error) {
	// Clean the path
	cleanPath := filepath.Clean(path)

	// Ensure it's absolute
	if !filepath.IsAbs(cleanPath) {
		return "", fmt.Errorf("path must be absolute")
	}

	// Check for path traversal
	if strings.Contains(cleanPath, "..") {
		return "", fmt.Errorf("path traversal not allowed")
	}

	// Check against allowed paths
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
func (h *OutgoingHandler) sendShareToReceiver(ctx context.Context, endPoint string, payload NewShareRequest, disc *discovery.Discovery) error {
	// Build shares URL using proper URL joining
	sharesURL, err := url.JoinPath(endPoint, "shares")
	if err != nil {
		return fmt.Errorf("failed to build shares URL: %w", err)
	}

	// Encode payload
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to encode payload: %w", err)
	}

	// Create request
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, sharesURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	// Apply outbound signing policy
	if h.outboundPolicy != nil {
		peerURL, parseErr := url.Parse(endPoint)
		var peerDomain string
		if parseErr != nil || peerURL.Host == "" {
			peerDomain = endPoint // best-effort fallback
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
		// Fallback for backward compatibility when no policy is set
		if err := h.signer.SignRequest(req, body); err != nil {
			return fmt.Errorf("failed to sign request: %w", err)
		}
	}

	// Send request
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

// sendError sends a JSON error response.
func (h *OutgoingHandler) sendError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{
		"error":       code,
		"description": message,
	})
}

// generateSharedSecret generates a random shared secret.
func generateSharedSecret() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

