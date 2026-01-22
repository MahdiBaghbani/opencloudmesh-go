package invites

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/appctx"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/federation"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/ocm/discovery"
)

// HTTPClient interface for outbound requests.
type HTTPClient interface {
	Do(ctx context.Context, req *http.Request) (*http.Response, error)
}

// InboxHandler handles invite inbox endpoints.
type InboxHandler struct {
	incomingRepo    IncomingInviteRepo
	discoveryClient *discovery.Client
	httpClient      HTTPClient
	signer          *crypto.RFC9421Signer
	outboundPolicy  *federation.OutboundPolicy
	ourUserID       string // Our user ID for accept requests
	ourProviderFQDN string
	logger          *slog.Logger
}

// NewInboxHandler creates a new inbox handler.
func NewInboxHandler(
	incomingRepo IncomingInviteRepo,
	discoveryClient *discovery.Client,
	httpClient HTTPClient,
	signer *crypto.RFC9421Signer,
	outboundPolicy *federation.OutboundPolicy,
	ourUserID string,
	ourProviderFQDN string,
	logger *slog.Logger,
) *InboxHandler {
	return &InboxHandler{
		incomingRepo:    incomingRepo,
		discoveryClient: discoveryClient,
		httpClient:      httpClient,
		signer:          signer,
		outboundPolicy:  outboundPolicy,
		ourUserID:       ourUserID,
		ourProviderFQDN: ourProviderFQDN,
		logger:          logger,
	}
}

// HandleList handles GET /api/inbox/invites.
func (h *InboxHandler) HandleList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ctx := r.Context()

	invites, err := h.incomingRepo.List(ctx)
	if err != nil {
		h.sendError(w, http.StatusInternalServerError, "list_failed", "failed to list invites")
		return
	}

	views := make([]InboxInviteView, 0, len(invites))
	for _, inv := range invites {
		views = append(views, InboxInviteView{
			ID:         inv.ID,
			SenderFQDN: inv.SenderFQDN,
			ReceivedAt: inv.ReceivedAt,
			Status:     inv.Status,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"invites": views,
	})
}

// HandleAccept handles POST /api/inbox/invites/{inviteId}/accept.
func (h *InboxHandler) HandleAccept(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get request-scoped logger with request correlation fields
	log := appctx.GetLogger(r.Context())

	inviteID := extractInviteID(r.URL.Path, "/accept")
	if inviteID == "" {
		h.sendError(w, http.StatusBadRequest, "missing_invite_id", "inviteId is required")
		return
	}

	ctx := r.Context()

	invite, err := h.incomingRepo.GetByID(ctx, inviteID)
	if err != nil {
		h.sendError(w, http.StatusNotFound, "invite_not_found", "invite not found")
		return
	}

	if invite.Status == InviteStatusAccepted {
		// Idempotent success
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"status":   string(InviteStatusAccepted),
			"inviteId": inviteID,
		})
		return
	}

	if invite.Status != InviteStatusPending {
		h.sendError(w, http.StatusConflict, "invalid_status", "invite is not pending")
		return
	}

	// Send invite-accepted to sender
	if err := h.sendInviteAccepted(ctx, invite); err != nil {
		log.Error("failed to send invite-accepted", "invite_id", inviteID, "error", err)
		h.sendError(w, http.StatusBadGateway, "accept_failed", "failed to notify sender")
		return
	}

	// Update local status
	if err := h.incomingRepo.UpdateStatus(ctx, inviteID, InviteStatusAccepted); err != nil {
		log.Error("failed to update invite status", "invite_id", inviteID, "error", err)
		// Already accepted on sender side, log but return success
	}

	log.Info("invite accepted", "invite_id", inviteID, "sender_fqdn", invite.SenderFQDN)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":   string(InviteStatusAccepted),
		"inviteId": inviteID,
	})
}

// HandleDecline handles POST /api/inbox/invites/{inviteId}/decline.
func (h *InboxHandler) HandleDecline(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get request-scoped logger with request correlation fields
	log := appctx.GetLogger(r.Context())

	inviteID := extractInviteID(r.URL.Path, "/decline")
	if inviteID == "" {
		h.sendError(w, http.StatusBadRequest, "missing_invite_id", "inviteId is required")
		return
	}

	ctx := r.Context()

	invite, err := h.incomingRepo.GetByID(ctx, inviteID)
	if err != nil {
		h.sendError(w, http.StatusNotFound, "invite_not_found", "invite not found")
		return
	}

	if invite.Status == InviteStatusDeclined {
		// Idempotent success
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"status":   string(InviteStatusDeclined),
			"inviteId": inviteID,
		})
		return
	}

	// Decline is local only - just delete the invite
	if err := h.incomingRepo.Delete(ctx, inviteID); err != nil {
		log.Error("failed to delete invite", "invite_id", inviteID, "error", err)
	}

	log.Info("invite declined", "invite_id", inviteID, "sender_fqdn", invite.SenderFQDN)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":   string(InviteStatusDeclined),
		"inviteId": inviteID,
	})
}

// sendInviteAccepted sends POST /ocm/invite-accepted to the sender.
func (h *InboxHandler) sendInviteAccepted(ctx context.Context, invite *IncomingInvite) error {
	// Discover sender's endpoint
	baseURL := "https://" + invite.SenderFQDN
	disc, err := h.discoveryClient.Discover(ctx, baseURL)
	if err != nil {
		return fmt.Errorf("discovery failed for %s: %w", invite.SenderFQDN, err)
	}

	// Build invite-accepted URL
	inviteAcceptedURL := disc.EndPoint + "/invite-accepted"

	// Build request body (token is raw, not base64)
	reqBody := InviteAcceptedRequest{
		RecipientProvider: h.ourProviderFQDN,
		Token:             invite.Token,
		UserID:            h.ourUserID,
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("failed to encode request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, inviteAcceptedURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	// Apply outbound signing policy
	if h.outboundPolicy != nil {
		decision := h.outboundPolicy.ShouldSign(
			federation.EndpointInvites,
			invite.SenderFQDN,
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

	resp, err := h.httpClient.Do(ctx, req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("invite-accepted rejected with status %d: %s", resp.StatusCode, string(respBody))
	}

	return nil
}

// extractInviteID extracts the inviteId from the request path.
func extractInviteID(path, suffix string) string {
	path = strings.TrimSuffix(path, suffix)
	parts := strings.Split(path, "/")
	if len(parts) < 1 {
		return ""
	}
	return parts[len(parts)-1]
}

// sendError sends a JSON error response.
func (h *InboxHandler) sendError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{
		"error":       code,
		"description": message,
	})
}
