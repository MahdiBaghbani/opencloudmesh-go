// Package invites implements session-gated inbox invite handlers.
// All endpoints enforce per-user scoping via the injected CurrentUser resolver.
package invites

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/api"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/outboundsigning"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/address"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites"
	invitesinbox "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites/inbox"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto"
	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/logutil"
)

// InboxInviteView is the public view of an incoming invite.
type InboxInviteView struct {
	ID         string              `json:"id"`
	SenderFQDN string              `json:"senderFqdn"`
	ReceivedAt time.Time           `json:"receivedAt"`
	Status     invites.InviteStatus `json:"status"`
}

// InboxListResponse wraps the invite views returned by HandleList.
type InboxListResponse struct {
	Invites []InboxInviteView `json:"invites"`
}

// InviteImportRequest is the request body for POST /api/inbox/invites/import.
type InviteImportRequest struct {
	InviteString string `json:"inviteString"`
}

// InviteImportResponse is the safe response for invite import (no token leaked).
type InviteImportResponse struct {
	ID         string              `json:"id"`
	SenderFQDN string             `json:"senderFqdn"`
	ReceivedAt string             `json:"receivedAt"`
	Status     invites.InviteStatus `json:"status"`
}

// Handler handles inbox invite list, import, accept, and decline endpoints.
type Handler struct {
	incomingRepo    invitesinbox.IncomingInviteRepo
	httpClient      httpclient.HTTPClient
	discoveryClient *discovery.Client
	signer          *crypto.RFC9421Signer
	outboundPolicy  *outboundsigning.OutboundPolicy
	localProvider   string // raw host[:port] for recipientProvider in invite-accepted
	currentUser     func(context.Context) (*identity.User, error)
	log             *slog.Logger
}

// NewHandler creates a new inbox invites handler.
func NewHandler(
	incomingRepo invitesinbox.IncomingInviteRepo,
	httpClient httpclient.HTTPClient,
	discoveryClient *discovery.Client,
	signer *crypto.RFC9421Signer,
	outboundPolicy *outboundsigning.OutboundPolicy,
	localProvider string,
	currentUser func(context.Context) (*identity.User, error),
	log *slog.Logger,
) *Handler {
	log = logutil.NoopIfNil(log)
	return &Handler{
		incomingRepo:    incomingRepo,
		httpClient:      httpClient,
		discoveryClient: discoveryClient,
		signer:          signer,
		outboundPolicy:  outboundPolicy,
		localProvider:   localProvider,
		currentUser:     currentUser,
		log:             log,
	}
}

// HandleList handles GET /api/inbox/invites.
// Lists only invites owned by the authenticated user.
func (h *Handler) HandleList(w http.ResponseWriter, r *http.Request) {
	user, err := h.currentUser(r.Context())
	if err != nil {
		api.WriteUnauthorized(w, api.ReasonUnauthenticated, "authentication required")
		return
	}

	result, err := h.incomingRepo.ListByRecipientUserID(r.Context(), user.ID)
	if err != nil {
		h.log.Error("failed to list inbox invites", "user_id", user.ID, "error", err)
		api.WriteInternalError(w, "failed to list inbox invites")
		return
	}

	views := make([]InboxInviteView, 0, len(result))
	for _, inv := range result {
		views = append(views, InboxInviteView{
			ID:         inv.ID,
			SenderFQDN: inv.SenderFQDN,
			ReceivedAt: inv.ReceivedAt,
			Status:     inv.Status,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(InboxListResponse{Invites: views})
}

// HandleImport handles POST /api/inbox/invites/import.
// Parses an invite string and stores it for the current user.
func (h *Handler) HandleImport(w http.ResponseWriter, r *http.Request) {
	user, err := h.currentUser(r.Context())
	if err != nil {
		api.WriteUnauthorized(w, api.ReasonUnauthenticated, "authentication required")
		return
	}

	var req InviteImportRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.WriteBadRequest(w, api.ReasonBadRequest, "invalid request body")
		return
	}

	if req.InviteString == "" {
		api.WriteBadRequest(w, api.ReasonMissingField, "inviteString is required")
		return
	}

	token, senderFQDN, err := invites.ParseInviteString(req.InviteString)
	if err != nil {
		api.WriteBadRequest(w, api.ReasonInvalidField, "invalid invite string: "+err.Error())
		return
	}

	ctx := r.Context()

	// Idempotent: check for existing invite with same token for this user
	existing, err := h.incomingRepo.GetByTokenForRecipientUserID(ctx, token, user.ID)
	if err == nil && existing != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(InviteImportResponse{
			ID:         existing.ID,
			SenderFQDN: existing.SenderFQDN,
			ReceivedAt: existing.ReceivedAt.Format("2006-01-02T15:04:05Z07:00"),
			Status:     existing.Status,
		})
		return
	}

	invite := &invitesinbox.IncomingInvite{
		Token:           token,
		SenderFQDN:      senderFQDN,
		RecipientUserID: user.ID,
		Status:          invites.InviteStatusPending,
	}

	if err := h.incomingRepo.Create(ctx, invite); err != nil {
		h.log.Error("failed to create incoming invite", "user_id", user.ID, "error", err)
		api.WriteInternalError(w, "failed to import invite")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(InviteImportResponse{
		ID:         invite.ID,
		SenderFQDN: invite.SenderFQDN,
		ReceivedAt: invite.ReceivedAt.Format("2006-01-02T15:04:05Z07:00"),
		Status:     invite.Status,
	})
}

// HandleAccept handles POST /api/inbox/invites/{inviteId}/accept.
// Enforces ownership by construction: the repo returns not-found for cross-user access.
func (h *Handler) HandleAccept(w http.ResponseWriter, r *http.Request) {
	user, err := h.currentUser(r.Context())
	if err != nil {
		api.WriteUnauthorized(w, api.ReasonUnauthenticated, "authentication required")
		return
	}

	inviteID := chi.URLParam(r, "inviteId")
	if inviteID == "" {
		api.WriteBadRequest(w, api.ReasonMissingField, "inviteId is required")
		return
	}

	ctx := r.Context()

	invite, err := h.incomingRepo.GetByIDForRecipientUserID(ctx, inviteID, user.ID)
	if err != nil {
		if errors.Is(err, invites.ErrInviteNotFound) {
			api.WriteNotFound(w, "invite not found")
			return
		}
		h.log.Error("failed to get invite", "invite_id", inviteID, "user_id", user.ID, "error", err)
		api.WriteInternalError(w, "failed to get invite")
		return
	}

	if invite.Status == invites.InviteStatusAccepted {
		// Idempotent success
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"status":   string(invites.InviteStatusAccepted),
			"inviteId": inviteID,
		})
		return
	}

	if invite.Status != invites.InviteStatusPending {
		api.WriteConflict(w, "invite is not pending")
		return
	}

	// Send POST /ocm/invite-accepted to sender with all spec-required fields (E7=A)
	if err := h.sendInviteAccepted(ctx, invite, user); err != nil {
		h.log.Error("failed to send invite-accepted",
			"invite_id", inviteID, "sender_fqdn", invite.SenderFQDN, "error", err)
		api.WriteError(w, http.StatusBadGateway, api.ReasonPeerUnreachable, "failed to notify sender")
		return
	}

	// Update local status
	if err := h.incomingRepo.UpdateStatusForRecipientUserID(ctx, inviteID, user.ID, invites.InviteStatusAccepted); err != nil {
		h.log.Error("failed to update invite status", "invite_id", inviteID, "error", err)
		// Already accepted on sender side, log but return success
	}

	h.log.Info("invite accepted", "invite_id", inviteID, "sender_fqdn", invite.SenderFQDN)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":   string(invites.InviteStatusAccepted),
		"inviteId": inviteID,
	})
}

// HandleDecline handles POST /api/inbox/invites/{inviteId}/decline.
// Enforces ownership by construction: the repo returns not-found for cross-user access.
func (h *Handler) HandleDecline(w http.ResponseWriter, r *http.Request) {
	user, err := h.currentUser(r.Context())
	if err != nil {
		api.WriteUnauthorized(w, api.ReasonUnauthenticated, "authentication required")
		return
	}

	inviteID := chi.URLParam(r, "inviteId")
	if inviteID == "" {
		api.WriteBadRequest(w, api.ReasonMissingField, "inviteId is required")
		return
	}

	ctx := r.Context()

	invite, err := h.incomingRepo.GetByIDForRecipientUserID(ctx, inviteID, user.ID)
	if err != nil {
		if errors.Is(err, invites.ErrInviteNotFound) {
			api.WriteNotFound(w, "invite not found")
			return
		}
		h.log.Error("failed to get invite", "invite_id", inviteID, "user_id", user.ID, "error", err)
		api.WriteInternalError(w, "failed to get invite")
		return
	}

	if invite.Status == invites.InviteStatusDeclined {
		// Idempotent success
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"status":   string(invites.InviteStatusDeclined),
			"inviteId": inviteID,
		})
		return
	}

	if invite.Status != invites.InviteStatusPending {
		api.WriteConflict(w, "invite is not pending")
		return
	}

	// Decline is local only - delete the invite
	if err := h.incomingRepo.DeleteForRecipientUserID(ctx, inviteID, user.ID); err != nil {
		h.log.Error("failed to delete invite", "invite_id", inviteID, "error", err)
	}

	h.log.Info("invite declined", "invite_id", inviteID, "sender_fqdn", invite.SenderFQDN)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":   string(invites.InviteStatusDeclined),
		"inviteId": inviteID,
	})
}

// sendInviteAccepted sends POST /ocm/invite-accepted to the sender with all
// five spec-required AcceptedInvite fields (E7=A).
func (h *Handler) sendInviteAccepted(ctx context.Context, invite *invitesinbox.IncomingInvite, user *identity.User) error {
	// Discover sender's OCM endpoint
	baseURL := "https://" + invite.SenderFQDN
	disc, err := h.discoveryClient.Discover(ctx, baseURL)
	if err != nil {
		return fmt.Errorf("discovery failed for %s: %w", invite.SenderFQDN, err)
	}

	inviteAcceptedURL := disc.EndPoint + "/invite-accepted"

	// All five fields are spec-required (E7=A)
	reqBody := spec.InviteAcceptedRequest{
		RecipientProvider: h.localProvider,
		Token:             invite.Token,
		UserID:            address.EncodeFederatedOpaqueID(user.ID, h.localProvider),
		Email:             user.Email,
		Name:              user.DisplayName,
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
			outboundsigning.EndpointInvites,
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
