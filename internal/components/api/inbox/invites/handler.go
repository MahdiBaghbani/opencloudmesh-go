// Package invites provides session-gated API handlers for inbox invites (list, import, accept, decline).
package invites

import (
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
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/address"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites"
	invitesinbox "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites/inbox"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/outbound"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/outboundsigning"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/peercompat"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto"
	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/logutil"
)

type InboxInviteView struct {
	ID         string               `json:"id"`
	SenderFQDN string               `json:"senderFqdn"`
	ReceivedAt time.Time            `json:"receivedAt"`
	Status     invites.InviteStatus `json:"status"`
}

type InboxListResponse struct {
	Invites []InboxInviteView `json:"invites"`
}

// InviteImportRequest is the body for POST /api/inbox/invites/import.
type InviteImportRequest struct {
	InviteString string `json:"inviteString"`
}

// InviteImportResponse is the safe response for invite import (no token leaked).
type InviteImportResponse struct {
	ID         string               `json:"id"`
	SenderFQDN string               `json:"senderFqdn"`
	ReceivedAt string               `json:"receivedAt"`
	Status     invites.InviteStatus `json:"status"`
}

// Handler serves list, import, accept, and decline for inbox invites.
type Handler struct {
	incomingRepo    invitesinbox.IncomingInviteRepo
	httpClient      httpclient.HTTPClient
	discoveryClient *discovery.Client
	signer          *crypto.RFC9421Signer
	outboundPolicy  *outboundsigning.OutboundPolicy
	peerContract    *peercompat.CompiledContract
	localProvider   string // raw host[:port] for recipientProvider in invite-accepted
	currentUser     func(context.Context) (*identity.User, error)
	log             *slog.Logger
}

// NewHandler returns a Handler with the given dependencies.
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

// SetPeerContract wires the compiled compatibility contract so invite sender
// discovery uses the shared peer-origin resolver.
func (h *Handler) SetPeerContract(peerContract *peercompat.CompiledContract) {
	h.peerContract = peerContract
}

// HandleList handles GET /api/inbox/invites; returns only invites for the authenticated user.
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

// HandleImport handles POST /api/inbox/invites/import; idempotent for same token and user.
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

// HandleAccept handles POST /api/inbox/invites/{inviteId}/accept; idempotent if already accepted.
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

	if err := h.sendInviteAccepted(ctx, invite, user); err != nil {
		h.log.Error("failed to send invite-accepted",
			"invite_id", inviteID, "sender_fqdn", invite.SenderFQDN, "error", err)
		api.WriteError(w, http.StatusBadGateway, api.ReasonPeerUnreachable, "failed to notify sender")
		return
	}

	if err := h.incomingRepo.UpdateStatusForRecipientUserID(ctx, inviteID, user.ID, invites.InviteStatusAccepted); err != nil {
		h.log.Error("failed to update invite status", "invite_id", inviteID, "error", err)
		// Sender was notified; return success even if local update failed
	}

	h.log.Info("invite accepted", "invite_id", inviteID, "sender_fqdn", invite.SenderFQDN)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":   string(invites.InviteStatusAccepted),
		"inviteId": inviteID,
	})
}

// HandleDecline handles POST /api/inbox/invites/{inviteId}/decline; deletes the invite locally (no outbound call).
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

// sendInviteAccepted sends POST /ocm/invite-accepted to the sender with all spec-required fields.
func (h *Handler) sendInviteAccepted(ctx context.Context, invite *invitesinbox.IncomingInvite, user *identity.User) error {
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

	poster := outbound.NewPoster(h.httpClient, h.discoveryClient, h.signer, h.outboundPolicy, h.peerContract)
	resp, err := poster.Send(ctx, outbound.Request{
		TargetHost:   invite.SenderFQDN,
		EndpointPath: "invite-accepted",
		Kind:         outboundsigning.EndpointInvites,
		Body:         body,
	})
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("invite-accepted rejected with status %d: %s", resp.StatusCode, string(respBody))
	}

	return nil
}
