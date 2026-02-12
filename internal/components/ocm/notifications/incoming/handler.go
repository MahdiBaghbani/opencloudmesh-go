package incoming

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/notifications"
	sharesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/appctx"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/hostport"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/logutil"
)

type Handler struct {
	outgoingRepo sharesoutgoing.OutgoingShareRepo
	logger       *slog.Logger
	localScheme  string // scheme from PublicOrigin for comparison normalization
}

func NewHandler(outgoingRepo sharesoutgoing.OutgoingShareRepo, publicOrigin string, logger *slog.Logger) *Handler {
	logger = logutil.NoopIfNil(logger)

	var localScheme string
	if u, err := url.Parse(publicOrigin); err == nil && u.Scheme != "" {
		localScheme = u.Scheme
	}

	return &Handler{
		outgoingRepo: outgoingRepo,
		logger:       logger,
		localScheme:  localScheme,
	}
}

func (h *Handler) HandleNotification(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	log := appctx.GetLogger(r.Context())
	var req notifications.NewNotification
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Warn("failed to parse notification request", "error", err)
		h.sendError(w, http.StatusBadRequest, "invalid_json", "failed to parse request body")
		return
	}
	if req.NotificationType == "" {
		h.sendError(w, http.StatusBadRequest, "missing_field", "notificationType is required")
		return
	}
	if !notifications.IsValidNotificationType(req.NotificationType) {
		h.sendError(w, http.StatusBadRequest, "invalid_notification_type", "unsupported notification type")
		return
	}
	if req.ResourceType == "" {
		h.sendError(w, http.StatusBadRequest, "missing_field", "resourceType is required")
		return
	}
	if req.ProviderID == "" {
		h.sendError(w, http.StatusBadRequest, "missing_field", "providerId is required")
		return
	}
	var senderAuthority string
	peerIdentity := crypto.GetPeerIdentity(r.Context())
	if peerIdentity != nil && peerIdentity.Authenticated {
		senderAuthority = peerIdentity.AuthorityForCompare
	}
	share, err := h.outgoingRepo.GetByProviderID(r.Context(), req.ProviderID)
	if err != nil {
		if senderAuthority == "" {
			log.Warn("notification for unknown share", "provider_id", req.ProviderID)
			h.sendError(w, http.StatusNotFound, "share_not_found", "no share found for providerId")
			return
		}
		log.Warn("notification for unknown share", "provider_id", req.ProviderID, "sender", senderAuthority)
		h.sendError(w, http.StatusNotFound, "share_not_found", "no share found for providerId")
		return
	}
	if senderAuthority != "" {
		normalizedReceiver, err := hostport.Normalize(share.ReceiverHost, h.localScheme)
		if err != nil {
			log.Warn("failed to normalize share receiver host",
				"host", share.ReceiverHost, "error", err)
		} else if normalizedReceiver != senderAuthority {
			log.Warn("notification sender mismatch",
				"provider_id", req.ProviderID,
				"expected", normalizedReceiver,
				"got", senderAuthority)
			h.sendError(w, http.StatusForbidden, "sender_mismatch", "notification sender does not match share receiver")
			return
		}
	}
	switch req.NotificationType {
	case notifications.NotificationShareAccepted:
		log.Info("share accepted notification",
			"provider_id", req.ProviderID,
			"share_id", share.ShareID,
			"receiver", share.ReceiverHost)

	case notifications.NotificationShareDeclined:
		log.Info("share declined notification",
			"provider_id", req.ProviderID,
			"share_id", share.ShareID,
			"receiver", share.ReceiverHost)

	case notifications.NotificationShareUnshared:
		log.Info("share unshared notification",
			"provider_id", req.ProviderID,
			"share_id", share.ShareID,
			"receiver", share.ReceiverHost)
	}
	w.WriteHeader(http.StatusCreated)
}

func (h *Handler) sendError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{
		"error":       code,
		"description": message,
	})
}
