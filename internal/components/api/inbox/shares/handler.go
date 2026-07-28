// Package shares provides session-gated API handlers for inbox shares (list, detail, accept, decline, verify-access).
package shares

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/api"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/access"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/reason"
	sharesinbox "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/inbox"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/logutil"
)

// Verify-access reason codes for structured error responses.
const (
	verifyReasonShareNotAccepted = "share_not_accepted"
	verifyReasonUnsafePath       = "unsafe_path"
)

// InboxShareView omits sensitive fields (e.g. SharedSecret) from API responses.
type InboxShareView struct {
	ShareID           string                  `json:"shareId"`
	ProviderID        string                  `json:"providerId"`
	Name              string                  `json:"name"`
	Description       string                  `json:"description,omitempty"`
	Owner             string                  `json:"owner"`
	Sender            string                  `json:"sender"`
	SenderHost        string                  `json:"senderHost"`
	ShareWith         string                  `json:"shareWith"`
	ResourceType      string                  `json:"resourceType"`
	ShareType         string                  `json:"shareType"`
	Permissions       []string                `json:"permissions"`
	Status            sharesinbox.ShareStatus `json:"status"`
	CreatedAt         time.Time               `json:"createdAt"`
	OwnerDisplayName  string                  `json:"ownerDisplayName,omitempty"`
	SenderDisplayName string                  `json:"senderDisplayName,omitempty"`
}

// NewInboxShareView maps an incoming share to a list-safe API view without secrets.
func NewInboxShareView(s *sharesinbox.IncomingShare) InboxShareView {
	return InboxShareView{
		ShareID:           s.ShareID,
		ProviderID:        s.ProviderID,
		Name:              s.Name,
		Description:       s.Description,
		Owner:             s.Owner,
		Sender:            s.Sender,
		SenderHost:        s.SenderHost,
		ShareWith:         s.ShareWith,
		ResourceType:      s.ResourceType,
		ShareType:         s.ShareType,
		Permissions:       s.Permissions,
		Status:            s.Status,
		CreatedAt:         s.CreatedAt,
		OwnerDisplayName:  s.OwnerDisplayName,
		SenderDisplayName: s.SenderDisplayName,
	}
}

// InboxShareDetailView extends InboxShareView with protocol and WebDAV detail fields.
type InboxShareDetailView struct {
	InboxShareView

	WebDAVID                 string              `json:"webdavId,omitempty"`
	AbsoluteWebDAVURIPresent bool                `json:"webdavUriAbsolutePresent"`
	Protocol                 *ProtocolDetailView `json:"protocol"`
}

// ProtocolDetailView groups WebDAV and webapp protocol arms for a share detail response.
type ProtocolDetailView struct {
	Name   string            `json:"name"`
	WebDAV *WebDAVDetailView `json:"webdav,omitempty"`
	Webapp *WebappDetailView `json:"webapp,omitempty"`
}

// WebDAVDetailView exposes WebDAV protocol fields; SharedSecret is masked in responses.
type WebDAVDetailView struct {
	URI          string   `json:"uri"`
	Permissions  []string `json:"permissions"`
	Requirements []string `json:"requirements"`
	SharedSecret string   `json:"sharedSecret"`
}

// WebappDetailView exposes the persisted webapp arm fields for the inbox
// detail response. The webapp sharedSecret is not persisted, so it has no
// field here.
type WebappDetailView struct {
	URI         string   `json:"uri,omitempty"`
	Targets     []string `json:"targets,omitempty"`
	Permissions []string `json:"permissions,omitempty"`
}

func isAbsoluteWebDAVURI(uri string) bool {
	u, err := url.Parse(uri)
	if err != nil {
		return false
	}

	return u.IsAbs()
}

// NewInboxShareDetailView returns a detail view with SharedSecret masked as [REDACTED].
func NewInboxShareDetailView(s *sharesinbox.IncomingShare) InboxShareDetailView {
	uri := s.WebDAVID

	requirements := s.Requirements
	if requirements == nil {
		requirements = []string{}
	}

	permissions := s.Permissions
	if permissions == nil {
		permissions = []string{}
	}

	// Emit the stored protocol name. Legacy rows have an empty value; never
	// synthesize "multi" for them.
	proto := &ProtocolDetailView{
		Name: s.ProtocolName,
		WebDAV: &WebDAVDetailView{
			URI:          uri,
			Permissions:  permissions,
			Requirements: requirements,
			SharedSecret: "[REDACTED]",
		},
	}

	// Attach the webapp arm only when persisted webapp data exists. Legacy
	// rows leave the webapp field empty and omit the arm. The Targets and
	// Permissions fields use omitempty JSON tags, so nil slices are omitted
	// on the wire without explicit normalization.
	if s.WebappURI != "" || len(s.WebappPermissions) > 0 || len(s.WebappTargets) > 0 {
		proto.Webapp = &WebappDetailView{
			URI:         s.WebappURI,
			Targets:     s.WebappTargets,
			Permissions: s.WebappPermissions,
		}
	}

	return InboxShareDetailView{
		InboxShareView:           NewInboxShareView(s),
		WebDAVID:                 s.WebDAVID,
		AbsoluteWebDAVURIPresent: isAbsoluteWebDAVURI(s.WebDAVID),
		Protocol:                 proto,
	}
}

// InboxListResponse is the JSON body for the inbox shares list endpoint.
type InboxListResponse struct {
	Shares []InboxShareView `json:"shares"`
}

// VerifyAccessResponse is the body of the verify-access endpoint.
type VerifyAccessResponse struct {
	OK                      bool   `json:"ok"`
	HTTPStatus              int    `json:"httpStatus,omitempty"`
	ContentType             string `json:"contentType,omitempty"`
	ContentPreview          string `json:"contentPreview,omitempty"`
	ContentPreviewTruncated bool   `json:"contentPreviewTruncated,omitempty"`
	ReasonCode              string `json:"reasonCode,omitempty"`
	Error                   string `json:"error,omitempty"`
}

const maxPreviewBytes = 4096

// Handler serves list, detail, accept, decline, and verify-access for inbox shares.
type Handler struct {
	repo         sharesinbox.IncomingShareRepo
	accessClient access.RemoteAccessor
	currentUser  func(context.Context) (*identity.User, error)
	log          *slog.Logger
}

// NewHandler returns a Handler with the given dependencies.
func NewHandler(
	repo sharesinbox.IncomingShareRepo,
	accessClient access.RemoteAccessor,
	currentUser func(context.Context) (*identity.User, error),
	log *slog.Logger,
) *Handler {
	log = logutil.NoopIfNil(log)

	return &Handler{
		repo:         repo,
		accessClient: accessClient,
		currentUser:  currentUser,
		log:          log,
	}
}

// HandleList handles GET /api/inbox/shares; returns only shares for the authenticated user.
func (h *Handler) HandleList(w http.ResponseWriter, r *http.Request) {
	user, err := h.currentUser(r.Context())
	if err != nil {
		api.WriteUnauthorized(w, api.ReasonUnauthenticated, "authentication required")
		return
	}

	result, err := h.repo.ListByRecipientUserID(r.Context(), user.ID)
	if err != nil {
		h.log.Error("failed to list inbox shares", "user_id", user.ID, "error", err)
		api.WriteInternalError(w, "failed to list inbox shares")

		return
	}

	views := make([]InboxShareView, 0, len(result))
	for _, s := range result {
		views = append(views, NewInboxShareView(s))
	}

	w.Header().Set("Content-Type", "application/json")
	//nolint:errcheck,errchkjson // response already started; write error cannot be recovered; payload marshals to fixed JSON, so encode failure is always nil in practice
	json.NewEncoder(w).Encode(InboxListResponse{Shares: views})
}

// HandleAccept handles POST /api/inbox/shares/{shareId}/accept; idempotent if already accepted.
func (h *Handler) HandleAccept(w http.ResponseWriter, r *http.Request) {
	user, err := h.currentUser(r.Context())
	if err != nil {
		api.WriteUnauthorized(w, api.ReasonUnauthenticated, "authentication required")
		return
	}

	shareID := chi.URLParam(r, "shareId")
	if shareID == "" {
		api.WriteBadRequest(w, api.ReasonMissingField, "shareId is required")
		return
	}

	ctx := r.Context()

	share, err := h.repo.GetByIDForRecipientUserID(ctx, shareID, user.ID)
	if err != nil {
		if errors.Is(err, sharesinbox.ErrShareNotFound) {
			api.WriteNotFound(w, "share not found")
			return
		}

		h.log.Error("failed to get share", "share_id", shareID, "user_id", user.ID, "error", err)
		api.WriteInternalError(w, "failed to get share")

		return
	}

	if share.Status == sharesinbox.ShareStatusAccepted {
		w.Header().Set("Content-Type", "application/json")
		//nolint:errcheck,errchkjson // response already started; write error cannot be recovered; payload marshals to fixed JSON, so encode failure is always nil in practice
		json.NewEncoder(w).Encode(map[string]string{
			"status":  string(sharesinbox.ShareStatusAccepted),
			"shareId": shareID,
		})

		return
	}

	if share.Status == sharesinbox.ShareStatusDeclined {
		api.WriteConflict(w, "share has already been declined")
		return
	}

	if err := h.repo.UpdateStatusForRecipientUserID(ctx, shareID, user.ID, sharesinbox.ShareStatusAccepted); err != nil {
		h.log.Error("failed to update share status", "share_id", shareID, "error", err)
		api.WriteInternalError(w, "failed to update share status")

		return
	}

	w.Header().Set("Content-Type", "application/json")
	//nolint:errcheck,errchkjson // response already started; write error cannot be recovered; payload marshals to fixed JSON, so encode failure is always nil in practice
	json.NewEncoder(w).Encode(map[string]string{
		"status":  string(sharesinbox.ShareStatusAccepted),
		"shareId": shareID,
	})
}

// HandleGetDetail handles GET /api/inbox/shares/{shareId}; returns protocol info with secrets masked.
func (h *Handler) HandleGetDetail(w http.ResponseWriter, r *http.Request) {
	user, err := h.currentUser(r.Context())
	if err != nil {
		api.WriteUnauthorized(w, api.ReasonUnauthenticated, "authentication required")
		return
	}

	shareID := chi.URLParam(r, "shareId")
	if shareID == "" {
		api.WriteBadRequest(w, api.ReasonMissingField, "shareId is required")
		return
	}

	share, err := h.repo.GetByIDForRecipientUserID(r.Context(), shareID, user.ID)
	if err != nil {
		if errors.Is(err, sharesinbox.ErrShareNotFound) {
			api.WriteNotFound(w, "share not found")
			return
		}

		h.log.Error("failed to get share", "share_id", shareID, "user_id", user.ID, "error", err)
		api.WriteInternalError(w, "failed to get share")

		return
	}

	detail := NewInboxShareDetailView(share)

	w.Header().Set("Content-Type", "application/json")

	if err := json.NewEncoder(w).Encode(detail); err != nil {
		h.log.Error("failed to encode share detail", "error", err)
	}
}

// HandleDecline handles POST /api/inbox/shares/{shareId}/decline.
func (h *Handler) HandleDecline(w http.ResponseWriter, r *http.Request) {
	user, err := h.currentUser(r.Context())
	if err != nil {
		api.WriteUnauthorized(w, api.ReasonUnauthenticated, "authentication required")
		return
	}

	shareID := chi.URLParam(r, "shareId")
	if shareID == "" {
		api.WriteBadRequest(w, api.ReasonMissingField, "shareId is required")
		return
	}

	ctx := r.Context()

	share, err := h.repo.GetByIDForRecipientUserID(ctx, shareID, user.ID)
	if err != nil {
		if errors.Is(err, sharesinbox.ErrShareNotFound) {
			api.WriteNotFound(w, "share not found")
			return
		}

		h.log.Error("failed to get share", "share_id", shareID, "user_id", user.ID, "error", err)
		api.WriteInternalError(w, "failed to get share")

		return
	}

	if share.Status == sharesinbox.ShareStatusDeclined {
		w.Header().Set("Content-Type", "application/json")

		if err := json.NewEncoder(w).Encode(map[string]string{
			"status":  string(sharesinbox.ShareStatusDeclined),
			"shareId": shareID,
		}); err != nil {
			h.log.Error("failed to encode declined share", "error", err)
		}

		return
	}

	if share.Status == sharesinbox.ShareStatusAccepted {
		api.WriteConflict(w, "share has already been accepted")
		return
	}

	if err := h.repo.UpdateStatusForRecipientUserID(ctx, shareID, user.ID, sharesinbox.ShareStatusDeclined); err != nil {
		h.log.Error("failed to update share status", "share_id", shareID, "error", err)
		api.WriteInternalError(w, "failed to update share status")

		return
	}

	w.Header().Set("Content-Type", "application/json")

	if err := json.NewEncoder(w).Encode(map[string]string{
		"status":  string(sharesinbox.ShareStatusDeclined),
		"shareId": shareID,
	}); err != nil {
		h.log.Error("failed to encode declined share", "error", err)
	}
}

// HandleVerifyAccess handles POST /api/inbox/shares/{shareId}/verify-access; all access is server-side (no secrets to browser).
func (h *Handler) HandleVerifyAccess(w http.ResponseWriter, r *http.Request) {
	user, err := h.currentUser(r.Context())
	if err != nil {
		api.WriteUnauthorized(w, api.ReasonUnauthenticated, "authentication required")
		return
	}

	shareID := chi.URLParam(r, "shareId")
	if shareID == "" {
		api.WriteBadRequest(w, api.ReasonMissingField, "shareId is required")
		return
	}

	ctx := r.Context()

	share, err := h.repo.GetByIDForRecipientUserID(ctx, shareID, user.ID)
	if err != nil {
		if errors.Is(err, sharesinbox.ErrShareNotFound) {
			api.WriteNotFound(w, "share not found")
			return
		}

		h.log.Error("failed to get share", "share_id", shareID, "user_id", user.ID, "error", err)
		api.WriteInternalError(w, "failed to get share")

		return
	}

	if share.Status != sharesinbox.ShareStatusAccepted {
		writeVerifyError(w, http.StatusBadRequest, verifyReasonShareNotAccepted, "share must be accepted before verifying access")
		return
	}

	if isUnsafePath(share.Name) {
		writeVerifyError(w, http.StatusBadRequest, verifyReasonUnsafePath, "share name contains unsafe path components")
		return
	}

	protocol := access.ProtocolWebDAV
	if share.WebappURI != "" || strings.EqualFold(share.ProtocolName, access.ProtocolWebapp) {
		protocol = access.ProtocolWebapp
	}

	shareInfo := access.ShareInfo{
		Status:            string(share.Status),
		SenderHost:        share.SenderHost,
		OwnerHost:         share.OwnerHost,
		SharedSecret:      share.SharedSecret,
		ProtocolName:      share.ProtocolName,
		Requirements:      share.Requirements,
		WebDAVID:          share.WebDAVID,
		WebappURI:         share.WebappURI,
		WebappTargets:     share.WebappTargets,
		WebappPermissions: share.WebappPermissions,
	}

	result, err := h.accessClient.Access(ctx, access.AccessOptions{
		Share:    &shareInfo,
		Protocol: protocol,
		Method:   "GET",
		SubPath:  url.PathEscape(share.Name),
	})
	if err != nil {
		h.writeAccessError(w, err)
		return
	}
	defer func() {
		//nolint:errcheck // best-effort cleanup; error is not actionable
		result.Response.Body.Close()
	}()

	if result.Response.StatusCode < 200 || result.Response.StatusCode >= 300 {
		writeVerifyError(w, reason.APIStatus(reason.PeerUnreachable), reason.VerifyCode(reason.PeerUnreachable),
			"remote server returned "+redactPeerValue(result.Response.Status, share.SharedSecret))

		return
	}

	preview, truncated, readErr := readBoundedPreview(result.Response.Body)
	if readErr != nil {
		h.log.Warn("partial read of remote response body", "share_id", shareID, "error", readErr)
	}

	w.Header().Set("Content-Type", "application/json")

	if err := json.NewEncoder(w).Encode(VerifyAccessResponse{
		OK:                      true,
		HTTPStatus:              result.Response.StatusCode,
		ContentType:             redactPeerValue(result.Response.Header.Get("Content-Type"), share.SharedSecret),
		ContentPreview:          redactPeerValue(string(preview), share.SharedSecret),
		ContentPreviewTruncated: truncated,
	}); err != nil {
		h.log.Error("failed to encode verify access response", "error", err)
	}
}

// isUnsafePath rejects share names containing /, \, or ..
func isUnsafePath(name string) bool {
	return strings.Contains(name, "/") ||
		strings.Contains(name, "\\") ||
		strings.Contains(name, "..")
}

// readBoundedPreview reads up to maxPreviewBytes; truncation=true if more bytes exist.
func readBoundedPreview(r io.Reader) ([]byte, bool, error) {
	buf, err := io.ReadAll(io.LimitReader(r, int64(maxPreviewBytes+1)))
	if len(buf) > maxPreviewBytes {
		return buf[:maxPreviewBytes], true, err
	}

	return buf, false, err
}

// redactPeerValue redacts peer-controlled values (preview, content-type,
// status text) before they reach the browser.
func redactPeerValue(value, secret string) string {
	const redacted = "[REDACTED]"
	if secret != "" {
		value = strings.ReplaceAll(value, secret, redacted)
	}

	value = strings.ReplaceAll(value, "code=", "[REDACTED_CODE_PARAM]")
	value = strings.ReplaceAll(value, "sharedSecret", "[REDACTED_FIELD]")

	return value
}

// writeVerifyError writes a VerifyAccessResponse with ok=false.
func writeVerifyError(w http.ResponseWriter, statusCode int, reasonCode, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	//nolint:errcheck,errchkjson // response already started; write error cannot be recovered; payload marshals to fixed JSON, so encode failure is always nil in practice
	json.NewEncoder(w).Encode(VerifyAccessResponse{
		OK:         false,
		ReasonCode: reasonCode,
		Error:      message,
	})
}

func (h *Handler) writeAccessError(w http.ResponseWriter, err error) {
	if errors.Is(err, access.ErrShareNotAccepted) {
		writeVerifyError(w, http.StatusBadRequest, verifyReasonShareNotAccepted, "share not accepted")
		return
	}

	if errors.Is(err, access.ErrTokenExchangeRequired) {
		writeVerifyError(w, reason.APIStatus(reason.PeerCapabilityMismatch), reason.VerifyCode(reason.PeerCapabilityMismatch), "token exchange required but not available")
		return
	}

	if errors.Is(err, access.ErrRemoteAccessFailed) {
		writeVerifyError(w, reason.APIStatus(reason.PeerUnreachable), reason.VerifyCode(reason.PeerUnreachable), "remote access failed: all methods exhausted")
		return
	}

	reasonCode := reason.CanonicalFromError(err)
	writeVerifyError(w, reason.APIStatus(reasonCode), reason.VerifyCode(reasonCode), "remote access failed")
}
