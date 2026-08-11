// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

// Package shares provides session-gated API handlers for inbox shares (list, detail, accept, decline, verify-access).
package shares

import (
	"context"
	"log/slog"
	"net/url"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/access"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares"
	sharesincoming "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/incoming"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/logutil"
)

// Verify-access reason codes for structured error responses.
const (
	verifyReasonShareNotAccepted    = "share_not_accepted"
	verifyReasonUnsupportedProtocol = "unsupported_protocol"
)

// InboxShareView omits sensitive fields (e.g. SharedSecret) from API responses.
type InboxShareView struct {
	ShareID           string             `json:"shareId"`
	ProviderID        string             `json:"providerId"`
	Name              string             `json:"name"`
	Description       string             `json:"description,omitempty"`
	Owner             string             `json:"owner"`
	Sender            string             `json:"sender"`
	SenderHost        string             `json:"senderHost"`
	ShareWith         string             `json:"shareWith"`
	ResourceType      string             `json:"resourceType"`
	ShareType         string             `json:"shareType"`
	Permissions       []string           `json:"permissions"`
	Status            shares.ShareStatus `json:"status"`
	CreatedAt         time.Time          `json:"createdAt"`
	OwnerDisplayName  string             `json:"ownerDisplayName,omitempty"`
	SenderDisplayName string             `json:"senderDisplayName,omitempty"`
}

// NewInboxShareView maps an incoming share to a list-safe API view without secrets.
func NewInboxShareView(s *sharesincoming.IncomingShare) InboxShareView {
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
func NewInboxShareDetailView(s *sharesincoming.IncomingShare) InboxShareDetailView {
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
	repo         sharesincoming.IncomingShareRepo
	accessClient access.RemoteAccessor
	currentUser  func(context.Context) (*identity.User, error)
	log          *slog.Logger
}

// NewHandler returns a Handler with the given dependencies.
func NewHandler(
	repo sharesincoming.IncomingShareRepo,
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
