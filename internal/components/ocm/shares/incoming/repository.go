// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package incoming

import (
	"context"
	"errors"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares"
)

// ErrShareNotFound is returned when a share is not found (including cross-user mismatch).
var ErrShareNotFound = errors.New("share not found")

// IncomingShareRepo manages incoming shares; all ops scoped by recipientUserID. Cross-user access = not found.
type IncomingShareRepo interface {
	Create(ctx context.Context, share *IncomingShare) error
	GetByIDForRecipientUserID(ctx context.Context, shareID string, recipientUserID string) (*IncomingShare, error)
	GetByProviderID(ctx context.Context, senderHost, providerID string) (*IncomingShare, error)
	ListByRecipientUserID(ctx context.Context, recipientUserID string) ([]*IncomingShare, error)
	UpdateStatusForRecipientUserID(ctx context.Context, shareID string, recipientUserID string, status shares.ShareStatus) error
	DeleteForRecipientUserID(ctx context.Context, shareID string, recipientUserID string) error
}
