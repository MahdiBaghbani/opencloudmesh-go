// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package outgoing

import (
	"context"
	"errors"
)

// ErrShareNotFound is returned when an outgoing share is not found.
var ErrShareNotFound = errors.New("share not found")

type OutgoingShareRepo interface { //nolint:revive // exported: self-explanatory CRUD interface for outgoing shares
	Create(ctx context.Context, share *OutgoingShare) error
	GetByID(ctx context.Context, shareID string) (*OutgoingShare, error)
	GetByProviderID(ctx context.Context, providerID string) (*OutgoingShare, error)
	GetByWebDAVID(ctx context.Context, webdavID string) (*OutgoingShare, error)
	GetBySharedSecret(ctx context.Context, sharedSecret string) (*OutgoingShare, error)
	List(ctx context.Context) ([]*OutgoingShare, error)
	Update(ctx context.Context, share *OutgoingShare) error
}
