// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

// Package forwardshare implements the validator's active forward-share
// dispatch leg: a policy guard on the generic outgoing-share handler that
// refuses every non-designated share while a run is active, plus the
// outbox-backed designated dispatch with a single-winner send permit,
// idempotent replay, and capability presence healing.
package forwardshare

import (
	"errors"

	outgoingshares "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/api/outgoing/shares"
	sharesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/localidentity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

// Deps are the constructor dependencies for the forward-share dispatch leg.
type Deps struct {
	Store          *validatorcore.Core
	OutgoingShares sharesoutgoing.OutgoingShareRepo
	LocalIdentity  localidentity.Identity
}

// Service guards and commits the designated forward-share dispatch for the
// active validation run.
type Service struct {
	deps Deps
}

var _ outgoingshares.DispatchHook = (*Service)(nil)

// New constructs the forward-share dispatch service.
func New(deps Deps) (*Service, error) {
	switch {
	case deps.Store == nil:
		return nil, errors.New("forwardshare: Store is required")
	case deps.OutgoingShares == nil:
		return nil, errors.New("forwardshare: OutgoingShares is required")
	case deps.LocalIdentity.Scheme == "":
		return nil, errors.New("forwardshare: LocalIdentity.Scheme is required")
	}

	return &Service{deps: deps}, nil
}
