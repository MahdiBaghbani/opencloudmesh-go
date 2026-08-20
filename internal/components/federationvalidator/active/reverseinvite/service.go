// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

// Package reverseinvite implements the validator's active reverse-invite leg:
// atomic outgoing invite minting, outgoing-acceptance observation, reverse
// solicit, paste import, and acceptance orchestration against the live OCM
// invite domain operations.
package reverseinvite

import (
	"errors"
	"log/slog"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	invitesincoming "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites/incoming"
	invitesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/localidentity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/logutil"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

var (
	// ErrSessionNotActive is returned when the named run is not the active run.
	ErrSessionNotActive = errors.New("reverseinvite: session is not the active run")

	// ErrBobNotBound is returned when the active run has no bob_user_id yet.
	ErrBobNotBound = errors.New("reverseinvite: session has no bound recipient")

	// ErrBobPartyMissing is returned when the bound Bob party is not
	// materialized in the party repo; solicit and accept never mint one.
	ErrBobPartyMissing = errors.New("reverseinvite: recipient party is not materialized")

	// ErrCorrelationMismatch is returned when the invite, the correlation row,
	// and the test run do not agree on token, invite ID, host, or recipient.
	ErrCorrelationMismatch = errors.New("reverseinvite: invite correlation mismatch")

	// ErrWrongTargetHost is returned when a pasted invite's sender host does
	// not normalize to the session target host.
	ErrWrongTargetHost = errors.New("reverseinvite: invite sender does not match target host")
)

// Deps carries the collaborators the reverse-invite orchestration needs.
type Deps struct {
	Store           *validatorcore.Core
	OutgoingInvites invitesoutgoing.OutgoingInviteRepo
	IncomingInvites invitesincoming.IncomingInviteRepo
	Parties         identity.PartyRepo
	Poster          invitesincoming.InviteAcceptedPoster
	LocalIdentity   localidentity.Identity
	Logger          *slog.Logger
}

// Service orchestrates the validator reverse-invite leg.
type Service struct {
	deps Deps
	log  *slog.Logger
}

// New validates deps and returns the service.
func New(deps Deps) (*Service, error) {
	switch {
	case deps.Store == nil:
		return nil, errors.New("reverseinvite: Store is required")
	case deps.OutgoingInvites == nil:
		return nil, errors.New("reverseinvite: OutgoingInvites is required")
	case deps.IncomingInvites == nil:
		return nil, errors.New("reverseinvite: IncomingInvites is required")
	case deps.Parties == nil:
		return nil, errors.New("reverseinvite: Parties is required")
	case deps.Poster == nil:
		return nil, errors.New("reverseinvite: Poster is required")
	case deps.LocalIdentity.ProviderDomain == "":
		return nil, errors.New("reverseinvite: LocalIdentity.ProviderDomain is required")
	case deps.LocalIdentity.Scheme == "":
		return nil, errors.New("reverseinvite: LocalIdentity.Scheme is required")
	}

	return &Service{deps: deps, log: logutil.NoopIfNil(deps.Logger)}, nil
}
