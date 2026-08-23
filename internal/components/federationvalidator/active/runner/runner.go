// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

// Package runner drives the validator active-session kick and heal loop.
package runner

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	invitesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites/outgoing"
	sharesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/localidentity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/logutil"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

const defaultPollInterval = 250 * time.Millisecond

// InviteDriver is the reverse-invite mint and solicit surface the runner
// heals through. Production wires reverseinvite.Service.
type InviteDriver interface {
	MintOutgoingInvite(ctx context.Context, testRunID string) (*invitesoutgoing.OutgoingInvite, error)
	SolicitReverse(ctx context.Context, testRunID string) error
}

// OutgoingCreator is the programmatic designated-share entry. Production
// wires outgoingshares.Handler.CreateAsUser.
type OutgoingCreator interface {
	CreateAsUser(
		ctx context.Context,
		user *identity.User,
		req sharesoutgoing.OutgoingShareRequest,
	) (*sharesoutgoing.OutgoingShare, error)
}

// Deps are the constructor dependencies for the active runner.
type Deps struct {
	Store         *validatorcore.Core
	Invites       InviteDriver
	Parties       identity.PartyRepo
	LocalIdentity localidentity.Identity
	ProbeEmail    string
	ProbeName     string
	ProbeFilePath string
	Log           *slog.Logger
	PollInterval  time.Duration
}

// Runner is the one long-lived active-session kick and heal loop.
type Runner struct {
	store        *validatorcore.Core
	invites      InviteDriver
	parties      identity.PartyRepo
	local        localidentity.Identity
	probeEmail   string
	probeName    string
	probePath    string
	log          *slog.Logger
	pollInterval time.Duration

	outgoingMu sync.RWMutex
	outgoing   OutgoingCreator

	wake      chan struct{}
	stop      chan struct{}
	done      chan struct{}
	ctx       context.Context //nolint:containedctx // runner-owned lifecycle context canceled by Stop
	cancel    context.CancelFunc
	startOnce sync.Once
	stopOnce  sync.Once
}

// New constructs a stopped runner. BindOutgoing then Start.
func New(deps Deps) (*Runner, error) {
	switch {
	case deps.Store == nil:
		return nil, errors.New("runner: Store is required")
	case deps.Invites == nil:
		return nil, errors.New("runner: Invites is required")
	case deps.Parties == nil:
		return nil, errors.New("runner: Parties is required")
	case deps.LocalIdentity.ProviderDomain == "":
		return nil, errors.New("runner: LocalIdentity.ProviderDomain is required")
	case deps.LocalIdentity.Scheme == "":
		return nil, errors.New("runner: LocalIdentity.Scheme is required")
	}

	poll := deps.PollInterval
	if poll <= 0 {
		poll = defaultPollInterval
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &Runner{
		store:        deps.Store,
		invites:      deps.Invites,
		parties:      deps.Parties,
		local:        deps.LocalIdentity,
		probeEmail:   deps.ProbeEmail,
		probeName:    deps.ProbeName,
		probePath:    deps.ProbeFilePath,
		log:          logutil.NoopIfNil(deps.Log),
		pollInterval: poll,
		wake:         make(chan struct{}, 1),
		stop:         make(chan struct{}),
		done:         make(chan struct{}),
		ctx:          ctx,
		cancel:       cancel,
	}, nil
}

// BindOutgoing installs the outgoing-share creator. Call before Start so a
// reverse_invite_accepted run can dispatch on the first tick.
func (r *Runner) BindOutgoing(creator OutgoingCreator) {
	if r == nil {
		return
	}

	r.outgoingMu.Lock()
	defer r.outgoingMu.Unlock()

	r.outgoing = creator
}

// Kick is the wake-only ActiveKicker. It carries no IDs. A full buffer
// drops the extra signal because the poll is the source of truth.
func (r *Runner) Kick() {
	if r == nil {
		return
	}

	select {
	case <-r.stop:
		return
	default:
	}

	select {
	case r.wake <- struct{}{}:
	default:
	}
}

// Start launches the single heal goroutine. Repeated calls are no-ops.
func (r *Runner) Start() {
	if r == nil {
		return
	}

	r.startOnce.Do(func() {
		go r.loop()
	})
}

// Stop cancels the runner context, then joins the loop. Safe before Start
// and after Stop. Cancel is invoked first so an in-flight DriveOnce can
// observe ctx.Err() and return.
func (r *Runner) Stop() {
	if r == nil {
		return
	}

	if r.cancel != nil {
		r.cancel()
	}

	r.stopOnce.Do(func() {
		close(r.stop)
	})
	r.startOnce.Do(func() {
		close(r.done)
	})
	<-r.done
}

func (r *Runner) outgoingCreator() OutgoingCreator {
	if r == nil {
		return nil
	}

	r.outgoingMu.RLock()
	defer r.outgoingMu.RUnlock()

	return r.outgoing
}

func (r *Runner) loop() {
	defer close(r.done)

	ticker := time.NewTicker(r.pollInterval)
	defer ticker.Stop()

	r.DriveOnce(r.ctx)

	for {
		select {
		case <-r.stop:
			return
		case <-r.wake:
			r.DriveOnce(r.ctx)
		case <-ticker.C:
			r.DriveOnce(r.ctx)
		}
	}
}
