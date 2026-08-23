// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package passive

import (
	"context"
	"errors"
	"fmt"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
)

// SetReverseReceiver records the in-process party repo and probe identity
// used to materialize Bob immediately after a successful promotion.
func (h *Handler) SetReverseReceiver(
	parties identity.PartyRepo,
	realm, email, displayName string,
) {
	if h == nil {
		return
	}

	h.receiverMu.Lock()
	h.parties = parties
	h.receiverRealm = realm
	h.receiverEmail = email
	h.receiverName = displayName
	h.receiverMu.Unlock()

	h.flushPromoteFollowUp()
}

func (h *Handler) materializeReverseReceiver(ctx context.Context, testRunID string) error {
	if h == nil {
		return nil
	}

	h.receiverMu.Lock()
	parties := h.parties
	realm := h.receiverRealm
	email := h.receiverEmail
	name := h.receiverName
	h.receiverMu.Unlock()

	if parties == nil {
		return nil
	}

	run, err := h.store.GetTestRun(ctx, testRunID)
	if err != nil {
		return fmt.Errorf("passive: load extended run: %w", err)
	}

	if run.BobUserID == nil || *run.BobUserID == "" {
		return errors.New("passive: extended run has no bound recipient")
	}

	if _, err := identity.EnsureReverseReceiver(ctx, parties, identity.ReverseReceiverSpec{
		ID:          *run.BobUserID,
		Email:       email,
		DisplayName: name,
		Realm:       realm,
	}); err != nil {
		return fmt.Errorf("passive: ensure reverse receiver: %w", err)
	}

	return nil
}
