// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package repos_test

import (
	"context"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/repos"
	tshttp "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/http"
	tsrepos "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/repos"
)

// TestRepoContract runs the full repo-level contract against every backend.
// memory is the semantic reference: all durable backends (json, sqlite, mirror)
// must match its observable behavior on every operation including list
// operations and recipient-scoped access.
func TestRepoContract(t *testing.T) {
	t.Parallel()

	for _, tt := range tsrepos.OpenTestRepos() {
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()

			r := tt.Open(t)
			defer tshttp.MustClose(t, r)

			runRepoContract(t, r)
		})
	}
}

// TestDurableDriversExposeAllRepoInterfaces verifies json, sqlite, and mirror
// each expose all four app repo interfaces and that every required list
// operation is callable without error. repos.New returns an error if the
// underlying store driver does not implement the fullStore union (via
// type-assertion in newStoreRepos); this test makes that assertion visible
// and also smoke-tests each list operation to confirm it is wired correctly.
func TestDurableDriversExposeAllRepoInterfaces(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	for _, backend := range tsrepos.DurableBackends() {
		t.Run(backend, func(t *testing.T) {
			t.Parallel()

			// repos.New internally type-asserts drv.(fullStore); failure here
			// means the driver is missing at least one store interface.
			r := tsrepos.OpenDurable(t, ctx, backend)
			defer tshttp.MustClose(t, r)

			if r.OutgoingShares == nil {
				t.Fatalf("%s: OutgoingShares is nil", backend)
			}

			if r.IncomingShares == nil {
				t.Fatalf("%s: IncomingShares is nil", backend)
			}

			if r.OutgoingInvites == nil {
				t.Fatalf("%s: OutgoingInvites is nil", backend)
			}

			if r.IncomingInvites == nil {
				t.Fatalf("%s: IncomingInvites is nil", backend)
			}

			// Smoke-test every list operation against an empty store to confirm
			// the method is implemented and correctly wired.
			if _, err := r.OutgoingShares.List(ctx); err != nil {
				t.Errorf("OutgoingShares.List on empty store: %v", err)
			}

			if _, err := r.IncomingShares.ListByRecipientUserID(ctx, "contract-user"); err != nil {
				t.Errorf("IncomingShares.ListByRecipientUserID on empty store: %v", err)
			}

			if _, err := r.OutgoingInvites.List(ctx); err != nil {
				t.Errorf("OutgoingInvites.List on empty store: %v", err)
			}

			if _, err := r.IncomingInvites.ListByRecipientUserID(ctx, "contract-user"); err != nil {
				t.Errorf("IncomingInvites.ListByRecipientUserID on empty store: %v", err)
			}
		})
	}
}

// TestOutgoingInviteAcceptedIdentityCoalescedOnEmptyUpdate verifies across
// every backend that re-accepting an already-accepted outgoing invite with an
// empty identity payload preserves the persisted accepted identity: the user
// id and normalized host coalesce from the stored row so a partial write cannot
// erase them, and the raw provider FQDN is not overwritten by the empty payload.
func TestOutgoingInviteAcceptedIdentityCoalescedOnEmptyUpdate(t *testing.T) {
	t.Parallel()

	for _, tt := range tsrepos.OpenTestRepos() {
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()

			r := tt.Open(t)
			defer tshttp.MustClose(t, r)

			runOutgoingInviteRepoContractAcceptedIdentityCoalescedOnEmptyUpdate(t, context.Background(), r)
		})
	}
}

// TestIncomingInviteAcceptedIdentityCoalescedOnEmptyUpdate verifies across
// every backend that re-accepting an already-accepted incoming invite with an
// empty identity payload preserves the persisted sender identity: the user id
// and normalized host coalesce from the stored row so a partial write cannot
// erase them, and the raw sender FQDN is not overwritten by the empty payload.
func TestIncomingInviteAcceptedIdentityCoalescedOnEmptyUpdate(t *testing.T) {
	t.Parallel()

	for _, tt := range tsrepos.OpenTestRepos() {
		t.Run(tt.Name, func(t *testing.T) {
			t.Parallel()

			r := tt.Open(t)
			defer tshttp.MustClose(t, r)

			runIncomingInviteRepoContractAcceptedIdentityCoalescedOnEmptyUpdate(t, context.Background(), r)
		})
	}
}

// runRepoContract exercises all four app repo interfaces against a single
// *repos.Repos instance. All subtests use IDs that are unique within this
// call so no state leaks between subtests.
func runRepoContract(t *testing.T, r *repos.Repos) {
	t.Helper()
	t.Run("OutgoingShares", func(t *testing.T) {
		runOutgoingShareRepoContract(t, r)
	})
	t.Run("IncomingShares", func(t *testing.T) {
		runIncomingShareRepoContract(t, r)
	})
	t.Run("OutgoingInvites", func(t *testing.T) {
		runOutgoingInviteRepoContract(t, r)
	})
	t.Run("IncomingInvites", func(t *testing.T) {
		runIncomingInviteRepoContract(t, r)
	})
}
