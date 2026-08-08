// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package sqlite_test

import (
	"fmt"
	"sync"
	"testing"

	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/sqlite"
	testutil "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/store"
)

// TestSQLiteConcurrentWritersSerialize validates the writer policy chosen in
// sqlitecore.Open: _txlock=immediate takes the write lock at BEGIN, and
// busy_timeout(5000) lets contenders wait for it instead of failing with
// SQLITE_BUSY. Many writers updating the same invite through the
// transaction-wrapped UpdateOutgoingInvite path must therefore ALL succeed,
// and the committed state must be exactly one writer's identity (the last to
// commit), never a stale or mixed coalesce.
//
// The strict all-writers-succeed assertion is what pins the immediate
// policy: with deferred transactions, competing writers race the
// SHARED-to-RESERVED lock upgrade and intermittently fail with SQLITE_BUSY,
// so this test would flake red without _txlock=immediate.
func TestSQLiteConcurrentWritersSerialize(t *testing.T) {
	t.Parallel()
	s, _, ctx := openSQLiteDriver(t, "ocm-test-sqlite-writers-*")

	invite := testutil.NewOutgoingInviteFixture()
	invite.ID = "concurrent-writers-invite"
	invite.Token = "concurrent-writers-token"
	invite.Status = "accepted"
	invite.AcceptedUserID = "user-0"
	invite.AcceptedProviderFQDNNormalized = invite.ProviderFQDN
	invite.AcceptedProviderFQDN = invite.ProviderFQDN

	if err := s.CreateOutgoingInvite(ctx, invite); err != nil {
		t.Fatalf("CreateOutgoingInvite: %v", err)
	}

	const writers = 8

	// start releases all writers at the same instant so their transactions
	// genuinely overlap instead of running back to back.
	start := make(chan struct{})

	var wg sync.WaitGroup

	errs := make([]error, writers)

	for i := range writers {
		wg.Add(1)

		go func() {
			defer wg.Done()

			<-start

			upd := *invite
			upd.AcceptedUserID = fmt.Sprintf("user-%d", i+1)
			upd.AcceptedProviderFQDNNormalized = invite.ProviderFQDN
			upd.AcceptedProviderFQDN = invite.ProviderFQDN

			errs[i] = s.UpdateOutgoingInvite(ctx, &upd)
		}()
	}

	close(start)
	wg.Wait()

	// Any SQLITE_BUSY here means the immediate policy is not in effect:
	// BEGIN IMMEDIATE plus the 5s busy timeout must absorb this contention.
	for i, err := range errs {
		if err != nil {
			t.Errorf("writer %d failed (want full serialization, no SQLITE_BUSY): %v", i, err)
		}
	}

	got, err := s.GetOutgoingInvite(ctx, invite.ID)
	if err != nil {
		t.Fatalf("GetOutgoingInvite after concurrent updates: %v", err)
	}

	// The final state must be exactly one writer's identity; a missing or
	// unknown value signals a lost update.
	valid := make(map[string]bool, writers)

	for i := range writers {
		valid[fmt.Sprintf("user-%d", i+1)] = true
	}

	if !valid[got.AcceptedUserID] {
		t.Errorf("AcceptedUserID after concurrent updates: got %q, want one of the writer identities", got.AcceptedUserID)
	}

	if got.AcceptedProviderFQDNNormalized != invite.ProviderFQDN {
		t.Errorf("AcceptedProviderFQDNNormalized after concurrent updates: got %q, want %q",
			got.AcceptedProviderFQDNNormalized, invite.ProviderFQDN)
	}
}
