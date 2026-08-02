// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package sqlite_test

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/sqlite"
	testutil "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/store"
)

func TestSQLiteDriver(t *testing.T) {
	tempDir := testutil.TempDataDir(t, "ocm-test-sqlite-*")

	cfg := &store.DriverConfig{
		Driver:  "sqlite",
		DataDir: tempDir,
	}

	testutil.RunDriverTests(t, "sqlite", cfg)

	// Verify database file was created
	if _, err := os.Stat(filepath.Join(tempDir, "ocm.db")); os.IsNotExist(err) {
		t.Error("ocm.db not created")
	}
}

// openSQLiteDriver creates and initializes a SQLite driver in a temp dir,
// registering cleanup to close it. The returned context is background.
func openSQLiteDriver(t *testing.T, name string) (store.OutgoingInviteStore, store.IncomingInviteStore, context.Context) {
	t.Helper()

	tempDir := testutil.TempDataDir(t, name)

	cfg := &store.DriverConfig{
		Driver:  "sqlite",
		DataDir: tempDir,
	}

	d, err := store.New(cfg)
	if err != nil {
		t.Fatalf("failed to create sqlite driver: %v", err)
	}

	ctx := context.Background()
	if initErr := d.Init(ctx); initErr != nil {
		if closeErr := d.Close(); closeErr != nil {
			t.Fatalf("failed to init sqlite driver: %v (close: %v)", initErr, closeErr)
		}

		t.Fatalf("failed to init sqlite driver: %v", initErr)
	}

	t.Cleanup(func() {
		if closeErr := d.Close(); closeErr != nil {
			t.Errorf("cleanup: close sqlite driver: %v", closeErr)
		}
	})

	out, ok := d.(store.OutgoingInviteStore)
	if !ok {
		t.Fatal("driver does not implement OutgoingInviteStore")
	}

	in, ok := d.(store.IncomingInviteStore)
	if !ok {
		t.Fatal("driver does not implement IncomingInviteStore")
	}

	return out, in, ctx
}

// TestSQLiteOutgoingInviteConcurrentUpdateNoStaleCoalesce verifies the
// transaction wrapping in UpdateOutgoingInvite prevents a TOCTOU stale
// coalesce: a coalescing writer (empty identity, carries over stored) and a
// replacing writer (new identity) update the same accepted invite with real
// overlap (both released by a single start barrier), so each writer reads and
// coalesces while the other may be mid-transaction.
//
// The replacing writer's committed value is the deterministic final state
// whenever it succeeds: the coalescing writer re-reads inside its own
// transaction, so it can never overwrite the replacing writer's identity with
// a stale carried-over value. If the transaction/row-lock were removed, the
// coalescing writer could read a stale row before the replacing writer commits
// and then overwrite it afterward, leaving the first writer's identity (user-a)
// even though the replacing writer succeeded; the exact assertion below fails
// in that case instead of masking it with an either/or check.
func TestSQLiteOutgoingInviteConcurrentUpdateNoStaleCoalesce(t *testing.T) {
	s, _, ctx := openSQLiteDriver(t, "ocm-test-sqlite-toctou-*")

	invite := testutil.NewOutgoingInviteFixture()
	invite.ID = "toctou-out-invite"
	invite.Token = "toctou-out-token"

	const (
		firstUserID  = "user-a"
		secondUserID = "user-b"
	)

	invite.Status = "accepted"
	invite.AcceptedUserID = firstUserID
	invite.AcceptedProviderFQDNNormalized = invite.ProviderFQDN
	invite.AcceptedProviderFQDN = invite.ProviderFQDN

	if err := s.CreateOutgoingInvite(ctx, invite); err != nil {
		t.Fatalf("CreateOutgoingInvite: %v", err)
	}

	// start releases both writers at the same instant so their
	// read/coalesce/write windows overlap instead of running back to back.
	start := make(chan struct{})

	var wg sync.WaitGroup

	errs := make([]error, 2)

	// Writer 1: re-accept with empty identity (coalesces from stored).
	wg.Add(1)

	go func() {
		defer wg.Done()

		<-start

		upd := *invite
		upd.AcceptedUserID = ""
		upd.AcceptedProviderFQDNNormalized = ""

		errs[0] = s.UpdateOutgoingInvite(ctx, &upd)
	}()

	// Writer 2: re-accept with a new identity (replaces stored).
	wg.Add(1)

	go func() {
		defer wg.Done()

		<-start

		upd := *invite
		upd.AcceptedUserID = secondUserID
		upd.AcceptedProviderFQDNNormalized = invite.ProviderFQDN

		errs[1] = s.UpdateOutgoingInvite(ctx, &upd)
	}()

	close(start)
	wg.Wait()

	// At least one update must succeed; a SQLITE_BUSY on one is acceptable
	// under contention, but both failing signals a real problem.
	if errs[0] != nil && errs[1] != nil {
		t.Fatalf("both concurrent updates failed: [0]=%v [1]=%v", errs[0], errs[1])
	}

	got, err := s.GetOutgoingInvite(ctx, invite.ID)
	if err != nil {
		t.Fatalf("GetOutgoingInvite after concurrent updates: %v", err)
	}

	if got.Status != "accepted" {
		t.Errorf("Status after concurrent updates: got %q, want accepted", got.Status)
	}

	// Observe which writer(s) committed and assert the exact final identity
	// for the last successful writer. The replacing writer's identity must
	// win whenever it committed; a stale coalesce leaving the first writer's
	// identity (user-a) would fail here.
	var wantUserID string

	switch {
	case errs[1] == nil:
		// The replacing writer committed, so its identity must be final.
		wantUserID = secondUserID
	case errs[0] == nil:
		// Only the coalescing writer committed (the replacing writer got
		// SQLITE_BUSY); it carried over the stored first identity.
		wantUserID = firstUserID
	default:
		t.Fatalf("no concurrent update succeeded: [0]=%v [1]=%v", errs[0], errs[1])
	}

	if got.AcceptedUserID != wantUserID {
		t.Errorf("AcceptedUserID after concurrent updates: got %q, want %q (last successful writer must win; first writer %q must not survive a stale coalesce)",
			got.AcceptedUserID, wantUserID, firstUserID)
	}

	if got.AcceptedProviderFQDNNormalized != invite.ProviderFQDN {
		t.Errorf("AcceptedProviderFQDNNormalized after concurrent updates: got %q, want %q",
			got.AcceptedProviderFQDNNormalized, invite.ProviderFQDN)
	}
}

// TestSQLiteIncomingInviteConcurrentUpdateNoStaleCoalesce verifies the
// transaction wrapping in UpdateIncomingInviteStatusForRecipient prevents a
// TOCTOU stale coalesce on the incoming side. A coalescing writer (empty
// identity, carries over stored) and a replacing writer (new identity) update
// the same accepted invite with real overlap (both released by a single start
// barrier), so each writer reads and coalesces while the other may be
// mid-transaction.
//
// The replacing writer's committed value is the deterministic final state
// whenever it succeeds: the coalescing writer re-reads inside its own
// transaction, so it can never overwrite the replacing writer's identity with
// a stale carried-over value. If the transaction/row-lock were removed, the
// coalescing writer could read a stale row before the replacing writer commits
// and then overwrite it afterward, leaving the first writer's identity
// (sender-a) even though the replacing writer succeeded; the exact assertion
// below fails in that case instead of masking it with an either/or check.
func TestSQLiteIncomingInviteConcurrentUpdateNoStaleCoalesce(t *testing.T) {
	_, s, ctx := openSQLiteDriver(t, "ocm-test-sqlite-toctou-in-*")

	invite := testutil.NewIncomingInviteFixture()
	invite.ID = "toctou-in-invite"
	invite.Token = "toctou-in-token"
	invite.RecipientUserID = "toctou-recipient"
	invite.Status = "pending"

	const (
		firstSenderID  = "sender-a"
		secondSenderID = "sender-b"
	)

	if err := s.CreateIncomingInvite(ctx, invite); err != nil {
		t.Fatalf("CreateIncomingInvite: %v", err)
	}

	// First accept with identity A.
	if err := s.UpdateIncomingInviteStatusForRecipient(ctx, invite.ID, invite.RecipientUserID, "accepted", firstSenderID, invite.SenderFQDN); err != nil {
		t.Fatalf("UpdateIncomingInviteStatusForRecipient initial accept: %v", err)
	}

	// start releases both writers at the same instant so their
	// read/coalesce/write windows overlap instead of running back to back.
	start := make(chan struct{})

	var wg sync.WaitGroup

	errs := make([]error, 2)

	// Writer 1: re-accept with empty identity (coalesces from stored).
	wg.Add(1)

	go func() {
		defer wg.Done()

		<-start

		errs[0] = s.UpdateIncomingInviteStatusForRecipient(ctx, invite.ID, invite.RecipientUserID, "accepted", "", "")
	}()

	// Writer 2: re-accept with a new identity (replaces stored).
	wg.Add(1)

	go func() {
		defer wg.Done()

		<-start

		errs[1] = s.UpdateIncomingInviteStatusForRecipient(ctx, invite.ID, invite.RecipientUserID, "accepted", secondSenderID, invite.SenderFQDN)
	}()

	close(start)
	wg.Wait()

	// At least one update must succeed; a SQLITE_BUSY on one is acceptable
	// under contention, but both failing signals a real problem.
	if errs[0] != nil && errs[1] != nil {
		t.Fatalf("both concurrent updates failed: [0]=%v [1]=%v", errs[0], errs[1])
	}

	got, err := s.GetIncomingInviteForRecipient(ctx, invite.ID, invite.RecipientUserID)
	if err != nil {
		t.Fatalf("GetIncomingInviteForRecipient after concurrent updates: %v", err)
	}

	if got.Status != "accepted" {
		t.Errorf("Status after concurrent updates: got %q, want accepted", got.Status)
	}

	// Observe which writer(s) committed and assert the exact final identity
	// for the last successful writer. The replacing writer's identity must
	// win whenever it committed; a stale coalesce leaving the first writer's
	// identity (sender-a) would fail here.
	var wantSenderID string

	switch {
	case errs[1] == nil:
		// The replacing writer committed, so its identity must be final.
		wantSenderID = secondSenderID
	case errs[0] == nil:
		// Only the coalescing writer committed (the replacing writer got
		// SQLITE_BUSY); it carried over the stored first identity.
		wantSenderID = firstSenderID
	default:
		t.Fatalf("no concurrent update succeeded: [0]=%v [1]=%v", errs[0], errs[1])
	}

	if got.SenderUserID != wantSenderID {
		t.Errorf("SenderUserID after concurrent updates: got %q, want %q (last successful writer must win; first writer %q must not survive a stale coalesce)",
			got.SenderUserID, wantSenderID, firstSenderID)
	}

	if got.SenderFQDNNormalized != invite.SenderFQDN {
		t.Errorf("SenderFQDNNormalized after concurrent updates: got %q, want %q",
			got.SenderFQDNNormalized, invite.SenderFQDN)
	}
}
