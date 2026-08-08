// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package json_test

import (
	"context"
	"os"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store"
	tshttp "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/http"
	testutil "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/store"
)

// TestJSONInviteSaveFailureRollback verifies that when saveFile fails the
// in-memory state is not left in a mutated state (no split-brain).
// The failure is injected by making the data directory read-only after Init.
func TestJSONInviteSaveFailureRollback(t *testing.T) {
	t.Parallel()
	runRollbackSuite(t, []rollbackCase{
		{"CreateOutgoingInvite", testCreateOutgoingInviteRollback},
		{"UpdateOutgoingInvite", testUpdateOutgoingInviteRollback},
		{"DeleteOutgoingInvite", testDeleteOutgoingInviteRollback},
		{"CreateIncomingInvite", testCreateIncomingInviteRollback},
		{"UpdateIncomingInviteStatusForRecipient", testUpdateIncomingInviteStatusRollback},
		{"DeleteIncomingInviteForRecipient", testDeleteIncomingInviteRollback},
	})
}

func makeDriver(t *testing.T, dir string) store.Driver {
	t.Helper()

	cfg := &store.DriverConfig{Driver: "json", DataDir: dir}

	return testutil.OpenDriver(t, cfg)
}

func lockDir(t *testing.T, dir string) {
	t.Helper()

	if err := os.Chmod(dir, 0500); err != nil { //nolint:gosec // test fixture: restrictive 0500 removes write permission on the temp dir to force store failures
		t.Fatal(err)
	}

	t.Cleanup(func() {
		restoreDirPerms(t, dir)
	})
}

func testCreateOutgoingInviteRollback(t *testing.T, ctx context.Context) {
	t.Helper()

	dir := testutil.TempDataDir(t, "ocm-test-json-rollback-create-out-*")

	d := makeDriver(t, dir) //nolint:contextcheck // test helper: driver open accepts no context
	defer tshttp.MustClose(t, d)

	outInvStore := requireOutgoingInviteStore(t, d)

	invite := testutil.NewOutgoingInviteFixture()

	lockDir(t, dir)

	if err := outInvStore.CreateOutgoingInvite(ctx, invite); err == nil {
		t.Fatal("expected error from CreateOutgoingInvite with read-only dir, got nil")
	}

	// Restore write permission and verify the invite is NOT in-memory (rollback succeeded).
	restoreDirPerms(t, dir)

	if _, err := outInvStore.GetOutgoingInvite(ctx, invite.ID); err == nil {
		t.Error("invite found in memory after failed create - rollback did not occur")
	}

	if _, err := outInvStore.GetOutgoingInviteByToken(ctx, invite.Token); err == nil {
		t.Error("invite token index not rolled back after failed create")
	}
}

func testUpdateOutgoingInviteRollback(t *testing.T, ctx context.Context) {
	t.Helper()

	dir := testutil.TempDataDir(t, "ocm-test-json-rollback-update-out-*")

	d := makeDriver(t, dir) //nolint:contextcheck // test helper: driver open accepts no context
	defer tshttp.MustClose(t, d)

	outInvStore := requireOutgoingInviteStore(t, d)

	invite := testutil.NewOutgoingInviteFixture()
	if err := outInvStore.CreateOutgoingInvite(ctx, invite); err != nil {
		t.Fatalf("setup CreateOutgoingInvite: %v", err)
	}

	updated := *invite
	updated.Token = "new-token"

	lockDir(t, dir)

	if err := outInvStore.UpdateOutgoingInvite(ctx, &updated); err == nil {
		t.Fatal("expected error from UpdateOutgoingInvite with read-only dir, got nil")
	}

	// Restore and verify the old value is still present (rollback succeeded).
	restoreDirPerms(t, dir)

	got, err := outInvStore.GetOutgoingInvite(ctx, invite.ID)
	if err != nil {
		t.Fatalf("invite missing after failed update: %v", err)
	}

	if got.Token != invite.Token {
		t.Errorf(
			"in-memory token changed after failed update: got %q, want %q",
			got.Token,
			invite.Token,
		)
	}

	if _, err := outInvStore.GetOutgoingInviteByToken(ctx, invite.Token); err != nil {
		t.Error("old token index entry missing after failed update rollback")
	}

	if _, err := outInvStore.GetOutgoingInviteByToken(ctx, updated.Token); err == nil {
		t.Error("new token index entry present after failed update - rollback incomplete")
	}
}

func testDeleteOutgoingInviteRollback(t *testing.T, ctx context.Context) {
	t.Helper()

	dir := testutil.TempDataDir(t, "ocm-test-json-rollback-delete-out-*")

	d := makeDriver(t, dir) //nolint:contextcheck // test helper: driver open accepts no context
	defer tshttp.MustClose(t, d)

	outInvStore := requireOutgoingInviteStore(t, d)

	invite := testutil.NewOutgoingInviteFixture()
	if err := outInvStore.CreateOutgoingInvite(ctx, invite); err != nil {
		t.Fatalf("setup CreateOutgoingInvite: %v", err)
	}

	lockDir(t, dir)

	if err := outInvStore.DeleteOutgoingInvite(ctx, invite.ID); err == nil {
		t.Fatal("expected error from DeleteOutgoingInvite with read-only dir, got nil")
	}

	// Restore and verify the invite is still present (rollback succeeded).
	restoreDirPerms(t, dir)

	if _, err := outInvStore.GetOutgoingInvite(ctx, invite.ID); err != nil {
		t.Errorf("invite missing after failed delete - rollback did not occur: %v", err)
	}

	if _, err := outInvStore.GetOutgoingInviteByToken(ctx, invite.Token); err != nil {
		t.Error("token index entry missing after failed delete rollback")
	}
}

func testCreateIncomingInviteRollback(t *testing.T, ctx context.Context) {
	t.Helper()

	dir := testutil.TempDataDir(t, "ocm-test-json-rollback-create-in-*")

	d := makeDriver(t, dir) //nolint:contextcheck // test helper: driver open accepts no context
	defer tshttp.MustClose(t, d)

	inInvStore := requireIncomingInviteStore(t, d)

	invite := testutil.NewIncomingInviteFixture()

	lockDir(t, dir)

	if err := inInvStore.CreateIncomingInvite(ctx, invite); err == nil {
		t.Fatal("expected error from CreateIncomingInvite with read-only dir, got nil")
	}

	restoreDirPerms(t, dir)

	if _, err := inInvStore.GetIncomingInviteForRecipient(
		ctx, invite.ID, invite.RecipientUserID,
	); err == nil {
		t.Error("incoming invite found in memory after failed create - rollback did not occur")
	}

	if _, err := inInvStore.GetIncomingInviteByToken(
		ctx, invite.Token, invite.RecipientUserID,
	); err == nil {
		t.Error("incoming invite token index not rolled back after failed create")
	}
}

func testUpdateIncomingInviteStatusRollback(t *testing.T, ctx context.Context) {
	t.Helper()

	dir := testutil.TempDataDir(t, "ocm-test-json-rollback-update-in-*")

	d := makeDriver(t, dir) //nolint:contextcheck // test helper: driver open accepts no context
	defer tshttp.MustClose(t, d)

	inInvStore := requireIncomingInviteStore(t, d)

	invite := testutil.NewIncomingInviteFixture()
	if err := inInvStore.CreateIncomingInvite(ctx, invite); err != nil {
		t.Fatalf("setup CreateIncomingInvite: %v", err)
	}

	oldStatus := invite.Status

	lockDir(t, dir)

	if err := inInvStore.UpdateIncomingInviteStatusForRecipient(
		ctx, invite.ID, invite.RecipientUserID, "new-status", "", "",
	); err == nil {
		t.Fatal("expected error from UpdateIncomingInviteStatusForRecipient with read-only dir, got nil")
	}

	restoreDirPerms(t, dir)

	got, err := inInvStore.GetIncomingInviteForRecipient(
		ctx, invite.ID, invite.RecipientUserID,
	)
	if err != nil {
		t.Fatalf("invite missing after failed status update: %v", err)
	}

	if got.Status != oldStatus {
		t.Errorf(
			"in-memory status changed after failed update: got %q, want %q",
			got.Status,
			oldStatus,
		)
	}
}

func testDeleteIncomingInviteRollback(t *testing.T, ctx context.Context) { //nolint:dupl // intentional: parallel invite/share delete rollback helpers share read-only-dir pattern but cover different stores
	t.Helper()

	dir := testutil.TempDataDir(t, "ocm-test-json-rollback-delete-in-*")

	d := makeDriver(t, dir) //nolint:contextcheck // test helper: driver open accepts no context
	defer tshttp.MustClose(t, d)

	inInvStore := requireIncomingInviteStore(t, d)

	invite := testutil.NewIncomingInviteFixture()
	if err := inInvStore.CreateIncomingInvite(ctx, invite); err != nil {
		t.Fatalf("setup CreateIncomingInvite: %v", err)
	}

	lockDir(t, dir)

	if err := inInvStore.DeleteIncomingInviteForRecipient(
		ctx, invite.ID, invite.RecipientUserID,
	); err == nil {
		t.Fatal("expected error from DeleteIncomingInviteForRecipient with read-only dir, got nil")
	}

	restoreDirPerms(t, dir)

	if _, err := inInvStore.GetIncomingInviteForRecipient(
		ctx, invite.ID, invite.RecipientUserID,
	); err != nil {
		t.Errorf("invite missing after failed delete - rollback did not occur: %v", err)
	}

	if _, err := inInvStore.GetIncomingInviteByToken(
		ctx, invite.Token, invite.RecipientUserID,
	); err != nil {
		t.Error("token-user index entry missing after failed delete rollback")
	}
}

// TestJSONInviteReopenDurability verifies that both invite surfaces persist
// and reload correctly after the JSON driver is closed and reopened.
