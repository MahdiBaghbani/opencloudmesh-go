package json_test

import (
	"context"
	"testing"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store"
	testutil "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/store"
)

func TestJSONIncomingInviteRecipientScope(t *testing.T) {
	tempDir := testutil.TempDataDir(t, "ocm-test-json-incoming-invite-*")

	ctx := context.Background()
	cfg := &store.DriverConfig{
		Driver:  "json",
		DataDir: tempDir,
	}

	driver := testutil.OpenDriver(t, cfg)
	defer driver.Close()

	inStore, ok := driver.(store.IncomingInviteStore)
	if !ok {
		t.Fatal("json driver does not implement IncomingInviteStore")
	}

	invite := &store.IncomingInvite{
		ID:              "incoming-invite-1",
		Token:           "invite-token-1",
		InviteString:    "ocm://invite",
		SenderFQDN:      "remote.example",
		RecipientUserId: "alice",
		Status:          "pending",
		ReceivedAt:      time.Now().Unix(),
		UpdatedAt:       time.Now().Unix(),
	}

	if err := inStore.CreateIncomingInvite(ctx, invite); err != nil {
		t.Fatalf("CreateIncomingInvite failed: %v", err)
	}

	got, err := inStore.GetIncomingInviteForRecipient(ctx, invite.ID, invite.RecipientUserId)
	if err != nil {
		t.Fatalf("GetIncomingInviteForRecipient failed: %v", err)
	}
	if got.ID != invite.ID {
		t.Fatalf("expected invite %q, got %q", invite.ID, got.ID)
	}

	_, err = inStore.GetIncomingInviteForRecipient(ctx, invite.ID, "bob")
	if err != store.ErrNotFound {
		t.Fatalf("expected ErrNotFound for wrong recipient lookup, got %v", err)
	}

	if err := inStore.UpdateIncomingInviteStatusForRecipient(
		ctx, invite.ID, invite.RecipientUserId, "accepted",
	); err != nil {
		t.Fatalf("UpdateIncomingInviteStatusForRecipient failed: %v", err)
	}

	err = inStore.UpdateIncomingInviteStatusForRecipient(ctx, invite.ID, "bob", "accepted")
	if err != store.ErrNotFound {
		t.Fatalf("expected ErrNotFound for wrong recipient update, got %v", err)
	}

	err = inStore.DeleteIncomingInviteForRecipient(ctx, invite.ID, "bob")
	if err != store.ErrNotFound {
		t.Fatalf("expected ErrNotFound for wrong recipient delete, got %v", err)
	}

	if err := inStore.DeleteIncomingInviteForRecipient(ctx, invite.ID, invite.RecipientUserId); err != nil {
		t.Fatalf("DeleteIncomingInviteForRecipient failed: %v", err)
	}

	_, err = inStore.GetIncomingInviteForRecipient(ctx, invite.ID, invite.RecipientUserId)
	if err != store.ErrNotFound {
		t.Fatalf("expected ErrNotFound after delete, got %v", err)
	}
}

// TestJSONListIncomingInvitesRecipientScope ensures ListIncomingInvites always
// uses exact recipient matching: empty or wrong recipientUserId yields no results.
func TestJSONListIncomingInvitesRecipientScope(t *testing.T) {
	driver, _ := newJSONDriver(t)
	defer driver.Close()
	ctx := context.Background()

	inStore := driver.(store.IncomingInviteStore)

	invite := &store.IncomingInvite{
		ID:              "scope-test-invite",
		Token:           "scope-token",
		InviteString:    "ocm://invite",
		SenderFQDN:      "remote.example",
		RecipientUserId: "alice",
		Status:          "pending",
		ReceivedAt:      time.Now().Unix(),
		UpdatedAt:       time.Now().Unix(),
	}
	if err := inStore.CreateIncomingInvite(ctx, invite); err != nil {
		t.Fatalf("CreateIncomingInvite: %v", err)
	}

	// Correct recipient returns the invite.
	got, err := inStore.ListIncomingInvites(ctx, "alice")
	if err != nil {
		t.Fatalf("ListIncomingInvites(alice): %v", err)
	}
	if len(got) != 1 {
		t.Errorf("expected 1 invite for alice, got %d", len(got))
	}

	// Wrong recipient must return empty, not all invites.
	got, err = inStore.ListIncomingInvites(ctx, "bob")
	if err != nil {
		t.Fatalf("ListIncomingInvites(bob): %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected 0 invites for bob, got %d", len(got))
	}

	// Empty string must return empty, not all invites (wildcard rejection).
	got, err = inStore.ListIncomingInvites(ctx, "")
	if err != nil {
		t.Fatalf("ListIncomingInvites(empty): %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected 0 invites for empty recipientUserId, got %d", len(got))
	}
}

// TestJSONOutgoingShareCreateConflictingShareId verifies that creating a second
// outgoing share with a ShareId already owned by a different record returns
// ErrAlreadyExists and leaves the original record intact.
func TestJSONOutgoingShareCreateConflictingShareId(t *testing.T) {
	driver, _ := newJSONDriver(t)
	defer driver.Close()
	ctx := context.Background()

	outStore := driver.(store.OutgoingShareStore)

	first := testutil.NewOutgoingShareFixture()
	first.ProviderId = "provider-a"
	first.ShareId = "shared-id"
	first.WebDAVId = "webdav-a"
	if err := outStore.CreateOutgoingShare(ctx, first); err != nil {
		t.Fatalf("CreateOutgoingShare(first): %v", err)
	}

	second := testutil.NewOutgoingShareFixture()
	second.ProviderId = "provider-b"
	second.ShareId = "shared-id" // same ShareId, different owner
	second.WebDAVId = "webdav-b"
	err := outStore.CreateOutgoingShare(ctx, second)
	if err != store.ErrAlreadyExists {
		t.Fatalf("expected ErrAlreadyExists for conflicting ShareId, got %v", err)
	}

	// Original must still be reachable.
	got, err := outStore.GetOutgoingShareByID(ctx, "shared-id")
	if err != nil {
		t.Fatalf("GetOutgoingShareByID after conflict: %v", err)
	}
	if got.ProviderId != "provider-a" {
		t.Errorf("original owner overwritten: expected provider-a, got %q", got.ProviderId)
	}
}

// TestJSONOutgoingShareUpdateConflictingShareId verifies that updating an
// outgoing share to a ShareId already owned by a different record returns
// ErrAlreadyExists and leaves both records intact.
func TestJSONOutgoingShareUpdateConflictingShareId(t *testing.T) {
	driver, _ := newJSONDriver(t)
	defer driver.Close()
	ctx := context.Background()

	outStore := driver.(store.OutgoingShareStore)

	first := testutil.NewOutgoingShareFixture()
	first.ProviderId = "provider-x"
	first.ShareId = "share-x"
	first.WebDAVId = "webdav-x"
	first.SharedSecret = "secret-x"
	if err := outStore.CreateOutgoingShare(ctx, first); err != nil {
		t.Fatalf("CreateOutgoingShare(first): %v", err)
	}

	second := testutil.NewOutgoingShareFixture()
	second.ProviderId = "provider-y"
	second.ShareId = "share-y"
	second.WebDAVId = "webdav-y"
	second.SharedSecret = "secret-y"
	if err := outStore.CreateOutgoingShare(ctx, second); err != nil {
		t.Fatalf("CreateOutgoingShare(second): %v", err)
	}

	// Attempt to steal first's ShareId via update.
	second.ShareId = "share-x"
	err := outStore.UpdateOutgoingShare(ctx, second)
	if err != store.ErrAlreadyExists {
		t.Fatalf("expected ErrAlreadyExists for conflicting ShareId on update, got %v", err)
	}

	// Original mapping must be untouched.
	got, err := outStore.GetOutgoingShareByID(ctx, "share-x")
	if err != nil {
		t.Fatalf("GetOutgoingShareByID after failed update: %v", err)
	}
	if got.ProviderId != "provider-x" {
		t.Errorf("original owner overwritten: expected provider-x, got %q", got.ProviderId)
	}
}

// TestJSONOutgoingShareCreateConflictingWebDAVId verifies that creating a second
// outgoing share with a WebDAVId already owned by a different record returns
// ErrAlreadyExists and leaves the original record intact.
func TestJSONOutgoingShareCreateConflictingWebDAVId(t *testing.T) {
	driver, _ := newJSONDriver(t)
	defer driver.Close()
	ctx := context.Background()

	outStore := driver.(store.OutgoingShareStore)

	first := testutil.NewOutgoingShareFixture()
	first.ProviderId = "provider-a"
	first.ShareId = "share-a"
	first.WebDAVId = "shared-webdav"
	if err := outStore.CreateOutgoingShare(ctx, first); err != nil {
		t.Fatalf("CreateOutgoingShare(first): %v", err)
	}

	second := testutil.NewOutgoingShareFixture()
	second.ProviderId = "provider-b"
	second.ShareId = "share-b"
	second.WebDAVId = "shared-webdav" // same WebDAVId, different owner
	err := outStore.CreateOutgoingShare(ctx, second)
	if err != store.ErrAlreadyExists {
		t.Fatalf("expected ErrAlreadyExists for conflicting WebDAVId, got %v", err)
	}

	// Original must still be reachable.
	got, err := outStore.GetOutgoingShareByWebDAVId(ctx, "shared-webdav")
	if err != nil {
		t.Fatalf("GetOutgoingShareByWebDAVId after conflict: %v", err)
	}
	if got.ProviderId != "provider-a" {
		t.Errorf("original owner overwritten: expected provider-a, got %q", got.ProviderId)
	}
}

// TestJSONOutgoingShareUpdateConflictingWebDAVId verifies that updating an
// outgoing share to a WebDAVId already owned by a different record returns
// ErrAlreadyExists and leaves both records intact.
func TestJSONOutgoingShareUpdateConflictingWebDAVId(t *testing.T) {
	driver, _ := newJSONDriver(t)
	defer driver.Close()
	ctx := context.Background()

	outStore := driver.(store.OutgoingShareStore)

	first := testutil.NewOutgoingShareFixture()
	first.ProviderId = "provider-m"
	first.ShareId = "share-m"
	first.WebDAVId = "webdav-m"
	first.SharedSecret = "secret-m"
	if err := outStore.CreateOutgoingShare(ctx, first); err != nil {
		t.Fatalf("CreateOutgoingShare(first): %v", err)
	}

	second := testutil.NewOutgoingShareFixture()
	second.ProviderId = "provider-n"
	second.ShareId = "share-n"
	second.WebDAVId = "webdav-n"
	second.SharedSecret = "secret-n"
	if err := outStore.CreateOutgoingShare(ctx, second); err != nil {
		t.Fatalf("CreateOutgoingShare(second): %v", err)
	}

	// Attempt to steal first's WebDAVId via update.
	second.WebDAVId = "webdav-m"
	err := outStore.UpdateOutgoingShare(ctx, second)
	if err != store.ErrAlreadyExists {
		t.Fatalf("expected ErrAlreadyExists for conflicting WebDAVId on update, got %v", err)
	}

	// Original mapping must be untouched.
	got, err := outStore.GetOutgoingShareByWebDAVId(ctx, "webdav-m")
	if err != nil {
		t.Fatalf("GetOutgoingShareByWebDAVId after failed update: %v", err)
	}
	if got.ProviderId != "provider-m" {
		t.Errorf("original owner overwritten: expected provider-m, got %q", got.ProviderId)
	}
}

// TestJSONOutgoingInviteCreateConflictingToken verifies that creating a second
// outgoing invite with a Token already owned by a different record returns
// ErrAlreadyExists and leaves the original record intact.
func TestJSONOutgoingInviteCreateConflictingToken(t *testing.T) {
	driver, _ := newJSONDriver(t)
	defer driver.Close()
	ctx := context.Background()

	outInvStore := driver.(store.OutgoingInviteStore)

	first := testutil.NewOutgoingInviteFixture()
	first.ID = "invite-a"
	first.Token = "shared-token"
	if err := outInvStore.CreateOutgoingInvite(ctx, first); err != nil {
		t.Fatalf("CreateOutgoingInvite(first): %v", err)
	}

	second := testutil.NewOutgoingInviteFixture()
	second.ID = "invite-b"
	second.Token = "shared-token" // same token, different invite ID
	err := outInvStore.CreateOutgoingInvite(ctx, second)
	if err != store.ErrAlreadyExists {
		t.Fatalf("expected ErrAlreadyExists for conflicting Token, got %v", err)
	}

	// Original must still be reachable.
	got, err := outInvStore.GetOutgoingInviteByToken(ctx, "shared-token")
	if err != nil {
		t.Fatalf("GetOutgoingInviteByToken after conflict: %v", err)
	}
	if got.ID != "invite-a" {
		t.Errorf("original invite overwritten: expected invite-a, got %q", got.ID)
	}
}

// TestJSONOutgoingInviteUpdateConflictingToken verifies that updating an
// outgoing invite to a Token already owned by a different record returns
// ErrAlreadyExists and leaves both records intact.
func TestJSONOutgoingInviteUpdateConflictingToken(t *testing.T) {
	driver, _ := newJSONDriver(t)
	defer driver.Close()
	ctx := context.Background()

	outInvStore := driver.(store.OutgoingInviteStore)

	first := testutil.NewOutgoingInviteFixture()
	first.ID = "invite-p"
	first.Token = "token-p"
	if err := outInvStore.CreateOutgoingInvite(ctx, first); err != nil {
		t.Fatalf("CreateOutgoingInvite(first): %v", err)
	}

	second := testutil.NewOutgoingInviteFixture()
	second.ID = "invite-q"
	second.Token = "token-q"
	if err := outInvStore.CreateOutgoingInvite(ctx, second); err != nil {
		t.Fatalf("CreateOutgoingInvite(second): %v", err)
	}

	// Attempt to steal first's token via update.
	second.Token = "token-p"
	err := outInvStore.UpdateOutgoingInvite(ctx, second)
	if err != store.ErrAlreadyExists {
		t.Fatalf("expected ErrAlreadyExists for conflicting Token on update, got %v", err)
	}

	// Original mapping must be untouched.
	got, err := outInvStore.GetOutgoingInviteByToken(ctx, "token-p")
	if err != nil {
		t.Fatalf("GetOutgoingInviteByToken after failed update: %v", err)
	}
	if got.ID != "invite-p" {
		t.Errorf("original invite overwritten: expected invite-p, got %q", got.ID)
	}
}
