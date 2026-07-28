package json_test

import (
	"context"
	"errors"
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
	defer driver.Close() //nolint:errcheck // test cleanup: driver close

	inStore, ok := driver.(store.IncomingInviteStore)
	if !ok {
		t.Fatal("json driver does not implement IncomingInviteStore")
	}

	invite := &store.IncomingInvite{
		ID:              "incoming-invite-1",
		Token:           "invite-token-1",
		InviteString:    "ocm://invite",
		SenderFQDN:      "remote.example",
		RecipientUserID: "alice",
		Status:          "pending",
		ReceivedAt:      time.Now().Unix(),
		UpdatedAt:       time.Now().Unix(),
	}

	if err := inStore.CreateIncomingInvite(ctx, invite); err != nil {
		t.Fatalf("CreateIncomingInvite failed: %v", err)
	}

	got, err := inStore.GetIncomingInviteForRecipient(ctx, invite.ID, invite.RecipientUserID)
	if err != nil {
		t.Fatalf("GetIncomingInviteForRecipient failed: %v", err)
	}

	if got.ID != invite.ID {
		t.Fatalf("expected invite %q, got %q", invite.ID, got.ID)
	}

	_, err = inStore.GetIncomingInviteForRecipient(ctx, invite.ID, "bob")
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected ErrNotFound for wrong recipient lookup, got %v", err)
	}

	if err := inStore.UpdateIncomingInviteStatusForRecipient( //nolint:govet // shadow: sequential err in table-driven test is benign
		ctx, invite.ID, invite.RecipientUserID, "accepted",
	); err != nil {
		t.Fatalf("UpdateIncomingInviteStatusForRecipient failed: %v", err)
	}

	err = inStore.UpdateIncomingInviteStatusForRecipient(ctx, invite.ID, "bob", "accepted")
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected ErrNotFound for wrong recipient update, got %v", err)
	}

	err = inStore.DeleteIncomingInviteForRecipient(ctx, invite.ID, "bob")
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected ErrNotFound for wrong recipient delete, got %v", err)
	}

	if err := inStore.DeleteIncomingInviteForRecipient(ctx, invite.ID, invite.RecipientUserID); err != nil { //nolint:govet // shadow: sequential err in table-driven test is benign
		t.Fatalf("DeleteIncomingInviteForRecipient failed: %v", err)
	}

	_, err = inStore.GetIncomingInviteForRecipient(ctx, invite.ID, invite.RecipientUserID)
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected ErrNotFound after delete, got %v", err)
	}
}

// TestJSONListIncomingInvitesRecipientScope ensures ListIncomingInvites always
// uses exact recipient matching: empty or wrong recipientUserID yields no results.
func TestJSONListIncomingInvitesRecipientScope(t *testing.T) {
	driver, _ := newJSONDriver(t)
	defer driver.Close() //nolint:errcheck // test cleanup: driver close

	ctx := context.Background()

	inStore := requireIncomingInviteStore(t, driver)

	invite := &store.IncomingInvite{
		ID:              "scope-test-invite",
		Token:           "scope-token",
		InviteString:    "ocm://invite",
		SenderFQDN:      "remote.example",
		RecipientUserID: "alice",
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
		t.Errorf("expected 0 invites for empty recipientUserID, got %d", len(got))
	}
}

// TestJSONOutgoingShareCreateConflictingShareID verifies that creating a second
// outgoing share with a ShareID already owned by a different record returns
// ErrAlreadyExists and leaves the original record intact.
func TestJSONOutgoingShareCreateConflictingShareID(t *testing.T) { //nolint:dupl // intentional: parallel ShareID/WebDAVID constraint tests share fixture setup but assert different unique keys
	driver, _ := newJSONDriver(t)
	defer driver.Close() //nolint:errcheck // test cleanup: driver close

	ctx := context.Background()

	outStore := requireOutgoingShareStore(t, driver)

	first := testutil.NewOutgoingShareFixture()
	first.ProviderID = "provider-a"
	first.ShareID = "shared-id"

	first.WebDAVID = "webdav-a"
	if err := outStore.CreateOutgoingShare(ctx, first); err != nil {
		t.Fatalf("CreateOutgoingShare(first): %v", err)
	}

	second := testutil.NewOutgoingShareFixture()
	second.ProviderID = "provider-b"
	second.ShareID = "shared-id" // same ShareID, different owner
	second.WebDAVID = "webdav-b"

	err := outStore.CreateOutgoingShare(ctx, second)
	if !errors.Is(err, store.ErrAlreadyExists) {
		t.Fatalf("expected ErrAlreadyExists for conflicting ShareID, got %v", err)
	}

	// Original must still be reachable.
	got, err := outStore.GetOutgoingShareByID(ctx, "shared-id")
	if err != nil {
		t.Fatalf("GetOutgoingShareByID after conflict: %v", err)
	}

	if got.ProviderID != "provider-a" {
		t.Errorf("original owner overwritten: expected provider-a, got %q", got.ProviderID)
	}
}

// TestJSONOutgoingShareUpdateConflictingShareID verifies that updating an
// outgoing share to a ShareID already owned by a different record returns
// ErrAlreadyExists and leaves both records intact.
func TestJSONOutgoingShareUpdateConflictingShareID(t *testing.T) {
	driver, _ := newJSONDriver(t)
	defer driver.Close() //nolint:errcheck // test cleanup: driver close

	ctx := context.Background()

	outStore := requireOutgoingShareStore(t, driver)

	first := testutil.NewOutgoingShareFixture()
	first.ProviderID = "provider-x"
	first.ShareID = "share-x"
	first.WebDAVID = "webdav-x"

	first.SharedSecret = "secret-x"
	if err := outStore.CreateOutgoingShare(ctx, first); err != nil {
		t.Fatalf("CreateOutgoingShare(first): %v", err)
	}

	second := testutil.NewOutgoingShareFixture()
	second.ProviderID = "provider-y"
	second.ShareID = "share-y"
	second.WebDAVID = "webdav-y"

	second.SharedSecret = "secret-y"
	if err := outStore.CreateOutgoingShare(ctx, second); err != nil {
		t.Fatalf("CreateOutgoingShare(second): %v", err)
	}

	// Attempt to steal first's ShareID via update.
	second.ShareID = "share-x"

	err := outStore.UpdateOutgoingShare(ctx, second)
	if !errors.Is(err, store.ErrAlreadyExists) {
		t.Fatalf("expected ErrAlreadyExists for conflicting ShareID on update, got %v", err)
	}

	// Original mapping must be untouched.
	got, err := outStore.GetOutgoingShareByID(ctx, "share-x")
	if err != nil {
		t.Fatalf("GetOutgoingShareByID after failed update: %v", err)
	}

	if got.ProviderID != "provider-x" {
		t.Errorf("original owner overwritten: expected provider-x, got %q", got.ProviderID)
	}
}

// TestJSONOutgoingShareCreateConflictingWebDAVID verifies that creating a second
// outgoing share with a WebDAVID already owned by a different record returns
// ErrAlreadyExists and leaves the original record intact.
func TestJSONOutgoingShareCreateConflictingWebDAVID(t *testing.T) { //nolint:dupl // intentional: parallel ShareID/WebDAVID constraint tests share fixture setup but assert different unique keys
	driver, _ := newJSONDriver(t)
	defer driver.Close() //nolint:errcheck // test cleanup: driver close

	ctx := context.Background()

	outStore := requireOutgoingShareStore(t, driver)

	first := testutil.NewOutgoingShareFixture()
	first.ProviderID = "provider-a"
	first.ShareID = "share-a"

	first.WebDAVID = "shared-webdav"
	if err := outStore.CreateOutgoingShare(ctx, first); err != nil {
		t.Fatalf("CreateOutgoingShare(first): %v", err)
	}

	second := testutil.NewOutgoingShareFixture()
	second.ProviderID = "provider-b"
	second.ShareID = "share-b"
	second.WebDAVID = "shared-webdav" // same WebDAVID, different owner

	err := outStore.CreateOutgoingShare(ctx, second)
	if !errors.Is(err, store.ErrAlreadyExists) {
		t.Fatalf("expected ErrAlreadyExists for conflicting WebDAVID, got %v", err)
	}

	// Original must still be reachable.
	got, err := outStore.GetOutgoingShareByWebDAVID(ctx, "shared-webdav")
	if err != nil {
		t.Fatalf("GetOutgoingShareByWebDAVID after conflict: %v", err)
	}

	if got.ProviderID != "provider-a" {
		t.Errorf("original owner overwritten: expected provider-a, got %q", got.ProviderID)
	}
}

// TestJSONOutgoingShareUpdateConflictingWebDAVID verifies that updating an
// outgoing share to a WebDAVID already owned by a different record returns
// ErrAlreadyExists and leaves both records intact.
func TestJSONOutgoingShareUpdateConflictingWebDAVID(t *testing.T) {
	driver, _ := newJSONDriver(t)
	defer driver.Close() //nolint:errcheck // test cleanup: driver close

	ctx := context.Background()

	outStore := requireOutgoingShareStore(t, driver)

	first := testutil.NewOutgoingShareFixture()
	first.ProviderID = "provider-m"
	first.ShareID = "share-m"
	first.WebDAVID = "webdav-m"

	first.SharedSecret = "secret-m"
	if err := outStore.CreateOutgoingShare(ctx, first); err != nil {
		t.Fatalf("CreateOutgoingShare(first): %v", err)
	}

	second := testutil.NewOutgoingShareFixture()
	second.ProviderID = "provider-n"
	second.ShareID = "share-n"
	second.WebDAVID = "webdav-n"

	second.SharedSecret = "secret-n"
	if err := outStore.CreateOutgoingShare(ctx, second); err != nil {
		t.Fatalf("CreateOutgoingShare(second): %v", err)
	}

	// Attempt to steal first's WebDAVID via update.
	second.WebDAVID = "webdav-m"

	err := outStore.UpdateOutgoingShare(ctx, second)
	if !errors.Is(err, store.ErrAlreadyExists) {
		t.Fatalf("expected ErrAlreadyExists for conflicting WebDAVID on update, got %v", err)
	}

	// Original mapping must be untouched.
	got, err := outStore.GetOutgoingShareByWebDAVID(ctx, "webdav-m")
	if err != nil {
		t.Fatalf("GetOutgoingShareByWebDAVID after failed update: %v", err)
	}

	if got.ProviderID != "provider-m" {
		t.Errorf("original owner overwritten: expected provider-m, got %q", got.ProviderID)
	}
}

// TestJSONOutgoingInviteCreateConflictingToken verifies that creating a second
// outgoing invite with a Token already owned by a different record returns
// ErrAlreadyExists and leaves the original record intact.
func TestJSONOutgoingInviteCreateConflictingToken(t *testing.T) {
	driver, _ := newJSONDriver(t)
	defer driver.Close() //nolint:errcheck // test cleanup: driver close

	ctx := context.Background()

	outInvStore := requireOutgoingInviteStore(t, driver)

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
	if !errors.Is(err, store.ErrAlreadyExists) {
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
	defer driver.Close() //nolint:errcheck // test cleanup: driver close

	ctx := context.Background()

	outInvStore := requireOutgoingInviteStore(t, driver)

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
	if !errors.Is(err, store.ErrAlreadyExists) {
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
