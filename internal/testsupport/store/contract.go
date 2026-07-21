package store

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store"
)

// RunDriverTests runs the standard test suite against a driver.
// All four persistence surfaces are required: OutgoingShareStore,
// IncomingShareStore, OutgoingInviteStore, and IncomingInviteStore.
//
// Each subtest creates and closes its own fresh driver in a subdirectory of
// cfg.DataDir, so no store state leaks between siblings. A preflight driver is
// also created from the original cfg to ensure on-disk artifacts (e.g. ocm.db,
// mirror/) appear under cfg.DataDir for callers that check for them after this
// function returns.
func RunDriverTests(t *testing.T, driverName string, cfg *store.DriverConfig) {
	t.Helper()
	ctx := context.Background()

	// Preflight: verify creation, initialization, name, and interface compliance
	// using the original cfg. Closing it immediately after checks keeps the
	// original DataDir's artifacts intact for caller assertions.
	preflight, err := store.New(cfg)
	if err != nil {
		t.Fatalf("failed to create %s driver: %v", driverName, err)
	}
	if err := preflight.Init(ctx); err != nil {
		preflight.Close()
		t.Fatalf("failed to init %s driver: %v", driverName, err)
	}
	if preflight.Name() != driverName {
		t.Errorf("expected driver name %q, got %q", driverName, preflight.Name())
	}
	if _, ok := preflight.(store.OutgoingShareStore); !ok {
		preflight.Close()
		t.Fatalf("%s driver does not implement OutgoingShareStore", driverName)
	}
	if _, ok := preflight.(store.IncomingShareStore); !ok {
		preflight.Close()
		t.Fatalf("%s driver does not implement IncomingShareStore", driverName)
	}
	if _, ok := preflight.(store.OutgoingInviteStore); !ok {
		preflight.Close()
		t.Fatalf("%s driver does not implement OutgoingInviteStore", driverName)
	}
	if _, ok := preflight.(store.IncomingInviteStore); !ok {
		preflight.Close()
		t.Fatalf("%s driver does not implement IncomingInviteStore", driverName)
	}
	preflight.Close()

	// newSubDriver creates a fresh, isolated driver in a new subdirectory of
	// cfg.DataDir. The subtest's t.Cleanup closes it when the subtest ends.
	newSubDriver := func(t *testing.T) store.Driver {
		t.Helper()
		subDir, err := os.MkdirTemp(cfg.DataDir, "sub-")
		if err != nil {
			t.Fatalf("create subtest dir: %v", err)
		}
		subCfg := cloneConfig(cfg, subDir)
		d, err := store.New(subCfg)
		if err != nil {
			t.Fatalf("failed to create %s sub-driver: %v", driverName, err)
		}
		if err := d.Init(ctx); err != nil {
			d.Close()
			t.Fatalf("failed to init %s sub-driver: %v", driverName, err)
		}
		t.Cleanup(func() { d.Close() })
		return d
	}

	t.Run("OutgoingShareCRUD", func(t *testing.T) {
		d := newSubDriver(t)
		runOutgoingShareCRUD(t, ctx, d.(store.OutgoingShareStore))
	})

	t.Run("OutgoingShareDuplicateSharedSecret", func(t *testing.T) {
		d := newSubDriver(t)
		runOutgoingShareDuplicateSharedSecret(t, ctx, d.(store.OutgoingShareStore))
	})

	t.Run("OutgoingShareEmptySharedSecretLookup", func(t *testing.T) {
		d := newSubDriver(t)
		runOutgoingShareEmptySharedSecretLookup(t, ctx, d.(store.OutgoingShareStore))
	})

	t.Run("OutgoingShareUpdateNotFound", func(t *testing.T) {
		d := newSubDriver(t)
		runOutgoingShareUpdateNotFound(t, ctx, d.(store.OutgoingShareStore))
	})

	t.Run("IncomingShareCRUD", func(t *testing.T) {
		d := newSubDriver(t)
		runIncomingShareCRUD(t, ctx, d.(store.IncomingShareStore))
	})

	t.Run("ProviderKeyScopedLookup", func(t *testing.T) {
		d := newSubDriver(t)
		runProviderKeyScopedLookup(t, ctx, d.(store.IncomingShareStore))
	})

	t.Run("OutgoingInviteCRUD", func(t *testing.T) {
		d := newSubDriver(t)
		runOutgoingInviteCRUD(t, ctx, d.(store.OutgoingInviteStore))
	})

	t.Run("OutgoingInviteUpdateNotFound", func(t *testing.T) {
		d := newSubDriver(t)
		runOutgoingInviteUpdateNotFound(t, ctx, d.(store.OutgoingInviteStore))
	})

	t.Run("IncomingInviteStatusContract", func(t *testing.T) {
		d := newSubDriver(t)
		runIncomingInviteStatusContract(t, ctx, d.(store.IncomingInviteStore))
	})

	t.Run("IncomingInviteCompositeUniqueness", func(t *testing.T) {
		d := newSubDriver(t)
		runIncomingInviteCompositeUniqueness(t, ctx, d.(store.IncomingInviteStore))
	})

	t.Run("IncomingShareProviderKeyUniqueness", func(t *testing.T) {
		d := newSubDriver(t)
		runIncomingShareProviderKeyUniqueness(t, ctx, d.(store.IncomingShareStore))
	})
}

// cloneConfig returns a shallow copy of cfg with DataDir replaced by dir.
func cloneConfig(cfg *store.DriverConfig, dir string) *store.DriverConfig {
	c := *cfg
	c.DataDir = dir
	return &c
}

func runOutgoingShareCRUD(t *testing.T, ctx context.Context, s store.OutgoingShareStore) {
	share := NewOutgoingShareFixture()

	// Create
	if err := s.CreateOutgoingShare(ctx, share); err != nil {
		t.Fatalf("CreateOutgoingShare failed: %v", err)
	}
	t.Cleanup(func() {
		if err := s.DeleteOutgoingShare(ctx, share.ProviderId); err != nil && err != store.ErrNotFound {
			t.Errorf("cleanup: DeleteOutgoingShare: %v", err)
		}
	})

	// Get by local share id
	gotByID, err := s.GetOutgoingShareByID(ctx, share.ShareId)
	if err != nil {
		t.Fatalf("GetOutgoingShareByID failed: %v", err)
	}
	if gotByID.ShareId != share.ShareId {
		t.Errorf("expected shareId %q, got %q", share.ShareId, gotByID.ShareId)
	}

	// Get by providerId
	got, err := s.GetOutgoingShare(ctx, share.ProviderId)
	if err != nil {
		t.Fatalf("GetOutgoingShare failed: %v", err)
	}
	if got.ProviderId != share.ProviderId {
		t.Errorf("expected providerId %q, got %q", share.ProviderId, got.ProviderId)
	}

	// Get by webdavId
	got, err = s.GetOutgoingShareByWebDAVId(ctx, share.WebDAVId)
	if err != nil {
		t.Fatalf("GetOutgoingShareByWebDAVId failed: %v", err)
	}
	if got.WebDAVId != share.WebDAVId {
		t.Errorf("expected webdavId %q, got %q", share.WebDAVId, got.WebDAVId)
	}

	// Get by shared secret
	gotBySecret, err := s.GetOutgoingShareBySharedSecret(ctx, share.SharedSecret)
	if err != nil {
		t.Fatalf("GetOutgoingShareBySharedSecret failed: %v", err)
	}
	if gotBySecret.SharedSecret != share.SharedSecret {
		t.Errorf("expected sharedSecret %q, got %q", share.SharedSecret, gotBySecret.SharedSecret)
	}

	// Update
	share.State = "accepted"
	if err := s.UpdateOutgoingShare(ctx, share); err != nil {
		t.Fatalf("UpdateOutgoingShare failed: %v", err)
	}
	got, _ = s.GetOutgoingShare(ctx, share.ProviderId)
	if got.State != "accepted" {
		t.Errorf("expected state 'accepted', got %q", got.State)
	}

	// List
	shares, err := s.ListOutgoingShares(ctx)
	if err != nil {
		t.Fatalf("ListOutgoingShares failed: %v", err)
	}
	if len(shares) == 0 {
		t.Error("expected at least one share in list")
	}

	// Delete
	if err := s.DeleteOutgoingShare(ctx, share.ProviderId); err != nil {
		t.Fatalf("DeleteOutgoingShare failed: %v", err)
	}

	// Verify deleted
	_, err = s.GetOutgoingShare(ctx, share.ProviderId)
	if err != store.ErrNotFound {
		t.Errorf("expected ErrNotFound after delete, got %v", err)
	}
}

func runIncomingShareCRUD(t *testing.T, ctx context.Context, s store.IncomingShareStore) {
	share := NewIncomingShareFixture()
	// Seed an older UpdatedAt so the post-update assertion is meaningful even at
	// second resolution: the update must set a timestamp strictly greater than this.
	share.UpdatedAt = time.Now().Add(-2 * time.Second).Unix()

	// Create
	if err := s.CreateIncomingShare(ctx, share); err != nil {
		t.Fatalf("CreateIncomingShare failed: %v", err)
	}
	t.Cleanup(func() {
		if err := s.DeleteIncomingShareForRecipient(ctx, share.ShareId, share.UserId); err != nil && err != store.ErrNotFound {
			t.Errorf("cleanup: DeleteIncomingShareForRecipient: %v", err)
		}
	})

	// Get by shareId scoped to recipient
	got, err := s.GetIncomingShareByIDForRecipient(ctx, share.ShareId, share.UserId)
	if err != nil {
		t.Fatalf("GetIncomingShareByIDForRecipient failed: %v", err)
	}
	if got.ShareId != share.ShareId {
		t.Errorf("expected shareId %q, got %q", share.ShareId, got.ShareId)
	}

	// Cross-user access must return not found
	_, err = s.GetIncomingShareByIDForRecipient(ctx, share.ShareId, "other-user")
	if err != store.ErrNotFound {
		t.Errorf("expected ErrNotFound for wrong recipient, got %v", err)
	}

	// Get by provider key (sender-scoped)
	got, err = s.GetIncomingShareByProviderKey(ctx, share.SendingServer, share.ProviderId)
	if err != nil {
		t.Fatalf("GetIncomingShareByProviderKey failed: %v", err)
	}
	if got.ShareId != share.ShareId {
		t.Errorf("expected shareId %q, got %q", share.ShareId, got.ShareId)
	}

	// Update status scoped to recipient
	priorUpdatedAt := share.UpdatedAt
	if err := s.UpdateIncomingShareStatusForRecipient(ctx, share.ShareId, share.UserId, "accepted"); err != nil {
		t.Fatalf("UpdateIncomingShareStatusForRecipient failed: %v", err)
	}
	updated, err := s.GetIncomingShareByIDForRecipient(ctx, share.ShareId, share.UserId)
	if err != nil {
		t.Fatalf("GetIncomingShareByIDForRecipient after status update failed: %v", err)
	}
	if updated.State != "accepted" {
		t.Errorf("expected state 'accepted' after status update, got %q", updated.State)
	}
	if updated.UpdatedAt <= priorUpdatedAt {
		t.Errorf(
			"UpdatedAt not increased after status update: got %d, want > %d",
			updated.UpdatedAt,
			priorUpdatedAt,
		)
	}

	// Cross-user update must return not found
	err = s.UpdateIncomingShareStatusForRecipient(ctx, share.ShareId, "other-user", "accepted")
	if err != store.ErrNotFound {
		t.Errorf("expected ErrNotFound for wrong recipient on update, got %v", err)
	}

	// List by recipient
	shares, err := s.ListIncomingSharesByRecipient(ctx, share.UserId)
	if err != nil {
		t.Fatalf("ListIncomingSharesByRecipient failed: %v", err)
	}
	if len(shares) == 0 {
		t.Error("expected at least one share in list")
	}

	// Delete scoped to recipient
	if err := s.DeleteIncomingShareForRecipient(ctx, share.ShareId, share.UserId); err != nil {
		t.Fatalf("DeleteIncomingShareForRecipient failed: %v", err)
	}

	// Verify deleted
	_, err = s.GetIncomingShareByIDForRecipient(ctx, share.ShareId, share.UserId)
	if err != store.ErrNotFound {
		t.Errorf("expected ErrNotFound after delete, got %v", err)
	}
}

// runProviderKeyScopedLookup verifies sender-scoped provider key lookup.
func runProviderKeyScopedLookup(t *testing.T, ctx context.Context, s store.IncomingShareStore) {
	// Create two shares with same providerId but different senders
	share1 := NewIncomingShareFixture()
	share1.ShareId = "share-1"
	share1.SendingServer = "server1.com"
	share1.ProviderId = "same-provider-id"

	share2 := NewIncomingShareFixture()
	share2.ShareId = "share-2"
	share2.SendingServer = "server2.com"
	share2.ProviderId = "same-provider-id"

	if err := s.CreateIncomingShare(ctx, share1); err != nil {
		t.Fatalf("CreateIncomingShare share1 failed: %v", err)
	}
	t.Cleanup(func() {
		if err := s.DeleteIncomingShareForRecipient(ctx, share1.ShareId, share1.UserId); err != nil && err != store.ErrNotFound {
			t.Errorf("cleanup: DeleteIncomingShareForRecipient share1: %v", err)
		}
	})
	if err := s.CreateIncomingShare(ctx, share2); err != nil {
		t.Fatalf("CreateIncomingShare share2 failed: %v", err)
	}
	t.Cleanup(func() {
		if err := s.DeleteIncomingShareForRecipient(ctx, share2.ShareId, share2.UserId); err != nil && err != store.ErrNotFound {
			t.Errorf("cleanup: DeleteIncomingShareForRecipient share2: %v", err)
		}
	})

	// Lookup by server1 should return share1
	got, err := s.GetIncomingShareByProviderKey(ctx, "server1.com", "same-provider-id")
	if err != nil {
		t.Fatalf("GetIncomingShareByProviderKey server1 failed: %v", err)
	}
	if got.ShareId != "share-1" {
		t.Errorf("expected share-1, got %q", got.ShareId)
	}

	// Lookup by server2 should return share2
	got, err = s.GetIncomingShareByProviderKey(ctx, "server2.com", "same-provider-id")
	if err != nil {
		t.Fatalf("GetIncomingShareByProviderKey server2 failed: %v", err)
	}
	if got.ShareId != "share-2" {
		t.Errorf("expected share-2, got %q", got.ShareId)
	}
}

// runOutgoingInviteCRUD tests CRUD operations for outgoing invites, including
// that the token index stays consistent when the token changes on update.
func runOutgoingInviteCRUD(t *testing.T, ctx context.Context, s store.OutgoingInviteStore) {
	invite := NewOutgoingInviteFixture()

	// Create
	if err := s.CreateOutgoingInvite(ctx, invite); err != nil {
		t.Fatalf("CreateOutgoingInvite failed: %v", err)
	}
	t.Cleanup(func() {
		if err := s.DeleteOutgoingInvite(ctx, invite.ID); err != nil && err != store.ErrNotFound {
			t.Errorf("cleanup: DeleteOutgoingInvite: %v", err)
		}
	})

	// Duplicate create must fail
	if err := s.CreateOutgoingInvite(ctx, invite); err != store.ErrAlreadyExists {
		t.Errorf("expected ErrAlreadyExists on duplicate create, got %v", err)
	}

	// Get by id
	got, err := s.GetOutgoingInvite(ctx, invite.ID)
	if err != nil {
		t.Fatalf("GetOutgoingInvite failed: %v", err)
	}
	if got.Token != invite.Token {
		t.Errorf("expected token %q, got %q", invite.Token, got.Token)
	}

	// Get by token
	got, err = s.GetOutgoingInviteByToken(ctx, invite.Token)
	if err != nil {
		t.Fatalf("GetOutgoingInviteByToken failed: %v", err)
	}
	if got.ID != invite.ID {
		t.Errorf("expected id %q, got %q", invite.ID, got.ID)
	}

	// Update with a new token - old token index entry must be removed.
	oldToken := invite.Token
	invite.Token = "new-invite-token"
	invite.Status = "accepted"
	if err := s.UpdateOutgoingInvite(ctx, invite); err != nil {
		t.Fatalf("UpdateOutgoingInvite failed: %v", err)
	}

	// Old token must no longer resolve.
	_, err = s.GetOutgoingInviteByToken(ctx, oldToken)
	if err != store.ErrNotFound {
		t.Errorf("expected ErrNotFound for stale token after update, got %v", err)
	}

	// New token must resolve correctly.
	got, err = s.GetOutgoingInviteByToken(ctx, invite.Token)
	if err != nil {
		t.Fatalf("GetOutgoingInviteByToken for new token failed: %v", err)
	}
	if got.Status != "accepted" {
		t.Errorf("expected status 'accepted', got %q", got.Status)
	}

	// List by user
	invites, err := s.ListOutgoingInvites(ctx, invite.CreatedByUserId)
	if err != nil {
		t.Fatalf("ListOutgoingInvites failed: %v", err)
	}
	if len(invites) == 0 {
		t.Error("expected at least one invite in list")
	}

	// Delete
	if err := s.DeleteOutgoingInvite(ctx, invite.ID); err != nil {
		t.Fatalf("DeleteOutgoingInvite failed: %v", err)
	}

	// Verify deleted
	_, err = s.GetOutgoingInvite(ctx, invite.ID)
	if err != store.ErrNotFound {
		t.Errorf("expected ErrNotFound after delete, got %v", err)
	}
}

// runIncomingInviteStatusContract verifies that incoming-invite updates are
// status-only: cross-user access is rejected and scope-defining fields (Token,
// RecipientUserId) are unchanged after a status update.
func runIncomingInviteStatusContract(t *testing.T, ctx context.Context, s store.IncomingInviteStore) {
	invite := NewIncomingInviteFixture()

	// Create
	if err := s.CreateIncomingInvite(ctx, invite); err != nil {
		t.Fatalf("CreateIncomingInvite failed: %v", err)
	}
	t.Cleanup(func() {
		if err := s.DeleteIncomingInviteForRecipient(ctx, invite.ID, invite.RecipientUserId); err != nil && err != store.ErrNotFound {
			t.Errorf("cleanup: DeleteIncomingInviteForRecipient: %v", err)
		}
	})

	// Get by id scoped to recipient
	got, err := s.GetIncomingInviteForRecipient(ctx, invite.ID, invite.RecipientUserId)
	if err != nil {
		t.Fatalf("GetIncomingInviteForRecipient failed: %v", err)
	}
	if got.Token != invite.Token {
		t.Errorf("expected token %q, got %q", invite.Token, got.Token)
	}

	// Cross-user get must return not found
	_, err = s.GetIncomingInviteForRecipient(ctx, invite.ID, "other-user")
	if err != store.ErrNotFound {
		t.Errorf("expected ErrNotFound for cross-user get, got %v", err)
	}

	// Get by token scoped to recipient
	got, err = s.GetIncomingInviteByToken(ctx, invite.Token, invite.RecipientUserId)
	if err != nil {
		t.Fatalf("GetIncomingInviteByToken failed: %v", err)
	}
	if got.ID != invite.ID {
		t.Errorf("expected id %q, got %q", invite.ID, got.ID)
	}

	// Cross-user token lookup must return not found
	_, err = s.GetIncomingInviteByToken(ctx, invite.Token, "other-user")
	if err != store.ErrNotFound {
		t.Errorf("expected ErrNotFound for cross-user token lookup, got %v", err)
	}

	// Status update scoped to recipient
	beforeUpdate := time.Now().Unix()
	if err := s.UpdateIncomingInviteStatusForRecipient(
		ctx, invite.ID, invite.RecipientUserId, "accepted",
	); err != nil {
		t.Fatalf("UpdateIncomingInviteStatusForRecipient failed: %v", err)
	}
	got, err = s.GetIncomingInviteForRecipient(ctx, invite.ID, invite.RecipientUserId)
	if err != nil {
		t.Fatalf("GetIncomingInviteForRecipient after update failed: %v", err)
	}
	if got.Status != "accepted" {
		t.Errorf("expected status 'accepted' after update, got %q", got.Status)
	}
	// Scope-defining fields must be unchanged
	if got.Token != invite.Token {
		t.Errorf(
			"token must not change on status update: expected %q, got %q",
			invite.Token,
			got.Token,
		)
	}
	if got.RecipientUserId != invite.RecipientUserId {
		t.Errorf(
			"recipient must not change on status update: expected %q, got %q",
			invite.RecipientUserId,
			got.RecipientUserId,
		)
	}
	// UpdatedAt must be refreshed
	if got.UpdatedAt < beforeUpdate {
		t.Errorf(
			"UpdatedAt not refreshed after status update: got %d, expected >= %d",
			got.UpdatedAt,
			beforeUpdate,
		)
	}

	// Cross-user status update must return not found
	err = s.UpdateIncomingInviteStatusForRecipient(ctx, invite.ID, "other-user", "declined")
	if err != store.ErrNotFound {
		t.Errorf("expected ErrNotFound for cross-user status update, got %v", err)
	}

	// Token index must still resolve after status update (token did not change)
	got, err = s.GetIncomingInviteByToken(ctx, invite.Token, invite.RecipientUserId)
	if err != nil {
		t.Fatalf("GetIncomingInviteByToken must still work after status update: %v", err)
	}
	if got.Status != "accepted" {
		t.Errorf("expected updated status via token lookup, got %q", got.Status)
	}

	// List by recipient
	invites, err := s.ListIncomingInvites(ctx, invite.RecipientUserId)
	if err != nil {
		t.Fatalf("ListIncomingInvites failed: %v", err)
	}
	if len(invites) == 0 {
		t.Error("expected at least one invite in list")
	}

	// Cross-user delete must return not found
	err = s.DeleteIncomingInviteForRecipient(ctx, invite.ID, "other-user")
	if err != store.ErrNotFound {
		t.Errorf("expected ErrNotFound for cross-user delete, got %v", err)
	}

	// Delete scoped to recipient
	if err := s.DeleteIncomingInviteForRecipient(ctx, invite.ID, invite.RecipientUserId); err != nil {
		t.Fatalf("DeleteIncomingInviteForRecipient failed: %v", err)
	}

	// Verify deleted
	_, err = s.GetIncomingInviteForRecipient(ctx, invite.ID, invite.RecipientUserId)
	if err != store.ErrNotFound {
		t.Errorf("expected ErrNotFound after delete, got %v", err)
	}
}

// runIncomingInviteCompositeUniqueness verifies that (token, recipientUserId)
// is enforced as a composite unique key across all backends:
// - a duplicate pair returns ErrAlreadyExists
// - the original record is not replaced
// - the same token with a different recipient is allowed
func runIncomingInviteCompositeUniqueness(
	t *testing.T,
	ctx context.Context,
	s store.IncomingInviteStore,
) {
	first := &store.IncomingInvite{
		ID:              "composite-unique-test-1",
		Token:           "composite-unique-token",
		InviteString:    "ocm://invite/test",
		SenderFQDN:      "remote.example",
		RecipientUserId: "alice",
		Status:          "pending",
		ReceivedAt:      time.Now().Unix(),
		UpdatedAt:       time.Now().Unix(),
	}
	if err := s.CreateIncomingInvite(ctx, first); err != nil {
		t.Fatalf("CreateIncomingInvite(first): %v", err)
	}
	t.Cleanup(func() {
		if err := s.DeleteIncomingInviteForRecipient(ctx, first.ID, first.RecipientUserId); err != nil && err != store.ErrNotFound {
			t.Errorf("cleanup: DeleteIncomingInviteForRecipient first: %v", err)
		}
	})

	// Same (token, recipientUserId), different ID: must fail.
	second := &store.IncomingInvite{
		ID:              "composite-unique-test-2",
		Token:           "composite-unique-token",
		InviteString:    "ocm://invite/test",
		SenderFQDN:      "remote.example",
		RecipientUserId: "alice",
		Status:          "pending",
		ReceivedAt:      time.Now().Unix(),
		UpdatedAt:       time.Now().Unix(),
	}
	if err := s.CreateIncomingInvite(ctx, second); err != store.ErrAlreadyExists {
		t.Fatalf("expected ErrAlreadyExists for duplicate (token, recipientUserId), got %v", err)
	}

	// Original must still be found by token lookup.
	got, err := s.GetIncomingInviteByToken(ctx, "composite-unique-token", "alice")
	if err != nil {
		t.Fatalf("GetIncomingInviteByToken after conflict: %v", err)
	}
	if got.ID != "composite-unique-test-1" {
		t.Errorf(
			"original invite overwritten: expected composite-unique-test-1, got %q",
			got.ID,
		)
	}

	// Same token, different recipient: must succeed.
	third := &store.IncomingInvite{
		ID:              "composite-unique-test-3",
		Token:           "composite-unique-token",
		InviteString:    "ocm://invite/test",
		SenderFQDN:      "remote.example",
		RecipientUserId: "bob",
		Status:          "pending",
		ReceivedAt:      time.Now().Unix(),
		UpdatedAt:       time.Now().Unix(),
	}
	if err := s.CreateIncomingInvite(ctx, third); err != nil {
		t.Fatalf("CreateIncomingInvite(third, different recipient): %v", err)
	}
	t.Cleanup(func() {
		if err := s.DeleteIncomingInviteForRecipient(ctx, third.ID, third.RecipientUserId); err != nil && err != store.ErrNotFound {
			t.Errorf("cleanup: DeleteIncomingInviteForRecipient third: %v", err)
		}
	})

	gotBob, err := s.GetIncomingInviteByToken(ctx, "composite-unique-token", "bob")
	if err != nil {
		t.Fatalf("GetIncomingInviteByToken for bob: %v", err)
	}
	if gotBob.ID != "composite-unique-test-3" {
		t.Errorf("expected composite-unique-test-3 for bob, got %q", gotBob.ID)
	}
}

// runOutgoingShareDuplicateSharedSecret verifies that a non-empty SharedSecret
// is unique across outgoing shares:
// - a duplicate non-empty secret on create returns ErrAlreadyExists
// - the original record is preserved by GetOutgoingShareBySharedSecret
// - attempting to steal the secret via update also returns ErrAlreadyExists
// - multiple shares with an empty secret are allowed (not subject to the constraint)
func runOutgoingShareDuplicateSharedSecret(
	t *testing.T,
	ctx context.Context,
	s store.OutgoingShareStore,
) {
	first := &store.OutgoingShare{
		ShareId:      "dup-secret-share-1",
		ProviderId:   "dup-secret-provider-1",
		WebDAVId:     "dup-secret-webdav-1",
		SharedSecret: "dup-shared-secret",
		LocalPath:    "/path/a",
		Owner:        "alice@example.com",
		Sender:       "alice@example.com",
		ShareWith:    "bob@remote.com",
		ReceiverHost: "remote.com",
		Name:         "file.txt",
		ResourceType: "file",
		Permissions:  "read",
		State:        "sent",
		CreatedAt:    time.Now().Unix(),
		UpdatedAt:    time.Now().Unix(),
	}
	if err := s.CreateOutgoingShare(ctx, first); err != nil {
		t.Fatalf("CreateOutgoingShare(first): %v", err)
	}
	t.Cleanup(func() {
		if err := s.DeleteOutgoingShare(ctx, first.ProviderId); err != nil && err != store.ErrNotFound {
			t.Errorf("cleanup: DeleteOutgoingShare first: %v", err)
		}
	})

	// Same SharedSecret, different ProviderId: must fail.
	second := &store.OutgoingShare{
		ShareId:      "dup-secret-share-2",
		ProviderId:   "dup-secret-provider-2",
		WebDAVId:     "dup-secret-webdav-2",
		SharedSecret: "dup-shared-secret",
		LocalPath:    "/path/b",
		Owner:        "alice@example.com",
		Sender:       "alice@example.com",
		ShareWith:    "bob@remote.com",
		ReceiverHost: "remote.com",
		Name:         "file.txt",
		ResourceType: "file",
		Permissions:  "read",
		State:        "sent",
		CreatedAt:    time.Now().Unix(),
		UpdatedAt:    time.Now().Unix(),
	}
	if err := s.CreateOutgoingShare(ctx, second); err != store.ErrAlreadyExists {
		t.Fatalf("expected ErrAlreadyExists for duplicate SharedSecret on create, got %v", err)
	}

	// Original must still be returned by GetOutgoingShareBySharedSecret.
	got, err := s.GetOutgoingShareBySharedSecret(ctx, "dup-shared-secret")
	if err != nil {
		t.Fatalf("GetOutgoingShareBySharedSecret after conflict: %v", err)
	}
	if got.ProviderId != "dup-secret-provider-1" {
		t.Errorf(
			"original share overwritten: expected dup-secret-provider-1, got %q",
			got.ProviderId,
		)
	}

	// A third share with a different secret may be created, then updated to steal the
	// existing secret - this must also fail.
	third := &store.OutgoingShare{
		ShareId:      "dup-secret-share-3",
		ProviderId:   "dup-secret-provider-3",
		WebDAVId:     "dup-secret-webdav-3",
		SharedSecret: "different-secret",
		LocalPath:    "/path/c",
		Owner:        "alice@example.com",
		Sender:       "alice@example.com",
		ShareWith:    "bob@remote.com",
		ReceiverHost: "remote.com",
		Name:         "file.txt",
		ResourceType: "file",
		Permissions:  "read",
		State:        "sent",
		CreatedAt:    time.Now().Unix(),
		UpdatedAt:    time.Now().Unix(),
	}
	if err := s.CreateOutgoingShare(ctx, third); err != nil {
		t.Fatalf("CreateOutgoingShare(third): %v", err)
	}
	t.Cleanup(func() {
		if err := s.DeleteOutgoingShare(ctx, third.ProviderId); err != nil && err != store.ErrNotFound {
			t.Errorf("cleanup: DeleteOutgoingShare third: %v", err)
		}
	})
	third.SharedSecret = "dup-shared-secret"
	if err := s.UpdateOutgoingShare(ctx, third); err != store.ErrAlreadyExists {
		t.Errorf("expected ErrAlreadyExists for conflicting SharedSecret on update, got %v", err)
	}

	// Multiple shares with an empty SharedSecret must be allowed.
	noSecret1 := &store.OutgoingShare{
		ShareId:      "no-secret-share-1",
		ProviderId:   "no-secret-provider-1",
		WebDAVId:     "no-secret-webdav-1",
		SharedSecret: "",
		LocalPath:    "/path/d",
		Owner:        "alice@example.com",
		Sender:       "alice@example.com",
		ShareWith:    "bob@remote.com",
		ReceiverHost: "remote.com",
		Name:         "file.txt",
		ResourceType: "file",
		Permissions:  "read",
		State:        "sent",
		CreatedAt:    time.Now().Unix(),
		UpdatedAt:    time.Now().Unix(),
	}
	noSecret2 := &store.OutgoingShare{
		ShareId:      "no-secret-share-2",
		ProviderId:   "no-secret-provider-2",
		WebDAVId:     "no-secret-webdav-2",
		SharedSecret: "",
		LocalPath:    "/path/e",
		Owner:        "alice@example.com",
		Sender:       "alice@example.com",
		ShareWith:    "bob@remote.com",
		ReceiverHost: "remote.com",
		Name:         "file.txt",
		ResourceType: "file",
		Permissions:  "read",
		State:        "sent",
		CreatedAt:    time.Now().Unix(),
		UpdatedAt:    time.Now().Unix(),
	}
	if err := s.CreateOutgoingShare(ctx, noSecret1); err != nil {
		t.Fatalf("CreateOutgoingShare(noSecret1): %v", err)
	}
	t.Cleanup(func() {
		if err := s.DeleteOutgoingShare(ctx, noSecret1.ProviderId); err != nil && err != store.ErrNotFound {
			t.Errorf("cleanup: DeleteOutgoingShare noSecret1: %v", err)
		}
	})
	if err := s.CreateOutgoingShare(ctx, noSecret2); err != nil {
		t.Fatalf("CreateOutgoingShare(noSecret2) with same empty secret: %v", err)
	}
	t.Cleanup(func() {
		if err := s.DeleteOutgoingShare(ctx, noSecret2.ProviderId); err != nil && err != store.ErrNotFound {
			t.Errorf("cleanup: DeleteOutgoingShare noSecret2: %v", err)
		}
	})
}

// runOutgoingShareEmptySharedSecretLookup verifies that empty shared secret is
// not a valid lookup key across all backends:
//   - GetOutgoingShareBySharedSecret("") must return ErrNotFound even when rows
//     with an empty shared secret exist (empty is an optional field allowed on
//     multiple rows, not a singular index key).
func runOutgoingShareEmptySharedSecretLookup(
	t *testing.T,
	ctx context.Context,
	s store.OutgoingShareStore,
) {
	row := &store.OutgoingShare{
		ShareId:      "empty-secret-lookup-share-1",
		ProviderId:   "empty-secret-lookup-provider-1",
		WebDAVId:     "empty-secret-lookup-webdav-1",
		SharedSecret: "",
		LocalPath:    "/path/empty-a",
		Owner:        "alice@example.com",
		Sender:       "alice@example.com",
		ShareWith:    "bob@remote.com",
		ReceiverHost: "remote.com",
		Name:         "file.txt",
		ResourceType: "file",
		Permissions:  "read",
		State:        "sent",
		CreatedAt:    time.Now().Unix(),
		UpdatedAt:    time.Now().Unix(),
	}
	if err := s.CreateOutgoingShare(ctx, row); err != nil {
		t.Fatalf("CreateOutgoingShare(empty-secret row): %v", err)
	}
	t.Cleanup(func() {
		if err := s.DeleteOutgoingShare(ctx, row.ProviderId); err != nil {
			t.Errorf("cleanup: DeleteOutgoingShare empty-secret row: %v", err)
		}
	})

	_, err := s.GetOutgoingShareBySharedSecret(ctx, "")
	if err != store.ErrNotFound {
		t.Errorf("GetOutgoingShareBySharedSecret(\"\") expected ErrNotFound, got %v", err)
	}
}

// runOutgoingShareUpdateNotFound verifies that UpdateOutgoingShare returns
// ErrNotFound when the target record does not exist.
func runOutgoingShareUpdateNotFound(t *testing.T, ctx context.Context, s store.OutgoingShareStore) {
	ghost := NewOutgoingShareFixture()
	ghost.ProviderId = "update-missing-out-share-provider"
	ghost.ShareId = "update-missing-out-share-id"
	ghost.WebDAVId = "update-missing-out-share-webdav"

	if err := s.UpdateOutgoingShare(ctx, ghost); err != store.ErrNotFound {
		t.Errorf("expected ErrNotFound for update of missing outgoing share, got %v", err)
	}
}

// runOutgoingInviteUpdateNotFound verifies that UpdateOutgoingInvite returns
// ErrNotFound when the target record does not exist.
func runOutgoingInviteUpdateNotFound(
	t *testing.T,
	ctx context.Context,
	s store.OutgoingInviteStore,
) {
	ghost := NewOutgoingInviteFixture()
	ghost.ID = "update-missing-out-invite-id"

	if err := s.UpdateOutgoingInvite(ctx, ghost); err != store.ErrNotFound {
		t.Errorf("expected ErrNotFound for update of missing outgoing invite, got %v", err)
	}
}

// runIncomingShareProviderKeyUniqueness verifies that (sendingServer, providerId)
// is enforced as a composite unique key across all backends:
// - a duplicate pair returns ErrAlreadyExists
// - the original record is still returned by GetIncomingShareByProviderKey
// - the same providerId with a different sendingServer still succeeds
func runIncomingShareProviderKeyUniqueness(
	t *testing.T,
	ctx context.Context,
	s store.IncomingShareStore,
) {
	first := &store.IncomingShare{
		ShareId:       "provider-key-unique-1",
		SendingServer: "provider-key-server.com",
		ProviderId:    "provider-key-unique-pid",
		Owner:         "alice@sender.com",
		Sender:        "alice@sender.com",
		ShareWith:     "bob@example.com",
		Name:          "shared.txt",
		ResourceType:  "file",
		Permissions:   "read",
		State:         "pending",
		UserId:        "bob",
		CreatedAt:     time.Now().Unix(),
		UpdatedAt:     time.Now().Unix(),
	}
	if err := s.CreateIncomingShare(ctx, first); err != nil {
		t.Fatalf("CreateIncomingShare(first): %v", err)
	}
	t.Cleanup(func() {
		if err := s.DeleteIncomingShareForRecipient(ctx, first.ShareId, first.UserId); err != nil && err != store.ErrNotFound {
			t.Errorf("cleanup: DeleteIncomingShareForRecipient first: %v", err)
		}
	})

	// Same (sendingServer, providerId), different shareId: must fail.
	second := &store.IncomingShare{
		ShareId:       "provider-key-unique-2",
		SendingServer: "provider-key-server.com",
		ProviderId:    "provider-key-unique-pid",
		Owner:         "alice@sender.com",
		Sender:        "alice@sender.com",
		ShareWith:     "bob@example.com",
		Name:          "shared.txt",
		ResourceType:  "file",
		Permissions:   "read",
		State:         "pending",
		UserId:        "bob",
		CreatedAt:     time.Now().Unix(),
		UpdatedAt:     time.Now().Unix(),
	}
	if err := s.CreateIncomingShare(ctx, second); err != store.ErrAlreadyExists {
		t.Fatalf("expected ErrAlreadyExists for duplicate (sendingServer, providerId), got %v", err)
	}

	// Original must still be found by provider key lookup.
	got, err := s.GetIncomingShareByProviderKey(ctx, "provider-key-server.com", "provider-key-unique-pid")
	if err != nil {
		t.Fatalf("GetIncomingShareByProviderKey after conflict: %v", err)
	}
	if got.ShareId != "provider-key-unique-1" {
		t.Errorf(
			"original share overwritten: expected provider-key-unique-1, got %q",
			got.ShareId,
		)
	}

	// Same providerId, different sendingServer: must succeed.
	third := &store.IncomingShare{
		ShareId:       "provider-key-unique-3",
		SendingServer: "other-server.com",
		ProviderId:    "provider-key-unique-pid",
		Owner:         "alice@sender.com",
		Sender:        "alice@sender.com",
		ShareWith:     "bob@example.com",
		Name:          "shared.txt",
		ResourceType:  "file",
		Permissions:   "read",
		State:         "pending",
		UserId:        "bob",
		CreatedAt:     time.Now().Unix(),
		UpdatedAt:     time.Now().Unix(),
	}
	if err := s.CreateIncomingShare(ctx, third); err != nil {
		t.Fatalf("CreateIncomingShare(third, different sendingServer): %v", err)
	}
	t.Cleanup(func() {
		if err := s.DeleteIncomingShareForRecipient(ctx, third.ShareId, third.UserId); err != nil && err != store.ErrNotFound {
			t.Errorf("cleanup: DeleteIncomingShareForRecipient third: %v", err)
		}
	})

	gotThird, err := s.GetIncomingShareByProviderKey(ctx, "other-server.com", "provider-key-unique-pid")
	if err != nil {
		t.Fatalf("GetIncomingShareByProviderKey for third: %v", err)
	}
	if gotThird.ShareId != "provider-key-unique-3" {
		t.Errorf("expected provider-key-unique-3, got %q", gotThird.ShareId)
	}
}
