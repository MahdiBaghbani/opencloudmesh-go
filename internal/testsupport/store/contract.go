package store

import (
	"context"
	"errors"
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
	preflight := createPreflightDriver(t, ctx, driverName, cfg)

	if preflight.Name() != driverName {
		t.Errorf("expected driver name %q, got %q", driverName, preflight.Name())
	}

	_, ok := preflight.(store.OutgoingShareStore)
	requireDriverImplements(t, driverName, preflight.Close, ok, "OutgoingShareStore")
	_, ok = preflight.(store.IncomingShareStore)
	requireDriverImplements(t, driverName, preflight.Close, ok, "IncomingShareStore")
	_, ok = preflight.(store.OutgoingInviteStore)
	requireDriverImplements(t, driverName, preflight.Close, ok, "OutgoingInviteStore")
	_, ok = preflight.(store.IncomingInviteStore)
	requireDriverImplements(t, driverName, preflight.Close, ok, "IncomingInviteStore")

	if err := preflight.Close(); err != nil {
		t.Fatalf("close preflight %s driver: %v", driverName, err)
	}

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
			if closeErr := d.Close(); closeErr != nil {
				t.Fatalf("failed to init %s sub-driver: %v (close: %v)", driverName, err, closeErr)
			}

			t.Fatalf("failed to init %s sub-driver: %v", driverName, err)
		}

		t.Cleanup(func() {
			if err := d.Close(); err != nil {
				t.Errorf("cleanup: close sub-driver: %v", err)
			}
		})

		return d
	}

	t.Run("OutgoingShareCRUD", func(t *testing.T) {
		d := newSubDriver(t)
		runOutgoingShareCRUD(t, ctx, requireOutgoingShareStore(t, d))
	})

	t.Run("OutgoingShareDuplicateSharedSecret", func(t *testing.T) {
		d := newSubDriver(t)
		runOutgoingShareDuplicateSharedSecret(t, ctx, requireOutgoingShareStore(t, d))
	})

	t.Run("OutgoingShareEmptySharedSecretLookup", func(t *testing.T) {
		d := newSubDriver(t)
		runOutgoingShareEmptySharedSecretLookup(t, ctx, requireOutgoingShareStore(t, d))
	})

	t.Run("OutgoingShareUpdateNotFound", func(t *testing.T) {
		d := newSubDriver(t)
		runOutgoingShareUpdateNotFound(t, ctx, requireOutgoingShareStore(t, d))
	})

	t.Run("IncomingShareCRUD", func(t *testing.T) {
		d := newSubDriver(t)
		runIncomingShareCRUD(t, ctx, requireIncomingShareStore(t, d))
	})

	t.Run("ProviderKeyScopedLookup", func(t *testing.T) {
		d := newSubDriver(t)
		runProviderKeyScopedLookup(t, ctx, requireIncomingShareStore(t, d))
	})

	t.Run("OutgoingInviteCRUD", func(t *testing.T) {
		d := newSubDriver(t)
		runOutgoingInviteCRUD(t, ctx, requireOutgoingInviteStore(t, d))
	})

	t.Run("OutgoingInviteUpdateNotFound", func(t *testing.T) {
		d := newSubDriver(t)
		runOutgoingInviteUpdateNotFound(t, ctx, requireOutgoingInviteStore(t, d))
	})

	t.Run("IncomingInviteStatusContract", func(t *testing.T) {
		d := newSubDriver(t)
		runIncomingInviteStatusContract(t, ctx, requireIncomingInviteStore(t, d))
	})

	t.Run("IncomingInviteCompositeUniqueness", func(t *testing.T) {
		d := newSubDriver(t)
		runIncomingInviteCompositeUniqueness(t, ctx, requireIncomingInviteStore(t, d))
	})

	t.Run("IncomingShareProviderKeyUniqueness", func(t *testing.T) {
		d := newSubDriver(t)
		runIncomingShareProviderKeyUniqueness(t, ctx, requireIncomingShareStore(t, d))
	})
}

func createPreflightDriver(t *testing.T, ctx context.Context, driverName string, cfg *store.DriverConfig) store.Driver {
	t.Helper()

	preflight, err := store.New(cfg)
	if err != nil {
		t.Fatalf("failed to create %s driver: %v", driverName, err)
	}

	if err := preflight.Init(ctx); err != nil {
		if closeErr := preflight.Close(); closeErr != nil {
			t.Fatalf("failed to init %s driver: %v (close: %v)", driverName, err, closeErr)
		}

		t.Fatalf("failed to init %s driver: %v", driverName, err)
	}

	return preflight
}

func requireDriverImplements(
	t *testing.T,
	driverName string,
	closeFn func() error,
	ok bool,
	name string,
) {
	t.Helper()

	if !ok {
		if closeErr := closeFn(); closeErr != nil {
			t.Fatalf("%s driver does not implement %s (close: %v)", driverName, name, closeErr)
		}

		t.Fatalf("%s driver does not implement %s", driverName, name)
	}
}

// cloneConfig returns a shallow copy of cfg with DataDir replaced by dir.
func cloneConfig(cfg *store.DriverConfig, dir string) *store.DriverConfig {
	c := *cfg
	c.DataDir = dir

	return &c
}

func requireOutgoingShareStore(t *testing.T, d store.Driver) store.OutgoingShareStore {
	t.Helper()

	s, ok := d.(store.OutgoingShareStore)
	if !ok {
		t.Fatal("driver does not implement OutgoingShareStore")
	}

	return s
}

func requireIncomingShareStore(t *testing.T, d store.Driver) store.IncomingShareStore {
	t.Helper()

	s, ok := d.(store.IncomingShareStore)
	if !ok {
		t.Fatal("driver does not implement IncomingShareStore")
	}

	return s
}

func requireOutgoingInviteStore(t *testing.T, d store.Driver) store.OutgoingInviteStore {
	t.Helper()

	s, ok := d.(store.OutgoingInviteStore)
	if !ok {
		t.Fatal("driver does not implement OutgoingInviteStore")
	}

	return s
}

func requireIncomingInviteStore(t *testing.T, d store.Driver) store.IncomingInviteStore {
	t.Helper()

	s, ok := d.(store.IncomingInviteStore)
	if !ok {
		t.Fatal("driver does not implement IncomingInviteStore")
	}

	return s
}

func runOutgoingShareCRUD(t *testing.T, ctx context.Context, s store.OutgoingShareStore) {
	share := NewOutgoingShareFixture()

	createOutgoingShare(t, ctx, s, share)
	requireOutgoingShareByIDEquals(t, ctx, s, share)
	requireOutgoingShareByProviderIDEquals(t, ctx, s, share)
	requireOutgoingShareByWebDAVIDEquals(t, ctx, s, share)
	requireOutgoingShareBySharedSecretEquals(t, ctx, s, share)
	updateOutgoingShareStatus(t, ctx, s, share, "accepted")
	requireOutgoingShareStatusEquals(t, ctx, s, share.ProviderID, "accepted")
	requireOutgoingShareListNonEmpty(t, ctx, s)
	deleteOutgoingShare(t, ctx, s, share.ProviderID)
	requireOutgoingShareNotFound(t, ctx, s, share.ProviderID)
}

func createOutgoingShare(t *testing.T, ctx context.Context, s store.OutgoingShareStore, share *store.OutgoingShare) {
	t.Helper()

	if err := s.CreateOutgoingShare(ctx, share); err != nil {
		t.Fatalf("CreateOutgoingShare failed: %v", err)
	}

	t.Cleanup(func() {
		if err := s.DeleteOutgoingShare(ctx, share.ProviderID); err != nil && !errors.Is(err, store.ErrNotFound) {
			t.Errorf("cleanup: DeleteOutgoingShare: %v", err)
		}
	})
}

func requireOutgoingShareByIDEquals(t *testing.T, ctx context.Context, s store.OutgoingShareStore, want *store.OutgoingShare) {
	t.Helper()

	got, err := s.GetOutgoingShareByID(ctx, want.ShareID)
	if err != nil {
		t.Fatalf("GetOutgoingShareByID failed: %v", err)
	}

	if got.ShareID != want.ShareID {
		t.Errorf("expected shareID %q, got %q", want.ShareID, got.ShareID)
	}
}

func requireOutgoingShareByProviderIDEquals(t *testing.T, ctx context.Context, s store.OutgoingShareStore, want *store.OutgoingShare) {
	t.Helper()

	got, err := s.GetOutgoingShare(ctx, want.ProviderID)
	if err != nil {
		t.Fatalf("GetOutgoingShare failed: %v", err)
	}

	if got.ProviderID != want.ProviderID {
		t.Errorf("expected providerID %q, got %q", want.ProviderID, got.ProviderID)
	}
}

func requireOutgoingShareByWebDAVIDEquals(t *testing.T, ctx context.Context, s store.OutgoingShareStore, want *store.OutgoingShare) {
	t.Helper()

	got, err := s.GetOutgoingShareByWebDAVID(ctx, want.WebDAVID)
	if err != nil {
		t.Fatalf("GetOutgoingShareByWebDAVID failed: %v", err)
	}

	if got.WebDAVID != want.WebDAVID {
		t.Errorf("expected webdavID %q, got %q", want.WebDAVID, got.WebDAVID)
	}
}

func requireOutgoingShareBySharedSecretEquals(t *testing.T, ctx context.Context, s store.OutgoingShareStore, want *store.OutgoingShare) {
	t.Helper()

	got, err := s.GetOutgoingShareBySharedSecret(ctx, want.SharedSecret)
	if err != nil {
		t.Fatalf("GetOutgoingShareBySharedSecret failed: %v", err)
	}

	if got.SharedSecret != want.SharedSecret {
		t.Errorf("expected sharedSecret %q, got %q", want.SharedSecret, got.SharedSecret)
	}
}

func updateOutgoingShareStatus(t *testing.T, ctx context.Context, s store.OutgoingShareStore, share *store.OutgoingShare, status string) {
	t.Helper()

	share.Status = status
	if err := s.UpdateOutgoingShare(ctx, share); err != nil {
		t.Fatalf("UpdateOutgoingShare failed: %v", err)
	}
}

func requireOutgoingShareStatusEquals(t *testing.T, ctx context.Context, s store.OutgoingShareStore, providerID, want string) {
	t.Helper()

	got, err := s.GetOutgoingShare(ctx, providerID)
	if err != nil {
		t.Fatalf("GetOutgoingShare after update failed: %v", err)
	}

	if got.Status != want {
		t.Errorf("expected status %q, got %q", want, got.Status)
	}
}

func requireOutgoingShareListNonEmpty(t *testing.T, ctx context.Context, s store.OutgoingShareStore) {
	t.Helper()

	shares, err := s.ListOutgoingShares(ctx)
	if err != nil {
		t.Fatalf("ListOutgoingShares failed: %v", err)
	}

	if len(shares) == 0 {
		t.Error("expected at least one share in list")
	}
}

func deleteOutgoingShare(t *testing.T, ctx context.Context, s store.OutgoingShareStore, providerID string) {
	t.Helper()

	if err := s.DeleteOutgoingShare(ctx, providerID); err != nil {
		t.Fatalf("DeleteOutgoingShare failed: %v", err)
	}
}

func requireOutgoingShareNotFound(t *testing.T, ctx context.Context, s store.OutgoingShareStore, providerID string) {
	t.Helper()

	_, err := s.GetOutgoingShare(ctx, providerID)
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("expected ErrNotFound after delete, got %v", err)
	}
}

func runIncomingShareCRUD(t *testing.T, ctx context.Context, s store.IncomingShareStore) {
	share := NewIncomingShareFixture()
	share.UpdatedAt = time.Now().Add(-2 * time.Second).Unix()

	createIncomingShare(t, ctx, s, share)
	requireIncomingShareByIDForRecipient(t, ctx, s, share)
	requireIncomingShareNotFoundForRecipient(t, ctx, s, share.ShareID, "other-user")
	requireIncomingShareByProviderKey(t, ctx, s, share)
	updateIncomingShareStatusAndAssert(t, ctx, s, share, "accepted")
	requireIncomingShareStatusUpdateNotFoundForRecipient(t, ctx, s, share.ShareID, "other-user", "accepted")
	requireIncomingShareListByRecipientNonEmpty(t, ctx, s, share.RecipientUserID)
	deleteIncomingShareForRecipient(t, ctx, s, share.ShareID, share.RecipientUserID)
	requireIncomingShareNotFoundForRecipient(t, ctx, s, share.ShareID, share.RecipientUserID)
}

func createIncomingShare(t *testing.T, ctx context.Context, s store.IncomingShareStore, share *store.IncomingShare) {
	t.Helper()

	if err := s.CreateIncomingShare(ctx, share); err != nil {
		t.Fatalf("CreateIncomingShare failed: %v", err)
	}

	t.Cleanup(func() {
		if err := s.DeleteIncomingShareForRecipient(ctx, share.ShareID, share.RecipientUserID); err != nil && !errors.Is(err, store.ErrNotFound) {
			t.Errorf("cleanup: DeleteIncomingShareForRecipient: %v", err)
		}
	})
}

func requireIncomingShareByIDForRecipient(t *testing.T, ctx context.Context, s store.IncomingShareStore, want *store.IncomingShare) {
	t.Helper()

	got, err := s.GetIncomingShareByIDForRecipient(ctx, want.ShareID, want.RecipientUserID)
	if err != nil {
		t.Fatalf("GetIncomingShareByIDForRecipient failed: %v", err)
	}

	if got.ShareID != want.ShareID {
		t.Errorf("expected shareID %q, got %q", want.ShareID, got.ShareID)
	}
}

func requireIncomingShareNotFoundForRecipient(t *testing.T, ctx context.Context, s store.IncomingShareStore, shareID, userID string) {
	t.Helper()

	_, err := s.GetIncomingShareByIDForRecipient(ctx, shareID, userID)
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("expected ErrNotFound for wrong recipient, got %v", err)
	}
}

func requireIncomingShareByProviderKey(t *testing.T, ctx context.Context, s store.IncomingShareStore, want *store.IncomingShare) {
	t.Helper()

	got, err := s.GetIncomingShareByProviderKey(ctx, want.SenderHost, want.ProviderID)
	if err != nil {
		t.Fatalf("GetIncomingShareByProviderKey failed: %v", err)
	}

	if got.ShareID != want.ShareID {
		t.Errorf("expected shareID %q, got %q", want.ShareID, got.ShareID)
	}
}

func updateIncomingShareStatusAndAssert(t *testing.T, ctx context.Context, s store.IncomingShareStore, share *store.IncomingShare, status string) {
	t.Helper()

	priorUpdatedAt := share.UpdatedAt
	if err := s.UpdateIncomingShareStatusForRecipient(ctx, share.ShareID, share.RecipientUserID, status); err != nil {
		t.Fatalf("UpdateIncomingShareStatusForRecipient failed: %v", err)
	}

	updated, err := s.GetIncomingShareByIDForRecipient(ctx, share.ShareID, share.RecipientUserID)
	if err != nil {
		t.Fatalf("GetIncomingShareByIDForRecipient after status update failed: %v", err)
	}

	if updated.Status != status {
		t.Errorf("expected status %q after status update, got %q", status, updated.Status)
	}

	if updated.UpdatedAt <= priorUpdatedAt {
		t.Errorf(
			"UpdatedAt not increased after status update: got %d, want > %d",
			updated.UpdatedAt,
			priorUpdatedAt,
		)
	}
}

func requireIncomingShareStatusUpdateNotFoundForRecipient(
	t *testing.T,
	ctx context.Context,
	s store.IncomingShareStore,
	shareID,
	userID,
	state string,
) {
	t.Helper()

	err := s.UpdateIncomingShareStatusForRecipient(ctx, shareID, userID, state)
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("expected ErrNotFound for wrong recipient on update, got %v", err)
	}
}

func requireIncomingShareListByRecipientNonEmpty(t *testing.T, ctx context.Context, s store.IncomingShareStore, userID string) {
	t.Helper()

	shares, err := s.ListIncomingSharesByRecipient(ctx, userID)
	if err != nil {
		t.Fatalf("ListIncomingSharesByRecipient failed: %v", err)
	}

	if len(shares) == 0 {
		t.Error("expected at least one share in list")
	}
}

func deleteIncomingShareForRecipient(t *testing.T, ctx context.Context, s store.IncomingShareStore, shareID, userID string) {
	t.Helper()

	if err := s.DeleteIncomingShareForRecipient(ctx, shareID, userID); err != nil {
		t.Fatalf("DeleteIncomingShareForRecipient failed: %v", err)
	}
}

// runProviderKeyScopedLookup verifies sender-scoped provider key lookup.
func runProviderKeyScopedLookup(t *testing.T, ctx context.Context, s store.IncomingShareStore) {
	// Create two shares with same providerID but different senders
	share1 := NewIncomingShareFixture()
	share1.ShareID = "share-1"
	share1.SenderHost = "server1.com"
	share1.ProviderID = "same-provider-id"

	share2 := NewIncomingShareFixture()
	share2.ShareID = "share-2"
	share2.SenderHost = "server2.com"
	share2.ProviderID = "same-provider-id"

	if err := s.CreateIncomingShare(ctx, share1); err != nil {
		t.Fatalf("CreateIncomingShare share1 failed: %v", err)
	}

	t.Cleanup(func() {
		if err := s.DeleteIncomingShareForRecipient(ctx, share1.ShareID, share1.RecipientUserID); err != nil && !errors.Is(err, store.ErrNotFound) {
			t.Errorf("cleanup: DeleteIncomingShareForRecipient share1: %v", err)
		}
	})

	if err := s.CreateIncomingShare(ctx, share2); err != nil {
		t.Fatalf("CreateIncomingShare share2 failed: %v", err)
	}

	t.Cleanup(func() {
		if err := s.DeleteIncomingShareForRecipient(ctx, share2.ShareID, share2.RecipientUserID); err != nil && !errors.Is(err, store.ErrNotFound) {
			t.Errorf("cleanup: DeleteIncomingShareForRecipient share2: %v", err)
		}
	})

	// Lookup by server1 should return share1
	got, err := s.GetIncomingShareByProviderKey(ctx, "server1.com", "same-provider-id")
	if err != nil {
		t.Fatalf("GetIncomingShareByProviderKey server1 failed: %v", err)
	}

	if got.ShareID != "share-1" {
		t.Errorf("expected share-1, got %q", got.ShareID)
	}

	// Lookup by server2 should return share2
	got, err = s.GetIncomingShareByProviderKey(ctx, "server2.com", "same-provider-id")
	if err != nil {
		t.Fatalf("GetIncomingShareByProviderKey server2 failed: %v", err)
	}

	if got.ShareID != "share-2" {
		t.Errorf("expected share-2, got %q", got.ShareID)
	}
}

func runOutgoingInviteCRUD(t *testing.T, ctx context.Context, s store.OutgoingInviteStore) {
	invite := NewOutgoingInviteFixture()

	createOutgoingInvite(t, ctx, s, invite)
	requireDuplicateCreateOutgoingInviteFails(t, ctx, s, invite)
	requireOutgoingInviteByID(t, ctx, s, invite)
	requireOutgoingInviteByToken(t, ctx, s, invite)
	oldToken := updateOutgoingInviteTokenAndStatus(t, ctx, s, invite, "new-invite-token", "accepted")
	requireOutgoingInviteByTokenNotFound(t, ctx, s, oldToken)
	requireOutgoingInviteByTokenHasStatus(t, ctx, s, invite.Token, "accepted")
	requireOutgoingInviteListByUserNonEmpty(t, ctx, s, invite.CreatedByUserID)
	deleteOutgoingInvite(t, ctx, s, invite.ID)
	requireOutgoingInviteNotFound(t, ctx, s, invite.ID)
}

func createOutgoingInvite(t *testing.T, ctx context.Context, s store.OutgoingInviteStore, invite *store.OutgoingInvite) {
	t.Helper()

	if err := s.CreateOutgoingInvite(ctx, invite); err != nil {
		t.Fatalf("CreateOutgoingInvite failed: %v", err)
	}

	t.Cleanup(func() {
		if err := s.DeleteOutgoingInvite(ctx, invite.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
			t.Errorf("cleanup: DeleteOutgoingInvite: %v", err)
		}
	})
}

func requireDuplicateCreateOutgoingInviteFails(t *testing.T, ctx context.Context, s store.OutgoingInviteStore, invite *store.OutgoingInvite) {
	t.Helper()

	if err := s.CreateOutgoingInvite(ctx, invite); !errors.Is(err, store.ErrAlreadyExists) {
		t.Errorf("expected ErrAlreadyExists on duplicate create, got %v", err)
	}
}

func requireOutgoingInviteByID(t *testing.T, ctx context.Context, s store.OutgoingInviteStore, invite *store.OutgoingInvite) {
	t.Helper()

	got, err := s.GetOutgoingInvite(ctx, invite.ID)
	if err != nil {
		t.Fatalf("GetOutgoingInvite failed: %v", err)
	}

	if got.Token != invite.Token {
		t.Errorf("expected token %q, got %q", invite.Token, got.Token)
	}
}

func requireOutgoingInviteByToken(t *testing.T, ctx context.Context, s store.OutgoingInviteStore, invite *store.OutgoingInvite) {
	t.Helper()

	got, err := s.GetOutgoingInviteByToken(ctx, invite.Token)
	if err != nil {
		t.Fatalf("GetOutgoingInviteByToken failed: %v", err)
	}

	if got.ID != invite.ID {
		t.Errorf("expected id %q, got %q", invite.ID, got.ID)
	}
}

func updateOutgoingInviteTokenAndStatus(
	t *testing.T,
	ctx context.Context,
	s store.OutgoingInviteStore,
	invite *store.OutgoingInvite,
	newToken,
	newStatus string,
) string {
	t.Helper()

	oldToken := invite.Token
	invite.Token = newToken
	invite.Status = newStatus

	if err := s.UpdateOutgoingInvite(ctx, invite); err != nil {
		t.Fatalf("UpdateOutgoingInvite failed: %v", err)
	}

	return oldToken
}

func requireOutgoingInviteByTokenNotFound(t *testing.T, ctx context.Context, s store.OutgoingInviteStore, token string) {
	t.Helper()

	_, err := s.GetOutgoingInviteByToken(ctx, token)
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("expected ErrNotFound for stale token after update, got %v", err)
	}
}

func requireOutgoingInviteByTokenHasStatus(t *testing.T, ctx context.Context, s store.OutgoingInviteStore, token, want string) {
	t.Helper()

	got, err := s.GetOutgoingInviteByToken(ctx, token)
	if err != nil {
		t.Fatalf("GetOutgoingInviteByToken for new token failed: %v", err)
	}

	if got.Status != want {
		t.Errorf("expected status %q, got %q", want, got.Status)
	}
}

func requireOutgoingInviteListByUserNonEmpty(t *testing.T, ctx context.Context, s store.OutgoingInviteStore, userID string) {
	t.Helper()

	invites, err := s.ListOutgoingInvites(ctx, userID)
	if err != nil {
		t.Fatalf("ListOutgoingInvites failed: %v", err)
	}

	if len(invites) == 0 {
		t.Error("expected at least one invite in list")
	}
}

func deleteOutgoingInvite(t *testing.T, ctx context.Context, s store.OutgoingInviteStore, id string) {
	t.Helper()

	if err := s.DeleteOutgoingInvite(ctx, id); err != nil {
		t.Fatalf("DeleteOutgoingInvite failed: %v", err)
	}
}

func requireOutgoingInviteNotFound(t *testing.T, ctx context.Context, s store.OutgoingInviteStore, id string) {
	t.Helper()

	_, err := s.GetOutgoingInvite(ctx, id)
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("expected ErrNotFound after delete, got %v", err)
	}
}

// runIncomingInviteStatusContract verifies that incoming-invite updates are
// status-only: cross-user access is rejected and scope-defining fields (Token,
// RecipientUserID) are unchanged after a status update.
func runIncomingInviteStatusContract(t *testing.T, ctx context.Context, s store.IncomingInviteStore) {
	invite := NewIncomingInviteFixture()

	createIncomingInvite(t, ctx, s, invite)
	requireIncomingInviteForRecipient(t, ctx, s, invite)
	requireIncomingInviteNotFoundForRecipient(t, ctx, s, invite.ID, "other-user")
	requireIncomingInviteByTokenForRecipient(t, ctx, s, invite)
	requireIncomingInviteByTokenNotFoundForRecipient(t, ctx, s, invite.Token, "other-user")
	updateIncomingInviteStatusAndAssert(t, ctx, s, invite, "accepted")
	requireIncomingInviteStatusUpdateNotFoundForRecipient(t, ctx, s, invite.ID, "other-user", "declined")
	requireIncomingInviteByTokenHasStatus(t, ctx, s, invite.Token, invite.RecipientUserID, "accepted")
	requireIncomingInviteListByRecipientNonEmpty(t, ctx, s, invite.RecipientUserID)
	requireIncomingInviteDeleteNotFoundForRecipient(t, ctx, s, invite.ID, "other-user")
	deleteIncomingInviteForRecipient(t, ctx, s, invite.ID, invite.RecipientUserID)
	requireIncomingInviteNotFoundForRecipient(t, ctx, s, invite.ID, invite.RecipientUserID)
}

func createIncomingInvite(t *testing.T, ctx context.Context, s store.IncomingInviteStore, invite *store.IncomingInvite) {
	t.Helper()

	if err := s.CreateIncomingInvite(ctx, invite); err != nil {
		t.Fatalf("CreateIncomingInvite failed: %v", err)
	}

	t.Cleanup(func() {
		if err := s.DeleteIncomingInviteForRecipient(ctx, invite.ID, invite.RecipientUserID); err != nil && !errors.Is(err, store.ErrNotFound) {
			t.Errorf("cleanup: DeleteIncomingInviteForRecipient: %v", err)
		}
	})
}

func requireIncomingInviteForRecipient(t *testing.T, ctx context.Context, s store.IncomingInviteStore, invite *store.IncomingInvite) {
	t.Helper()

	got, err := s.GetIncomingInviteForRecipient(ctx, invite.ID, invite.RecipientUserID)
	if err != nil {
		t.Fatalf("GetIncomingInviteForRecipient failed: %v", err)
	}

	if got.Token != invite.Token {
		t.Errorf("expected token %q, got %q", invite.Token, got.Token)
	}
}

func requireIncomingInviteNotFoundForRecipient(t *testing.T, ctx context.Context, s store.IncomingInviteStore, id, userID string) {
	t.Helper()

	_, err := s.GetIncomingInviteForRecipient(ctx, id, userID)
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("expected ErrNotFound for cross-user get, got %v", err)
	}
}

func requireIncomingInviteByTokenForRecipient(t *testing.T, ctx context.Context, s store.IncomingInviteStore, invite *store.IncomingInvite) {
	t.Helper()

	got, err := s.GetIncomingInviteByToken(ctx, invite.Token, invite.RecipientUserID)
	if err != nil {
		t.Fatalf("GetIncomingInviteByToken failed: %v", err)
	}

	if got.ID != invite.ID {
		t.Errorf("expected id %q, got %q", invite.ID, got.ID)
	}
}

func requireIncomingInviteByTokenNotFoundForRecipient(t *testing.T, ctx context.Context, s store.IncomingInviteStore, token, userID string) {
	t.Helper()

	_, err := s.GetIncomingInviteByToken(ctx, token, userID)
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("expected ErrNotFound for cross-user token lookup, got %v", err)
	}
}

func updateIncomingInviteStatusAndAssert(t *testing.T, ctx context.Context, s store.IncomingInviteStore, invite *store.IncomingInvite, state string) {
	t.Helper()

	beforeUpdate := time.Now().Unix()

	if err := s.UpdateIncomingInviteStatusForRecipient(ctx, invite.ID, invite.RecipientUserID, state, "ct-sender-user-1", "ct-sender.example.com"); err != nil {
		t.Fatalf("UpdateIncomingInviteStatusForRecipient failed: %v", err)
	}

	got, err := s.GetIncomingInviteForRecipient(ctx, invite.ID, invite.RecipientUserID)
	if err != nil {
		t.Fatalf("GetIncomingInviteForRecipient after update failed: %v", err)
	}

	if got.Status != state {
		t.Errorf("expected status %q after update, got %q", state, got.Status)
	}

	if got.Token != invite.Token {
		t.Errorf("token must not change on status update: expected %q, got %q", invite.Token, got.Token)
	}

	if got.RecipientUserID != invite.RecipientUserID {
		t.Errorf(
			"recipient must not change on status update: expected %q, got %q",
			invite.RecipientUserID,
			got.RecipientUserID,
		)
	}

	if got.SenderUserID != "ct-sender-user-1" {
		t.Errorf("expected sender user id persisted on status update, got %q", got.SenderUserID)
	}

	if got.SenderFQDNNormalized != "ct-sender.example.com" {
		t.Errorf("expected normalized sender fqdn persisted on status update, got %q", got.SenderFQDNNormalized)
	}

	if got.UpdatedAt < beforeUpdate {
		t.Errorf(
			"UpdatedAt not refreshed after status update: got %d, expected >= %d",
			got.UpdatedAt,
			beforeUpdate,
		)
	}
}

func requireIncomingInviteStatusUpdateNotFoundForRecipient(
	t *testing.T,
	ctx context.Context,
	s store.IncomingInviteStore,
	id,
	userID,
	state string,
) {
	t.Helper()

	err := s.UpdateIncomingInviteStatusForRecipient(ctx, id, userID, state, "", "")
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("expected ErrNotFound for cross-user status update, got %v", err)
	}
}

func requireIncomingInviteByTokenHasStatus(t *testing.T, ctx context.Context, s store.IncomingInviteStore, token, userID, want string) {
	t.Helper()

	got, err := s.GetIncomingInviteByToken(ctx, token, userID)
	if err != nil {
		t.Fatalf("GetIncomingInviteByToken must still work after status update: %v", err)
	}

	if got.Status != want {
		t.Errorf("expected updated status via token lookup, got %q", got.Status)
	}
}

func requireIncomingInviteListByRecipientNonEmpty(t *testing.T, ctx context.Context, s store.IncomingInviteStore, userID string) {
	t.Helper()

	invites, err := s.ListIncomingInvites(ctx, userID)
	if err != nil {
		t.Fatalf("ListIncomingInvites failed: %v", err)
	}

	if len(invites) == 0 {
		t.Error("expected at least one invite in list")
	}
}

func requireIncomingInviteDeleteNotFoundForRecipient(t *testing.T, ctx context.Context, s store.IncomingInviteStore, id, userID string) {
	t.Helper()

	err := s.DeleteIncomingInviteForRecipient(ctx, id, userID)
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("expected ErrNotFound for cross-user delete, got %v", err)
	}
}

func deleteIncomingInviteForRecipient(t *testing.T, ctx context.Context, s store.IncomingInviteStore, id, userID string) {
	t.Helper()

	if err := s.DeleteIncomingInviteForRecipient(ctx, id, userID); err != nil {
		t.Fatalf("DeleteIncomingInviteForRecipient failed: %v", err)
	}
}

// runIncomingInviteCompositeUniqueness verifies that (token, recipientUserID)
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
		RecipientUserID: "alice",
		Status:          "pending",
		ReceivedAt:      time.Now().Unix(),
		UpdatedAt:       time.Now().Unix(),
	}
	if err := s.CreateIncomingInvite(ctx, first); err != nil {
		t.Fatalf("CreateIncomingInvite(first): %v", err)
	}

	t.Cleanup(func() {
		if err := s.DeleteIncomingInviteForRecipient(ctx, first.ID, first.RecipientUserID); err != nil && !errors.Is(err, store.ErrNotFound) {
			t.Errorf("cleanup: DeleteIncomingInviteForRecipient first: %v", err)
		}
	})

	// Same (token, recipientUserID), different ID: must fail.
	second := &store.IncomingInvite{
		ID:              "composite-unique-test-2",
		Token:           "composite-unique-token",
		InviteString:    "ocm://invite/test",
		SenderFQDN:      "remote.example",
		RecipientUserID: "alice",
		Status:          "pending",
		ReceivedAt:      time.Now().Unix(),
		UpdatedAt:       time.Now().Unix(),
	}
	if err := s.CreateIncomingInvite(ctx, second); !errors.Is(err, store.ErrAlreadyExists) {
		t.Fatalf("expected ErrAlreadyExists for duplicate (token, recipientUserID), got %v", err)
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
		RecipientUserID: "bob",
		Status:          "pending",
		ReceivedAt:      time.Now().Unix(),
		UpdatedAt:       time.Now().Unix(),
	}
	if createErr := s.CreateIncomingInvite(ctx, third); createErr != nil {
		t.Fatalf("CreateIncomingInvite(third, different recipient): %v", createErr)
	}

	t.Cleanup(func() {
		if deleteErr := s.DeleteIncomingInviteForRecipient(ctx, third.ID, third.RecipientUserID); deleteErr != nil && !errors.Is(deleteErr, store.ErrNotFound) {
			t.Errorf("cleanup: DeleteIncomingInviteForRecipient third: %v", deleteErr)
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
		ShareID:      "dup-secret-share-1",
		ProviderID:   "dup-secret-provider-1",
		WebDAVID:     "dup-secret-webdav-1",
		SharedSecret: "dup-shared-secret",
		LocalPath:    "/path/a",
		Owner:        "alice@example.com",
		Sender:       "alice@example.com",
		ShareWith:    "bob@remote.com",
		ReceiverHost: "remote.com",
		Name:         "file.txt",
		ResourceType: "file",
		Permissions:  "read",
		Status:       "sent",
		CreatedAt:    time.Now().Unix(),
		UpdatedAt:    time.Now().Unix(),
	}
	createOutgoingShare(t, ctx, s, first)

	second := &store.OutgoingShare{
		ShareID:      "dup-secret-share-2",
		ProviderID:   "dup-secret-provider-2",
		WebDAVID:     "dup-secret-webdav-2",
		SharedSecret: "dup-shared-secret",
		LocalPath:    "/path/b",
		Owner:        "alice@example.com",
		Sender:       "alice@example.com",
		ShareWith:    "bob@remote.com",
		ReceiverHost: "remote.com",
		Name:         "file.txt",
		ResourceType: "file",
		Permissions:  "read",
		Status:       "sent",
		CreatedAt:    time.Now().Unix(),
		UpdatedAt:    time.Now().Unix(),
	}
	requireDuplicateSharedSecretCreateFails(t, ctx, s, second)
	requireOutgoingShareBySharedSecretProviderID(t, ctx, s, "dup-shared-secret", "dup-secret-provider-1")

	third := &store.OutgoingShare{
		ShareID:      "dup-secret-share-3",
		ProviderID:   "dup-secret-provider-3",
		WebDAVID:     "dup-secret-webdav-3",
		SharedSecret: "different-secret",
		LocalPath:    "/path/c",
		Owner:        "alice@example.com",
		Sender:       "alice@example.com",
		ShareWith:    "bob@remote.com",
		ReceiverHost: "remote.com",
		Name:         "file.txt",
		ResourceType: "file",
		Permissions:  "read",
		Status:       "sent",
		CreatedAt:    time.Now().Unix(),
		UpdatedAt:    time.Now().Unix(),
	}
	createOutgoingShare(t, ctx, s, third)
	requireUpdateSharedSecretFails(t, ctx, s, third, "dup-shared-secret")

	noSecret1 := &store.OutgoingShare{
		ShareID:      "no-secret-share-1",
		ProviderID:   "no-secret-provider-1",
		WebDAVID:     "no-secret-webdav-1",
		SharedSecret: "",
		LocalPath:    "/path/d",
		Owner:        "alice@example.com",
		Sender:       "alice@example.com",
		ShareWith:    "bob@remote.com",
		ReceiverHost: "remote.com",
		Name:         "file.txt",
		ResourceType: "file",
		Permissions:  "read",
		Status:       "sent",
		CreatedAt:    time.Now().Unix(),
		UpdatedAt:    time.Now().Unix(),
	}
	noSecret2 := &store.OutgoingShare{
		ShareID:      "no-secret-share-2",
		ProviderID:   "no-secret-provider-2",
		WebDAVID:     "no-secret-webdav-2",
		SharedSecret: "",
		LocalPath:    "/path/e",
		Owner:        "alice@example.com",
		Sender:       "alice@example.com",
		ShareWith:    "bob@remote.com",
		ReceiverHost: "remote.com",
		Name:         "file.txt",
		ResourceType: "file",
		Permissions:  "read",
		Status:       "sent",
		CreatedAt:    time.Now().Unix(),
		UpdatedAt:    time.Now().Unix(),
	}

	createOutgoingShare(t, ctx, s, noSecret1)
	createOutgoingShare(t, ctx, s, noSecret2)
}

func requireDuplicateSharedSecretCreateFails(t *testing.T, ctx context.Context, s store.OutgoingShareStore, share *store.OutgoingShare) {
	t.Helper()

	if err := s.CreateOutgoingShare(ctx, share); !errors.Is(err, store.ErrAlreadyExists) {
		t.Fatalf("expected ErrAlreadyExists for duplicate SharedSecret on create, got %v", err)
	}
}

func requireOutgoingShareBySharedSecretProviderID(t *testing.T, ctx context.Context, s store.OutgoingShareStore, secret, want string) {
	t.Helper()

	got, err := s.GetOutgoingShareBySharedSecret(ctx, secret)
	if err != nil {
		t.Fatalf("GetOutgoingShareBySharedSecret after conflict: %v", err)
	}

	if got.ProviderID != want {
		t.Errorf("original share overwritten: expected %q, got %q", want, got.ProviderID)
	}
}

func requireUpdateSharedSecretFails(t *testing.T, ctx context.Context, s store.OutgoingShareStore, share *store.OutgoingShare, targetSecret string) {
	t.Helper()

	share.SharedSecret = targetSecret
	if err := s.UpdateOutgoingShare(ctx, share); !errors.Is(err, store.ErrAlreadyExists) {
		t.Errorf("expected ErrAlreadyExists for conflicting SharedSecret on update, got %v", err)
	}
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
		ShareID:      "empty-secret-lookup-share-1",
		ProviderID:   "empty-secret-lookup-provider-1",
		WebDAVID:     "empty-secret-lookup-webdav-1",
		SharedSecret: "",
		LocalPath:    "/path/empty-a",
		Owner:        "alice@example.com",
		Sender:       "alice@example.com",
		ShareWith:    "bob@remote.com",
		ReceiverHost: "remote.com",
		Name:         "file.txt",
		ResourceType: "file",
		Permissions:  "read",
		Status:       "sent",
		CreatedAt:    time.Now().Unix(),
		UpdatedAt:    time.Now().Unix(),
	}
	if err := s.CreateOutgoingShare(ctx, row); err != nil {
		t.Fatalf("CreateOutgoingShare(empty-secret row): %v", err)
	}

	t.Cleanup(func() {
		if err := s.DeleteOutgoingShare(ctx, row.ProviderID); err != nil {
			t.Errorf("cleanup: DeleteOutgoingShare empty-secret row: %v", err)
		}
	})

	_, err := s.GetOutgoingShareBySharedSecret(ctx, "")
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("GetOutgoingShareBySharedSecret(\"\") expected ErrNotFound, got %v", err)
	}
}

// runOutgoingShareUpdateNotFound verifies that UpdateOutgoingShare returns
// ErrNotFound when the target record does not exist.
func runOutgoingShareUpdateNotFound(t *testing.T, ctx context.Context, s store.OutgoingShareStore) {
	ghost := NewOutgoingShareFixture()
	ghost.ProviderID = "update-missing-out-share-provider"
	ghost.ShareID = "update-missing-out-share-id"
	ghost.WebDAVID = "update-missing-out-share-webdav"

	if err := s.UpdateOutgoingShare(ctx, ghost); !errors.Is(err, store.ErrNotFound) {
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

	if err := s.UpdateOutgoingInvite(ctx, ghost); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("expected ErrNotFound for update of missing outgoing invite, got %v", err)
	}
}

// runIncomingShareProviderKeyUniqueness verifies that (sendingServer, providerID)
// is enforced as a composite unique key across all backends:
// - a duplicate pair returns ErrAlreadyExists
// - the original record is still returned by GetIncomingShareByProviderKey
// - the same providerID with a different sendingServer still succeeds
func runIncomingShareProviderKeyUniqueness(
	t *testing.T,
	ctx context.Context,
	s store.IncomingShareStore,
) {
	first := &store.IncomingShare{
		ShareID:         "provider-key-unique-1",
		SenderHost:      "provider-key-server.com",
		ProviderID:      "provider-key-unique-pid",
		Owner:           "alice@sender.com",
		Sender:          "alice@sender.com",
		ShareWith:       "bob@example.com",
		Name:            "shared.txt",
		ResourceType:    "file",
		Permissions:     "read",
		Status:          "pending",
		RecipientUserID: "bob",
		CreatedAt:       time.Now().Unix(),
		UpdatedAt:       time.Now().Unix(),
	}
	if err := s.CreateIncomingShare(ctx, first); err != nil {
		t.Fatalf("CreateIncomingShare(first): %v", err)
	}

	t.Cleanup(func() {
		if err := s.DeleteIncomingShareForRecipient(ctx, first.ShareID, first.RecipientUserID); err != nil && !errors.Is(err, store.ErrNotFound) {
			t.Errorf("cleanup: DeleteIncomingShareForRecipient first: %v", err)
		}
	})

	// Same (sendingServer, providerID), different shareID: must fail.
	second := &store.IncomingShare{
		ShareID:         "provider-key-unique-2",
		SenderHost:      "provider-key-server.com",
		ProviderID:      "provider-key-unique-pid",
		Owner:           "alice@sender.com",
		Sender:          "alice@sender.com",
		ShareWith:       "bob@example.com",
		Name:            "shared.txt",
		ResourceType:    "file",
		Permissions:     "read",
		Status:          "pending",
		RecipientUserID: "bob",
		CreatedAt:       time.Now().Unix(),
		UpdatedAt:       time.Now().Unix(),
	}
	if err := s.CreateIncomingShare(ctx, second); !errors.Is(err, store.ErrAlreadyExists) {
		t.Fatalf("expected ErrAlreadyExists for duplicate (sendingServer, providerID), got %v", err)
	}

	// Original must still be found by provider key lookup.
	got, err := s.GetIncomingShareByProviderKey(ctx, "provider-key-server.com", "provider-key-unique-pid")
	if err != nil {
		t.Fatalf("GetIncomingShareByProviderKey after conflict: %v", err)
	}

	if got.ShareID != "provider-key-unique-1" {
		t.Errorf(
			"original share overwritten: expected provider-key-unique-1, got %q",
			got.ShareID,
		)
	}

	// Same providerID, different sendingServer: must succeed.
	third := &store.IncomingShare{
		ShareID:         "provider-key-unique-3",
		SenderHost:      "other-server.com",
		ProviderID:      "provider-key-unique-pid",
		Owner:           "alice@sender.com",
		Sender:          "alice@sender.com",
		ShareWith:       "bob@example.com",
		Name:            "shared.txt",
		ResourceType:    "file",
		Permissions:     "read",
		Status:          "pending",
		RecipientUserID: "bob",
		CreatedAt:       time.Now().Unix(),
		UpdatedAt:       time.Now().Unix(),
	}
	if createErr := s.CreateIncomingShare(ctx, third); createErr != nil {
		t.Fatalf("CreateIncomingShare(third, different sendingServer): %v", createErr)
	}

	t.Cleanup(func() {
		if deleteErr := s.DeleteIncomingShareForRecipient(ctx, third.ShareID, third.RecipientUserID); deleteErr != nil && !errors.Is(deleteErr, store.ErrNotFound) {
			t.Errorf("cleanup: DeleteIncomingShareForRecipient third: %v", deleteErr)
		}
	})

	gotThird, err := s.GetIncomingShareByProviderKey(ctx, "other-server.com", "provider-key-unique-pid")
	if err != nil {
		t.Fatalf("GetIncomingShareByProviderKey for third: %v", err)
	}

	if gotThird.ShareID != "provider-key-unique-3" {
		t.Errorf("expected provider-key-unique-3, got %q", gotThird.ShareID)
	}
}
