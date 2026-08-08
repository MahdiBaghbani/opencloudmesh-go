// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package store

import (
	"context"
	"errors"
	"testing"

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

		subDir := t.TempDir()

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

	t.Run("OutgoingInviteAcceptedIdentityCoalescedOnEmptyUpdate", func(t *testing.T) {
		d := newSubDriver(t)
		runOutgoingInviteAcceptedIdentityCoalescedOnEmptyUpdate(t, ctx, requireOutgoingInviteStore(t, d))
	})

	t.Run("IncomingInviteStatusContract", func(t *testing.T) {
		d := newSubDriver(t)
		runIncomingInviteStatusContract(t, ctx, requireIncomingInviteStore(t, d))
	})

	t.Run("IncomingInviteAcceptedIdentityCoalescedOnEmptyUpdate", func(t *testing.T) {
		d := newSubDriver(t)
		runIncomingInviteAcceptedIdentityCoalescedOnEmptyUpdate(t, ctx, requireIncomingInviteStore(t, d))
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
	t.Helper()

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
