package repos_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares"
	sharesincoming "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/incoming"
	sharesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/repos"
)

// runIncomingShareRepoContract verifies CRUD, list, recipient-scope enforcement,
// auto-fill, and ErrShareNotFound sentinel for the IncomingShareRepo interface.
func runIncomingShareRepoContract(t *testing.T, r *repos.Repos) {
	t.Helper()

	ctx := context.Background()

	t.Run("CRUD", func(t *testing.T) { runIncomingShareRepoContractCRUD(t, ctx, r) })
	t.Run("ListByRecipientUserID", func(t *testing.T) { runIncomingShareRepoContractListByRecipientUserID(t, ctx, r) })
	t.Run("EnforcesRecipientScope", func(t *testing.T) { runIncomingShareRepoContractEnforcesRecipientScope(t, ctx, r) })
	t.Run("EnforcesProviderIDScope", func(t *testing.T) { runIncomingShareRepoContractEnforcesProviderIDScope(t, ctx, r) })
	t.Run("AutoFill", func(t *testing.T) { runIncomingShareRepoContractAutoFill(t, ctx, r) })
	t.Run("ErrShareNotFoundSentinel", func(t *testing.T) { runIncomingShareRepoContractErrShareNotFoundSentinel(t, ctx, r) })
}

func runIncomingShareRepoContractCRUD(t *testing.T, ctx context.Context, r *repos.Repos) {
	t.Helper()

	share := &sharesincoming.IncomingShare{
		ShareID:         "ct-in-s1",
		ProviderID:      "ct-in-p1",
		SenderHost:      "ct.sender.example",
		ShareWith:       "bob",
		Name:            "ct-inshare",
		ResourceType:    "file",
		Permissions:     []string{"read"},
		Status:          shares.ShareStatusPending,
		RecipientUserID: "ct-user-1",
		CreatedAt:       time.Unix(time.Now().Unix(), 0).UTC(),
		UpdatedAt:       time.Unix(time.Now().Unix(), 0).UTC(),
	}
	if err := r.IncomingShares.Create(ctx, share); err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := r.IncomingShares.GetByIDForRecipientUserID(ctx, share.ShareID, share.RecipientUserID)
	if err != nil {
		t.Fatalf("GetByIDForRecipientUserID: %v", err)
	}

	if got.ShareID != share.ShareID {
		t.Errorf("ShareID: got %q, want %q", got.ShareID, share.ShareID)
	}

	got, err = r.IncomingShares.GetByProviderID(ctx, share.SenderHost, share.ProviderID)
	if err != nil {
		t.Fatalf("GetByProviderID: %v", err)
	}

	if got.ShareID != share.ShareID {
		t.Errorf("GetByProviderID ShareID: got %q, want %q", got.ShareID, share.ShareID)
	}

	if err := r.IncomingShares.UpdateStatusForRecipientUserID( //nolint:govet // shadow: sequential err in table-driven test is benign
		ctx, share.ShareID, share.RecipientUserID, shares.ShareStatusAccepted,
	); err != nil {
		t.Fatalf("UpdateStatusForRecipientUserID: %v", err)
	}

	got, err = r.IncomingShares.GetByIDForRecipientUserID(ctx, share.ShareID, share.RecipientUserID)
	if err != nil {
		t.Fatalf("GetByIDForRecipientUserID after status update: %v", err)
	}

	if got.Status != shares.ShareStatusAccepted {
		t.Errorf("Status after update: got %q, want accepted", got.Status)
	}

	if err := r.IncomingShares.DeleteForRecipientUserID(ctx, share.ShareID, share.RecipientUserID); err != nil { //nolint:govet // shadow: sequential err in table-driven test is benign
		t.Fatalf("DeleteForRecipientUserID: %v", err)
	}

	_, err = r.IncomingShares.GetByIDForRecipientUserID(ctx, share.ShareID, share.RecipientUserID)
	if !errors.Is(err, sharesincoming.ErrShareNotFound) {
		t.Errorf("GetByIDForRecipientUserID after delete: expected ErrShareNotFound, got %v", err)
	}
}

func runIncomingShareRepoContractListByRecipientUserID(t *testing.T, ctx context.Context, r *repos.Repos) {
	t.Helper()

	share := &sharesincoming.IncomingShare{
		ShareID:         "ct-list-in-s1",
		ProviderID:      "ct-list-in-p1",
		SenderHost:      "ct.list.sender.example",
		ShareWith:       "listuser",
		Name:            "ct-list-inshare",
		ResourceType:    "file",
		Permissions:     []string{"read"},
		Status:          shares.ShareStatusPending,
		RecipientUserID: "ct-list-user",
		CreatedAt:       time.Unix(time.Now().Unix(), 0).UTC(),
		UpdatedAt:       time.Unix(time.Now().Unix(), 0).UTC(),
	}
	if err := r.IncomingShares.Create(ctx, share); err != nil {
		t.Fatalf("Create: %v", err)
	}

	shares, err := r.IncomingShares.ListByRecipientUserID(ctx, share.RecipientUserID)
	if err != nil {
		t.Fatalf("ListByRecipientUserID: %v", err)
	}

	found := false

	for _, s := range shares {
		if s.ShareID == share.ShareID {
			found = true
			break
		}
	}

	if !found {
		t.Errorf("ListByRecipientUserID: created share %q not found in result", share.ShareID)
	}

	others, err := r.IncomingShares.ListByRecipientUserID(ctx, "ct-other-user-entirely")
	if err != nil {
		t.Fatalf("ListByRecipientUserID other user: %v", err)
	}

	for _, s := range others {
		if s.ShareID == share.ShareID {
			t.Errorf("ListByRecipientUserID: share %q leaked to other user", share.ShareID)
		}
	}
}

func runIncomingShareRepoContractEnforcesRecipientScope(t *testing.T, ctx context.Context, r *repos.Repos) {
	t.Helper()

	share := &sharesincoming.IncomingShare{
		ShareID:         "ct-scope-in-s1",
		ProviderID:      "ct-scope-in-p1",
		SenderHost:      "ct.scope.sender.example",
		ShareWith:       "scopeuser",
		Name:            "ct-scope-inshare",
		ResourceType:    "file",
		Permissions:     []string{"read"},
		Status:          shares.ShareStatusPending,
		RecipientUserID: "ct-scope-owner",
		CreatedAt:       time.Unix(time.Now().Unix(), 0).UTC(),
		UpdatedAt:       time.Unix(time.Now().Unix(), 0).UTC(),
	}
	if err := r.IncomingShares.Create(ctx, share); err != nil {
		t.Fatalf("Create: %v", err)
	}

	_, err := r.IncomingShares.GetByIDForRecipientUserID(ctx, share.ShareID, "ct-wrong-user")
	if !errors.Is(err, sharesincoming.ErrShareNotFound) {
		t.Errorf("GetByIDForRecipientUserID wrong user: expected ErrShareNotFound, got %v", err)
	}

	err = r.IncomingShares.UpdateStatusForRecipientUserID(
		ctx, share.ShareID, "ct-wrong-user", shares.ShareStatusAccepted,
	)
	if !errors.Is(err, sharesincoming.ErrShareNotFound) {
		t.Errorf("UpdateStatusForRecipientUserID wrong user: expected ErrShareNotFound, got %v", err)
	}

	err = r.IncomingShares.DeleteForRecipientUserID(ctx, share.ShareID, "ct-wrong-user")
	if !errors.Is(err, sharesincoming.ErrShareNotFound) {
		t.Errorf("DeleteForRecipientUserID wrong user: expected ErrShareNotFound, got %v", err)
	}
}

func runIncomingShareRepoContractEnforcesProviderIDScope(t *testing.T, ctx context.Context, r *repos.Repos) {
	t.Helper()

	shareA := &sharesincoming.IncomingShare{
		ShareID:         "ct-pscope-in-s-A",
		ProviderID:      "ct-pscope-p1",
		SenderHost:      "ct.sender-a.pscope.example",
		ShareWith:       "pscope-user",
		Name:            "ct-pscope-share-A",
		ResourceType:    "file",
		Permissions:     []string{"read"},
		Status:          shares.ShareStatusPending,
		RecipientUserID: "ct-pscope-recipient-A",
		CreatedAt:       time.Unix(time.Now().Unix(), 0).UTC(),
		UpdatedAt:       time.Unix(time.Now().Unix(), 0).UTC(),
	}
	shareB := &sharesincoming.IncomingShare{
		ShareID:         "ct-pscope-in-s-B",
		ProviderID:      "ct-pscope-p1",
		SenderHost:      "ct.sender-b.pscope.example",
		ShareWith:       "pscope-user",
		Name:            "ct-pscope-share-B",
		ResourceType:    "file",
		Permissions:     []string{"read"},
		Status:          shares.ShareStatusPending,
		RecipientUserID: "ct-pscope-recipient-B",
		CreatedAt:       time.Unix(time.Now().Unix(), 0).UTC(),
		UpdatedAt:       time.Unix(time.Now().Unix(), 0).UTC(),
	}

	if err := r.IncomingShares.Create(ctx, shareA); err != nil {
		t.Fatalf("Create shareA: %v", err)
	}

	if err := r.IncomingShares.Create(ctx, shareB); err != nil {
		t.Fatalf("Create shareB: %v", err)
	}

	gotA, err := r.IncomingShares.GetByProviderID(ctx, shareA.SenderHost, "ct-pscope-p1")
	if err != nil {
		t.Fatalf("GetByProviderID senderHost-A: %v", err)
	}

	if gotA.ShareID != shareA.ShareID {
		t.Errorf("GetByProviderID senderHost-A: got ShareID %q, want %q", gotA.ShareID, shareA.ShareID)
	}

	gotB, err := r.IncomingShares.GetByProviderID(ctx, shareB.SenderHost, "ct-pscope-p1")
	if err != nil {
		t.Fatalf("GetByProviderID senderHost-B: %v", err)
	}

	if gotB.ShareID != shareB.ShareID {
		t.Errorf("GetByProviderID senderHost-B: got ShareID %q, want %q", gotB.ShareID, shareB.ShareID)
	}
}

func runIncomingShareRepoContractAutoFill(t *testing.T, ctx context.Context, r *repos.Repos) {
	t.Helper()

	share := &sharesincoming.IncomingShare{
		ProviderID:      "ct-autofill-in-p1",
		SenderHost:      "ct.autofill.sender.example",
		ShareWith:       "autofill-user",
		Name:            "ct-autofill-inshare",
		Permissions:     []string{"read"},
		RecipientUserID: "ct-autofill-recipient",
	}
	if err := r.IncomingShares.Create(ctx, share); err != nil {
		t.Fatalf("Create: %v", err)
	}

	if share.ShareID == "" {
		t.Error("ShareID not auto-filled after Create")
	}

	if share.CreatedAt.IsZero() {
		t.Error("CreatedAt not auto-filled after Create")
	}

	if share.UpdatedAt.IsZero() {
		t.Error("UpdatedAt not auto-filled after Create")
	}
}

func runIncomingShareRepoContractErrShareNotFoundSentinel(t *testing.T, ctx context.Context, r *repos.Repos) {
	t.Helper()

	_, err := r.IncomingShares.GetByIDForRecipientUserID(ctx, "ct-in-missing-share", "any-user")
	if !errors.Is(err, sharesincoming.ErrShareNotFound) {
		t.Errorf("expected ErrShareNotFound, got %v", err)
	}
}

// runOutgoingShareRepoContract verifies CRUD, list, auto-fill, and not-found
// sentinel behaviour for the OutgoingShareRepo interface.
func runOutgoingShareRepoContract(t *testing.T, r *repos.Repos) {
	t.Helper()

	ctx := context.Background()

	t.Run("CRUD", func(t *testing.T) { runOutgoingShareRepoContractCRUD(t, ctx, r) })
	t.Run("List", func(t *testing.T) { runOutgoingShareRepoContractList(t, ctx, r) })
	t.Run("AutoFill", func(t *testing.T) { runOutgoingShareRepoContractAutoFill(t, ctx, r) })
	t.Run("NotFoundSentinel", func(t *testing.T) { runOutgoingShareRepoContractNotFoundSentinel(t, ctx, r) })
}

func runOutgoingShareRepoContractCRUD(t *testing.T, ctx context.Context, r *repos.Repos) {
	t.Helper()

	share := &sharesoutgoing.OutgoingShare{
		ShareID:      "ct-out-s1",
		ProviderID:   "ct-out-p1",
		WebDAVID:     "ct-out-w1",
		SharedSecret: "ct-secret-1",
		ShareWith:    "alice@peer",
		Name:         "ct-outshare",
		ResourceType: "file",
		Permissions:  []string{"read"},
		Status:       shares.OutgoingShareStatusSent,
		CreatedAt:    time.Unix(time.Now().Unix(), 0).UTC(),
	}
	if err := r.OutgoingShares.Create(ctx, share); err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := r.OutgoingShares.GetByID(ctx, share.ShareID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}

	if got.ShareID != share.ShareID {
		t.Errorf("GetByID ShareID: got %q, want %q", got.ShareID, share.ShareID)
	}

	got, err = r.OutgoingShares.GetByProviderID(ctx, share.ProviderID)
	if err != nil {
		t.Fatalf("GetByProviderID: %v", err)
	}

	if got.ProviderID != share.ProviderID {
		t.Errorf("GetByProviderID: got %q, want %q", got.ProviderID, share.ProviderID)
	}

	got, err = r.OutgoingShares.GetByWebDAVID(ctx, share.WebDAVID)
	if err != nil {
		t.Fatalf("GetByWebDAVID: %v", err)
	}

	if got.WebDAVID != share.WebDAVID {
		t.Errorf("GetByWebDAVID: got %q, want %q", got.WebDAVID, share.WebDAVID)
	}

	got, err = r.OutgoingShares.GetBySharedSecret(ctx, share.SharedSecret)
	if err != nil {
		t.Fatalf("GetBySharedSecret: %v", err)
	}

	if got.SharedSecret != share.SharedSecret {
		t.Errorf("GetBySharedSecret: got %q, want %q", got.SharedSecret, share.SharedSecret)
	}

	share.Status = shares.OutgoingShareStatusAccepted
	if err := r.OutgoingShares.Update(ctx, share); err != nil { //nolint:govet // shadow: sequential err in table-driven test is benign
		t.Fatalf("Update: %v", err)
	}

	got, err = r.OutgoingShares.GetByID(ctx, share.ShareID)
	if err != nil {
		t.Fatalf("GetByID after Update: %v", err)
	}

	if got.Status != shares.OutgoingShareStatusAccepted {
		t.Errorf("Status after Update: got %q, want accepted", got.Status)
	}
}

func runOutgoingShareRepoContractList(t *testing.T, ctx context.Context, r *repos.Repos) {
	t.Helper()

	share := &sharesoutgoing.OutgoingShare{
		ShareID:      "ct-list-out-s1",
		ProviderID:   "ct-list-out-p1",
		WebDAVID:     "ct-list-out-w1",
		SharedSecret: "ct-list-secret-1",
		ShareWith:    "bob@peer",
		Name:         "ct-list-share",
		ResourceType: "file",
		Permissions:  []string{"read"},
		Status:       shares.OutgoingShareStatusSent,
		CreatedAt:    time.Unix(time.Now().Unix(), 0).UTC(),
	}
	if err := r.OutgoingShares.Create(ctx, share); err != nil {
		t.Fatalf("Create: %v", err)
	}

	all, err := r.OutgoingShares.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}

	found := false

	for _, s := range all {
		if s.ShareID == share.ShareID {
			found = true
			break
		}
	}

	if !found {
		t.Errorf("List: created share %q not found in result", share.ShareID)
	}
}

func runOutgoingShareRepoContractAutoFill(t *testing.T, ctx context.Context, r *repos.Repos) {
	t.Helper()

	share := &sharesoutgoing.OutgoingShare{
		ProviderID:  "ct-autofill-out-p1",
		WebDAVID:    "ct-autofill-out-w1",
		ShareWith:   "carol@peer",
		Name:        "ct-autofill-share",
		Permissions: []string{"read"},
	}
	if err := r.OutgoingShares.Create(ctx, share); err != nil {
		t.Fatalf("Create: %v", err)
	}

	if share.ShareID == "" {
		t.Error("ShareID not auto-filled after Create")
	}

	if share.CreatedAt.IsZero() {
		t.Error("CreatedAt not auto-filled after Create")
	}
}

func runOutgoingShareRepoContractNotFoundSentinel(t *testing.T, ctx context.Context, r *repos.Repos) {
	t.Helper()

	_, err := r.OutgoingShares.GetByID(ctx, "ct-out-missing-id")
	if err == nil {
		t.Error("GetByID nonexistent: expected error, got nil")
	}

	_, err = r.OutgoingShares.GetByProviderID(ctx, "ct-out-missing-provider")
	if err == nil {
		t.Error("GetByProviderID nonexistent: expected error, got nil")
	}

	_, err = r.OutgoingShares.GetBySharedSecret(ctx, "ct-out-missing-secret")
	if err == nil {
		t.Error("GetBySharedSecret nonexistent: expected error, got nil")
	}
}
