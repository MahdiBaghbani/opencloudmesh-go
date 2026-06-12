package repos_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites"
	invitesinbox "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites/inbox"
	invitesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites/outgoing"
	sharesinbox "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/inbox"
	sharesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store"
)

// ---- memory adapter behavior (round-trip via in-process repos) ----

func TestMemory_OutgoingShare_CreateAndGet(t *testing.T) {
	ctx := context.Background()
	r := newMemoryRepos(t)
	defer r.Close()

	share := &sharesoutgoing.OutgoingShare{
		ShareID:      "s1",
		ProviderID:   "p1",
		SharedSecret: "secret",
		ShareWith:    "alice@peer",
		Name:         "testshare",
		ResourceType: "file",
		Permissions:  []string{"read"},
		Status:       "pending",
		CreatedAt:    time.Now().Truncate(time.Second),
	}
	if err := r.OutgoingShares.Create(ctx, share); err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := r.OutgoingShares.GetByID(ctx, "s1")
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.ShareID != share.ShareID {
		t.Errorf("ShareID mismatch: got %q, want %q", got.ShareID, share.ShareID)
	}
	if got.ShareWith != share.ShareWith {
		t.Errorf("ShareWith mismatch: got %q, want %q", got.ShareWith, share.ShareWith)
	}
}

func TestMemory_IncomingShare_ErrShareNotFound(t *testing.T) {
	ctx := context.Background()
	r := newMemoryRepos(t)
	defer r.Close()

	_, err := r.IncomingShares.GetByIDForRecipientUserID(ctx, "noexist", "user1")
	if !errors.Is(err, sharesinbox.ErrShareNotFound) {
		t.Errorf("expected ErrShareNotFound, got %v", err)
	}
}

func TestMemory_OutgoingInvite_TokenSentinel(t *testing.T) {
	ctx := context.Background()
	r := newMemoryRepos(t)
	defer r.Close()

	_, err := r.OutgoingInvites.GetByToken(ctx, "notoken")
	if !errors.Is(err, invites.ErrTokenNotFound) {
		t.Errorf("expected ErrTokenNotFound, got %v", err)
	}
}

func TestMemory_OutgoingInvite_ErrInviteNotFound(t *testing.T) {
	ctx := context.Background()
	r := newMemoryRepos(t)
	defer r.Close()

	_, err := r.OutgoingInvites.GetByID(ctx, "noid")
	if !errors.Is(err, invites.ErrInviteNotFound) {
		t.Errorf("expected ErrInviteNotFound, got %v", err)
	}
}

func TestMemory_IncomingInvite_CreateAndGetByToken(t *testing.T) {
	ctx := context.Background()
	r := newMemoryRepos(t)
	defer r.Close()

	invite := &invitesinbox.IncomingInvite{
		ID:              "ii1",
		Token:           "tok-abc",
		InviteString:    "b64string",
		SenderFQDN:      "peer.example",
		RecipientUserID: "user1",
		Status:          invites.InviteStatusPending,
		ReceivedAt:      time.Now().Truncate(time.Second),
	}
	if err := r.IncomingInvites.Create(ctx, invite); err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := r.IncomingInvites.GetByTokenForRecipientUserID(ctx, "tok-abc", "user1")
	if err != nil {
		t.Fatalf("GetByTokenForRecipientUserID: %v", err)
	}
	if got.ID != invite.ID {
		t.Errorf("ID mismatch: got %q, want %q", got.ID, invite.ID)
	}
	if got.SenderFQDN != invite.SenderFQDN {
		t.Errorf("SenderFQDN mismatch: got %q, want %q", got.SenderFQDN, invite.SenderFQDN)
	}
}

// ---- JSON adapter behavior (proves adapters return working app repos) ----

func TestJSON_OutgoingShare_CreateAndGet(t *testing.T) {
	ctx := context.Background()
	r := newJSONRepos(t)
	defer r.Close()

	share := &sharesoutgoing.OutgoingShare{
		ShareID:      "js1",
		ProviderID:   "jp1",
		SharedSecret: "jsecret",
		ShareWith:    "bob@peer",
		Name:         "jsonshare",
		ResourceType: "folder",
		Permissions:  []string{"read", "write"},
		Status:       "pending",
		CreatedAt:    time.Unix(time.Now().Unix(), 0),
	}
	if err := r.OutgoingShares.Create(ctx, share); err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := r.OutgoingShares.GetByID(ctx, "js1")
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.ShareID != share.ShareID {
		t.Errorf("ShareID mismatch: got %q, want %q", got.ShareID, share.ShareID)
	}
	if got.ShareWith != share.ShareWith {
		t.Errorf("ShareWith mismatch: got %q, want %q", got.ShareWith, share.ShareWith)
	}
	if got.ResourceType != share.ResourceType {
		t.Errorf("ResourceType mismatch: got %q, want %q", got.ResourceType, share.ResourceType)
	}
	// Permissions round-trip via comma-join/split
	if len(got.Permissions) != len(share.Permissions) {
		t.Errorf("Permissions len mismatch: got %v, want %v", got.Permissions, share.Permissions)
	}
}

func TestJSON_IncomingShare_ErrShareNotFound(t *testing.T) {
	ctx := context.Background()
	r := newJSONRepos(t)
	defer r.Close()

	_, err := r.IncomingShares.GetByIDForRecipientUserID(ctx, "noexist", "user1")
	if !errors.Is(err, sharesinbox.ErrShareNotFound) {
		t.Errorf("expected ErrShareNotFound, got %v", err)
	}
}

func TestJSON_IncomingShare_StatusUpdate(t *testing.T) {
	ctx := context.Background()
	r := newJSONRepos(t)
	defer r.Close()

	share := &sharesinbox.IncomingShare{
		ShareID:         "is1",
		ProviderID:      "ip1",
		SenderHost:      "sender.example",
		SharedSecret:    "isecret",
		ShareWith:       "carol",
		Name:            "incoming-share",
		ResourceType:    "file",
		Permissions:     []string{"read"},
		Status:          sharesinbox.ShareStatusPending,
		RecipientUserID: "user2",
		CreatedAt:       time.Unix(time.Now().Unix(), 0),
		UpdatedAt:       time.Unix(time.Now().Unix(), 0),
	}
	if err := r.IncomingShares.Create(ctx, share); err != nil {
		t.Fatalf("Create: %v", err)
	}

	if err := r.IncomingShares.UpdateStatusForRecipientUserID(
		ctx, "is1", "user2", sharesinbox.ShareStatusAccepted,
	); err != nil {
		t.Fatalf("UpdateStatus: %v", err)
	}

	got, err := r.IncomingShares.GetByIDForRecipientUserID(ctx, "is1", "user2")
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.Status != sharesinbox.ShareStatusAccepted {
		t.Errorf("Status mismatch: got %q, want %q", got.Status, sharesinbox.ShareStatusAccepted)
	}
}

func TestJSON_OutgoingInvite_TokenSentinel(t *testing.T) {
	ctx := context.Background()
	r := newJSONRepos(t)
	defer r.Close()

	_, err := r.OutgoingInvites.GetByToken(ctx, "notoken")
	if !errors.Is(err, invites.ErrTokenNotFound) {
		t.Errorf("expected ErrTokenNotFound, got %v", err)
	}
}

func TestJSON_OutgoingInvite_CreateAndUpdateStatus(t *testing.T) {
	ctx := context.Background()
	r := newJSONRepos(t)
	defer r.Close()

	now := time.Unix(time.Now().Unix(), 0)
	invite := &invitesoutgoing.OutgoingInvite{
		ID:              "oi1",
		Token:           "tok-xyz",
		ProviderFQDN:    "provider.example",
		InviteString:    "b64data",
		RecipientEmail:  "dave@example.com",
		CreatedByUserID: "user3",
		CreatedAt:       now,
		ExpiresAt:       now.Add(24 * time.Hour),
		Status:          invites.InviteStatusPending,
	}
	if err := r.OutgoingInvites.Create(ctx, invite); err != nil {
		t.Fatalf("Create: %v", err)
	}

	if err := r.OutgoingInvites.UpdateStatus(ctx, "oi1", invites.InviteStatusAccepted, "user99"); err != nil {
		t.Fatalf("UpdateStatus: %v", err)
	}

	got, err := r.OutgoingInvites.GetByID(ctx, "oi1")
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.Status != invites.InviteStatusAccepted {
		t.Errorf("Status mismatch: got %q, want %q", got.Status, invites.InviteStatusAccepted)
	}
	if got.AcceptedBy != "user99" {
		t.Errorf("AcceptedBy mismatch: got %q, want user99", got.AcceptedBy)
	}
}

func TestJSON_IncomingInvite_ErrInviteNotFound(t *testing.T) {
	ctx := context.Background()
	r := newJSONRepos(t)
	defer r.Close()

	_, err := r.IncomingInvites.GetByIDForRecipientUserID(ctx, "noid", "user1")
	if !errors.Is(err, invites.ErrInviteNotFound) {
		t.Errorf("expected ErrInviteNotFound, got %v", err)
	}
}

// ---- corrected adapter semantics ----

// TestJSON_IncomingShare_CreateDuplicate verifies that a second Create for the
// same provider key returns a duplicate error (wrapping store.ErrAlreadyExists),
// not ErrShareNotFound.
func TestJSON_IncomingShare_CreateDuplicate(t *testing.T) {
	ctx := context.Background()
	r := newJSONRepos(t)
	defer r.Close()

	share := &sharesinbox.IncomingShare{
		ShareID:         "dup1",
		ProviderID:      "dp1",
		SenderHost:      "sender.example",
		SharedSecret:    "sec",
		ShareWith:       "alice",
		Name:            "dup-share",
		ResourceType:    "file",
		Permissions:     []string{"read"},
		Status:          sharesinbox.ShareStatusPending,
		RecipientUserID: "user1",
		CreatedAt:       time.Unix(time.Now().Unix(), 0),
		UpdatedAt:       time.Unix(time.Now().Unix(), 0),
	}
	if err := r.IncomingShares.Create(ctx, share); err != nil {
		t.Fatalf("first Create: %v", err)
	}

	err := r.IncomingShares.Create(ctx, share)
	if err == nil {
		t.Fatal("second Create: expected error, got nil")
	}
	if errors.Is(err, sharesinbox.ErrShareNotFound) {
		t.Errorf("second Create: got ErrShareNotFound, want a duplicate error")
	}
	if !errors.Is(err, store.ErrAlreadyExists) {
		t.Errorf("second Create: expected error wrapping store.ErrAlreadyExists, got %v", err)
	}
}

// TestJSON_IncomingInvite_CreateDuplicate verifies that a second Create for the
// same invite id returns a duplicate error (wrapping store.ErrAlreadyExists),
// not ErrInviteNotFound.
func TestJSON_IncomingInvite_CreateDuplicate(t *testing.T) {
	ctx := context.Background()
	r := newJSONRepos(t)
	defer r.Close()

	invite := &invitesinbox.IncomingInvite{
		ID:              "dup-ii1",
		Token:           "tok-dup",
		InviteString:    "b64dup",
		SenderFQDN:      "peer.example",
		RecipientUserID: "user1",
		Status:          invites.InviteStatusPending,
		ReceivedAt:      time.Unix(time.Now().Unix(), 0),
	}
	if err := r.IncomingInvites.Create(ctx, invite); err != nil {
		t.Fatalf("first Create: %v", err)
	}

	err := r.IncomingInvites.Create(ctx, invite)
	if err == nil {
		t.Fatal("second Create: expected error, got nil")
	}
	if errors.Is(err, invites.ErrInviteNotFound) {
		t.Errorf("second Create: got ErrInviteNotFound, want a duplicate error")
	}
	if !errors.Is(err, store.ErrAlreadyExists) {
		t.Errorf("second Create: expected error wrapping store.ErrAlreadyExists, got %v", err)
	}
}

// TestJSON_OutgoingShare_SentAt_RoundTrip verifies that SentAt survives a
// Create -> GetByID round-trip through the JSON backend.
func TestJSON_OutgoingShare_SentAt_RoundTrip(t *testing.T) {
	ctx := context.Background()
	r := newJSONRepos(t)
	defer r.Close()

	sentAt := time.Unix(time.Now().Unix(), 0).UTC()
	share := &sharesoutgoing.OutgoingShare{
		ShareID:      "sa1",
		ProviderID:   "sap1",
		SharedSecret: "sasecret",
		ShareWith:    "eve@peer",
		Name:         "sentat-share",
		ResourceType: "file",
		Permissions:  []string{"read"},
		Status:       "sent",
		CreatedAt:    time.Unix(time.Now().Unix(), 0).UTC(),
		SentAt:       &sentAt,
	}
	if err := r.OutgoingShares.Create(ctx, share); err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := r.OutgoingShares.GetByID(ctx, "sa1")
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.SentAt == nil {
		t.Fatal("SentAt round-trip: got nil, want non-nil")
	}
	if !got.SentAt.Equal(sentAt) {
		t.Errorf("SentAt round-trip: got %v, want %v", got.SentAt, sentAt)
	}
}

// ---- durable Create auto-fill (memory-repo parity) ----

// TestDurable_OutgoingShare_Create_AutoFill verifies that the durable adapter
// fills ShareID and CreatedAt when the caller passes an empty struct, matching
// the memory repo Create semantics.
func TestDurable_OutgoingShare_Create_AutoFill(t *testing.T) {
	ctx := context.Background()
	for _, backend := range []string{config.BackendJSON, config.BackendSQLite, config.BackendMirror} {
		backend := backend
		t.Run(backend, func(t *testing.T) {
			r := newDurableRepos(t, backend)
			defer r.Close()

			share := &sharesoutgoing.OutgoingShare{
				ProviderID:  "prov-autofill",
				ShareWith:   "autofill@peer",
				Name:        "autofill-share",
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
		})
	}
}

// TestDurable_IncomingShare_Create_AutoFill verifies that the durable adapter
// fills ShareID, CreatedAt, and UpdatedAt when the caller omits them.
func TestDurable_IncomingShare_Create_AutoFill(t *testing.T) {
	ctx := context.Background()
	for _, backend := range []string{config.BackendJSON, config.BackendSQLite, config.BackendMirror} {
		backend := backend
		t.Run(backend, func(t *testing.T) {
			r := newDurableRepos(t, backend)
			defer r.Close()

			share := &sharesinbox.IncomingShare{
				ProviderID:      "prov-inc-autofill",
				SenderHost:      "sender.example",
				ShareWith:       "user@local",
				Name:            "inc-autofill",
				Permissions:     []string{"read"},
				RecipientUserID: "uid1",
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
		})
	}
}

// TestDurable_OutgoingInvite_Create_AutoFill verifies that the durable adapter
// fills ID, CreatedAt, and Status when the caller omits them.
func TestDurable_OutgoingInvite_Create_AutoFill(t *testing.T) {
	ctx := context.Background()
	for _, backend := range []string{config.BackendJSON, config.BackendSQLite, config.BackendMirror} {
		backend := backend
		t.Run(backend, func(t *testing.T) {
			r := newDurableRepos(t, backend)
			defer r.Close()

			invite := &invitesoutgoing.OutgoingInvite{
				Token:        "tok-autofill-" + backend,
				ProviderFQDN: "provider.example",
				InviteString: "b64data",
			}
			if err := r.OutgoingInvites.Create(ctx, invite); err != nil {
				t.Fatalf("Create: %v", err)
			}
			if invite.ID == "" {
				t.Error("ID not auto-filled after Create")
			}
			if invite.CreatedAt.IsZero() {
				t.Error("CreatedAt not auto-filled after Create")
			}
			if invite.Status == "" {
				t.Error("Status not auto-filled after Create")
			}
		})
	}
}

// TestDurable_IncomingInvite_Create_AutoFill verifies that the durable adapter
// fills ID, ReceivedAt, and Status when the caller omits them.
func TestDurable_IncomingInvite_Create_AutoFill(t *testing.T) {
	ctx := context.Background()
	for _, backend := range []string{config.BackendJSON, config.BackendSQLite, config.BackendMirror} {
		backend := backend
		t.Run(backend, func(t *testing.T) {
			r := newDurableRepos(t, backend)
			defer r.Close()

			invite := &invitesinbox.IncomingInvite{
				Token:           "tok-inc-autofill-" + backend,
				InviteString:    "b64data",
				SenderFQDN:      "peer.example",
				RecipientUserID: "uid1",
			}
			if err := r.IncomingInvites.Create(ctx, invite); err != nil {
				t.Fatalf("Create: %v", err)
			}
			if invite.ID == "" {
				t.Error("ID not auto-filled after Create")
			}
			if invite.ReceivedAt.IsZero() {
				t.Error("ReceivedAt not auto-filled after Create")
			}
			if invite.Status == "" {
				t.Error("Status not auto-filled after Create")
			}
		})
	}
}

// ---- new-field round-trips ----

// TestDurable_OutgoingShare_SentAt_RoundTrip verifies that SentAt survives a
// Create -> GetByID round-trip through all durable backends (json, sqlite, mirror).
// This closes the coverage gap where only the json backend was exercised.
func TestDurable_OutgoingShare_SentAt_RoundTrip(t *testing.T) {
	ctx := context.Background()
	for _, backend := range []string{config.BackendJSON, config.BackendSQLite, config.BackendMirror} {
		backend := backend
		t.Run(backend, func(t *testing.T) {
			r := newDurableRepos(t, backend)
			defer r.Close()

			sentAt := time.Unix(time.Now().Unix(), 0).UTC()
			share := &sharesoutgoing.OutgoingShare{
				ShareID:      "sat-" + backend,
				ProviderID:   "satp-" + backend,
				SharedSecret: "satsecret-" + backend,
				ShareWith:    "eve@peer",
				Name:         "sentat-durable-share",
				ResourceType: "file",
				Permissions:  []string{"read"},
				Status:       "sent",
				CreatedAt:    time.Unix(time.Now().Unix(), 0).UTC(),
				SentAt:       &sentAt,
			}
			if err := r.OutgoingShares.Create(ctx, share); err != nil {
				t.Fatalf("Create: %v", err)
			}

			got, err := r.OutgoingShares.GetByID(ctx, "sat-"+backend)
			if err != nil {
				t.Fatalf("GetByID: %v", err)
			}
			if got.SentAt == nil {
				t.Fatal("SentAt round-trip: got nil, want non-nil")
			}
			if !got.SentAt.Equal(sentAt) {
				t.Errorf("SentAt round-trip: got %v, want %v", got.SentAt, sentAt)
			}
		})
	}
}

// TestDurable_OutgoingShare_NewFields_RoundTrip verifies that the fields added
// in Q3 T3 (ReceiverEndPoint, ShareType, Error, MustExchangeToken) survive a
// Create -> GetByID round-trip through durable backends.
func TestDurable_OutgoingShare_NewFields_RoundTrip(t *testing.T) {
	ctx := context.Background()
	for _, backend := range []string{config.BackendJSON, config.BackendSQLite, config.BackendMirror} {
		backend := backend
		t.Run(backend, func(t *testing.T) {
			r := newDurableRepos(t, backend)
			defer r.Close()

			share := &sharesoutgoing.OutgoingShare{
				ShareID:           "nf-out-" + backend,
				ProviderID:        "nfp-" + backend,
				SharedSecret:      "nfsec-" + backend,
				ShareWith:         "bob@peer",
				Name:              "new-fields-share",
				ResourceType:      "file",
				Permissions:       []string{"read"},
				Status:            "sent",
				ReceiverEndPoint:  "https://peer.example/ocm",
				ShareType:         "user",
				Error:             "some error",
				MustExchangeToken: true,
				CreatedAt:         time.Unix(time.Now().Unix(), 0).UTC(),
			}
			if err := r.OutgoingShares.Create(ctx, share); err != nil {
				t.Fatalf("Create: %v", err)
			}

			got, err := r.OutgoingShares.GetByID(ctx, "nf-out-"+backend)
			if err != nil {
				t.Fatalf("GetByID: %v", err)
			}
			if got.ReceiverEndPoint != share.ReceiverEndPoint {
				t.Errorf("ReceiverEndPoint: got %q, want %q", got.ReceiverEndPoint, share.ReceiverEndPoint)
			}
			if got.ShareType != share.ShareType {
				t.Errorf("ShareType: got %q, want %q", got.ShareType, share.ShareType)
			}
			if got.Error != share.Error {
				t.Errorf("Error: got %q, want %q", got.Error, share.Error)
			}
			if got.MustExchangeToken != share.MustExchangeToken {
				t.Errorf("MustExchangeToken: got %v, want %v", got.MustExchangeToken, share.MustExchangeToken)
			}
		})
	}
}

// TestDurable_IncomingShare_NewFields_RoundTrip verifies that the fields added
// in Q3 T3 (Description, ShareType, OwnerDisplayName, SenderDisplayName,
// Expiration) survive a Create -> GetByIDForRecipientUserID round-trip.
func TestDurable_IncomingShare_NewFields_RoundTrip(t *testing.T) {
	ctx := context.Background()
	exp := int64(9999999)
	for _, backend := range []string{config.BackendJSON, config.BackendSQLite, config.BackendMirror} {
		backend := backend
		t.Run(backend, func(t *testing.T) {
			r := newDurableRepos(t, backend)
			defer r.Close()

			share := &sharesinbox.IncomingShare{
				ShareID:           "nf-in-" + backend,
				ProviderID:        "nfip-" + backend,
				SenderHost:        "sender.example",
				SharedSecret:      "nfisec-" + backend,
				ShareWith:         "carol",
				Name:              "new-fields-incoming",
				ResourceType:      "file",
				Permissions:       []string{"read"},
				Status:            sharesinbox.ShareStatusPending,
				RecipientUserID:   "uid1",
				Description:       "a shared folder",
				ShareType:         "user",
				OwnerDisplayName:  "Alice Owner",
				SenderDisplayName: "Bob Sender",
				Expiration:        &exp,
				CreatedAt:         time.Unix(time.Now().Unix(), 0).UTC(),
				UpdatedAt:         time.Unix(time.Now().Unix(), 0).UTC(),
			}
			if err := r.IncomingShares.Create(ctx, share); err != nil {
				t.Fatalf("Create: %v", err)
			}

			got, err := r.IncomingShares.GetByIDForRecipientUserID(ctx, "nf-in-"+backend, "uid1")
			if err != nil {
				t.Fatalf("GetByIDForRecipientUserID: %v", err)
			}
			if got.Description != share.Description {
				t.Errorf("Description: got %q, want %q", got.Description, share.Description)
			}
			if got.ShareType != share.ShareType {
				t.Errorf("ShareType: got %q, want %q", got.ShareType, share.ShareType)
			}
			if got.OwnerDisplayName != share.OwnerDisplayName {
				t.Errorf("OwnerDisplayName: got %q, want %q", got.OwnerDisplayName, share.OwnerDisplayName)
			}
			if got.SenderDisplayName != share.SenderDisplayName {
				t.Errorf("SenderDisplayName: got %q, want %q", got.SenderDisplayName, share.SenderDisplayName)
			}
			if got.Expiration == nil {
				t.Error("Expiration: got nil, want non-nil")
			} else if *got.Expiration != exp {
				t.Errorf("Expiration: got %d, want %d", *got.Expiration, exp)
			}
		})
	}
}
