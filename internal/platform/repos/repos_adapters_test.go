// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package repos_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites"
	invitesincoming "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites/incoming"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares"
	sharesincoming "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/incoming"
	sharesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store"
	tshttp "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/http"
	tsrepos "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/repos"
)

// TestJSON_IncomingShare_CreateDuplicate verifies that a second Create for the
// same provider key returns a duplicate error (wrapping store.ErrAlreadyExists),
// not ErrShareNotFound.
func TestJSON_IncomingShare_CreateDuplicate(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	r := tsrepos.OpenJSON(t)
	defer tshttp.MustClose(t, r)

	share := &sharesincoming.IncomingShare{
		ShareID:         "dup1",
		ProviderID:      "dp1",
		SenderHost:      "sender.example",
		SharedSecret:    "sec",
		ShareWith:       "alice",
		Name:            "dup-share",
		ResourceType:    "file",
		Permissions:     []string{"read"},
		Status:          shares.ShareStatusPending,
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

	if errors.Is(err, sharesincoming.ErrShareNotFound) {
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
	t.Parallel()

	ctx := context.Background()

	r := tsrepos.OpenJSON(t)
	defer tshttp.MustClose(t, r)

	invite := &invitesincoming.IncomingInvite{
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

// TestDurable_OutgoingShare_SentAt_RoundTrip verifies that SentAt survives a
// Create -> GetByID round-trip through all durable backends (json, sqlite, mirror).
func TestDurable_OutgoingShare_SentAt_RoundTrip(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	for _, backend := range tsrepos.DurableBackends() {
		t.Run(backend, func(t *testing.T) {
			t.Parallel()

			r := tsrepos.OpenDurable(t, ctx, backend)
			defer tshttp.MustClose(t, r)

			sentAt := time.Unix(time.Now().Unix(), 0).UTC()

			share := &sharesoutgoing.OutgoingShare{
				ShareID:      "sat-" + backend,
				ProviderID:   "satp-" + backend,
				SharedSecret: "satsecret-" + backend,
				ShareWith:    "eve@peer",
				Name:         "sentat-durable-share",
				ResourceType: "file",
				Permissions:  []string{"read"},
				Status:       shares.OutgoingShareStatusSent,
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

// TestDurable_OutgoingShare_NewFields_RoundTrip verifies that ReceiverEndPoint,
// ShareType, Error, and Requirements survive a Create -> GetByID round-trip
// through durable backends.
func TestDurable_OutgoingShare_NewFields_RoundTrip(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	for _, backend := range tsrepos.DurableBackends() {
		t.Run(backend, func(t *testing.T) {
			t.Parallel()

			r := tsrepos.OpenDurable(t, ctx, backend)
			defer tshttp.MustClose(t, r)

			share := &sharesoutgoing.OutgoingShare{
				ShareID:          "nf-out-" + backend,
				ProviderID:       "nfp-" + backend,
				SharedSecret:     "nfsec-" + backend,
				ShareWith:        "bob@peer",
				Name:             "new-fields-share",
				ResourceType:     "file",
				Permissions:      []string{"read"},
				Status:           shares.OutgoingShareStatusSent,
				ReceiverEndPoint: "https://peer.example/ocm",
				ShareType:        "user",
				Error:            "some error",
				Requirements:     []string{spec.RequirementMustExchangeToken},
				CreatedAt:        time.Unix(time.Now().Unix(), 0).UTC(),
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

			if len(got.Requirements) != len(share.Requirements) || got.Requirements[0] != share.Requirements[0] {
				t.Errorf("Requirements: got %v, want %v", got.Requirements, share.Requirements)
			}
		})
	}
}

// TestDurable_OutgoingShare_Requirements_StorageToStruct_Isolation verifies
// that mutating the Requirements slice on an OutgoingShare loaded from storage
// does not corrupt the stored share. Guards the slice copy at
// outgoing_share_adapter.go storeOutgoingShareToApp.
func TestDurable_OutgoingShare_Requirements_StorageToStruct_Isolation(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	for _, backend := range tsrepos.DurableBackends() {
		t.Run(backend, func(t *testing.T) {
			t.Parallel()

			r := tsrepos.OpenDurable(t, ctx, backend)
			defer tshttp.MustClose(t, r)

			shareID := "iso-sts-" + backend

			share := &sharesoutgoing.OutgoingShare{
				ShareID:      shareID,
				ProviderID:   "iso-sts-p-" + backend,
				SharedSecret: "iso-sts-sec-" + backend,
				ShareWith:    "bob@peer",
				Name:         "iso-sts-share",
				ResourceType: "file",
				Permissions:  []string{"read"},
				Status:       shares.OutgoingShareStatusSent,
				Requirements: []string{spec.RequirementMustExchangeToken},
				CreatedAt:    time.Unix(time.Now().Unix(), 0).UTC(),
			}
			if err := r.OutgoingShares.Create(ctx, share); err != nil {
				t.Fatalf("Create: %v", err)
			}

			got, err := r.OutgoingShares.GetByID(ctx, shareID)
			if err != nil {
				t.Fatalf("GetByID: %v", err)
			}

			if len(got.Requirements) != 1 || got.Requirements[0] != spec.RequirementMustExchangeToken {
				t.Fatalf("Requirements before mutation: got %v, want [%s]", got.Requirements, spec.RequirementMustExchangeToken)
			}
			// Mutate the returned slice in place after the copy boundary.
			got.Requirements[0] = "iso-sts-mutated"

			reloaded, err := r.OutgoingShares.GetByID(ctx, shareID)
			if err != nil {
				t.Fatalf("reload GetByID: %v", err)
			}

			if len(reloaded.Requirements) != 1 || reloaded.Requirements[0] != spec.RequirementMustExchangeToken {
				t.Errorf("Requirements after mutation: got %v, want [%s] (storage corrupted by caller)", reloaded.Requirements, spec.RequirementMustExchangeToken)
			}
		})
	}
}

// TestDurable_OutgoingShare_Requirements_StructToStorage_Isolation verifies
// that mutating the Requirements slice on the original OutgoingShare after
// Create does not corrupt the stored share. Guards the slice copy at
// outgoing_share_adapter.go appOutgoingShareToStore.
func TestDurable_OutgoingShare_Requirements_StructToStorage_Isolation(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	for _, backend := range tsrepos.DurableBackends() {
		t.Run(backend, func(t *testing.T) {
			t.Parallel()

			r := tsrepos.OpenDurable(t, ctx, backend)
			defer tshttp.MustClose(t, r)

			shareID := "iso-tss-" + backend

			share := &sharesoutgoing.OutgoingShare{
				ShareID:      shareID,
				ProviderID:   "iso-tss-p-" + backend,
				SharedSecret: "iso-tss-sec-" + backend,
				ShareWith:    "carol@peer",
				Name:         "iso-tss-share",
				ResourceType: "file",
				Permissions:  []string{"read"},
				Status:       shares.OutgoingShareStatusSent,
				Requirements: []string{spec.RequirementMustExchangeToken},
				CreatedAt:    time.Unix(time.Now().Unix(), 0).UTC(),
			}
			if err := r.OutgoingShares.Create(ctx, share); err != nil {
				t.Fatalf("Create: %v", err)
			}
			// Mutate the original slice after persistence crosses the copy boundary.
			share.Requirements[0] = "iso-tss-mutated"

			reloaded, err := r.OutgoingShares.GetByID(ctx, shareID)
			if err != nil {
				t.Fatalf("reload GetByID: %v", err)
			}

			if len(reloaded.Requirements) != 1 || reloaded.Requirements[0] != spec.RequirementMustExchangeToken {
				t.Errorf("Requirements after caller mutation: got %v, want [%s] (storage corrupted by caller)", reloaded.Requirements, spec.RequirementMustExchangeToken)
			}
		})
	}
}

// TestDurable_IncomingShare_NewFields_RoundTrip verifies that Description,
// ShareType, OwnerDisplayName, SenderDisplayName, and Expiration survive a
// Create -> GetByIDForRecipientUserID round-trip through durable backends.
func TestDurable_IncomingShare_NewFields_RoundTrip(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	exp := int64(9999999)

	for _, backend := range tsrepos.DurableBackends() {
		t.Run(backend, func(t *testing.T) {
			t.Parallel()

			r := tsrepos.OpenDurable(t, ctx, backend)
			defer tshttp.MustClose(t, r)

			share := &sharesincoming.IncomingShare{
				ShareID:           "nf-in-" + backend,
				ProviderID:        "nfip-" + backend,
				SenderHost:        "sender.example",
				SharedSecret:      "nfisec-" + backend,
				ShareWith:         "carol",
				Name:              "new-fields-incoming",
				ResourceType:      "file",
				Permissions:       []string{"read"},
				Status:            shares.ShareStatusPending,
				RecipientUserID:   "uid1",
				Description:       "a shared folder",
				ShareType:         "user",
				OwnerDisplayName:  "Alice Owner",
				SenderDisplayName: "Bob Sender",
				Expiration:        &exp,
				Requirements:      []string{"must-exchange-token"},
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

			if len(got.Requirements) != 1 || got.Requirements[0] != "must-exchange-token" {
				t.Errorf("Requirements: got %v, want [must-exchange-token]", got.Requirements)
			}
		})
	}
}
