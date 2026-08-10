// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package memcore

import (
	"context"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store"
)

func TestDeepCloneSlicesIndependent(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	core := NewCore()

	out := &store.OutgoingShare{
		ShareID:      "clone-out-share",
		ProviderID:   "clone-out-provider",
		WebDAVID:     "clone-out-webdav",
		SharedSecret: "clone-out-secret",
		Requirements: []string{"must-share", "must-invite"},
		Status:       "sent",
	}

	if err := core.CreateOutgoingShare(ctx, out); err != nil {
		t.Fatalf("CreateOutgoingShare: %v", err)
	}

	gotOut, getErr := core.GetOutgoingShare(ctx, out.ProviderID)
	if getErr != nil {
		t.Fatalf("GetOutgoingShare: %v", getErr)
	}

	gotOut.Requirements[0] = "mutated"

	gotOutAgain, getAgainErr := core.GetOutgoingShare(ctx, out.ProviderID)
	if getAgainErr != nil {
		t.Fatalf("second GetOutgoingShare: %v", getAgainErr)
	}

	if gotOutAgain.Requirements[0] != "must-share" {
		t.Errorf("outgoing Requirements[0] = %q, want %q", gotOutAgain.Requirements[0], "must-share")
	}

	in := &store.IncomingShare{
		ShareID:         "clone-in-share",
		SenderHost:      "sender.example",
		ProviderID:      "clone-in-provider",
		RecipientUserID: "bob",
		Requirements:    []string{"incoming-req"},
		WebappTargets:   []string{"files", "calendar"},
		Status:          "pending",
	}

	if err := core.CreateIncomingShare(ctx, in); err != nil {
		t.Fatalf("CreateIncomingShare: %v", err)
	}

	gotIn, getInErr := core.GetIncomingShareByIDForRecipient(ctx, in.ShareID, in.RecipientUserID)
	if getInErr != nil {
		t.Fatalf("GetIncomingShareByIDForRecipient: %v", getInErr)
	}

	gotIn.Requirements[0] = "mutated-req"
	gotIn.WebappTargets[0] = "mutated-target"

	gotInAgain, getInAgainErr := core.GetIncomingShareByIDForRecipient(ctx, in.ShareID, in.RecipientUserID)
	if getInAgainErr != nil {
		t.Fatalf("second GetIncomingShareByIDForRecipient: %v", getInAgainErr)
	}

	if gotInAgain.Requirements[0] != "incoming-req" {
		t.Errorf("incoming Requirements[0] = %q, want %q", gotInAgain.Requirements[0], "incoming-req")
	}

	if gotInAgain.WebappTargets[0] != "files" {
		t.Errorf("incoming WebappTargets[0] = %q, want %q", gotInAgain.WebappTargets[0], "files")
	}
}
