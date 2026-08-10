// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package json_test

import (
	"context"
	"testing"

	tshttp "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/http"
	testutil "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/store"
)

func TestDeepCloneSlicesIndependent(t *testing.T) {
	t.Parallel()

	driver := newJSONDriver(t)
	defer tshttp.MustClose(t, driver)

	ctx := context.Background()
	outStore := requireOutgoingShareStore(t, driver)
	inStore := requireIncomingShareStore(t, driver)

	outShare := testutil.NewOutgoingShareFixture()
	outShare.ShareID = "clone-out-share"
	outShare.ProviderID = "clone-out-provider"
	outShare.WebDAVID = "clone-out-webdav"
	outShare.Requirements = []string{"must-share", "must-invite"}

	if err := outStore.CreateOutgoingShare(ctx, outShare); err != nil {
		t.Fatalf("CreateOutgoingShare: %v", err)
	}

	gotOut, getErr := outStore.GetOutgoingShare(ctx, outShare.ProviderID)
	if getErr != nil {
		t.Fatalf("GetOutgoingShare: %v", getErr)
	}

	gotOut.Requirements[0] = "mutated"

	gotOutAgain, getAgainErr := outStore.GetOutgoingShare(ctx, outShare.ProviderID)
	if getAgainErr != nil {
		t.Fatalf("second GetOutgoingShare: %v", getAgainErr)
	}

	if gotOutAgain.Requirements[0] != "must-share" {
		t.Errorf("outgoing Requirements[0] = %q, want %q", gotOutAgain.Requirements[0], "must-share")
	}

	inShare := testutil.NewIncomingShareFixture()
	inShare.ShareID = "clone-in-share"
	inShare.SenderHost = "sender.example"
	inShare.ProviderID = "clone-in-provider"
	inShare.RecipientUserID = "bob"
	inShare.Requirements = []string{"incoming-req"}
	inShare.WebappTargets = []string{"files", "calendar"}

	if err := inStore.CreateIncomingShare(ctx, inShare); err != nil {
		t.Fatalf("CreateIncomingShare: %v", err)
	}

	gotIn, getInErr := inStore.GetIncomingShareByIDForRecipient(ctx, inShare.ShareID, inShare.RecipientUserID)
	if getInErr != nil {
		t.Fatalf("GetIncomingShareByIDForRecipient: %v", getInErr)
	}

	gotIn.Requirements[0] = "mutated-req"
	gotIn.WebappTargets[0] = "mutated-target"

	gotInAgain, getInAgainErr := inStore.GetIncomingShareByIDForRecipient(ctx, inShare.ShareID, inShare.RecipientUserID)
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
