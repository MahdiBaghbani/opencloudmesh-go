package shares_test

import (
	"context"
	"testing"

	sharesinbox "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/inbox"
	tsrepos "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/repos"
)

// TestIncomingShareAdapter_DurableRoundTrip_PersistsProtocolNameAndWebappArm
// verifies the real JSON store plus the incoming-share adapter preserve
// ProtocolName and the webapp arm fields across a Create -> read-back
// round-trip. This proves the durable persistence path that the in-memory
// HTTP rendering test (TestHandleGetDetail_RendersProtocolNameAndWebappArm,
// in handler_detail_test.go) cannot cover.
func TestIncomingShareAdapter_DurableRoundTrip_PersistsProtocolNameAndWebappArm(t *testing.T) {
	ctx := context.Background()
	r := tsrepos.OpenJSON(t)
	defer r.Close()

	repo := r.IncomingShares

	share := &sharesinbox.IncomingShare{
		ProviderID:        "prov-durable-rt",
		SenderHost:        "sender.example.com",
		ShareWith:         userAID + "@example.com",
		RecipientUserID:   userAID,
		Status:            sharesinbox.ShareStatusPending,
		ResourceType:      "file",
		Name:              "test-share-durable",
		Owner:             "owner@sender.example.com",
		Sender:            "sender@sender.example.com",
		ShareType:         "user",
		Permissions:       []string{"read"},
		WebDAVID:          "wdid-durable",
		SharedSecret:      "secret",
		Requirements:      []string{"must-exchange-token"},
		ProtocolName:      "custom-app",
		WebappURI:         "https://app.sender.example.com/launch",
		WebappTargets:     []string{"blank", "_self"},
		WebappPermissions: []string{"view", "share"},
	}
	if err := repo.Create(ctx, share); err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := repo.GetByIDForRecipientUserID(ctx, share.ShareID, userAID)
	if err != nil {
		t.Fatalf("GetByIDForRecipientUserID: %v", err)
	}
	if got.ProtocolName != "custom-app" {
		t.Errorf("ProtocolName: got %q, want %q", got.ProtocolName, "custom-app")
	}
	if got.WebappURI != "https://app.sender.example.com/launch" {
		t.Errorf("WebappURI: got %q, want %q", got.WebappURI, "https://app.sender.example.com/launch")
	}
	if len(got.WebappTargets) != 2 || got.WebappTargets[0] != "blank" || got.WebappTargets[1] != "_self" {
		t.Errorf("WebappTargets: got %v, want [blank _self]", got.WebappTargets)
	}
	if len(got.WebappPermissions) != 2 || got.WebappPermissions[0] != "view" || got.WebappPermissions[1] != "share" {
		t.Errorf("WebappPermissions: got %v, want [view share]", got.WebappPermissions)
	}
}
