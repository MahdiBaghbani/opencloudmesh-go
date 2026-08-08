// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package accepted_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	tsrepos "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/repos"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites"
	invitesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites/outgoing"
)

func TestHandleInviteAccepted_ResponseFieldsAlwaysPresent(t *testing.T) {
	t.Parallel()
	repo := tsrepos.OpenMemory(t).OutgoingInvites
	partyRepo := identity.NewMemoryPartyRepo()

	localUser := &identity.User{
		ID:       "user-uuid-789",
		Username: "charlie",
	}
	if err := partyRepo.Create(context.Background(), localUser); err != nil {
		t.Fatalf("Create: %v", err)
	}

	handler := newTestHandler(repo, partyRepo)

	invite := &invitesoutgoing.OutgoingInvite{
		Token:           "field-test-token",
		ProviderFQDN:    testProvider,
		CreatedByUserID: localUser.ID,
		ExpiresAt:       time.Now().Add(24 * time.Hour),
		Status:          invites.InviteStatusPending,
	}
	if err := repo.Create(context.Background(), invite); err != nil {
		t.Fatalf("Create: %v", err)
	}

	w := postInviteAccepted(handler, `{"token":"field-test-token","recipientProvider":"other.com","userID":"u@host","email":"e","name":"n"}`)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Parse as raw JSON to verify email and name fields are present (not omitted)
	var raw map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &raw); err != nil {
		t.Fatalf("failed to parse raw JSON: %v", err)
	}

	for _, field := range []string{"userID", "email", "name"} {
		if _, ok := raw[field]; !ok {
			t.Errorf("field %q missing from response", field)
		}
	}
}
