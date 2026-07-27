package incoming_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites"
	invitesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites/outgoing"
)

func TestHandleInviteAccepted_ResponseFieldsAlwaysPresent(t *testing.T) {
	repo := invitesoutgoing.NewMemoryOutgoingInviteRepo()
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
	var raw map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &raw); err != nil {
		t.Fatalf("failed to parse raw JSON: %v", err)
	}

	for _, field := range []string{"userID", "email", "name"} {
		if _, ok := raw[field]; !ok {
			t.Errorf("field %q missing from response", field)
		}
	}
}
