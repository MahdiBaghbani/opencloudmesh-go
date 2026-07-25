package incoming_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	inboundsignature "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/inbound/signature"
	sharesinbox "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/inbox"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
)

func TestCreateShare_Authenticated_RejectsUntrustedOwnerProvider(t *testing.T) {
	const ownerHost = "owner.example.com"
	const senderHost = "relay.example.com"
	const providerID = "owner-sender-split"

	repo := sharesinbox.NewMemoryIncomingShareRepo()
	partyRepo := setupTestPartyRepo()
	handler := newTestHandler(repo, partyRepo)

	body := validShareBodyWithOwnerAndSenderHosts("alice@localhost:9200", ownerHost, senderHost, providerID)
	req := httptest.NewRequest(http.MethodPost, "/ocm/shares", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	ctx := context.WithValue(req.Context(), inboundsignature.PeerIdentityKey, &inboundsignature.PeerIdentity{
		Authority:           senderHost,
		AuthorityForCompare: senderHost,
		Authenticated:       true,
	})
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	handler.CreateShare(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
	}

	var resp spec.OCMErrorResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode error response: %v", err)
	}
	if resp.Message != "UNTRUSTED_PROVIDER" {
		t.Errorf("expected UNTRUSTED_PROVIDER, got %q", resp.Message)
	}

	if _, err := repo.GetByProviderID(context.Background(), senderHost, providerID); err == nil {
		t.Fatal("expected no share persisted for untrusted owner provider")
	}
}
func TestCreateShare_AuthenticatedIdentityOverridesRawSender(t *testing.T) {
	const authenticatedSender = "verified-sender.com"
	const rawSenderHost = "wrong-sender.com"
	const providerID = "auth-sender-override"

	repo := sharesinbox.NewMemoryIncomingShareRepo()
	partyRepo := setupTestPartyRepo()

	handler := newTestHandler(repo, partyRepo)

	body := `{
		"shareWith": "alice@localhost:9200",
		"name": "test.txt",
		"providerId": "` + providerID + `",
		"owner": "owner@` + authenticatedSender + `",
		"sender": "user@` + rawSenderHost + `",
		"shareType": "user",
		"resourceType": "file",
		"protocol": {
			"name": "webdav",
			"webdav": {
				"uri": "abc123",
				"sharedSecret": "secret123",
				"permissions": ["read"],
				"requirements": ["must-exchange-token"]
			}
		}
	}`

	req := httptest.NewRequest(http.MethodPost, "/ocm/shares", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	ctx := context.WithValue(req.Context(), inboundsignature.PeerIdentityKey, &inboundsignature.PeerIdentity{
		Authority:           authenticatedSender,
		AuthorityForCompare: authenticatedSender,
		Authenticated:       true,
	})
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	handler.CreateShare(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	stored, err := repo.GetByProviderID(context.Background(), authenticatedSender, providerID)
	if err != nil {
		t.Fatalf("expected share indexed by authenticated sender, got error: %v", err)
	}
	if stored.SenderHost != authenticatedSender {
		t.Fatalf("SenderHost = %q, want authenticated authority %q", stored.SenderHost, authenticatedSender)
	}

	if _, err := repo.GetByProviderID(context.Background(), rawSenderHost, providerID); err == nil {
		t.Fatal("expected share not indexed under raw sender host")
	}
}

func TestCreateShare_Authenticated_AcceptsDistinctOwnerAndSenderUserIDs(t *testing.T) {
	const authority = "relay.example.com"
	const providerID = "distinct-users-same-authority"

	repo := sharesinbox.NewMemoryIncomingShareRepo()
	partyRepo := setupTestPartyRepo()
	handler := newTestHandler(repo, partyRepo)

	body := `{
		"shareWith": "alice@localhost:9200",
		"name": "test.txt",
		"providerId": "` + providerID + `",
		"owner": "owner-user@` + authority + `",
		"sender": "sender-user@` + authority + `",
		"shareType": "user",
		"resourceType": "file",
		"protocol": {
			"name": "webdav",
			"webdav": {
				"uri": "abc123",
				"sharedSecret": "secret123",
				"permissions": ["read"],
				"requirements": ["must-exchange-token"]
			}
		}
	}`

	req := httptest.NewRequest(http.MethodPost, "/ocm/shares", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	ctx := context.WithValue(req.Context(), inboundsignature.PeerIdentityKey, &inboundsignature.PeerIdentity{
		Authority:           authority,
		AuthorityForCompare: authority,
		Authenticated:       true,
	})
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	handler.CreateShare(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	stored, err := repo.GetByProviderID(context.Background(), authority, providerID)
	if err != nil {
		t.Fatalf("expected persisted share, got error: %v", err)
	}
	if stored.OwnerHost != authority {
		t.Fatalf("OwnerHost = %q, want %q", stored.OwnerHost, authority)
	}
	if stored.SenderHost != authority {
		t.Fatalf("SenderHost = %q, want %q", stored.SenderHost, authority)
	}
	if stored.Owner == "sender-user@"+authority {
		t.Fatalf("expected distinct owner and sender user IDs, both %q", stored.Owner)
	}
	if stored.Sender == stored.Owner {
		t.Fatalf("expected distinct owner and sender addresses, both %q", stored.Owner)
	}
}
