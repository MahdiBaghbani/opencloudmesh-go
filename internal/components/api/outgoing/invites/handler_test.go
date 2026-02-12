package invites_test

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	outgoinginvites "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/api/outgoing/invites"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites"
	invitesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites/outgoing"
)

var testLogger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

const testProvider = "example.com:9200"

func testCurrentUser(user *identity.User) func(context.Context) (*identity.User, error) {
	return func(ctx context.Context) (*identity.User, error) {
		return user, nil
	}
}

func failCurrentUser() func(context.Context) (*identity.User, error) {
	return func(ctx context.Context) (*identity.User, error) {
		return nil, http.ErrNoCookie
	}
}

func TestHandleCreateOutgoing_Success(t *testing.T) {
	repo := invitesoutgoing.NewMemoryOutgoingInviteRepo()
	handler := outgoinginvites.NewHandler(repo, testProvider, nil, testLogger)

	req := httptest.NewRequest(http.MethodPost, "/api/invites/outgoing", nil)
	w := httptest.NewRecorder()

	handler.HandleCreateOutgoing(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	var resp invites.CreateOutgoingResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.InviteString == "" {
		t.Error("inviteString is empty")
	}
	if resp.Token == "" {
		t.Error("token is empty")
	}
	if resp.ProviderFQDN != testProvider {
		t.Errorf("providerFqdn = %q, want %q", resp.ProviderFQDN, testProvider)
	}

	stored, err := repo.GetByToken(context.Background(), resp.Token)
	if err != nil {
		t.Errorf("failed to get stored invite: %v", err)
	}
	if stored.InviteString != resp.InviteString {
		t.Errorf("stored inviteString mismatch")
	}
}

func TestHandleCreateOutgoing_SetsCreatedByUserID(t *testing.T) {
	repo := invitesoutgoing.NewMemoryOutgoingInviteRepo()
	user := &identity.User{
		ID:       "creator-uuid",
		Username: "alice",
	}
	handler := outgoinginvites.NewHandler(repo, testProvider, testCurrentUser(user), testLogger)

	req := httptest.NewRequest(http.MethodPost, "/api/invites/outgoing", nil)
	w := httptest.NewRecorder()

	handler.HandleCreateOutgoing(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	var resp invites.CreateOutgoingResponse
	json.NewDecoder(w.Body).Decode(&resp)

	stored, err := repo.GetByToken(context.Background(), resp.Token)
	if err != nil {
		t.Fatalf("failed to get stored invite: %v", err)
	}
	if stored.CreatedByUserID != "creator-uuid" {
		t.Errorf("CreatedByUserID = %q, want %q", stored.CreatedByUserID, "creator-uuid")
	}
}

func TestHandleCreateOutgoing_NilCurrentUser_NoCreatedByUserID(t *testing.T) {
	repo := invitesoutgoing.NewMemoryOutgoingInviteRepo()
	handler := outgoinginvites.NewHandler(repo, testProvider, nil, testLogger)

	req := httptest.NewRequest(http.MethodPost, "/api/invites/outgoing", nil)
	w := httptest.NewRecorder()

	handler.HandleCreateOutgoing(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	var resp invites.CreateOutgoingResponse
	json.NewDecoder(w.Body).Decode(&resp)

	stored, _ := repo.GetByToken(context.Background(), resp.Token)
	if stored.CreatedByUserID != "" {
		t.Errorf("CreatedByUserID = %q, want empty (no currentUser)", stored.CreatedByUserID)
	}
}

func TestHandleCreateOutgoing_MethodNotAllowed(t *testing.T) {
	repo := invitesoutgoing.NewMemoryOutgoingInviteRepo()
	handler := outgoinginvites.NewHandler(repo, testProvider, nil, testLogger)

	req := httptest.NewRequest(http.MethodGet, "/api/invites/outgoing", nil)
	w := httptest.NewRecorder()

	handler.HandleCreateOutgoing(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHandleCreateOutgoing_MethodNotAllowed_Returns405(t *testing.T) {
	repo := invitesoutgoing.NewMemoryOutgoingInviteRepo()
	handler := outgoinginvites.NewHandler(repo, testProvider, nil, testLogger)

	req := httptest.NewRequest(http.MethodPut, "/api/invites/outgoing", nil)
	w := httptest.NewRecorder()

	handler.HandleCreateOutgoing(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}
