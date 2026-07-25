package invites_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/go-chi/chi/v5"

	inboxinvites "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/api/inbox/invites"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites"
	invitesinbox "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites/inbox"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache/loader"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto"
	tslocalid "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/localidentity"
)

func TestHandleAccept_CrossUserReturns404(t *testing.T) {
	repo := invitesinbox.NewMemoryIncomingInviteRepo()
	invite := createInviteForUser(repo, userAID, "accept-token", "sender.example.com")

	userB := &identity.User{ID: userBID, Username: "bob"}
	router := newTestRouter(t, repo, userB)

	req := httptest.NewRequest(http.MethodPost, "/inbox/invites/"+invite.ID+"/accept", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 for cross-user accept, got %d", w.Code)
	}
}

func TestHandleAccept_NonexistentReturns404(t *testing.T) {
	repo := invitesinbox.NewMemoryIncomingInviteRepo()
	userA := &identity.User{ID: userAID, Username: "alice"}
	router := newTestRouter(t, repo, userA)

	req := httptest.NewRequest(http.MethodPost, "/inbox/invites/nonexistent-id/accept", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestHandleAccept_IdempotentForAlreadyAccepted(t *testing.T) {
	repo := invitesinbox.NewMemoryIncomingInviteRepo()
	invite := createInviteForUser(repo, userAID, "idem-accept-token", "sender.example.com")

	repo.UpdateStatusForRecipientUserID(context.Background(), invite.ID, userAID, invites.InviteStatusAccepted)

	userA := &identity.User{ID: userAID, Username: "alice"}
	router := newTestRouter(t, repo, userA)

	req := httptest.NewRequest(http.MethodPost, "/inbox/invites/"+invite.ID+"/accept", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for idempotent accept, got %d", w.Code)
	}
}

func TestHandleAccept_ConflictForDeclinedInvite(t *testing.T) {
	repo := invitesinbox.NewMemoryIncomingInviteRepo()
	invite := createInviteForUser(repo, userAID, "conflict-token", "sender.example.com")

	// Decline normally deletes; manually set declined to test accept-after-decline returns 409
	repo.UpdateStatusForRecipientUserID(context.Background(), invite.ID, userAID, invites.InviteStatusDeclined)

	userA := &identity.User{ID: userAID, Username: "alice"}
	router := newTestRouter(t, repo, userA)

	req := httptest.NewRequest(http.MethodPost, "/inbox/invites/"+invite.ID+"/accept", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusConflict {
		t.Errorf("expected 409 for accepting a declined invite, got %d", w.Code)
	}
}

func TestHandleAccept_Unauthenticated(t *testing.T) {
	repo := invitesinbox.NewMemoryIncomingInviteRepo()
	router := newTestRouter(t, repo, nil)

	req := httptest.NewRequest(http.MethodPost, "/inbox/invites/some-id/accept", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestHandleAccept_StrictPolicyWithoutSignerReturnsBadGateway(t *testing.T) {
	repo := invitesinbox.NewMemoryIncomingInviteRepo()
	senderServer, inviteAcceptedCalls, _ := startInviteSenderServer(t)
	defer senderServer.Close()

	senderFQDN := strings.TrimPrefix(senderServer.URL, "https://")
	invite := createInviteForUser(repo, userAID, "strict-accept-token", senderFQDN)

	requestClient, discoveryClient := newTestOutboundClients(t)
	userA := &identity.User{ID: userAID, Username: "alice"}
	router := newTestRouterWithDeps(t,
		repo,
		userA,
		requestClient,
		discoveryClient,
		nil,
	)

	req := httptest.NewRequest(http.MethodPost, "/inbox/invites/"+invite.ID+"/accept", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadGateway {
		t.Fatalf("expected 502 when strict invite-accepted signing has no signer, got %d: %s", w.Code, w.Body.String())
	}
	if inviteAcceptedCalls.Load() != 0 {
		t.Fatalf("expected invite-accepted endpoint not to be called, got %d calls", inviteAcceptedCalls.Load())
	}

	stored, err := repo.GetByIDForRecipientUserID(context.Background(), invite.ID, userAID)
	if err != nil {
		t.Fatalf("expected invite to remain pending after outbound failure: %v", err)
	}
	if stored.Status != invites.InviteStatusPending {
		t.Fatalf("expected pending status after outbound failure, got %s", stored.Status)
	}
}

func TestHandleAccept_RecipientProviderStripsDefaultHTTPSPort(t *testing.T) {
	const originWithDefaultPort = "https://example.com:443"
	wantProvider := tslocalid.MustTestIdentity(t, originWithDefaultPort, "").ProviderDomain
	if wantProvider != "example.com" {
		t.Fatalf("test setup: ProviderDomain = %q, want example.com", wantProvider)
	}

	repo := invitesinbox.NewMemoryIncomingInviteRepo()
	inviteAcceptedCalls := &atomic.Int32{}
	var capturedRecipientProvider string

	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/ocm":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(spec.Discovery{
				Enabled:       true,
				APIVersion:    "1.4.0",
				EndPoint:      srv.URL + "/ocm",
				Capabilities:  []string{"exchange-token"},
				TokenEndPoint: srv.URL + "/ocm/token",
			})
		case "/ocm/invite-accepted":
			inviteAcceptedCalls.Add(1)
			var body spec.InviteAcceptedRequest
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("decode invite-accepted body: %v", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			capturedRecipientProvider = body.RecipientProvider
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"status":"ok"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	senderFQDN := strings.TrimPrefix(srv.URL, "https://")
	invite := createInviteForUser(repo, userAID, "default-port-accept-token", senderFQDN)

	requestClient, discoveryClient := newTestOutboundClients(t)
	userA := &identity.User{ID: userAID, Username: "alice"}
	km := crypto.NewKeyManager("", testPublicOrigin)
	if err := km.LoadOrGenerate(); err != nil {
		t.Fatal(err)
	}
	signer := crypto.NewRFC9421Signer(km)
	h := inboxinvites.NewHandler(
		repo,
		requestClient,
		discoveryClient,
		signer,
		wantProvider,
		currentUserFunc(userA),
		testLogger,
	)
	r := chi.NewRouter()
	r.Route("/inbox/invites", func(r chi.Router) {
		r.Post("/{inviteId}/accept", h.HandleAccept)
	})

	req := httptest.NewRequest(http.MethodPost, "/inbox/invites/"+invite.ID+"/accept", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if inviteAcceptedCalls.Load() != 1 {
		t.Fatalf("expected invite-accepted endpoint to be called once, got %d", inviteAcceptedCalls.Load())
	}
	if capturedRecipientProvider != wantProvider {
		t.Errorf("RecipientProvider = %q, want %q", capturedRecipientProvider, wantProvider)
	}
}
