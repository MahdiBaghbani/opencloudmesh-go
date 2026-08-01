// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package invites_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	tsrepos "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/repos"

	"github.com/go-chi/chi/v5"

	inboxinvites "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/api/inbox/invites"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/address"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites"
	invitesincoming "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites/incoming"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/outbound"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache/loader"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto"
	tslocalid "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/localidentity"
)

// failingUpdateRepo wraps the memory repo and fails
// UpdateStatusForRecipientUserID to exercise the accept persistence-failure
// path.
type failingUpdateRepo struct {
	invitesincoming.IncomingInviteRepo
}

func (r *failingUpdateRepo) UpdateStatusForRecipientUserID(_ context.Context, _ string, _ string, _ invites.InviteStatus, _ *invitesincoming.Acceptance) error {
	return errors.New("simulated update failure")
}

func TestHandleAccept_CrossUserReturns404(t *testing.T) {
	repo := tsrepos.OpenMemory(t).IncomingInvites
	invite := createInviteForUser(t, repo, userAID, "accept-token", "sender.example.com")

	userB := &identity.User{ID: userBID, Username: "bob"}
	router := newTestRouter(t, repo, userB)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/inbox/invites/"+invite.ID+"/accept", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 for cross-user accept, got %d", w.Code)
	}
}

func TestHandleAccept_NonexistentReturns404(t *testing.T) {
	repo := tsrepos.OpenMemory(t).IncomingInvites
	userA := &identity.User{ID: userAID, Username: "alice"}
	router := newTestRouter(t, repo, userA)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/inbox/invites/nonexistent-id/accept", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestHandleAccept_IdempotentForAlreadyAccepted(t *testing.T) {
	repo := tsrepos.OpenMemory(t).IncomingInvites
	invite := createInviteForUser(t, repo, userAID, "idem-accept-token", "sender.example.com")

	if err := repo.UpdateStatusForRecipientUserID(context.Background(), invite.ID, userAID, invites.InviteStatusAccepted, &invitesincoming.Acceptance{
		UserID:                 "remote-sender@sender.example.com",
		ProviderFQDN:           "sender.example.com",
		ProviderFQDNNormalized: "sender.example.com",
	}); err != nil {
		t.Fatalf("UpdateStatusForRecipientUserID: %v", err)
	}

	userA := &identity.User{ID: userAID, Username: "alice"}
	router := newTestRouter(t, repo, userA)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/inbox/invites/"+invite.ID+"/accept", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for idempotent accept, got %d", w.Code)
	}
}

func TestHandleAccept_ConflictForDeclinedInvite(t *testing.T) {
	repo := tsrepos.OpenMemory(t).IncomingInvites
	invite := createInviteForUser(t, repo, userAID, "conflict-token", "sender.example.com")

	// Decline normally deletes; manually set declined to test accept-after-decline returns 409
	if err := repo.UpdateStatusForRecipientUserID(context.Background(), invite.ID, userAID, invites.InviteStatusDeclined, nil); err != nil {
		t.Fatalf("UpdateStatusForRecipientUserID: %v", err)
	}

	userA := &identity.User{ID: userAID, Username: "alice"}
	router := newTestRouter(t, repo, userA)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/inbox/invites/"+invite.ID+"/accept", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusConflict {
		t.Errorf("expected 409 for accepting a declined invite, got %d", w.Code)
	}
}

func TestHandleAccept_Unauthenticated(t *testing.T) {
	repo := tsrepos.OpenMemory(t).IncomingInvites
	router := newTestRouter(t, repo, nil)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/inbox/invites/some-id/accept", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestHandleAccept_StrictPolicyWithoutSignerReturnsBadGateway(t *testing.T) {
	repo := tsrepos.OpenMemory(t).IncomingInvites

	senderServer, inviteAcceptedCalls, _ := startInviteSenderServer(t)
	defer senderServer.Close()

	senderFQDN := strings.TrimPrefix(senderServer.URL, "https://")
	invite := createInviteForUser(t, repo, userAID, "strict-accept-token", senderFQDN)

	requestClient, discoveryClient := newTestOutboundClients(t)
	userA := &identity.User{ID: userAID, Username: "alice"}
	router := newTestRouterWithDeps(t,
		repo,
		userA,
		requestClient,
		discoveryClient,
	)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/inbox/invites/"+invite.ID+"/accept", nil)
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

func TestHandleAccept_PersistsRemoteSenderIdentity(t *testing.T) {
	repo := tsrepos.OpenMemory(t).IncomingInvites

	remoteSenderUserID := address.EncodeFederatedOpaqueID("remote-inviter-uuid", "sender.example.com")

	var srv *httptest.Server

	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/ocm":
			w.Header().Set("Content-Type", "application/json")
			mustEncodeJSON(t, w, spec.Discovery{
				Enabled:       true,
				APIVersion:    "1.4.0",
				EndPoint:      srv.URL + "/ocm",
				Capabilities:  []string{"exchange-token"},
				TokenEndPoint: srv.URL + "/ocm/token",
			})
		case "/ocm/invite-accepted":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			mustEncodeJSON(t, w, spec.InviteAcceptedResponse{
				UserID: remoteSenderUserID,
				Email:  "inviter@sender.example.com",
				Name:   "Remote Inviter",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	senderFQDN := strings.TrimPrefix(srv.URL, "https://")
	invite := createInviteForUser(t, repo, userAID, "persist-sender-token", senderFQDN)

	requestClient, discoveryClient := newTestOutboundClients(t)
	userA := &identity.User{ID: userAID, Username: "alice"}
	router := newTestRouterWithDeps(t,
		repo,
		userA,
		requestClient,
		discoveryClient,
	)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/inbox/invites/"+invite.ID+"/accept", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	stored, err := repo.GetByIDForRecipientUserID(context.Background(), invite.ID, userAID)
	if err != nil {
		t.Fatalf("expected invite to be stored: %v", err)
	}

	if stored.SenderUserID != remoteSenderUserID {
		t.Errorf("SenderUserID = %q, want %q", stored.SenderUserID, remoteSenderUserID)
	}

	if stored.SenderFQDNNormalized != senderFQDN {
		t.Errorf("SenderFQDNNormalized = %q, want %q", stored.SenderFQDNNormalized, senderFQDN)
	}
}

func TestHandleAccept_RecipientProviderStripsDefaultHTTPSPort(t *testing.T) {
	const originWithDefaultPort = "https://example.com:443"

	wantProvider := tslocalid.MustTestIdentity(t, originWithDefaultPort, "").ProviderDomain
	if wantProvider != "example.com" {
		t.Fatalf("test setup: ProviderDomain = %q, want example.com", wantProvider)
	}

	repo := tsrepos.OpenMemory(t).IncomingInvites
	inviteAcceptedCalls := &atomic.Int32{}

	var capturedRecipientProvider string

	var srv *httptest.Server

	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/ocm":
			w.Header().Set("Content-Type", "application/json")
			mustEncodeJSON(t, w, spec.Discovery{
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

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			mustEncodeJSON(t, w, spec.InviteAcceptedResponse{
				UserID: "remote-sender@sender.example",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	senderFQDN := strings.TrimPrefix(srv.URL, "https://")
	invite := createInviteForUser(t, repo, userAID, "default-port-accept-token", senderFQDN)

	requestClient, discoveryClient := newTestOutboundClients(t)
	userA := &identity.User{ID: userAID, Username: "alice"}

	km := crypto.NewKeyManager("", testPublicOrigin)
	if err := km.LoadOrGenerate(); err != nil {
		t.Fatal(err)
	}

	signer := crypto.NewRFC9421Signer(km)
	localIdentity := tslocalid.MustTestIdentity(t, originWithDefaultPort, "")
	h := inboxinvites.NewHandler(
		repo,
		&testInviteAcceptedPoster{poster: outbound.NewPoster(requestClient, discoveryClient, signer, nil)},
		wantProvider,
		localIdentity.Scheme,
		currentUserFunc(userA),
		testLogger,
	)
	r := chi.NewRouter()
	r.Route("/inbox/invites", func(r chi.Router) {
		r.Post("/{inviteId}/accept", h.HandleAccept)
	})

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/inbox/invites/"+invite.ID+"/accept", nil)
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

// startConfigurableSenderServer returns a sender mock whose invite-accepted
// endpoint answers with the given status and body.
func startConfigurableSenderServer(t *testing.T, status int, respBody string) (*httptest.Server, *atomic.Int32) {
	t.Helper()

	inviteAcceptedCalls := &atomic.Int32{}

	var srv *httptest.Server

	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/ocm":
			w.Header().Set("Content-Type", "application/json")
			mustEncodeJSON(t, w, spec.Discovery{
				Enabled:       true,
				APIVersion:    "1.4.0",
				EndPoint:      srv.URL + "/ocm",
				Capabilities:  []string{"exchange-token"},
				TokenEndPoint: srv.URL + "/ocm/token",
			})
		case "/ocm/invite-accepted":
			inviteAcceptedCalls.Add(1)

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)

			if _, err := w.Write([]byte(respBody)); err != nil {
				t.Errorf("write response: %v", err)
			}
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	return srv, inviteAcceptedCalls
}

// TestHandleAccept_PersistFailureReturns5xx verifies a local update failure
// after a successful invite-accepted call surfaces as 5xx, leaving the
// invite pending for retry.
func TestHandleAccept_PersistFailureReturns5xx(t *testing.T) {
	mem := tsrepos.OpenMemory(t).IncomingInvites

	senderServer, _ := startConfigurableSenderServer(t, http.StatusCreated,
		`{"userID":"remote-sender@sender.example","email":"s@example","name":"Sender"}`)

	senderFQDN := strings.TrimPrefix(senderServer.URL, "https://")
	invite := createInviteForUser(t, mem, userAID, "persist-fail-token", senderFQDN)

	repo := &failingUpdateRepo{mem}
	requestClient, discoveryClient := newTestOutboundClients(t)
	userA := &identity.User{ID: userAID, Username: "alice"}
	router := newTestRouterWithDeps(t, repo, userA, requestClient, discoveryClient)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/inbox/invites/"+invite.ID+"/accept", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 on persist failure, got %d: %s", w.Code, w.Body.String())
	}

	stored, err := mem.GetByIDForRecipientUserID(context.Background(), invite.ID, userAID)
	if err != nil {
		t.Fatalf("expected invite to remain after failed accept: %v", err)
	}

	if stored.Status != invites.InviteStatusPending {
		t.Errorf("expected invite to remain pending, got %s", stored.Status)
	}
}

// TestHandleAccept_ConflictWithIdentityCompensates verifies the retry path
// after a local persist failure: the sender answers 409 INVITE_ALREADY_ACCEPTED
// with its identity body, which is idempotent success — the handler persists
// accepted state plus sender identity and returns 200.
func TestHandleAccept_ConflictWithIdentityCompensates(t *testing.T) {
	repo := tsrepos.OpenMemory(t).IncomingInvites

	senderServer, _ := startConfigurableSenderServer(t, http.StatusConflict,
		`{"userID":"remote-sender@sender.example","email":"s@example","name":"Sender"}`)

	senderFQDN := strings.TrimPrefix(senderServer.URL, "https://")
	invite := createInviteForUser(t, repo, userAID, "conflict-comp-token", senderFQDN)

	requestClient, discoveryClient := newTestOutboundClients(t)
	userA := &identity.User{ID: userAID, Username: "alice"}
	router := newTestRouterWithDeps(t, repo, userA, requestClient, discoveryClient)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/inbox/invites/"+invite.ID+"/accept", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for 409-with-identity compensation, got %d: %s", w.Code, w.Body.String())
	}

	stored, err := repo.GetByIDForRecipientUserID(context.Background(), invite.ID, userAID)
	if err != nil {
		t.Fatalf("expected invite to be stored: %v", err)
	}

	if stored.Status != invites.InviteStatusAccepted {
		t.Errorf("expected accepted status after compensation, got %s", stored.Status)
	}

	if stored.SenderUserID != "remote-sender@sender.example" {
		t.Errorf("SenderUserID = %q, want remote-sender@sender.example", stored.SenderUserID)
	}

	if stored.SenderFQDNNormalized != senderFQDN {
		t.Errorf("SenderFQDNNormalized = %q, want %q", stored.SenderFQDNNormalized, senderFQDN)
	}
}

// assertPeerErrorLeavesInvitePending drives an accept against a sender
// endpoint returning the given status and body, asserts the handler maps it to
// the expected HTTP status, and asserts the invite stays pending.
func assertPeerErrorLeavesInvitePending(t *testing.T, peerStatus int, peerBody, token string, wantStatus int) {
	t.Helper()

	repo := tsrepos.OpenMemory(t).IncomingInvites

	senderServer, _ := startConfigurableSenderServer(t, peerStatus, peerBody)

	senderFQDN := strings.TrimPrefix(senderServer.URL, "https://")
	invite := createInviteForUser(t, repo, userAID, token, senderFQDN)

	requestClient, discoveryClient := newTestOutboundClients(t)
	userA := &identity.User{ID: userAID, Username: "alice"}
	router := newTestRouterWithDeps(t, repo, userA, requestClient, discoveryClient)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/inbox/invites/"+invite.ID+"/accept", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != wantStatus {
		t.Fatalf("expected %d, got %d: %s", wantStatus, w.Code, w.Body.String())
	}

	stored, err := repo.GetByIDForRecipientUserID(context.Background(), invite.ID, userAID)
	if err != nil {
		t.Fatalf("expected invite to remain: %v", err)
	}

	if stored.Status != invites.InviteStatusPending {
		t.Errorf("expected invite to remain pending, got %s", stored.Status)
	}
}

// TestHandleAccept_BodylessConflictReturns502 verifies a 409 without a
// decodable identity body is an honest 502.
func TestHandleAccept_BodylessConflictReturns502(t *testing.T) {
	assertPeerErrorLeavesInvitePending(t, http.StatusConflict, ``, "bodyless-conflict-token", http.StatusBadGateway)
}

// TestHandleAccept_EmptyPeerUserIDReturns502 verifies a 201 response without
// userID is rejected as 502 and never marks the invite accepted.
func TestHandleAccept_EmptyPeerUserIDReturns502(t *testing.T) {
	assertPeerErrorLeavesInvitePending(t, http.StatusCreated, `{"status":"ok"}`, "empty-userid-token", http.StatusBadGateway)
}

// TestHandleAccept_MalformedStoredSenderFailsClosed verifies a stored sender
// host that fails normalization returns an internal error before any outbound
// call or persistence (no lowercase fallback).
func TestHandleAccept_MalformedStoredSenderFailsClosed(t *testing.T) {
	repo := tsrepos.OpenMemory(t).IncomingInvites

	senderServer, inviteAcceptedCalls := startConfigurableSenderServer(t, http.StatusCreated,
		`{"userID":"remote-sender@sender.example"}`)
	_ = senderServer

	invite := createInviteForUser(t, repo, userAID, "malformed-sender-token", "bad host")

	requestClient, discoveryClient := newTestOutboundClients(t)
	userA := &identity.User{ID: userAID, Username: "alice"}
	router := newTestRouterWithDeps(t, repo, userA, requestClient, discoveryClient)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/inbox/invites/"+invite.ID+"/accept", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 for malformed stored sender, got %d: %s", w.Code, w.Body.String())
	}

	if inviteAcceptedCalls.Load() != 0 {
		t.Errorf("expected no outbound invite-accepted call, got %d", inviteAcceptedCalls.Load())
	}

	stored, err := repo.GetByIDForRecipientUserID(context.Background(), invite.ID, userAID)
	if err != nil {
		t.Fatalf("expected invite to remain: %v", err)
	}

	if stored.Status != invites.InviteStatusPending {
		t.Errorf("expected invite to remain pending, got %s", stored.Status)
	}
}
