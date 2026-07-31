// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package incoming_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/address"
	inboundsignature "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/inbound/signature"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites"
	invitesincoming "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites/incoming"
	invitesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/reason"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/incoming"
)

const (
	mustInviteRecipientID = "user-a-uuid"
	mustInviteRemoteUser  = "remote-user-uuid"
	mustInviteRemoteHost  = "sender.com"
)

// mustInviteShareBody builds a valid webdav share request with an explicit
// sender string, so gate tests control the sender identity directly.
func mustInviteShareBody(sender, providerID string) string {
	return `{
		"shareWith": "alice@localhost:9200",
		"name": "test.txt",
		"providerId": "` + providerID + `",
		"owner": "owner@` + mustInviteRemoteHost + `",
		"sender": "` + sender + `",
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
}

// mustInviteSenderString formats the canonical remote sender address for the
// fixed remote user on the fixed remote host.
func mustInviteSenderString(t *testing.T) string {
	t.Helper()

	return address.EncodeFederatedOpaqueID(mustInviteRemoteUser, mustInviteRemoteHost) + "@" + mustInviteRemoteHost
}

func seedAcceptedIncomingInvite(t *testing.T, repo *invitesincoming.MemoryIncomingInviteRepo, senderUserID, senderHost string) {
	t.Helper()

	invite := &invitesincoming.IncomingInvite{
		Token:                "must-invite-in-token",
		SenderFQDN:           senderHost,
		RecipientUserID:      mustInviteRecipientID,
		Status:               invites.InviteStatusAccepted,
		SenderUserID:         senderUserID,
		SenderFQDNNormalized: senderHost,
	}
	if err := repo.Create(context.Background(), invite); err != nil {
		t.Fatalf("seed incoming invite: %v", err)
	}
}

func seedAcceptedOutgoingInvite(t *testing.T, repo *invitesoutgoing.MemoryOutgoingInviteRepo, creatorID, accepterUserID, accepterHost string) {
	t.Helper()

	invite := &invitesoutgoing.OutgoingInvite{
		Token:                          "must-invite-out-token",
		ProviderFQDN:                   accepterHost,
		CreatedByUserID:                creatorID,
		Status:                         invites.InviteStatusAccepted,
		AcceptedUserID:                 accepterUserID,
		AcceptedProviderFQDNNormalized: accepterHost,
	}
	if err := repo.Create(context.Background(), invite); err != nil {
		t.Fatalf("seed outgoing invite: %v", err)
	}
}

// failingIncomingInviteRepo wraps the memory repo with a storage failure on
// FindAcceptedForSender to exercise the STORAGE_ERROR branch.
type failingIncomingInviteRepo struct {
	*invitesincoming.MemoryIncomingInviteRepo
}

func (f *failingIncomingInviteRepo) FindAcceptedForSender(context.Context, string, string, string) (*invitesincoming.IncomingInvite, error) {
	return nil, errors.New("storage unavailable")
}

// failingOutgoingInviteRepo wraps the memory repo with a storage failure on
// FindAcceptedForRecipient to exercise the STORAGE_ERROR branch.
type failingOutgoingInviteRepo struct {
	*invitesoutgoing.MemoryOutgoingInviteRepo
}

func (f *failingOutgoingInviteRepo) FindAcceptedForRecipient(context.Context, string, string, string) (*invitesoutgoing.OutgoingInvite, error) {
	return nil, errors.New("storage unavailable")
}

func postShare(t *testing.T, handler interface {
	CreateShare(w http.ResponseWriter, r *http.Request)
}, body string,
) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequest(http.MethodPost, "/ocm/shares", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	handler.CreateShare(w, req)

	return w
}

// postShareAuthenticated posts a share carrying an authenticated peer identity
// for the given authority, so gate tests exercise the authenticated path.
func postShareAuthenticated(t *testing.T, handler interface {
	CreateShare(w http.ResponseWriter, r *http.Request)
}, body, authority string,
) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequest(http.MethodPost, "/ocm/shares", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	ctx := context.WithValue(req.Context(), inboundsignature.PeerIdentityKey, &inboundsignature.PeerIdentity{
		Authority:           authority,
		AuthorityForCompare: authority,
		Authenticated:       true,
	})
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	handler.CreateShare(w, req)

	return w
}

func TestMustInviteGate_EnforcedNoInviteReturns403(t *testing.T) {
	repo := incoming.NewMemoryIncomingShareRepo()
	handler := newTestHandlerWithInvites(
		repo,
		setupTestPartyRepo(),
		invitesincoming.NewMemoryIncomingInviteRepo(),
		invitesoutgoing.NewMemoryOutgoingInviteRepo(),
		true,
	)

	body := mustInviteShareBody(mustInviteSenderString(t), "mi-no-invite")
	w := postShare(t, handler, body)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
	}

	if !strings.Contains(w.Body.String(), reason.SenderNotTrusted) {
		t.Errorf("expected %s message, got %s", reason.SenderNotTrusted, w.Body.String())
	}
}

func TestMustInviteGate_MalformedSenderRejected(t *testing.T) {
	repo := incoming.NewMemoryIncomingShareRepo()
	handler := newTestHandlerWithInvites(
		repo,
		setupTestPartyRepo(),
		invitesincoming.NewMemoryIncomingInviteRepo(),
		invitesoutgoing.NewMemoryOutgoingInviteRepo(),
		true,
	)

	// A sender missing the '@' separator is rejected earlier as a 400 format
	// error; the must-invite gate's own sender rejection is exercised with an
	// authenticated peer whose body sender parses but cannot be normalized.
	body := mustInviteShareBody("user@bad host", "mi-malformed")
	w := postShareAuthenticated(t, handler, body, mustInviteRemoteHost)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
	}

	if !strings.Contains(w.Body.String(), reason.SenderNotTrusted) {
		t.Errorf("expected %s message, got %s", reason.SenderNotTrusted, w.Body.String())
	}
}

func TestMustInviteGate_HostMatchUserMismatchReturns403(t *testing.T) {
	repo := incoming.NewMemoryIncomingShareRepo()
	incomingInvites := invitesincoming.NewMemoryIncomingInviteRepo()

	seedAcceptedIncomingInvite(t, incomingInvites,
		address.EncodeFederatedOpaqueID("other-remote-user", mustInviteRemoteHost), mustInviteRemoteHost)

	handler := newTestHandlerWithInvites(
		repo,
		setupTestPartyRepo(),
		incomingInvites,
		invitesoutgoing.NewMemoryOutgoingInviteRepo(),
		true,
	)

	body := mustInviteShareBody(mustInviteSenderString(t), "mi-user-mismatch")
	w := postShare(t, handler, body)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
	}

	if !strings.Contains(w.Body.String(), reason.SenderNotTrusted) {
		t.Errorf("expected %s message, got %s", reason.SenderNotTrusted, w.Body.String())
	}
}

func TestMustInviteGate_UserMatchHostMismatchReturns403(t *testing.T) {
	repo := incoming.NewMemoryIncomingShareRepo()
	incomingInvites := invitesincoming.NewMemoryIncomingInviteRepo()

	seedAcceptedIncomingInvite(t, incomingInvites,
		address.EncodeFederatedOpaqueID(mustInviteRemoteUser, "other.example.com"), "other.example.com")

	handler := newTestHandlerWithInvites(
		repo,
		setupTestPartyRepo(),
		incomingInvites,
		invitesoutgoing.NewMemoryOutgoingInviteRepo(),
		true,
	)

	body := mustInviteShareBody(mustInviteSenderString(t), "mi-host-mismatch")
	w := postShare(t, handler, body)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
	}

	if !strings.Contains(w.Body.String(), reason.SenderNotTrusted) {
		t.Errorf("expected %s message, got %s", reason.SenderNotTrusted, w.Body.String())
	}
}

func TestMustInviteGate_PendingInviteDoesNotAdmit(t *testing.T) {
	repo := incoming.NewMemoryIncomingShareRepo()
	incomingInvites := invitesincoming.NewMemoryIncomingInviteRepo()

	pending := &invitesincoming.IncomingInvite{
		Token:                "must-invite-pending-token",
		SenderFQDN:           mustInviteRemoteHost,
		RecipientUserID:      mustInviteRecipientID,
		Status:               invites.InviteStatusPending,
		SenderUserID:         address.EncodeFederatedOpaqueID(mustInviteRemoteUser, mustInviteRemoteHost),
		SenderFQDNNormalized: mustInviteRemoteHost,
	}
	if err := incomingInvites.Create(context.Background(), pending); err != nil {
		t.Fatalf("seed pending invite: %v", err)
	}

	handler := newTestHandlerWithInvites(
		repo,
		setupTestPartyRepo(),
		incomingInvites,
		invitesoutgoing.NewMemoryOutgoingInviteRepo(),
		true,
	)

	body := mustInviteShareBody(mustInviteSenderString(t), "mi-pending")
	w := postShare(t, handler, body)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
	}
}

func TestMustInviteGate_IncomingInviteExactMatchAdmits(t *testing.T) {
	repo := incoming.NewMemoryIncomingShareRepo()
	incomingInvites := invitesincoming.NewMemoryIncomingInviteRepo()

	seedAcceptedIncomingInvite(t, incomingInvites,
		address.EncodeFederatedOpaqueID(mustInviteRemoteUser, mustInviteRemoteHost), mustInviteRemoteHost)

	handler := newTestHandlerWithInvites(
		repo,
		setupTestPartyRepo(),
		incomingInvites,
		invitesoutgoing.NewMemoryOutgoingInviteRepo(),
		true,
	)

	body := mustInviteShareBody(mustInviteSenderString(t), "mi-in-match")
	w := postShare(t, handler, body)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}
}

func TestMustInviteGate_OutgoingInviteExactMatchAdmits(t *testing.T) {
	repo := incoming.NewMemoryIncomingShareRepo()
	outgoingInvites := invitesoutgoing.NewMemoryOutgoingInviteRepo()

	seedAcceptedOutgoingInvite(t, outgoingInvites, mustInviteRecipientID,
		address.EncodeFederatedOpaqueID(mustInviteRemoteUser, mustInviteRemoteHost), mustInviteRemoteHost)

	handler := newTestHandlerWithInvites(
		repo,
		setupTestPartyRepo(),
		invitesincoming.NewMemoryIncomingInviteRepo(),
		outgoingInvites,
		true,
	)

	body := mustInviteShareBody(mustInviteSenderString(t), "mi-out-match")
	w := postShare(t, handler, body)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}
}

func TestMustInviteGate_DuplicateAdmittedReturns200(t *testing.T) {
	repo := incoming.NewMemoryIncomingShareRepo()
	incomingInvites := invitesincoming.NewMemoryIncomingInviteRepo()

	seedAcceptedIncomingInvite(t, incomingInvites,
		address.EncodeFederatedOpaqueID(mustInviteRemoteUser, mustInviteRemoteHost), mustInviteRemoteHost)

	handler := newTestHandlerWithInvites(
		repo,
		setupTestPartyRepo(),
		incomingInvites,
		invitesoutgoing.NewMemoryOutgoingInviteRepo(),
		true,
	)

	body := mustInviteShareBody(mustInviteSenderString(t), "mi-duplicate")

	first := postShare(t, handler, body)
	if first.Code != http.StatusCreated {
		t.Fatalf("expected 201 on first post, got %d: %s", first.Code, first.Body.String())
	}

	second := postShare(t, handler, body)
	if second.Code != http.StatusOK {
		t.Fatalf("expected 200 on duplicate post, got %d: %s", second.Code, second.Body.String())
	}
}

func TestMustInviteGate_IncomingStorageFailureReturns500(t *testing.T) {
	repo := incoming.NewMemoryIncomingShareRepo()
	handler := newTestHandlerWithInvites(
		repo,
		setupTestPartyRepo(),
		&failingIncomingInviteRepo{invitesincoming.NewMemoryIncomingInviteRepo()},
		invitesoutgoing.NewMemoryOutgoingInviteRepo(),
		true,
	)

	body := mustInviteShareBody(mustInviteSenderString(t), "mi-storage-in")
	w := postShare(t, handler, body)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d: %s", w.Code, w.Body.String())
	}

	if !strings.Contains(w.Body.String(), reason.StorageError) {
		t.Errorf("expected %s message, got %s", reason.StorageError, w.Body.String())
	}
}

func TestMustInviteGate_OutgoingStorageFailureReturns500(t *testing.T) {
	repo := incoming.NewMemoryIncomingShareRepo()
	handler := newTestHandlerWithInvites(
		repo,
		setupTestPartyRepo(),
		invitesincoming.NewMemoryIncomingInviteRepo(),
		&failingOutgoingInviteRepo{invitesoutgoing.NewMemoryOutgoingInviteRepo()},
		true,
	)

	body := mustInviteShareBody(mustInviteSenderString(t), "mi-storage-out")
	w := postShare(t, handler, body)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d: %s", w.Code, w.Body.String())
	}

	if !strings.Contains(w.Body.String(), reason.StorageError) {
		t.Errorf("expected %s message, got %s", reason.StorageError, w.Body.String())
	}
}

func TestMustInviteGate_OptOutRetainsLegacyAcceptance(t *testing.T) {
	repo := incoming.NewMemoryIncomingShareRepo()
	handler := newTestHandlerWithInvites(
		repo,
		setupTestPartyRepo(),
		invitesincoming.NewMemoryIncomingInviteRepo(),
		invitesoutgoing.NewMemoryOutgoingInviteRepo(),
		false,
	)

	body := mustInviteShareBody(mustInviteSenderString(t), "mi-opt-out")
	w := postShare(t, handler, body)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201 with enforcement disabled and no invite, got %d: %s", w.Code, w.Body.String())
	}
}

// TestMustInviteGate_AuthenticatedAuthorityMismatchReturns403 verifies the
// anti-spoof check: an authenticated peer whose signature authority does not
// match the normalized body sender host is rejected even when a valid invite
// exists for the body sender (C4). The owner host matches the authority so the
// request reaches the must-invite gate, where the sender mismatch is caught.
func TestMustInviteGate_AuthenticatedAuthorityMismatchReturns403(t *testing.T) {
	repo := incoming.NewMemoryIncomingShareRepo()
	incomingInvites := invitesincoming.NewMemoryIncomingInviteRepo()

	seedAcceptedIncomingInvite(t, incomingInvites,
		address.EncodeFederatedOpaqueID(mustInviteRemoteUser, mustInviteRemoteHost), mustInviteRemoteHost)

	handler := newTestHandlerWithInvites(
		repo,
		setupTestPartyRepo(),
		incomingInvites,
		invitesoutgoing.NewMemoryOutgoingInviteRepo(),
		true,
	)

	body := `{
		"shareWith": "alice@localhost:9200",
		"name": "test.txt",
		"providerId": "mi-authority-mismatch",
		"owner": "owner@attacker.example",
		"sender": "` + mustInviteSenderString(t) + `",
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
	w := postShareAuthenticated(t, handler, body, "attacker.example")

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
	}

	if !strings.Contains(w.Body.String(), reason.SenderNotTrusted) {
		t.Errorf("expected %s message, got %s", reason.SenderNotTrusted, w.Body.String())
	}
}

// TestMustInviteGate_AuthenticatedDefaultPortEquivalentAdmits verifies a body
// sender host carrying the scheme's default port normalizes to the
// authenticated authority and admits on the persisted invite (C4).
func TestMustInviteGate_AuthenticatedDefaultPortEquivalentAdmits(t *testing.T) {
	repo := incoming.NewMemoryIncomingShareRepo()
	incomingInvites := invitesincoming.NewMemoryIncomingInviteRepo()

	seedAcceptedIncomingInvite(t, incomingInvites,
		address.EncodeFederatedOpaqueID(mustInviteRemoteUser, mustInviteRemoteHost), mustInviteRemoteHost)

	handler := newTestHandlerWithInvites(
		repo,
		setupTestPartyRepo(),
		incomingInvites,
		invitesoutgoing.NewMemoryOutgoingInviteRepo(),
		true,
	)

	senderWithDefaultPort := address.EncodeFederatedOpaqueID(mustInviteRemoteUser, mustInviteRemoteHost) + "@" + mustInviteRemoteHost + ":443"
	body := mustInviteShareBody(senderWithDefaultPort, "mi-default-port")
	w := postShareAuthenticated(t, handler, body, mustInviteRemoteHost)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201 for default-port-equivalent sender, got %d: %s", w.Code, w.Body.String())
	}
}
