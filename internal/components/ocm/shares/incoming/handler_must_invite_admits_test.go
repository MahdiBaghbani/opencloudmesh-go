// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package incoming_test

import (
	"context"
	"net/http"
	"strings"
	"testing"

	tsrepos "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/repos"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/address"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites"
	invitesincoming "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites/incoming"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/reason"
)

func TestMustInviteGate_PendingInviteDoesNotAdmit(t *testing.T) {
	t.Parallel()
	repo := tsrepos.OpenMemory(t).IncomingShares
	incomingInvites := tsrepos.OpenMemory(t).IncomingInvites

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
		setupTestPartyRepo(t),
		incomingInvites,
		tsrepos.OpenMemory(t).OutgoingInvites,
		true,
	)

	body := mustInviteShareBody(mustInviteSenderString(t), "mi-pending")
	w := postShare(t, handler, body)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
	}
}

func TestMustInviteGate_IncomingInviteExactMatchAdmits(t *testing.T) {
	t.Parallel()
	repo := tsrepos.OpenMemory(t).IncomingShares
	incomingInvites := tsrepos.OpenMemory(t).IncomingInvites

	seedAcceptedIncomingInvite(t, incomingInvites,
		address.EncodeFederatedOpaqueID(mustInviteRemoteUser, mustInviteRemoteHost), mustInviteRemoteHost)

	handler := newTestHandlerWithInvites(
		repo,
		setupTestPartyRepo(t),
		incomingInvites,
		tsrepos.OpenMemory(t).OutgoingInvites,
		true,
	)

	body := mustInviteShareBody(mustInviteSenderString(t), "mi-in-match")
	w := postShare(t, handler, body)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}
}

func TestMustInviteGate_OutgoingInviteExactMatchAdmits(t *testing.T) {
	t.Parallel()
	repo := tsrepos.OpenMemory(t).IncomingShares
	outgoingInvites := tsrepos.OpenMemory(t).OutgoingInvites

	seedAcceptedOutgoingInvite(t, outgoingInvites, mustInviteRecipientID,
		address.EncodeFederatedOpaqueID(mustInviteRemoteUser, mustInviteRemoteHost), mustInviteRemoteHost)

	handler := newTestHandlerWithInvites(
		repo,
		setupTestPartyRepo(t),
		tsrepos.OpenMemory(t).IncomingInvites,
		outgoingInvites,
		true,
	)

	body := mustInviteShareBody(mustInviteSenderString(t), "mi-out-match")
	w := postShare(t, handler, body)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}
}

func TestMustInviteGate_DuplicateAdmittedReturns201(t *testing.T) {
	t.Parallel()
	repo := tsrepos.OpenMemory(t).IncomingShares
	incomingInvites := tsrepos.OpenMemory(t).IncomingInvites

	seedAcceptedIncomingInvite(t, incomingInvites,
		address.EncodeFederatedOpaqueID(mustInviteRemoteUser, mustInviteRemoteHost), mustInviteRemoteHost)

	handler := newTestHandlerWithInvites(
		repo,
		setupTestPartyRepo(t),
		incomingInvites,
		tsrepos.OpenMemory(t).OutgoingInvites,
		true,
	)

	body := mustInviteShareBody(mustInviteSenderString(t), "mi-duplicate")

	first := postShare(t, handler, body)
	if first.Code != http.StatusCreated {
		t.Fatalf("expected 201 on first post, got %d: %s", first.Code, first.Body.String())
	}

	second := postShare(t, handler, body)
	if second.Code != http.StatusCreated {
		t.Fatalf("expected 201 on duplicate post, got %d: %s", second.Code, second.Body.String())
	}
}

func TestMustInviteGate_IncomingStorageFailureReturns500(t *testing.T) {
	t.Parallel()
	repo := tsrepos.OpenMemory(t).IncomingShares
	handler := newTestHandlerWithInvites(
		repo,
		setupTestPartyRepo(t),
		&failingIncomingInviteRepo{tsrepos.OpenMemory(t).IncomingInvites},
		tsrepos.OpenMemory(t).OutgoingInvites,
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
	t.Parallel()
	repo := tsrepos.OpenMemory(t).IncomingShares
	handler := newTestHandlerWithInvites(
		repo,
		setupTestPartyRepo(t),
		tsrepos.OpenMemory(t).IncomingInvites,
		&failingOutgoingInviteRepo{tsrepos.OpenMemory(t).OutgoingInvites},
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
	t.Parallel()
	repo := tsrepos.OpenMemory(t).IncomingShares
	handler := newTestHandlerWithInvites(
		repo,
		setupTestPartyRepo(t),
		tsrepos.OpenMemory(t).IncomingInvites,
		tsrepos.OpenMemory(t).OutgoingInvites,
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
// exists for the body sender. The owner host matches the authority so the
// request reaches the must-invite gate, where the sender mismatch is caught.
func TestMustInviteGate_AuthenticatedAuthorityMismatchReturns403(t *testing.T) {
	t.Parallel()
	repo := tsrepos.OpenMemory(t).IncomingShares
	incomingInvites := tsrepos.OpenMemory(t).IncomingInvites

	seedAcceptedIncomingInvite(t, incomingInvites,
		address.EncodeFederatedOpaqueID(mustInviteRemoteUser, mustInviteRemoteHost), mustInviteRemoteHost)

	handler := newTestHandlerWithInvites(
		repo,
		setupTestPartyRepo(t),
		incomingInvites,
		tsrepos.OpenMemory(t).OutgoingInvites,
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
// authenticated authority and admits on the persisted invite.
func TestMustInviteGate_AuthenticatedDefaultPortEquivalentAdmits(t *testing.T) {
	t.Parallel()
	repo := tsrepos.OpenMemory(t).IncomingShares
	incomingInvites := tsrepos.OpenMemory(t).IncomingInvites

	seedAcceptedIncomingInvite(t, incomingInvites,
		address.EncodeFederatedOpaqueID(mustInviteRemoteUser, mustInviteRemoteHost), mustInviteRemoteHost)

	handler := newTestHandlerWithInvites(
		repo,
		setupTestPartyRepo(t),
		incomingInvites,
		tsrepos.OpenMemory(t).OutgoingInvites,
		true,
	)

	senderWithDefaultPort := address.EncodeFederatedOpaqueID(mustInviteRemoteUser, mustInviteRemoteHost) + "@" + mustInviteRemoteHost + ":443"
	body := mustInviteShareBody(senderWithDefaultPort, "mi-default-port")
	w := postShareAuthenticated(t, handler, body, mustInviteRemoteHost)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201 for default-port-equivalent sender, got %d: %s", w.Code, w.Body.String())
	}
}
