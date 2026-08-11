// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package incoming_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	inboundsignature "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/inbound/signature"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/notifications/incoming"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares"
	sharesincoming "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/incoming"
	sharesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	tsrepos "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/repos"
)

func decodeOCMMessage(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()

	var resp spec.OCMErrorResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v body=%q", err, w.Body.String())
	}

	return resp.Message
}

func postNotification(t *testing.T, handler *incoming.Handler, body string, senderHost string) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/ocm/notifications", bytes.NewBufferString(body))
	if senderHost != "" {
		ctx := context.WithValue(req.Context(), inboundsignature.PeerIdentityKey, &inboundsignature.PeerIdentity{
			AuthorityForCompare: senderHost,
			Authenticated:       true,
		})
		req = req.WithContext(ctx)
	}

	w := httptest.NewRecorder()
	handler.HandleNotification(w, req)

	return w
}

func TestHandleNotification_MissingFields(t *testing.T) {
	t.Parallel()

	repos := tsrepos.OpenMemory(t)
	handler := incoming.NewHandler(repos.OutgoingShares, repos.IncomingShares, "https", nil)

	w := postNotification(t, handler, `{}`, "sender.example.com")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestHandleNotification_ExperimentalTypeRejected(t *testing.T) {
	t.Parallel()

	repos := tsrepos.OpenMemory(t)
	handler := incoming.NewHandler(repos.OutgoingShares, repos.IncomingShares, "https", nil)

	w := postNotification(t, handler, `{"notificationType":"REQUEST_RESHARE","providerId":"p1"}`, "sender.example.com")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}

	if msg := decodeOCMMessage(t, w); msg != "INVALID_NOTIFICATION_REQUEST" {
		t.Fatalf("message = %q", msg)
	}
}

func TestHandleNotification_ShareAcceptedUpdatesOutgoing(t *testing.T) {
	t.Parallel()

	runOutgoingNotificationStatusTest(t, outgoingNotificationCase{
		notificationType: spec.NotificationTypeShareAccepted,
		providerID:       "provider-accepted",
		receiverHost:     "receiver.example.com",
		senderHost:       "receiver.example.com",
		initialStatus:    shares.OutgoingShareStatusSent,
		wantHTTP:         http.StatusOK,
		wantStatus:       shares.OutgoingShareStatusAccepted,
	})
}

func TestHandleNotification_ShareAcceptedIdempotent(t *testing.T) {
	t.Parallel()

	repos := tsrepos.OpenMemory(t)
	ctx := context.Background()

	share := &sharesoutgoing.OutgoingShare{
		ProviderID:   "provider-idem",
		ReceiverHost: "receiver.example.com",
		Status:       shares.OutgoingShareStatusAccepted,
		CreatedAt:    time.Now(),
	}
	if err := repos.OutgoingShares.Create(ctx, share); err != nil {
		t.Fatalf("create outgoing share: %v", err)
	}

	handler := incoming.NewHandler(repos.OutgoingShares, repos.IncomingShares, "https", nil)

	w := postNotification(t, handler, `{"notificationType":"SHARE_ACCEPTED","providerId":"provider-idem"}`, "receiver.example.com")
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestHandleNotification_ShareDeclinedUpdatesOutgoing(t *testing.T) {
	t.Parallel()

	runOutgoingNotificationStatusTest(t, outgoingNotificationCase{
		notificationType: spec.NotificationTypeShareDeclined,
		providerID:       "provider-declined",
		receiverHost:     "receiver.example.com",
		senderHost:       "receiver.example.com",
		initialStatus:    shares.OutgoingShareStatusSent,
		wantHTTP:         http.StatusOK,
		wantStatus:       shares.OutgoingShareStatusDeclined,
	})
}

func TestHandleNotification_ShareUnsharedUpdatesIncoming(t *testing.T) {
	t.Parallel()

	repos := tsrepos.OpenMemory(t)
	ctx := context.Background()

	inShare := &sharesincoming.IncomingShare{
		ProviderID:      "provider-unshared",
		SenderHost:      "sender.example.com",
		RecipientUserID: "user-a",
		Status:          shares.ShareStatusAccepted,
		CreatedAt:       time.Now(),
	}
	if err := repos.IncomingShares.Create(ctx, inShare); err != nil {
		t.Fatalf("create incoming share: %v", err)
	}

	handler := incoming.NewHandler(repos.OutgoingShares, repos.IncomingShares, "https", nil)

	w := postNotification(t, handler, `{"notificationType":"SHARE_UNSHARED","providerId":"provider-unshared"}`, "sender.example.com")
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	updated, err := repos.IncomingShares.GetByProviderID(ctx, "sender.example.com", "provider-unshared")
	if err != nil {
		t.Fatalf("get incoming share: %v", err)
	}

	if updated.Status != shares.ShareStatusUnshared {
		t.Fatalf("status = %q, want unshared", updated.Status)
	}
}

func TestHandleNotification_ShareUnsharedUnauthorizedSender(t *testing.T) {
	t.Parallel()

	repos := tsrepos.OpenMemory(t)
	ctx := context.Background()

	inShare := &sharesincoming.IncomingShare{
		ProviderID:      "provider-unauth-unshared",
		SenderHost:      "sender.example.com",
		RecipientUserID: "user-a",
		Status:          shares.ShareStatusAccepted,
		CreatedAt:       time.Now(),
	}
	if err := repos.IncomingShares.Create(ctx, inShare); err != nil {
		t.Fatalf("create incoming share: %v", err)
	}

	handler := incoming.NewHandler(
		repos.OutgoingShares,
		&incomingShareLookupStub{
			IncomingShareRepo: repos.IncomingShares,
			share:             inShare,
		},
		"https",
		nil,
	)

	w := postNotification(t, handler, `{"notificationType":"SHARE_UNSHARED","providerId":"provider-unauth-unshared"}`, "other.example.com")
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}

	if msg := decodeOCMMessage(t, w); msg != "SENDER_NOT_AUTHORIZED" {
		t.Fatalf("message = %q", msg)
	}

	updated, err := repos.IncomingShares.GetByProviderID(ctx, "sender.example.com", "provider-unauth-unshared")
	if err != nil {
		t.Fatalf("get incoming share: %v", err)
	}

	if updated.Status != shares.ShareStatusAccepted {
		t.Fatalf("status = %q, want accepted", updated.Status)
	}
}

type incomingShareLookupStub struct {
	sharesincoming.IncomingShareRepo

	share *sharesincoming.IncomingShare
}

func (s *incomingShareLookupStub) GetByProviderID(_ context.Context, _, providerID string) (*sharesincoming.IncomingShare, error) {
	if providerID != s.share.ProviderID {
		return nil, sharesincoming.ErrShareNotFound
	}

	return s.share, nil
}

func TestHandleNotification_OutgoingNotFound(t *testing.T) {
	t.Parallel()

	repos := tsrepos.OpenMemory(t)
	handler := incoming.NewHandler(repos.OutgoingShares, repos.IncomingShares, "https", nil)

	w := postNotification(t, handler, `{"notificationType":"SHARE_ACCEPTED","providerId":"missing"}`, "receiver.example.com")
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}

	if msg := decodeOCMMessage(t, w); msg != "SHARE_NOT_FOUND" {
		t.Fatalf("message = %q", msg)
	}
}

func TestHandleNotification_IncomingNotFound(t *testing.T) {
	t.Parallel()

	repos := tsrepos.OpenMemory(t)
	handler := incoming.NewHandler(repos.OutgoingShares, repos.IncomingShares, "https", nil)

	w := postNotification(t, handler, `{"notificationType":"SHARE_UNSHARED","providerId":"missing"}`, "sender.example.com")
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestHandleNotification_RequiresAuthenticatedPeer(t *testing.T) {
	t.Parallel()

	repos := tsrepos.OpenMemory(t)
	handler := incoming.NewHandler(repos.OutgoingShares, repos.IncomingShares, "https", nil)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/ocm/notifications", bytes.NewBufferString(`{"notificationType":"SHARE_ACCEPTED","providerId":"p1"}`))
	w := httptest.NewRecorder()
	handler.HandleNotification(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
}

type failingOutgoingRepo struct {
	sharesoutgoing.OutgoingShareRepo
}

func (f *failingOutgoingRepo) GetByProviderID(_ context.Context, _ string) (*sharesoutgoing.OutgoingShare, error) {
	return nil, errors.New("db unavailable")
}

func TestHandleNotification_RepoErrorReturns500(t *testing.T) {
	t.Parallel()

	repos := tsrepos.OpenMemory(t)
	handler := incoming.NewHandler(&failingOutgoingRepo{OutgoingShareRepo: repos.OutgoingShares}, repos.IncomingShares, "https", nil)

	w := postNotification(t, handler, `{"notificationType":"SHARE_ACCEPTED","providerId":"p1"}`, "receiver.example.com")
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", w.Code)
	}
}

func TestHandleNotification_ShareAcceptedUnauthorizedSender(t *testing.T) {
	t.Parallel()

	runOutgoingNotificationStatusTest(t, outgoingNotificationCase{
		notificationType: spec.NotificationTypeShareAccepted,
		providerID:       "provider-unauth",
		receiverHost:     "receiver.example.com",
		senderHost:       "other.example.com",
		initialStatus:    shares.OutgoingShareStatusSent,
		wantHTTP:         http.StatusForbidden,
		wantStatus:       shares.OutgoingShareStatusSent,
		wantMessage:      "SENDER_NOT_AUTHORIZED",
	})
}

func TestHandleNotification_ShareDeclinedUnauthorizedSender(t *testing.T) {
	t.Parallel()

	runOutgoingNotificationStatusTest(t, outgoingNotificationCase{
		notificationType: spec.NotificationTypeShareDeclined,
		providerID:       "provider-unauth-decline",
		receiverHost:     "receiver.example.com",
		senderHost:       "other.example.com",
		initialStatus:    shares.OutgoingShareStatusSent,
		wantHTTP:         http.StatusForbidden,
		wantStatus:       shares.OutgoingShareStatusSent,
	})
}

func TestHandleNotification_NormalizedReceiverHostMatch(t *testing.T) {
	t.Parallel()

	runOutgoingNotificationStatusTest(t, outgoingNotificationCase{
		notificationType: spec.NotificationTypeShareAccepted,
		providerID:       "provider-normalized",
		receiverHost:     "receiver.example.com:443",
		senderHost:       "receiver.example.com",
		initialStatus:    shares.OutgoingShareStatusSent,
		wantHTTP:         http.StatusOK,
		wantStatus:       shares.OutgoingShareStatusAccepted,
	})
}

func TestHandleNotification_NormalizedReceiverHostMatchInverse(t *testing.T) {
	t.Parallel()

	runOutgoingNotificationStatusTest(t, outgoingNotificationCase{
		notificationType: spec.NotificationTypeShareAccepted,
		providerID:       "provider-normalized-inverse",
		receiverHost:     "receiver.example.com",
		senderHost:       "receiver.example.com:443",
		initialStatus:    shares.OutgoingShareStatusSent,
		wantHTTP:         http.StatusOK,
		wantStatus:       shares.OutgoingShareStatusAccepted,
	})
}

func TestHandleNotification_AcceptedThenDeclinedReturnsConflict(t *testing.T) {
	t.Parallel()

	runOutgoingNotificationStatusTest(t, outgoingNotificationCase{
		notificationType: spec.NotificationTypeShareDeclined,
		providerID:       "provider-accepted-then-declined",
		receiverHost:     "receiver.example.com",
		senderHost:       "receiver.example.com",
		initialStatus:    shares.OutgoingShareStatusAccepted,
		wantHTTP:         http.StatusConflict,
		wantStatus:       shares.OutgoingShareStatusAccepted,
		wantMessage:      "SHARE_STATUS_CONFLICT",
	})
}

func TestHandleNotification_DeclinedThenAcceptedReturnsConflict(t *testing.T) {
	t.Parallel()

	runOutgoingNotificationStatusTest(t, outgoingNotificationCase{
		notificationType: spec.NotificationTypeShareAccepted,
		providerID:       "provider-declined-then-accepted",
		receiverHost:     "receiver.example.com",
		senderHost:       "receiver.example.com",
		initialStatus:    shares.OutgoingShareStatusDeclined,
		wantHTTP:         http.StatusConflict,
		wantStatus:       shares.OutgoingShareStatusDeclined,
		wantMessage:      "SHARE_STATUS_CONFLICT",
	})
}

type outgoingNotificationCase struct {
	notificationType string
	providerID       string
	receiverHost     string
	senderHost       string
	initialStatus    shares.OutgoingShareStatus
	wantHTTP         int
	wantStatus       shares.OutgoingShareStatus
	wantMessage      string
}

func runOutgoingNotificationStatusTest(t *testing.T, tc outgoingNotificationCase) {
	t.Helper()

	repos := tsrepos.OpenMemory(t)
	ctx := context.Background()

	share := &sharesoutgoing.OutgoingShare{
		ProviderID:   tc.providerID,
		ReceiverHost: tc.receiverHost,
		Status:       tc.initialStatus,
		CreatedAt:    time.Now(),
	}
	if err := repos.OutgoingShares.Create(ctx, share); err != nil {
		t.Fatalf("create outgoing share: %v", err)
	}

	handler := incoming.NewHandler(repos.OutgoingShares, repos.IncomingShares, "https", nil)

	body := `{"notificationType":"` + tc.notificationType + `","providerId":"` + tc.providerID + `"}`

	w := postNotification(t, handler, body, tc.senderHost)
	if w.Code != tc.wantHTTP {
		t.Fatalf("expected %d, got %d: %s", tc.wantHTTP, w.Code, w.Body.String())
	}

	if tc.wantMessage != "" {
		if msg := decodeOCMMessage(t, w); msg != tc.wantMessage {
			t.Fatalf("message = %q", msg)
		}
	}

	updated, err := repos.OutgoingShares.GetByProviderID(ctx, tc.providerID)
	if err != nil {
		t.Fatalf("get outgoing share: %v", err)
	}

	if updated.Status != tc.wantStatus {
		t.Fatalf("status = %q, want %s", updated.Status, tc.wantStatus)
	}
}
