// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package shares_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	inboxshares "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/api/inbox/shares"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/notifications"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	tsrepos "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/repos"
)

type recordingNotifier struct {
	calls []notifyCall
	err   error
	done  chan struct{}
}

type blockingNotifier struct {
	entered chan struct{}
	release chan struct{}
	done    chan struct{}
	calls   []notifyCall
}

type notifyCall struct {
	targetHost       string
	providerID       string
	resourceType     string
	notificationType string
}

func (n *recordingNotifier) Notify(
	_ context.Context,
	targetHost string,
	providerID string,
	resourceType string,
	notificationType string,
	_ json.RawMessage,
) error {
	n.calls = append(n.calls, notifyCall{
		targetHost:       targetHost,
		providerID:       providerID,
		resourceType:     resourceType,
		notificationType: notificationType,
	})

	if n.done != nil {
		close(n.done)
	}

	return n.err
}

func (n *blockingNotifier) Notify(
	_ context.Context,
	targetHost string,
	providerID string,
	resourceType string,
	notificationType string,
	_ json.RawMessage,
) error {
	n.calls = append(n.calls, notifyCall{
		targetHost:       targetHost,
		providerID:       providerID,
		resourceType:     resourceType,
		notificationType: notificationType,
	})

	close(n.entered)
	<-n.release

	if n.done != nil {
		close(n.done)
	}

	return nil
}

func waitForNotifier(t *testing.T, done <-chan struct{}) {
	t.Helper()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for async notification")
	}
}

func postInboxShareAction(t *testing.T, router http.Handler, shareID, action string) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/inbox/shares/"+shareID+"/"+action, nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	return w
}

func runAsyncNotifyPersistedStatusTest(
	t *testing.T,
	action, providerID string,
	notifyErr error,
	want shares.ShareStatus,
) {
	t.Helper()

	repo := tsrepos.OpenMemory(t).IncomingShares
	share := createShareForUser(t, repo, userAID, providerID, "sender.example.com")

	done := make(chan struct{})
	notifier := &recordingNotifier{err: notifyErr, done: done}
	userA := &identity.User{ID: userAID, Username: "alice"}
	h := inboxshares.NewHandler(repo, nil, notifier, currentUserFunc(userA), testLogger)
	r := chiRouterForHandler(t, h)

	w := postInboxShareAction(t, r, share.ShareID, action)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	waitForNotifier(t, done)

	updated, err := repo.GetByIDForRecipientUserID(context.Background(), share.ShareID, userAID)
	if err != nil {
		t.Fatalf("get share: %v", err)
	}

	if updated.Status != want {
		t.Fatalf("status = %q, want %s", updated.Status, want)
	}
}

func runUnsharedShareActionTest(t *testing.T, action string, wantHTTP int) {
	t.Helper()

	repo := tsrepos.OpenMemory(t).IncomingShares
	share := createShareForUser(t, repo, userAID, "prov-unshared-"+action, "sender.example.com")

	if err := repo.UpdateStatusForRecipientUserID(
		context.Background(),
		share.ShareID,
		userAID,
		shares.ShareStatusUnshared,
	); err != nil {
		t.Fatalf("set unshared: %v", err)
	}

	userA := &identity.User{ID: userAID, Username: "alice"}
	h := inboxshares.NewHandler(repo, nil, nil, currentUserFunc(userA), testLogger)
	r := chiRouterForHandler(t, h)

	w := postInboxShareAction(t, r, share.ShareID, action)
	if w.Code != wantHTTP {
		t.Fatalf("expected %d, got %d: %s", wantHTTP, w.Code, w.Body.String())
	}

	updated, err := repo.GetByIDForRecipientUserID(context.Background(), share.ShareID, userAID)
	if err != nil {
		t.Fatalf("get share: %v", err)
	}

	if updated.Status != shares.ShareStatusUnshared {
		t.Fatalf("status = %q, want unshared", updated.Status)
	}
}

func TestHandleAccept_ResponseBeforeNotifierCompletes(t *testing.T) {
	t.Parallel()

	runResponseBeforeNotifierTest(t, "accept")
}

func TestHandleDecline_ResponseBeforeNotifierCompletes(t *testing.T) {
	t.Parallel()

	runResponseBeforeNotifierTest(t, "decline")
}

func runResponseBeforeNotifierTest(t *testing.T, action string) {
	t.Helper()

	repo := tsrepos.OpenMemory(t).IncomingShares
	share := createShareForUser(t, repo, userAID, "prov-block-"+action, "sender.example.com")

	entered := make(chan struct{})
	release := make(chan struct{})
	notifyDone := make(chan struct{})
	notifier := &blockingNotifier{
		entered: entered,
		release: release,
		done:    notifyDone,
	}

	userA := &identity.User{ID: userAID, Username: "alice"}
	h := inboxshares.NewHandler(repo, nil, notifier, currentUserFunc(userA), testLogger)
	r := chiRouterForHandler(t, h)

	responseDone := make(chan *httptest.ResponseRecorder, 1)
	errCh := make(chan string, 1)

	go func() {
		w := postInboxShareAction(t, r, share.ShareID, action)
		if w.Code != http.StatusOK {
			errCh <- fmt.Sprintf("expected 200, got %d", w.Code)

			return
		}

		responseDone <- w
	}()

	<-entered

	select {
	case errMsg := <-errCh:
		t.Fatal(errMsg)
	case w := <-responseDone:
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for HTTP response while notifier blocked")
	}

	select {
	case <-notifyDone:
		t.Fatal("notifier completed before release")
	default:
	}

	close(release)
	waitForNotifier(t, notifyDone)
}

func TestHandleAccept_NotifiesSender(t *testing.T) {
	t.Parallel()

	repo := tsrepos.OpenMemory(t).IncomingShares
	share := createShareForUser(t, repo, userAID, "prov-notify", "sender.example.com")

	done := make(chan struct{})
	notifier := &recordingNotifier{done: done}
	userA := &identity.User{ID: userAID, Username: "alice"}
	h := inboxshares.NewHandler(repo, nil, notifier, currentUserFunc(userA), testLogger)
	r := chiRouterForHandler(t, h)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/inbox/shares/"+share.ShareID+"/accept", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	waitForNotifier(t, done)

	if len(notifier.calls) != 1 {
		t.Fatalf("expected 1 notify call, got %d", len(notifier.calls))
	}

	call := notifier.calls[0]
	if call.targetHost != "sender.example.com" ||
		call.providerID != "prov-notify" ||
		call.resourceType != "file" ||
		call.notificationType != spec.NotificationTypeShareAccepted {
		t.Fatalf("unexpected notify call: %#v", call)
	}
}

func TestHandleDecline_NotifiesSender(t *testing.T) {
	t.Parallel()

	repo := tsrepos.OpenMemory(t).IncomingShares
	share := createShareForUser(t, repo, userAID, "prov-decline-notify", "sender.example.com")

	done := make(chan struct{})
	notifier := &recordingNotifier{done: done}
	userA := &identity.User{ID: userAID, Username: "alice"}
	h := inboxshares.NewHandler(repo, nil, notifier, currentUserFunc(userA), testLogger)
	r := chiRouterForHandler(t, h)

	w := postInboxShareAction(t, r, share.ShareID, "decline")

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	waitForNotifier(t, done)

	if len(notifier.calls) != 1 {
		t.Fatalf("expected 1 notify call, got %d", len(notifier.calls))
	}

	if notifier.calls[0].notificationType != spec.NotificationTypeShareDeclined {
		t.Fatalf("notification type = %q", notifier.calls[0].notificationType)
	}

	if notifier.calls[0].resourceType != "file" {
		t.Fatalf("resourceType = %q, want file", notifier.calls[0].resourceType)
	}
}

func TestHandleAccept_NilNotifierSkips(t *testing.T) {
	t.Parallel()

	runShareStatusTransition(t, "accept", "prov-nil-notifier", shares.ShareStatusAccepted)
}

func TestHandleAccept_NotAdvertisedSkips(t *testing.T) {
	t.Parallel()

	runAsyncNotifyPersistedStatusTest(
		t,
		"accept",
		"prov-not-adv",
		notifications.ErrNotificationsNotAdvertised,
		shares.ShareStatusAccepted,
	)
}

func TestHandleAccept_NotifyErrorStillSucceeds(t *testing.T) {
	t.Parallel()

	runAsyncNotifyPersistedStatusTest(
		t,
		"accept",
		"prov-notify-err",
		errors.New("peer unreachable"),
		shares.ShareStatusAccepted,
	)
}

func TestHandleDecline_NilNotifierSkips(t *testing.T) {
	t.Parallel()

	runShareStatusTransition(t, "decline", "prov-decline-nil-notifier", shares.ShareStatusDeclined)
}

func TestHandleDecline_NotAdvertisedSkips(t *testing.T) {
	t.Parallel()

	runAsyncNotifyPersistedStatusTest(
		t,
		"decline",
		"prov-decline-not-adv",
		notifications.ErrNotificationsNotAdvertised,
		shares.ShareStatusDeclined,
	)
}

func TestHandleDecline_NotifyErrorStillSucceeds(t *testing.T) {
	t.Parallel()

	runAsyncNotifyPersistedStatusTest(
		t,
		"decline",
		"prov-decline-notify-err",
		errors.New("peer unreachable"),
		shares.ShareStatusDeclined,
	)
}

func TestHandleAccept_UnsharedShareReturnsConflict(t *testing.T) {
	t.Parallel()

	runUnsharedShareActionTest(t, "accept", http.StatusConflict)
}

func TestHandleDecline_UnsharedShareIsIdempotent(t *testing.T) {
	t.Parallel()

	runUnsharedShareActionTest(t, "decline", http.StatusOK)
}

func chiRouterForHandler(t *testing.T, h *inboxshares.Handler) http.Handler {
	t.Helper()

	r := chi.NewRouter()
	r.Route("/inbox/shares", func(r chi.Router) {
		r.Post("/{shareId}/accept", h.HandleAccept)
		r.Post("/{shareId}/decline", h.HandleDecline)
	})

	return r
}
