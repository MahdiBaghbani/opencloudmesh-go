// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package shares_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	tsrepos "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/repos"

	outgoingshares "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/api/outgoing/shares"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/peerorigin"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/policy"
	ocmshares "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares"
	sharesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/logutil"
)

// createFailingRepo wraps an OutgoingShareRepo and fails Create, injecting a
// persistence failure into the outgoing share create path.
type createFailingRepo struct {
	sharesoutgoing.OutgoingShareRepo

	createErr error
}

func (r *createFailingRepo) Create(_ context.Context, _ *sharesoutgoing.OutgoingShare) error {
	return r.createErr
}

// createCapturingRepo records the status passed to Create before persistence.
type createCapturingRepo struct {
	sharesoutgoing.OutgoingShareRepo

	createStatus ocmshares.OutgoingShareStatus
}

func (r *createCapturingRepo) Create(ctx context.Context, share *sharesoutgoing.OutgoingShare) error {
	r.createStatus = share.Status

	if err := r.OutgoingShareRepo.Create(ctx, share); err != nil {
		return fmt.Errorf("createCapturingRepo: %w", err)
	}

	return nil
}

// updateFailingRepo fails Update when the share reaches a specific status.
type updateFailingRepo struct {
	sharesoutgoing.OutgoingShareRepo

	failOnStatus ocmshares.OutgoingShareStatus
	updateErr    error
}

func (r *updateFailingRepo) Update(ctx context.Context, share *sharesoutgoing.OutgoingShare) error {
	if share.Status == r.failOnStatus {
		return r.updateErr
	}

	if err := r.OutgoingShareRepo.Update(ctx, share); err != nil {
		return fmt.Errorf("updateFailingRepo: %w", err)
	}

	return nil
}

// TestHandleCreate_PersistFailure_NoDelivery proves the persist-before-deliver
// ordering: when the local Create fails, the handler returns 500 and never
// attempts delivery, so the peer can never hold a share we have no record of.
// The post counter only increments on POST /ocm/shares, so the discovery
// traffic that necessarily precedes share formation is not counted.
func TestHandleCreate_PersistFailure_NoDelivery(t *testing.T) {
	t.Parallel()

	srv, postCount := makeReceiverTLSServer(t, []string{"exchange-token"}, []string{})
	defer srv.Close()

	user := &identity.User{ID: "user-uuid", Username: "alice"}
	repo := tsrepos.OpenMemory(t).OutgoingShares
	failing := &createFailingRepo{OutgoingShareRepo: repo, createErr: errors.New("injected create failure")}
	discClient, ctxClient := makeTLSClients()
	handler := newStrictOutgoingHandler(t, failing, discClient, ctxClient, user)

	tmpFile := createTempShareFile(t, "outgoing-persist-fail-*")
	receiverHost := srv.Listener.Addr().String()

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/shares/outgoing", bytes.NewBufferString(outgoingCreateBody(receiverHost, tmpFile)))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	handler.HandleCreate(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d: %s", w.Code, w.Body.String())
	}

	if postCount.Load() != 0 {
		t.Fatalf("expected no share delivery POST, got %d", postCount.Load())
	}

	all, err := repo.List(t.Context())
	if err != nil {
		t.Fatalf("list shares: %v", err)
	}

	if len(all) != 0 {
		t.Fatalf("expected no stored shares, got %d", len(all))
	}
}

// TestHandleCreate_DeliverFailure_PersistsFailedShare proves that a failed
// delivery still leaves exactly one local record, transitioned to "failed":
// the share is not an orphan because the peer never received it.
func TestHandleCreate_DeliverFailure_PersistsFailedShare(t *testing.T) {
	t.Parallel()

	srv := makePeerErrorReceiverTLSServer(t, "DELIVERY_FAILURE_CANARY")
	defer srv.Close()

	user := &identity.User{ID: "user-uuid", Username: "alice"}
	repo := tsrepos.OpenMemory(t).OutgoingShares
	discClient, ctxClient := makeTLSClients()
	handler := newStrictOutgoingHandler(t, repo, discClient, ctxClient, user)

	tmpFile := createTempShareFile(t, "outgoing-deliver-fail-*")
	receiverHost := srv.Listener.Addr().String()

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/shares/outgoing", bytes.NewBufferString(outgoingCreateBody(receiverHost, tmpFile)))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	handler.HandleCreate(w, req)

	if w.Code != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d: %s", w.Code, w.Body.String())
	}

	all, err := repo.List(t.Context())
	if err != nil {
		t.Fatalf("list shares: %v", err)
	}

	if len(all) != 1 {
		t.Fatalf("expected one stored share, got %d", len(all))
	}

	stored := all[0]

	if stored.Status != ocmshares.OutgoingShareStatusFailed {
		t.Fatalf("expected stored share status %q, got %q", ocmshares.OutgoingShareStatusFailed, stored.Status)
	}

	if stored.SentAt != nil {
		t.Fatal("expected SentAt to remain nil after failed delivery")
	}

	if stored.Error == "" {
		t.Fatal("expected delivery error to be persisted on failed share")
	}
}

// TestHandleCreate_DeliverFailure_FailedUpdateStillReturns502 proves that when
// delivery fails and the follow-up failed-state Update also fails, the handler
// still returns 502 without panicking and logs both failures.
func TestHandleCreate_DeliverFailure_FailedUpdateStillReturns502(t *testing.T) {
	t.Parallel()

	const canary = "DELIVERY_FAILURE_CANARY"

	srv := makePeerErrorReceiverTLSServer(t, canary)
	defer srv.Close()

	user := &identity.User{ID: "user-uuid", Username: "alice"}
	baseRepo := tsrepos.OpenMemory(t).OutgoingShares
	repo := &updateFailingRepo{
		OutgoingShareRepo: baseRepo,
		failOnStatus:      ocmshares.OutgoingShareStatusFailed,
		updateErr:         errors.New("injected failed-state update failure"),
	}
	discClient, ctxClient := makeTLSClients()
	capture := logutil.NewCapturingLogger(slog.LevelDebug)
	handler := outgoingshares.NewHandler(
		repo,
		discClient,
		ctxClient,
		makeTestSigner(t),
		testProvider,
		testCurrentUser(user),
		capture.Logger,
		&stubResolver{facts: policy.NewCodeFlow().Evaluate()},
		"https://example.com/ocm/token",
	)
	handler.SetAllowedPaths([]string{"/tmp"})
	handler.SetPeerOrigin(peerorigin.NewResolver(false))

	tmpFile := createTempShareFile(t, "outgoing-deliver-fail-update-fail-*")
	receiverHost := srv.Listener.Addr().String()

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/shares/outgoing", bytes.NewBufferString(outgoingCreateBody(receiverHost, tmpFile)))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	handler.HandleCreate(w, req)

	if w.Code != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d: %s", w.Code, w.Body.String())
	}

	logOutput := capture.Output()
	if !strings.Contains(logOutput, "failed to deliver share to receiver") {
		t.Fatalf("expected delivery failure warn log, got: %s", logOutput)
	}

	if !strings.Contains(logOutput, "failed to mark outgoing share as failed") {
		t.Fatalf("expected failed-state update error log, got: %s", logOutput)
	}

	all, err := baseRepo.List(t.Context())
	if err != nil {
		t.Fatalf("list shares: %v", err)
	}

	if len(all) != 1 {
		t.Fatalf("expected one stored share, got %d", len(all))
	}

	if all[0].SentAt != nil {
		t.Fatal("expected SentAt to remain nil when failed-state update fails")
	}
}

// TestHandleCreate_DeliverSuccess_SentUpdateFailureReturns500 documents the
// current handler contract: after peer delivery succeeds, a failed sent-state
// Update is treated as fatal and returns 500 even though the receiver already
// accepted the share.
func TestHandleCreate_DeliverSuccess_SentUpdateFailureReturns500(t *testing.T) {
	t.Parallel()

	srv, postCount := makeReceiverTLSServer(t, []string{"exchange-token"}, []string{})
	defer srv.Close()

	user := &identity.User{ID: "user-uuid", Username: "alice"}
	baseRepo := tsrepos.OpenMemory(t).OutgoingShares
	repo := &updateFailingRepo{
		OutgoingShareRepo: baseRepo,
		failOnStatus:      ocmshares.OutgoingShareStatusSent,
		updateErr:         errors.New("injected sent-state update failure"),
	}
	discClient, ctxClient := makeTLSClients()
	handler := newStrictOutgoingHandler(t, repo, discClient, ctxClient, user)

	tmpFile := createTempShareFile(t, "outgoing-sent-update-fail-*")
	receiverHost := srv.Listener.Addr().String()

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/shares/outgoing", bytes.NewBufferString(outgoingCreateBody(receiverHost, tmpFile)))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	handler.HandleCreate(w, req)

	if postCount.Load() != 1 {
		t.Fatalf("expected one delivery POST, got %d", postCount.Load())
	}

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 after sent-state update failure, got %d: %s", w.Code, w.Body.String())
	}

	if !strings.Contains(w.Body.String(), "share sent but local persistence failed") {
		t.Fatalf("expected persistence failure message, got: %s", w.Body.String())
	}
}

// TestHandleCreate_HappyPath_PersistsSentShare proves the success path keeps
// its external shape (201, status "sent") and persists one share transitioned
// to "sent" with SentAt set.
func TestHandleCreate_HappyPath_PersistsSentShare(t *testing.T) {
	t.Parallel()

	srv, postCount := makeReceiverTLSServer(t, []string{"exchange-token"}, []string{})
	defer srv.Close()

	user := &identity.User{ID: "user-uuid", Username: "alice"}
	baseRepo := tsrepos.OpenMemory(t).OutgoingShares
	capturingRepo := &createCapturingRepo{OutgoingShareRepo: baseRepo}
	discClient, ctxClient := makeTLSClients()
	handler := newStrictOutgoingHandler(t, capturingRepo, discClient, ctxClient, user)

	tmpFile := createTempShareFile(t, "outgoing-happy-path-*")
	receiverHost := srv.Listener.Addr().String()

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/shares/outgoing", bytes.NewBufferString(outgoingCreateBody(receiverHost, tmpFile)))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	handler.HandleCreate(w, req)

	if capturingRepo.createStatus != ocmshares.OutgoingShareStatusPending {
		t.Fatalf("expected pending status at Create, got %q", capturingRepo.createStatus)
	}

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	if postCount.Load() != 1 {
		t.Fatalf("expected one delivery POST, got %d", postCount.Load())
	}

	var resp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if resp["status"] != string(ocmshares.OutgoingShareStatusSent) {
		t.Fatalf("expected response status %q, got %q", ocmshares.OutgoingShareStatusSent, resp["status"])
	}

	all, err := baseRepo.List(t.Context())
	if err != nil {
		t.Fatalf("list shares: %v", err)
	}

	if len(all) != 1 {
		t.Fatalf("expected one stored share, got %d", len(all))
	}

	stored := all[0]

	if stored.Status != ocmshares.OutgoingShareStatusSent {
		t.Fatalf("expected stored share status %q, got %q", ocmshares.OutgoingShareStatusSent, stored.Status)
	}

	if stored.SentAt == nil {
		t.Fatal("expected SentAt to be set on delivered share")
	}

	if resp["shareId"] != stored.ShareID {
		t.Fatalf("response shareId %q does not match stored share %q", resp["shareId"], stored.ShareID)
	}
}
