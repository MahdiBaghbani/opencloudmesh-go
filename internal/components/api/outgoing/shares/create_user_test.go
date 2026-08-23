// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package shares_test

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	tsrepos "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/repos"

	outgoingshares "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/api/outgoing/shares"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/peerorigin"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/policy"
	ocmshares "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares"
	sharesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
)

type recordingDispatchHook struct {
	err      error
	calls    int
	lastUser string
	lastReq  sharesoutgoing.OutgoingShareRequest
}

func (h *recordingDispatchHook) GuardCreate(
	_ context.Context,
	req sharesoutgoing.OutgoingShareRequest,
	userID string,
) (*outgoingshares.DispatchPlan, error) {
	h.calls++
	h.lastUser = userID
	h.lastReq = req

	return nil, h.err
}

func (h *recordingDispatchHook) NoteWireURI(context.Context, *outgoingshares.DispatchPlan, string) error {
	return nil
}

func (h *recordingDispatchHook) CheckSendClaim(context.Context, *outgoingshares.DispatchPlan) error {
	return nil
}

func (h *recordingDispatchHook) CommitSent(context.Context, *outgoingshares.DispatchPlan, *sharesoutgoing.OutgoingShare) error {
	return nil
}

func (h *recordingDispatchHook) AbortSend(context.Context, *outgoingshares.DispatchPlan) error {
	return nil
}

func TestCreateAsUser_SucceedsWithoutHTTPSession(t *testing.T) {
	t.Parallel()

	srv, postCount := makeReceiverTLSServer(t, []string{"exchange-token"}, []string{})
	defer srv.Close()

	repo := tsrepos.OpenMemory(t).OutgoingShares
	discClient, ctxClient := makeTLSClients()
	handler := outgoingshares.NewHandler(
		repo,
		discClient,
		ctxClient,
		makeTestSigner(t),
		testProvider,
		failCurrentUser(),
		testLogger,
		&stubResolver{facts: policy.NewCodeFlow().Evaluate()},
		"https://example.com/ocm/token",
	)
	handler.SetAllowedPaths([]string{"/tmp"})
	handler.SetPeerOrigin(peerorigin.NewResolver(false))

	tmpFile := createTempShareFile(t, "create-as-user-*")
	alice := &identity.User{ID: "run-alice", Username: "session-inviter"}
	req := sharesoutgoing.OutgoingShareRequest{
		ReceiverDomain: srv.Listener.Addr().String(),
		ShareWith:      "omar@" + srv.Listener.Addr().String(),
		LocalPath:      tmpFile,
		Permissions:    append([]string{}, spec.SupportedWebDAVPermissions...),
	}

	share, err := handler.CreateAsUser(t.Context(), alice, req)
	if err != nil {
		t.Fatalf("CreateAsUser: %v", err)
	}

	if share == nil || share.ShareID == "" {
		t.Fatal("expected a persisted share")
	}

	if share.Status != ocmshares.OutgoingShareStatusSent {
		t.Fatalf("status = %q, want sent", share.Status)
	}

	if postCount.Load() != 1 {
		t.Fatalf("receiver posts = %d, want 1", postCount.Load())
	}
}

func TestCreateAsUser_InvokesGuardCreate(t *testing.T) {
	t.Parallel()

	repo := tsrepos.OpenMemory(t).OutgoingShares
	discClient, ctxClient := makeTLSClients()
	handler := newStrictOutgoingHandler(t, repo, discClient, ctxClient, &identity.User{ID: "http-user"})

	hook := &recordingDispatchHook{err: outgoingshares.ErrDispatchRefused}
	handler.SetDispatchHook(hook)

	tmpFile := createTempShareFile(t, "create-as-user-guard-*")
	alice := &identity.User{ID: "run-alice"}
	req := sharesoutgoing.OutgoingShareRequest{
		ReceiverDomain: "peer.example",
		ShareWith:      "omar@peer.example",
		LocalPath:      tmpFile,
		Permissions:    append([]string{}, spec.SupportedWebDAVPermissions...),
	}

	_, err := handler.CreateAsUser(t.Context(), alice, req)
	if !errors.Is(err, outgoingshares.ErrDispatchRefused) {
		t.Fatalf("CreateAsUser = %v, want ErrDispatchRefused", err)
	}

	if hook.calls != 1 {
		t.Fatalf("GuardCreate calls = %d, want 1", hook.calls)
	}

	if hook.lastUser != alice.ID {
		t.Fatalf("guard user = %q, want %q", hook.lastUser, alice.ID)
	}
}

func TestCreateAsUser_DispatchInProgressReturned(t *testing.T) {
	t.Parallel()

	repo := tsrepos.OpenMemory(t).OutgoingShares
	discClient, ctxClient := makeTLSClients()
	handler := newStrictOutgoingHandler(t, repo, discClient, ctxClient, &identity.User{ID: "http-user"})

	hook := &recordingDispatchHook{err: outgoingshares.ErrDispatchInProgress}
	handler.SetDispatchHook(hook)

	tmpFile := createTempShareFile(t, "create-as-user-busy-*")
	req := sharesoutgoing.OutgoingShareRequest{
		ReceiverDomain: "peer.example",
		ShareWith:      "omar@peer.example",
		LocalPath:      tmpFile,
		Permissions:    append([]string{}, spec.SupportedWebDAVPermissions...),
	}

	_, err := handler.CreateAsUser(t.Context(), &identity.User{ID: "run-alice"}, req)
	if !errors.Is(err, outgoingshares.ErrDispatchInProgress) {
		t.Fatalf("CreateAsUser = %v, want ErrDispatchInProgress", err)
	}
}

func TestHandleCreate_StillRequiresHTTPSession(t *testing.T) {
	t.Parallel()

	handler := newTestHandler(t, failCurrentUser())
	tmpFile := createTempShareFile(t, "create-http-session-*")

	req := httptest.NewRequestWithContext(
		t.Context(),
		http.MethodPost,
		"/api/shares/outgoing",
		bytes.NewBufferString(outgoingCreateBody("peer.example", tmpFile)),
	)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	handler.HandleCreate(w, req)

	if w.Code == http.StatusCreated {
		t.Fatal("HandleCreate succeeded without a session")
	}
}
