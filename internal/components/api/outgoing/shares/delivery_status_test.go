// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package shares_test

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	tsrepos "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/repos"

	outgoingshares "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/api/outgoing/shares"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/peerorigin"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/policy"
	sharesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	tshttp "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/http"
)

func TestCreateAsUser_ReceiverStatusAcceptedCodes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		status int
	}{
		{name: "http 200", status: http.StatusOK},
		{name: "http 201", status: http.StatusCreated},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			share, err := deliverShareWithStatus(t, tt.status)
			if err != nil {
				t.Fatalf("CreateAsUser: %v", err)
			}

			if share == nil || share.ShareID == "" {
				t.Fatal("expected a persisted share")
			}
		})
	}
}

func TestCreateAsUser_ReceiverStatusRejectedAsReceiverStatusError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		status int
	}{
		{name: "http 202", status: http.StatusAccepted},
		{name: "http 204", status: http.StatusNoContent},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := deliverShareWithStatus(t, tt.status)
			if err == nil {
				t.Fatal("expected receiver status error")
			}

			var recv *outgoingshares.ReceiverStatusError
			if !errors.As(err, &recv) {
				t.Fatalf("CreateAsUser = %v, want *ReceiverStatusError", err)
			}

			if recv.Status != tt.status {
				t.Fatalf("status = %d, want %d", recv.Status, tt.status)
			}

			if recv.PermanentRefuse() {
				t.Fatal("202/204 must stay retryable")
			}
		})
	}
}

func deliverShareWithStatus(t *testing.T, status int) (*sharesoutgoing.OutgoingShare, error) {
	t.Helper()

	srv := makeReceiverTLSServerWithShareStatus(t, status)
	t.Cleanup(srv.Close)

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

	req := sharesoutgoing.OutgoingShareRequest{
		ReceiverDomain: srv.Listener.Addr().String(),
		ShareWith:      "omar@" + srv.Listener.Addr().String(),
		LocalPath:      createTempShareFile(t, "delivery-status-*"),
		Permissions:    append([]string{}, spec.SupportedWebDAVPermissions...),
	}

	share, err := handler.CreateAsUser(t.Context(), &identity.User{ID: "run-alice", Username: "session-inviter"}, req)
	if err != nil {
		return nil, fmt.Errorf("create as user: %w", err)
	}

	return share, nil
}

func makeReceiverTLSServerWithShareStatus(t *testing.T, status int) *httptest.Server {
	t.Helper()

	var srv *httptest.Server

	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/ocm" {
			disc := spec.Discovery{
				Enabled:       true,
				APIVersion:    "1.4.0",
				EndPoint:      srv.URL + "/ocm",
				Capabilities:  []string{"exchange-token"},
				TokenEndPoint: srv.URL + "/ocm/token",
			}

			w.Header().Set("Content-Type", "application/json")
			tshttp.WriteJSON(w, disc)

			return
		}

		if r.Method == http.MethodPost && r.URL.Path == "/ocm/shares" {
			w.WriteHeader(status)

			if status != http.StatusNoContent {
				tshttp.MustWrite(t, w, []byte(`{"ok":true}`))
			}

			return
		}

		http.NotFound(w, r)
	}))

	return srv
}
