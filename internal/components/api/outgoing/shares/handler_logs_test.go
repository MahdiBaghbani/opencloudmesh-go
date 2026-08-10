// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package shares_test

import (
	"bytes"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	tshttp "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/http"
	tsrepos "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/repos"

	outgoingshares "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/api/outgoing/shares"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/peerorigin"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/policy"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/logutil"
)

func TestHandleCreate_DoesNotLogSensitiveValues(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		authorization string
		signature     string
	}{
		{
			name:          "primary request credentials",
			authorization: "outgoing-share-auth-token-must-not-log",
			signature:     "outgoing-share-signature-must-not-log",
		},
		{
			name:          "second request credentials",
			authorization: "outgoing-share-auth-second-must-not-log",
			signature:     "outgoing-share-signature-second-must-not-log",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			srv, postCount := makeReceiverTLSServer(t,
				[]string{"exchange-token"},
				[]string{"must-exchange-token"},
			)
			t.Cleanup(srv.Close)

			user := &identity.User{ID: "user-uuid", Username: "alice"}
			repo := tsrepos.OpenMemory(t).OutgoingShares
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

			tmpFile := createTempShareFile(t, "outgoing-logs-*")
			receiverHost := srv.Listener.Addr().String()

			req := httptest.NewRequestWithContext(
				t.Context(),
				http.MethodPost,
				"/api/shares/outgoing",
				bytes.NewBufferString(outgoingCreateBody(receiverHost, tmpFile)),
			)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+tt.authorization)
			req.Header.Set("Signature", tt.signature)

			w := httptest.NewRecorder()
			handler.HandleCreate(w, req)

			if w.Code != http.StatusCreated {
				t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
			}

			if postCount.Load() == 0 {
				t.Fatal("expected outbound share POST")
			}

			createdShares, err := repo.List(t.Context())
			if err != nil {
				t.Fatalf("list created shares: %v", err)
			}

			if len(createdShares) != 1 {
				t.Fatalf("created share count = %d, want 1", len(createdShares))
			}

			if capture.ContainsAny(
				tt.authorization,
				tt.signature,
				createdShares[0].SharedSecret,
				"Authorization",
				"Signature",
				"Bearer ",
			) {
				t.Fatalf("logs leaked sensitive values: %s", capture.Output())
			}
		})
	}
}

func TestHandleCreate_DoesNotEchoPeerErrorBody(t *testing.T) {
	t.Parallel()

	assertPeerErrorBodyNotEchoed(t, "PEER_ERROR_CANARY_DO_NOT_ECHO", makePeerErrorReceiverTLSServer(t, "PEER_ERROR_CANARY_DO_NOT_ECHO"), "outgoing-peer-error-*")
}

func TestHandleCreate_DoesNotEchoOversizePeerErrorBody(t *testing.T) {
	t.Parallel()

	const canary = "PEER_OVERSIZE_CANARY_DO_NOT_ECHO"

	assertPeerErrorBodyNotEchoed(
		t,
		canary,
		makePeerOversizeErrorReceiverTLSServer(t, canary),
		"outgoing-peer-oversize-*",
		"status 400",
		"response body too large",
		fmt.Sprintf("%d bytes read", config.DefaultMaxResponseBytes+1),
	)
}

func assertPeerErrorBodyNotEchoed(t *testing.T, canary string, srv *httptest.Server, tempFilePattern string, wantLogContains ...string) {
	t.Helper()

	t.Cleanup(srv.Close)

	user := &identity.User{ID: "user-uuid", Username: "alice"}
	repo := tsrepos.OpenMemory(t).OutgoingShares
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

	tmpFile := createTempShareFile(t, tempFilePattern)
	receiverHost := srv.Listener.Addr().String()

	req := httptest.NewRequestWithContext(
		t.Context(),
		http.MethodPost,
		"/api/shares/outgoing",
		bytes.NewBufferString(outgoingCreateBody(receiverHost, tmpFile)),
	)
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	handler.HandleCreate(w, req)

	if w.Code != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d: %s", w.Code, w.Body.String())
	}

	responseBody := w.Body.String()
	if strings.Contains(responseBody, canary) {
		t.Fatalf("HTTP response echoed peer error body: %s", responseBody)
	}

	if !strings.Contains(responseBody, "failed to deliver share to receiver") {
		t.Fatalf("expected stable client message, got: %s", responseBody)
	}

	if capture.Contains(canary) {
		t.Fatalf("logs must not contain peer error body: %s", capture.Output())
	}

	logOutput := capture.Output()
	for _, want := range wantLogContains {
		if !strings.Contains(logOutput, want) {
			t.Fatalf("logs missing safe metadata %q: %s", want, logOutput)
		}
	}
}

func makePeerErrorReceiverTLSServer(t *testing.T, errorBody string) *httptest.Server {
	t.Helper()

	var srv *httptest.Server

	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/ocm" {
			disc := spec.Discovery{
				Enabled:       true,
				APIVersion:    "1.4.0",
				EndPoint:      srv.URL + "/ocm",
				Capabilities:  []string{"exchange-token"},
				Criteria:      []string{"must-exchange-token"},
				TokenEndPoint: srv.URL + "/ocm/token",
			}

			w.Header().Set("Content-Type", "application/json")
			tshttp.WriteJSON(w, disc)

			return
		}

		if r.Method == http.MethodPost && r.URL.Path == "/ocm/shares" {
			w.WriteHeader(http.StatusBadRequest)
			tshttp.MustWrite(t, w, []byte(errorBody))

			return
		}

		http.NotFound(w, r)
	}))

	return srv
}

func makePeerOversizeErrorReceiverTLSServer(t *testing.T, canary string) *httptest.Server {
	t.Helper()

	oversizeBody := make([]byte, config.DefaultMaxResponseBytes+1)
	copy(oversizeBody, canary)

	var srv *httptest.Server

	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/ocm" {
			disc := spec.Discovery{
				Enabled:       true,
				APIVersion:    "1.4.0",
				EndPoint:      srv.URL + "/ocm",
				Capabilities:  []string{"exchange-token"},
				Criteria:      []string{"must-exchange-token"},
				TokenEndPoint: srv.URL + "/ocm/token",
			}

			w.Header().Set("Content-Type", "application/json")
			tshttp.WriteJSON(w, disc)

			return
		}

		if r.Method == http.MethodPost && r.URL.Path == "/ocm/shares" {
			w.WriteHeader(http.StatusBadRequest)
			tshttp.MustWrite(t, w, oversizeBody)

			return
		}

		http.NotFound(w, r)
	}))

	return srv
}
