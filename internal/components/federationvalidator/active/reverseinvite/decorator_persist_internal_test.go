// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package reverseinvite

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites"
	invitesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/localidentity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/repos"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
	tshttp "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/http"
)

type persistInternalEnv struct {
	store    *validatorcore.Core
	svc      *Service
	outgoing invitesoutgoing.OutgoingInviteRepo
}

func newPersistInternalEnv(t *testing.T) *persistInternalEnv {
	t.Helper()

	r, err := repos.New(t.Context(), config.PersistenceConfig{
		Backend: config.BackendSQLite,
		DataDir: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("repos.New: %v", err)
	}

	t.Cleanup(func() { tshttp.MustClose(t, r) })

	db, err := r.SharedDB()
	if err != nil {
		t.Fatalf("SharedDB: %v", err)
	}

	store, err := validatorcore.Attach(db, validatorcore.DefaultSessionConfig())
	if err != nil {
		t.Fatalf("validatorcore.Attach: %v", err)
	}

	svc, err := New(Deps{
		Store:           store,
		OutgoingInvites: r.OutgoingInvites,
		IncomingInvites: r.IncomingInvites,
		Parties:         identity.NewMemoryPartyRepo(),
		Poster:          &okInvitePoster{},
		LocalIdentity: localidentity.Identity{
			Origin:                "https://local.example",
			Scheme:                "https",
			ProviderDomain:        "local.example",
			ProviderDomainCompare: "local.example",
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	return &persistInternalEnv{store: store, svc: svc, outgoing: r.OutgoingInvites}
}

type okInvitePoster struct{}

func (okInvitePoster) PostInviteAccepted(_ context.Context, _ string, _ []byte) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(`{"userID":"sender@peer.example"}`)),
	}, nil
}

func (e *persistInternalEnv) seedMintedAccepted(t *testing.T, runID string) *invitesoutgoing.OutgoingInvite {
	t.Helper()

	now := time.Now().Unix()
	if err := e.store.DB().WithContext(t.Context()).Create(&validatorcore.TestRun{
		TestRunID:    runID,
		IsActive:     true,
		State:        validatorcore.StateActiveRunning,
		TargetOrigin: "https://peer.example",
		TargetHost:   "peer.example",
		DiscoveryURL: "https://peer.example/.well-known/ocm",
		CreatedAt:    now,
		UpdatedAt:    now,
	}).Error; err != nil {
		t.Fatalf("seed run: %v", err)
	}

	invite, err := e.svc.MintOutgoingInvite(t.Context(), runID)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	if err := e.outgoing.UpdateStatus(t.Context(), invite.ID, invites.InviteStatusAccepted, &invitesoutgoing.Acceptance{
		ProviderFQDN:           "peer.example",
		UserID:                 "accepter-user",
		ProviderFQDNNormalized: "peer.example",
	}); err != nil {
		t.Fatalf("mark invite accepted: %v", err)
	}

	return invite
}

func (e *persistInternalEnv) requireState(t *testing.T, runID, want string) {
	t.Helper()

	run, err := e.store.GetTestRun(t.Context(), runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if run.State != want {
		t.Fatalf("state = %q, want %q", run.State, want)
	}
}

func inviteAcceptedObserveArgs(t *testing.T, token string) (*http.Request, []byte, []byte) {
	t.Helper()

	body := []byte(`{"recipientProvider":"peer.example","token":"` + token +
		`","userID":"accepter-user","email":"a@example","name":"Accepter"}`)
	req := httptest.NewRequestWithContext(
		t.Context(),
		http.MethodPost,
		"/ocm/invite-accepted",
		strings.NewReader(string(body)),
	)

	return req, body, []byte(`{"userID":"accepter-user"}`)
}

func TestObserveAccepted_EvidenceFailureDoesNotAdvanceAndRetryHeals(t *testing.T) {
	t.Parallel()

	env := newPersistInternalEnv(t)
	runID := "run-dec-evidence-fail"
	invite := env.seedMintedAccepted(t, runID)
	req, body, resp := inviteAcceptedObserveArgs(t, invite.Token)

	env.svc.recordAccepted = func(context.Context, string, int) error {
		return errors.New("injected evidence failure")
	}

	err := env.svc.observeAccepted(req, body, http.StatusOK, resp)
	if err == nil {
		t.Fatal("observeAccepted error = nil, want evidence failure")
	}

	env.requireState(t, runID, validatorcore.StateInviteMinted)

	run, err := env.store.GetTestRun(t.Context(), runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if run.DesignatedShareWith != nil {
		t.Fatalf("designated_share_with = %v, want nil before evidence lands", run.DesignatedShareWith)
	}

	env.svc.recordAccepted = nil

	if err := env.svc.observeAccepted(req, body, http.StatusOK, resp); err != nil {
		t.Fatalf("retry observeAccepted: %v", err)
	}

	env.requireState(t, runID, validatorcore.StateInviteAccepted)
}

func TestDecorateInviteAccepted_EvidenceFailureKeepsProtocolResponse(t *testing.T) {
	t.Parallel()

	env := newPersistInternalEnv(t)
	runID := "run-dec-evidence-http"
	invite := env.seedMintedAccepted(t, runID)

	env.svc.recordAccepted = func(context.Context, string, int) error {
		return errors.New("injected evidence failure")
	}

	handler := env.svc.DecorateInviteAccepted(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	_, body, _ := inviteAcceptedObserveArgs(t, invite.Token)
	req := httptest.NewRequestWithContext(
		t.Context(),
		http.MethodPost,
		"/ocm/invite-accepted",
		strings.NewReader(string(body)),
	)
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (protocol unaffected)", rec.Code)
	}

	env.requireState(t, runID, validatorcore.StateInviteMinted)
}
