// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package passive

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/federationvalidator/active/reverseinvite"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/localidentity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/repos"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
	tshttp "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/http"
)

const (
	claimTestLocalDomain  = "local.example"
	claimTestTargetHost   = "peer.example"
	claimTestTargetOrigin = "https://peer.example"
)

type claimTestEnv struct {
	store   *validatorcore.Core
	handler *Handler
	mint    *reverseinvite.Service
	logs    *bytes.Buffer
}

func newClaimTestEnv(t *testing.T) *claimTestEnv {
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

	var logs bytes.Buffer

	log := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))

	mint, err := reverseinvite.New(reverseinvite.Deps{
		Store:           store,
		OutgoingInvites: r.OutgoingInvites,
		IncomingInvites: r.IncomingInvites,
		Parties:         identity.NewMemoryPartyRepo(),
		Poster:          unusedClaimPoster{},
		LocalIdentity: localidentity.Identity{
			Origin:                "https://" + claimTestLocalDomain,
			Scheme:                "https",
			ProviderDomain:        claimTestLocalDomain,
			ProviderDomainCompare: claimTestLocalDomain,
		},
		Logger: log,
	})
	if err != nil {
		t.Fatalf("reverseinvite.New: %v", err)
	}

	return &claimTestEnv{
		store:   store,
		handler: NewHandler(store, log),
		mint:    mint,
		logs:    &logs,
	}
}

type unusedClaimPoster struct{}

func (unusedClaimPoster) PostInviteAccepted(_ context.Context, _ string, _ []byte) (*http.Response, error) {
	return nil, errors.New("invite-accepted poster is unused on the mint path")
}

func (e *claimTestEnv) seedMinted(t *testing.T, runID string) string {
	t.Helper()

	now := int64(1_700_000_000)
	if err := e.store.DB().WithContext(t.Context()).Create(&validatorcore.TestRun{
		TestRunID:    runID,
		IsActive:     true,
		State:        validatorcore.StateActiveRunning,
		TargetOrigin: claimTestTargetOrigin,
		TargetHost:   claimTestTargetHost,
		DiscoveryURL: claimTestTargetOrigin + "/.well-known/ocm",
		CreatedAt:    now,
		UpdatedAt:    now,
	}).Error; err != nil {
		t.Fatalf("seed run: %v", err)
	}

	invite, err := e.mint.MintOutgoingInvite(t.Context(), runID)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	return invite.Token
}

func claimRouter(h *Handler) chi.Router {
	r := chi.NewRouter()
	r.Method(http.MethodPost, RouteAPISessionInvite, http.HandlerFunc(h.HandleClaimInvite))
	r.Method(http.MethodGet, RouteAPISession, http.HandlerFunc(h.HandleSession))

	return r
}

func doClaim(t *testing.T, h *Handler, runID string) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/session/"+runID+"/invite", nil)
	rec := httptest.NewRecorder()
	claimRouter(h).ServeHTTP(rec, req)

	return rec
}

func decodeClaimJSON(t *testing.T, rec *httptest.ResponseRecorder) map[string]json.RawMessage {
	t.Helper()

	var payload map[string]json.RawMessage
	if err := json.NewDecoder(rec.Body).Decode(&payload); err != nil {
		t.Fatalf("decode: %v", err)
	}

	return payload
}
