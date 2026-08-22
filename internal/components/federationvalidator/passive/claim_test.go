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
	"strings"
	"sync"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/federationvalidator/active/reverseinvite"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/localidentity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/repos"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store"
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

func TestHandleClaimInvite_FirstReturnsSafeFields(t *testing.T) {
	t.Parallel()

	env := newClaimTestEnv(t)
	runID := "run-claim-first"
	token := env.seedMinted(t, runID)

	rec := doClaim(t, env.handler, runID)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}

	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", got)
	}

	payload := decodeClaimJSON(t, rec)
	assertExactKeys(t, payload, []string{
		"expiresAt",
		"inviteString",
		"issuerFqdn",
		"pasteTargetHost",
		"pasteTargetOrigin",
	})

	var issuer, origin, host, inviteString string
	if err := json.Unmarshal(payload["issuerFqdn"], &issuer); err != nil {
		t.Fatalf("issuerFqdn: %v", err)
	}

	if err := json.Unmarshal(payload["pasteTargetOrigin"], &origin); err != nil {
		t.Fatalf("pasteTargetOrigin: %v", err)
	}

	if err := json.Unmarshal(payload["pasteTargetHost"], &host); err != nil {
		t.Fatalf("pasteTargetHost: %v", err)
	}

	if err := json.Unmarshal(payload["inviteString"], &inviteString); err != nil {
		t.Fatalf("inviteString: %v", err)
	}

	if issuer != claimTestLocalDomain {
		t.Fatalf("issuerFqdn = %q, want %q", issuer, claimTestLocalDomain)
	}

	if origin != claimTestTargetOrigin {
		t.Fatalf("pasteTargetOrigin = %q, want %q", origin, claimTestTargetOrigin)
	}

	if host != claimTestTargetHost {
		t.Fatalf("pasteTargetHost = %q, want %q", host, claimTestTargetHost)
	}

	if inviteString == "" {
		t.Fatal("inviteString is empty")
	}

	if strings.Contains(rec.Body.String(), `"token"`) {
		t.Fatalf("response includes a token field: %s", rec.Body.String())
	}

	if strings.Contains(env.logs.String(), token) || strings.Contains(env.logs.String(), inviteString) {
		t.Fatalf("logs leaked invite material: %s", env.logs.String())
	}
}

func TestHandleClaimInvite_SecondReturnsGoneWithoutInvite(t *testing.T) {
	t.Parallel()

	env := newClaimTestEnv(t)
	runID := "run-claim-second"
	token := env.seedMinted(t, runID)

	first := doClaim(t, env.handler, runID)
	if first.Code != http.StatusOK {
		t.Fatalf("first status = %d, want 200", first.Code)
	}

	var firstBody map[string]string
	if err := json.NewDecoder(first.Body).Decode(&firstBody); err != nil {
		t.Fatalf("decode first: %v", err)
	}

	rec := doClaim(t, env.handler, runID)
	if rec.Code != http.StatusGone {
		t.Fatalf("second status = %d, want 410 (body %s)", rec.Code, rec.Body.String())
	}

	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", got)
	}

	var payload map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&payload); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if payload["error"] != validatorcore.CodeInviteAlreadyClaimed {
		t.Fatalf("error = %q, want %q", payload["error"], validatorcore.CodeInviteAlreadyClaimed)
	}

	body := rec.Body.String()
	if strings.Contains(body, firstBody["inviteString"]) || strings.Contains(body, token) {
		t.Fatalf("410 body leaked invite material: %s", body)
	}

	if _, ok := payload["inviteString"]; ok {
		t.Fatal("410 body includes inviteString")
	}

	if strings.Contains(env.logs.String(), token) || strings.Contains(env.logs.String(), firstBody["inviteString"]) {
		t.Fatalf("logs leaked invite material: %s", env.logs.String())
	}
}

func TestHandleClaimInvite_ConcurrentSingleDisclosure(t *testing.T) {
	t.Parallel()

	env := newClaimTestEnv(t)
	runID := "run-claim-race"
	token := env.seedMinted(t, runID)

	const workers = 8

	var wg sync.WaitGroup

	codes := make([]int, workers)
	bodies := make([]string, workers)

	for i := range workers {
		wg.Add(1)

		go func() {
			defer wg.Done()

			rec := doClaim(t, env.handler, runID)
			codes[i] = rec.Code
			bodies[i] = rec.Body.String()
		}()
	}

	wg.Wait()

	okCount := 0
	goneCount := 0

	for i, code := range codes {
		switch code {
		case http.StatusOK:
			okCount++
		case http.StatusGone:
			goneCount++

			if strings.Contains(bodies[i], token) {
				t.Fatalf("410 body leaked token: %s", bodies[i])
			}
		default:
			t.Fatalf("worker status = %d, want 200 or 410 (body %s)", code, bodies[i])
		}
	}

	if okCount != 1 {
		t.Fatalf("200 responses = %d, want exactly 1", okCount)
	}

	if goneCount < 1 {
		t.Fatal("expected at least one 410")
	}
}

func TestHandleClaimInvite_PollStaysTokenFreeWithPasteS1(t *testing.T) {
	t.Parallel()

	env := newClaimTestEnv(t)
	runID := "run-claim-poll"
	token := env.seedMinted(t, runID)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/session/"+runID, nil)
	rec := httptest.NewRecorder()
	claimRouter(env.handler).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("poll status = %d, want 200", rec.Code)
	}

	payload := decodeClaimJSON(t, rec)
	assertExactKeys(t, payload, []string{"nextInstruction", "state", "ts"})

	var next string
	if err := json.Unmarshal(payload["nextInstruction"], &next); err != nil {
		t.Fatalf("nextInstruction: %v", err)
	}

	if next != "paste_s1" {
		t.Fatalf("nextInstruction = %q, want paste_s1", next)
	}

	body := rec.Body.String()
	if strings.Contains(body, token) {
		t.Fatalf("poll leaked token: %s", body)
	}

	if strings.Contains(body, "inviteString") {
		t.Fatalf("poll includes inviteString: %s", body)
	}

	claimed := doClaim(t, env.handler, runID)
	if claimed.Code != http.StatusOK {
		t.Fatalf("claim status = %d, want 200", claimed.Code)
	}

	after := doPoll(t, env.handler, runID)

	afterBody := after.Body.String()
	if strings.Contains(afterBody, token) || strings.Contains(afterBody, "inviteString") {
		t.Fatalf("post-claim poll leaked invite material: %s", afterBody)
	}

	afterPayload := decodeClaimJSON(t, after)
	if pollNextInstruction(t, afterPayload) != "paste_s1" {
		t.Fatalf("post-claim nextInstruction = %s, want paste_s1", afterPayload["nextInstruction"])
	}
}

func TestHandleClaimInvite_PayloadLoadFailureDoesNotConsume(t *testing.T) {
	t.Parallel()

	env := newClaimTestEnv(t)
	runID := "run-claim-load-fail"
	token := env.seedMinted(t, runID)

	injected := errors.New("injected payload load failure")

	env.store.SetClaimPayloadLoadHook(func() error {
		env.store.SetClaimPayloadLoadHook(nil)

		return injected
	})

	first := doClaim(t, env.handler, runID)
	if first.Code != http.StatusInternalServerError {
		t.Fatalf("first status = %d, want 500 (body %s)", first.Code, first.Body.String())
	}

	if strings.Contains(first.Body.String(), token) {
		t.Fatalf("500 body leaked token: %s", first.Body.String())
	}

	run, err := env.store.GetTestRun(t.Context(), runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if run.S1ClaimedAt != nil {
		t.Fatalf("s1_claimed_at = %v after failed load, want nil", run.S1ClaimedAt)
	}

	retry := doClaim(t, env.handler, runID)
	if retry.Code != http.StatusOK {
		t.Fatalf("retry status = %d, want 200 (body %s)", retry.Code, retry.Body.String())
	}

	payload := decodeClaimJSON(t, retry)

	var inviteString string
	if unmarshalErr := json.Unmarshal(payload["inviteString"], &inviteString); unmarshalErr != nil {
		t.Fatalf("inviteString: %v", unmarshalErr)
	}

	if inviteString == "" {
		t.Fatal("retry inviteString is empty")
	}

	second := doClaim(t, env.handler, runID)
	if second.Code != http.StatusGone {
		t.Fatalf("second status = %d, want 410 (body %s)", second.Code, second.Body.String())
	}

	if strings.Contains(env.logs.String(), token) || strings.Contains(env.logs.String(), inviteString) {
		t.Fatalf("logs leaked invite material: %s", env.logs.String())
	}
}

func TestHandleClaimInvite_StoreErrorLogsNoToken(t *testing.T) {
	t.Parallel()

	env := newClaimTestEnv(t)
	runID := "run-claim-store-error"
	token := env.seedMinted(t, runID)

	if err := env.store.DB().WithContext(t.Context()).Where("1 = 1").Delete(&store.OutgoingInvite{}).Error; err != nil {
		t.Fatalf("delete outgoing invites: %v", err)
	}

	rec := doClaim(t, env.handler, runID)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 (body %s)", rec.Code, rec.Body.String())
	}

	if strings.Contains(rec.Body.String(), token) {
		t.Fatalf("500 body leaked token: %s", rec.Body.String())
	}

	run, err := env.store.GetTestRun(t.Context(), runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if run.S1ClaimedAt != nil {
		t.Fatalf("s1_claimed_at = %v after missing payload, want nil", run.S1ClaimedAt)
	}

	logs := env.logs.String()
	if strings.Contains(logs, token) {
		t.Fatalf("500 logs leaked token: %s", logs)
	}

	if !strings.Contains(logs, "validator claim failed") {
		t.Fatalf("expected generic claim failure log, got %s", logs)
	}
}

func TestHandleClaimInvite_UnknownSession404(t *testing.T) {
	t.Parallel()

	env := newClaimTestEnv(t)

	rec := doClaim(t, env.handler, "missing-run")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}

	var payload map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&payload); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if payload["error"] != validatorcore.CodeSessionNotFound {
		t.Fatalf("error = %q, want %q", payload["error"], validatorcore.CodeSessionNotFound)
	}
}

func TestHandleClaimInvite_NotMinted409(t *testing.T) {
	t.Parallel()

	env := newClaimTestEnv(t)
	runID := "run-claim-not-ready"
	now := int64(1_700_000_000)

	if err := env.store.DB().WithContext(t.Context()).Create(&validatorcore.TestRun{
		TestRunID:    runID,
		IsActive:     true,
		State:        validatorcore.StateActiveRunning,
		TargetOrigin: claimTestTargetOrigin,
		TargetHost:   claimTestTargetHost,
		CreatedAt:    now,
		UpdatedAt:    now,
	}).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}

	rec := doClaim(t, env.handler, runID)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", rec.Code)
	}

	var payload map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&payload); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if payload["error"] != validatorcore.CodeSessionNotReady {
		t.Fatalf("error = %q, want %q", payload["error"], validatorcore.CodeSessionNotReady)
	}
}

func TestHandleClaimInvite_MethodNotAllowedAndNoGETRoute(t *testing.T) {
	t.Parallel()

	env := newClaimTestEnv(t)
	runID := "run-claim-get"
	token := env.seedMinted(t, runID)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/session/"+runID+"/invite", nil)
	rec := httptest.NewRecorder()
	claimRouter(env.handler).ServeHTTP(rec, req)

	if rec.Code == http.StatusOK {
		t.Fatal("GET claim must not succeed")
	}

	if strings.Contains(rec.Body.String(), token) {
		t.Fatalf("GET claim leaked token: %s", rec.Body.String())
	}

	direct := httptest.NewRecorder()
	env.handler.HandleClaimInvite(
		direct,
		httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/session/"+runID+"/invite", nil),
	)

	if direct.Code != http.StatusMethodNotAllowed {
		t.Fatalf("direct GET status = %d, want 405", direct.Code)
	}
}

func TestMountPlaneARoutes_ClaimIsPostOnlyAndSessionBound(t *testing.T) {
	t.Parallel()

	r := newPlaneATestRouter(t)

	routes, err := EnumeratePlaneARoutes(r)
	if err != nil {
		t.Fatalf("EnumeratePlaneARoutes: %v", err)
	}

	var claimPosts, claimGets int

	for _, route := range routes {
		if !strings.HasSuffix(route.FullPath, "/api/session/{id}/invite") {
			continue
		}

		switch route.Method {
		case http.MethodPost:
			claimPosts++
		case http.MethodGet:
			claimGets++
		}
	}

	if claimPosts != 1 {
		t.Fatalf("POST claim routes = %d, want 1", claimPosts)
	}

	if claimGets != 0 {
		t.Fatalf("GET claim routes = %d, want 0", claimGets)
	}

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/session/run-1/invite", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code == http.StatusOK {
		t.Fatal("mounted GET claim must not succeed")
	}
}
