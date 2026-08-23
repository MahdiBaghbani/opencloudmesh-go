// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package forwardshare_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/federationvalidator/active/reverseinvite"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/federationvalidator/active/reverseshare"
	fedcore "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/federationvalidator/core"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites/outgoing/accepted"
	sharesincoming "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/incoming"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/statistics"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

// matrixRemoteUser is the remote accepter identity the peer reports when it
// accepts the session's outgoing invite; it becomes the designated recipient.
const matrixRemoteUser = "matrix-remote-accepter"

// courierPoster fakes the peer's invite-accepted endpoint for the reverse
// leg: it captures the outbound request and answers a valid 200 identity.
type courierPoster struct {
	calls    int
	lastHost string
	lastBody []byte
}

func (p *courierPoster) PostInviteAccepted(_ context.Context, targetHost string, body []byte) (*http.Response, error) {
	p.calls++
	p.lastHost = targetHost
	p.lastBody = body

	return &http.Response{
		StatusCode: http.StatusOK,
		Body: io.NopCloser(strings.NewReader(
			`{"userID":"matrix-sender","email":"sender@peer.invalid","name":"Matrix Sender"}`)),
	}, nil
}

// courierMatrixEnv is the in-process courier matrix fixture: the shared
// forward-share harness plus the reverse legs on the same store and repos.
type courierMatrixEnv struct {
	*testEnv

	parties        *identity.MemoryPartyRepo
	reverseInvite  *reverseinvite.Service
	reverseShare   *reverseshare.Service
	inviteAccepted http.HandlerFunc
	pasteRouter    *chi.Mux
	hasher         validatorcore.StatsHostHasher
	poster         *courierPoster
}

func newCourierMatrixEnv(t *testing.T) *courierMatrixEnv {
	t.Helper()

	env := newTestEnv(t, true)

	salt := make([]byte, statistics.RedactionSaltSize)
	for i := range salt {
		salt[i] = byte(i + 1)
	}

	hasher, err := fedcore.New(salt)
	if err != nil {
		t.Fatalf("fedcore.New: %v", err)
	}

	env.store.SetStatsHostHasher(hasher)

	parties := identity.NewMemoryPartyRepo()
	poster := &courierPoster{}

	reverseInvite, err := reverseinvite.New(reverseinvite.Deps{
		Store:           env.store,
		OutgoingInvites: env.repos.OutgoingInvites,
		IncomingInvites: env.repos.IncomingInvites,
		Parties:         parties,
		Poster:          poster,
		LocalIdentity:   testLocalIdentity(),
	})
	if err != nil {
		t.Fatalf("reverseinvite.New: %v", err)
	}

	reverseShare, err := reverseshare.New(reverseshare.Deps{
		Store:          env.store,
		IncomingShares: env.repos.IncomingShares,
		LocalIdentity:  testLocalIdentity(),
	})
	if err != nil {
		t.Fatalf("reverseshare.New: %v", err)
	}

	product := accepted.NewHandler(env.repos.OutgoingInvites, parties, nil, testLocalDomain, "https")

	pasteRouter := chi.NewRouter()
	pasteRouter.Post("/api/session/{id}/reverse-invite", reverseInvite.HandleReverseInvite)

	return &courierMatrixEnv{
		testEnv:        env,
		parties:        parties,
		reverseInvite:  reverseInvite,
		reverseShare:   reverseShare,
		inviteAccepted: reverseInvite.DecorateInviteAccepted(product.HandleInviteAccepted),
		pasteRouter:    pasteRouter,
		hasher:         hasher,
		poster:         poster,
	}
}

// startActiveSession inserts a passive-complete session row aimed at the
// receiver, extends it to the active run, and materializes the Bob party the
// extension already bound; the bound bob_user_id is never reminted here.
func (e *courierMatrixEnv) startActiveSession(t *testing.T) string {
	t.Helper()

	ctx := t.Context()

	runID, err := identity.UUIDv7()
	if err != nil {
		t.Fatalf("mint run id: %v", err)
	}

	now := time.Now().Unix()

	if err := e.store.CreatePassiveSession(ctx, &validatorcore.TestRun{
		TestRunID:    runID,
		IsActive:     false,
		State:        validatorcore.StatePassiveComplete,
		TargetOrigin: "https://" + e.targetHost,
		TargetHost:   e.targetHost,
		OptInStats:   true,
		CreatedAt:    now,
		UpdatedAt:    now,
	}); err != nil {
		t.Fatalf("create passive session: %v", err)
	}

	if err := e.store.ExtendToActive(ctx, runID); err != nil {
		t.Fatalf("extend to active: %v", err)
	}

	run := e.requireRun(t, runID)

	if run.State != validatorcore.StateActiveRunning {
		t.Fatalf("state = %q, want %q", run.State, validatorcore.StateActiveRunning)
	}

	if !run.IsActive {
		t.Fatal("is_active = false, want true")
	}

	if validatorcore.SessionKindOf(run) != validatorcore.SessionKindActiveFull {
		t.Fatalf("session kind = %q, want %q", validatorcore.SessionKindOf(run), validatorcore.SessionKindActiveFull)
	}

	if run.BobUserID == nil || *run.BobUserID == "" {
		t.Fatal("bob_user_id is empty after extension")
	}

	bobID := *run.BobUserID

	parsed, parseErr := uuid.Parse(bobID)
	if parseErr != nil || parsed.Version() != 7 {
		t.Fatalf("bob_user_id %q is not a UUIDv7 (err=%v)", bobID, parseErr)
	}

	if bobID == runID {
		t.Fatal("bob_user_id must differ from the test run id")
	}

	if err := e.parties.Create(ctx, &identity.User{
		ID:          bobID,
		Username:    "bob-" + bobID,
		Email:       "bob-probe-" + bobID + "@local.example",
		DisplayName: "Bob",
		Role:        identity.RoleProbe,
		Realm:       testLocalDomain,
		CreatedAt:   time.Now(),
	}); err != nil {
		t.Fatalf("create bob party: %v", err)
	}

	return runID
}

// acceptForwardInvite mints the outgoing invite, proves the inviting party
// materialized on the run id, binds it as the dispatching user, and drives
// the real wrapped invite-accepted endpoint. Returns the minted token.
func (e *courierMatrixEnv) acceptForwardInvite(t *testing.T, runID string) string {
	t.Helper()

	ctx := t.Context()

	invite, err := e.reverseInvite.MintOutgoingInvite(ctx, runID)
	if err != nil {
		t.Fatalf("mint outgoing invite: %v", err)
	}

	alice, err := e.parties.Get(ctx, runID)
	if err != nil {
		t.Fatalf("load inviting party: %v", err)
	}

	if alice.ID != runID {
		t.Fatalf("inviting party id = %q, want %q", alice.ID, runID)
	}

	if alice.Role != identity.RoleProbe {
		t.Fatalf("inviting party role = %q, want %q", alice.Role, identity.RoleProbe)
	}

	if alice.Realm != testLocalDomain {
		t.Fatalf("inviting party realm = %q, want %q", alice.Realm, testLocalDomain)
	}

	if alice.ExpiresAt != nil {
		t.Fatalf("inviting party expires_at = %v, want nil", alice.ExpiresAt)
	}

	e.user.Store(alice)

	e.postInviteAccepted(t, invite.Token)

	e.requireState(t, runID, validatorcore.StateInviteAccepted)

	run := e.requireRun(t, runID)
	if run.DesignatedShareWith == nil || *run.DesignatedShareWith != matrixRemoteUser {
		t.Fatalf("designated_share_with = %v, want %q", run.DesignatedShareWith, matrixRemoteUser)
	}

	return invite.Token
}

// postInviteAccepted posts one invite-accepted request and requires the 200.
func (e *courierMatrixEnv) postInviteAccepted(t *testing.T, token string) {
	t.Helper()

	rec := e.postInviteAcceptedRaw(t, token)
	if rec.Code != http.StatusOK {
		t.Fatalf("invite-accepted status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
}

// postInviteAcceptedRaw posts one invite-accepted request through the wrapped
// product handler and returns the recorder so callers can assert replays.
func (e *courierMatrixEnv) postInviteAcceptedRaw(t *testing.T, token string) *httptest.ResponseRecorder {
	t.Helper()

	body := `{"recipientProvider":"` + e.targetHost + `","token":"` + token +
		`","userID":"` + matrixRemoteUser + `","email":"accepter@peer.invalid","name":"Matrix Accepter"}`

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/ocm/invite-accepted", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()
	e.inviteAccepted(rec, req)

	return rec
}

// pasteReverseInvite solicits the reverse leg, mints the peer's reverse
// invite token, pastes it through the matrix router, and proves the
// accepted world: final state, exact correlation, accepted incoming invite
// for Bob, and exactly one reverse-invite accept evidence row. Returns the
// pasted token.
func (e *courierMatrixEnv) pasteReverseInvite(t *testing.T, runID string) string {
	t.Helper()

	ctx := t.Context()

	if err := e.reverseInvite.SolicitReverse(ctx, runID); err != nil {
		t.Fatalf("solicit reverse: %v", err)
	}

	token := matrixInviteToken(t)
	inviteString := invites.BuildInviteString(token, e.targetHost)

	e.postReverseInvite(t, runID, inviteString)

	e.requireState(t, runID, validatorcore.StateReverseInviteAccepted)

	run := e.requireRun(t, runID)
	bobID := *run.BobUserID

	corr, err := e.store.GetShareCorrelation(ctx, runID, validatorcore.RoleIncomingInvite, validatorcore.LocalIdentityB)
	if err != nil {
		t.Fatalf("GetShareCorrelation: %v", err)
	}

	if corr.ProviderID != token {
		t.Fatalf("correlation provider id = %q, want %q", corr.ProviderID, token)
	}

	if corr.InviteID == nil || *corr.InviteID == "" {
		t.Fatal("correlation invite id is empty")
	}

	if corr.SenderHost != e.targetHost {
		t.Fatalf("correlation sender host = %q, want %q", corr.SenderHost, e.targetHost)
	}

	invite, err := e.repos.IncomingInvites.GetByIDForRecipientUserID(ctx, *corr.InviteID, bobID)
	if err != nil {
		t.Fatalf("load incoming invite: %v", err)
	}

	if invite.Token != token {
		t.Fatalf("incoming invite token = %q, want %q", invite.Token, token)
	}

	if invite.RecipientUserID != bobID {
		t.Fatalf("incoming invite recipient = %q, want %q", invite.RecipientUserID, bobID)
	}

	if invite.Status != invites.InviteStatusAccepted {
		t.Fatalf("incoming invite status = %q, want %q", invite.Status, invites.InviteStatusAccepted)
	}

	rows := e.evidenceRows(t, runID, validatorcore.SpecificationAreaSharing, "invite_accepted", "reverse_invite_accepted")
	if len(rows) != 1 {
		t.Fatalf("reverse-invite evidence rows = %d, want 1", len(rows))
	}

	if rows[0].Severity != validatorcore.GradePass {
		t.Fatalf("reverse-invite evidence severity = %q, want %q", rows[0].Severity, validatorcore.GradePass)
	}

	if !rows[0].AffectsGrade {
		t.Fatal("reverse-invite evidence must be grade-affecting")
	}

	assertOutboundAcceptance(t, e, token, bobID)

	return token
}

// postReverseInvite pastes one canonical invite string through the matrix
// router and requires the protocol 200.
func (e *courierMatrixEnv) postReverseInvite(t *testing.T, runID, inviteString string) {
	t.Helper()

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost,
		"/api/session/"+runID+"/reverse-invite",
		strings.NewReader(`{"inviteString":"`+inviteString+`"}`))
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()
	e.pasteRouter.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("paste status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
}

// dispatchForwardShare drives the designated dispatch to the receiver and
// proves the committed world, then replays the same request and proves no
// second remote share or provider identity appears. Counts are per-dispatch
// deltas so sequential sessions can share one fixture.
func (e *courierMatrixEnv) dispatchForwardShare(t *testing.T, runID string) {
	t.Helper()

	body := shareBody(e.targetHost, matrixRemoteUser+"@"+e.targetHost, e.probePath)

	basePosts := e.postCount.Load()

	w := e.doCreate(t, body)
	if w.Code != http.StatusCreated {
		t.Fatalf("dispatch status = %d, want 201: %s", w.Code, w.Body.String())
	}

	e.requireState(t, runID, validatorcore.StateForwardShareSent)

	if got := e.postCount.Load() - basePosts; got != 1 {
		t.Fatalf("outbound POSTs for dispatch = %d, want 1", got)
	}

	reservation := e.requireReservation(t, runID)
	if reservation.Status != validatorcore.DispatchStatusCASCommitted {
		t.Fatalf("reservation status = %q, want %q", reservation.Status, validatorcore.DispatchStatusCASCommitted)
	}

	e.shareForProvider(t, reservation.ProviderID)

	payload := e.capturedPayload(t, reservation.ProviderID)
	if payload.Protocol.WebDAV == nil || payload.Protocol.WebDAV.SharedSecret != reservation.SharedSecret {
		t.Fatal("wire shared secret does not match the reservation snapshot")
	}

	w = e.doCreate(t, body)
	if w.Code != http.StatusCreated {
		t.Fatalf("replay status = %d, want 201: %s", w.Code, w.Body.String())
	}

	if got := e.postCount.Load() - basePosts; got != 1 {
		t.Fatalf("outbound POSTs after replay = %d, want 1", got)
	}

	e.shareForProvider(t, reservation.ProviderID)
	e.capturedPayload(t, reservation.ProviderID)
}

// exerciseForwardCapability observes the token exchange for the run's
// dispatched share and proves the capability evidence row and the wait.
func (e *courierMatrixEnv) exerciseForwardCapability(t *testing.T, runID string) {
	t.Helper()

	reservation := e.requireReservation(t, runID)
	share := e.shareForProvider(t, reservation.ProviderID)

	if err := e.reverseShare.ObserveTokenExchange(t.Context(), share); err != nil {
		t.Fatalf("observe token exchange: %v", err)
	}

	rows := e.evidenceRows(t, runID, "capability", "file_opened", "token_exchange")
	if len(rows) != 1 {
		t.Fatalf("capability evidence rows = %d, want 1", len(rows))
	}

	if rows[0].Severity != validatorcore.GradePass || !rows[0].AffectsGrade {
		t.Fatalf("capability evidence = (%q, %v), want (%q, true)",
			rows[0].Severity, rows[0].AffectsGrade, validatorcore.GradePass)
	}

	e.requireState(t, runID, validatorcore.StateReverseAwaitingShare)
}

// deliverReverseShare persists the peer's reverse share addressed to Bob and
// observes it, then proves the terminal-pass world: state and reason, the
// reverse provider id stamp, the reverse-share evidence row, and statistics
// landed before the observe call reported success. Returns the provider id.
func (e *courierMatrixEnv) deliverReverseShare(t *testing.T, runID, wantReason string) string {
	t.Helper()

	ctx := t.Context()

	run := e.requireRun(t, runID)
	bobID := *run.BobUserID

	providerID, err := identity.UUIDv7()
	if err != nil {
		t.Fatalf("mint reverse provider id: %v", err)
	}

	share := &sharesincoming.IncomingShare{
		ShareID:         matrixShareID(t),
		ProviderID:      providerID,
		SenderHost:      e.targetHost,
		RecipientUserID: bobID,
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
	}
	if err := e.repos.IncomingShares.Create(ctx, share); err != nil {
		t.Fatalf("create incoming share: %v", err)
	}

	if err := e.reverseShare.ObserveCreatedShare(ctx, share); err != nil {
		t.Fatalf("observe created share: %v", err)
	}

	run = e.requireRun(t, runID)

	if run.State != validatorcore.StateTerminalPass {
		t.Fatalf("state = %q, want %q", run.State, validatorcore.StateTerminalPass)
	}

	if run.TerminalReason == nil || *run.TerminalReason != wantReason {
		t.Fatalf("terminal_reason = %v, want %q", run.TerminalReason, wantReason)
	}

	if run.ReverseShareProviderID == nil || *run.ReverseShareProviderID != providerID {
		t.Fatalf("reverse_share_provider_id = %v, want %q", run.ReverseShareProviderID, providerID)
	}

	rows := e.evidenceRows(t, runID, "sharing", "reverse_share", "reverse_share_received")
	if len(rows) != 1 {
		t.Fatalf("reverse-share evidence rows = %d, want 1", len(rows))
	}

	if run.StatsWrittenAt == nil {
		t.Fatal("stats_written_at is null after the observed pass")
	}

	return providerID
}
