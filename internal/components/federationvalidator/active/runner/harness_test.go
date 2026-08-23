// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package runner_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/federationvalidator/active/reverseinvite"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/federationvalidator/active/runner"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	invitesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites/outgoing"
	sharesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/localidentity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/repos"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
	tshttp "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/http"
)

const (
	testLocalDomain = "local.example"
	testTargetHost  = "peer.example"
	testProbeEmail  = "probe@localhost"
	testProbeName   = "Probe User"
)

func testLocalIdentity() localidentity.Identity {
	return localidentity.Identity{
		Origin:                "https://" + testLocalDomain,
		Scheme:                "https",
		ProviderDomain:        testLocalDomain,
		ProviderDomainCompare: testLocalDomain,
	}
}

type stubPoster struct {
	status int
	body   string
}

func (p *stubPoster) PostInviteAccepted(_ context.Context, _ string, _ []byte) (*http.Response, error) {
	status := p.status
	if status == 0 {
		status = http.StatusOK
	}

	body := p.body
	if body == "" {
		body = `{"userID":"sender@peer.example"}`
	}

	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(body)),
	}, nil
}

type stubInvites struct {
	mintErr    error
	solicitErr error
	mint       *invitesoutgoing.OutgoingInvite
	solicits   int
	mints      int
}

func (s *stubInvites) MintOutgoingInvite(_ context.Context, testRunID string) (*invitesoutgoing.OutgoingInvite, error) {
	s.mints++
	if s.mintErr != nil {
		return nil, s.mintErr
	}

	if s.mint != nil {
		return s.mint, nil
	}

	return &invitesoutgoing.OutgoingInvite{ID: "invite-" + testRunID, Token: "tok-" + testRunID}, nil
}

func (s *stubInvites) SolicitReverse(_ context.Context, _ string) error {
	s.solicits++

	return s.solicitErr
}

// blockingInvites blocks MintOutgoingInvite until ctx is canceled so Stop
// can prove it interrupts an in-flight drive.
type blockingInvites struct {
	started chan struct{}
	once    sync.Once
	mu      sync.Mutex
	seen    error
}

func newBlockingInvites() *blockingInvites {
	return &blockingInvites{started: make(chan struct{})}
}

func (s *blockingInvites) MintOutgoingInvite(ctx context.Context, _ string) (*invitesoutgoing.OutgoingInvite, error) {
	s.once.Do(func() {
		close(s.started)
	})

	<-ctx.Done()

	err := ctx.Err()

	s.mu.Lock()
	s.seen = err
	s.mu.Unlock()

	return nil, fmt.Errorf("blocking mint: %w", err)
}

func (s *blockingInvites) SolicitReverse(ctx context.Context, _ string) error {
	<-ctx.Done()

	return fmt.Errorf("blocking solicit: %w", ctx.Err())
}

func (s *blockingInvites) err() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.seen
}

type stubOutgoing struct {
	err     error
	calls   int
	lastReq sharesoutgoing.OutgoingShareRequest
	lastID  string
}

func (s *stubOutgoing) CreateAsUser(
	_ context.Context,
	user *identity.User,
	req sharesoutgoing.OutgoingShareRequest,
) (*sharesoutgoing.OutgoingShare, error) {
	s.calls++
	s.lastReq = req

	if user != nil {
		s.lastID = user.ID
	}

	if s.err != nil {
		return nil, s.err
	}

	return &sharesoutgoing.OutgoingShare{ShareID: "share-1"}, nil
}

type testEnv struct {
	store   *validatorcore.Core
	parties *identity.MemoryPartyRepo
	svc     *reverseinvite.Service
	runner  *runner.Runner
	invites *stubInvites
	out     *stubOutgoing
}

func newRealInviteEnv(t *testing.T) *testEnv {
	t.Helper()

	ctx := t.Context()

	r, err := repos.New(ctx, config.PersistenceConfig{
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

	parties := identity.NewMemoryPartyRepo()

	svc, err := reverseinvite.New(reverseinvite.Deps{
		Store:           store,
		OutgoingInvites: r.OutgoingInvites,
		IncomingInvites: r.IncomingInvites,
		Parties:         parties,
		Poster:          &stubPoster{},
		LocalIdentity:   testLocalIdentity(),
	})
	if err != nil {
		t.Fatalf("reverseinvite.New: %v", err)
	}

	out := &stubOutgoing{}

	active, err := runner.New(runner.Deps{
		Store:         store,
		Invites:       svc,
		Parties:       parties,
		LocalIdentity: testLocalIdentity(),
		ProbeEmail:    testProbeEmail,
		ProbeName:     testProbeName,
		ProbeFilePath: createProbeFile(t),
		PollInterval:  time.Hour,
	})
	if err != nil {
		t.Fatalf("runner.New: %v", err)
	}

	active.BindOutgoing(out)

	return &testEnv{
		store:   store,
		parties: parties,
		svc:     svc,
		runner:  active,
		out:     out,
	}
}

func newStubEnv(t *testing.T, invites runner.InviteDriver, out *stubOutgoing) *testEnv {
	t.Helper()

	var stub *stubInvites
	if invites == nil {
		stub = &stubInvites{}
		invites = stub
	} else if typed, ok := invites.(*stubInvites); ok {
		stub = typed
	}

	if out == nil {
		out = &stubOutgoing{}
	}

	ctx := t.Context()

	r, err := repos.New(ctx, config.PersistenceConfig{
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

	parties := identity.NewMemoryPartyRepo()

	active, err := runner.New(runner.Deps{
		Store:         store,
		Invites:       invites,
		Parties:       parties,
		LocalIdentity: testLocalIdentity(),
		ProbeEmail:    testProbeEmail,
		ProbeName:     testProbeName,
		ProbeFilePath: createProbeFile(t),
		PollInterval:  time.Hour,
	})
	if err != nil {
		t.Fatalf("runner.New: %v", err)
	}

	active.BindOutgoing(out)

	return &testEnv{
		store:   store,
		parties: parties,
		runner:  active,
		invites: stub,
		out:     out,
	}
}

func (e *testEnv) seedActive(t *testing.T, runID, state string) {
	t.Helper()

	now := time.Now().Unix()
	if err := e.store.DB().WithContext(t.Context()).Create(&validatorcore.TestRun{
		TestRunID:    runID,
		IsActive:     true,
		State:        state,
		TargetOrigin: "https://" + testTargetHost,
		TargetHost:   testTargetHost,
		DiscoveryURL: "https://" + testTargetHost + "/.well-known/ocm",
		CreatedAt:    now,
		UpdatedAt:    now,
	}).Error; err != nil {
		t.Fatalf("seed run %s: %v", runID, err)
	}
}

func (e *testEnv) bindBob(t *testing.T, runID string) string {
	t.Helper()

	bobID := uuid.NewString()
	if err := e.store.DB().WithContext(t.Context()).Model(&validatorcore.TestRun{}).
		Where("test_run_id = ?", runID).
		Update("bob_user_id", bobID).Error; err != nil {
		t.Fatalf("bind bob: %v", err)
	}

	return bobID
}

func (e *testEnv) pinDesignated(t *testing.T, runID, shareWith string) {
	t.Helper()

	if err := e.store.DB().WithContext(t.Context()).Model(&validatorcore.TestRun{}).
		Where("test_run_id = ?", runID).
		Update("designated_share_with", shareWith).Error; err != nil {
		t.Fatalf("pin designated: %v", err)
	}
}

func (e *testEnv) requireState(t *testing.T, runID, want string) {
	t.Helper()

	run, err := e.store.GetTestRun(t.Context(), runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if run.State != want {
		t.Fatalf("state = %q, want %q", run.State, want)
	}
}

func (e *testEnv) requireReason(t *testing.T, runID, want string) {
	t.Helper()

	run, err := e.store.GetTestRun(t.Context(), runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if run.TerminalReason == nil || *run.TerminalReason != want {
		t.Fatalf("terminal_reason = %v, want %q", run.TerminalReason, want)
	}
}

func (e *testEnv) ageUpdatedAt(t *testing.T, runID string, at int64) {
	t.Helper()

	if err := e.store.DB().WithContext(t.Context()).Model(&validatorcore.TestRun{}).
		Where("test_run_id = ?", runID).
		Update("updated_at", at).Error; err != nil {
		t.Fatalf("age updated_at: %v", err)
	}
}

func (e *testEnv) requireUpdatedAt(t *testing.T, runID string, want int64) {
	t.Helper()

	run, err := e.store.GetTestRun(t.Context(), runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if run.UpdatedAt != want {
		t.Fatalf("updated_at = %d, want %d", run.UpdatedAt, want)
	}
}

func (e *testEnv) requireInactive(t *testing.T, runID string) {
	t.Helper()

	run, err := e.store.GetTestRun(t.Context(), runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if run.IsActive {
		t.Fatalf("%s is_active = 1, want 0", runID)
	}
}

func (e *testEnv) startFastRunner(t *testing.T, poll time.Duration) *runner.Runner {
	t.Helper()

	var invites runner.InviteDriver
	if e.invites != nil {
		invites = e.invites
	} else {
		invites = e.svc
	}

	fast, err := runner.New(runner.Deps{
		Store:         e.store,
		Invites:       invites,
		Parties:       e.parties,
		LocalIdentity: testLocalIdentity(),
		ProbeEmail:    testProbeEmail,
		ProbeName:     testProbeName,
		ProbeFilePath: createProbeFile(t),
		PollInterval:  poll,
	})
	if err != nil {
		t.Fatalf("runner.New: %v", err)
	}

	fast.BindOutgoing(e.out)
	fast.Start()

	return fast
}

func seedReadyWaiter(t *testing.T, store *validatorcore.Core, runID string, readyAt int64) {
	t.Helper()

	row := &validatorcore.TestRun{
		TestRunID:      runID,
		State:          validatorcore.StatePassiveRunning,
		TargetHost:     testTargetHost,
		TargetOrigin:   "https://" + testTargetHost,
		DiscoveryURL:   "https://" + testTargetHost + "/.well-known/ocm",
		OptInActive:    true,
		PassiveReadyAt: &readyAt,
		CreatedAt:      readyAt,
		UpdatedAt:      readyAt,
	}
	if err := store.DB().WithContext(t.Context()).Create(row).Error; err != nil {
		t.Fatalf("seed ready waiter %s: %v", runID, err)
	}
}

func createProbeFile(t *testing.T) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "hello-ocm.txt")
	if err := os.WriteFile(path, []byte("probe"), 0o600); err != nil {
		t.Fatalf("write probe file: %v", err)
	}

	return path
}
