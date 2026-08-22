// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package reverseinvite_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/federationvalidator/active/reverseinvite"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	invitesincoming "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites/incoming"
	invitesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/invites/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/localidentity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/repos"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
	tshttp "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/http"
)

const (
	testLocalDomain = "local.example"
	testTargetHost  = "peer.example"
)

// stubPoster returns a canned response for the invite-accepted call and
// records invocations so tests can prove whether the wire call happened.
type stubPoster struct {
	status   int
	body     string
	err      error
	calls    int
	lastBody []byte
}

func (p *stubPoster) PostInviteAccepted(_ context.Context, _ string, body []byte) (*http.Response, error) {
	p.calls++
	p.lastBody = body

	if p.err != nil {
		return nil, p.err
	}

	return &http.Response{
		StatusCode: p.status,
		Body:       io.NopCloser(strings.NewReader(p.body)),
	}, nil
}

func testLocalIdentity() localidentity.Identity {
	return localidentity.Identity{
		Origin:                "https://" + testLocalDomain,
		Scheme:                "https",
		ProviderDomain:        testLocalDomain,
		ProviderDomainCompare: testLocalDomain,
	}
}

type testEnv struct {
	store    *validatorcore.Core
	svc      *reverseinvite.Service
	parties  *identity.MemoryPartyRepo
	outgoing invitesoutgoing.OutgoingInviteRepo
	incoming invitesincoming.IncomingInviteRepo
	poster   *stubPoster
}

func newTestEnv(t *testing.T) *testEnv {
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
	poster := &stubPoster{
		status: http.StatusOK,
		body:   `{"userID":"sender@peer.example","email":"s@example","name":"Sender"}`,
	}

	svc, err := reverseinvite.New(reverseinvite.Deps{
		Store:           store,
		OutgoingInvites: r.OutgoingInvites,
		IncomingInvites: r.IncomingInvites,
		Parties:         parties,
		Poster:          poster,
		LocalIdentity:   testLocalIdentity(),
	})
	if err != nil {
		t.Fatalf("reverseinvite.New: %v", err)
	}

	return &testEnv{
		store:    store,
		svc:      svc,
		parties:  parties,
		outgoing: r.OutgoingInvites,
		incoming: r.IncomingInvites,
		poster:   poster,
	}
}

// seedRun creates the singleton active run in the given state, targeted at
// the test peer host.
func (e *testEnv) seedRun(t *testing.T, runID, state string) {
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

// bindBob sets bob_user_id on the run and materializes the Bob party, the way
// session extension plus probe creation leave the world.
func (e *testEnv) bindBob(t *testing.T, runID string) string {
	t.Helper()

	bobID := uuid.NewString()

	if err := e.store.DB().WithContext(t.Context()).Model(&validatorcore.TestRun{}).
		Where("test_run_id = ?", runID).
		Update("bob_user_id", bobID).Error; err != nil {
		t.Fatalf("bind bob: %v", err)
	}

	if err := e.parties.Create(t.Context(), &identity.User{
		ID:          bobID,
		Username:    "bob-" + bobID,
		DisplayName: "Bob",
		Role:        identity.RoleProbe,
		Realm:       testLocalDomain,
		CreatedAt:   time.Now(),
	}); err != nil {
		t.Fatalf("create bob party: %v", err)
	}

	return bobID
}

// createIncoming stores a pending incoming invite for Bob, mirroring what the
// paste flow persists before the import CAS.
func (e *testEnv) createIncoming(
	t *testing.T,
	inviteString, token, sender, bobID string,
) (*invitesincoming.IncomingInvite, error) {
	t.Helper()

	invite := &invitesincoming.IncomingInvite{
		InviteString:    inviteString,
		Token:           token,
		SenderFQDN:      sender,
		RecipientUserID: bobID,
		ReceivedAt:      time.Now(),
		Status:          "pending",
	}
	if err := e.incoming.Create(t.Context(), invite); err != nil {
		return nil, fmt.Errorf("create incoming invite: %w", err)
	}

	return invite, nil
}

func (e *testEnv) requireNoS1Claim(t *testing.T, runID string) {
	t.Helper()

	run, err := e.store.GetTestRun(t.Context(), runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	if run.S1ClaimedAt != nil {
		t.Fatalf("s1_claimed_at = %v, want nil", run.S1ClaimedAt)
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

func (e *testEnv) countEvidence(t *testing.T, runID string) int {
	t.Helper()

	var count int64
	if err := e.store.DB().WithContext(t.Context()).
		Model(&validatorcore.EvidenceRow{}).
		Where("test_run_id = ? AND area = ? AND step = ? AND reason_code = ?",
			runID, validatorcore.SpecificationAreaSharing, "invite_accepted", "reverse_invite_accepted").
		Count(&count).Error; err != nil {
		t.Fatalf("count evidence: %v", err)
	}

	return int(count)
}
