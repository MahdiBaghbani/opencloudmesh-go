// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package forwardshare_test

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	outgoingshares "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/api/outgoing/shares"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/federationvalidator/active/forwardshare"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/identity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/peerorigin"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/policy"
	ocmshares "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares"
	sharesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache/loader"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto"
	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/localidentity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/repos"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
	tshttp "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/http"
)

const (
	testLocalDomain = "local.example"
	testDesignated  = "alice"
)

var testLogger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

type testEnv struct {
	store       *validatorcore.Core
	svc         *forwardshare.Service
	handler     *outgoingshares.Handler
	shares      sharesoutgoing.OutgoingShareRepo
	postCount   *atomic.Int32
	failPosts   *atomic.Int32
	flakyPosts  *atomic.Int32
	blockPosts  *atomic.Bool
	postEntered chan struct{}
	postRelease chan struct{}
	captured    *capturedShares
	discovery   *atomic.Pointer[spec.Discovery]
	targetHost  string
	probePath   string
	user        atomic.Pointer[identity.User]
}

func testLocalIdentity() localidentity.Identity {
	return localidentity.Identity{
		Origin:                "https://" + testLocalDomain,
		Scheme:                "https",
		ProviderDomain:        testLocalDomain,
		ProviderDomainCompare: testLocalDomain,
	}
}

// newTestEnv builds the real-DB stack: sqlite repos, the validator store,
// the receiver TLS peer, and the outgoing-share handler with the dispatch
// hook installed (unless withHook is false).
func newTestEnv(t *testing.T, withHook bool) *testEnv {
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

	env := &testEnv{
		store:       store,
		shares:      r.OutgoingShares,
		postCount:   &atomic.Int32{},
		failPosts:   &atomic.Int32{},
		flakyPosts:  &atomic.Int32{},
		blockPosts:  &atomic.Bool{},
		postEntered: make(chan struct{}, 1),
		postRelease: make(chan struct{}),
		captured:    newCapturedShares(),
		discovery:   &atomic.Pointer[spec.Discovery]{},
		probePath:   createProbeFile(t),
	}

	srv := httptest.NewTLSServer(env.receiverHandler(t))
	t.Cleanup(srv.Close)

	env.targetHost = srv.Listener.Addr().String()

	svc, err := forwardshare.New(forwardshare.Deps{
		Store:          store,
		OutgoingShares: r.OutgoingShares,
		LocalIdentity:  testLocalIdentity(),
	})
	if err != nil {
		t.Fatalf("forwardshare.New: %v", err)
	}

	env.svc = svc

	env.discovery.Store(&spec.Discovery{
		Enabled:       true,
		APIVersion:    "1.4.0",
		EndPoint:      srv.URL + "/ocm",
		Capabilities:  []string{"exchange-token"},
		Criteria:      []string{},
		TokenEndPoint: srv.URL + "/ocm/token",
	})

	env.user.Store(&identity.User{ID: "user-alice-local", Username: "alice-local"})

	cfg := tshttp.PermissiveConfig()
	cfg.InsecureSkipVerify = true
	raw := httpclient.New(cfg, nil)

	km := crypto.NewKeyManager("", "https://"+testLocalDomain)
	if err := km.LoadOrGenerate(); err != nil {
		t.Fatalf("key manager: %v", err)
	}

	handler := outgoingshares.NewHandler(
		r.OutgoingShares,
		// No caching: tests change the advertised discovery between attempts
		// to prove the retry replays the snapshotted wire identity.
		discovery.NewClient(raw, cache.NewNoopCache()),
		httpclient.NewContextClient(raw),
		crypto.NewRFC9421Signer(km),
		testLocalDomain,
		env.currentUser,
		testLogger,
		&stubResolver{facts: policy.NewCodeFlow().Evaluate()},
		"https://"+testLocalDomain+"/ocm/token",
	)
	handler.SetAllowedPaths([]string{"/tmp"})
	handler.SetPeerOrigin(peerorigin.NewResolver(false))

	if withHook {
		handler.SetDispatchHook(svc)
	}

	env.handler = handler

	return env
}

func (e *testEnv) currentUser(_ context.Context) (*identity.User, error) {
	return e.user.Load(), nil
}

// receiverHandler serves the mock peer: discovery plus the incoming-share
// endpoint with block, failure, and flake knobs for the retry tests.
func (e *testEnv) receiverHandler(t *testing.T) http.HandlerFunc {
	t.Helper()

	return func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/.well-known/ocm" {
			w.Header().Set("Content-Type", "application/json")
			tshttp.WriteJSON(w, e.discovery.Load())

			return
		}

		if req.Method != http.MethodPost || req.URL.Path != "/ocm/shares" {
			http.NotFound(w, req)

			return
		}

		e.postCount.Add(1)

		// Blocked send: hold the POST open until the test releases it or
		// the client goes away, so a test can cancel mid-flight.
		if e.blockPosts.Load() {
			e.postEntered <- struct{}{}

			select {
			case <-e.postRelease:
				w.WriteHeader(http.StatusInternalServerError)
			case <-req.Context().Done():
			}

			return
		}

		// Clean failure: the receiver never creates a row.
		if e.failPosts.Load() > 0 {
			e.failPosts.Add(-1)
			w.WriteHeader(http.StatusInternalServerError)

			return
		}

		var payload spec.NewShareRequest
		if decodeErr := json.NewDecoder(req.Body).Decode(&payload); decodeErr != nil {
			w.WriteHeader(http.StatusBadRequest)

			return
		}

		if _, recordErr := e.captured.record(payload); recordErr != nil {
			w.WriteHeader(http.StatusConflict)

			return
		}

		// Flaky failure: the row exists but the response reports an
		// error, the uncertain-send case.
		if e.flakyPosts.Load() > 0 {
			e.flakyPosts.Add(-1)
			w.WriteHeader(http.StatusInternalServerError)

			return
		}

		w.WriteHeader(http.StatusCreated)
		tshttp.MustWrite(t, w, []byte(`{"ok":true}`))
	}
}

// seedActiveRun creates the singleton active run in the given state with the
// designated recipient pinned, and binds the session's dispatching party as
// the current user: its local user ID is the run ID.
func (e *testEnv) seedActiveRun(t *testing.T, runID, state string) {
	t.Helper()

	now := time.Now().Unix()
	designated := testDesignated

	if err := e.store.DB().WithContext(t.Context()).Create(&validatorcore.TestRun{
		TestRunID:           runID,
		IsActive:            true,
		State:               state,
		SessionKind:         validatorcore.SessionKindActiveFull,
		TargetHost:          e.targetHost,
		DesignatedShareWith: &designated,
		CreatedAt:           now,
		UpdatedAt:           now,
	}).Error; err != nil {
		t.Fatalf("seed run %s: %v", runID, err)
	}

	e.user.Store(&identity.User{ID: runID, Username: "session-inviter-" + runID})
}

// driftDiscovery re-advertises the receiver with an absolute webdav-receive
// URI kind rooted at the given path, simulating discovery drift.
func (e *testEnv) driftDiscovery(webdavPath string) {
	current := e.discovery.Load()

	drifted := *current
	drifted.ResourceTypes = []spec.ResourceType{
		{
			Name:       "file",
			ShareTypes: []string{"user"},
			Protocols: spec.Protocols{
				spec.ProtocolWebDAV:        spec.StringProtocolRole(webdavPath),
				spec.ProtocolWebDAVReceive: spec.WebDAVReceiveRole(spec.WebDAVReceiveURIAbsolute),
			},
		},
	}

	e.discovery.Store(&drifted)
}

// bindRecipient marks the run's bound recipient user.
func (e *testEnv) bindRecipient(t *testing.T, runID string) *identity.User {
	t.Helper()

	bob := &identity.User{ID: "user-bob-probe", Username: "bob-probe"}

	if err := e.store.DB().WithContext(t.Context()).Model(&validatorcore.TestRun{}).
		Where("test_run_id = ?", runID).
		Update("bob_user_id", bob.ID).Error; err != nil {
		t.Fatalf("bind recipient: %v", err)
	}

	return bob
}

// designatedBody is the one allowed dispatch.
func (e *testEnv) designatedBody() string {
	return shareBody(e.targetHost, testDesignated+"@"+e.targetHost, e.probePath)
}

// designatedRequest is the parsed form of designatedBody.
func designatedRequest(env *testEnv) sharesoutgoing.OutgoingShareRequest {
	return sharesoutgoing.OutgoingShareRequest{
		ReceiverDomain: env.targetHost,
		ShareWith:      testDesignated + "@" + env.targetHost,
		LocalPath:      env.probePath,
		Permissions:    []string{"read"},
	}
}

func shareBody(receiverHost, shareWith, localPath string) string {
	return `{
		"receiverDomain": "` + receiverHost + `",
		"shareWith": "` + shareWith + `",
		"localPath": "` + localPath + `",
		"permissions": ["read"]
	}`
}

// doCreate drives the handler once.
func (e *testEnv) doCreate(t *testing.T, body string) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/shares/outgoing", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	e.handler.HandleCreate(w, req)

	return w
}

// deliverPlan drives the delivery path with a plan the guard granted.
func (e *testEnv) deliverPlan(t *testing.T, plan *outgoingshares.DispatchPlan) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/shares/outgoing", bytes.NewBufferString(e.designatedBody()))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	e.handler.DeliverWithPlan(w, req, designatedRequest(e), e.user.Load(), plan)

	return w
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

func (e *testEnv) requireReservation(t *testing.T, runID string) *validatorcore.DispatchReservation {
	t.Helper()

	reservation, err := e.store.GetDispatchReservation(t.Context(), runID)
	if err != nil {
		t.Fatalf("GetDispatchReservation: %v", err)
	}

	return reservation
}

// ageReservation backdates the reservation's last update.
func (e *testEnv) ageReservation(t *testing.T, runID string, ageSeconds int64) {
	t.Helper()

	if err := e.store.DB().WithContext(t.Context()).Table("dispatch_reservation").
		Where("test_run_id = ?", runID).
		Update("updated_at", time.Now().Unix()-ageSeconds).Error; err != nil {
		t.Fatalf("age reservation: %v", err)
	}
}

func (e *testEnv) listShares(t *testing.T) []*sharesoutgoing.OutgoingShare {
	t.Helper()

	all, err := e.shares.List(t.Context())
	if err != nil {
		t.Fatalf("list shares: %v", err)
	}

	return all
}

// persistDispatchedShare stores the local row the handler persists right
// before the outbound POST.
func (e *testEnv) persistDispatchedShare(t *testing.T, plan *outgoingshares.DispatchPlan) {
	t.Helper()

	e.persistDispatchedShareWithStatus(t, plan, ocmshares.OutgoingShareStatusSent)
}

func (e *testEnv) persistDispatchedShareWithStatus(
	t *testing.T,
	plan *outgoingshares.DispatchPlan,
	status ocmshares.OutgoingShareStatus,
) {
	t.Helper()

	share := &sharesoutgoing.OutgoingShare{
		ProviderID:   plan.ProviderID,
		WebDAVID:     plan.WebDAVID,
		SharedSecret: plan.SharedSecret,
		LocalPath:    e.probePath,
		ReceiverHost: e.targetHost,
		ShareWith:    testDesignated + "@" + e.targetHost,
		Name:         filepath.Base(e.probePath),
		ResourceType: "file",
		ShareType:    "user",
		Permissions:  []string{"read"},
		Status:       status,
	}

	if err := e.shares.Create(t.Context(), share); err != nil {
		t.Fatalf("persist dispatched share: %v", err)
	}
}

func (e *testEnv) seedCapabilityEvidence(t *testing.T, runID, reason string) {
	t.Helper()

	if err := e.store.DB().WithContext(t.Context()).Create(&validatorcore.EvidenceRow{
		TestRunID:    runID,
		Area:         "capability",
		Step:         "file_opened",
		ReasonCode:   reason,
		Severity:     validatorcore.GradePass,
		AffectsGrade: true,
		CreatedAt:    time.Now().Unix(),
	}).Error; err != nil {
		t.Fatalf("seed evidence row: %v", err)
	}
}
