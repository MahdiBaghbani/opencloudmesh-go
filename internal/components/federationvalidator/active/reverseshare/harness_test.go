// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package reverseshare_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/federationvalidator/active/reverseshare"
	fedcore "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/federationvalidator/core"
	sharesincoming "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/incoming"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/localidentity"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/repos"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/statistics"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
	tshttp "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/http"
)

const (
	testTargetHost   = "peer.example"
	testTargetOrigin = "https://peer.example"
)

// testLocalIdentity is the harness local identity; only the scheme feeds the
// sender-host normalization under test.
var testLocalIdentity = localidentity.Identity{Scheme: "https"}

type testEnv struct {
	store  *validatorcore.Core
	svc    *reverseshare.Service
	shares sharesincoming.IncomingShareRepo
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

	store.SetStatsHostHasher(testStatsHostHasher(t))

	svc, err := reverseshare.New(reverseshare.Deps{
		Store:          store,
		IncomingShares: r.IncomingShares,
		LocalIdentity:  testLocalIdentity,
	})
	if err != nil {
		t.Fatalf("reverseshare.New: %v", err)
	}

	return &testEnv{store: store, svc: svc, shares: r.IncomingShares}
}

// seedRun creates the singleton active run in the given state with a fresh
// Bob binding, opted into statistics.
func (e *testEnv) seedRun(t *testing.T, runID, state string) string {
	t.Helper()

	now := time.Now().Unix()
	bobID := uuid.NewString()

	if err := e.store.DB().WithContext(t.Context()).Create(&validatorcore.TestRun{
		TestRunID:    runID,
		IsActive:     true,
		State:        state,
		TargetOrigin: testTargetOrigin,
		TargetHost:   testTargetHost,
		BobUserID:    &bobID,
		OptInStats:   true,
		CreatedAt:    now,
		UpdatedAt:    now,
	}).Error; err != nil {
		t.Fatalf("seed run %s: %v", runID, err)
	}

	return bobID
}

// addShare stores a reverse share in the recipient's inbox the way the
// inbound handler leaves it after a durable create.
func (e *testEnv) addShare(t *testing.T, recipientUserID, providerID, senderHost string) *sharesincoming.IncomingShare {
	t.Helper()

	share := &sharesincoming.IncomingShare{
		ShareID:         uuid.NewString(),
		ProviderID:      providerID,
		SenderHost:      senderHost,
		RecipientUserID: recipientUserID,
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
	}
	if err := e.shares.Create(t.Context(), share); err != nil {
		t.Fatalf("create incoming share: %v", err)
	}

	return share
}

func (e *testEnv) requireRun(t *testing.T, runID string) *validatorcore.TestRun {
	t.Helper()

	run, err := e.store.GetTestRun(t.Context(), runID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	return run
}

func (e *testEnv) evidenceRows(
	t *testing.T,
	runID, area, step, reason string,
) []validatorcore.EvidenceRow {
	t.Helper()

	var rows []validatorcore.EvidenceRow
	if err := e.store.DB().WithContext(t.Context()).
		Where("test_run_id = ? AND area = ? AND step = ? AND reason_code = ?", runID, area, step, reason).
		Find(&rows).Error; err != nil {
		t.Fatalf("list evidence rows: %v", err)
	}

	return rows
}

func (e *testEnv) requireLateShareStats(t *testing.T, runID string) {
	t.Helper()

	if count := e.countStatsRaw(t); count != 1 {
		t.Fatalf("stats_raw count = %d, want 1", count)
	}

	var raw validatorcore.StatsRaw
	if err := e.store.DB().WithContext(t.Context()).First(&raw).Error; err != nil {
		t.Fatalf("load stats_raw: %v", err)
	}

	if raw.GradeSharing == nil || *raw.GradeSharing != validatorcore.GradePass {
		t.Fatalf("late grade_sharing = %v, want %q from share evidence",
			raw.GradeSharing, validatorcore.GradePass)
	}

	e.requireReverseShareEvidence(t, runID)
}

func (e *testEnv) requireReverseShareEvidence(t *testing.T, runID string) {
	t.Helper()

	rows := e.evidenceRows(
		t,
		runID,
		validatorcore.SpecificationAreaSharing,
		"reverse_share",
		"reverse_share_received",
	)
	if len(rows) != 1 {
		t.Fatalf("reverse-share evidence = %d, want 1", len(rows))
	}

	if rows[0].Severity != validatorcore.GradePass {
		t.Fatalf("reverse-share severity = %q, want %q", rows[0].Severity, validatorcore.GradePass)
	}

	if !rows[0].AffectsGrade {
		t.Fatal("reverse-share evidence must affect grade")
	}
}

func (e *testEnv) countReportExchanges(t *testing.T, runID string) int64 {
	t.Helper()

	var count int64
	if err := e.store.DB().WithContext(t.Context()).
		Model(&validatorcore.ReportExchange{}).
		Where("test_run_id = ?", runID).
		Count(&count).Error; err != nil {
		t.Fatalf("count report exchanges: %v", err)
	}

	return count
}

func (e *testEnv) countStatsRaw(t *testing.T) int64 {
	t.Helper()

	var count int64
	if err := e.store.DB().WithContext(t.Context()).Model(&validatorcore.StatsRaw{}).Count(&count).Error; err != nil {
		t.Fatalf("count stats_raw: %v", err)
	}

	return count
}

func testStatsHostHasher(t *testing.T) validatorcore.StatsHostHasher {
	t.Helper()

	salt := make([]byte, statistics.RedactionSaltSize)
	for i := range salt {
		salt[i] = byte(i + 1)
	}

	hasher, err := fedcore.New(salt)
	if err != nil {
		t.Fatalf("fedcore.New: %v", err)
	}

	return hasher
}

// newServiceWithShares builds the service on an existing store with a
// replaced incoming-share repo, for tests that wrap the inbox.
func newServiceWithShares(
	t *testing.T,
	store *validatorcore.Core,
	shares sharesincoming.IncomingShareRepo,
) (*reverseshare.Service, error) {
	t.Helper()

	svc, err := reverseshare.New(reverseshare.Deps{
		Store:          store,
		IncomingShares: shares,
		LocalIdentity:  testLocalIdentity,
	})
	if err != nil {
		return nil, fmt.Errorf("reverseshare.New: %w", err)
	}

	return svc, nil
}
