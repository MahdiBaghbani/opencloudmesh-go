// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package passive

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	gormsqlite "github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/federationvalidator/catalog"
	fedcore "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/federationvalidator/core"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/statistics"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

func openHandlerTestStore(t *testing.T) *validatorcore.Core {
	t.Helper()

	dsn := fmt.Sprintf(
		"file:%s?mode=memory&cache=shared",
		strings.NewReplacer("/", "_", " ", "_").Replace(t.Name()),
	)

	db, err := gorm.Open(gormsqlite.Open(dsn), &gorm.Config{
		Logger:         logger.Default.LogMode(logger.Silent),
		TranslateError: true,
	})
	if err != nil {
		t.Fatalf("open memory db: %v", err)
	}

	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("db handle: %v", err)
	}

	sqlDB.SetMaxOpenConns(1)

	if err := validatorcore.MigrateModels(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	core := validatorcore.NewCore(db)
	core.SetSessionConfig(validatorcore.SessionConfig{InFlightPassiveLimit: 10})
	core.SetStatsHostHasher(testFedCore(t))

	return core
}

func allowActiveExtend(h *Handler) {
	if h == nil {
		return
	}

	h.SetCaps(catalog.FullCaps())
}

func allowProbeExtend(p *ProbeRunner) {
	if p == nil {
		return
	}

	p.canExtend = func() bool { return true }
}

func testFedCore(t *testing.T) *fedcore.Core {
	t.Helper()

	salt := make([]byte, statistics.RedactionSaltSize)
	for i := range salt {
		salt[i] = byte(i + 1)
	}

	c, err := fedcore.New(salt)
	if err != nil {
		t.Fatalf("fedcore.New: %v", err)
	}

	return c
}

const (
	// Budget for StartAsync completion under make test-go
	// (-race -coverpkg -shuffle). Isolation is ~1.4s; 2s flakes
	// when the full tree contends. Matches session_stall_sweep_test
	// and sessionPollTimeout budgets.
	waitForStateDeadline = 10 * time.Second
	waitForStatePoll     = 20 * time.Millisecond
)

func waitForState(t *testing.T, store *validatorcore.Core, ctx context.Context, runID string) {
	t.Helper()

	const wantState = validatorcore.StatePassiveComplete

	deadline := time.Now().Add(waitForStateDeadline)

	for time.Now().Before(deadline) {
		got, err := store.GetTestRun(ctx, runID)
		if err == nil && got.State == wantState {
			return
		}

		time.Sleep(waitForStatePoll)
	}

	got, err := store.GetTestRun(ctx, runID)
	if err != nil {
		t.Fatalf("GetTestRun while waiting for %q: %v", wantState, err)
	}

	t.Fatalf("state = %q, want %q before deadline", got.State, wantState)
}

func mustJSON(t *testing.T, payload any) []byte {
	t.Helper()

	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	return body
}

func loadCreatedRun(
	t *testing.T,
	store *validatorcore.Core,
	rec *httptest.ResponseRecorder,
) *validatorcore.TestRun {
	t.Helper()

	created := decodeCreateEcho(t, rec)

	row, err := store.GetTestRun(t.Context(), created.ID)
	if err != nil {
		t.Fatalf("GetTestRun: %v", err)
	}

	return row
}
