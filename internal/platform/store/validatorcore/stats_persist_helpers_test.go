// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

import (
	"testing"
	"time"

	fedcore "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/federationvalidator/core"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/statistics"
)

func testStatsHostHasher(t *testing.T) StatsHostHasher {
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

func seedPassiveComplete(t *testing.T, core *Core, runID, targetOrigin string, optInStats bool) {
	t.Helper()

	ctx := t.Context()
	now := time.Now().Unix()

	row := &TestRun{
		TestRunID:    runID,
		State:        StatePassiveComplete,
		TargetOrigin: targetOrigin,
		TargetHost:   "peer.example",
		OptInStats:   optInStats,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	if err := core.CreatePassiveSession(ctx, row); err != nil {
		t.Fatalf("CreatePassiveSession: %v", err)
	}
}

func seedTerminalStatsRun(t *testing.T, core *Core, runID string, finishedAt int64) {
	t.Helper()

	row := &TestRun{
		TestRunID:    runID,
		State:        StateTerminalPass,
		TargetOrigin: "https://peer.example",
		TargetHost:   "peer.example",
		FinishedAt:   &finishedAt,
		OptInStats:   true,
		CreatedAt:    finishedAt,
		UpdatedAt:    finishedAt,
	}

	if err := core.DB().WithContext(t.Context()).Create(row).Error; err != nil {
		t.Fatalf("seed terminal run: %v", err)
	}
}

func seedEvidenceRow(
	t *testing.T,
	core *Core,
	runID, leg, area, step, reasonCode, severity string,
	affectsGrade bool,
) {
	t.Helper()

	row := &EvidenceRow{
		TestRunID:    runID,
		Leg:          &leg,
		Area:         area,
		Step:         step,
		ReasonCode:   reasonCode,
		Severity:     severity,
		AffectsGrade: affectsGrade,
		CreatedAt:    time.Now().Unix(),
	}

	if err := core.DB().WithContext(t.Context()).Create(row).Error; err != nil {
		t.Fatalf("seed evidence row: %v", err)
	}
}
