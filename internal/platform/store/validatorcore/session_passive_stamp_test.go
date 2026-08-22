// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

import (
	"testing"
	"time"
)

func TestStampPassiveProbeMetadata_WritesNonEmptyOnly(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	now := time.Now().Unix()
	runID := "run-stamp-meta"

	row := &TestRun{
		TestRunID:  runID,
		State:      StateCreated,
		TargetHost: "peer.example",
		CreatedAt:  now,
		UpdatedAt:  now,
	}
	if err := core.CreatePassiveSession(ctx, row); err != nil {
		t.Fatalf("create: %v", err)
	}

	if err := core.StampPassiveProbeMetadata(ctx, runID, "", "", ""); err != nil {
		t.Fatalf("empty stamp: %v", err)
	}

	got, loadErr := core.GetTestRun(ctx, runID)
	if loadErr != nil {
		t.Fatalf("GetTestRun: %v", loadErr)
	}

	if got.JwksURI != "" || got.Platform != nil || got.APIVersion != nil {
		t.Fatalf("empty stamp wrote values jwks=%q platform=%v api=%v", got.JwksURI, got.Platform, got.APIVersion)
	}

	if stampErr := core.StampPassiveProbeMetadata(ctx, runID, "https://peer.example/jwks", "nextcloud", "1.4.0"); stampErr != nil {
		t.Fatalf("stamp: %v", stampErr)
	}

	got, loadErr = core.GetTestRun(ctx, runID)
	if loadErr != nil {
		t.Fatalf("GetTestRun after stamp: %v", loadErr)
	}

	if got.JwksURI != "https://peer.example/jwks" {
		t.Fatalf("jwks_uri = %q", got.JwksURI)
	}

	if got.Platform == nil || *got.Platform != "nextcloud" {
		t.Fatalf("platform = %v", got.Platform)
	}

	if got.APIVersion == nil || *got.APIVersion != "1.4.0" {
		t.Fatalf("api_version = %v", got.APIVersion)
	}
}

func TestStampPassiveReadyAt_FirstWins(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)
	ctx := t.Context()
	now := time.Now().Unix()
	runID := "run-ready"

	row := &TestRun{
		TestRunID:   runID,
		State:       StateCreated,
		TargetHost:  "peer.example",
		OptInActive: true,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := core.CreatePassiveSession(ctx, row); err != nil {
		t.Fatalf("create: %v", err)
	}

	if err := core.RunStartProbe(ctx, runID); err != nil {
		t.Fatalf("RunStartProbe: %v", err)
	}

	if err := core.StampPassiveReadyAt(ctx, runID); err != nil {
		t.Fatalf("stamp: %v", err)
	}

	first, loadErr := core.GetTestRun(ctx, runID)
	if loadErr != nil {
		t.Fatalf("GetTestRun: %v", loadErr)
	}

	if first.PassiveReadyAt == nil {
		t.Fatal("passive_ready_at unset")
	}

	if stampErr := core.StampPassiveReadyAt(ctx, runID); stampErr != nil {
		t.Fatalf("repeat stamp: %v", stampErr)
	}

	second, loadErr := core.GetTestRun(ctx, runID)
	if loadErr != nil {
		t.Fatalf("GetTestRun after repeat: %v", loadErr)
	}

	if second.PassiveReadyAt == nil || *second.PassiveReadyAt != *first.PassiveReadyAt {
		t.Fatalf("ready_at first=%v second=%v", first.PassiveReadyAt, second.PassiveReadyAt)
	}
}

func TestFailPassive_RejectsActiveState(t *testing.T) {
	t.Parallel()

	core := openTestCore(t)

	err := core.FailPassive(t.Context(), "run-x", StateActiveRunning, "passive_probe_failed")
	if err == nil {
		t.Fatal("expected unsupported state error")
	}
}
