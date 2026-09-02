// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package reverseshare_test

import (
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	sharesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

func TestConcurrentObserve_NotificationRekeysPerProvider(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	ctx := t.Context()

	env.seedRun(t, "run-alpha", validatorcore.StateForwardShareSent)
	seedRunOn(t, env, "run-beta", "beta.example", validatorcore.StateForwardShareSent)
	env.seedReservation(t, "run-alpha", "provider-alpha")
	seedReservationOn(t, env, "run-beta", "provider-beta", "beta.example")

	var wg sync.WaitGroup

	start := make(chan struct{})
	errs := make(chan error, 3)

	wg.Add(3)

	go func() {
		defer wg.Done()

		<-start

		errs <- env.svc.ObserveNotification(ctx, &sharesoutgoing.OutgoingShare{ProviderID: "provider-alpha"})
	}()
	go func() {
		defer wg.Done()

		<-start

		errs <- env.svc.ObserveNotification(ctx, &sharesoutgoing.OutgoingShare{ProviderID: "provider-beta"})
	}()
	go func() {
		defer wg.Done()

		<-start

		errs <- env.svc.ObserveNotification(ctx, &sharesoutgoing.OutgoingShare{ProviderID: "provider-missing"})
	}()

	close(start)
	wg.Wait()
	close(errs)

	for err := range errs {
		if err != nil {
			t.Fatalf("ObserveNotification: %v", err)
		}
	}

	alpha := env.evidenceRows(
		t,
		"run-alpha",
		validatorcore.SpecificationAreaNotification,
		"notify",
		"notification_received",
	)

	beta := env.evidenceRows(
		t,
		"run-beta",
		validatorcore.SpecificationAreaNotification,
		"notify",
		"notification_received",
	)
	if len(alpha) != 1 || len(beta) != 1 {
		t.Fatalf("notification evidence alpha=%d beta=%d, want 1 each", len(alpha), len(beta))
	}

	if env.countReportExchanges(t, "run-alpha") != 1 || env.countReportExchanges(t, "run-beta") != 1 {
		t.Fatal("notification exchanges did not stay per-run")
	}

	if env.requireRun(t, "run-alpha").State != validatorcore.StateForwardShareSent {
		t.Fatal("alpha state changed on a notification hit path")
	}

	if env.requireRun(t, "run-beta").State != validatorcore.StateForwardShareSent {
		t.Fatal("beta state changed on a notification hit path")
	}
}

func TestConcurrentObserve_CapabilityRekeysAndMissSkips(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	ctx := t.Context()

	env.seedRun(t, "run-alpha", validatorcore.StateForwardShareSent)
	seedRunOn(t, env, "run-beta", "beta.example", validatorcore.StateForwardShareSent)
	env.seedReservation(t, "run-alpha", "provider-alpha")
	seedReservationOn(t, env, "run-beta", "provider-beta", "beta.example")

	var wg sync.WaitGroup

	start := make(chan struct{})
	errs := make(chan error, 4)

	wg.Add(4)

	go func() {
		defer wg.Done()

		<-start

		errs <- env.svc.ObserveTokenExchange(ctx, exerciseShare("provider-alpha"))
	}()
	go func() {
		defer wg.Done()

		<-start

		errs <- env.svc.ObserveWebDAVGet(ctx, exerciseShare("provider-beta"))
	}()
	go func() {
		defer wg.Done()

		<-start

		errs <- env.svc.ObserveTokenExchange(ctx, exerciseShare("provider-missing"))
	}()
	go func() {
		defer wg.Done()

		<-start

		errs <- env.svc.ObserveWebDAVGet(ctx, exerciseShare("provider-foreign"))
	}()

	close(start)
	wg.Wait()
	close(errs)

	for err := range errs {
		if err != nil {
			t.Fatalf("capability observe: %v", err)
		}
	}

	alpha := env.requireRun(t, "run-alpha")
	beta := env.requireRun(t, "run-beta")

	if alpha.State != validatorcore.StateReverseAwaitingShare {
		t.Fatalf("alpha state = %q, want %q", alpha.State, validatorcore.StateReverseAwaitingShare)
	}

	if beta.State != validatorcore.StateReverseAwaitingShare {
		t.Fatalf("beta state = %q, want %q", beta.State, validatorcore.StateReverseAwaitingShare)
	}

	if env.countEvidence(t, "run-alpha") != 2 {
		t.Fatalf("alpha evidence = %d, want 2", env.countEvidence(t, "run-alpha"))
	}

	if env.countEvidence(t, "run-beta") != 2 {
		t.Fatalf("beta evidence = %d, want 2", env.countEvidence(t, "run-beta"))
	}

	gotAlpha, err := env.store.FindActiveByProviderID(ctx, "provider-alpha")
	if err != nil {
		t.Fatalf("FindActiveByProviderID alpha: %v", err)
	}

	gotBeta, err := env.store.FindActiveByProviderID(ctx, "provider-beta")
	if err != nil {
		t.Fatalf("FindActiveByProviderID beta: %v", err)
	}

	if gotAlpha != "run-alpha" || gotBeta != "run-beta" {
		t.Fatalf("provider re-key = %q, %q", gotAlpha, gotBeta)
	}
}

func seedRunOn(t *testing.T, env *testEnv, runID, host, state string) {
	t.Helper()

	now := time.Now().Unix()
	bobID := uuid.NewString()

	if err := env.store.DB().WithContext(t.Context()).Create(&validatorcore.TestRun{
		TestRunID:    runID,
		IsActive:     true,
		State:        state,
		TargetOrigin: "https://" + host,
		TargetHost:   host,
		BobUserID:    &bobID,
		OptInStats:   true,
		CreatedAt:    now,
		UpdatedAt:    now,
	}).Error; err != nil {
		t.Fatalf("seed run %s: %v", runID, err)
	}
}

func seedReservationOn(t *testing.T, env *testEnv, runID, providerID, host string) {
	t.Helper()

	table := validatorcore.DispatchReservation{}.TableName()

	if err := env.store.DB().WithContext(t.Context()).Table(table).Create(map[string]any{
		"test_run_id":     runID,
		"provider_id":     providerID,
		"webdav_id":       uuid.NewString(),
		"shared_secret":   uuid.NewString(),
		"receiver_host":   host,
		"share_with":      "user@" + host,
		"probe_file_path": "/probe.txt",
		"status":          validatorcore.DispatchStatusCASCommitted,
		"created_at":      time.Now().Unix(),
	}).Error; err != nil {
		t.Fatalf("seed reservation %s: %v", runID, err)
	}
}
