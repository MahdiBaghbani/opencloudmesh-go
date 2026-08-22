// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package incoming_test

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/notifications/incoming"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares"
	sharesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/repos"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
	tshttp "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/http"
)

type notificationObserverEnv struct {
	repos *repos.Repos
	store *validatorcore.Core
	runID string
}

func newNotificationObserverEnv(t *testing.T, runID, providerID string) *notificationObserverEnv {
	t.Helper()

	ctx := t.Context()

	opened, err := repos.New(ctx, config.PersistenceConfig{
		Backend: config.BackendSQLite,
		DataDir: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("repos.New: %v", err)
	}

	t.Cleanup(func() { tshttp.MustClose(t, opened) })

	db, err := opened.SharedDB()
	if err != nil {
		t.Fatalf("SharedDB: %v", err)
	}

	store, err := validatorcore.Attach(db, validatorcore.DefaultSessionConfig())
	if err != nil {
		t.Fatalf("validatorcore.Attach: %v", err)
	}

	now := time.Now().Unix()
	if err := store.DB().WithContext(ctx).Create(&validatorcore.TestRun{
		TestRunID:    runID,
		IsActive:     true,
		State:        validatorcore.StateActiveRunning,
		TargetOrigin: "https://receiver.example.com",
		TargetHost:   "receiver.example.com",
		DiscoveryURL: "https://receiver.example.com/.well-known/ocm",
		CreatedAt:    now,
		UpdatedAt:    now,
	}).Error; err != nil {
		t.Fatalf("seed run: %v", err)
	}

	share := &sharesoutgoing.OutgoingShare{
		ProviderID:   providerID,
		ReceiverHost: "receiver.example.com",
		Status:       shares.OutgoingShareStatusSent,
		CreatedAt:    time.Now(),
	}
	if err := opened.OutgoingShares.Create(ctx, share); err != nil {
		t.Fatalf("create outgoing share: %v", err)
	}

	return &notificationObserverEnv{repos: opened, store: store, runID: runID}
}

func (e *notificationObserverEnv) handler() *incoming.Handler {
	return incoming.NewHandler(e.repos.OutgoingShares, e.repos.IncomingShares, "https", nil)
}

func (e *notificationObserverEnv) notificationEvidence(t *testing.T) []validatorcore.EvidenceRow {
	t.Helper()

	var rows []validatorcore.EvidenceRow
	if err := e.store.DB().WithContext(t.Context()).
		Where("test_run_id = ? AND area = ?", e.runID, validatorcore.SpecificationAreaNotification).
		Find(&rows).Error; err != nil {
		t.Fatalf("list notification evidence: %v", err)
	}

	return rows
}

func (e *notificationObserverEnv) notificationExchanges(t *testing.T) []validatorcore.ReportExchange {
	t.Helper()

	var rows []validatorcore.ReportExchange
	if err := e.store.DB().WithContext(t.Context()).
		Where("test_run_id = ? AND endpoint_id = ?", e.runID, validatorcore.EndpointNotifications).
		Find(&rows).Error; err != nil {
		t.Fatalf("list notification exchanges: %v", err)
	}

	return rows
}

func TestHandleNotification_ObserverSuccessPersistsNotificationEvidence(t *testing.T) {
	t.Parallel()

	const (
		runID      = "run-notify-obs-ok"
		providerID = "provider-obs-ok"
	)

	env := newNotificationObserverEnv(t, runID, providerID)
	handler := env.handler()

	var observed *sharesoutgoing.OutgoingShare

	handler.SetObserver(func(ctx context.Context, share *sharesoutgoing.OutgoingShare) error {
		observed = share

		return env.store.PersistActiveExchangeAndFact(
			ctx,
			validatorcore.IncomingNotificationExchange(runID),
			validatorcore.NotificationReceivedFact(runID, nil),
		)
	})

	w := postNotification(
		t,
		handler,
		`{"notificationType":"SHARE_ACCEPTED","providerId":"`+providerID+`"}`,
		"receiver.example.com",
	)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	if observed == nil || observed.ProviderID != providerID {
		t.Fatalf("observer share = %v, want provider %q", observed, providerID)
	}

	exchanges := env.notificationExchanges(t)
	if len(exchanges) != 1 {
		t.Fatalf("notification exchanges = %d, want 1", len(exchanges))
	}

	if exchanges[0].EndpointID != validatorcore.EndpointNotifications {
		t.Fatalf("endpoint = %q, want %q", exchanges[0].EndpointID, validatorcore.EndpointNotifications)
	}

	rows := env.notificationEvidence(t)
	if len(rows) != 1 {
		t.Fatalf("notification evidence = %d, want 1", len(rows))
	}

	if rows[0].Area != validatorcore.SpecificationAreaNotification {
		t.Fatalf("area = %q, want %q", rows[0].Area, validatorcore.SpecificationAreaNotification)
	}

	if rows[0].Step != "notify" {
		t.Fatalf("step = %q, want notify", rows[0].Step)
	}

	if rows[0].ReasonCode != "notification_received" {
		t.Fatalf("reason_code = %q, want notification_received", rows[0].ReasonCode)
	}

	if rows[0].Leg == nil || *rows[0].Leg != validatorcore.EvidenceLegForward {
		t.Fatalf("leg = %v, want %q", rows[0].Leg, validatorcore.EvidenceLegForward)
	}
}

func TestHandleNotification_ObserverErrorReturnsInternalError(t *testing.T) {
	t.Parallel()

	const (
		runID      = "run-notify-obs-err"
		providerID = "provider-obs-err"
	)

	env := newNotificationObserverEnv(t, runID, providerID)
	handler := env.handler()

	called := false

	handler.SetObserver(func(context.Context, *sharesoutgoing.OutgoingShare) error {
		called = true

		return errors.New("injected observer failure")
	})

	w := postNotification(
		t,
		handler,
		`{"notificationType":"SHARE_ACCEPTED","providerId":"`+providerID+`"}`,
		"receiver.example.com",
	)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d: %s", w.Code, w.Body.String())
	}

	if msg := decodeOCMMessage(t, w); msg != "INTERNAL_ERROR" {
		t.Fatalf("message = %q, want INTERNAL_ERROR", msg)
	}

	if !called {
		t.Fatal("observer was not invoked")
	}

	if got := len(env.notificationEvidence(t)); got != 0 {
		t.Fatalf("notification evidence = %d, want 0 after observer failure", got)
	}

	if got := len(env.notificationExchanges(t)); got != 0 {
		t.Fatalf("notification exchanges = %d, want 0 after observer failure", got)
	}
}
