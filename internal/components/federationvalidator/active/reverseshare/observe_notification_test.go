// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package reverseshare_test

import (
	"testing"

	sharesoutgoing "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/shares/outgoing"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

func TestObserveNotification_RecordsNotificationEvidence(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	env.seedRun(t, "run-observe-notify", validatorcore.StateForwardShareSent)
	env.seedReservation(t, "run-observe-notify", "provider-notify")

	share := &sharesoutgoing.OutgoingShare{ProviderID: "provider-notify"}
	if err := env.svc.ObserveNotification(t.Context(), share); err != nil {
		t.Fatalf("ObserveNotification: %v", err)
	}

	if err := env.svc.ObserveNotification(t.Context(), share); err != nil {
		t.Fatalf("retry ObserveNotification: %v", err)
	}

	rows := env.evidenceRows(
		t,
		"run-observe-notify",
		validatorcore.SpecificationAreaNotification,
		"notify",
		"notification_received",
	)
	if len(rows) != 1 {
		t.Fatalf("notification evidence = %d, want 1", len(rows))
	}

	if rows[0].Severity != validatorcore.GradePass || !rows[0].AffectsGrade {
		t.Fatalf("notification evidence = %+v, want grade-pass affecting", rows[0])
	}

	if got := env.countReportExchanges(t, "run-observe-notify"); got != 1 {
		t.Fatalf("notification exchanges = %d, want 1", got)
	}
}

func TestObserveNotification_ProviderMismatchNoOps(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	env.seedRun(t, "run-observe-notify-miss", validatorcore.StateForwardShareSent)
	env.seedReservation(t, "run-observe-notify-miss", "provider-owned")

	share := &sharesoutgoing.OutgoingShare{ProviderID: "provider-foreign"}
	if err := env.svc.ObserveNotification(t.Context(), share); err != nil {
		t.Fatalf("ObserveNotification: %v", err)
	}

	rows := env.evidenceRows(
		t,
		"run-observe-notify-miss",
		validatorcore.SpecificationAreaNotification,
		"notify",
		"notification_received",
	)
	if len(rows) != 0 {
		t.Fatalf("notification evidence = %d, want 0", len(rows))
	}
}

func TestObserveNotification_NilShareNoOps(t *testing.T) {
	t.Parallel()

	env := newTestEnv(t)
	env.seedRun(t, "run-observe-notify-nil", validatorcore.StateForwardShareSent)

	if err := env.svc.ObserveNotification(t.Context(), nil); err != nil {
		t.Fatalf("ObserveNotification: %v", err)
	}
}
