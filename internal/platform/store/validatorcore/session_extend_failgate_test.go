// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

import (
	"errors"
	"testing"
)

func TestFailGate_WhitespaceSeverityAgreesOnStopAndExtend(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		id       string
		severity string
		raw      bool
	}{
		{
			name:     "canonical fail still blocks",
			id:       "canonical",
			severity: GradeFail,
		},
		{
			name:     "trailing tab via persist",
			id:       "tab-persist",
			severity: GradeFail + "\t",
		},
		{
			name:     "trailing newline via persist",
			id:       "nl-persist",
			severity: GradeFail + "\n",
		},
		{
			name:     "raw trailing tab still blocks",
			id:       "tab-raw",
			severity: GradeFail + "\t",
			raw:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			core := openTestCore(t)
			ctx := t.Context()
			stopID := "run-ws-stop-" + tt.id
			extendID := "run-ws-extend-" + tt.id

			seedPassiveComplete(t, core, stopID, "https://peer.example", false)
			seedPassiveComplete(t, core, extendID, "https://peer.example", false)
			seedFailGatedSeverity(t, core, stopID, tt.severity, tt.raw)
			seedFailGatedSeverity(t, core, extendID, tt.severity, tt.raw)

			if !tt.raw {
				got := mustLoadEvidence(t, core, stopID)
				if got.Severity != GradeFail {
					t.Fatalf("persisted severity = %q, want canonical %q", got.Severity, GradeFail)
				}
			}

			if err := core.StopPassive(ctx, stopID); err != nil {
				t.Fatalf("StopPassive: %v", err)
			}

			stopped, err := core.GetTestRun(ctx, stopID)
			if err != nil {
				t.Fatalf("GetTestRun stop: %v", err)
			}

			if stopped.State != StateTerminalFail {
				t.Fatalf("StopPassive state = %q, want %q", stopped.State, StateTerminalFail)
			}

			if stopped.OverallGrade == nil || *stopped.OverallGrade != GradeFail {
				t.Fatalf("StopPassive overall_grade = %v, want %q", stopped.OverallGrade, GradeFail)
			}

			extendErr := core.ExtendToActive(ctx, extendID)
			if !errors.Is(extendErr, ErrSessionNotReady) {
				t.Fatalf("ExtendToActive error = %v, want ErrSessionNotReady", extendErr)
			}

			extended, getErr := core.GetTestRun(ctx, extendID)
			if getErr != nil {
				t.Fatalf("GetTestRun extend: %v", getErr)
			}

			if extended.IsActive {
				t.Fatal("failed-probe run must not take the active lock")
			}

			if extended.State != StatePassiveComplete {
				t.Fatalf("state = %q, want %q", extended.State, StatePassiveComplete)
			}
		})
	}
}

func seedFailGatedSeverity(t *testing.T, core *Core, runID, severity string, raw bool) {
	t.Helper()

	if raw {
		seedEvidenceRow(
			t,
			core,
			runID,
			evidenceLegPassive,
			SpecificationAreaDiscovery,
			"probe",
			"probed",
			severity,
			true,
		)

		return
	}

	seedGradedEvidence(t, core, runID, SpecificationAreaDiscovery, severity)
}
