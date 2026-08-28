// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

import (
	"errors"
	"slices"
	"testing"
)

func TestLegalTerminalReasons(t *testing.T) {
	t.Parallel()

	wantFail := []string{
		ReasonProbeStartFailed,
		ReasonProbeCompleteFailed,
		ReasonPassiveProbeFailed,
		ReasonCreatedTTLExpired,
		ReasonPassiveRunningTTLExpired,
		ReasonPassiveCompleteTTLExpired,
		ReasonActiveHardFail,
		ReasonActiveHardFailIdentity,
		ReasonActiveHardFailDispatch,
		ReasonActiveHardFailCorrelation,
		ReasonOperatorAborted,
		ReasonWrongAccepter,
		ReasonActiveUnavailable,
	}
	wantInterrupted := []string{
		ReasonReverseShareTimeout,
		ReasonReverseInviteTimeout,
		ReasonStallInactivityExpired,
		ReasonStartupUnrecoverableActive,
		ReasonForwardShareCommitStall,
	}
	wantPass := []string{
		ReasonStopped,
		ReasonReverseShareObserved,
		ReasonLateReverseShare,
	}

	gotFail := legalTerminalReasons(StateTerminalFail)
	gotInterrupted := legalTerminalReasons(StateInterrupted)
	gotPass := legalTerminalReasons(StateTerminalPass)

	assertExactReasonSet(t, "terminal_fail", gotFail, wantFail)
	assertExactReasonSet(t, "interrupted", gotInterrupted, wantInterrupted)
	assertExactReasonSet(t, "terminal_pass", gotPass, wantPass)

	union := slices.Concat(gotFail, gotInterrupted, gotPass)
	if len(union) != 21 {
		t.Fatalf("union size = %d, want 21", len(union))
	}

	owner := map[string]string{}

	for state, reasons := range map[string][]string{
		StateTerminalFail: gotFail,
		StateInterrupted:  gotInterrupted,
		StateTerminalPass: gotPass,
	} {
		for _, reason := range reasons {
			if other, ok := owner[reason]; ok {
				t.Fatalf("reason %q is legal for both %q and %q", reason, other, state)
			}

			owner[reason] = state
		}
	}

	if len(owner) != 21 {
		t.Fatalf("unique tokens = %d, want 21", len(owner))
	}

	gotCreated := legalTerminalReasons(StateCreated)
	if gotCreated != nil {
		t.Fatalf("legalTerminalReasons(StateCreated) = %#v, want nil", gotCreated)
	}

	if legalTerminalReasons("not-a-state") != nil {
		t.Fatal("legalTerminalReasons for an unknown state must be nil")
	}

	gotFail[0] = "mutated"

	if legalTerminalReasons(StateTerminalFail)[0] == "mutated" {
		t.Fatal("legalTerminalReasons must clone the destination group")
	}
}

func TestValidateTerminalReason(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		state   string
		reason  string
		wantErr error
		bare    bool
	}{
		{
			name:    "non-terminal destination",
			state:   StateCreated,
			reason:  ReasonStopped,
			wantErr: ErrTerminalStateInvalid,
			bare:    true,
		},
		{
			name:    "empty reason for terminal fail",
			state:   StateTerminalFail,
			reason:  "",
			wantErr: ErrTerminalReasonInvalid,
		},
		{
			name:    "unknown token",
			state:   StateTerminalFail,
			reason:  "not_a_reason",
			wantErr: ErrTerminalReasonInvalid,
		},
		{
			name:    "interrupted reason rejected for terminal fail",
			state:   StateTerminalFail,
			reason:  ReasonReverseShareTimeout,
			wantErr: ErrTerminalReasonInvalid,
		},
		{
			name:   "active hard fail is legal for terminal fail",
			state:  StateTerminalFail,
			reason: ReasonActiveHardFail,
		},
		{
			name:   "active unavailable is legal for terminal fail",
			state:  StateTerminalFail,
			reason: ReasonActiveUnavailable,
		},
		{
			name:    "whitespace is not trimmed",
			state:   "  ",
			reason:  "\t",
			wantErr: ErrTerminalStateInvalid,
			bare:    true,
		},
		{
			name:    "whitespace reason is not trimmed",
			state:   StateTerminalFail,
			reason:  "\t",
			wantErr: ErrTerminalReasonInvalid,
		},
		{
			name:    "padded legal token is not trimmed",
			state:   StateTerminalFail,
			reason:  " " + ReasonActiveHardFail + " ",
			wantErr: ErrTerminalReasonInvalid,
		},
		{
			name:   "late reverse share is legal for terminal pass",
			state:  StateTerminalPass,
			reason: ReasonLateReverseShare,
		},
		{
			name:   "reverse share timeout is legal for interrupted",
			state:  StateInterrupted,
			reason: ReasonReverseShareTimeout,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := validateTerminalReason(tt.state, tt.reason)
			if tt.wantErr == nil {
				if err != nil {
					t.Fatalf("validateTerminalReason(%q, %q) = %v, want nil", tt.state, tt.reason, err)
				}

				return
			}

			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("validateTerminalReason(%q, %q) = %v, want %v", tt.state, tt.reason, err, tt.wantErr)
			}

			unwrapped := errors.Unwrap(err)
			if tt.bare && unwrapped != nil {
				t.Fatalf("error = %v, want bare %v", err, tt.wantErr)
			}

			if !tt.bare && unwrapped == nil {
				t.Fatalf("error = %v, want wrapped %v", err, tt.wantErr)
			}
		})
	}
}

func assertExactReasonSet(t *testing.T, dest string, got, want []string) {
	t.Helper()

	if len(got) != len(want) {
		t.Fatalf("%s reasons: got %d %v, want %d %v", dest, len(got), got, len(want), want)
	}

	for _, reason := range want {
		if !slices.Contains(got, reason) {
			t.Fatalf("%s reasons missing %q: %v", dest, reason, got)
		}
	}

	for _, reason := range got {
		if !slices.Contains(want, reason) {
			t.Fatalf("%s reasons have extra %q: %v", dest, reason, got)
		}
	}
}
