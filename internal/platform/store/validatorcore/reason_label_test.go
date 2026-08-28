// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

import "testing"

func TestTerminalReasonLabel(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		state  string
		reason string
		want   string
	}{
		{
			name:   "probe could not start",
			state:  StateTerminalFail,
			reason: ReasonProbeStartFailed,
			want:   "Probe could not start",
		},
		{
			name:   "probe could not complete",
			state:  StateTerminalFail,
			reason: ReasonProbeCompleteFailed,
			want:   "Probe could not complete",
		},
		{
			name:   "passive probe failed",
			state:  StateTerminalFail,
			reason: ReasonPassiveProbeFailed,
			want:   "Passive probe failed",
		},
		{
			name:   "session expired before probe started",
			state:  StateTerminalFail,
			reason: ReasonCreatedTTLExpired,
			want:   "Session expired before probe started",
		},
		{
			name:   "passive session expired",
			state:  StateTerminalFail,
			reason: ReasonPassiveRunningTTLExpired,
			want:   "Passive session expired",
		},
		{
			name:   "completed session expired",
			state:  StateTerminalFail,
			reason: ReasonPassiveCompleteTTLExpired,
			want:   "Completed session expired",
		},
		{
			name:   "active run failed",
			state:  StateTerminalFail,
			reason: ReasonActiveHardFail,
			want:   "Active run failed",
		},
		{
			name:   "active run failed identity binding",
			state:  StateTerminalFail,
			reason: ReasonActiveHardFailIdentity,
			want:   "Active run failed: identity binding",
		},
		{
			name:   "active run failed forward dispatch",
			state:  StateTerminalFail,
			reason: ReasonActiveHardFailDispatch,
			want:   "Active run failed: forward dispatch",
		},
		{
			name:   "active run failed correlation",
			state:  StateTerminalFail,
			reason: ReasonActiveHardFailCorrelation,
			want:   "Active run failed: correlation",
		},
		{
			name:   "operator aborted the run",
			state:  StateTerminalFail,
			reason: ReasonOperatorAborted,
			want:   "Operator aborted the run",
		},
		{
			name:   "accepted by the wrong peer",
			state:  StateTerminalFail,
			reason: ReasonWrongAccepter,
			want:   "Accepted by the wrong peer",
		},
		{
			name:   "active extension unavailable",
			state:  StateTerminalFail,
			reason: ReasonActiveUnavailable,
			want:   "Active extension unavailable",
		},
		{
			name:   "reverse share timed out",
			state:  StateInterrupted,
			reason: ReasonReverseShareTimeout,
			want:   "Reverse share timed out",
		},
		{
			name:   "reverse invite timed out",
			state:  StateInterrupted,
			reason: ReasonReverseInviteTimeout,
			want:   "Reverse invite timed out",
		},
		{
			name:   "run stalled",
			state:  StateInterrupted,
			reason: ReasonStallInactivityExpired,
			want:   "Run stalled",
		},
		{
			name:   "interrupted on startup recovery",
			state:  StateInterrupted,
			reason: ReasonStartupUnrecoverableActive,
			want:   "Interrupted on startup recovery",
		},
		{
			name:   "forward share commit stalled",
			state:  StateInterrupted,
			reason: ReasonForwardShareCommitStall,
			want:   "Forward share commit stalled",
		},
		{
			name:   "run stopped",
			state:  StateTerminalPass,
			reason: ReasonStopped,
			want:   "Run stopped",
		},
		{
			name:   "reverse share observed",
			state:  StateTerminalPass,
			reason: ReasonReverseShareObserved,
			want:   "Reverse share observed",
		},
		{
			name:   "late reverse share observed",
			state:  StateTerminalPass,
			reason: ReasonLateReverseShare,
			want:   "Late reverse share observed",
		},
		{
			name:   "empty state and reason",
			state:  "",
			reason: "",
		},
		{
			name:   "empty reason on terminal fail",
			state:  StateTerminalFail,
			reason: "",
		},
		{
			name:   "whitespace reason on terminal fail",
			state:  StateTerminalFail,
			reason: "   ",
		},
		{
			name:   "unknown token on terminal fail",
			state:  StateTerminalFail,
			reason: "not_a_token",
		},
		{
			name:   "unpaired reverse share timeout on terminal fail",
			state:  StateTerminalFail,
			reason: ReasonReverseShareTimeout,
		},
		{
			name:   "unpaired active hard fail on interrupted",
			state:  StateInterrupted,
			reason: ReasonActiveHardFail,
		},
		{
			name:   "unpaired active hard fail on terminal pass",
			state:  StateTerminalPass,
			reason: ReasonActiveHardFail,
		},
		{
			name:   "unpaired active hard fail on created",
			state:  StateCreated,
			reason: ReasonActiveHardFail,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := TerminalReasonLabel(tt.state, tt.reason)
			if got != tt.want {
				t.Fatalf("TerminalReasonLabel(%q, %q) = %q, want %q", tt.state, tt.reason, got, tt.want)
			}

			if got != "" && got == tt.reason {
				t.Fatalf("TerminalReasonLabel echoed raw token %q", tt.reason)
			}
		})
	}
}
