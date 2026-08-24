// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

// Operator-facing labels for legal closed terminal reasons; unknown or unpaired tokens stay empty.

package validatorcore

import "slices"

// TerminalReasonLabel returns the operator-facing label for a legal closed reason, or empty for unknown or unpaired tokens.
func TerminalReasonLabel(state, reason string) string { //nolint:cyclop // exhaustive legal closed-reason label map
	if !slices.Contains(legalTerminalReasons(state), reason) {
		return ""
	}

	switch reason {
	case ReasonProbeStartFailed:
		return "Probe could not start"
	case ReasonProbeCompleteFailed:
		return "Probe could not complete"
	case ReasonPassiveProbeFailed:
		return "Passive probe failed"
	case ReasonCreatedTTLExpired:
		return "Session expired before probe started"
	case ReasonPassiveRunningTTLExpired:
		return "Passive session expired"
	case ReasonPassiveCompleteTTLExpired:
		return "Completed session expired"
	case ReasonActiveHardFail:
		return "Active run failed"
	case ReasonActiveHardFailIdentity:
		return "Active run failed: identity binding"
	case ReasonActiveHardFailDispatch:
		return "Active run failed: forward dispatch"
	case ReasonActiveHardFailCorrelation:
		return "Active run failed: correlation"
	case ReasonOperatorAborted:
		return "Operator aborted the run"
	case ReasonWrongAccepter:
		return "Accepted by the wrong peer"
	case ReasonActiveUnavailable:
		return "Active extension unavailable"
	case ReasonReverseShareTimeout:
		return "Reverse share timed out"
	case ReasonReverseInviteTimeout:
		return "Reverse invite timed out"
	case ReasonStallInactivityExpired:
		return "Run stalled"
	case ReasonStartupUnrecoverableActive:
		return "Interrupted on startup recovery"
	case ReasonForwardShareCommitStall:
		return "Forward share commit stalled"
	case ReasonStopped:
		return "Run stopped"
	case ReasonReverseShareObserved:
		return "Reverse share observed"
	case ReasonLateReverseShare:
		return "Late reverse share observed"
	default:
		return ""
	}
}
