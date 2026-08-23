// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

import (
	"slices"
	"testing"
)

// TestSessionStateReachableSet_ActiveNonTerminal pins the exact set of states a
// session row matching is_active=1 AND NOT isTerminalState(state) can hold.
func TestSessionStateReachableSet_ActiveNonTerminal(t *testing.T) {
	t.Parallel()

	states := []string{
		StateActiveRunning,
		StateInviteMinted,
		StateInviteAccepted,
		StateReverseAwaitingInvite,
		StateReverseInviteAccepted,
		StateForwardShareSent,
		StateCapabilityExercise,
		StateReverseAwaitingShare,
	}

	for _, state := range states {
		if isTerminalState(state) {
			t.Errorf("active non-terminal state %q must not be terminal", state)
		}

		if !slices.Contains(testRunStates, state) {
			t.Errorf("active non-terminal state %q must be in the schema state set", state)
		}

		if NextInstructionForState(state) == "" {
			t.Errorf("active non-terminal state %q must publish a nextInstruction key", state)
		}
	}
}

// Passive states are reachable with is_active=0 and are non-terminal.
func TestSessionStateReachableSet_PassiveNonTerminal(t *testing.T) {
	t.Parallel()

	for _, state := range []string{StateCreated, StatePassiveRunning, StatePassiveComplete} {
		if isTerminalState(state) {
			t.Errorf("passive state %q must not be terminal", state)
		}

		if !slices.Contains(testRunStates, state) {
			t.Errorf("passive state %q must be in the schema state set", state)
		}

		if state == StatePassiveComplete {
			if NextInstructionForState(state) != "" {
				t.Errorf("passive state %q must not publish a nextInstruction key", state)
			}

			continue
		}

		if NextInstructionForState(state) == "" {
			t.Errorf("passive state %q must publish a nextInstruction key", state)
		}
	}
}

func TestSessionStateReachableSet_Terminal(t *testing.T) {
	t.Parallel()

	for _, state := range []string{StateTerminalPass, StateTerminalFail, StateInterrupted} {
		if !isTerminalState(state) {
			t.Errorf("state %q must be terminal", state)
		}

		if !slices.Contains(testRunStates, state) {
			t.Errorf("terminal state %q must be in the schema state set", state)
		}

		if NextInstructionForState(state) != "" {
			t.Errorf("terminal state %q must not publish a nextInstruction key", state)
		}
	}
}

func TestPrunableTerminalStates(t *testing.T) {
	t.Parallel()

	wantPrunable := []string{StateTerminalPass, StateTerminalFail}
	if got := prunableTerminalStateSet(); !slices.Equal(got, wantPrunable) {
		t.Errorf("prunableTerminalStateSet() = %v, want %v", got, wantPrunable)
	}

	for _, state := range testRunStates {
		writerTerminal := isTerminalState(state)
		prunable := isPrunableTerminalState(state)
		wantWriter := state == StateTerminalPass ||
			state == StateTerminalFail ||
			state == StateInterrupted
		wantPrunable := state == StateTerminalPass || state == StateTerminalFail

		if writerTerminal != wantWriter {
			t.Errorf("isTerminalState(%q) = %v, want %v", state, writerTerminal, wantWriter)
		}

		if prunable != wantPrunable {
			t.Errorf("isPrunableTerminalState(%q) = %v, want %v", state, prunable, wantPrunable)
		}
	}
}

// Dormant states stay off the reachable graph: outside the schema state set,
// non-terminal, and without a nextInstruction key.
func TestSessionStateReachableSet_DormantUnreachable(t *testing.T) {
	t.Parallel()

	states := []string{
		"awaiting_return_share",
		"passive_done",
		"reverse_share_accepted",
		"reverse_capability_exercise",
	}

	for _, state := range states {
		if slices.Contains(testRunStates, state) {
			t.Errorf("dormant state %q must stay outside the schema state set", state)
		}

		if isTerminalState(state) {
			t.Errorf("dormant state %q must not be terminal", state)
		}

		if isPrunableTerminalState(state) {
			t.Errorf("dormant state %q must not be prunable", state)
		}

		if NextInstructionForState(state) != "" {
			t.Errorf("dormant state %q must not publish a nextInstruction key", state)
		}
	}
}

// The 14-value enum is exactly 3 passive plus 8 active non-terminal plus 3
// terminal; dormant values never join the set.
func TestSessionStateReachableSet_EnumSize(t *testing.T) {
	t.Parallel()

	if len(testRunStates) != 14 {
		t.Errorf("testRunStates holds %d values, want 14", len(testRunStates))
	}
}

func TestNextInstructionForState(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		state string
		want  string
	}{
		{name: "created waits on probe", state: StateCreated, want: "wait_probe"},
		{name: "passive running waits on probe", state: StatePassiveRunning, want: "wait_probe"},
		{name: "passive complete publishes nothing", state: StatePassiveComplete, want: ""},
		{name: "active running waits on invite mint", state: StateActiveRunning, want: "wait_invite_mint"},
		{name: "invite minted asks for paste", state: StateInviteMinted, want: "paste_s1"},
		{name: "invite accepted waits on reverse start", state: StateInviteAccepted, want: "wait_reverse_start"},
		{name: "reverse awaiting invite asks for paste", state: StateReverseAwaitingInvite, want: "paste_s2"},
		{name: "reverse invite accepted waits on forward share", state: StateReverseInviteAccepted, want: "wait_forward_share"},
		{name: "forward share sent opens forward file", state: StateForwardShareSent, want: "open_forward_file"},
		{name: "capability exercise waits on open", state: StateCapabilityExercise, want: "wait_oq2_open"},
		{name: "reverse awaiting share waits on share or timeout", state: StateReverseAwaitingShare, want: "wait_reverse_share_or_timeout"},
		{name: "terminal pass publishes nothing", state: StateTerminalPass, want: ""},
		{name: "terminal fail publishes nothing", state: StateTerminalFail, want: ""},
		{name: "interrupted publishes nothing", state: StateInterrupted, want: ""},
		{name: "dormant awaiting return share publishes nothing", state: "awaiting_return_share", want: ""},
		{name: "dormant passive done publishes nothing", state: "passive_done", want: ""},
		{name: "dormant reverse share accepted publishes nothing", state: "reverse_share_accepted", want: ""},
		{name: "dormant reverse capability exercise publishes nothing", state: "reverse_capability_exercise", want: ""},
		{name: "unknown state publishes nothing", state: "bogus", want: ""},
		{name: "empty state publishes nothing", state: "", want: ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := NextInstructionForState(tc.state); got != tc.want {
				t.Errorf("NextInstructionForState(%q) = %q, want %q", tc.state, got, tc.want)
			}
		})
	}
}

func TestNextInstructionForRun_ReadyWaiterUsesActiveSlot(t *testing.T) {
	t.Parallel()

	readyAt := int64(10)
	row := &TestRun{
		OptInActive:    true,
		State:          StatePassiveRunning,
		PassiveReadyAt: &readyAt,
	}

	if got := NextInstructionForRun(row); got != "wait_active_slot" {
		t.Fatalf("NextInstructionForRun ready waiter = %q, want wait_active_slot", got)
	}

	if got := NextInstructionForRun(&TestRun{State: StatePassiveRunning}); got != "wait_probe" {
		t.Fatalf("NextInstructionForRun running = %q, want wait_probe", got)
	}
}
