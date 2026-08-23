// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

// Next-instruction keys published by session polling. Labels are operator-facing
// and carry no session secrets.
const (
	InstructionWaitProbe                 = "wait_probe"
	InstructionStop                      = "stop"
	InstructionWaitInviteMint            = "wait_invite_mint"
	InstructionPasteS1                   = "paste_s1"
	InstructionWaitReverseStart          = "wait_reverse_start"
	InstructionPasteS2                   = "paste_s2"
	InstructionWaitForwardShare          = "wait_forward_share"
	InstructionOpenForwardFile           = "open_forward_file"
	InstructionWaitOpen                  = "wait_oq2_open"
	InstructionWaitReverseShareOrTimeout = "wait_reverse_share_or_timeout"
	InstructionWaitActiveSlot            = "wait_active_slot"
)

// NextInstructionKeys lists every nextInstruction key the poll can publish.
func NextInstructionKeys() []string {
	return []string{
		InstructionWaitProbe,
		InstructionStop,
		InstructionWaitInviteMint,
		InstructionPasteS1,
		InstructionWaitReverseStart,
		InstructionPasteS2,
		InstructionWaitForwardShare,
		InstructionOpenForwardFile,
		InstructionWaitOpen,
		InstructionWaitReverseShareOrTimeout,
		InstructionWaitActiveSlot,
	}
}

// NextInstructionLabel returns the operator-facing label for a nextInstruction
// key. Unknown keys return an empty string.
func NextInstructionLabel(key string) string {
	switch key {
	case InstructionWaitProbe:
		return "Wait for the discovery probe"
	case InstructionStop:
		return "Stop the session"
	case InstructionWaitInviteMint:
		return "Wait for the invite to be minted"
	case InstructionPasteS1:
		return "Paste the outgoing invite"
	case InstructionWaitReverseStart:
		return "Wait for reverse invite start"
	case InstructionPasteS2:
		return "Paste the reverse invite"
	case InstructionWaitForwardShare:
		return "Wait for the forward share"
	case InstructionOpenForwardFile:
		return "Open the forwarded file"
	case InstructionWaitOpen:
		return "Wait for the capability open"
	case InstructionWaitReverseShareOrTimeout:
		return "Wait for the reverse share or timeout"
	case InstructionWaitActiveSlot:
		return "Wait for the active slot"
	default:
		return ""
	}
}
