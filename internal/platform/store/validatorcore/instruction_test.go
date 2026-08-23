// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package validatorcore

import (
	"testing"
)

func TestNextInstructionLabel_KnownKeys(t *testing.T) {
	t.Parallel()

	for _, key := range NextInstructionKeys() {
		t.Run(key, func(t *testing.T) {
			t.Parallel()

			if got := NextInstructionLabel(key); got == "" {
				t.Fatalf("NextInstructionLabel(%q) is empty", key)
			}
		})
	}
}

func TestNextInstructionLabel_UnknownEmpty(t *testing.T) {
	t.Parallel()

	if got := NextInstructionLabel("not-an-instruction"); got != "" {
		t.Fatalf("NextInstructionLabel unknown = %q, want empty", got)
	}
}
