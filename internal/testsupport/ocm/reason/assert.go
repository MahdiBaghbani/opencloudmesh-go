// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package reason

import (
	"errors"
	"testing"

	ocmreason "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/reason"
)

// AssertClassifiedReason fatals when err is nil, not a *ocmreason.ClassifiedError, or
// has a ReasonCode other than wantReason.
func AssertClassifiedReason(tb testing.TB, err error, wantReason string) {
	tb.Helper()

	if err == nil {
		tb.Fatalf("expected a classified error, got nil")
	}

	var ce *ocmreason.ClassifiedError
	if !errors.As(err, &ce) {
		tb.Fatalf("error is not a ClassifiedError: %v", err)
	}

	if ce.ReasonCode != wantReason {
		tb.Fatalf("classified reason mismatch: got %q, want %q", ce.ReasonCode, wantReason)
	}
}
