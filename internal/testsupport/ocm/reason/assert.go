// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 OpenCloudMesh Authors

package reason

import (
	"errors"
	"testing"

	ocmreason "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/reason"
)

// AssertClassifiedReason fatals when err is nil, not a *ocmreason.ClassifiedError, or
// has a ReasonCode other than wantReason.
func AssertClassifiedReason(t testing.TB, err error, wantReason string) {
	t.Helper()

	if err == nil {
		t.Fatalf("expected a classified error, got nil")
	}

	var ce *ocmreason.ClassifiedError
	if !errors.As(err, &ce) {
		t.Fatalf("error is not a ClassifiedError: %v", err)
	}

	if ce.ReasonCode != wantReason {
		t.Fatalf("classified reason mismatch: got %q, want %q", ce.ReasonCode, wantReason)
	}
}
