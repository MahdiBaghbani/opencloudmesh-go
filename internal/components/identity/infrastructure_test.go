// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package identity

import (
	"errors"
	"fmt"
	"testing"
)

func TestIsInfrastructureError(t *testing.T) {
	t.Parallel()

	sentinelTests := []error{
		ErrUserNotFound,
		ErrInvalidPassword,
		ErrSessionNotFound,
		ErrSessionExpired,
		fmt.Errorf("wrapped: %w", ErrUserNotFound),
	}

	for _, err := range sentinelTests {
		if IsInfrastructureError(err) {
			t.Errorf("expected sentinel %v to not be infrastructure", err)
		}
	}

	infraErr := errors.New("db unavailable")
	if !IsInfrastructureError(infraErr) {
		t.Errorf("expected %v to be infrastructure", infraErr)
	}

	if IsInfrastructureError(nil) {
		t.Error("expected nil to not be infrastructure")
	}
}
