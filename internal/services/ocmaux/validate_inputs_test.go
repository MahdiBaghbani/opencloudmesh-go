// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package ocmaux

import (
	"strings"
	"testing"
)

func TestValidateInputs_ReportsMissingRatelimitKeyFunc(t *testing.T) {
	err := validateInputs(Inputs{})
	if err == nil {
		t.Fatal("expected validation error")
	}

	if !strings.Contains(err.Error(), "Ratelimit.KeyFunc is required") {
		t.Fatalf("error = %q, want Ratelimit.KeyFunc required", err.Error())
	}
}

func TestValidateInputs_AcceptsRatelimitKeyFunc(t *testing.T) {
	if err := validateInputs(testOCMAuxInputs()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
