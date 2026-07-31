// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package spec

import (
	"testing"
)

// runRequirementsAdmissionBoolSeam drives the shared bool-seam admission rows
// for one requirements validator (webdav or webapp). Admission alone does not
// enforce must-exchange-token; wire does.
func runRequirementsAdmissionBoolSeam(t *testing.T, field string, validate func(bool, []string) []ValidationError) {
	t.Helper()

	t.Run("true+omit requires requirements", func(t *testing.T) {
		errs := validate(true, nil)
		if !hasValidationError(errs, field) {
			t.Fatalf("expected REQUIRED for true+omit, got %v", errs)
		}

		for _, e := range errs {
			if e.Name == field && e.Message != "REQUIRED" {
				t.Fatalf("requirements error = %q, want REQUIRED", e.Message)
			}
		}
	})
	t.Run("false+omit allows empty", func(t *testing.T) {
		if errs := validate(false, nil); len(errs) != 0 {
			t.Fatalf("expected no admission error for false+omit, got %v", errs)
		}
	})
	t.Run("false+has reqs allows", func(t *testing.T) {
		reqs := []string{RequirementMustExchangeToken}
		if errs := validate(false, reqs); len(errs) != 0 {
			t.Fatalf("expected no admission error for false+has, got %v", errs)
		}
	})
	t.Run("true+has reqs allows", func(t *testing.T) {
		reqs := []string{RequirementMustExchangeToken}
		if errs := validate(true, reqs); len(errs) != 0 {
			t.Fatalf("expected no admission error for true+has, got %v", errs)
		}
	})
}

func TestWebDAVRequirementsAdmission_BoolSeam(t *testing.T) {
	runRequirementsAdmissionBoolSeam(t, "protocol.webdav.requirements", ValidateWebDAVRequirementsAdmission)
}

func TestWebappRequirementsAdmission_BoolSeam(t *testing.T) {
	runRequirementsAdmissionBoolSeam(t, "protocol.webapp.requirements", ValidateWebappRequirementsAdmission)
}
