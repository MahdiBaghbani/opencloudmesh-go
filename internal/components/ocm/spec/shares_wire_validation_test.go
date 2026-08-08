// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package spec

import (
	"testing"
)

func TestWebDAVProtocolWire_AcceptsEmptyRequirements(t *testing.T) {
	p := &WebDAVProtocol{
		URI:          "u",
		SharedSecret: "s",
		Permissions:  []string{"read"},
	}
	if errs := ValidateWebDAVProtocolWire(p); len(errs) != 0 {
		t.Fatalf("wire should accept empty requirements, got %v", errs)
	}
}

func TestWebDAVProtocolWire_RejectsUnknownRequirement(t *testing.T) {
	p := &WebDAVProtocol{
		URI:          "u",
		SharedSecret: "s",
		Permissions:  []string{"read"},
		Requirements: []string{"an-unsupported-requirement"},
	}

	errs := ValidateWebDAVProtocolWire(p)
	if !hasValidationError(errs, "protocol.webdav.requirements") {
		t.Fatalf("expected a requirements validation error, got %v", errs)
	}

	for _, e := range errs {
		if e.Name == "protocol.webdav.requirements" && e.Message != "UNSUPPORTED" {
			t.Fatalf("requirements error = %q, want UNSUPPORTED", e.Message)
		}
	}
}

func TestWebappProtocolWire_RejectsMustUseMFAWithGapNote(t *testing.T) {
	p := validWebapp()
	p.Requirements = []string{RequirementMustExchangeToken, RequirementMustUseMFA}
	errs := ValidateWebappProtocolWire(p)

	wantMsg := "must-use-mfa rejected at admit; MFA enforcement is not supported"

	var mfaErr *ValidationError

	for i := range errs {
		if errs[i].Name == "protocol.webapp.requirements" && errs[i].Message == wantMsg {
			mfaErr = &errs[i]

			break
		}
	}

	if mfaErr == nil {
		t.Fatalf("expected requirements error %q, got %v", wantMsg, errs)
	}
}

func TestWebappProtocolWire_RequiresMustExchangeToken(t *testing.T) {
	p := validWebapp()
	p.Requirements = nil

	errs := ValidateWebappProtocolWire(p)
	if !hasValidationError(errs, "protocol.webapp.requirements") {
		t.Fatalf("wire should require must-exchange-token (empty requirements), got %v", errs)
	}

	foundRequired := false

	for _, e := range errs {
		if e.Name == "protocol.webapp.requirements" && e.Message == "REQUIRED" {
			foundRequired = true
		}
	}

	if !foundRequired {
		t.Fatalf("expected REQUIRED for empty requirements on wire, got %v", errs)
	}

	// Wire validation rejects requirements that omit must-exchange-token.
	p.Requirements = []string{RequirementMustUseMFA}

	errs = ValidateWebappProtocolWire(p)
	if !hasValidationError(errs, "protocol.webapp.requirements") {
		t.Fatalf("wire should require must-exchange-token when absent, got %v", errs)
	}

	foundRequired = false

	for _, e := range errs {
		if e.Name == "protocol.webapp.requirements" && e.Message == "REQUIRED" {
			foundRequired = true
		}
	}

	if !foundRequired {
		t.Fatalf("expected REQUIRED for missing must-exchange-token on wire, got %v", errs)
	}
}
