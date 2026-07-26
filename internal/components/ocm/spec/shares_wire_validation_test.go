package spec

import (
	"strings"
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

	var gapErr *ValidationError

	for i := range errs {
		if errs[i].Name == "protocol.webapp.requirements" && strings.Contains(errs[i].Message, "GAP") {
			gapErr = &errs[i]
			break
		}
	}

	if gapErr == nil {
		t.Fatalf("expected a GAP-bearing requirements error, got %v", errs)
	}

	if !strings.Contains(gapErr.Message, "must-use-mfa") {
		t.Errorf("GAP error should name must-use-mfa, got %q", gapErr.Message)
	}

	if !strings.Contains(gapErr.Message, "enforce-mfa") {
		t.Errorf("GAP error should explain enforce-mfa is not implemented, got %q", gapErr.Message)
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
