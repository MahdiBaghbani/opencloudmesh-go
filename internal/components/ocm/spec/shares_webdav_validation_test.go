package spec

import (
	"encoding/json"
	"testing"
)

func TestWebDAVRequiresURI(t *testing.T) {
	p := &WebDAVProtocol{SharedSecret: "s", Permissions: []string{"read"}, Requirements: []string{RequirementMustExchangeToken}}
	errs := ValidateWebDAVProtocol(p)
	if !hasValidationError(errs, "protocol.webdav.uri") {
		t.Fatalf("expected a uri validation error, got %v", errs)
	}
}

func TestWebDAVRequiresSharedSecret(t *testing.T) {
	p := &WebDAVProtocol{URI: "u", Permissions: []string{"read"}, Requirements: []string{RequirementMustExchangeToken}}
	errs := ValidateWebDAVProtocol(p)
	if !hasValidationError(errs, "protocol.webdav.sharedSecret") {
		t.Fatalf("expected a sharedSecret validation error, got %v", errs)
	}
}

func TestWebDAVRequiresPermissions(t *testing.T) {
	p := &WebDAVProtocol{URI: "u", SharedSecret: "s", Requirements: []string{RequirementMustExchangeToken}}
	errs := ValidateWebDAVProtocol(p)
	if !hasValidationError(errs, "protocol.webdav.permissions") {
		t.Fatalf("expected a permissions validation error, got %v", errs)
	}
}

func TestWebDAVAcceptsRemoteAccessTypes(t *testing.T) {
	const body = `{"uri":"u","sharedSecret":"s","permissions":["read"],"accessTypes":["remote"],"requirements":["must-exchange-token"]}`
	var p WebDAVProtocol
	if err := json.Unmarshal([]byte(body), &p); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(p.AccessTypes) != 1 || p.AccessTypes[0] != "remote" {
		t.Errorf("AccessTypes = %v, want [remote]", p.AccessTypes)
	}
	if errs := ValidateWebDAVProtocol(&p); len(errs) != 0 {
		t.Errorf("unexpected validation errors: %v", errs)
	}
}

func TestWebDAVRejectsUnsupportedAccessTypes(t *testing.T) {
	const body = `{"uri":"u","sharedSecret":"s","permissions":["read"],"accessTypes":["datatx"],"requirements":["must-exchange-token"]}`
	var p WebDAVProtocol
	if err := json.Unmarshal([]byte(body), &p); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	errs := ValidateWebDAVProtocol(&p)
	if !hasValidationError(errs, "protocol.webdav.accessTypes") {
		t.Fatalf("expected accessTypes validation error, got %v", errs)
	}
	for _, e := range errs {
		if e.Name == "protocol.webdav.accessTypes" && e.Message != "UNSUPPORTED" {
			t.Fatalf("accessTypes error = %q, want UNSUPPORTED", e.Message)
		}
	}
}

func TestWebDAVAcceptsMissingAccessTypesAsRemote(t *testing.T) {
	p := &WebDAVProtocol{
		URI:          "u",
		SharedSecret: "s",
		Permissions:  []string{"read"},
		Requirements: []string{RequirementMustExchangeToken},
	}
	if errs := ValidateWebDAVProtocol(p); len(errs) != 0 {
		t.Errorf("unexpected validation errors: %v", errs)
	}
}

func TestWebDAVRejectsUnsupportedPermissions(t *testing.T) {
	p := &WebDAVProtocol{
		URI:          "u",
		SharedSecret: "s",
		Permissions:  []string{"write"},
		Requirements: []string{RequirementMustExchangeToken},
	}
	errs := ValidateWebDAVProtocol(p)
	if !hasValidationError(errs, "protocol.webdav.permissions") {
		t.Fatalf("expected permissions validation error, got %v", errs)
	}
	for _, e := range errs {
		if e.Name == "protocol.webdav.permissions" && e.Message != "UNSUPPORTED" {
			t.Fatalf("permissions error = %q, want UNSUPPORTED", e.Message)
		}
	}
}

func TestWebDAVRejectsUnknownRequirement(t *testing.T) {
	p := &WebDAVProtocol{
		URI:          "u",
		SharedSecret: "s",
		Permissions:  []string{"read"},
		Requirements: []string{"an-unsupported-requirement"},
	}
	errs := ValidateWebDAVProtocol(p)
	if !hasValidationError(errs, "protocol.webdav.requirements") {
		t.Fatalf("expected a requirements validation error, got %v", errs)
	}
}

func TestValidateWebDAVProtocol_RejectsEmptyRequirements(t *testing.T) {
	validShape := func() *WebDAVProtocol {
		return &WebDAVProtocol{
			URI:          "u",
			SharedSecret: "s",
			Permissions:  []string{"read"},
		}
	}

	assertRequiredRequirements := func(t *testing.T, errs []ValidationError) {
		t.Helper()
		if !hasValidationError(errs, "protocol.webdav.requirements") {
			t.Fatalf("expected requirements validation error, got %v", errs)
		}
		requiredCount := 0
		for _, e := range errs {
			if e.Name == "protocol.webdav.requirements" && e.Message == "REQUIRED" {
				requiredCount++
			}
		}
		if requiredCount != 1 {
			t.Fatalf("empty requirements must yield exactly one REQUIRED, got %d in %v", requiredCount, errs)
		}
	}

	t.Run("nil requirements", func(t *testing.T) {
		p := validShape()
		p.Requirements = nil
		assertRequiredRequirements(t, ValidateWebDAVProtocol(p))
	})
	t.Run("empty requirements", func(t *testing.T) {
		p := validShape()
		p.Requirements = []string{}
		assertRequiredRequirements(t, ValidateWebDAVProtocol(p))
	})
	t.Run("must-exchange-token accepted", func(t *testing.T) {
		p := validShape()
		p.Requirements = []string{RequirementMustExchangeToken}
		if errs := ValidateWebDAVProtocol(p); len(errs) != 0 {
			t.Fatalf("expected no validation errors, got %v", errs)
		}
	})
}
