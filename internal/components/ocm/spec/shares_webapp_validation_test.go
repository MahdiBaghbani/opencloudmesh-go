package spec

import (
	"encoding/json"
	"testing"
)

func TestWebappDTO_DecodeValid(t *testing.T) {
	const body = `{"uri":"https://sender.example/apps/files/abc","targets":["blank","iframe"],"permissions":["view","read","write","share"],"requirements":["must-exchange-token"],"sharedSecret":"s"}`

	var p WebappProtocol
	if err := json.Unmarshal([]byte(body), &p); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if p.URI == "" || p.SharedSecret != "s" {
		t.Fatalf("decoded webapp = %+v", p)
	}

	if len(p.Targets) != 2 || p.Targets[0] != "blank" || p.Targets[1] != "iframe" {
		t.Errorf("Targets = %v, want [blank iframe]", p.Targets)
	}

	if len(p.Permissions) != 4 {
		t.Errorf("Permissions = %v, want 4 entries", p.Permissions)
	}

	if errs := ValidateWebappProtocol(&p); len(errs) != 0 {
		t.Errorf("unexpected validation errors: %v", errs)
	}
}

func TestWebappProtocol_AcceptsValid(t *testing.T) {
	if errs := ValidateWebappProtocol(validWebapp()); len(errs) != 0 {
		t.Fatalf("expected no validation errors, got %v", errs)
	}
}

func TestWebappProtocol_RequiresURI(t *testing.T) {
	p := validWebapp()
	p.URI = ""

	errs := ValidateWebappProtocol(p)
	if !hasValidationError(errs, "protocol.webapp.uri") {
		t.Fatalf("expected uri validation error, got %v", errs)
	}
}

func TestWebappProtocol_RequiresTargets(t *testing.T) {
	p := validWebapp()
	p.Targets = nil

	errs := ValidateWebappProtocol(p)
	if !hasValidationError(errs, "protocol.webapp.targets") {
		t.Fatalf("expected targets validation error, got %v", errs)
	}
}

func TestWebappProtocol_RequiresPermissions(t *testing.T) {
	p := validWebapp()
	p.Permissions = nil

	errs := ValidateWebappProtocol(p)
	if !hasValidationError(errs, "protocol.webapp.permissions") {
		t.Fatalf("expected permissions validation error, got %v", errs)
	}
}

func TestWebappProtocol_RequiresRequirements(t *testing.T) {
	p := validWebapp()
	p.Requirements = nil

	errs := ValidateWebappProtocol(p)
	if !hasValidationError(errs, "protocol.webapp.requirements") {
		t.Fatalf("expected requirements validation error, got %v", errs)
	}

	requiredCount := 0

	for _, e := range errs {
		if e.Name == "protocol.webapp.requirements" && e.Message == "REQUIRED" {
			requiredCount++
		}
	}

	if requiredCount != 1 {
		t.Fatalf("strict empty requirements must yield exactly one REQUIRED, got %d in %v", requiredCount, errs)
	}
}

func TestWebappProtocol_RequiresSharedSecret(t *testing.T) {
	p := validWebapp()
	p.SharedSecret = ""

	errs := ValidateWebappProtocol(p)
	if !hasValidationError(errs, "protocol.webapp.sharedSecret") {
		t.Fatalf("expected sharedSecret validation error, got %v", errs)
	}
}

func TestWebappProtocol_RequiresMustExchangeToken(t *testing.T) {
	// Non-empty requirements without must-exchange-token must be rejected,
	// even when the only other requirement is the recognized must-use-mfa.
	p := validWebapp()
	p.Requirements = []string{RequirementMustUseMFA}

	errs := ValidateWebappProtocol(p)
	if !hasValidationError(errs, "protocol.webapp.requirements") {
		t.Fatalf("expected requirements error for missing must-exchange-token, got %v", errs)
	}
}

func TestWebappProtocol_RejectsUnknownRequirement(t *testing.T) {
	p := validWebapp()
	p.Requirements = []string{RequirementMustExchangeToken, "an-unsupported-requirement"}

	errs := ValidateWebappProtocol(p)
	if !hasValidationError(errs, "protocol.webapp.requirements") {
		t.Fatalf("expected a requirements validation error, got %v", errs)
	}

	for _, e := range errs {
		if e.Name == "protocol.webapp.requirements" && e.Message == "UNSUPPORTED" {
			return
		}
	}

	t.Fatalf("expected UNSUPPORTED requirement error, got %v", errs)
}

func TestWebappProtocol_RejectsUnsupportedPermission(t *testing.T) {
	p := validWebapp()
	p.Permissions = []string{"delete"}

	errs := ValidateWebappProtocol(p)
	if !hasValidationError(errs, "protocol.webapp.permissions") {
		t.Fatalf("expected permissions validation error, got %v", errs)
	}

	for _, e := range errs {
		if e.Name == "protocol.webapp.permissions" && e.Message == "UNSUPPORTED" {
			return
		}
	}

	t.Fatalf("expected UNSUPPORTED permission error, got %v", errs)
}

func TestWebappPermissions_DistinctFromWebDAV(t *testing.T) {
	// The webapp allow-list must be distinct and broader than WebDAV's.
	// view/write/share are supported for webapp but NOT for webdav.
	for _, perm := range []string{"view", "write", "share"} {
		if !isSupportedWebappPermission(perm) {
			t.Errorf("webapp should support %q", perm)
		}

		if isSupportedWebDAVPermission(perm) {
			t.Errorf("webdav must not support %q (lists must be distinct)", perm)
		}
	}
	// SupportedWebappPermissions must be exactly {view, read, write, share}.
	want := map[string]bool{"view": true, "read": true, "write": true, "share": true}
	if len(SupportedWebappPermissions) != len(want) {
		t.Fatalf("SupportedWebappPermissions = %v, want 4 entries", SupportedWebappPermissions)
	}

	for _, p := range SupportedWebappPermissions {
		if !want[p] {
			t.Errorf("unexpected webapp permission %q", p)
		}
	}
}

func TestWebappProtocol_RejectsMustUseMFAWithGapNote(t *testing.T) {
	p := validWebapp()
	p.Requirements = []string{RequirementMustExchangeToken, RequirementMustUseMFA}
	errs := ValidateWebappProtocol(p)

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
