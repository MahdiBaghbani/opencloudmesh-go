package spec

import (
	"encoding/json"
	"strings"
	"testing"
)

func hasValidationError(errs []ValidationError, name string) bool {
	for _, e := range errs {
		if e.Name == name {
			return true
		}
	}
	return false
}

func TestProtocolAcceptsMultiWithWebDAV(t *testing.T) {
	const body = `{"name":"multi","webdav":{"uri":"u","sharedSecret":"s","permissions":["read"]}}`
	var p Protocol
	if err := json.Unmarshal([]byte(body), &p); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if p.Name != "multi" {
		t.Errorf("Name = %q, want multi", p.Name)
	}
	if p.WebDAV == nil {
		t.Fatal("expected non-nil WebDAV")
	}
	if p.WebDAV.URI != "u" {
		t.Errorf("URI = %q, want u", p.WebDAV.URI)
	}
	if p.WebDAV.SharedSecret != "s" {
		t.Errorf("SharedSecret = %q, want s", p.WebDAV.SharedSecret)
	}
	if len(p.WebDAV.Permissions) != 1 || p.WebDAV.Permissions[0] != "read" {
		t.Errorf("Permissions = %v, want [read]", p.WebDAV.Permissions)
	}
}

func TestProtocolAcceptsNamedWebDAV(t *testing.T) {
	const body = `{"name":"webdav","webdav":{"uri":"u","sharedSecret":"s","permissions":["read"]}}`
	var p Protocol
	if err := json.Unmarshal([]byte(body), &p); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if p.Name != "webdav" {
		t.Errorf("Name = %q, want webdav", p.Name)
	}
	if p.WebDAV == nil {
		t.Fatal("expected non-nil WebDAV")
	}
}

func TestProtocolRejectsMissingName(t *testing.T) {
	const body = `{"webdav":{"uri":"u","sharedSecret":"s","permissions":["read"]}}`
	var p Protocol
	if err := json.Unmarshal([]byte(body), &p); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if err := ValidateProtocolShape(p); err == nil {
		t.Fatal("expected a validation error for a missing protocol name")
	}
}

func TestProtocolRejectsUnknownProtocolArm(t *testing.T) {
	const body = `{"name":"multi","webdav":{"uri":"u","sharedSecret":"s","permissions":["read"]},"futureArm":{"uri":"u2"}}`
	var p Protocol
	if err := json.Unmarshal([]byte(body), &p); err != nil {
		t.Fatalf("unmarshal typed protocol: %v", err)
	}
	if p.Name != "multi" {
		t.Errorf("Name = %q, want multi", p.Name)
	}
	if p.WebDAV == nil {
		t.Fatal("expected non-nil WebDAV on typed decode")
	}
	if p.WebDAV.URI != "u" || p.WebDAV.SharedSecret != "s" {
		t.Fatalf("typed WebDAV = %+v, want uri=u sharedSecret=s", p.WebDAV)
	}
	if len(p.WebDAV.Permissions) != 1 || p.WebDAV.Permissions[0] != "read" {
		t.Errorf("Permissions = %v, want [read]", p.WebDAV.Permissions)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(body), &raw); err != nil {
		t.Fatalf("unmarshal raw protocol: %v", err)
	}
	if _, ok := raw["futureArm"]; !ok {
		t.Fatal("fixture did not retain futureArm")
	}
	err := ValidateProtocolArms(raw)
	if err == nil {
		t.Fatal("expected general UNSUPPORTED error for unknown protocol arm")
	}
	if err.Error() != "UNSUPPORTED" {
		t.Fatalf("error = %q, want UNSUPPORTED", err.Error())
	}
}

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

func TestProtocolArmsAllowWebapp(t *testing.T) {
	const body = `{"name":"multi","webapp":{"uri":"u","targets":["blank"],"permissions":["view"],"requirements":["must-exchange-token"],"sharedSecret":"s"}}`
	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(body), &raw); err != nil {
		t.Fatalf("unmarshal raw: %v", err)
	}
	if err := ValidateProtocolArms(raw); err != nil {
		t.Fatalf("webapp arm should be admitted, got %v", err)
	}
}

func TestProtocolArmsRejectUnknownAlongsideWebapp(t *testing.T) {
	const body = `{"name":"multi","webapp":{"uri":"u"},"futureArm":{"uri":"u2"}}`
	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(body), &raw); err != nil {
		t.Fatalf("unmarshal raw: %v", err)
	}
	if err := ValidateProtocolArms(raw); err == nil {
		t.Fatal("expected UNSUPPORTED error for unknown arm alongside webapp")
	}
}

func TestProtocolShapeAdmitsMultiWithWebappOnly(t *testing.T) {
	p := Protocol{
		Name:   "multi",
		Webapp: &WebappProtocol{URI: "u"},
	}
	if err := ValidateProtocolShape(p); err != nil {
		t.Fatalf("multi+webapp-only should be admitted, got %v", err)
	}
}

func TestProtocolShapeRejectsMultiWithNoArms(t *testing.T) {
	p := Protocol{Name: "multi"}
	if err := ValidateProtocolShape(p); err == nil {
		t.Fatal("expected a validation error for multi with no arms")
	}
}

func TestProtocolShapePreservesNamedWebDAVRequirement(t *testing.T) {
	// name="webdav" must still require a webdav arm even though webapp exists.
	p := Protocol{Name: "webdav", Webapp: &WebappProtocol{URI: "u"}}
	if err := ValidateProtocolShape(p); err == nil {
		t.Fatal("expected named webdav shape to require a webdav arm")
	}
}

func validWebapp() *WebappProtocol {
	return &WebappProtocol{
		URI:          "https://sender.example/apps/files/abc",
		Targets:      []string{"blank"},
		Permissions:  []string{"view", "read"},
		Requirements: []string{RequirementMustExchangeToken},
		SharedSecret: "topsecret",
	}
}

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
