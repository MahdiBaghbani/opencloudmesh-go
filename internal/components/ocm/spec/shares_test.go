package spec

import (
	"encoding/json"
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
	p := &WebDAVProtocol{SharedSecret: "s", Permissions: []string{"read"}}
	errs := ValidateWebDAVProtocol(p)
	if !hasValidationError(errs, "protocol.webdav.uri") {
		t.Fatalf("expected a uri validation error, got %v", errs)
	}
}

func TestWebDAVRequiresSharedSecret(t *testing.T) {
	p := &WebDAVProtocol{URI: "u", Permissions: []string{"read"}}
	errs := ValidateWebDAVProtocol(p)
	if !hasValidationError(errs, "protocol.webdav.sharedSecret") {
		t.Fatalf("expected a sharedSecret validation error, got %v", errs)
	}
}

func TestWebDAVRequiresPermissions(t *testing.T) {
	p := &WebDAVProtocol{URI: "u", SharedSecret: "s"}
	errs := ValidateWebDAVProtocol(p)
	if !hasValidationError(errs, "protocol.webdav.permissions") {
		t.Fatalf("expected a permissions validation error, got %v", errs)
	}
}

func TestWebDAVAcceptsAccessTypes(t *testing.T) {
	const body = `{"uri":"u","sharedSecret":"s","permissions":["read"],"accessTypes":["read","write"]}`
	var p WebDAVProtocol
	if err := json.Unmarshal([]byte(body), &p); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(p.AccessTypes) != 2 || p.AccessTypes[0] != "read" || p.AccessTypes[1] != "write" {
		t.Errorf("AccessTypes = %v, want [read write]", p.AccessTypes)
	}
	if errs := ValidateWebDAVProtocol(&p); len(errs) != 0 {
		t.Errorf("unexpected validation errors: %v", errs)
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
