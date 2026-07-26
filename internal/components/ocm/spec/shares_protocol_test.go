package spec

import (
	"encoding/json"
	"testing"
)

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
