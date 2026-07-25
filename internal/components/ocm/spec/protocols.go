package spec

import (
	"encoding/json"
	"fmt"
)

// WebDAVReceiveURIKind is the uri field of a webdav-receive protocol role.
type WebDAVReceiveURIKind string

const (
	WebDAVReceiveURIAbsolute WebDAVReceiveURIKind = "absolute"
	WebDAVReceiveURIRelative WebDAVReceiveURIKind = "relative"
)

// ProtocolWebDAV and ProtocolWebDAVReceive are the canonical OCM discovery protocol role keys.
const (
	ProtocolWebDAV        = "webdav"
	ProtocolWebDAVReceive = "webdav-receive"
)

// WebDAVReceive is the structured webdav-receive protocol role.
type WebDAVReceive struct {
	URI WebDAVReceiveURIKind `json:"uri"`
}

// ProtocolRole is either a string path/address or a structured JSON object.
type ProtocolRole struct {
	kind   protocolRoleKind
	string string
	object json.RawMessage
}

type protocolRoleKind int

const (
	protocolRoleUnset protocolRoleKind = iota
	protocolRoleString
	protocolRoleObject
)

// StringProtocolRole constructs a string-valued protocol role.
func StringProtocolRole(s string) ProtocolRole {
	return ProtocolRole{kind: protocolRoleString, string: s}
}

// ObjectProtocolRole marshals v as a JSON object protocol role.
func ObjectProtocolRole(v any) (ProtocolRole, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return ProtocolRole{}, err
	}
	if len(raw) == 0 || raw[0] != '{' {
		return ProtocolRole{}, fmt.Errorf("protocol role object must marshal to a JSON object")
	}
	return ProtocolRole{kind: protocolRoleObject, object: raw}, nil
}

// WebDAVReceiveRole constructs a webdav-receive protocol role.
func WebDAVReceiveRole(uri WebDAVReceiveURIKind) ProtocolRole {
	role, _ := ObjectProtocolRole(WebDAVReceive{URI: uri})
	return role
}

func (p ProtocolRole) MarshalJSON() ([]byte, error) {
	switch p.kind {
	case protocolRoleString:
		return json.Marshal(p.string)
	case protocolRoleObject:
		if len(p.object) == 0 {
			return []byte("{}"), nil
		}
		return p.object, nil
	default:
		return nil, fmt.Errorf("invalid protocol role")
	}
}

func (p *ProtocolRole) UnmarshalJSON(data []byte) error {
	if len(data) == 0 || string(data) == "null" {
		return fmt.Errorf("protocol role cannot be null")
	}
	if data[0] == '"' {
		var s string
		if err := json.Unmarshal(data, &s); err != nil {
			return err
		}
		p.kind = protocolRoleString
		p.string = s
		p.object = nil
		return nil
	}
	if data[0] != '{' {
		return fmt.Errorf("protocol role must be string or object")
	}
	p.kind = protocolRoleObject
	p.object = append(json.RawMessage(nil), data...)
	p.string = ""
	return nil
}

// StringValue returns the string form when the role is string-valued.
func (p ProtocolRole) StringValue() (string, bool) {
	if p.kind != protocolRoleString {
		return "", false
	}
	return p.string, true
}

// WebDAVReceive decodes a webdav-receive object role.
func (p ProtocolRole) WebDAVReceive() (*WebDAVReceive, bool) {
	if p.kind != protocolRoleObject {
		return nil, false
	}
	var wr WebDAVReceive
	if err := json.Unmarshal(p.object, &wr); err != nil || wr.URI == "" {
		return nil, false
	}
	return &wr, true
}

// Protocols maps OCM protocol role names to string or object values.
type Protocols map[string]ProtocolRole

// StringRole returns a string-valued role by name.
func (p Protocols) StringRole(name string) (string, bool) {
	role, ok := p[name]
	if !ok {
		return "", false
	}
	return role.StringValue()
}

// WebDAVReceive returns a webdav-receive role when present.
func (p Protocols) WebDAVReceive() (*WebDAVReceive, bool) {
	role, ok := p[ProtocolWebDAVReceive]
	if !ok {
		return nil, false
	}
	return role.WebDAVReceive()
}
