package spec_test

import (
	"encoding/json"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
)

func assertProtocolsRoundTrip(t *testing.T, input string) {
	t.Helper()
	var wrapper struct {
		Protocols spec.Protocols `json:"protocols"`
	}
	if err := json.Unmarshal([]byte(input), &wrapper); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	out, err := json.Marshal(wrapper)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var inWrap struct {
		Protocols map[string]json.RawMessage `json:"protocols"`
	}
	if err := json.Unmarshal([]byte(input), &inWrap); err != nil {
		t.Fatalf("decode input roles: %v", err)
	}
	var outWrap struct {
		Protocols map[string]json.RawMessage `json:"protocols"`
	}
	if err := json.Unmarshal(out, &outWrap); err != nil {
		t.Fatalf("decode output roles: %v", err)
	}
	if len(inWrap.Protocols) != len(outWrap.Protocols) {
		t.Fatalf("role count: in=%d out=%d", len(inWrap.Protocols), len(outWrap.Protocols))
	}
	for name, inRaw := range inWrap.Protocols {
		outRaw, ok := outWrap.Protocols[name]
		if !ok {
			t.Fatalf("missing role %q in output", name)
		}
		if string(inRaw) != string(outRaw) {
			t.Errorf("role %q: in=%s out=%s", name, inRaw, outRaw)
		}
	}
}

func TestObjectProtocolRole_RejectsNonObject(t *testing.T) {
	cases := []any{
		"scalar",
		42,
		[]string{"blank"},
	}
	for _, tc := range cases {
		if _, err := spec.ObjectProtocolRole(tc); err == nil {
			t.Fatalf("ObjectProtocolRole(%#v) expected error", tc)
		}
	}
}

func TestObjectProtocolRole_AcceptsObject(t *testing.T) {
	role, err := spec.ObjectProtocolRole(spec.WebDAVReceive{URI: spec.WebDAVReceiveURIAbsolute})
	if err != nil {
		t.Fatalf("ObjectProtocolRole: %v", err)
	}
	wr, ok := role.WebDAVReceive()
	if !ok || wr.URI != spec.WebDAVReceiveURIAbsolute {
		t.Fatalf("WebDAVReceive = %+v, ok=%v", wr, ok)
	}
}

func TestProtocolRole_UnmarshalJSON_RejectsInvalidTypes(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{name: "null", input: "null"},
		{name: "number", input: "42"},
		{name: "array", input: "[1,2,3]"},
		{name: "boolean", input: "true"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var role spec.ProtocolRole
			if err := json.Unmarshal([]byte(tc.input), &role); err == nil {
				t.Fatalf("Unmarshal(%s) expected error", tc.input)
			}
		})
	}
}

func TestProtocolRole_JSONRoundTrip_StringRole(t *testing.T) {
	const input = `{"protocols":{"webdav":"/remote/dav/ocm/"}}`
	assertProtocolsRoundTrip(t, input)

	var wrapper struct {
		Protocols spec.Protocols `json:"protocols"`
	}
	if err := json.Unmarshal([]byte(input), &wrapper); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	path, ok := wrapper.Protocols.StringRole("webdav")
	if !ok || path != "/remote/dav/ocm/" {
		t.Fatalf("webdav = %q, ok=%v", path, ok)
	}
}

func TestProtocolRole_JSONRoundTrip_ObjectReceiveRoles(t *testing.T) {
	const input = `{"protocols":{"webdav-receive":{"uri":"absolute"}}}`
	assertProtocolsRoundTrip(t, input)

	var wrapper struct {
		Protocols spec.Protocols `json:"protocols"`
	}
	if err := json.Unmarshal([]byte(input), &wrapper); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	wr, ok := wrapper.Protocols.WebDAVReceive()
	if !ok || wr.URI != spec.WebDAVReceiveURIAbsolute {
		t.Fatalf("WebDAVReceive = %+v, ok=%v", wr, ok)
	}
}

func TestProtocolRole_JSONRoundTrip_CustomProtocol(t *testing.T) {
	const input = `{"protocols":{"custom-proto":"/custom/path","custom-recv":{"mode":"push"}}}`
	assertProtocolsRoundTrip(t, input)

	var wrapper struct {
		Protocols spec.Protocols `json:"protocols"`
	}
	if err := json.Unmarshal([]byte(input), &wrapper); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	path, ok := wrapper.Protocols.StringRole("custom-proto")
	if !ok || path != "/custom/path" {
		t.Fatalf("custom-proto = %q, ok=%v", path, ok)
	}
}

func TestProtocolRole_JSONRoundTrip_FullExample(t *testing.T) {
	const input = `{"protocols":{"webdav":"/remote/dav/ocm/","webdav-receive":{"uri":"absolute"}}}`
	assertProtocolsRoundTrip(t, input)
}

func TestDiscovery_GetWebDAVPath_TypedStringRole(t *testing.T) {
	disc := &spec.Discovery{
		ResourceTypes: []spec.ResourceType{{
			Name: "file",
			Protocols: spec.Protocols{
				"webdav": spec.StringProtocolRole("/webdav/ocm/"),
			},
		}},
	}
	if got := disc.GetWebDAVPath(); got != "/webdav/ocm/" {
		t.Errorf("GetWebDAVPath() = %q", got)
	}
}
