package spec_test

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/modroot"
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

func TestProtocolWireValues(t *testing.T) {
	cases := []struct {
		name string
		got  string
		want string
	}{
		{name: "webdav", got: spec.ProtocolWebDAV, want: "webdav"},
		{name: "webdav-receive", got: spec.ProtocolWebDAVReceive, want: "webdav-receive"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.got != tc.want {
				t.Errorf("wire value = %q, want %q", tc.got, tc.want)
			}
		})
	}
}

// protocolClosedPathFiles are production files on the closed migration path.
// Each must not contain raw protocol wire string literals; use spec.*.
var protocolClosedPathFiles = []string{
	"internal/components/ocm/discovery/builder.go",
	"internal/components/ocm/discovery/validate.go",
	"internal/components/ocm/policy/compiler.go",
}

var protocolWireLiterals = []string{
	`"webdav"`,
	`"webdav-receive"`,
}

func TestProtocolClosedPathNoRawWireLiterals(t *testing.T) {
	root := modroot.ModuleRoot(t)
	for _, rel := range protocolClosedPathFiles {
		t.Run(rel, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
			if err != nil {
				t.Fatalf("read %s: %v", rel, err)
			}

			content := string(data)
			for _, lit := range protocolWireLiterals {
				if strings.Contains(content, lit) {
					t.Errorf("%s still contains raw protocol literal %s; use spec.*", rel, lit)
				}
			}
		})
	}
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

func TestProtocolsDiscoveryProductionUsesSpecConstants(t *testing.T) {
	root := modroot.ModuleRoot(t)

	files := []string{
		"internal/components/ocm/discovery/builder.go",
		"internal/components/ocm/discovery/validate.go",
	}
	for _, rel := range files {

		t.Run(rel, func(t *testing.T) {
			path := filepath.Join(root, rel)

			src, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v", rel, err)
			}

			fset := token.NewFileSet()

			f, err := parser.ParseFile(fset, rel, src, parser.ParseComments)
			if err != nil {
				t.Fatalf("parse %s: %v", rel, err)
			}

			found := map[string]bool{}

			ast.Inspect(f, func(n ast.Node) bool {
				if sel, ok := n.(*ast.SelectorExpr); ok {
					name := selectorExprName(sel)
					switch name {
					case "spec.ProtocolWebDAV", "spec.ProtocolWebDAVReceive":
						found[name] = true
					}
				}

				if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING {
					val, err := strconv.Unquote(lit.Value)
					if err != nil {
						return true
					}

					if val == "webdav" || val == "webdav-receive" {
						pos := fset.Position(lit.Pos())
						t.Errorf("%s:%d: raw protocol literal %q", rel, pos.Line, val)
					}
				}

				return true
			})

			if !found["spec.ProtocolWebDAV"] {
				t.Errorf("%s: missing spec.ProtocolWebDAV", rel)
			}

			if !found["spec.ProtocolWebDAVReceive"] {
				t.Errorf("%s: missing spec.ProtocolWebDAVReceive", rel)
			}
		})
	}
}

func selectorExprName(sel *ast.SelectorExpr) string {
	if sel == nil || sel.Sel == nil {
		return ""
	}

	if ident, ok := sel.X.(*ast.Ident); ok {
		return ident.Name + "." + sel.Sel.Name
	}

	return ""
}
