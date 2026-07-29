package spec_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/localidentity"
	tslocalid "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/localidentity"

	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/services/ocm"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/services/ui"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/services/webdav"
)

func TestHasCriteria_CanonicalEqualityOnly(t *testing.T) {
	disc := &spec.Discovery{
		Criteria: []string{spec.CriteriaMustUseHTTPSig, spec.CriteriaMustExchangeToken},
	}

	for _, query := range []string{
		spec.CriteriaMustUseHTTPSig,
		spec.CriteriaMustExchangeToken,
	} {
		if !disc.HasCriteria(query) {
			t.Errorf("HasCriteria(%q) = false, want true", query)
		}
	}

	if disc.HasCriteria("unknown") {
		t.Error("HasCriteria(unknown) should be false")
	}
}

func TestRequiresHTTPSigAndIsHTTPSigCapable(t *testing.T) {
	disc := &spec.Discovery{
		Capabilities: []string{"http-sig"},
		Criteria:     []string{"must-use-http-sig"},
	}
	if !disc.RequiresHTTPSig() {
		t.Error("RequiresHTTPSig() should be true")
	}

	if !disc.IsHTTPSigCapable() {
		t.Error("IsHTTPSigCapable() should be true")
	}

	if (&spec.Discovery{}).RequiresHTTPSig() {
		t.Error("nil criteria should not require http sig")
	}
}

func TestDeriveDiscoveryPaths_RootMount(t *testing.T) {
	id := tslocalid.MustTestIdentity(t, "https://example.com", "")

	paths, ok := spec.DeriveDiscoveryPaths(id, service.DefaultRouteOpts())
	if !ok {
		t.Fatal("expected projection ok")
	}

	if paths.EndPoint != "https://example.com/ocm" {
		t.Errorf("EndPoint = %q, want https://example.com/ocm", paths.EndPoint)
	}

	if paths.TokenEndPoint != "https://example.com/ocm/token" {
		t.Errorf("TokenEndPoint = %q, want https://example.com/ocm/token", paths.TokenEndPoint)
	}

	if paths.WebDAVRoot != "/webdav/ocm/" {
		t.Errorf("WebDAVRoot = %q, want /webdav/ocm/", paths.WebDAVRoot)
	}

	if paths.InviteAcceptDialog != "" {
		t.Errorf("InviteAcceptDialog = %q, want empty when invite accept disabled", paths.InviteAcceptDialog)
	}
}

func TestDeriveDiscoveryPaths_BasePathAndInviteAccept(t *testing.T) {
	id := tslocalid.MustTestIdentity(t, "https://cloud.example.com", "/ocm")
	opts := service.RouteOpts{
		ExternalBasePath:    "/ocm",
		WayfEnabled:         true,
		InviteAcceptEnabled: true,
		TokenExchangePath:   "token",
	}

	paths, ok := spec.DeriveDiscoveryPaths(id, opts)
	if !ok {
		t.Fatal("expected projection ok")
	}

	if paths.EndPoint != "https://cloud.example.com/ocm/ocm" {
		t.Errorf("EndPoint = %q, want https://cloud.example.com/ocm/ocm", paths.EndPoint)
	}

	if paths.WebDAVRoot != "/ocm/webdav/ocm/" {
		t.Errorf("WebDAVRoot = %q, want /ocm/webdav/ocm/", paths.WebDAVRoot)
	}

	if paths.InviteAcceptDialog != "https://cloud.example.com/ocm/ui/accept-invite" {
		t.Errorf("InviteAcceptDialog = %q", paths.InviteAcceptDialog)
	}
}

func TestResolveInviteAcceptDialog_RelativePeerValue(t *testing.T) {
	got := spec.ResolveInviteAcceptDialog("https://peer.example.com/ocm", "/apps/ocm/invite-accept")

	want := "https://peer.example.com/apps/ocm/invite-accept"
	if got != want {
		t.Errorf("ResolveInviteAcceptDialog() = %q, want %q", got, want)
	}
}

func TestDeriveDiscoveryPaths_SameAuthorityEndpoints(t *testing.T) {
	id := tslocalid.MustTestIdentity(t, "https://cloud.example.com", "/ocm")
	opts := service.RouteOpts{ExternalBasePath: "/ocm"}

	paths, ok := spec.DeriveDiscoveryPaths(id, opts)
	if !ok {
		t.Fatal("expected projection ok")
	}

	if paths.EndPoint == "" || paths.TokenEndPoint == "" {
		t.Fatal("expected non-empty projected endpoints")
	}

	if !strings.HasPrefix(paths.EndPoint, "https://cloud.example.com/") {
		t.Errorf("EndPoint = %q, want same-authority projection", paths.EndPoint)
	}

	if !strings.HasPrefix(paths.TokenEndPoint, "https://cloud.example.com/") {
		t.Errorf("TokenEndPoint = %q, want same-authority projection", paths.TokenEndPoint)
	}
}

func TestDeriveDiscoveryPaths_RequiresOrigin(t *testing.T) {
	_, ok := spec.DeriveDiscoveryPaths(localidentity.Identity{ExternalBasePath: "/ocm"}, service.DefaultRouteOpts())
	if ok {
		t.Error("expected projection false without Origin")
	}
}

func TestWebDAVReceiveURIKind(t *testing.T) {
	absDisc := &spec.Discovery{
		ResourceTypes: []spec.ResourceType{{
			Name: "file",
			Protocols: spec.Protocols{
				"webdav-receive": spec.WebDAVReceiveRole(spec.WebDAVReceiveURIAbsolute),
			},
		}},
	}
	if got := absDisc.WebDAVReceiveURIKind(); got != spec.WebDAVReceiveURIAbsolute {
		t.Fatalf("WebDAVReceiveURIKind() = %q, want %q", got, spec.WebDAVReceiveURIAbsolute)
	}

	relDisc := &spec.Discovery{
		ResourceTypes: []spec.ResourceType{{
			Name: "folder",
			Protocols: spec.Protocols{
				"webdav-receive": spec.WebDAVReceiveRole(spec.WebDAVReceiveURIRelative),
			},
		}},
	}
	if got := relDisc.WebDAVReceiveURIKind(); got != spec.WebDAVReceiveURIRelative {
		t.Fatalf("WebDAVReceiveURIKind() = %q, want %q", got, spec.WebDAVReceiveURIRelative)
	}

	if got := (&spec.Discovery{}).WebDAVReceiveURIKind(); got != "" {
		t.Fatalf("WebDAVReceiveURIKind() = %q, want empty", got)
	}
}

func TestSupportedResourceTypes(t *testing.T) {
	if len(spec.SupportedResourceTypes) != 2 {
		t.Fatalf("SupportedResourceTypes = %v, want [file folder]", spec.SupportedResourceTypes)
	}

	for _, rt := range []string{"file", "folder"} {
		if !spec.IsSupportedResourceType(rt) {
			t.Errorf("IsSupportedResourceType(%q) = false, want true", rt)
		}
	}

	if spec.IsSupportedResourceType("calendar") {
		t.Error("IsSupportedResourceType(calendar) = true, want false")
	}
}

func TestDiscovery_JwksUriPresent(t *testing.T) {
	const jwksURI = "https://example.com/ocm/jwks"

	disc := &spec.Discovery{
		Enabled:       true,
		APIVersion:    "1.4.0",
		EndPoint:      "https://example.com/ocm",
		ResourceTypes: []spec.ResourceType{},
		Criteria:      []string{},
		JwksUri:       jwksURI,
	}

	data, err := json.Marshal(disc)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("failed to unmarshal map: %v", err)
	}

	got, ok := parsed["jwksUri"]
	if !ok {
		t.Fatal("jwksUri key must be present in JSON")
	}

	if got != jwksURI {
		t.Errorf("jwksUri = %v, want %q", got, jwksURI)
	}

	var roundTrip spec.Discovery
	if err := json.Unmarshal(data, &roundTrip); err != nil {
		t.Fatalf("failed to unmarshal Discovery: %v", err)
	}

	if roundTrip.JwksUri != jwksURI {
		t.Errorf("JwksUri = %q, want %q", roundTrip.JwksUri, jwksURI)
	}
}

func TestDiscovery_JwksUriOmittedWhenEmpty(t *testing.T) {
	disc := &spec.Discovery{
		Enabled:       true,
		APIVersion:    "1.4.0",
		EndPoint:      "https://example.com/ocm",
		ResourceTypes: []spec.ResourceType{},
		Criteria:      []string{},
	}

	data, err := json.Marshal(disc)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("failed to unmarshal map: %v", err)
	}

	if _, ok := parsed["jwksUri"]; ok {
		t.Error("jwksUri key must be omitted when empty")
	}

	payload := `{"enabled":true,"apiVersion":"1.4.0","endPoint":"https://example.com/ocm","resourceTypes":[],"criteria":[]}`

	var fromJSON spec.Discovery
	if err := json.Unmarshal([]byte(payload), &fromJSON); err != nil {
		t.Fatalf("failed to unmarshal Discovery: %v", err)
	}

	if fromJSON.JwksUri != "" {
		t.Errorf("JwksUri = %q, want empty string", fromJSON.JwksUri)
	}
}

func TestCriteriaAlwaysPresent(t *testing.T) {
	disc := &spec.Discovery{
		Enabled:    true,
		APIVersion: "1.4.0",
		Criteria:   []string{},
	}

	if disc.Criteria == nil {
		t.Error("Criteria must not be nil")
	}

	data, err := json.Marshal(disc)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	criteriaRaw, ok := parsed["criteria"]
	if !ok {
		t.Error("criteria key must be present in JSON")
	}

	criteriaSlice, ok := criteriaRaw.([]interface{})
	if !ok {
		t.Errorf("criteria must be an array, got %T", criteriaRaw)
	}

	if len(criteriaSlice) != 0 {
		t.Errorf("expected empty criteria array, got %v", criteriaSlice)
	}
}

func TestDiscovery_Helpers(t *testing.T) {
	disc := &spec.Discovery{
		Enabled:    true,
		APIVersion: "1.4.0",
		EndPoint:   "https://example.com/ocm",
		ResourceTypes: []spec.ResourceType{
			{
				Name:       "file",
				ShareTypes: []string{"user"},
				Protocols:  spec.Protocols{"webdav": spec.StringProtocolRole("/webdav/ocm/")},
			},
		},
		Capabilities: []string{"http-sig", "exchange-token"},
		Criteria:     []string{spec.CriteriaMustUseHTTPSig},
	}

	if disc.GetWebDAVPath() != "/webdav/ocm/" {
		t.Errorf("GetWebDAVPath failed: %q", disc.GetWebDAVPath())
	}

	if !disc.HasCriteria(spec.CriteriaMustUseHTTPSig) {
		t.Error("HasCriteria must-use-http-sig should be true")
	}

	url, err := disc.BuildWebDAVURL("abc123")
	if err != nil {
		t.Fatalf("BuildWebDAVURL failed: %v", err)
	}

	if url != "https://example.com/webdav/ocm/abc123" {
		t.Errorf("BuildWebDAVURL returned %q", url)
	}
}
