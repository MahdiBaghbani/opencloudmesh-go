package discovery_test

import (
	"encoding/json"
	"net/url"
	"sort"
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
)

func TestBuildDiscovery_DisabledWhenNoEndPoint(t *testing.T) {
	disc := discovery.BuildDiscovery(discovery.BuildParams{Provider: "OpenCloudMesh"}, nil)
	if disc.Enabled {
		t.Error("expected Enabled=false when endPoint is empty")
	}
}

func TestBuildDiscovery_DisabledWhenInvalidEndPoint(t *testing.T) {
	disc := discovery.BuildDiscovery(discovery.BuildParams{EndPoint: "://invalid-url"}, nil)
	if disc.Enabled {
		t.Error("expected Enabled=false for invalid URL")
	}
}

func TestBuildDiscovery_EnabledWithProjectedPaths(t *testing.T) {
	disc := discovery.BuildDiscovery(discovery.BuildParams{
		EndPoint:   "https://example.com/myapp/ocm",
		WebDAVRoot: "/webdav/ocm/",
	}, nil)

	if !disc.Enabled {
		t.Fatal("expected Enabled=true")
	}

	if disc.EndPoint != "https://example.com/myapp/ocm" {
		t.Errorf("EndPoint = %q", disc.EndPoint)
	}

	path, ok := disc.ResourceTypes[0].Protocols.StringRole("webdav")
	if !ok || path != "/webdav/ocm/" {
		t.Errorf("webdav protocol = %q, ok=%v", path, ok)
	}
}

func TestBuildDiscovery_TokenExchangeUsesProjectedEndpoint(t *testing.T) {
	disc := discovery.BuildDiscovery(discovery.BuildParams{
		EndPoint:             "https://example.com/app/ocm",
		TokenEndPoint:        "https://example.com/app/ocm/exchange",
		TokenExchangeCapable: true,
	}, nil)

	if !disc.HasCapability("exchange-token") {
		t.Error("expected exchange-token capability")
	}

	if disc.TokenEndPoint != "https://example.com/app/ocm/exchange" {
		t.Errorf("TokenEndPoint = %q", disc.TokenEndPoint)
	}
}

func TestBuildDiscovery_CriteriaUseIETFStrings(t *testing.T) {
	disc := discovery.BuildDiscovery(discovery.BuildParams{
		EndPoint:               "https://example.com/ocm",
		WebDAVRoot:             "/webdav/ocm/",
		TokenEndPoint:          "https://example.com/ocm/token",
		AdvertiseHTTPSig:       true,
		TokenExchangeCapable:   true,
		RequiresTokenExchange:  true,
		RequiresHTTPSignatures: true,
	}, nil)

	if !disc.HasCriteria(spec.CriteriaMustUseHTTPSig) {
		t.Error("expected must-use-http-sig criterion")
	}

	if !disc.HasCriteria(spec.CriteriaMustExchangeToken) {
		t.Error("expected must-exchange-token criterion")
	}
}

func TestBuildDiscovery_OmitsTokenExchangeWhenEndpointEmpty(t *testing.T) {
	disc := discovery.BuildDiscovery(discovery.BuildParams{
		EndPoint:              "https://example.com/ocm",
		WebDAVRoot:            "/webdav/ocm/",
		TokenExchangeCapable:  true,
		RequiresTokenExchange: true,
	}, nil)

	if disc.HasCapability("exchange-token") {
		t.Error("did not expect exchange-token without token endpoint")
	}

	if disc.TokenEndPoint != "" {
		t.Errorf("TokenEndPoint = %q, want empty", disc.TokenEndPoint)
	}

	if disc.HasCriteria(spec.CriteriaMustExchangeToken) {
		t.Error("did not expect must-exchange-token without token endpoint")
	}
}

func TestBuildDiscovery_InviteAcceptIndependentFromWAYF(t *testing.T) {
	disc := discovery.BuildDiscovery(discovery.BuildParams{
		EndPoint:           "https://example.com/ocm",
		WebDAVRoot:         "/webdav/ocm/",
		InviteAcceptDialog: "https://example.com/ui/accept-invite",
		WayfEnabled:        false,
	}, nil)

	if disc.InviteAcceptDialog == "" {
		t.Error("expected inviteAcceptDialog without invite-wayf")
	}

	if disc.HasCapability("invite-wayf") {
		t.Error("did not expect invite-wayf capability")
	}
}

func TestBuildDiscovery_InvitesCapabilityFromRouteFlag(t *testing.T) {
	disc := discovery.BuildDiscovery(discovery.BuildParams{
		EndPoint:       "https://example.com/ocm",
		WebDAVRoot:     "/webdav/ocm/",
		InvitesEnabled: true,
	}, nil)

	if !disc.HasCapability("invites") {
		t.Error("expected invites capability when invites route is enabled")
	}
}

func TestBuildDiscovery_InviteWAYFFromRouteFlag(t *testing.T) {
	disc := discovery.BuildDiscovery(discovery.BuildParams{
		EndPoint:    "https://example.com/ocm",
		WebDAVRoot:  "/webdav/ocm/",
		WayfEnabled: true,
	}, nil)

	if !disc.HasCapability("invite-wayf") {
		t.Error("expected invite-wayf when WAYF route is enabled")
	}
}

func TestBuildDiscovery_AdvertiseHTTPSigWithoutInlinePublicKeys(t *testing.T) {
	disc := discovery.BuildDiscovery(discovery.BuildParams{
		EndPoint:         "https://example.com/ocm",
		WebDAVRoot:       "/webdav/ocm/",
		AdvertiseHTTPSig: true,
	}, nil)

	if !disc.IsHTTPSigCapable() {
		t.Error("expected http-sig capability from AdvertiseHTTPSig")
	}

	out, err := json.Marshal(disc)
	if err != nil {
		t.Fatalf("marshal discovery: %v", err)
	}

	if strings.Contains(string(out), "publicKey") {
		t.Fatalf("expected no inline public key material in discovery JSON, got %s", out)
	}
}

func TestBuildDiscovery_APIVersion140(t *testing.T) {
	disc := discovery.BuildDiscovery(discovery.BuildParams{
		EndPoint:   "https://example.com/ocm",
		WebDAVRoot: "/webdav/ocm/",
	}, nil)
	if disc.APIVersion != "1.4.0" {
		t.Errorf("APIVersion = %q, want 1.4.0", disc.APIVersion)
	}
}

func TestBuildDiscovery_ProtocolInventory(t *testing.T) {
	disc := discovery.BuildDiscovery(discovery.BuildParams{
		EndPoint:         "https://example.com/ocm",
		WebDAVRoot:       "/webdav/ocm/",
		WebDAVReceiveURI: "relative",
	}, nil)

	protocols := disc.ResourceTypes[0].Protocols

	keys := make([]string, 0, len(protocols))
	for key := range protocols {
		keys = append(keys, key)
	}

	sort.Strings(keys)

	want := []string{"webdav", "webdav-receive"}
	if len(keys) != len(want) {
		t.Fatalf("protocol keys = %v, want %v", keys, want)
	}

	for i, key := range want {
		if keys[i] != key {
			t.Fatalf("protocol keys = %v, want %v", keys, want)
		}
	}
}

func TestBuildDiscovery_DisabledWhenRelativePathEndPoint(t *testing.T) {
	disc := discovery.BuildDiscovery(discovery.BuildParams{
		EndPoint:   "/ocm",
		WebDAVRoot: "/webdav/ocm/",
	}, nil)
	if disc.Enabled {
		t.Error("expected Enabled=false for relative path endPoint")
	}
}

func TestBuildDiscovery_DisabledWhenNoScheme(t *testing.T) {
	disc := discovery.BuildDiscovery(discovery.BuildParams{
		EndPoint:   "//example.com/ocm",
		WebDAVRoot: "/webdav/ocm/",
	}, nil)
	if disc.Enabled {
		t.Error("expected Enabled=false for endPoint without scheme")
	}
}

func TestBuildDiscovery_DisabledWhenNoHost(t *testing.T) {
	disc := discovery.BuildDiscovery(discovery.BuildParams{
		EndPoint:   "https:///ocm",
		WebDAVRoot: "/webdav/ocm/",
	}, nil)
	if disc.Enabled {
		t.Error("expected Enabled=false for endPoint without host")
	}
}

func TestBuildDiscovery_StrictDocument(t *testing.T) {
	webdavRoot := "/webdav/ocm/"
	disc := discovery.BuildDiscovery(discovery.BuildParams{
		EndPoint:               "https://example.com/ocm",
		WebDAVRoot:             webdavRoot,
		WebDAVReceiveURI:       "relative",
		TokenEndPoint:          "https://example.com/ocm/token",
		AdvertiseHTTPSig:       true,
		TokenExchangeCapable:   true,
		RequiresTokenExchange:  true,
		RequiresHTTPSignatures: true,
	}, nil)

	if disc.APIVersion != "1.4.0" {
		t.Errorf("APIVersion = %q, want 1.4.0", disc.APIVersion)
	}

	if !disc.Enabled {
		t.Fatal("expected Enabled=true")
	}

	if disc.EndPoint != "https://example.com/ocm" {
		t.Errorf("EndPoint = %q, want an absolute URL", disc.EndPoint)
	}

	endpointURL, err := url.Parse(disc.EndPoint)
	if err != nil {
		t.Fatalf("parse EndPoint: %v", err)
	}

	tokenURL, err := url.Parse(disc.TokenEndPoint)
	if err != nil {
		t.Fatalf("parse TokenEndPoint: %v", err)
	}

	if tokenURL.Scheme != endpointURL.Scheme || tokenURL.Host != endpointURL.Host {
		t.Errorf("TokenEndPoint authority = %q, want same authority as EndPoint %q", disc.TokenEndPoint, disc.EndPoint)
	}

	if !disc.HasCapability("http-sig") {
		t.Error("expected http-sig capability")
	}

	if !disc.HasCapability("exchange-token") {
		t.Error("expected exchange-token capability")
	}

	if !disc.HasCriteria(spec.CriteriaMustUseHTTPSig) {
		t.Error("expected must-use-http-sig criterion")
	}

	if !disc.HasCriteria(spec.CriteriaMustExchangeToken) {
		t.Error("expected must-exchange-token criterion")
	}

	if len(disc.ResourceTypes) != 2 {
		t.Fatalf("ResourceTypes = %+v, want file and folder", disc.ResourceTypes)
	}

	for i, wantName := range []string{"file", "folder"} {
		if disc.ResourceTypes[i].Name != wantName {
			t.Errorf("ResourceTypes[%d].Name = %q, want %q", i, disc.ResourceTypes[i].Name, wantName)
		}

		if len(disc.ResourceTypes[i].ShareTypes) != 1 || disc.ResourceTypes[i].ShareTypes[0] != "user" {
			t.Errorf("ResourceTypes[%d].ShareTypes = %v, want [user]", i, disc.ResourceTypes[i].ShareTypes)
		}
	}

	protocols := disc.ResourceTypes[0].Protocols

	keys := make([]string, 0, len(protocols))
	for k := range protocols {
		keys = append(keys, k)
	}

	sort.Strings(keys)

	wantKeys := []string{"webdav", "webdav-receive"}
	if len(keys) != len(wantKeys) {
		t.Fatalf("protocol keys = %v, want %v", keys, wantKeys)
	}

	for i, want := range wantKeys {
		if keys[i] != want {
			t.Fatalf("protocol keys = %v, want %v", keys, wantKeys)
		}
	}

	webdav, ok := protocols.StringRole("webdav")
	if !ok || webdav != webdavRoot {
		t.Fatalf("webdav = %q, ok=%v, want uri=%s", webdav, ok, webdavRoot)
	}

	wr, ok := protocols.WebDAVReceive()
	if !ok || wr.URI != spec.WebDAVReceiveURIRelative {
		t.Fatalf("webdav-receive = %+v, ok=%v, want uri=relative", wr, ok)
	}
}

func TestBuildDiscovery_MustUseHTTPSig_RequiresAdvertise(t *testing.T) {
	disc := discovery.BuildDiscovery(discovery.BuildParams{
		EndPoint:               "https://example.com/ocm",
		WebDAVRoot:             "/webdav/ocm/",
		RequiresHTTPSignatures: true,
		AdvertiseHTTPSig:       false,
	}, nil)

	if !disc.Enabled {
		t.Fatal("expected enabled discovery with absolute endpoint")
	}

	if disc.HasCriteria(spec.CriteriaMustUseHTTPSig) {
		t.Error("did not expect must-use-http-sig when AdvertiseHTTPSig is false")
	}

	if disc.HasCapability("http-sig") {
		t.Error("did not expect http-sig capability when AdvertiseHTTPSig is false")
	}
}

func TestBuildDiscovery_DisabledWhenEndPointNotAbsolute(t *testing.T) {
	disc := discovery.BuildDiscovery(discovery.BuildParams{
		EndPoint:   "/ocm",
		WebDAVRoot: "/webdav/ocm/",
	}, nil)
	if disc.Enabled {
		t.Error("expected Enabled=false for a non-absolute endPoint")
	}
}

func TestBuildDiscovery_AdvertisesJwksUriWhenHTTPSig(t *testing.T) {
	disc := discovery.BuildDiscovery(discovery.BuildParams{
		EndPoint:         "https://example.com/ocm",
		WebDAVRoot:       "/webdav/ocm/",
		AdvertiseHTTPSig: true,
	}, nil)

	if !disc.IsHTTPSigCapable() {
		t.Fatal("expected http-sig capability")
	}

	if disc.JwksUri != "https://example.com/ocm/jwks" {
		t.Errorf("JwksUri = %q, want %q", disc.JwksUri, "https://example.com/ocm/jwks")
	}

	out, err := json.Marshal(disc)
	if err != nil {
		t.Fatalf("marshal discovery: %v", err)
	}

	if !strings.Contains(string(out), `"jwksUri":"https://example.com/ocm/jwks"`) {
		t.Errorf("expected jwksUri in discovery JSON, got %s", out)
	}
}

func TestBuildDiscovery_JwksUriDerivedUnderBasePathEndPoint(t *testing.T) {
	disc := discovery.BuildDiscovery(discovery.BuildParams{
		EndPoint:         "https://example.com/myapp/ocm",
		WebDAVRoot:       "/webdav/ocm/",
		AdvertiseHTTPSig: true,
	}, nil)

	if disc.JwksUri != "https://example.com/myapp/ocm/jwks" {
		t.Errorf("JwksUri = %q, want jwks under endPoint", disc.JwksUri)
	}
}

func TestBuildDiscovery_OmitsJwksUriWithoutHTTPSig(t *testing.T) {
	disc := discovery.BuildDiscovery(discovery.BuildParams{
		EndPoint:   "https://example.com/ocm",
		WebDAVRoot: "/webdav/ocm/",
	}, nil)

	if disc.JwksUri != "" {
		t.Errorf("JwksUri = %q, want empty without http-sig capability", disc.JwksUri)
	}
}

func TestBuildDiscovery_JwksURIOverrideAdvertisedVerbatim(t *testing.T) {
	disc := discovery.BuildDiscovery(discovery.BuildParams{
		EndPoint:         "https://example.com/ocm",
		WebDAVRoot:       "/webdav/ocm/",
		AdvertiseHTTPSig: true,
		JwksURI:          "https://example.com/custom/jwks.json",
	}, nil)

	if disc.JwksUri != "https://example.com/custom/jwks.json" {
		t.Errorf("JwksUri = %q, want configured override verbatim", disc.JwksUri)
	}
}

func TestBuildDiscovery_EmptyJwksURIOverrideStillDerivesFromEndPoint(t *testing.T) {
	disc := discovery.BuildDiscovery(discovery.BuildParams{
		EndPoint:         "https://example.com/ocm",
		WebDAVRoot:       "/webdav/ocm/",
		AdvertiseHTTPSig: true,
		JwksURI:          "",
	}, nil)

	if disc.JwksUri != "https://example.com/ocm/jwks" {
		t.Errorf("JwksUri = %q, want derived from endPoint", disc.JwksUri)
	}
}

func TestBuildDiscovery_JwksURIOverrideOmittedWithoutHTTPSig(t *testing.T) {
	disc := discovery.BuildDiscovery(discovery.BuildParams{
		EndPoint:   "https://example.com/ocm",
		WebDAVRoot: "/webdav/ocm/",
		JwksURI:    "https://example.com/custom/jwks.json",
	}, nil)

	if disc.JwksUri != "" {
		t.Errorf("JwksUri = %q, want empty without http-sig capability even with override set", disc.JwksUri)
	}
}

func TestBuildDiscovery_JwksUriFollowsDevHTTPEndPoint(t *testing.T) {
	disc := discovery.BuildDiscovery(discovery.BuildParams{
		EndPoint:         "http://localhost:9200/ocm",
		WebDAVRoot:       "/webdav/ocm/",
		AdvertiseHTTPSig: true,
	}, nil)

	if disc.JwksUri != "http://localhost:9200/ocm/jwks" {
		t.Errorf("JwksUri = %q, want %q", disc.JwksUri, "http://localhost:9200/ocm/jwks")
	}
}
