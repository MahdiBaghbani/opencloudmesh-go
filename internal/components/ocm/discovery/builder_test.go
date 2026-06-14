package discovery_test

import (
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
	if disc.ResourceTypes[0].Protocols["webdav"] != "/webdav/ocm/" {
		t.Errorf("webdav protocol = %q", disc.ResourceTypes[0].Protocols["webdav"])
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

func TestBuildDiscovery_InviteAcceptIndependentFromWAYF(t *testing.T) {
	disc := discovery.BuildDiscovery(discovery.BuildParams{
		EndPoint:           "https://example.com/ocm",
		WebDAVRoot:         "/webdav/ocm/",
		InviteAcceptDialog: "https://example.com/ui/accept-invite",
		AdvertiseInviteWAYF: false,
	}, nil)

	if disc.InviteAcceptDialog == "" {
		t.Error("expected inviteAcceptDialog without invite-wayf")
	}
	if disc.HasCapability("invite-wayf") {
		t.Error("did not expect invite-wayf capability")
	}
}

func TestBuildDiscovery_InviteWAYFFromAdvertiseFlag(t *testing.T) {
	disc := discovery.BuildDiscovery(discovery.BuildParams{
		EndPoint:            "https://example.com/ocm",
		WebDAVRoot:          "/webdav/ocm/",
		AdvertiseInviteWAYF: true,
	}, nil)

	if !disc.HasCapability("invite-wayf") {
		t.Error("expected invite-wayf from advertise flag")
	}
}
