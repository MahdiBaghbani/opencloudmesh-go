// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package discovery_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
)

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

func TestBuildDiscovery_AdvertisesDenylistWhenConfigured(t *testing.T) {
	disc := discovery.BuildDiscovery(discovery.BuildParams{
		EndPoint:          "https://example.com/ocm",
		WebDAVRoot:        "/webdav/ocm/",
		AdvertiseDenylist: true,
	}, nil)

	if !disc.HasCriteria(spec.CriteriaDenylist) {
		t.Error("expected denylist criterion when AdvertiseDenylist is true")
	}
}

func TestBuildDiscovery_OmitsDenylistWhenNotConfigured(t *testing.T) {
	disc := discovery.BuildDiscovery(discovery.BuildParams{
		EndPoint:   "https://example.com/ocm",
		WebDAVRoot: "/webdav/ocm/",
	}, nil)

	if disc.HasCriteria(spec.CriteriaDenylist) {
		t.Error("did not expect denylist criterion when AdvertiseDenylist is false")
	}
}

func TestBuildDiscovery_AdvertisesAllowlistWhenConfigured(t *testing.T) {
	disc := discovery.BuildDiscovery(discovery.BuildParams{
		EndPoint:           "https://example.com/ocm",
		WebDAVRoot:         "/webdav/ocm/",
		AdvertiseAllowlist: true,
	}, nil)

	if !disc.HasCriteria(spec.CriteriaAllowlist) {
		t.Error("expected allowlist criterion when AdvertiseAllowlist is true")
	}
}

func TestBuildDiscovery_OmitsAllowlistWhenNotConfigured(t *testing.T) {
	disc := discovery.BuildDiscovery(discovery.BuildParams{
		EndPoint:   "https://example.com/ocm",
		WebDAVRoot: "/webdav/ocm/",
	}, nil)

	if disc.HasCriteria(spec.CriteriaAllowlist) {
		t.Error("did not expect allowlist criterion when AdvertiseAllowlist is false")
	}
}

func TestBuildDiscovery_EmitsOnlySpecDefinedCriteria(t *testing.T) {
	known := make(map[string]struct{}, len(spec.KnownCriteria()))
	for _, c := range spec.KnownCriteria() {
		known[c] = struct{}{}
	}

	disc := discovery.BuildDiscovery(discovery.BuildParams{
		EndPoint:               "https://example.com/ocm",
		WebDAVRoot:             "/webdav/ocm/",
		TokenEndPoint:          "https://example.com/ocm/token",
		AdvertiseHTTPSig:       true,
		TokenExchangeCapable:   true,
		RequiresTokenExchange:  true,
		RequiresHTTPSignatures: true,
		AdvertiseDenylist:      true,
		AdvertiseAllowlist:     true,
	}, nil)

	for _, criterion := range disc.Criteria {
		if _, ok := known[criterion]; !ok {
			t.Errorf("criterion %q is not a spec-defined value", criterion)
		}
	}

	if disc.HasCriteria(spec.CriteriaMustInvite) {
		t.Error("must-invite must not be emitted until enforcement is implemented")
	}
}
