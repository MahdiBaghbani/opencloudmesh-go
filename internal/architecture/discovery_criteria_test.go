package architecture

import (
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
)

func TestDiscoveryCriteria_OnlySpecDefinedValues(t *testing.T) {
	known := make(map[string]struct{}, len(spec.KnownCriteria()))
	for _, c := range spec.KnownCriteria() {
		known[c] = struct{}{}
	}

	disc := discovery.BuildDiscovery(discovery.BuildParams{
		EndPoint:               "https://example.org/ocm",
		WebDAVRoot:             "/webdav/ocm/",
		TokenEndPoint:          "https://example.org/ocm/token",
		AdvertiseHTTPSig:       true,
		TokenExchangeCapable:   true,
		RequiresTokenExchange:  true,
		RequiresHTTPSignatures: true,
		AdvertiseDenylist:      true,
		AdvertiseAllowlist:     true,
	}, nil)

	for _, criterion := range disc.Criteria {
		if _, ok := known[criterion]; !ok {
			t.Errorf("criterion %q is not one of the five spec-defined values", criterion)
		}
	}

	if disc.HasCriteria(spec.CriteriaMustInvite) {
		t.Error("must-invite must not appear in discovery criteria (enforcement not yet implemented)")
	}
}
