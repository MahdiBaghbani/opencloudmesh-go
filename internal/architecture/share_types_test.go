package architecture

import (
	"slices"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery"
)

func TestDiscoveryShareTypes_AdvertiseUserNotFederation(t *testing.T) {
	// "federation" is an OCM-MLS share type, not core OCM
	// (https://github.com/cs3org/OCM-API/blob/a5b5da6/IETF-OCM.md#L1803-L1805); ocmgo must never advertise it.
	disc := discovery.BuildDiscovery(discovery.BuildParams{
		EndPoint: "https://example.org/ocm",
	}, nil)

	if !disc.Enabled {
		t.Fatal("expected enabled discovery for absolute endPoint")
	}
	if len(disc.ResourceTypes) == 0 {
		t.Fatal("expected at least one resource type")
	}

	for _, rt := range disc.ResourceTypes {
		if !slices.Contains(rt.ShareTypes, "user") {
			t.Errorf("resource type %q ShareTypes = %v, want to contain \"user\"", rt.Name, rt.ShareTypes)
		}
		if slices.Contains(rt.ShareTypes, "federation") {
			t.Errorf("resource type %q ShareTypes = %v, must not contain \"federation\"", rt.Name, rt.ShareTypes)
		}
	}
}
