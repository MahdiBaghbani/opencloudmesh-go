// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package architecture

import (
	"slices"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery"
)

func TestDiscoveryShareTypes_AdvertiseUserNotFederation(t *testing.T) {
	t.Parallel()

	// "federation" is an OCM-MLS share type, not core OCM
	// (https://github.com/cs3org/OCM-API/blob/6a0586183cbef10ecae9dedc42561806447eb2f5/IETF-OCM.md#L1874-L1876); ocmgo must never advertise it.

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
