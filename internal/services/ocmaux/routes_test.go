// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package ocmaux

import (
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
)

func TestRegisteredRouteSpecs(t *testing.T) {
	specs := registeredRouteSpecs(service.DefaultRouteOpts())
	if len(specs) != 2 {
		t.Fatalf("expected 2 route specs, got %d", len(specs))
	}

	for _, spec := range specs {
		if spec.SurfaceClass != service.SurfaceHelper {
			t.Errorf("spec %q surface = %q, want helper", spec.ID, spec.SurfaceClass)
		}

		if spec.SessionPolicy != service.SessionPublic {
			t.Errorf("spec %q session = %q, want public", spec.ID, spec.SessionPolicy)
		}
	}
}
