// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package wellknown

import (
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
)

func TestRegisteredRouteSpecs(t *testing.T) {
	opts := service.DefaultRouteOpts()

	specs := registeredRouteSpecs(opts)
	if len(specs) != 2 {
		t.Fatalf("expected 2 route specs, got %d", len(specs))
	}

	for _, spec := range specs {
		if spec.Service != "wellknown" {
			t.Errorf("spec %q has service %q, want wellknown", spec.ID, spec.Service)
		}

		if spec.SurfaceClass != service.SurfaceDiscovery {
			t.Errorf("spec %q surface = %q, want discovery", spec.ID, spec.SurfaceClass)
		}

		if len(spec.DiscoveryFields) == 0 {
			t.Errorf("spec %q missing discovery fields", spec.ID)
		}
	}
}

func TestRouteConstants_MatchChiRegistration(t *testing.T) {
	paths := []string{
		RouteWellKnownOCM,
		RouteWellKnownOCMSlash,
	}

	specs := registeredRouteSpecs(service.DefaultRouteOpts())
	if len(paths) != len(specs) {
		t.Fatalf("constant count = %d, spec count = %d", len(paths), len(specs))
	}

	for i, path := range paths {
		if specs[i].Pattern != path {
			t.Errorf("spec pattern = %q, want constant %q", specs[i].Pattern, path)
		}
	}
}
