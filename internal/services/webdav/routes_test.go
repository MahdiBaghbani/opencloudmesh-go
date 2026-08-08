// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package webdav

import (
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
)

func TestRegisteredRouteSpecs(t *testing.T) {
	t.Parallel()

	specs := registeredRouteSpecs(service.DefaultRouteOpts())
	if len(specs) != 1 {
		t.Fatalf("expected 1 webdav route spec, got %d", len(specs))
	}

	spec := specs[0]
	if spec.Pattern != RouteOCMWildcard {
		t.Errorf("pattern = %q, want %q", spec.Pattern, RouteOCMWildcard)
	}

	if spec.HandlerAuth != service.HandlerAuthBearer {
		t.Errorf("handler auth = %q, want bearer", spec.HandlerAuth)
	}

	if spec.SurfaceClass != service.SurfaceWebDAV {
		t.Errorf("surface = %q, want webdav", spec.SurfaceClass)
	}
}
