// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package wellknown

import (
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery/resolve"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/policy"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
	tslocalid "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/localidentity"
)

func handlerResolveInputs(t *testing.T, basePath string) resolve.ResolveInputs {
	t.Helper()

	opts := service.RouteOpts{ExternalBasePath: basePath}
	if basePath == "" {
		opts = service.DefaultRouteOpts()
	}

	return resolve.ResolveInputs{
		LocalIdentity: tslocalid.MustTestIdentity(t, "https://example.com", basePath),
		RouteOpts:     opts,
		CodeFlow:      policy.NewCodeFlow(),
	}
}
