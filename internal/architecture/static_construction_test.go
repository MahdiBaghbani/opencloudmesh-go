// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package architecture

import (
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/callscan"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/modroot"
)

func TestNoProductionDynamicServiceConstruction(t *testing.T) {
	root := modroot.ModuleRoot(t)
	productionRoots := []string{"cmd", "internal", "tests/integration/harness"}

	violations := callscan.FindProductionCallSites(t, root, productionRoots, "", callscan.ProductionCallSpec{
		ImportSuffix: "/service",
		FuncName:     "Get",
	}, true)
	if len(violations) > 0 {
		t.Fatalf("service.Get must not appear in production code; violations: %s",
			strings.Join(violations, ", "))
	}
}

func TestNoProductionDynamicInterceptorConstruction(t *testing.T) {
	root := modroot.ModuleRoot(t)
	productionRoots := []string{"cmd", "internal", "tests/integration/harness"}

	violations := callscan.FindProductionCallSites(t, root, productionRoots, "", callscan.ProductionCallSpec{
		ImportSuffix: "/interceptors",
		FuncName:     "Get",
	}, true)
	if len(violations) > 0 {
		t.Fatalf("interceptors.Get must not appear in production code; violations: %s",
			strings.Join(violations, ", "))
	}
}
