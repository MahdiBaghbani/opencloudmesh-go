// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package architecture

import (
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/modroot"
)

func TestNoProductionServiceLoaderImports(t *testing.T) {
	t.Parallel()
	root := modroot.ModuleRoot(t)
	productionRoots := []string{"cmd", "internal", "tests/integration/harness"}

	violations := findProductionImportSuffix(t, root, productionRoots, "/services/loader")
	if len(violations) > 0 {
		t.Fatalf("services/loader blank imports must not appear in production code; violations: %s",
			strings.Join(violations, ", "))
	}
}

func TestNoProductionInterceptorLoaderImports(t *testing.T) {
	t.Parallel()
	root := modroot.ModuleRoot(t)
	productionRoots := []string{"cmd", "internal", "tests/integration/harness"}

	violations := findProductionImportSuffix(t, root, productionRoots, "/interceptors/loader")
	if len(violations) > 0 {
		t.Fatalf("interceptors/loader blank imports must not appear in production code; violations: %s",
			strings.Join(violations, ", "))
	}
}
