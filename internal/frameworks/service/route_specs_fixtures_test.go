// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package service_test

import (
	"strings"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
)

func isRootOnlyDiscoveryPath(path string) bool {
	return path == "/.well-known/ocm" ||
		path == "/.well-known/ocm/"
}

func publicPathsUnderBase(opts service.RouteOpts) []string {
	rows := service.DerivedRouteInventory(opts)

	var paths []string

	for _, row := range rows {
		if row.SessionPolicy != service.SessionPublic {
			continue
		}

		if !row.MountAtRoot && !strings.HasPrefix(row.FullPath, "/ocm/") {
			continue
		}

		paths = append(paths, row.FullPath)
	}

	return paths
}
