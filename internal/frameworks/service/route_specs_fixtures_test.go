package service_test

import (
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
)

func hasPrefix(path, prefix string) bool {
	return len(path) >= len(prefix) && path[:len(prefix)] == prefix
}

func isRootOnlyDiscoveryPath(path string) bool {
	return path == "/.well-known/ocm" ||
		path == "/.well-known/ocm/" ||
		path == "/.well-known/jwks.json"
}

func publicPathsUnderBase(opts service.RouteOpts) []string {
	rows := service.DerivedRouteInventory(opts)
	var paths []string
	for _, row := range rows {
		if row.SessionPolicy != service.SessionPublic {
			continue
		}
		if !row.MountAtRoot && !hasPrefix(row.FullPath, "/ocm/") {
			continue
		}
		paths = append(paths, row.FullPath)
	}
	return paths
}
