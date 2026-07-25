package service_test

import (
	"strings"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
)

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
		if !row.MountAtRoot && !strings.HasPrefix(row.FullPath, "/ocm/") {
			continue
		}
		paths = append(paths, row.FullPath)
	}
	return paths
}
