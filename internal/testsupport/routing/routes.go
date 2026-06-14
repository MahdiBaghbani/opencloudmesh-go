// Package routing provides shared route-policy test helpers and ensures service
// route spec registrars are linked for aggregation tests.
package routing

import (
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"

	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/services/api"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/services/ocm"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/services/ocmaux"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/services/ui"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/services/webdav"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/services/wellknown"
)

// DefaultOpts returns baseline route opts with all service registrars linked.
func DefaultOpts() service.RouteOpts {
	return service.DefaultRouteOpts()
}

// DevOpts returns route opts for default dev config shape (WAYF off, token path).
func DevOpts() service.RouteOpts {
	return service.DefaultRouteOpts()
}

// WayfEnabledOpts returns route opts with WAYF and invite accept enabled.
func WayfEnabledOpts() service.RouteOpts {
	opts := DevOpts()
	opts.WayfEnabled = true
	opts.InviteAcceptEnabled = true
	return opts
}

// PublicSessionPaths returns full paths that should not require session auth.
func PublicSessionPaths(opts service.RouteOpts) []string {
	rows := service.DerivedRouteInventory(opts)
	var paths []string
	for _, row := range rows {
		if row.SessionPolicy == service.SessionPublic ||
			(row.SessionPolicy == service.SessionPublicWhenWAYF && opts.WayfEnabled) {
			paths = append(paths, row.FullPath)
		}
	}
	return paths
}

// ProtectedSessionPaths returns full paths that should require session auth.
func ProtectedSessionPaths(opts service.RouteOpts) []string {
	rows := service.DerivedRouteInventory(opts)
	var paths []string
	for _, row := range rows {
		if row.SessionPolicy == service.SessionProtected ||
			(row.SessionPolicy == service.SessionPublicWhenWAYF && !opts.WayfEnabled) {
			paths = append(paths, row.FullPath)
		}
	}
	return paths
}
