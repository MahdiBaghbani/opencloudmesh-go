// Package routing provides shared route-policy test helpers and ensures service
// route spec registrars are linked for aggregation tests.
package routing

import (
	"strings"

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

// WayfEnabledOpts returns route opts with WAYF enabled.
func WayfEnabledOpts() service.RouteOpts {
	opts := DevOpts()
	opts.WayfEnabled = true

	return opts
}

// InviteAcceptEnabledOpts returns route opts with invite accept UI enabled.
func InviteAcceptEnabledOpts() service.RouteOpts {
	opts := DevOpts()
	opts.InviteAcceptEnabled = true

	return opts
}

// ProductRoutes returns non-synthetic rows from Routes(opts).
func ProductRoutes(opts service.RouteOpts) []service.RouteRow {
	rows := service.Routes(opts)

	out := make([]service.RouteRow, 0, len(rows))
	for _, row := range rows {
		if row.Synthetic {
			continue
		}

		out = append(out, row)
	}

	return out
}

// SyntheticRoutes returns synthetic subtree rows from Routes(opts).
func SyntheticRoutes(opts service.RouteOpts) []service.RouteRow {
	rows := service.Routes(opts)

	out := make([]service.RouteRow, 0, len(rows))
	for _, row := range rows {
		if !row.Synthetic {
			continue
		}

		out = append(out, row)
	}

	return out
}

// RoutesBySurface returns product routes with the given surface class.
func RoutesBySurface(opts service.RouteOpts, surface service.SurfaceClass) []service.RouteRow {
	rows := ProductRoutes(opts)

	out := make([]service.RouteRow, 0, len(rows))
	for _, row := range rows {
		if row.SurfaceClass == surface {
			out = append(out, row)
		}
	}

	return out
}

// ProtocolRoutes returns product routes on the OCM protocol surface.
func ProtocolRoutes(opts service.RouteOpts) []service.RouteRow {
	return RoutesBySurface(opts, service.SurfaceProtocol)
}

// KnownOutboundKinds lists outbound protocol kinds used on API route specs.
func KnownOutboundKinds() []service.OutboundProtocolKind {
	return []service.OutboundProtocolKind{
		service.OutboundShares,
		service.OutboundInvites,
		service.OutboundAccess,
	}
}

// IsKnownOutboundKind reports whether kind is a declared outbound protocol kind.
func IsKnownOutboundKind(kind service.OutboundProtocolKind) bool {
	if kind == service.OutboundNone {
		return false
	}

	for _, known := range KnownOutboundKinds() {
		if kind == known {
			return true
		}
	}

	return false
}

// HasDiscoveryField reports whether row discovery metadata includes field.
func HasDiscoveryField(row service.RouteRow, field string) bool {
	for _, f := range row.DiscoveryFields {
		if f == field {
			return true
		}
	}

	return false
}

// IsOCMProtocolPath reports whether fullPath is under the mounted OCM protocol prefix.
func IsOCMProtocolPath(fullPath string, opts service.RouteOpts) bool {
	prefix := "/ocm"
	if opts.ExternalBasePath != "" {
		prefix = strings.TrimSuffix(opts.ExternalBasePath, "/") + "/ocm"
	}

	return fullPath == prefix || strings.HasPrefix(fullPath, prefix+"/")
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
