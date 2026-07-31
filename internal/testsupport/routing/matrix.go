// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package routing

import (
	"net/http"
	"strings"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
)

// MatrixVariant is one route-policy variant derived from mount metadata knobs.
type MatrixVariant struct {
	Name string
	Opts service.RouteOpts
}

// MatrixVariants returns the route-policy variants required by the G6.2 path
// matrix: empty and non-empty external_base_path, default and custom token
// paths, and WAYF on/off feature shapes.
func MatrixVariants() []MatrixVariant {
	return []MatrixVariant{
		{Name: "root-default", Opts: DefaultOpts()},
		{Name: "base-path", Opts: service.RouteOpts{
			ExternalBasePath:    "/ocm",
			TokenExchangePath:   "token",
			WayfEnabled:         false,
			InviteAcceptEnabled: false,
			InvitesEnabled:      true,
		}},
		{Name: "base-path-custom-token", Opts: service.RouteOpts{
			ExternalBasePath:    "/ocm",
			TokenExchangePath:   "auth/exchange",
			WayfEnabled:         false,
			InviteAcceptEnabled: false,
			InvitesEnabled:      true,
		}},
		{Name: "base-path-nested-token", Opts: service.RouteOpts{
			ExternalBasePath:    "/ocm",
			TokenExchangePath:   "token/v2",
			WayfEnabled:         false,
			InviteAcceptEnabled: false,
			InvitesEnabled:      true,
		}},
		{Name: "root-custom-token", Opts: service.RouteOpts{
			TokenExchangePath:   "auth/exchange",
			WayfEnabled:         false,
			InviteAcceptEnabled: false,
			InvitesEnabled:      true,
		}},
		{Name: "root-nested-token", Opts: service.RouteOpts{
			TokenExchangePath:   "token/v2",
			WayfEnabled:         false,
			InviteAcceptEnabled: false,
			InvitesEnabled:      true,
		}},
		{Name: "root-wayf-enabled", Opts: WayfEnabledOpts()},
		{Name: "base-path-wayf-enabled", Opts: service.RouteOpts{
			ExternalBasePath:    "/ocm",
			WayfEnabled:         true,
			InviteAcceptEnabled: false,
			InvitesEnabled:      true,
			TokenExchangePath:   "token",
		}},
	}
}

// InventoryRows returns active product rows from Routes(opts).
func InventoryRows(opts service.RouteOpts) []service.RouteRow {
	return service.DerivedRouteInventory(opts)
}

// ProbePathFromRow expands a route row FullPath into a concrete request path.
func ProbePathFromRow(row service.RouteRow) string {
	path := row.FullPath
	if strings.HasSuffix(path, "/*") {
		return strings.TrimSuffix(path, "/*") + "/matrix-probe"
	}

	if idx := strings.Index(path, "{"); idx >= 0 {
		end := strings.Index(path[idx:], "}")
		if end < 0 {
			return path
		}

		return path[:idx] + "matrix-probe" + path[idx+end+1:]
	}

	return path
}

// ProbeMethodFromRow returns the HTTP method used to probe route mounting.
func ProbeMethodFromRow(row service.RouteRow) string {
	switch row.Method {
	case http.MethodPost:
		return "POST"
	case http.MethodGet:
		return "GET"
	default:
		return "GET"
	}
}

// HostRootDiscoveryPaths returns well-known discovery paths that must stay at
// the host root regardless of external_base_path.
func HostRootDiscoveryPaths() []string {
	return []string{
		"/.well-known/ocm",
	}
}

// RowByID returns the active inventory row with the given stable ID.
func RowByID(opts service.RouteOpts, id string) (service.RouteRow, bool) {
	for _, row := range InventoryRows(opts) {
		if row.ID == id {
			return row, true
		}
	}

	return service.RouteRow{}, false
}

// OCMTokenRow returns the OCM token exchange endpoint row from Routes(opts).
func OCMTokenRow(opts service.RouteOpts) (service.RouteRow, bool) {
	return RowByID(opts, service.RouteIDOCMToken)
}

// OCMTokenFullPath returns the aggregate full path for the OCM token endpoint row.
func OCMTokenFullPath(opts service.RouteOpts) (string, bool) {
	row, ok := OCMTokenRow(opts)
	if !ok {
		return "", false
	}

	return row.FullPath, true
}

// HealthFullPath returns the aggregate full path for the api-healthz row.
func HealthFullPath(opts service.RouteOpts) (string, bool) {
	row, ok := RowByID(opts, service.RouteIDAPIHealthz)
	if !ok {
		return "", false
	}

	return row.FullPath, true
}
