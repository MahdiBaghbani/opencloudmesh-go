// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package service

// RouteSpecRegistrar returns service-owned route specs for the given opts.
type RouteSpecRegistrar func(opts RouteOpts) []RouteSpec

var routeSpecRegistrars []RouteSpecRegistrar

// RegisterRouteSpecs registers a service-owned route spec provider. Services
// call this from init() to avoid import cycles with the framework package.
func RegisterRouteSpecs(registrar RouteSpecRegistrar) {
	routeSpecRegistrars = append(routeSpecRegistrars, registrar)
}
