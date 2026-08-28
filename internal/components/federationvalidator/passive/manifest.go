// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package passive

import (
	"net/http"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/federationvalidator/catalog"
)

const (
	manifestSchema         = catalog.ManifestSchema
	scanSchema             = catalog.ScanSchema
	startSchema            = catalog.StartSchema
	sessionSchema          = catalog.SessionSchema
	manifestAPIVersion     = catalog.APIVersion
	manifestServicePrefix  = catalog.ServicePrefix
	schemaFieldTypeString  = "string"
	schemaFieldTypeBoolean = "boolean"
	optInQueryContribute   = "contribute"
	optInQueryPermanent    = "permanent"
	optInLiteralValue      = "1"
)

// MountedAPIRoute describes one advertised client-usable validator route.
type MountedAPIRoute = catalog.AdvertisedRoute

type manifestRouteResponse = catalog.Manifest
type scanQueryParam = catalog.ScanQueryParam
type manifestAvailabilityMeta = catalog.AvailabilityMeta
type manifestSessionKindMeta = catalog.SessionKindMeta

// MountedAPIRoutesFor returns advertised routes for caps.
func MountedAPIRoutesFor(caps catalog.Caps) []MountedAPIRoute {
	return catalog.AdvertisedRoutes("", caps)
}

// BuildManifest returns the full-capability federation_tester_manifest.v1 payload.
func BuildManifest() manifestRouteResponse {
	return catalog.BuildManifest("", catalog.FullCaps())
}

func buildManifest(externalBasePath string) manifestRouteResponse {
	return catalog.BuildManifest(externalBasePath, catalog.FullCaps())
}

func buildManifestFor(externalBasePath string, caps catalog.Caps) manifestRouteResponse {
	return catalog.BuildManifest(externalBasePath, caps)
}

// HandleManifest serves GET /api/manifest for anonymous manifest reads.
func (h *Handler) HandleManifest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)

		return
	}

	writeJSON(w, h.log, http.StatusOK, buildManifestFor(h.externalBasePath, h.Caps()))
}
