// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package passive

import (
	"net/http"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

const (
	manifestSchema        = "federation_tester_manifest.v1"
	scanSchema            = "federation_tester_scan.v1"
	manifestAPIVersion    = "1.3.0"
	manifestServicePrefix = "validator"
	schemaFieldTypeString = "string"
)

// MountedAPIRoute describes one plane-A client-usable route wired in
// MountPlaneARoutes. Session and report polling routes are registered
// but not mounted in v1.3.0 and are intentionally omitted here.
type MountedAPIRoute struct {
	Method   string `json:"method"`
	FullPath string `json:"full_path"` //nolint:tagliatelle // federation_tester_manifest.v1 locked schema
}

// manifestRouteResponse is the locked federation_tester_manifest.v1 payload.
// Add fields only; do not rename or remove existing JSON keys.
type manifestRouteResponse struct {
	Schema        string                   `json:"schema"`
	APIVersion    string                   `json:"api_version"` //nolint:tagliatelle // federation_tester_manifest.v1 locked schema
	Schemas       []string                 `json:"schemas"`
	ServicePrefix string                   `json:"service_prefix"` //nolint:tagliatelle // federation_tester_manifest.v1 locked schema
	Routes        []MountedAPIRoute        `json:"routes"`
	Statistics    manifestStatisticsMeta   `json:"statistics"`
	Scan          scanSchemaV1             `json:"scan"`
	SessionKind   manifestSessionKindMeta  `json:"session_kind"` //nolint:tagliatelle // federation_tester_manifest.v1 locked schema
	Contribute    manifestContributeMeta   `json:"contribute"`
	ReverseInvite manifestAvailabilityMeta `json:"reverse_invite"` //nolint:tagliatelle // federation_tester_manifest.v1 locked schema
	Platform      manifestAvailabilityMeta `json:"platform"`
	TLSSummary    manifestAvailabilityMeta `json:"tls_summary"` //nolint:tagliatelle // federation_tester_manifest.v1 locked schema
}

type manifestStatisticsMeta struct {
	Schema                string `json:"schema"`
	TimeframesDays        []int  `json:"timeframes_days"`          //nolint:tagliatelle // federation_tester_manifest.v1 locked schema
	DefaultDays           int    `json:"default_days"`             //nolint:tagliatelle // federation_tester_manifest.v1 locked schema
	KAnonymityUniqueHosts int    `json:"k_anonymity_unique_hosts"` //nolint:tagliatelle // federation_tester_manifest.v1 locked schema
	UnknownPlatformExempt bool   `json:"unknown_platform_exempt"`  //nolint:tagliatelle // federation_tester_manifest.v1 locked schema
}

type manifestSessionKindMeta struct {
	Supported   []string `json:"supported"`
	ScanDefault string   `json:"scan_default"` //nolint:tagliatelle // federation_tester_manifest.v1 locked schema
}

type manifestContributeMeta struct {
	Available  bool   `json:"available"`
	OptInQuery string `json:"opt_in_query"` //nolint:tagliatelle // federation_tester_manifest.v1 locked schema
	OptInValue string `json:"opt_in_value"` //nolint:tagliatelle // federation_tester_manifest.v1 locked schema
}

type manifestAvailabilityMeta struct {
	Available bool `json:"available"`
}

// scanSchemaV1 is the locked federation_tester_scan.v1 description embedded in
// the manifest. It mirrors the live GET /api/scan handler only.
type scanSchemaV1 struct {
	Schema   string             `json:"schema"`
	Request  scanRequestSchema  `json:"request"`
	Response scanResponseSchema `json:"response"`
}

type scanRequestSchema struct {
	Method string                    `json:"method"`
	Query  map[string]scanQueryParam `json:"query"`
}

type scanQueryParam struct {
	Required    bool   `json:"required"`
	Type        string `json:"type"`
	Description string `json:"description,omitempty"`
	OptInValue  string `json:"opt_in_value,omitempty"` //nolint:tagliatelle // federation_tester_scan.v1 locked schema
}

type scanResponseSchema struct {
	SuccessStatus int              `json:"success_status"` //nolint:tagliatelle // federation_tester_scan.v1 locked schema
	Body          scanResponseBody `json:"body"`
}

type scanResponseBody struct {
	ID scanFieldSchema `json:"id"`
}

type scanFieldSchema struct {
	Type        string `json:"type"`
	Description string `json:"description,omitempty"`
}

// MountedAPIRoutes returns plane-A routes actually mounted for client use in
// v1.3.0. Keep this in sync with MountPlaneARoutes.
func MountedAPIRoutes() []MountedAPIRoute {
	prefix := "/" + manifestServicePrefix

	return []MountedAPIRoute{
		{Method: http.MethodPost, FullPath: prefix + RouteStartCreateSession},
		{Method: http.MethodPost, FullPath: prefix + RouteStopSession},
		{Method: http.MethodGet, FullPath: prefix + RouteAPIScan},
		{Method: http.MethodGet, FullPath: prefix + RouteAPIManifest},
		{Method: http.MethodGet, FullPath: prefix + RouteAPIStatistics},
	}
}

// BuildManifest returns the authoritative federation_tester_manifest.v1 payload.
func BuildManifest() manifestRouteResponse {
	return manifestRouteResponse{
		Schema:        manifestSchema,
		APIVersion:    manifestAPIVersion,
		ServicePrefix: manifestServicePrefix,
		Schemas: []string{
			manifestSchema,
			scanSchema,
			statisticsSchema,
		},
		Routes: MountedAPIRoutes(),
		Statistics: manifestStatisticsMeta{
			Schema:                statisticsSchema,
			TimeframesDays:        append([]int(nil), statisticsSupportedDays...),
			DefaultDays:           statisticsDefaultDays,
			KAnonymityUniqueHosts: statisticsKAnonymityUniqueHosts,
			UnknownPlatformExempt: true,
		},
		Scan: buildScanSchemaV1(),
		SessionKind: manifestSessionKindMeta{
			Supported: []string{
				validatorcore.SessionKindPassiveOnly,
				validatorcore.SessionKindActiveFull,
			},
			ScanDefault: validatorcore.SessionKindPassiveOnly,
		},
		Contribute: manifestContributeMeta{
			Available:  true,
			OptInQuery: "contribute",
			OptInValue: "1",
		},
		ReverseInvite: manifestAvailabilityMeta{Available: false},
		Platform:      manifestAvailabilityMeta{Available: true},
		TLSSummary:    manifestAvailabilityMeta{Available: true},
	}
}

func buildScanSchemaV1() scanSchemaV1 {
	return scanSchemaV1{
		Schema: scanSchema,
		Request: scanRequestSchema{
			Method: http.MethodGet,
			Query: map[string]scanQueryParam{
				"target": {
					Required:    true,
					Type:        schemaFieldTypeString,
					Description: "absolute URL with http or https scheme and host",
				},
				"contribute": {
					Required:    false,
					Type:        schemaFieldTypeString,
					Description: "statistics contribute opt-in; only literal 1 opts in",
					OptInValue:  "1",
				},
			},
		},
		Response: scanResponseSchema{
			SuccessStatus: http.StatusCreated,
			Body: scanResponseBody{
				ID: scanFieldSchema{
					Type:        schemaFieldTypeString,
					Description: "passive session id",
				},
			},
		},
	}
}

// HandleManifest serves GET /api/manifest for anonymous manifest reads.
func (h *Handler) HandleManifest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)

		return
	}

	writeJSON(w, h.log, http.StatusOK, BuildManifest())
}
