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
	manifestSchema         = "federation_tester_manifest.v1"
	scanSchema             = "federation_tester_scan.v1"
	manifestAPIVersion     = "1.3.0"
	manifestServicePrefix  = "validator"
	schemaFieldTypeString  = "string"
	schemaFieldTypeBoolean = "boolean"
	optInQueryContribute   = "contribute"
	optInQueryPermanent    = "permanent"
	optInLiteralValue      = "1"
)

// MountedAPIRoute describes one plane-A client-usable route wired in
// MountPlaneARoutes. HTML report pages sit beside plane-A and are omitted.
type MountedAPIRoute struct {
	Method   string `json:"method"`
	FullPath string `json:"fullPath"`
}

// manifestRouteResponse is the federation_tester_manifest.v1 payload.
// Additive fields only; keys are camelCase per .golangci.yml json: camel.
type manifestRouteResponse struct {
	Schema        string                   `json:"schema"`
	APIVersion    string                   `json:"apiVersion"`
	Schemas       []string                 `json:"schemas"`
	ServicePrefix string                   `json:"servicePrefix"`
	Routes        []MountedAPIRoute        `json:"routes"`
	Statistics    manifestStatisticsMeta   `json:"statistics"`
	Scan          scanSchemaV1             `json:"scan"`
	SessionKind   manifestSessionKindMeta  `json:"sessionKind"`
	Contribute    manifestContributeMeta   `json:"contribute"`
	Permanent     manifestContributeMeta   `json:"permanent"`
	OptIn         manifestOptInMeta        `json:"optIn"`
	Report        manifestReportMeta       `json:"report"`
	Retention     manifestRetentionMeta    `json:"retention"`
	ReverseInvite manifestAvailabilityMeta `json:"reverseInvite"`
	Platform      manifestAvailabilityMeta `json:"platform"`
	TLSSummary    manifestAvailabilityMeta `json:"tlsSummary"`
}

type manifestStatisticsMeta struct {
	Schema                string `json:"schema"`
	TimeframesDays        []int  `json:"timeframesDays"`
	DefaultDays           int    `json:"defaultDays"`
	KAnonymityUniqueHosts int    `json:"kAnonymityUniqueHosts"`
	UnknownPlatformExempt bool   `json:"unknownPlatformExempt"`
}

type manifestSessionKindMeta struct {
	Supported   []string `json:"supported"`
	ScanDefault string   `json:"scanDefault"`
}

type manifestContributeMeta struct {
	Available  bool   `json:"available"`
	OptInQuery string `json:"optInQuery"`
	OptInValue string `json:"optInValue"`
}

type manifestOptInMeta struct {
	Default string                 `json:"default"`
	Start   manifestOptInStartMeta `json:"start"`
	Scan    manifestOptInScanMeta  `json:"scan"`
}

type manifestOptInStartMeta struct {
	OptInStats     manifestOptInStartField `json:"optInStats"`
	OptInPermanent manifestOptInStartField `json:"optInPermanent"`
}

type manifestOptInStartField struct {
	Type    string `json:"type"`
	Default bool   `json:"default"`
}

type manifestOptInScanMeta struct {
	StatsQuery     string `json:"statsQuery"`
	PermanentQuery string `json:"permanentQuery"`
	OptInValue     string `json:"optInValue"`
}

type manifestAvailabilityMeta struct {
	Available bool `json:"available"`
}

// scanSchemaV1 is the federation_tester_scan.v1 description embedded in the
// manifest. It mirrors the live GET /api/scan handler only.
// Additive fields only; keys are camelCase per .golangci.yml json: camel.
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
	OptInValue  string `json:"optInValue,omitempty"`
}

type scanResponseSchema struct {
	SuccessStatus int              `json:"successStatus"`
	Body          scanResponseBody `json:"body"`
}

type scanResponseBody struct {
	ID             scanFieldSchema `json:"id"`
	OptInStats     scanFieldSchema `json:"optInStats"`
	OptInPermanent scanFieldSchema `json:"optInPermanent"`
}

type scanFieldSchema struct {
	Type        string `json:"type"`
	Description string `json:"description,omitempty"`
}

// MountedAPIRoutes returns plane-A routes actually mounted for client use in
// v1.3.0. Keep this in sync with MountPlaneARoutes.
func MountedAPIRoutes() []MountedAPIRoute {
	return mountedAPIRoutes("")
}

func mountedAPIRoutes(externalBasePath string) []MountedAPIRoute {
	return []MountedAPIRoute{
		{
			Method:   http.MethodPost,
			FullPath: joinReportPath(externalBasePath, manifestServicePrefix, RouteStartCreateSession),
		},
		{
			Method:   http.MethodPost,
			FullPath: joinReportPath(externalBasePath, manifestServicePrefix, RouteStopSession),
		},
		{
			Method:   http.MethodGet,
			FullPath: joinReportPath(externalBasePath, manifestServicePrefix, RouteAPIScan),
		},
		{
			Method:   http.MethodGet,
			FullPath: joinReportPath(externalBasePath, manifestServicePrefix, RouteAPISession),
		},
		{
			Method:   http.MethodGet,
			FullPath: joinReportPath(externalBasePath, manifestServicePrefix, RouteAPIReport),
		},
		{
			Method:   http.MethodPatch,
			FullPath: joinReportPath(externalBasePath, manifestServicePrefix, RouteAPIReportRetention),
		},
		{
			Method:   http.MethodPost,
			FullPath: joinReportPath(externalBasePath, manifestServicePrefix, RouteAPIReportLock),
		},
		{
			Method:   http.MethodGet,
			FullPath: joinReportPath(externalBasePath, manifestServicePrefix, RouteAPIManifest),
		},
		{
			Method:   http.MethodGet,
			FullPath: joinReportPath(externalBasePath, manifestServicePrefix, RouteAPIStatistics),
		},
	}
}

// BuildManifest returns the authoritative federation_tester_manifest.v1 payload.
func BuildManifest() manifestRouteResponse {
	return buildManifest("")
}

func buildManifest(externalBasePath string) manifestRouteResponse {
	return manifestRouteResponse{
		Schema:        manifestSchema,
		APIVersion:    manifestAPIVersion,
		ServicePrefix: manifestServicePrefix,
		Schemas: []string{
			manifestSchema,
			scanSchema,
			statisticsSchema,
			reportSchema,
		},
		Routes: mountedAPIRoutes(externalBasePath),
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
			OptInQuery: optInQueryContribute,
			OptInValue: optInLiteralValue,
		},
		Permanent: manifestContributeMeta{
			Available:  true,
			OptInQuery: optInQueryPermanent,
			OptInValue: optInLiteralValue,
		},
		OptIn: manifestOptInMeta{
			Default: "neither",
			Start: manifestOptInStartMeta{
				OptInStats:     manifestOptInStartField{Type: schemaFieldTypeBoolean, Default: false},
				OptInPermanent: manifestOptInStartField{Type: schemaFieldTypeBoolean, Default: false},
			},
			Scan: manifestOptInScanMeta{
				StatsQuery:     optInQueryContribute,
				PermanentQuery: optInQueryPermanent,
				OptInValue:     optInLiteralValue,
			},
		},
		Report:        buildManifestReportMeta(externalBasePath),
		Retention:     buildManifestRetentionMeta(externalBasePath),
		ReverseInvite: manifestAvailabilityMeta{Available: true},
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
				optInQueryContribute: {
					Required:    false,
					Type:        schemaFieldTypeString,
					Description: "statistics contribute opt-in; only literal 1 opts in",
					OptInValue:  optInLiteralValue,
				},
				optInQueryPermanent: {
					Required:    false,
					Type:        schemaFieldTypeString,
					Description: "permanent report opt-in; only literal 1 opts in",
					OptInValue:  optInLiteralValue,
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
				OptInStats: scanFieldSchema{
					Type:        schemaFieldTypeBoolean,
					Description: "statistics contribute opt-in echo",
				},
				OptInPermanent: scanFieldSchema{
					Type:        schemaFieldTypeBoolean,
					Description: "permanent report opt-in echo",
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

	writeJSON(w, h.log, http.StatusOK, buildManifest(h.externalBasePath))
}
