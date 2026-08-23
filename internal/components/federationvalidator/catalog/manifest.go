// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package catalog

import (
	"net/http"
	"strings"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

// Schema names, API version, and locked advertisement literals.
const (
	ManifestSchema           = "federation_tester_manifest.v1"
	ScanSchema               = "federation_tester_scan.v1"
	StartSchema              = "federation_tester_start.v1"
	SessionSchema            = "federation_tester_session.v1"
	StatisticsSchema         = "federation_tester_statistics.v1"
	ReportSchema             = "federation_tester_report.v1"
	APIVersion               = "1.3.0"
	schemaTypeString         = "string"
	schemaTypeBoolean        = "boolean"
	optInQueryContribute     = "contribute"
	optInQueryPermanent      = "permanent"
	optInLiteralValue        = "1"
	optInDefaultNeither      = "neither"
	retentionClockFinishedAt = "finishedAt"
	identityPlainUserID      = "plain_user_id"
	identityWrongHost        = "wrong_host"
	identityOpaque           = "opaque"
	identityUUID             = "uuid"
	identitySeverityWarn     = "warn"
	scanTargetDescription    = "URL or OCM id"
	statisticsDefaultDays    = 14
	statisticsKAnonymity     = 5
)

// AdvertisedRoute is one anonymous-manifest route.
type AdvertisedRoute struct {
	Method   string `json:"method"`
	FullPath string `json:"fullPath"`
}

// Manifest is the federation_tester_manifest.v1 payload.
type Manifest struct {
	Schema          string               `json:"schema"`
	APIVersion      string               `json:"apiVersion"`
	Schemas         []string             `json:"schemas"`
	ServicePrefix   string               `json:"servicePrefix"`
	Routes          []AdvertisedRoute    `json:"routes"`
	Statistics      StatisticsMeta       `json:"statistics"`
	Scan            *ScanSchemaV1        `json:"scan,omitempty"`
	SessionKind     SessionKindMeta      `json:"sessionKind"`
	Contribute      ContributeMeta       `json:"contribute"`
	Permanent       ContributeMeta       `json:"permanent"`
	OptIn           OptInMeta            `json:"optIn"`
	Report          ReportMeta           `json:"report"`
	Retention       RetentionMeta        `json:"retention"`
	ReverseInvite   AvailabilityMeta     `json:"reverseInvite"`
	Platform        AvailabilityMeta     `json:"platform"`
	TLSSummary      AvailabilityMeta     `json:"tlsSummary"`
	Abort           *AvailabilityMeta    `json:"abort,omitempty"`
	IdentityBinding *IdentityBindingMeta `json:"identityBinding,omitempty"`
	NextInstruction map[string]string    `json:"nextInstruction"`
}

// StatisticsMeta describes GET /api/statistics.
type StatisticsMeta struct {
	Schema                string `json:"schema"`
	TimeframesDays        []int  `json:"timeframesDays"`
	DefaultDays           int    `json:"defaultDays"`
	KAnonymityUniqueHosts int    `json:"kAnonymityUniqueHosts"`
	UnknownPlatformExempt bool   `json:"unknownPlatformExempt"`
}

// SessionKindMeta lists supported session kinds.
type SessionKindMeta struct {
	Supported   []string `json:"supported"`
	ScanDefault string   `json:"scanDefault"`
}

// ContributeMeta describes an opt-in query flag.
type ContributeMeta struct {
	Available  bool   `json:"available"`
	OptInQuery string `json:"optInQuery"`
	OptInValue string `json:"optInValue"`
}

// OptInMeta describes start and scan consent fields.
type OptInMeta struct {
	Default string         `json:"default"`
	Start   OptInStartMeta `json:"start"`
	Scan    OptInScanMeta  `json:"scan"`
}

// OptInStartMeta describes POST /start consent fields.
type OptInStartMeta struct {
	OptInStats     OptInStartField  `json:"optInStats"`
	OptInPermanent OptInStartField  `json:"optInPermanent"`
	OptInActive    *OptInStartField `json:"optInActive,omitempty"`
}

// OptInStartField is one boolean start consent field.
type OptInStartField struct {
	Type    string `json:"type"`
	Default bool   `json:"default"`
}

// OptInScanMeta describes scan consent query parameters.
type OptInScanMeta struct {
	StatsQuery     string `json:"statsQuery"`
	PermanentQuery string `json:"permanentQuery"`
	OptInValue     string `json:"optInValue"`
}

// AvailabilityMeta is a boolean capability advertisement.
type AvailabilityMeta struct {
	Available bool `json:"available"`
}

// IdentityBindingMeta describes identity-binding enforcement.
type IdentityBindingMeta struct {
	Enforceable    []string `json:"enforceable"`
	WarnOnly       []string `json:"warnOnly"`
	ReportSeverity string   `json:"reportSeverity"`
}

// ReportMeta describes HTML and JSON report paths.
type ReportMeta struct {
	HTMLPath string `json:"htmlPath"`
	APIPath  string `json:"apiPath"`
}

// RetentionMeta describes report retention controls.
type RetentionMeta struct {
	Tiers       []string `json:"tiers"`
	DefaultTier string   `json:"defaultTier"`
	Clock       string   `json:"clock"`
	PatchPath   string   `json:"patchPath"`
	LockPath    string   `json:"lockPath"`
}

// ScanSchemaV1 describes GET /api/scan.
type ScanSchemaV1 struct {
	Schema   string             `json:"schema"`
	Request  ScanRequestSchema  `json:"request"`
	Response ScanResponseSchema `json:"response"`
}

// ScanRequestSchema describes the scan query.
type ScanRequestSchema struct {
	Method string                    `json:"method"`
	Query  map[string]ScanQueryParam `json:"query"`
}

// ScanQueryParam is one scan query field.
type ScanQueryParam struct {
	Required    bool   `json:"required"`
	Type        string `json:"type"`
	Description string `json:"description,omitempty"`
	OptInValue  string `json:"optInValue,omitempty"`
}

// ScanResponseSchema describes the scan success body.
type ScanResponseSchema struct {
	SuccessStatus int              `json:"successStatus"`
	Body          ScanResponseBody `json:"body"`
}

// ScanResponseBody lists scan response fields.
type ScanResponseBody struct {
	ID             ScanFieldSchema `json:"id"`
	OptInStats     ScanFieldSchema `json:"optInStats"`
	OptInPermanent ScanFieldSchema `json:"optInPermanent"`
}

// ScanFieldSchema is one typed scan response field.
type ScanFieldSchema struct {
	Type        string `json:"type"`
	Description string `json:"description,omitempty"`
}

// BuildManifest returns the capability-conditioned federation tester manifest.
func BuildManifest(externalBasePath string, caps Caps) Manifest {
	reverseReady := caps.ReverseInviteAvailable()

	return Manifest{
		Schema:          ManifestSchema,
		APIVersion:      APIVersion,
		ServicePrefix:   ServicePrefix,
		Schemas:         schemaNames(reverseReady),
		Routes:          AdvertisedRoutes(externalBasePath, caps),
		Statistics:      statisticsMeta(),
		Scan:            optionalScanSchema(reverseReady),
		SessionKind:     sessionKindMeta(reverseReady),
		Contribute:      contributeMeta(optInQueryContribute),
		Permanent:       contributeMeta(optInQueryPermanent),
		OptIn:           optInMeta(reverseReady),
		Report:          reportMeta(externalBasePath),
		Retention:       retentionMeta(externalBasePath),
		ReverseInvite:   AvailabilityMeta{Available: reverseReady},
		Platform:        AvailabilityMeta{Available: true},
		TLSSummary:      AvailabilityMeta{Available: true},
		Abort:           optionalAbort(caps.Abort),
		IdentityBinding: optionalIdentityBinding(reverseReady),
		NextInstruction: instructionCatalog(),
	}
}

// AdvertisedRoutes returns the anonymous-manifest route list for caps.
func AdvertisedRoutes(externalBasePath string, caps Caps) []AdvertisedRoute {
	routes := make([]AdvertisedRoute, 0, len(Routes()))

	for _, def := range Routes() {
		if !def.Advertise || !def.ShouldMount(caps) {
			continue
		}

		routes = append(routes, AdvertisedRoute{
			Method:   def.Method,
			FullPath: JoinFullPath(externalBasePath, ServicePrefix, def.Pattern),
		})
	}

	return routes
}

// JoinFullPath prefixes optional base segments the same way service full paths
// are built: trim slashes and skip empty parts.
func JoinFullPath(externalBasePath string, parts ...string) string {
	segments := make([]string, 0, len(parts)+1)

	if trimmed := strings.Trim(externalBasePath, "/"); trimmed != "" {
		segments = append(segments, trimmed)
	}

	for _, part := range parts {
		trimmed := strings.Trim(part, "/")
		if trimmed == "" {
			continue
		}

		segments = append(segments, trimmed)
	}

	if len(segments) == 0 {
		return "/"
	}

	return "/" + strings.Join(segments, "/")
}

func schemaNames(includeScan bool) []string {
	names := []string{ManifestSchema}
	if includeScan {
		names = append(names, ScanSchema)
	}

	return append(names, StartSchema, SessionSchema, StatisticsSchema, ReportSchema)
}

func optionalScanSchema(include bool) *ScanSchemaV1 {
	if !include {
		return nil
	}

	schema := buildScanSchema()

	return &schema
}

func buildScanSchema() ScanSchemaV1 {
	return ScanSchemaV1{
		Schema: ScanSchema,
		Request: ScanRequestSchema{
			Method: http.MethodGet,
			Query: map[string]ScanQueryParam{
				"target": {
					Required:    true,
					Type:        schemaTypeString,
					Description: scanTargetDescription,
				},
				optInQueryContribute: {
					Required:    false,
					Type:        schemaTypeString,
					Description: "statistics contribute opt-in; only literal 1 opts in",
					OptInValue:  optInLiteralValue,
				},
				optInQueryPermanent: {
					Required:    false,
					Type:        schemaTypeString,
					Description: "permanent report opt-in; only literal 1 opts in",
					OptInValue:  optInLiteralValue,
				},
			},
		},
		Response: ScanResponseSchema{
			SuccessStatus: http.StatusCreated,
			Body: ScanResponseBody{
				ID: ScanFieldSchema{
					Type:        schemaTypeString,
					Description: "passive session id",
				},
				OptInStats: ScanFieldSchema{
					Type:        schemaTypeBoolean,
					Description: "statistics contribute opt-in echo",
				},
				OptInPermanent: ScanFieldSchema{
					Type:        schemaTypeBoolean,
					Description: "permanent report opt-in echo",
				},
			},
		},
	}
}

func sessionKindMeta(includeActive bool) SessionKindMeta {
	supported := []string{validatorcore.SessionKindPassiveOnly}
	if includeActive {
		supported = append(supported, validatorcore.SessionKindActiveFull)
	}

	return SessionKindMeta{
		Supported:   supported,
		ScanDefault: validatorcore.SessionKindPassiveOnly,
	}
}

func contributeMeta(query string) ContributeMeta {
	return ContributeMeta{
		Available:  true,
		OptInQuery: query,
		OptInValue: optInLiteralValue,
	}
}

func optInMeta(includeActive bool) OptInMeta {
	start := OptInStartMeta{
		OptInStats:     OptInStartField{Type: schemaTypeBoolean, Default: false},
		OptInPermanent: OptInStartField{Type: schemaTypeBoolean, Default: false},
	}
	if includeActive {
		start.OptInActive = &OptInStartField{Type: schemaTypeBoolean, Default: false}
	}

	return OptInMeta{
		Default: optInDefaultNeither,
		Start:   start,
		Scan: OptInScanMeta{
			StatsQuery:     optInQueryContribute,
			PermanentQuery: optInQueryPermanent,
			OptInValue:     optInLiteralValue,
		},
	}
}

func optionalAbort(include bool) *AvailabilityMeta {
	if !include {
		return nil
	}

	return &AvailabilityMeta{Available: true}
}

func optionalIdentityBinding(include bool) *IdentityBindingMeta {
	if !include {
		return nil
	}

	return &IdentityBindingMeta{
		Enforceable:    []string{identityPlainUserID, identityWrongHost},
		WarnOnly:       []string{identityOpaque, identityUUID},
		ReportSeverity: identitySeverityWarn,
	}
}

// InstructionLabels returns the catalog of nextInstruction keys to labels.
func InstructionLabels() map[string]string {
	return instructionCatalog()
}

func instructionCatalog() map[string]string {
	keys := validatorcore.NextInstructionKeys()
	out := make(map[string]string, len(keys))

	for _, key := range keys {
		out[key] = validatorcore.NextInstructionLabel(key)
	}

	return out
}

func statisticsMeta() StatisticsMeta {
	return StatisticsMeta{
		Schema:                StatisticsSchema,
		TimeframesDays:        []int{7, 14, 30, 60, 90, 365, 0},
		DefaultDays:           statisticsDefaultDays,
		KAnonymityUniqueHosts: statisticsKAnonymity,
		UnknownPlatformExempt: true,
	}
}

func reportMeta(externalBasePath string) ReportMeta {
	return ReportMeta{
		HTMLPath: JoinFullPath(externalBasePath, ServicePrefix, "report", "{id}"),
		APIPath:  JoinFullPath(externalBasePath, ServicePrefix, "api", "report", "{id}"),
	}
}

func retentionMeta(externalBasePath string) RetentionMeta {
	return RetentionMeta{
		Tiers: []string{
			validatorcore.RetentionTierForever,
			validatorcore.RetentionTier7,
			validatorcore.RetentionTier14,
			validatorcore.RetentionTier30,
			validatorcore.RetentionTier60,
			validatorcore.RetentionTier90,
		},
		DefaultTier: validatorcore.DefaultRetentionTier,
		Clock:       retentionClockFinishedAt,
		PatchPath:   JoinFullPath(externalBasePath, ServicePrefix, "api", "report", "{id}", "retention"),
		LockPath:    JoinFullPath(externalBasePath, ServicePrefix, "api", "report", "{id}", "lock"),
	}
}
