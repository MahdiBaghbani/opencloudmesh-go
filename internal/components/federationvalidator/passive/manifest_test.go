// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package passive

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

func TestHandleManifest_ReturnsManifestV1Schema(t *testing.T) {
	t.Parallel()

	h := NewHandler(openHandlerTestStore(t), nil)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/manifest", nil)
	rec := httptest.NewRecorder()
	h.HandleManifest(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	var payload manifestRouteResponse
	if err := json.NewDecoder(rec.Body).Decode(&payload); err != nil {
		t.Fatalf("decode: %v", err)
	}

	if payload.Schema != manifestSchema {
		t.Fatalf("schema = %q, want %q", payload.Schema, manifestSchema)
	}

	if payload.APIVersion != manifestAPIVersion {
		t.Fatalf("apiVersion = %q, want %q", payload.APIVersion, manifestAPIVersion)
	}
}

func TestHandleManifest_SchemaVersionsIncludeLiveSchemas(t *testing.T) {
	t.Parallel()

	payload := BuildManifest()

	wantSchemas := []string{
		manifestSchema,
		scanSchema,
		statisticsSchema,
		reportSchema,
	}

	if !reflect.DeepEqual(payload.Schemas, wantSchemas) {
		t.Fatalf("schemas = %v, want %v", payload.Schemas, wantSchemas)
	}
}

func TestHandleManifest_AdvertisedRoutesMatchMountedAPIRoutes(t *testing.T) {
	t.Parallel()

	mounted := mountedRouteSet(t, newPlaneATestRouter(t))
	advertised := advertisedRouteSet(BuildManifest().Routes)

	assertSymmetricRouteSets(t, mounted, advertised)
}

func TestHandleManifest_AdvertisesSessionAndReport(t *testing.T) {
	t.Parallel()

	payload := BuildManifest()

	var hasSession bool

	var hasReport bool

	for _, route := range payload.Routes {
		switch {
		case route.FullPath == "/validator/api/session/{id}" && route.Method == http.MethodGet:
			hasSession = true
		case route.FullPath == "/validator/api/report/{id}" && route.Method == http.MethodGet:
			hasReport = true
		}
	}

	if !hasSession {
		t.Fatal("expected GET /validator/api/session/{id} in manifest routes")
	}

	if !hasReport {
		t.Fatal("expected GET /validator/api/report/{id} in manifest routes")
	}
}

func TestHandleManifest_ScanSchemaMatchesLiveHandler(t *testing.T) {
	t.Parallel()

	payload := BuildManifest()
	scan := payload.Scan

	if scan.Schema != scanSchema {
		t.Fatalf("scan.schema = %q, want %q", scan.Schema, scanSchema)
	}

	if scan.Request.Method != http.MethodGet {
		t.Fatalf("scan.request.method = %q, want GET", scan.Request.Method)
	}

	assertRequiredScanQuery(t, scan.Request.Query, "target")
	assertOptionalScanOptInQuery(t, scan.Request.Query, optInQueryContribute)
	assertOptionalScanOptInQuery(t, scan.Request.Query, optInQueryPermanent)

	if scan.Response.SuccessStatus != http.StatusCreated {
		t.Fatalf("scan successStatus = %d, want 201", scan.Response.SuccessStatus)
	}

	if scan.Response.Body.ID.Type != schemaFieldTypeString || scan.Response.Body.ID.Description == "" {
		t.Fatalf("scan response id = %+v, want string session id", scan.Response.Body.ID)
	}

	if scan.Response.Body.OptInStats.Type != schemaFieldTypeBoolean ||
		scan.Response.Body.OptInStats.Description == "" {
		t.Fatalf("scan response optInStats = %+v, want boolean", scan.Response.Body.OptInStats)
	}

	if scan.Response.Body.OptInPermanent.Type != schemaFieldTypeBoolean ||
		scan.Response.Body.OptInPermanent.Description == "" {
		t.Fatalf("scan response optInPermanent = %+v, want boolean", scan.Response.Body.OptInPermanent)
	}

	h := NewHandler(openHandlerTestStore(t), nil)

	req := httptest.NewRequestWithContext(
		t.Context(),
		http.MethodGet,
		"/api/scan?target=https://peer.example",
		nil,
	)
	rec := httptest.NewRecorder()
	h.HandleScan(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("live scan status = %d, want 201", rec.Code)
	}

	var live map[string]json.RawMessage
	if err := json.NewDecoder(rec.Body).Decode(&live); err != nil {
		t.Fatalf("decode live scan: %v", err)
	}

	assertExactKeys(t, live, []string{"id", "optInPermanent", "optInStats"})

	var id string
	if err := json.Unmarshal(live["id"], &id); err != nil {
		t.Fatalf("live scan id: %v", err)
	}

	if id == "" {
		t.Fatal("live scan response must contain id field")
	}
}

func TestHandleManifest_StatisticsMetadataMatchesLiveHandler(t *testing.T) {
	t.Parallel()

	payload := BuildManifest()

	if payload.Statistics.Schema != statisticsSchema {
		t.Fatalf("statistics.schema = %q, want %q", payload.Statistics.Schema, statisticsSchema)
	}

	if !reflect.DeepEqual(payload.Statistics.TimeframesDays, statisticsSupportedDays) {
		t.Fatalf("timeframesDays = %v, want %v", payload.Statistics.TimeframesDays, statisticsSupportedDays)
	}

	if payload.Statistics.DefaultDays != statisticsDefaultDays {
		t.Fatalf("defaultDays = %d, want %d", payload.Statistics.DefaultDays, statisticsDefaultDays)
	}

	if payload.Statistics.KAnonymityUniqueHosts != statisticsKAnonymityUniqueHosts {
		t.Fatalf("kAnonymityUniqueHosts = %d, want %d", payload.Statistics.KAnonymityUniqueHosts, statisticsKAnonymityUniqueHosts)
	}

	if !payload.Statistics.UnknownPlatformExempt {
		t.Fatal("expected unknownPlatformExempt true")
	}
}

func TestHandleManifest_AdditiveFieldDiscipline(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/manifest", nil)
	rec := httptest.NewRecorder()
	NewHandler(openHandlerTestStore(t), nil).HandleManifest(rec, req)

	var raw map[string]json.RawMessage
	if err := json.NewDecoder(rec.Body).Decode(&raw); err != nil {
		t.Fatalf("decode: %v", err)
	}

	wantTopLevel := []string{
		"apiVersion",
		"contribute",
		"optIn",
		"permanent",
		"platform",
		"report",
		"retention",
		"reverseInvite",
		"routes",
		"scan",
		"schema",
		"schemas",
		"servicePrefix",
		"sessionKind",
		"statistics",
		"tlsSummary",
	}

	assertExactKeys(t, raw, wantTopLevel)

	var statistics map[string]json.RawMessage
	if err := json.Unmarshal(raw["statistics"], &statistics); err != nil {
		t.Fatalf("unmarshal statistics: %v", err)
	}

	assertExactKeys(t, statistics, []string{
		"defaultDays",
		"kAnonymityUniqueHosts",
		"schema",
		"timeframesDays",
		"unknownPlatformExempt",
	})

	var sessionKind map[string]json.RawMessage
	if err := json.Unmarshal(raw["sessionKind"], &sessionKind); err != nil {
		t.Fatalf("unmarshal sessionKind: %v", err)
	}

	assertExactKeys(t, sessionKind, []string{"scanDefault", "supported"})

	var contribute map[string]json.RawMessage
	if err := json.Unmarshal(raw["contribute"], &contribute); err != nil {
		t.Fatalf("unmarshal contribute: %v", err)
	}

	assertExactKeys(t, contribute, []string{"available", "optInQuery", "optInValue"})
	assertOptInWireKeys(t, raw)

	var scan map[string]json.RawMessage
	if err := json.Unmarshal(raw["scan"], &scan); err != nil {
		t.Fatalf("unmarshal scan: %v", err)
	}

	assertExactKeys(t, scan, []string{"request", "response", "schema"})

	var scanRequest map[string]json.RawMessage
	if err := json.Unmarshal(scan["request"], &scanRequest); err != nil {
		t.Fatalf("unmarshal scan request: %v", err)
	}

	assertExactKeys(t, scanRequest, []string{"method", "query"})

	var scanQuery map[string]json.RawMessage
	if err := json.Unmarshal(scanRequest["query"], &scanQuery); err != nil {
		t.Fatalf("unmarshal scan query: %v", err)
	}

	var scanTarget map[string]json.RawMessage
	if err := json.Unmarshal(scanQuery["target"], &scanTarget); err != nil {
		t.Fatalf("unmarshal scan query target: %v", err)
	}

	// target has no opt-in value, so optInValue is omitted on the wire.
	assertExactKeys(t, scanTarget, []string{"description", "required", "type"})

	var scanContribute map[string]json.RawMessage
	if err := json.Unmarshal(scanQuery["contribute"], &scanContribute); err != nil {
		t.Fatalf("unmarshal scan query contribute: %v", err)
	}

	assertExactKeys(t, scanContribute, []string{"description", "optInValue", "required", "type"})
	assertScanQueryPermanentKeys(t, scanQuery)

	var scanResponse map[string]json.RawMessage
	if err := json.Unmarshal(scan["response"], &scanResponse); err != nil {
		t.Fatalf("unmarshal scan response: %v", err)
	}

	assertExactKeys(t, scanResponse, []string{"body", "successStatus"})
	assertExactKeys(t, mustRawObject(t, scanResponse["body"], "scan response body"), []string{
		"id",
		"optInPermanent",
		"optInStats",
	})
	assertExactKeys(t, mustRawObject(t, raw["report"], "report"), []string{"apiPath", "htmlPath"})
	assertExactKeys(t, mustRawObject(t, raw["retention"], "retention"), []string{
		"clock",
		"defaultTier",
		"lockPath",
		"patchPath",
		"tiers",
	})
}

func TestBuildManifest_RoutesWireContract(t *testing.T) {
	t.Parallel()

	manifest := BuildManifest()
	advertised := manifest.Routes

	wire := mustJSON(t, manifest)

	var top map[string]json.RawMessage
	if err := json.Unmarshal(wire, &top); err != nil {
		t.Fatalf("unmarshal top-level manifest: %v", err)
	}

	var routeObjects []json.RawMessage
	if err := json.Unmarshal(top["routes"], &routeObjects); err != nil {
		t.Fatalf("unmarshal routes array: %v", err)
	}

	if len(routeObjects) != len(advertised) {
		t.Fatalf("routes len on wire = %d, want %d", len(routeObjects), len(advertised))
	}

	wireRoutes := make([]MountedAPIRoute, 0, len(routeObjects))

	for i, routeRaw := range routeObjects {
		var routeObj map[string]json.RawMessage
		if err := json.Unmarshal(routeRaw, &routeObj); err != nil {
			t.Fatalf("unmarshal route[%d] object: %v", i, err)
		}

		// Required wire keys must stay method and fullPath; extra route keys may be added later.
		assertRequiredKeys(t, routeObj, []string{"fullPath", "method"})

		var method string
		if err := json.Unmarshal(routeObj["method"], &method); err != nil {
			t.Fatalf("route[%d] method wire value: %v", i, err)
		}

		var fullPath string
		if err := json.Unmarshal(routeObj["fullPath"], &fullPath); err != nil {
			t.Fatalf("route[%d] fullPath wire value: %v", i, err)
		}

		wireRoutes = append(wireRoutes, MountedAPIRoute{
			Method:   method,
			FullPath: fullPath,
		})
	}

	if !reflect.DeepEqual(wireRoutes, advertised) {
		t.Fatalf("wire routes = %+v, want %+v", wireRoutes, advertised)
	}
}

func TestHandleManifest_CapabilityMetadataLockedValues(t *testing.T) {
	t.Parallel()

	payload := BuildManifest()

	wantSessionKinds := []string{
		validatorcore.SessionKindPassiveOnly,
		validatorcore.SessionKindActiveFull,
	}

	if !slices.Equal(payload.SessionKind.Supported, wantSessionKinds) {
		t.Fatalf("sessionKind.supported = %v, want %v", payload.SessionKind.Supported, wantSessionKinds)
	}

	if payload.SessionKind.ScanDefault != validatorcore.SessionKindPassiveOnly {
		t.Fatalf("sessionKind.scanDefault = %q", payload.SessionKind.ScanDefault)
	}

	assertConsentAdvertisement(t, payload)

	if payload.ReverseInvite.Available {
		t.Fatal("reverseInvite.available must be false in v1.3.0")
	}

	if !payload.Platform.Available || !payload.TLSSummary.Available {
		t.Fatalf("platform = %+v tlsSummary = %+v", payload.Platform, payload.TLSSummary)
	}
}

func TestHandleManifest_MethodNotAllowed(t *testing.T) {
	t.Parallel()

	h := NewHandler(openHandlerTestStore(t), nil)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/manifest", nil)
	rec := httptest.NewRecorder()
	h.HandleManifest(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rec.Code)
	}
}
