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
		t.Fatalf("api_version = %q, want %q", payload.APIVersion, manifestAPIVersion)
	}
}

func TestHandleManifest_SchemaVersionsIncludeLiveSchemas(t *testing.T) {
	t.Parallel()

	payload := BuildManifest()

	wantSchemas := []string{
		manifestSchema,
		scanSchema,
		statisticsSchema,
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

func TestHandleManifest_AdvertisesSessionNotReport(t *testing.T) {
	t.Parallel()

	payload := BuildManifest()

	var hasSession bool

	for _, route := range payload.Routes {
		switch route.FullPath {
		case "/validator/api/session/{id}":
			if route.Method != http.MethodGet {
				t.Fatalf("session route method = %q, want GET", route.Method)
			}

			hasSession = true
		case "/validator/api/report/{id}":
			t.Fatalf("must not advertise unmounted route %q", route.FullPath)
		}
	}

	if !hasSession {
		t.Fatal("expected GET /validator/api/session/{id} in manifest routes")
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

	target, ok := scan.Request.Query["target"]
	if !ok || !target.Required || target.Type != schemaFieldTypeString {
		t.Fatalf("scan target query = %+v, want required string", target)
	}

	contribute, ok := scan.Request.Query["contribute"]
	if !ok || contribute.Required || contribute.OptInValue != "1" {
		t.Fatalf("scan contribute query = %+v, want optional opt_in_value 1", contribute)
	}

	if scan.Response.SuccessStatus != http.StatusCreated {
		t.Fatalf("scan success_status = %d, want 201", scan.Response.SuccessStatus)
	}

	if scan.Response.Body.ID.Type != schemaFieldTypeString || scan.Response.Body.ID.Description == "" {
		t.Fatalf("scan response id = %+v, want string session id", scan.Response.Body.ID)
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

	var live map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&live); err != nil {
		t.Fatalf("decode live scan: %v", err)
	}

	if _, ok := live["id"]; !ok {
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
		t.Fatalf("timeframes_days = %v, want %v", payload.Statistics.TimeframesDays, statisticsSupportedDays)
	}

	if payload.Statistics.DefaultDays != statisticsDefaultDays {
		t.Fatalf("default_days = %d, want %d", payload.Statistics.DefaultDays, statisticsDefaultDays)
	}

	if payload.Statistics.KAnonymityUniqueHosts != statisticsKAnonymityUniqueHosts {
		t.Fatalf("k_anonymity_unique_hosts = %d, want %d", payload.Statistics.KAnonymityUniqueHosts, statisticsKAnonymityUniqueHosts)
	}

	if !payload.Statistics.UnknownPlatformExempt {
		t.Fatal("expected unknown_platform_exempt true")
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
		"api_version",
		"contribute",
		"platform",
		"reverse_invite",
		"routes",
		"scan",
		"schema",
		"schemas",
		"service_prefix",
		"session_kind",
		"statistics",
		"tls_summary",
	}

	assertExactKeys(t, raw, wantTopLevel)

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

	var scanResponse map[string]json.RawMessage
	if err := json.Unmarshal(scan["response"], &scanResponse); err != nil {
		t.Fatalf("unmarshal scan response: %v", err)
	}

	assertExactKeys(t, scanResponse, []string{"body", "success_status"})
}

func TestBuildManifest_RoutesWireContract(t *testing.T) {
	t.Parallel()

	manifest := BuildManifest()
	advertised := manifest.Routes

	wire, err := json.Marshal(manifest) //nolint:errchkjson // wire contract test; manifestRouteResponse is json-safe
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}

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

		// Required wire keys must stay method and full_path; extra route keys may be added later.
		assertRequiredKeys(t, routeObj, []string{"method", "full_path"})

		var method string
		if err := json.Unmarshal(routeObj["method"], &method); err != nil {
			t.Fatalf("route[%d] method wire value: %v", i, err)
		}

		var fullPath string
		if err := json.Unmarshal(routeObj["full_path"], &fullPath); err != nil {
			t.Fatalf("route[%d] full_path wire value: %v", i, err)
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
		t.Fatalf("session_kind.supported = %v, want %v", payload.SessionKind.Supported, wantSessionKinds)
	}

	if payload.SessionKind.ScanDefault != validatorcore.SessionKindPassiveOnly {
		t.Fatalf("session_kind.scan_default = %q", payload.SessionKind.ScanDefault)
	}

	if !payload.Contribute.Available || payload.Contribute.OptInQuery != "contribute" || payload.Contribute.OptInValue != "1" {
		t.Fatalf("contribute = %+v", payload.Contribute)
	}

	if payload.ReverseInvite.Available {
		t.Fatal("reverse_invite.available must be false in v1.3.0")
	}

	if !payload.Platform.Available || !payload.TLSSummary.Available {
		t.Fatalf("platform = %+v tls_summary = %+v", payload.Platform, payload.TLSSummary)
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

func assertExactKeys(t *testing.T, raw map[string]json.RawMessage, want []string) {
	t.Helper()

	got := make([]string, 0, len(raw))
	for key := range raw {
		got = append(got, key)
	}

	slices.Sort(got)
	slices.Sort(want)

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("keys = %v, want %v", got, want)
	}
}

func assertRequiredKeys(t *testing.T, raw map[string]json.RawMessage, required []string) {
	t.Helper()

	for _, key := range required {
		if _, ok := raw[key]; !ok {
			t.Fatalf("missing required wire key %q; keys present: %v", key, sortedWireKeys(raw))
		}
	}
}

func sortedWireKeys(raw map[string]json.RawMessage) []string {
	keys := make([]string, 0, len(raw))
	for key := range raw {
		keys = append(keys, key)
	}

	slices.Sort(keys)

	return keys
}
