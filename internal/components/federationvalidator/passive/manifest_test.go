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

	"github.com/go-chi/chi/v5"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/federationvalidator/catalog"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

func TestHandleManifest_ReturnsManifestV1Schema(t *testing.T) {
	t.Parallel()

	h := NewHandler(openHandlerTestStore(t), nil)
	h.SetCaps(catalog.FullCaps())

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
		startSchema,
		sessionSchema,
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
	advertised := advertisedRouteSet(planeAAdvertised(BuildManifest().Routes))

	assertSymmetricRouteSets(t, mounted, advertised)
}

func TestHandleManifest_EmptyCapsMatchMountedRoutes(t *testing.T) {
	t.Parallel()

	h := NewHandler(openHandlerTestStore(t), nil)
	r := chi.NewRouter()
	MountPlaneARoutes(r, h, nil)

	assertSymmetricRouteSets(
		t,
		mountedRouteSet(t, r),
		advertisedRouteSet(planeAAdvertised(buildManifestFor("", catalog.Caps{}).Routes)),
	)
}

func TestBuildManifest_EmptyCapsAdvertisesScan(t *testing.T) {
	t.Parallel()

	payload := buildManifestFor("", catalog.Caps{})

	if payload.Scan == nil {
		t.Fatal("empty caps must advertise a non-nil scan object")
	}

	if payload.Scan.Schema != scanSchema {
		t.Fatalf("scan.schema = %q, want %q", payload.Scan.Schema, scanSchema)
	}

	if !slices.Contains(payload.Schemas, scanSchema) {
		t.Fatalf("schemas = %v, want %q", payload.Schemas, scanSchema)
	}

	var hasScan bool

	for _, route := range payload.Routes {
		if route.Method == http.MethodGet && route.FullPath == "/validator/api/scan" {
			hasScan = true
		}
	}

	if !hasScan {
		t.Fatalf("advertised routes missing GET /validator/api/scan: %+v", payload.Routes)
	}
}

func TestHandleManifest_EmptyCapsOmitsUnfinished(t *testing.T) {
	t.Parallel()

	h := NewHandler(openHandlerTestStore(t), nil)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/manifest", nil)
	rec := httptest.NewRecorder()
	h.HandleManifest(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	var raw map[string]json.RawMessage
	if err := json.NewDecoder(rec.Body).Decode(&raw); err != nil {
		t.Fatalf("decode: %v", err)
	}

	for _, key := range []string{"abort", "identityBinding"} {
		if _, ok := raw[key]; ok {
			t.Fatalf("empty caps advertised %s", key)
		}
	}

	if _, ok := raw["scan"]; !ok {
		t.Fatal("empty caps omitted scan")
	}

	optIn := mustRawObject(t, raw["optIn"], "optIn")
	assertExactKeys(t, mustRawObject(t, optIn["start"], "optIn start"), []string{"optInPermanent", "optInStats"})

	var sessionKind manifestSessionKindMeta
	if err := json.Unmarshal(raw["sessionKind"], &sessionKind); err != nil {
		t.Fatalf("sessionKind: %v", err)
	}

	if slices.Contains(sessionKind.Supported, validatorcore.SessionKindActiveFull) {
		t.Fatal("empty caps advertised active_full")
	}

	var reverseInvite manifestAvailabilityMeta
	if err := json.Unmarshal(raw["reverseInvite"], &reverseInvite); err != nil {
		t.Fatalf("reverseInvite: %v", err)
	}

	if reverseInvite.Available {
		t.Fatal("empty caps advertised reverseInvite.available true")
	}
}

func TestHandleManifest_AdvertisesSessionAndReport(t *testing.T) {
	t.Parallel()

	payload := BuildManifest()

	var hasSession bool

	var hasReport bool

	var hasClaimPost bool

	var hasClaimGet bool

	for _, route := range payload.Routes {
		switch {
		case route.FullPath == "/validator/api/session/{id}" && route.Method == http.MethodGet:
			hasSession = true
		case route.FullPath == "/validator/api/report/{id}" && route.Method == http.MethodGet:
			hasReport = true
		case route.FullPath == "/validator/api/session/{id}/invite" && route.Method == http.MethodPost:
			hasClaimPost = true
		case route.FullPath == "/validator/api/session/{id}/invite" && route.Method == http.MethodGet:
			hasClaimGet = true
		}
	}

	if !hasSession {
		t.Fatal("expected GET /validator/api/session/{id} in manifest routes")
	}

	if !hasReport {
		t.Fatal("expected GET /validator/api/report/{id} in manifest routes")
	}

	if !hasClaimPost {
		t.Fatal("expected POST /validator/api/session/{id}/invite in manifest routes")
	}

	if hasClaimGet {
		t.Fatal("GET /validator/api/session/{id}/invite must not be advertised")
	}
}

func TestHandleManifest_AdvertisesAbort(t *testing.T) {
	t.Parallel()

	var hasAbortPost bool

	var hasAbortGet bool

	for _, route := range BuildManifest().Routes {
		if route.FullPath != "/validator/api/session/{id}/abort" {
			continue
		}

		switch route.Method {
		case http.MethodPost:
			hasAbortPost = true
		case http.MethodGet:
			hasAbortGet = true
		}
	}

	if !hasAbortPost {
		t.Fatal("expected POST /validator/api/session/{id}/abort in manifest routes")
	}

	if hasAbortGet {
		t.Fatal("GET /validator/api/session/{id}/abort must not be advertised")
	}
}
