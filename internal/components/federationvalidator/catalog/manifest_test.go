// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package catalog

import (
	"net/http"
	"slices"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store/validatorcore"
)

func TestBuildManifest_EmptyOmitsUnfinished(t *testing.T) {
	t.Parallel()

	payload := BuildManifest("", Caps{})

	if payload.APIVersion != APIVersion {
		t.Fatalf("apiVersion = %q, want %q", payload.APIVersion, APIVersion)
	}

	if payload.ReverseInvite.Available {
		t.Fatal("empty caps must not advertise reverse invite")
	}

	if payload.Scan == nil {
		t.Fatal("empty caps must include scan")
	}

	if payload.Abort != nil {
		t.Fatal("empty caps must omit abort")
	}

	if payload.IdentityBinding != nil {
		t.Fatal("empty caps must omit identity binding")
	}

	if payload.OptIn.Start.OptInActive != nil {
		t.Fatal("empty caps must omit optInActive")
	}

	if slices.Contains(payload.SessionKind.Supported, validatorcore.SessionKindActiveFull) {
		t.Fatal("empty caps must not advertise active_full")
	}

	if !slices.Contains(payload.Schemas, ScanSchema) {
		t.Fatal("empty caps must list the scan schema")
	}

	assertNoUnfinishedRoutes(t, payload.Routes)
}

func TestBuildManifest_FullAdvertisesConditionedSurfaces(t *testing.T) {
	t.Parallel()

	payload := BuildManifest("", FullCaps())

	if !payload.ReverseInvite.Available {
		t.Fatal("full caps must advertise reverse invite")
	}

	if payload.Scan == nil || payload.Scan.Request.Query["target"].Description != scanTargetDescription {
		t.Fatalf("scan target = %+v, want %q", payload.Scan, scanTargetDescription)
	}

	if payload.Abort == nil || !payload.Abort.Available {
		t.Fatal("full caps must advertise abort")
	}

	assertIdentityBindingExact(t, payload.IdentityBinding)

	if payload.OptIn.Start.OptInActive == nil {
		t.Fatal("full caps must advertise optInActive")
	}

	if !slices.Contains(payload.SessionKind.Supported, validatorcore.SessionKindActiveFull) {
		t.Fatal("full caps must advertise active_full")
	}

	if !slices.Contains(payload.Schemas, StartSchema) || !slices.Contains(payload.Schemas, SessionSchema) {
		t.Fatalf("schemas = %v, want start and session", payload.Schemas)
	}

	if payload.NextInstruction[validatorcore.InstructionWaitProbe] == "" {
		t.Fatal("nextInstruction catalog must include wait_probe label")
	}

	assertConditionedRoutesAdvertised(t, payload.Routes)
}

func assertNoUnfinishedRoutes(t *testing.T, routes []AdvertisedRoute) {
	t.Helper()

	for _, route := range routes {
		switch {
		case route.FullPath == "/validator/api/session/{id}/abort":
			t.Fatal("empty caps advertised abort")
		case route.FullPath == "/validator/api/session/{id}/invite":
			t.Fatal("empty caps advertised claim")
		case route.FullPath == "/validator/api/session/{id}/reverse-invite":
			t.Fatal("empty caps advertised paste")
		case route.Method == http.MethodGet && route.FullPath == "/validator/start":
			t.Fatal("empty caps advertised GET /start")
		}
	}
}

func assertIdentityBindingExact(t *testing.T, meta *IdentityBindingMeta) {
	t.Helper()

	if meta == nil {
		t.Fatal("full caps must advertise identity binding")
	}

	if !slices.Equal(meta.Enforceable, []string{identityPlainUserID, identityWrongHost}) {
		t.Fatalf("enforceable = %v", meta.Enforceable)
	}

	if !slices.Equal(meta.WarnOnly, []string{identityOpaque, identityUUID}) {
		t.Fatalf("warnOnly = %v", meta.WarnOnly)
	}

	if meta.ReportSeverity != identitySeverityWarn {
		t.Fatalf("reportSeverity = %q", meta.ReportSeverity)
	}
}

func assertConditionedRoutesAdvertised(t *testing.T, routes []AdvertisedRoute) {
	t.Helper()

	got := make(map[string]struct{}, len(routes))

	for _, route := range routes {
		got[route.Method+" "+route.FullPath] = struct{}{}
	}

	for _, key := range []string{
		http.MethodGet + " /validator/api/scan",
		http.MethodPost + " /validator/api/session/{id}/abort",
		http.MethodPost + " /validator/api/session/{id}/invite",
		http.MethodPost + " /validator/api/session/{id}/reverse-invite",
	} {
		if _, ok := got[key]; !ok {
			t.Fatalf("full caps missing advertised route %s", key)
		}
	}
}

func TestAdvertisedRoutes_MatchMountableAdvertiseSet(t *testing.T) {
	t.Parallel()

	for _, caps := range []Caps{{}, FullCaps()} {
		advertised := AdvertisedRoutes("", caps)

		var want []AdvertisedRoute

		for _, def := range Routes() {
			if !def.Advertise || !def.ShouldMount(caps) {
				continue
			}

			want = append(want, AdvertisedRoute{
				Method:   def.Method,
				FullPath: JoinFullPath("", ServicePrefix, def.Pattern),
			})
		}

		if !slices.Equal(advertised, want) {
			t.Fatalf("caps=%+v advertised = %+v, want %+v", caps, advertised, want)
		}
	}
}
