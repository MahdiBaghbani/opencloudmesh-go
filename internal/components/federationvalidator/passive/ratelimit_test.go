// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package passive

import (
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
)

func TestCreateSessionRoute_IsPublicRatelimitOnly(t *testing.T) {
	t.Parallel()

	specs := []service.RouteSpec{CreateSessionRouteSpec()}

	var createSession *service.RouteSpec

	for i := range specs {
		if specs[i].Pattern == RouteStartCreateSession {
			createSession = &specs[i]

			break
		}
	}

	if createSession == nil {
		t.Fatal("missing POST /start create-session route spec")
	}

	if createSession.SessionPolicy != service.SessionPublic {
		t.Errorf("SessionPolicy = %q, want public", createSession.SessionPolicy)
	}

	if createSession.HandlerAuth != service.HandlerAuthRateLimitOnly {
		t.Errorf("HandlerAuth = %q, want rate limit only", createSession.HandlerAuth)
	}
}

func TestCreateSessionRateLimitProfile_UsesScanPublicPath(t *testing.T) {
	t.Parallel()

	cfg := config.ValidatorConfig()

	profile, err := CreateSessionRateLimitProfile(cfg)
	if err != nil {
		t.Fatalf("CreateSessionRateLimitProfile: %v", err)
	}

	if profile["requests_per_window"] != int64(10) {
		t.Errorf("requests_per_window = %v, want 10", profile["requests_per_window"])
	}

	if profile["window_seconds"] != 60 {
		t.Errorf("window_seconds = %v, want 60", profile["window_seconds"])
	}
}

func TestCreateSessionRateLimitProfile_NestedBucketNotParentDefault(t *testing.T) {
	t.Parallel()

	cfg := config.ValidatorConfig()

	rlCfg, ok := cfg.HTTP.Interceptors["ratelimit"]
	if !ok {
		t.Fatal("missing ratelimit interceptor")
	}

	profilesRaw, ok := rlCfg["profiles"]
	if !ok {
		t.Fatal("missing ratelimit profiles")
	}

	profiles, ok := profilesRaw.(map[string]any)
	if !ok {
		t.Fatal("ratelimit profiles must be a map")
	}

	parentMap, ok := profiles[config.ScanPublicRatelimitProfile].(map[string]any)
	if !ok {
		t.Fatal("scan_public parent must be a map")
	}

	if _, has := parentMap["requests_per_window"]; has {
		t.Fatal("scan_public parent must not be a flat limiter bucket")
	}

	profile, err := CreateSessionRateLimitProfile(cfg)
	if err != nil {
		t.Fatalf("CreateSessionRateLimitProfile: %v", err)
	}

	if profile["requests_per_window"] != int64(10) {
		t.Errorf("nested requests_per_window = %v, want 10 (not parent default 100)", profile["requests_per_window"])
	}

	if profile["window_seconds"] != 60 {
		t.Errorf("nested window_seconds = %v, want 60", profile["window_seconds"])
	}

	if len(profile) != 2 {
		t.Errorf("pinned bucket keys = %v, want only limiter fields", profile)
	}
}
