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
