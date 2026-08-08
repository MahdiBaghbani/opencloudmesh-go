// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package server

import (
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/routing"
)

func TestMountSpecs_FromDerivedProjection(t *testing.T) {
	t.Parallel()

	groups := GetMountSpecs()
	if len(groups) == 0 {
		t.Fatal("expected derived route groups")
	}
}

func TestPathMatchesPrefix_ViaServiceProjection(t *testing.T) {
	t.Parallel()

	opts := service.DefaultRouteOpts()

	cases := []struct {
		path string
		want bool
	}{
		{"/api/healthz", false},
		{"/api/inbox/shares", true},
	}
	for _, tc := range cases {
		got := service.SessionAuthRequiredForPath(tc.path, opts)
		if got != tc.want {
			t.Errorf("SessionAuthRequiredForPath(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}
