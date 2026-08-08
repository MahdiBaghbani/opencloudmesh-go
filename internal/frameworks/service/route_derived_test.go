// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package service_test

import (
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/services/api"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/services/ocm"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/services/ocmaux"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/services/ui"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/services/webdav"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/services/wellknown"
)

func TestDerivedAuthRows_ProjectsFromRoutes(t *testing.T) {
	t.Parallel()

	opts := service.DefaultRouteOpts()
	rows := service.Routes(opts)

	authRows := service.DerivedAuthRows(opts)
	if len(authRows) != len(rows) {
		t.Fatalf("auth row count = %d, route count = %d", len(authRows), len(rows))
	}
}

func TestDerivedMountSpecs_ProjectsFromRoutes(t *testing.T) {
	t.Parallel()

	opts := service.DefaultRouteOpts()
	rows := service.Routes(opts)

	groups := service.DerivedMountSpecs(opts)
	if len(groups) == 0 {
		t.Fatal("expected derived route groups")
	}

	wantHostRoot, wantSubtree := countMountSpecKinds(rows)

	if len(groups) != wantHostRoot+wantSubtree {
		t.Fatalf("group count = %d, want %d host-root + %d subtree", len(groups), wantHostRoot, wantSubtree)
	}

	byPrefix := make(map[string]service.DerivedRouteGroup, len(groups))
	for _, g := range groups {
		byPrefix[g.PathPrefix] = g
	}

	for _, row := range rows {
		assertRowMountGroup(t, opts, row, byPrefix)
	}
}

// countMountSpecKinds counts the host-root and synthetic-subtree route rows.
func countMountSpecKinds(rows []service.RouteRow) (hostRoot, subtree int) {
	for _, row := range rows {
		if row.AtHostRoot && !row.Synthetic {
			hostRoot++
		}

		if row.Synthetic && !row.AtHostRoot {
			subtree++
		}
	}

	return hostRoot, subtree
}

// assertRowMountGroup checks one route row against its derived mount group.
func assertRowMountGroup(t *testing.T, opts service.RouteOpts, row service.RouteRow, byPrefix map[string]service.DerivedRouteGroup) {
	t.Helper()

	switch {
	case row.Synthetic && !row.AtHostRoot:
		assertSubtreeGroup(t, opts, row, byPrefix)
	case row.AtHostRoot && !row.Synthetic:
		assertHostRootGroup(t, opts, row, byPrefix)
	}
}

// assertSubtreeGroup checks a synthetic subtree row against its mount group.
func assertSubtreeGroup(t *testing.T, opts service.RouteOpts, row service.RouteRow, byPrefix map[string]service.DerivedRouteGroup) {
	t.Helper()

	g, ok := byPrefix[row.FullPath]
	if !ok {
		t.Errorf("missing subtree group for synthetic row %q prefix %q", row.ID, row.FullPath)

		return
	}

	if g.Name != row.Service {
		t.Errorf("subtree group %q name = %q, want service %q", row.FullPath, g.Name, row.Service)
	}

	if g.AtHostRoot {
		t.Errorf("subtree group %q AtHostRoot = true, want false", row.FullPath)
	}

	assertGroupRequiresAuth(t, opts, "subtree", row.FullPath, g)
}

// assertHostRootGroup checks a host-root row against its mount group.
func assertHostRootGroup(t *testing.T, opts service.RouteOpts, row service.RouteRow, byPrefix map[string]service.DerivedRouteGroup) {
	t.Helper()

	g, ok := byPrefix[row.FullPath]
	if !ok {
		t.Errorf("missing host-root group for row %q prefix %q", row.ID, row.FullPath)

		return
	}

	if g.Name != row.ID {
		t.Errorf("host-root group %q name = %q, want id %q", row.FullPath, g.Name, row.ID)
	}

	if !g.AtHostRoot {
		t.Errorf("host-root group %q AtHostRoot = false, want true", row.FullPath)
	}

	assertGroupRequiresAuth(t, opts, "host-root", row.FullPath, g)
}

// assertGroupRequiresAuth checks the group's auth projection against
// SessionAuthRequiredForPath.
func assertGroupRequiresAuth(t *testing.T, opts service.RouteOpts, kind, fullPath string, g service.DerivedRouteGroup) {
	t.Helper()

	wantAuth := service.SessionAuthRequiredForPath(fullPath+"/probe", opts)
	if g.RequiresAuth != wantAuth {
		t.Errorf("%s group %q RequiresAuth = %v, want %v", kind, fullPath, g.RequiresAuth, wantAuth)
	}
}

func TestSessionAuthRequiredForPath_PublicAndProtected(t *testing.T) {
	t.Parallel()

	opts := service.DefaultRouteOpts()

	cases := []struct {
		path     string
		wantAuth bool
	}{
		{"/.well-known/ocm", false},
		{"/api/healthz", false},
		{"/api/auth/login", false},
		{"/ui/login", false},
		{"/ocm/shares", false},
		{"/api/inbox/shares", true},
		{"/ui/inbox", true},
		{"/unknown", true},
	}
	for _, tc := range cases {
		got := service.SessionAuthRequiredForPath(tc.path, opts)
		if got != tc.wantAuth {
			t.Errorf("SessionAuthRequiredForPath(%q) = %v, want %v", tc.path, got, tc.wantAuth)
		}
	}
}

func TestSessionAuthRequiredForPath_WayfRoutes(t *testing.T) {
	t.Parallel()

	disabled := service.DefaultRouteOpts()
	if !service.SessionAuthRequiredForPath("/ui/wayf", disabled) {
		t.Error("expected /ui/wayf protected when WAYF disabled")
	}

	enabled := service.RouteOpts{
		WayfEnabled:         true,
		InviteAcceptEnabled: true,
		TokenExchangePath:   "token",
	}
	if service.SessionAuthRequiredForPath("/ui/wayf", enabled) {
		t.Error("expected /ui/wayf public when WAYF enabled")
	}

	if !service.SessionAuthRequiredForPath("/ui/accept-invite", enabled) {
		t.Error("expected /ui/accept-invite protected when invite accept enabled")
	}
}
