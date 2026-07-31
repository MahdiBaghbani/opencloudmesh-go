// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package service_test

import (
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/services/api"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/services/ocm"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/services/ocmaux"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/services/ui"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/services/webdav"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/services/wellknown"
)

func TestRegisteredRouteSpecs_AllResolveDescriptor(t *testing.T) {
	tests := []struct {
		name string
		opts service.RouteOpts
	}{
		{
			name: "default opts",
			opts: service.DefaultRouteOpts(),
		},
		{
			name: "WAYF-enabled opts",
			opts: service.RouteOpts{
				ExternalBasePath:    "",
				WayfEnabled:         true,
				InviteAcceptEnabled: true,
				TokenExchangePath:   "token",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			specs := service.RegisteredRouteSpecs(tt.opts)
			for _, spec := range specs {
				if _, ok := service.DescriptorByName(spec.Service); !ok {
					t.Errorf("route spec %q service %q has no descriptor", spec.ID, spec.Service)
				}
			}
		})
	}
}

func TestRouteIDSSOT_StaticTokenAndSubtreeDefault(t *testing.T) {
	if got := service.SubtreeDefaultID("ocm"); got != "ocm-subtree-default" {
		t.Errorf("SubtreeDefaultID(ocm) = %q, want ocm-subtree-default", got)
	}

	tokenPaths := []string{"token", "auth/exchange", "token/v2"}
	for _, tokenPath := range tokenPaths {
		t.Run(tokenPath, func(t *testing.T) {
			opts := service.RouteOpts{TokenExchangePath: tokenPath}
			rows := service.Routes(opts)

			var tokenRow *service.RouteRow

			for i := range rows {
				if rows[i].ID == service.RouteIDOCMToken {
					tokenRow = &rows[i]
					break
				}
			}

			if tokenRow == nil {
				t.Fatalf("Routes(opts) missing token row for path %q", tokenPath)
			}

			if tokenRow.ID != service.RouteIDOCMToken {
				t.Errorf("token row ID = %q, want %q", tokenRow.ID, service.RouteIDOCMToken)
			}
		})
	}
}

func TestDerivedRouteInventory_ExternalBasePath(t *testing.T) {
	opts := service.RouteOpts{
		ExternalBasePath:    "/ocm",
		WayfEnabled:         false,
		InviteAcceptEnabled: false,
		TokenExchangePath:   "token",
	}
	inventory := service.DerivedRouteInventory(opts)

	prefixedServices := map[string]bool{"api": false, "ui": false, "ocm": false}

	for _, row := range inventory {
		if row.MountAtRoot {
			if isRootOnlyDiscoveryPath(row.FullPath) {
				continue
			}

			t.Errorf("unexpected host-root inventory row %q with external base path", row.FullPath)

			continue
		}

		if !strings.HasPrefix(row.FullPath, "/ocm/") && row.FullPath != "/ocm" {
			t.Errorf("inventory row %q FullPath = %q, want /ocm prefix", row.ID, row.FullPath)
		}

		if _, ok := prefixedServices[row.Service]; ok {
			prefixedServices[row.Service] = true
		}
	}

	for svc, seen := range prefixedServices {
		if !seen {
			t.Errorf("missing prefixed inventory row for service %q", svc)
		}
	}

	for _, path := range publicPathsUnderBase(opts) {
		if service.SessionAuthRequiredForPath(path, opts) {
			t.Errorf("expected public path %q under external base", path)
		}
	}
}
