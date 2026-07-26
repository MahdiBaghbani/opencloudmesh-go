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

func TestRegisteredRouteSpecs_IncludesAllCoreServices(t *testing.T) {
	opts := service.DefaultRouteOpts()

	specs := service.RegisteredRouteSpecs(opts)
	if len(specs) == 0 {
		t.Fatal("expected registered route specs")
	}

	seen := make(map[string]struct{})

	for _, spec := range specs {
		if spec.ID == "" {
			t.Errorf("route spec missing ID: %+v", spec)
		}

		if spec.Service == "" {
			t.Errorf("route spec %q missing Service", spec.ID)
		}

		if spec.Pattern == "" {
			t.Errorf("route spec %q missing Pattern", spec.ID)
		}

		if spec.SurfaceClass == "" {
			t.Errorf("route spec %q missing SurfaceClass", spec.ID)
		}

		if spec.HandlerAuth == "" {
			t.Errorf("route spec %q missing HandlerAuth", spec.ID)
		}

		if spec.TrustClass == "" {
			t.Errorf("route spec %q missing TrustClass", spec.ID)
		}

		seen[spec.Service] = struct{}{}
	}

	for _, name := range service.CoreServices {
		if _, ok := seen[name]; !ok {
			t.Errorf("no registered route specs for core service %q", name)
		}
	}
}
