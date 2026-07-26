package wellknown

import (
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/discovery/resolve"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/policy"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
	tslocalid "github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/localidentity"
)

func handlerResolveInputs(t *testing.T, basePath string) resolve.ResolveInputs {
	t.Helper()

	opts := service.RouteOpts{ExternalBasePath: basePath}
	if basePath == "" {
		opts = service.DefaultRouteOpts()
	}

	return resolve.ResolveInputs{
		LocalIdentity: tslocalid.MustTestIdentity(t, "https://example.com", basePath),
		RouteOpts:     opts,
		CodeFlow:      policy.NewCodeFlow(),
	}
}
