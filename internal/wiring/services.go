package wiring

import (
	"fmt"
	"log/slog"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/frameworks/service"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/services/api"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/services/ocm"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/services/ocmaux"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/services/ui"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/services/webdav"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/services/wellknown"
)

type coreServiceEntry struct {
	name  string
	newFn service.NewService
}

// coreServiceTable is the static ordered construction table for core HTTP services.
// Order mirrors service.CoreServices for route mount parity.
var coreServiceTable = []coreServiceEntry{
	{name: "wellknown", newFn: wellknown.New},
	{name: "ocm", newFn: ocm.New},
	{name: "ocmaux", newFn: ocmaux.New},
	{name: "api", newFn: api.New},
	{name: "ui", newFn: ui.New},
	{name: "webdav", newFn: webdav.New},
}

// CoreServiceNames returns core service names from the static construction table.
func CoreServiceNames() []string {
	names := make([]string, len(coreServiceTable))
	for i, entry := range coreServiceTable {
		names[i] = entry.name
	}
	return names
}

// BuildCoreServices constructs all core services from the static table in order.
func BuildCoreServices(cfg *config.Config, logger *slog.Logger) (map[string]service.Service, error) {
	services := make(map[string]service.Service, len(coreServiceTable))
	for _, entry := range coreServiceTable {
		svcCfg := cfg.BuildServiceConfig(entry.name)
		if svcCfg == nil {
			svcCfg = make(map[string]any)
		}
		svc, err := entry.newFn(svcCfg, logger)
		if err != nil {
			return nil, fmt.Errorf("create service %q: %w", entry.name, err)
		}
		services[entry.name] = svc
	}
	return services, nil
}
