// Package loader triggers service registration via blank imports.
// Import this package to ensure all services are registered with the registry.
package loader

import (
	// Import services here to trigger their init() registration.
	// Services are added incrementally as they are migrated.
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/apiservice"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/ocm"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/ocmaux"
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/wellknown"
)
