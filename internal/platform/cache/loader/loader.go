// Package loader registers cache drivers via blank imports.
// Import this package to ensure the default cache drivers are available.
//
// Usage in main.go:
//
//	import _ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache/loader"
package loader

import (
	// Register the memory cache driver
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache/memory"

	// Register the redis/valkey cache driver
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache/redis"
)
