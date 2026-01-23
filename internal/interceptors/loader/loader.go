// Package loader triggers interceptor registration via blank imports.
package loader

import (
	// Register ratelimit interceptor
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/interceptors/ratelimit"
)
