// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

// Package loader registers cache drivers via blank imports.
// Import this package to ensure the default cache drivers are available.
//
// Usage in main.go:
//
//	import _ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache/loader"
package loader

import (
	// Register the memory cache driver.
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache/memory"

	// Register the redis/valkey cache driver.
	_ "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/cache/redis"
)
