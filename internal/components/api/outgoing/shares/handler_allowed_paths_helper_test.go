// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package shares_test

import (
	"fmt"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
)

func resolveDefaultAllowedPaths(contentDir string) ([]string, error) {
	root, err := config.ResolveContentDir(contentDir)
	if err != nil {
		return nil, fmt.Errorf("resolve content directory: %w", err)
	}

	return []string{root}, nil
}
