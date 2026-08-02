// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package signature_test

import (
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
)

func defaultSigTestConfig() *config.SignatureConfig {
	cfg := config.DefaultSignatureConfig()
	return &cfg
}
