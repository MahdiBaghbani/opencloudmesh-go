// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package incoming_test

import (
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/policy"
	tokenincoming "github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/token/incoming"
)

// enabledSettings returns token exchange path settings for testing.
func enabledSettings() *tokenincoming.TokenExchangeSettings {
	s := &tokenincoming.TokenExchangeSettings{}
	s.ApplyDefaults()

	return s
}

func enabledCodeFlow() *policy.CodeFlow {
	return policy.NewCodeFlow()
}
