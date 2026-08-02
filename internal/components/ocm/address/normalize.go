// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package address

import (
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/hostport"
)

// NormalizedProviderFrom parses the provider from an OCM address and returns a
// scheme-aware normalized host[:port]. Parse and normalize failures share a
// single error return path.
func NormalizedProviderFrom(addr, scheme string) (string, error) {
	_, provider, err := Parse(addr)
	if err != nil {
		return "", err
	}

	return hostport.Normalize(provider, scheme)
}
