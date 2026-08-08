// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package address

import (
	"fmt"

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

	normalized, err := hostport.Normalize(provider, scheme)
	if err != nil {
		return "", fmt.Errorf("ocm: normalize address: %w", err)
	}

	return normalized, nil
}
