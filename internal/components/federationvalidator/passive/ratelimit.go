// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package passive

import (
	"fmt"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
)

const (
	// ScanPublicProfile is the ratelimit profile for public scan surfaces.
	ScanPublicProfile = config.ScanPublicRatelimitProfile

	// StartPublicBucket is the create-session bucket under scan_public.
	StartPublicBucket = config.StartPublicRatelimitBucket
)

// CreateSessionRateLimitProfile returns the start_public bucket config used to
// gate passive-core create-session (POST /start). The limit applies to every
// create-session request, not only active-run branches (S-RL).
func CreateSessionRateLimitProfile(cfg *config.Config) (map[string]any, error) {
	bucket, err := config.StartPublicRatelimitProfile(cfg)
	if err != nil {
		return nil, fmt.Errorf("passive: start_public ratelimit profile: %w", err)
	}

	return bucket, nil
}
