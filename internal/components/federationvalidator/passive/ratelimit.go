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

// CreateSessionRateLimitProfile returns the nested start_public limiter bucket
// shared by create-session, scan, claim, and paste. It does not return the
// scan_public parent map: that parent has no top-level limiter fields, and
// ratelimit.New would default it to 100 requests / 60 seconds. The nested
// bucket is pinned to requests_per_window and window_seconds only.
func CreateSessionRateLimitProfile(cfg *config.Config) (map[string]any, error) {
	bucket, err := config.StartPublicRatelimitProfile(cfg)
	if err != nil {
		return nil, fmt.Errorf("passive: start_public ratelimit profile: %w", err)
	}

	return map[string]any{
		"requests_per_window": bucket["requests_per_window"],
		"window_seconds":      bucket["window_seconds"],
	}, nil
}
