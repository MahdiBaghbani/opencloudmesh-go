// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package config

const (
	// ScanPublicRatelimitProfile is the public scan ratelimit profile name.
	// Configured at [http.interceptors.ratelimit.profiles.scan_public].
	ScanPublicRatelimitProfile = "scan_public"

	// StartPublicRatelimitBucket is the create-session bucket under scan_public.
	// Configured at [http.interceptors.ratelimit.profiles.scan_public.start_public].
	StartPublicRatelimitBucket = "start_public"

	// defaultStartPublicWindowSeconds is the validator preset window for start_public.
	defaultStartPublicWindowSeconds = 60
)
