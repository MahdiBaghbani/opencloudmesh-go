// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package interceptors

import "fmt"

// GetProfileConfig looks up a named profile from an interceptor's config.
func GetProfileConfig(interceptorsCfg map[string]map[string]any, interceptorName, profileName string) (map[string]any, error) {
	if interceptorsCfg == nil {
		return nil, fmt.Errorf("no interceptors configured, cannot find %s profile %q", interceptorName, profileName)
	}

	interceptorCfg, ok := interceptorsCfg[interceptorName]
	if !ok {
		return nil, fmt.Errorf("no %s interceptor configured, cannot find profile %q", interceptorName, profileName)
	}

	profilesRaw, ok := interceptorCfg["profiles"]
	if !ok {
		return nil, fmt.Errorf("no %s profiles configured, cannot find profile %q", interceptorName, profileName)
	}

	profiles, ok := profilesRaw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s profiles is not a map, cannot find profile %q", interceptorName, profileName)
	}

	profileRaw, ok := profiles[profileName]
	if !ok {
		return nil, fmt.Errorf("%s profile %q not found", interceptorName, profileName)
	}

	profileConfig, ok := profileRaw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s profile %q is not a map", interceptorName, profileName)
	}

	return profileConfig, nil
}

// GetRatelimitBucketConfig resolves a ratelimit profile to the flat bucket map
// accepted by ratelimit.New. Flat profiles expose requests_per_window and/or
// window_seconds at the top level. Nested profiles group buckets under the
// profile map and require bucketName (for example scan_public.start_public).
func GetRatelimitBucketConfig(
	interceptorsCfg map[string]map[string]any,
	profileName,
	bucketName string,
) (map[string]any, error) {
	profile, err := GetProfileConfig(interceptorsCfg, "ratelimit", profileName)
	if err != nil {
		return nil, err
	}

	if isFlatRatelimitBucket(profile) {
		if bucketName != "" {
			return nil, fmt.Errorf(
				"ratelimit profile %q is flat, bucket %q is not applicable",
				profileName,
				bucketName,
			)
		}

		return profile, nil
	}

	if bucketName == "" {
		return nil, fmt.Errorf("ratelimit profile %q is nested, bucket name is required", profileName)
	}

	bucketRaw, ok := profile[bucketName]
	if !ok {
		return nil, fmt.Errorf("ratelimit profile %q bucket %q not found", profileName, bucketName)
	}

	bucket, ok := bucketRaw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("ratelimit profile %q bucket %q is not a map", profileName, bucketName)
	}

	if !isFlatRatelimitBucket(bucket) {
		return nil, fmt.Errorf(
			"ratelimit profile %q bucket %q is not a flat limiter bucket",
			profileName,
			bucketName,
		)
	}

	return bucket, nil
}

func isFlatRatelimitBucket(m map[string]any) bool {
	if m == nil {
		return false
	}

	_, hasRequests := m["requests_per_window"]
	_, hasWindow := m["window_seconds"]

	return hasRequests || hasWindow
}
