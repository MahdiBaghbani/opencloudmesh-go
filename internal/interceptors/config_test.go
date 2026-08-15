// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package interceptors

import (
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
)

func TestGetRatelimitBucketConfig_FlatProfile(t *testing.T) {
	t.Parallel()

	interceptorsCfg := map[string]map[string]any{
		"ratelimit": {
			"profiles": map[string]any{
				"login": map[string]any{
					"requests_per_window": int64(5),
					"window_seconds":      30,
				},
			},
		},
	}

	bucket, err := GetRatelimitBucketConfig(interceptorsCfg, "login", "")
	if err != nil {
		t.Fatalf("GetRatelimitBucketConfig() = %v, want nil", err)
	}

	if bucket["requests_per_window"] != int64(5) {
		t.Errorf("requests_per_window = %v, want 5", bucket["requests_per_window"])
	}

	if bucket["window_seconds"] != 30 {
		t.Errorf("window_seconds = %v, want 30", bucket["window_seconds"])
	}
}

func TestGetRatelimitBucketConfig_NestedScanPublicStartPublic(t *testing.T) {
	t.Parallel()

	interceptorsCfg := map[string]map[string]any{
		"ratelimit": {
			"profiles": map[string]any{
				config.ScanPublicRatelimitProfile: map[string]any{
					config.StartPublicRatelimitBucket: map[string]any{
						"requests_per_window": int64(10),
						"window_seconds":      60,
					},
				},
			},
		},
	}

	bucket, err := GetRatelimitBucketConfig(
		interceptorsCfg,
		config.ScanPublicRatelimitProfile,
		config.StartPublicRatelimitBucket,
	)
	if err != nil {
		t.Fatalf("GetRatelimitBucketConfig() = %v, want nil", err)
	}

	if bucket["requests_per_window"] != int64(10) {
		t.Errorf("requests_per_window = %v, want 10", bucket["requests_per_window"])
	}

	if bucket["window_seconds"] != 60 {
		t.Errorf("window_seconds = %v, want 60", bucket["window_seconds"])
	}
}

func TestGetRatelimitBucketConfig_NestedProfileRequiresBucket(t *testing.T) {
	t.Parallel()

	interceptorsCfg := map[string]map[string]any{
		"ratelimit": {
			"profiles": map[string]any{
				config.ScanPublicRatelimitProfile: map[string]any{
					config.StartPublicRatelimitBucket: map[string]any{
						"requests_per_window": int64(10),
						"window_seconds":      60,
					},
				},
			},
		},
	}

	_, err := GetRatelimitBucketConfig(interceptorsCfg, config.ScanPublicRatelimitProfile, "")
	if err == nil {
		t.Fatal("GetRatelimitBucketConfig() = nil, want nested bucket error")
	}

	if !strings.Contains(err.Error(), "bucket name is required") {
		t.Fatalf("error = %q, want nested bucket requirement", err)
	}
}

func TestGetRatelimitBucketConfig_FlatProfileRejectsBucketName(t *testing.T) {
	t.Parallel()

	interceptorsCfg := map[string]map[string]any{
		"ratelimit": {
			"profiles": map[string]any{
				"login": map[string]any{
					"requests_per_window": int64(5),
					"window_seconds":      30,
				},
			},
		},
	}

	_, err := GetRatelimitBucketConfig(interceptorsCfg, "login", "extra")
	if err == nil {
		t.Fatal("GetRatelimitBucketConfig() = nil, want flat profile bucket error")
	}

	if !strings.Contains(err.Error(), "is flat") {
		t.Fatalf("error = %q, want flat profile rejection", err)
	}
}

func TestGetRatelimitBucketConfig_MissingNestedBucketName(t *testing.T) {
	t.Parallel()

	interceptorsCfg := map[string]map[string]any{
		"ratelimit": {
			"profiles": map[string]any{
				config.ScanPublicRatelimitProfile: map[string]any{
					config.StartPublicRatelimitBucket: map[string]any{
						"requests_per_window": int64(10),
						"window_seconds":      60,
					},
				},
			},
		},
	}

	_, err := GetRatelimitBucketConfig(
		interceptorsCfg,
		config.ScanPublicRatelimitProfile,
		"missing_bucket",
	)
	if err == nil {
		t.Fatal("GetRatelimitBucketConfig() = nil, want missing bucket error")
	}

	if !strings.Contains(err.Error(), "not found") {
		t.Fatalf("error = %q, want missing bucket name", err)
	}
}

func TestGetRatelimitBucketConfig_BucketValueNotMap(t *testing.T) {
	t.Parallel()

	interceptorsCfg := map[string]map[string]any{
		"ratelimit": {
			"profiles": map[string]any{
				config.ScanPublicRatelimitProfile: map[string]any{
					"start_public": "not-a-map",
				},
			},
		},
	}

	_, err := GetRatelimitBucketConfig(
		interceptorsCfg,
		config.ScanPublicRatelimitProfile,
		"start_public",
	)
	if err == nil {
		t.Fatal("GetRatelimitBucketConfig() = nil, want bucket map error")
	}

	if !strings.Contains(err.Error(), "is not a map") {
		t.Fatalf("error = %q, want bucket map requirement", err)
	}
}

func TestGetRatelimitBucketConfig_NestedBucketNotFlatLimiter(t *testing.T) {
	t.Parallel()

	interceptorsCfg := map[string]map[string]any{
		"ratelimit": {
			"profiles": map[string]any{
				config.ScanPublicRatelimitProfile: map[string]any{
					config.StartPublicRatelimitBucket: map[string]any{
						"nested": map[string]any{
							"requests_per_window": int64(10),
						},
					},
				},
			},
		},
	}

	_, err := GetRatelimitBucketConfig(
		interceptorsCfg,
		config.ScanPublicRatelimitProfile,
		config.StartPublicRatelimitBucket,
	)
	if err == nil {
		t.Fatal("GetRatelimitBucketConfig() = nil, want flat limiter bucket error")
	}

	if !strings.Contains(err.Error(), "not a flat limiter bucket") {
		t.Fatalf("error = %q, want flat limiter bucket requirement", err)
	}
}

func TestGetRatelimitBucketConfig_MissingRatelimitInterceptor(t *testing.T) {
	t.Parallel()

	_, err := GetRatelimitBucketConfig(map[string]map[string]any{}, "login", "")
	if err == nil {
		t.Fatal("GetRatelimitBucketConfig() = nil, want missing interceptor error")
	}

	if !strings.Contains(err.Error(), "no ratelimit interceptor configured") {
		t.Fatalf("error = %q, want missing ratelimit interceptor", err)
	}
}

func TestGetRatelimitBucketConfig_MissingProfiles(t *testing.T) {
	t.Parallel()

	interceptorsCfg := map[string]map[string]any{
		"ratelimit": {},
	}

	_, err := GetRatelimitBucketConfig(interceptorsCfg, "login", "")
	if err == nil {
		t.Fatal("GetRatelimitBucketConfig() = nil, want missing profiles error")
	}

	if !strings.Contains(err.Error(), "no ratelimit profiles configured") {
		t.Fatalf("error = %q, want missing profiles", err)
	}
}

func TestGetRatelimitBucketConfig_ProfilesNotMap(t *testing.T) {
	t.Parallel()

	interceptorsCfg := map[string]map[string]any{
		"ratelimit": {
			"profiles": "not-a-map",
		},
	}

	_, err := GetRatelimitBucketConfig(interceptorsCfg, "login", "")
	if err == nil {
		t.Fatal("GetRatelimitBucketConfig() = nil, want profiles map error")
	}

	if !strings.Contains(err.Error(), "profiles is not a map") {
		t.Fatalf("error = %q, want profiles map requirement", err)
	}
}

func TestGetRatelimitBucketConfig_MissingProfile(t *testing.T) {
	t.Parallel()

	interceptorsCfg := map[string]map[string]any{
		"ratelimit": {
			"profiles": map[string]any{},
		},
	}

	_, err := GetRatelimitBucketConfig(interceptorsCfg, "missing", "")
	if err == nil {
		t.Fatal("GetRatelimitBucketConfig() = nil, want missing profile error")
	}

	if !strings.Contains(err.Error(), "profile \"missing\" not found") {
		t.Fatalf("error = %q, want missing profile", err)
	}
}

func TestGetRatelimitBucketConfig_ProfileNotMap(t *testing.T) {
	t.Parallel()

	interceptorsCfg := map[string]map[string]any{
		"ratelimit": {
			"profiles": map[string]any{
				"login": "not-a-map",
			},
		},
	}

	_, err := GetRatelimitBucketConfig(interceptorsCfg, "login", "")
	if err == nil {
		t.Fatal("GetRatelimitBucketConfig() = nil, want profile map error")
	}

	if !strings.Contains(err.Error(), "profile \"login\" is not a map") {
		t.Fatalf("error = %q, want profile map requirement", err)
	}
}
