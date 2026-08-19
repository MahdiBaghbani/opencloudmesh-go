// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package config

import (
	"errors"
	"fmt"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/realip"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/store"
)

func validateValidatorTrustedProxies(cfg *Config) error {
	if !IsValidatorMode(cfg) {
		return nil
	}

	if _, err := realip.NewTrustedProxiesStrict(cfg.Server.TrustedProxies); err != nil {
		return fmt.Errorf("server.trusted_proxies: %w", err)
	}

	return nil
}

func validateValidatorStatistics(cfg *Config) error {
	if !IsValidatorMode(cfg) {
		return nil
	}

	if !cfg.Statistics.Enabled {
		return errors.New("mode=validator requires statistics.enabled=true")
	}

	if cfg.Persistence.Backend == BackendMemory {
		return errors.New("mode=validator requires a durable persistence backend for redaction salt")
	}

	if cfg.Persistence.Backend == BackendJSON {
		return fmt.Errorf(
			"mode=validator requires a SQLite-backed persistence backend: %w",
			store.ErrNoSharedSQLiteHandle,
		)
	}

	return nil
}

func validateValidatorScanPublicRatelimit(cfg *Config) error {
	if !IsValidatorMode(cfg) {
		return nil
	}

	startPublic, err := StartPublicRatelimitProfile(cfg)
	if err != nil {
		return err
	}

	if err := validateCompleteRatelimitBucket(
		startPublic,
		fmt.Sprintf(
			"http.interceptors.ratelimit.profiles.%s.%s",
			ScanPublicRatelimitProfile,
			StartPublicRatelimitBucket,
		),
	); err != nil {
		return err
	}

	if cfg.HTTP.Services == nil {
		return errors.New("mode=validator requires http.services.validator.ratelimit profile scan_public")
	}

	svcCfg, ok := cfg.HTTP.Services["validator"]
	if !ok {
		return errors.New("mode=validator requires http.services.validator")
	}

	rlCfg, ok := svcCfg["ratelimit"]
	if !ok {
		return errors.New("mode=validator requires http.services.validator.ratelimit")
	}

	rlMap, ok := rlCfg.(map[string]any)
	if !ok {
		return errors.New("http.services.validator.ratelimit must be a map")
	}

	profile, ok := rlMap["profile"].(string)
	if !ok || profile != ScanPublicRatelimitProfile {
		return fmt.Errorf(
			"http.services.validator.ratelimit.profile must be %q",
			ScanPublicRatelimitProfile,
		)
	}

	return nil
}

// StartPublicRatelimitProfile returns the start_public bucket under scan_public.
func StartPublicRatelimitProfile(cfg *Config) (map[string]any, error) {
	if cfg == nil {
		return nil, errors.New("config is nil")
	}

	if cfg.HTTP.Interceptors == nil {
		return nil, fmt.Errorf(
			"missing http.interceptors.ratelimit.profiles.%s.%s",
			ScanPublicRatelimitProfile,
			StartPublicRatelimitBucket,
		)
	}

	rlCfg, ok := cfg.HTTP.Interceptors["ratelimit"]
	if !ok {
		return nil, fmt.Errorf(
			"missing http.interceptors.ratelimit.profiles.%s.%s",
			ScanPublicRatelimitProfile,
			StartPublicRatelimitBucket,
		)
	}

	profilesRaw, ok := rlCfg["profiles"]
	if !ok {
		return nil, fmt.Errorf(
			"missing http.interceptors.ratelimit.profiles.%s.%s",
			ScanPublicRatelimitProfile,
			StartPublicRatelimitBucket,
		)
	}

	profiles, ok := profilesRaw.(map[string]any)
	if !ok {
		return nil, errors.New("http.interceptors.ratelimit.profiles must be a map")
	}

	scanPublic, ok := profiles[ScanPublicRatelimitProfile]
	if !ok {
		return nil, fmt.Errorf("missing http.interceptors.ratelimit.profiles.%s", ScanPublicRatelimitProfile)
	}

	scanMap, ok := scanPublic.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("http.interceptors.ratelimit.profiles.%s must be a map", ScanPublicRatelimitProfile)
	}

	startPublic, ok := scanMap[StartPublicRatelimitBucket]
	if !ok {
		return nil, fmt.Errorf(
			"missing http.interceptors.ratelimit.profiles.%s.%s",
			ScanPublicRatelimitProfile,
			StartPublicRatelimitBucket,
		)
	}

	startMap, ok := startPublic.(map[string]any)
	if !ok {
		return nil, fmt.Errorf(
			"http.interceptors.ratelimit.profiles.%s.%s must be a map",
			ScanPublicRatelimitProfile,
			StartPublicRatelimitBucket,
		)
	}

	return startMap, nil
}

// validateCompleteRatelimitBucket requires both limiter fields to be present and
// positive, matching the ratelimit interceptor contract without runtime defaults.
func validateCompleteRatelimitBucket(bucket map[string]any, path string) error {
	if bucket == nil {
		return fmt.Errorf("%s must be a map", path)
	}

	requestsRaw, ok := bucket["requests_per_window"]
	if !ok {
		return fmt.Errorf("%s.requests_per_window is required", path)
	}

	requests, err := positiveInt64Field(requestsRaw, path+".requests_per_window")
	if err != nil {
		return err
	}

	if requests <= 0 {
		return fmt.Errorf("%s.requests_per_window must be positive", path)
	}

	windowRaw, ok := bucket["window_seconds"]
	if !ok {
		return fmt.Errorf("%s.window_seconds is required", path)
	}

	window, err := positiveIntField(windowRaw, path+".window_seconds")
	if err != nil {
		return err
	}

	if window <= 0 {
		return fmt.Errorf("%s.window_seconds must be positive", path)
	}

	return nil
}

func positiveInt64Field(value any, field string) (int64, error) {
	switch n := value.(type) {
	case int64:
		return n, nil
	case int:
		return int64(n), nil
	case float64:
		if n != float64(int64(n)) {
			return 0, fmt.Errorf("%s must be an integer", field)
		}

		return int64(n), nil
	default:
		return 0, fmt.Errorf("%s must be an integer", field)
	}
}

func positiveIntField(value any, field string) (int, error) {
	n, err := positiveInt64Field(value, field)
	if err != nil {
		return 0, err
	}

	return int(n), nil
}
