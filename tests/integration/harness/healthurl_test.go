// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 OpenCloudMesh Authors

package harness

import (
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/policy"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
)

func TestHealthEndpointURL(t *testing.T) {
	cases := []struct {
		name             string
		baseURL          string
		externalBasePath string
		want             string
	}{
		{
			name:             "no base path mounts at root",
			baseURL:          "http://localhost:8080",
			externalBasePath: "",
			want:             "http://localhost:8080/api/healthz",
		},
		{
			name:             "leading-slash base path",
			baseURL:          "http://localhost:8080",
			externalBasePath: "/ocm",
			want:             "http://localhost:8080/ocm/api/healthz",
		},
		{
			name:             "base path without leading slash",
			baseURL:          "https://localhost:8443",
			externalBasePath: "ocm",
			want:             "https://localhost:8443/ocm/api/healthz",
		},
		{
			name:             "trailing slashes trimmed on both",
			baseURL:          "http://localhost:8080/",
			externalBasePath: "/ocm/",
			want:             "http://localhost:8080/ocm/api/healthz",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := healthEndpointURL(tc.baseURL, tc.externalBasePath)
			if got != tc.want {
				t.Fatalf("healthEndpointURL(%q, %q) = %q, want %q",
					tc.baseURL, tc.externalBasePath, got, tc.want)
			}
		})
	}
}

func TestLocalListenerBaseURL(t *testing.T) {
	cases := []struct {
		name    string
		tlsMode string
		port    int
		want    string
	}{
		{name: "tls off serves http", tlsMode: "off", port: 8080, want: "http://localhost:8080"},
		{name: "selfsigned serves https", tlsMode: "selfsigned", port: 8443, want: "https://localhost:8443"},
		{name: "static serves https", tlsMode: "static", port: 9000, want: "https://localhost:9000"},
		{name: "whitespace off still http", tlsMode: " off ", port: 8081, want: "http://localhost:8081"},
		{name: "empty mode defaults https", tlsMode: "", port: 8082, want: "https://localhost:8082"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := localListenerBaseURL(tc.tlsMode, tc.port)
			if got != tc.want {
				t.Fatalf("localListenerBaseURL(%q, %d) = %q, want %q",
					tc.tlsMode, tc.port, got, tc.want)
			}
		})
	}
}

func TestValidatePreBootstrapStartup(t *testing.T) {
	cases := []struct {
		name      string
		mutate    func(*config.Config)
		wantError bool
	}{
		{
			name:      "valid none-scope strict config passes",
			mutate:    func(*config.Config) {},
			wantError: false,
		},
		{
			name: "scoped config with tls.mode off rejected before startup",
			mutate: func(cfg *config.Config) {
				cfg.CompatibilityScope = "scoped"
				cfg.TLS.Mode = "off"
			},
			wantError: true,
		},
		{
			name: "none-scope allow_mismatch contradiction rejected before startup",
			mutate: func(cfg *config.Config) {
				// scope=none with signature.allow_mismatch=true is a static
				// contradiction the posture-only guard does not catch.
				cfg.CompatibilityScope = "none"
				cfg.Signature.AllowMismatch = true
			},
			wantError: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// StrictConfig is compatibility_scope=none and satisfies the
			// none-scope guardrails, giving each case a valid starting point.
			cfg := config.StrictConfig()
			tc.mutate(cfg)
			err := validatePreBootstrapStartup(cfg)
			if tc.wantError && err == nil {
				t.Fatalf("validatePreBootstrapStartup() = nil, want error")
			}
			if !tc.wantError && err != nil {
				t.Fatalf("validatePreBootstrapStartup() = %v, want nil", err)
			}
		})
	}
}

func TestCheckStartupPosture(t *testing.T) {
	cases := []struct {
		name      string
		scope     string
		isStrict  bool
		wantError bool
	}{
		{name: "none with strict posture is allowed", scope: "none", isStrict: true, wantError: false},
		{name: "none with non-strict posture is rejected", scope: "none", isStrict: false, wantError: true},
		{name: "scoped with non-strict posture is allowed", scope: "scoped", isStrict: false, wantError: false},
		{name: "unbounded with non-strict posture is allowed", scope: "unbounded", isStrict: false, wantError: false},
		{name: "empty scope with non-strict posture is allowed", scope: "", isStrict: false, wantError: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{CompatibilityScope: tc.scope}
			eval := policy.RuntimeEvaluation{
				CompatibilityScope: tc.scope,
				Strict:             policy.StrictAssessment{IsStrict: tc.isStrict},
			}
			err := checkStartupPosture(cfg, eval)
			if tc.wantError && err == nil {
				t.Fatalf("checkStartupPosture(scope=%q, strict=%v) = nil, want error", tc.scope, tc.isStrict)
			}
			if !tc.wantError && err != nil {
				t.Fatalf("checkStartupPosture(scope=%q, strict=%v) = %v, want nil", tc.scope, tc.isStrict, err)
			}
		})
	}
}
