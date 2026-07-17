// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 OpenCloudMesh Authors

package harness

import (
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/policy"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/wiring"
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
		// wantSubstr, when set, requires the returned error to contain this
		// exact loader substring. Used to fence specific regression strings.
		wantSubstr string
	}{
		{
			name:      "valid none-scope strict config passes",
			mutate:    func(*config.Config) {},
			wantError: false,
		},
		{
			// Scoped compatibility does not constrain transport settings;
			// strict signature and peer posture from StrictConfig keep this valid.
			name: "scoped config with tls.mode off allowed before startup",
			mutate: func(cfg *config.Config) {
				cfg.CompatibilityScope = "scoped"
				cfg.TLS.Mode = "off"
			},
			wantError: false,
		},
		{
			name: "none-scope allow_mismatch contradiction rejected before startup",
			mutate: func(cfg *config.Config) {
				// scope=none with signature.allow_mismatch=true is a static
				// contradiction the posture-only validation does not catch.
				cfg.CompatibilityScope = "none"
				cfg.Signature.AllowMismatch = true
			},
			wantError: true,
		},
		{
			name: "none-scope non-strict peer_policy rejected before startup",
			mutate: func(cfg *config.Config) {
				cfg.PeerPolicy = "prefer-strict"
			},
			wantError:  true,
			wantSubstr: "compatibility_scope=none requires peer_policy=strict",
		},
		{
			name: "none-scope peer trust without global_enforce rejected before startup",
			mutate: func(cfg *config.Config) {
				cfg.PeerTrust.Enabled = true
				cfg.PeerTrust.Policy.GlobalEnforce = false
			},
			wantError:  true,
			wantSubstr: "compatibility_scope=none requires peer_trust.policy.global_enforce=true when peer trust is enabled",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// StrictConfig is compatibility_scope=none and satisfies the
			// none-scope compatibility requirements, giving each case a valid starting point.
			cfg := config.StrictConfig()
			tc.mutate(cfg)
			err := validatePreBootstrapStartup(cfg)
			if tc.wantError && err == nil {
				t.Fatalf("validatePreBootstrapStartup() = nil, want error")
			}
			if !tc.wantError && err != nil {
				t.Fatalf("validatePreBootstrapStartup() = %v, want nil", err)
			}
			if tc.wantSubstr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantSubstr)) {
				t.Fatalf("validatePreBootstrapStartup() = %v, want error containing %q", err, tc.wantSubstr)
			}
		})
	}
}

func TestApplyIETFConfigDefaults(t *testing.T) {
	dev := config.DevConfig()
	cfg := config.DevConfig()
	applyIETFConfigDefaults(cfg)

	if cfg.Signature.InboundMode != "strict" {
		t.Fatalf("Signature.InboundMode = %q, want strict", cfg.Signature.InboundMode)
	}
	if cfg.Signature.OutboundMode != "strict" {
		t.Fatalf("Signature.OutboundMode = %q, want strict", cfg.Signature.OutboundMode)
	}
	if cfg.Signature.Label != config.DefaultSignatureLabel {
		t.Fatalf("Signature.Label = %q, want %q", cfg.Signature.Label, config.DefaultSignatureLabel)
	}
	if cfg.Signature.AllowMismatch {
		t.Fatal("Signature.AllowMismatch = true, want false")
	}
	if !cfg.RequireTokenExchange {
		t.Fatal("RequireTokenExchange = false, want true")
	}

	assertIETFHarnessLocalhostPeerMappings(t, cfg.PeerProfiles.Mappings)

	// Intentionally preserved DevConfig leniencies for in-process localhost tests.
	if cfg.Mode != dev.Mode {
		t.Fatalf("Mode = %q, want preserved %q", cfg.Mode, dev.Mode)
	}
	if cfg.CompatibilityScope != dev.CompatibilityScope {
		t.Fatalf("CompatibilityScope = %q, want preserved %q", cfg.CompatibilityScope, dev.CompatibilityScope)
	}
	if cfg.TLS.Mode != dev.TLS.Mode {
		t.Fatalf("TLS.Mode = %q, want preserved %q", cfg.TLS.Mode, dev.TLS.Mode)
	}
	if cfg.OutboundHTTP.SSRF.Mode != dev.OutboundHTTP.SSRF.Mode {
		t.Fatalf("OutboundHTTP.SSRF.Mode = %q, want preserved %q", cfg.OutboundHTTP.SSRF.Mode, dev.OutboundHTTP.SSRF.Mode)
	}
	if cfg.OutboundHTTP.InsecureSkipVerify != dev.OutboundHTTP.InsecureSkipVerify {
		t.Fatalf("OutboundHTTP.InsecureSkipVerify = %v, want preserved %v", cfg.OutboundHTTP.InsecureSkipVerify, dev.OutboundHTTP.InsecureSkipVerify)
	}
	if cfg.Signature.PeerProfileLevelOverride != dev.Signature.PeerProfileLevelOverride {
		t.Fatalf("Signature.PeerProfileLevelOverride = %q, want preserved %q", cfg.Signature.PeerProfileLevelOverride, dev.Signature.PeerProfileLevelOverride)
	}
	if cfg.PeerPolicy != dev.PeerPolicy {
		t.Fatalf("PeerPolicy = %q, want preserved %q", cfg.PeerPolicy, dev.PeerPolicy)
	}
}

func TestIETFHarnessLocalhostPeerMappings(t *testing.T) {
	mappings := ietfHarnessLocalhostPeerMappings()
	assertIETFHarnessLocalhostPeerMappings(t, mappings)
}

func assertIETFHarnessLocalhostPeerMappings(t *testing.T, mappings []config.PeerProfileMapping) {
	t.Helper()

	want := map[string]string{
		"localhost": "dev",
		"127.0.0.1": "dev",
	}
	if len(mappings) != len(want) {
		t.Fatalf("peer profile mappings = %d, want %d", len(mappings), len(want))
	}

	got := make(map[string]string, len(mappings))
	for _, mapping := range mappings {
		got[mapping.Pattern] = mapping.Profile
	}
	for pattern, profile := range want {
		if got[pattern] != profile {
			t.Fatalf("mapping[%q] = %q, want profile %q (full mappings: %+v)",
				pattern, got[pattern], profile, mappings)
		}
	}
}

func TestIETFIntegrationBuildOpts(t *testing.T) {
	opts := IETFIntegrationBuildOpts()
	if opts.SkipCrypto {
		t.Fatal("SkipCrypto must be false for IETF integration path")
	}

	base := IntegrationBuildOpts()
	if opts.FastAuth != base.FastAuth {
		t.Fatal("IETF opts should preserve FastAuth from integration baseline")
	}
	if opts.SkipPeerTrust != base.SkipPeerTrust {
		t.Fatal("IETF opts should preserve SkipPeerTrust from integration baseline")
	}
	if opts.SkipDiscoveryCache != base.SkipDiscoveryCache {
		t.Fatal("IETF opts should preserve SkipDiscoveryCache from integration baseline")
	}
}

func TestIETFIntegrationBuildOpts_MatchesWiringBuildOpts(t *testing.T) {
	got := IETFIntegrationBuildOpts()
	want := wiring.BuildOpts{
		FastAuth:           true,
		SkipCrypto:         false,
		SkipPeerTrust:      true,
		OutboundOverride:   got.OutboundOverride,
		SkipDiscoveryCache: true,
	}
	if got != want {
		t.Fatalf("IETFIntegrationBuildOpts() = %+v, want %+v", got, want)
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
