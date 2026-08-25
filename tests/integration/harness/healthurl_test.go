// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package harness

import (
	"reflect"
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/validatorpeer"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/wiring"
)

func TestHealthEndpointURL(t *testing.T) {
	t.Parallel()

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
			t.Parallel()

			got := healthEndpointURL(tc.baseURL, tc.externalBasePath)
			if got != tc.want {
				t.Fatalf("healthEndpointURL(%q, %q) = %q, want %q",
					tc.baseURL, tc.externalBasePath, got, tc.want)
			}
		})
	}
}

func TestLocalListenerBaseURL(t *testing.T) {
	t.Parallel()

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
			t.Parallel()

			got := localListenerBaseURL(tc.tlsMode, tc.port)
			if got != tc.want {
				t.Fatalf("localListenerBaseURL(%q, %d) = %q, want %q",
					tc.tlsMode, tc.port, got, tc.want)
			}
		})
	}
}

func TestValidatePreBootstrapStartup(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		mutate    func(*config.Config)
		wantError bool
		// wantSubstr, when set, requires the returned error to contain this
		// exact loader substring. Used to fence specific regression strings.
		wantSubstr string
	}{
		{
			name:      "valid strict config passes",
			mutate:    func(*config.Config) {},
			wantError: false,
		},
		{
			name: "dev config with tls.mode off allowed before startup",
			mutate: func(cfg *config.Config) {
				cfg.Mode = "dev"
				cfg.TLS.Mode = "off"
				cfg.OutboundHTTP.SSRF.Mode = "off"
				cfg.OutboundHTTP.InsecureSkipVerify = true
			},
			wantError: false,
		},
		{
			name: "strict config with tls.mode off rejected",
			mutate: func(cfg *config.Config) {
				cfg.TLS.Mode = "off"
			},
			wantError:  true,
			wantSubstr: "mode=strict requires tls.mode!=off",
		},
		{
			name: "validator config with ssrf off rejected",
			mutate: func(cfg *config.Config) {
				cfg.Mode = string(config.ModeValidator)
				cfg.OutboundHTTP.SSRF.Mode = "off"
			},
			wantError:  true,
			wantSubstr: "mode=validator requires outbound_http.ssrf.mode=strict",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

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
	t.Parallel()

	dev := config.DevConfig()
	cfg := config.DevConfig()
	applyIETFConfigDefaults(cfg)

	if cfg.Signature.Label != config.DefaultSignatureLabel {
		t.Fatalf("Signature.Label = %q, want %q", cfg.Signature.Label, config.DefaultSignatureLabel)
	}

	// Intentionally preserved DevConfig leniencies for in-process localhost tests.
	if cfg.Mode != dev.Mode {
		t.Fatalf("Mode = %q, want preserved %q", cfg.Mode, dev.Mode)
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
}

func TestIETFIntegrationBuildOpts(t *testing.T) {
	t.Parallel()

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
	t.Parallel()

	got := IETFIntegrationBuildOpts()

	want := wiring.BuildOpts{
		FastAuth:           true,
		SkipCrypto:         false,
		SkipPeerTrust:      true,
		OutboundOverride:   got.OutboundOverride,
		OutboundDialHosts:  validatorpeer.DialHosts(),
		SkipDiscoveryCache: true,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("IETFIntegrationBuildOpts() = %+v, want %+v", got, want)
	}
}
