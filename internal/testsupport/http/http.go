// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

// Package http provides test helper factories for outbound HTTP client configs
// and clients. Helpers return fresh values so callers can safely override
// individual fields without affecting other tests.
package http

import (
	"crypto/x509"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	httpclient "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/http/client"
)

// Re-exported test timeout defaults (SSOT: config package).
const (
	TestOutboundTimeoutMS = config.TestOutboundTimeoutMS
	TestOutboundConnectMS = config.TestOutboundConnectMS

	ssrfModeOff    = "off"
	ssrfModeStrict = "strict"

	// StrictNoneOutboundConfig uses longer timeouts for SSRF behavior tests.
	strictNoneOutboundTimeoutMS = 1000
	strictNoneOutboundConnectMS = 500
	// StrictShortTimeoutConfig uses short timeouts for route-policy unit tests.
	strictShortOutboundTimeoutMS = 200
	strictShortOutboundConnectMS = 100
)

// DefaultShutdownWait is the standard bounded wait for server shutdown and
// async test synchronization.
const DefaultShutdownWait = config.DefaultTestShutdownWait

// PermissiveConfig returns a fresh OutboundHTTPConfig with SSRF off and
// relaxed timeouts. Modify the returned pointer to add proxy settings or
// other test-specific overrides.
func PermissiveConfig() *config.OutboundHTTPConfig {
	return &config.OutboundHTTPConfig{
		SSRF:             config.SSRFConfig{Mode: ssrfModeOff},
		UseEnvFallback:   false,
		TimeoutMS:        TestOutboundTimeoutMS,
		ConnectTimeoutMS: TestOutboundConnectMS,
		MaxRedirects:     config.DefaultOutboundMaxRedirects,
		MaxResponseBytes: config.DefaultMaxResponseBytes,
	}
}

// HarnessOutboundConfig returns the integration-harness outbound baseline:
// permissive SSRF, test timeouts, and TLS verification disabled.
func HarnessOutboundConfig() *config.OutboundHTTPConfig {
	return config.TestHarnessOutboundHTTP()
}

// StrictNoneOutboundConfig returns a fresh OutboundHTTPConfig with strict
// SSRF enforcement and conservative timeouts suited for SSRF behavior tests.
// Modify the returned pointer to add proxy settings or other test-specific
// overrides.
func StrictNoneOutboundConfig() *config.OutboundHTTPConfig {
	return &config.OutboundHTTPConfig{
		SSRF:             config.SSRFConfig{Mode: ssrfModeStrict},
		TimeoutMS:        strictNoneOutboundTimeoutMS,
		ConnectTimeoutMS: strictNoneOutboundConnectMS,
		MaxRedirects:     config.DefaultOutboundMaxRedirects,
		MaxResponseBytes: config.DefaultMaxResponseBytes,
	}
}

// StrictShortTimeoutConfig returns a fresh OutboundHTTPConfig with strict SSRF
// and very short timeouts (200ms/100ms) suited for route-policy unit tests that
// use a fixedResolver and never actually dial out. Modify the returned pointer
// to add RoutePolicy and RoutePolicies overrides.
func StrictShortTimeoutConfig() *config.OutboundHTTPConfig {
	return &config.OutboundHTTPConfig{
		SSRF:             config.SSRFConfig{Mode: ssrfModeStrict},
		TimeoutMS:        strictShortOutboundTimeoutMS,
		ConnectTimeoutMS: strictShortOutboundConnectMS,
		MaxRedirects:     config.DefaultOutboundMaxRedirects,
		MaxResponseBytes: config.DefaultMaxResponseBytes,
	}
}

// NewPermissive constructs a Client using PermissiveConfig. Pass a non-nil
// rootCAs pool to trust additional TLS certificates.
func NewPermissive(rootCAs *x509.CertPool) *httpclient.Client {
	return httpclient.New(PermissiveConfig(), rootCAs)
}

// NewStrictNone constructs a Client using StrictNoneOutboundConfig. Pass a
// non-nil rootCAs pool to trust additional TLS certificates.
func NewStrictNone(rootCAs *x509.CertPool) *httpclient.Client {
	return httpclient.New(StrictNoneOutboundConfig(), rootCAs)
}
