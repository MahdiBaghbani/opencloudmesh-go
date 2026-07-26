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
)

// DefaultShutdownWait is the standard bounded wait for server shutdown and
// async test synchronization.
const DefaultShutdownWait = config.DefaultTestShutdownWait

// PermissiveConfig returns a fresh OutboundHTTPConfig with SSRF off and
// relaxed timeouts. Modify the returned pointer to add proxy settings or
// other test-specific overrides.
func PermissiveConfig() *config.OutboundHTTPConfig {
	return &config.OutboundHTTPConfig{
		SSRF:             config.SSRFConfig{Mode: "off"},
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
		SSRF:             config.SSRFConfig{Mode: "strict"},
		TimeoutMS:        1000,
		ConnectTimeoutMS: 500,
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
		SSRF:             config.SSRFConfig{Mode: "strict"},
		TimeoutMS:        200,
		ConnectTimeoutMS: 100,
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
