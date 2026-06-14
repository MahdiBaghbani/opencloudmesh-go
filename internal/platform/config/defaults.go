package config

import "time"

// Outbound HTTP defaults (production strict preset baseline).
const (
	DefaultOutboundTimeoutMS        = 10000
	DefaultOutboundConnectTimeoutMS = 2000
	DefaultOutboundMaxRedirects     = 1
	DefaultMaxResponseBytes         = 1 << 20
	DefaultOutboundMaxIdleConns     = 10
	DefaultOutboundIdleConnTimeout  = 30 * time.Second
)

// Server HTTP listener defaults.
const (
	DefaultServerReadTimeout     = 30 * time.Second
	DefaultServerWriteTimeout    = 30 * time.Second
	DefaultServerIdleTimeout     = 60 * time.Second
	DefaultChallengeReadTimeout  = 10 * time.Second
	DefaultChallengeWriteTimeout = 10 * time.Second
	DefaultChallengeIdleTimeout  = 60 * time.Second
	DefaultServerShutdownTimeout = 2 * time.Second
)

// Peer trust membership cache defaults (seconds, TOML-facing).
const (
	DefaultPeerTrustCacheTTLSeconds      = 21600  // 6 hours
	DefaultPeerTrustCacheMaxStaleSeconds = 604800 // 7 days
)

// Test-oriented outbound and wait defaults (integration harness + unit tests).
const (
	TestOutboundTimeoutMS = 5000
	TestOutboundConnectMS = 2000
)

// DefaultTestShutdownWait is the standard bounded wait for server shutdown and
// async test synchronization.
const DefaultTestShutdownWait = 5 * time.Second

// TestHarnessOutboundHTTP returns the integration-harness outbound baseline.
func TestHarnessOutboundHTTP() *OutboundHTTPConfig {
	return &OutboundHTTPConfig{
		SSRF:               SSRFConfig{Mode: "off"},
		DerivedSSRFMode:    "off",
		TimeoutMS:          TestOutboundTimeoutMS,
		ConnectTimeoutMS:   TestOutboundConnectMS,
		MaxRedirects:       DefaultOutboundMaxRedirects,
		MaxResponseBytes:   DefaultMaxResponseBytes,
		InsecureSkipVerify: true,
	}
}

// DefaultOutboundHTTP returns the strict preset outbound HTTP baseline.
// Callers that need non-ambient proxy behavior (for example client.New(nil))
// should use OutboundHTTPConfigStrict instead.
func DefaultOutboundHTTP() OutboundHTTPConfig {
	return OutboundHTTPConfig{
		SSRF:               SSRFConfig{Mode: "strict"},
		DerivedSSRFMode:    "strict",
		TimeoutMS:          DefaultOutboundTimeoutMS,
		ConnectTimeoutMS:   DefaultOutboundConnectTimeoutMS,
		MaxRedirects:       DefaultOutboundMaxRedirects,
		MaxResponseBytes:   DefaultMaxResponseBytes,
		InsecureSkipVerify: false,
		ProxyEnvFallback:   true,
	}
}

// DefaultPeerTrustMembershipCache returns preset peer-trust cache TTL defaults.
func DefaultPeerTrustMembershipCache() PeerTrustMembershipCacheConfig {
	return PeerTrustMembershipCacheConfig{
		TTLSeconds:      DefaultPeerTrustCacheTTLSeconds,
		MaxStaleSeconds: DefaultPeerTrustCacheMaxStaleSeconds,
	}
}
