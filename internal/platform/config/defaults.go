// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package config

import (
	"time"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/sigalg"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/crypto/sigparams"
)

// Outbound HTTP defaults (production strict preset baseline).
const (
	DefaultOutboundTimeoutMS             = 10000
	DefaultOutboundConnectTimeoutMS      = 2000
	DefaultOutboundMaxRedirects          = 1
	DefaultMaxResponseBytes              = 1 << 20
	DefaultOutboundMaxIdleConns          = 10
	DefaultOutboundMaxConnsPerHost       = 10
	DefaultOutboundIdleConnTimeout       = 30 * time.Second
	DefaultOutboundResponseHeaderTimeout = 10 * time.Second
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

// HTTP signature defaults (https://www.rfc-editor.org/rfc/rfc9421.html; OCM Appendix B, informative: https://github.com/cs3org/OCM-API/blob/6a0586183cbef10ecae9dedc42561806447eb2f5/IETF-OCM.md#L2136).
const (
	DefaultSignatureLabel          = sigparams.SignatureLabelOCM
	DefaultSignatureKidFragment    = "key1"
	DefaultSignatureCreatedMaxAge  = 300
	DefaultSignatureCreatedMaxSkew = 60
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
		TimeoutMS:          TestOutboundTimeoutMS,
		ConnectTimeoutMS:   TestOutboundConnectMS,
		MaxRedirects:       DefaultOutboundMaxRedirects,
		MaxResponseBytes:   DefaultMaxResponseBytes,
		InsecureSkipVerify: true,
	}
}

// DefaultOutboundHTTP returns the strict preset outbound HTTP baseline.
// use_env_fallback defaults to false: ambient HTTP_PROXY/HTTPS_PROXY/NO_PROXY
// are ignored unless the operator explicitly opts in via the config field or
// its environment-variable override. The returned config is already non-ambient,
// so callers do not need a separate strict variant to avoid env proxy discovery.
func DefaultOutboundHTTP() OutboundHTTPConfig {
	return OutboundHTTPConfig{
		SSRF:               SSRFConfig{Mode: "strict"},
		TimeoutMS:          DefaultOutboundTimeoutMS,
		ConnectTimeoutMS:   DefaultOutboundConnectTimeoutMS,
		MaxRedirects:       DefaultOutboundMaxRedirects,
		MaxResponseBytes:   DefaultMaxResponseBytes,
		InsecureSkipVerify: false,
		UseEnvFallback:     false,
	}
}

// DefaultPeerTrustMembershipCache returns preset peer-trust cache TTL defaults.
func DefaultPeerTrustMembershipCache() PeerTrustMembershipCacheConfig {
	return PeerTrustMembershipCacheConfig{
		TTLSeconds:      DefaultPeerTrustCacheTTLSeconds,
		MaxStaleSeconds: DefaultPeerTrustCacheMaxStaleSeconds,
	}
}

// DefaultDiscoveryConfig returns inbound peer discovery validation defaults.
func DefaultDiscoveryConfig() DiscoveryConfig {
	return DiscoveryConfig{
		PeerAPIVersionPolicy: "accept-any",
		PeerAPIVersionWarn:   "any-diff",
	}
}

// DefaultSignatureConfig returns RFC 9421 / OCM IETF signature defaults.
func DefaultSignatureConfig() SignatureConfig {
	return SignatureConfig{
		KeyPath:               ".ocm/keys/signing.pem",
		Label:                 DefaultSignatureLabel,
		KidFragment:           DefaultSignatureKidFragment,
		CreatedMaxAgeSeconds:  DefaultSignatureCreatedMaxAge,
		CreatedMaxSkewSeconds: DefaultSignatureCreatedMaxSkew,
		AllowedAlgorithms:     append([]string(nil), sigalg.DefaultAllowed()...),
	}
}
