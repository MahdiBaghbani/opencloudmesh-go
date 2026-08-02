// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

// Package protocol provides TOML config fragments for strict two-server protocol
// integration tests. It does not start servers or assert outcomes.
package protocol

import (
	"fmt"
	"path/filepath"
	"strings"
)

// Variant selects which strict-protocol fixture overlay to emit.
type Variant int

const (
	// VariantProtocolPair is the default wire/auth protocol-class pair overlay.
	VariantProtocolPair Variant = iota
	// VariantPeerTrustStaleMembership enables peer trust with an empty trust-group
	// fixture (no directory services) and a zero-TTL membership cache overlay.
	VariantPeerTrustStaleMembership
	// VariantSSRFStrictRedirect keeps SSRF strict with redirect governance for
	// redirect/SSRF negative tests.
	VariantSSRFStrictRedirect
)

// StrictProtocolPairExtraConfigOptions tunes the extra TOML appended to the
// integration subprocess harness for strict protocol pair fixtures.
type StrictProtocolPairExtraConfigOptions struct {
	ModuleRoot   string
	LoopbackHost string
	AllowedPorts []int
	Variant      Variant
}

// StrictProtocolTLSRootCA returns the shared test CA bundle for static TLS in
// strict protocol integration tests.
func StrictProtocolTLSRootCA(moduleRoot string) string {
	return filepath.Join(moduleRoot, "tests", "ca_pool", "testdata", "certificate-authority", "dockypody.crt")
}

// StrictProtocolPairExtraConfig returns TOML appended to the subprocess harness
// config. public_origin, listen_addr, outbound_http baseline, and
// tls_root_ca_file remain owned by harness.SubprocessConfig fields.
func StrictProtocolPairExtraConfig(opts StrictProtocolPairExtraConfigOptions) string {
	tlsCert := filepath.Join(opts.ModuleRoot, "tests", "e2e", "testdata", "tls", "localhost.crt")
	tlsKey := filepath.Join(opts.ModuleRoot, "tests", "e2e", "testdata", "tls", "localhost.key")

	cfg := fmt.Sprintf(`
[tls]
mode = "static"
cert_file = %q
key_file = %q

[persistence]
backend = "json"
data_dir = "data"

[outbound_http.ssrf]
mode = "strict"
route_policy = "loopback"

[outbound_http.ssrf.route_policies.loopback]
allow_private_host_suffixes = [%q, "localhost"]
allow_private_cidrs = ["127.0.0.0/8", "::1/128"]
allowed_ports = [%s]
allow_ip_literals = false
`, tlsCert, tlsKey, opts.LoopbackHost, formatPortList(opts.AllowedPorts))

	switch opts.Variant {
	case VariantProtocolPair:
		// no variant-specific block; base config suffices
	case VariantPeerTrustStaleMembership:
		cfg += `
[peer_trust]
enabled = true
config_paths = ["trust-group.json"]

[peer_trust.membership_cache]
ttl_seconds = 0
max_stale_seconds = 600
`
	case VariantSSRFStrictRedirect:
		// Redirect governance is covered by the harness base [outbound_http] block
		// (max_redirects = 1). This variant marks redirect/SSRF negative tests only.
	}

	return cfg
}

func formatPortList(ports []int) string {
	if len(ports) == 0 {
		return ""
	}

	parts := make([]string, len(ports))
	for i, p := range ports {
		parts[i] = fmt.Sprintf("%d", p)
	}

	return strings.Join(parts, ", ")
}
