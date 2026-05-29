// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 OpenCloudMesh Authors

// Package configfixture provides reusable TOML string fragments for config
// loader tests. It deliberately does not import internal/platform/config to
// avoid import cycles: loader_test.go is package config, and
// internal/ocmtest/helpers.go already imports config, so loader_test.go
// cannot import ocmtest directly. This subpackage has no such constraint.
//
// Usage pattern: compose fragments with string concatenation.
//
//	tomlContent := configfixture.NoneScopeBase() +
//	    configfixture.SSRFStrictWithPolicy("internal") +
//	    configfixture.RoutePolicyInternal("internal")
//
// Each fragment starts with "\n" so that concatenation naturally produces a
// blank-line separator between TOML sections. TOML parsers ignore leading
// whitespace, so an extra leading newline on the assembled string is harmless.
package configfixture

import "fmt"

// NoneScopeBase returns the TOML header for a compatibility_scope=none strict
// config: mode=strict + explicit compatibility_scope=none.
func NoneScopeBase() string {
	return "\nmode = \"strict\"\ncompatibility_scope = \"none\"\n"
}

// ScopedScopeBase returns the TOML header for a compatibility_scope=scoped
// strict config: mode=strict + compatibility_scope=scoped.
func ScopedScopeBase() string {
	return "\nmode = \"strict\"\ncompatibility_scope = \"scoped\"\n"
}

// SSRFOff returns an [outbound_http.ssrf] block with mode=off.
func SSRFOff() string {
	return "\n[outbound_http.ssrf]\nmode = \"off\"\n"
}

// SSRFStrictWithPolicy returns an [outbound_http.ssrf] block with mode=strict
// and a route_policy reference to policyName.
func SSRFStrictWithPolicy(policyName string) string {
	return fmt.Sprintf(
		"\n[outbound_http.ssrf]\nmode = \"strict\"\nroute_policy = \"%s\"\n",
		policyName,
	)
}

// SSRFRoutePolicyRef returns an [outbound_http.ssrf] block that only sets a
// route_policy reference with no explicit mode. Used where the mode inherits
// from the preset (e.g. blank-host-suffix guardrail tests).
func SSRFRoutePolicyRef(policyName string) string {
	return fmt.Sprintf(
		"\n[outbound_http.ssrf]\nroute_policy = \"%s\"\n",
		policyName,
	)
}

// RoutePolicyInternal returns a standard internal route policy block:
// allow_private_host_suffixes=["svc.cluster.local"], allow_private_cidrs=["10.0.0.0/8"],
// allowed_ports=[8080], allow_ip_literals=false.
func RoutePolicyInternal(policyName string) string {
	return fmt.Sprintf(`
[outbound_http.ssrf.route_policies.%s]
allow_private_host_suffixes = ["svc.cluster.local"]
allow_private_cidrs = ["10.0.0.0/8"]
allowed_ports = [8080]
allow_ip_literals = false
`, policyName)
}

// RoutePolicyInternalIPLiteralsTrue is like RoutePolicyInternal but sets
// allow_ip_literals=true.
func RoutePolicyInternalIPLiteralsTrue(policyName string) string {
	return fmt.Sprintf(`
[outbound_http.ssrf.route_policies.%s]
allow_private_host_suffixes = ["svc.cluster.local"]
allow_private_cidrs = ["10.0.0.0/8"]
allowed_ports = [8080]
allow_ip_literals = true
`, policyName)
}

// RoutePolicyCatchAll returns a route policy with a catch-all CIDR 0.0.0.0/0.
func RoutePolicyCatchAll(policyName string) string {
	return fmt.Sprintf(`
[outbound_http.ssrf.route_policies.%s]
allow_private_host_suffixes = ["svc.cluster.local"]
allow_private_cidrs = ["0.0.0.0/0"]
allowed_ports = [8080]
allow_ip_literals = false
`, policyName)
}

// RoutePolicyMinimalNoSuffixes returns a route policy with an empty
// allow_private_host_suffixes slice.
func RoutePolicyMinimalNoSuffixes(policyName string) string {
	return fmt.Sprintf(`
[outbound_http.ssrf.route_policies.%s]
allow_private_host_suffixes = []
allow_private_cidrs = ["10.0.0.0/8"]
allowed_ports = [8080]
allow_ip_literals = false
`, policyName)
}

// RoutePolicyInternalInvalidCIDR returns an internal-style route policy with
// an invalid CIDR string in allow_private_cidrs.
func RoutePolicyInternalInvalidCIDR(policyName string) string {
	return fmt.Sprintf(`
[outbound_http.ssrf.route_policies.%s]
allow_private_host_suffixes = ["svc.cluster.local"]
allow_private_cidrs = ["not-a-cidr"]
allowed_ports = [8080]
allow_ip_literals = false
`, policyName)
}

// RoutePolicyInternalWithPort returns an internal-style route policy with a
// custom port. port is a raw integer string such as "0" or "65536".
func RoutePolicyInternalWithPort(policyName, port string) string {
	return fmt.Sprintf(`
[outbound_http.ssrf.route_policies.%s]
allow_private_host_suffixes = ["svc.cluster.local"]
allow_private_cidrs = ["10.0.0.0/8"]
allowed_ports = [%s]
allow_ip_literals = false
`, policyName, port)
}

// RoutePolicyWithBlankSuffix returns a route policy where
// allow_private_host_suffixes is set to suffixesLiteral, a raw TOML array
// literal such as `[""]` or `["   "]`. Used to test blank-suffix guardrails
// without duplicating the full policy block.
func RoutePolicyWithBlankSuffix(policyName, suffixesLiteral string) string {
	return fmt.Sprintf(`
[outbound_http.ssrf.route_policies.%s]
allow_private_host_suffixes = %s
allow_private_cidrs = ["10.0.0.0/8"]
allowed_ports = [8080]
allow_ip_literals = false
`, policyName, suffixesLiteral)
}
