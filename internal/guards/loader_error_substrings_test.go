// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 OpenCloudMesh Authors

// G0.1: regression guard for loader error message inventory.
//
// Before splitting or refactoring loader.go, these 34 substrings must appear
// in at least one of: loader_test.go assertion strings OR loader.go error
// message literals. If a substring vanishes from both files, the guard fails
// with a clear message identifying which strings were lost.
//
// Categories:
//   - compatibility_scope=none  (16 strings)
//   - ssrf                      (9 strings)
//   - proxy                     (3 strings)
//   - route_policy / scoped     (6 strings)
package guards

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// loaderErrorSubstrings is the read-only inventory of error substrings that
// must remain present in loader.go error messages or loader_test.go assertions.
var loaderErrorSubstrings = []struct {
	category string
	substr   string
}{
	// compatibility_scope=none
	{"compatibility_scope=none", "compatibility_scope=none requires signature.inbound_mode=strict"},
	{"compatibility_scope=none", "compatibility_scope=none requires signature.outbound_mode=strict"},
	{"compatibility_scope=none", "compatibility_scope=none requires signature.peer_profile_level_override=off"},
	{"compatibility_scope=none", "compatibility_scope=none requires signature.on_discovery_error=reject"},
	{"compatibility_scope=none", "compatibility_scope=none requires signature.allow_mismatch=false"},
	{"compatibility_scope=none", "compatibility_scope=none requires require_token_exchange=true"},
	{"compatibility_scope=none", "compatibility_scope=none requires peer_policy=strict"},
	{"compatibility_scope=none", "compatibility_scope=none requires peer_trust.policy.global_enforce=true when peer trust is enabled"},
	{"compatibility_scope=none", "compatibility_scope=none requires outbound_http.ssrf.mode=strict"},
	{"compatibility_scope=none", "compatibility_scope=none requires tls.mode!=off"},
	{"compatibility_scope=none", "compatibility_scope=none requires outbound_http.insecure_skip_verify=false"},
	{"compatibility_scope=none", "compatibility_scope=none forbids peer_profiles.mappings"},
	{"compatibility_scope=none", "compatibility_scope=none forbids peer_profiles.custom_profiles.peer-a.allow_unsigned_inbound"},
	{"compatibility_scope=none", "compatibility_scope=none forbids peer_profiles.custom_profiles.peer-a.allow_unsigned_outbound"},
	{"compatibility_scope=none", "compatibility_scope=none forbids peer_profiles.custom_profiles.peer-a.allow_http"},
	{"compatibility_scope=none", "compatibility_scope=none forbids peer_profiles.custom_profiles.peer-a.token_exchange_quirks"},

	// ssrf
	{"ssrf", "outbound_http.ssrf_mode"},
	{"ssrf", "invalid outbound_http.ssrf.mode"},
	{"ssrf", "outbound_http.ssrf.redirect_mode"},
	{"ssrf", "outbound_http.ssrf.dns_resolution"},
	{"ssrf", "allow_ip_literals=false"},
	{"ssrf", "0.0.0.0/0"},
	{"ssrf", "allow_private_host_suffixes"},
	{"ssrf", "invalid CIDR"},
	{"ssrf", "invalid port"},

	// proxy
	{"proxy", "proxy_url"},
	{"proxy", "must be an absolute URL with http or https scheme"},
	{"proxy", "must not include userinfo"},

	// route_policy (scoped compatibility enforcement)
	{"route_policy", "compatibility_scope=scoped requires signature.inbound_mode=strict"},
	{"route_policy", "compatibility_scope=scoped requires signature.outbound_mode=strict"},
	{"route_policy", "compatibility_scope=scoped requires signature.peer_profile_level_override!=all"},
	{"route_policy", "compatibility_scope=scoped requires signature.on_discovery_error=reject"},
	{"route_policy", "compatibility_scope=scoped requires outbound_http.ssrf.mode=strict"},
	{"route_policy", "compatibility_scope=scoped requires tls.mode!=off"},
}

func TestLoaderErrorSubstrings_InventoryPresent(t *testing.T) {
	repoRoot := findRepoRoot(t)

	loaderPath := filepath.Join(repoRoot, "internal", "platform", "config", "loader.go")
	loaderTestPath := filepath.Join(repoRoot, "internal", "platform", "config", "loader_test.go")

	loaderBytes, err := os.ReadFile(loaderPath)
	if err != nil {
		t.Fatalf("read loader.go: %v", err)
	}
	loaderTestBytes, err := os.ReadFile(loaderTestPath)
	if err != nil {
		t.Fatalf("read loader_test.go: %v", err)
	}

	loaderSrc := string(loaderBytes)
	loaderTestSrc := string(loaderTestBytes)

	var missing []string
	for _, entry := range loaderErrorSubstrings {
		inLoader := strings.Contains(loaderSrc, entry.substr)
		inLoaderTest := strings.Contains(loaderTestSrc, entry.substr)
		if !inLoader && !inLoaderTest {
			missing = append(
				missing,
				"["+entry.category+"] "+entry.substr,
			)
		}
	}

	if len(missing) > 0 {
		t.Fatalf(
			"G0.1: %d error substring(s) missing from both loader.go and loader_test.go.\n"+
				"Update the inventory in loader_error_substrings_test.go to reflect the new\n"+
				"error message wording before proceeding with the loader refactor.\n\nMissing:\n  %s",
			len(missing),
			strings.Join(missing, "\n  "),
		)
	}
}
