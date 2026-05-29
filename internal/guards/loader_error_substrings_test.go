// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 OpenCloudMesh Authors

// G0.1: regression guard for loader error message inventory.
//
// Before splitting or refactoring loader.go, these 34 substrings must appear
// somewhere in the loader area: either a loader*.go test assertion string or a
// loader.go error message literal. The Q2 split spread these assertions across
// dedicated files (for example loader_compatibility_scope_test.go and
// loader_ssrf_test.go), so the guard scans every loader*.go file in
// internal/platform/config/. If a substring vanishes from all of them, the
// guard fails with a clear message identifying which strings were lost.
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
// must remain present somewhere across the loader*.go files in
// internal/platform/config/ (source error literals or test assertions).
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
	// These must stay uniquely proxy-scoped. The trailing text "must be an
	// absolute URL with http or https scheme" and "must not include userinfo"
	// is shared with public_origin validation, so the entries pin the full
	// "invalid outbound_http.proxy_url" prefix to keep proxy coverage honest.
	{"proxy", "proxy_url"},
	{"proxy", "invalid outbound_http.proxy_url %q: must be an absolute URL with http or https scheme"},
	{"proxy", "invalid outbound_http.proxy_url %q: must not include userinfo"},

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

	configDir := filepath.Join(repoRoot, "internal", "platform", "config")
	loaderFiles, err := filepath.Glob(filepath.Join(configDir, "loader*.go"))
	if err != nil {
		t.Fatalf("glob loader*.go: %v", err)
	}
	if len(loaderFiles) == 0 {
		t.Fatalf("G0.1: no loader*.go files found in %s", configDir)
	}

	var combined strings.Builder
	for _, path := range loaderFiles {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		combined.Write(data)
		combined.WriteByte('\n')
	}
	loaderArea := combined.String()

	var missing []string
	for _, entry := range loaderErrorSubstrings {
		if !strings.Contains(loaderArea, entry.substr) {
			missing = append(
				missing,
				"["+entry.category+"] "+entry.substr,
			)
		}
	}

	if len(missing) > 0 {
		t.Fatalf(
			"G0.1: %d error substring(s) missing from all loader*.go files in\n"+
				"internal/platform/config/ (%d file(s) scanned).\n"+
				"Update the inventory in loader_error_substrings_test.go to reflect the new\n"+
				"error message wording before proceeding with the loader refactor.\n\nMissing:\n  %s",
			len(missing),
			len(loaderFiles),
			strings.Join(missing, "\n  "),
		)
	}
}
