// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2025 OpenCloudMesh Authors

package architecture

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/testsupport/modroot"
)

var loaderErrorSubstrings = []struct {
	category string
	substr   string
}{
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

	{"ssrf", "outbound_http.ssrf_mode"},
	{"ssrf", "invalid outbound_http.ssrf.mode"},
	{"ssrf", "outbound_http.ssrf.redirect_mode"},
	{"ssrf", "outbound_http.ssrf.dns_resolution"},
	{"ssrf", "allow_ip_literals=false"},
	{"ssrf", "0.0.0.0/0"},
	{"ssrf", "allow_private_host_suffixes"},
	{"ssrf", "invalid CIDR"},
	{"ssrf", "invalid port"},

	{"proxy", "proxy_url"},
	{"proxy", "invalid outbound_http.proxy_url %q: must be an absolute URL with http or https scheme"},
	{"proxy", "invalid outbound_http.proxy_url %q: must not include userinfo"},

	{"route_policy", "compatibility_scope=scoped requires signature.inbound_mode=strict"},
	{"route_policy", "compatibility_scope=scoped requires signature.outbound_mode=strict"},
	{"route_policy", "compatibility_scope=scoped requires signature.peer_profile_level_override!=all"},
	{"route_policy", "compatibility_scope=scoped requires signature.on_discovery_error=reject"},
	{"route_policy", "compatibility_scope=scoped requires outbound_http.ssrf.mode=strict"},
	{"route_policy", "compatibility_scope=scoped requires tls.mode!=off"},
}

func TestLoaderErrorSubstringsInventoryPresent(t *testing.T) {
	root := modroot.ModuleRoot(t)

	configDir := filepath.Join(root, "internal", "platform", "config")
	loaderFiles, err := filepath.Glob(filepath.Join(configDir, "loader*.go"))
	if err != nil {
		t.Fatalf("glob loader*.go: %v", err)
	}
	if len(loaderFiles) == 0 {
		t.Fatalf("no loader*.go files found in %s", configDir)
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
			"%d error substring(s) missing from all loader*.go files in\n"+
				"internal/platform/config/ (%d file(s) scanned).\n\nMissing:\n  %s",
			len(missing),
			len(loaderFiles),
			strings.Join(missing, "\n  "),
		)
	}
}
