// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package policy_test

import (
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/policy"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
)

// TestPeerMapping_OverlayTruthTable covers the two relaxable peer_compat knobs
// at each merge tier. Merge order is instance > platform > global config
// > CodeFlow baseline; nil inherits the parent value (default true).
// The global tier also covers the http-sig knob; platform and instance tiers do
// not carry it because per-peer http-sig overrides were removed.
func TestPeerMapping_OverlayTruthTable(t *testing.T) {
	falseVal := false
	trueVal := true

	const (
		host         = "host.example"
		platformName = "platform-a"
	)

	const (
		fieldIncludes = "IncludesTokenExchangeRequirement"
		fieldRequires = "RequiresTokenExchangeRequirement"
		fieldHTTP     = "RequiresHTTPRequestSignatures"
	)

	type stateCase struct {
		name  string
		value *bool
		want  bool
	}

	states := []stateCase{
		{name: "nil_inherit", value: nil, want: true},
		{name: "false_relax", value: &falseVal, want: false},
		{name: "true_enforce", value: &trueVal, want: true},
	}

	globalFields := []string{fieldIncludes, fieldRequires, fieldHTTP}
	peerFields := []string{fieldIncludes, fieldRequires}
	tiers := []struct {
		name   string
		fields []string
		scope  config.CompatibilityScope
	}{
		{name: "global", fields: globalFields, scope: config.CompatibilityScopeGlobal},
		{name: "platform", fields: peerFields, scope: config.CompatibilityScopeGlobal},
		{name: "instance", fields: peerFields, scope: config.CompatibilityScopeGlobal},
	}

	for _, tier := range tiers {
		for _, field := range tier.fields {
			for _, st := range states {
				name := field + "/" + tier.name + "/" + st.name
				t.Run(name, func(t *testing.T) {
					global := policy.NewCodeFlow()

					var cfg config.PeerMappingConfig

					switch tier.name {
					case "global":
						cfg = globalConfigWithField(field, st.value)
					case "platform":
						cfg = config.PeerMappingConfig{
							HostPlatform: map[string]string{host: platformName},
							Platform: map[string]config.PeerPlatformOverlay{
								platformName: platformOverlayWithField(field, st.value),
							},
						}
					case "instance":
						cfg = config.PeerMappingConfig{
							Platform: map[string]config.PeerPlatformOverlay{
								platformName: {
									Instance: map[string]config.PeerMappingInstanceOverlay{
										host: instanceOverlayWithField(field, st.value),
									},
								},
							},
						}
					default:
						t.Fatalf("unknown tier %q", tier.name)
					}

					resolver := policy.NewPeerMappingResolver(global, &cfg, tier.scope)
					facts := resolver.ResolveFacts(host)

					got := factForField(field, facts)
					if got != st.want {
						t.Fatalf("merged fact = %v, want %v (facts=%+v)", got, st.want, facts)
					}

					wantBase := policy.NewCodeFlow().Evaluate()
					if field != fieldIncludes && facts.IncludesTokenExchangeRequirement != wantBase.IncludesTokenExchangeRequirement {
						t.Errorf("IncludesTokenExchangeRequirement bled: got %v, want %v",
							facts.IncludesTokenExchangeRequirement, wantBase.IncludesTokenExchangeRequirement)
					}

					if field != fieldRequires && facts.RequiresTokenExchange != wantBase.RequiresTokenExchange {
						t.Errorf("RequiresTokenExchange bled: got %v, want %v",
							facts.RequiresTokenExchange, wantBase.RequiresTokenExchange)
					}

					if field != fieldHTTP && facts.RequiresHTTPRequestSignatures != wantBase.RequiresHTTPRequestSignatures {
						t.Errorf("RequiresHTTPRequestSignatures bled: got %v, want %v",
							facts.RequiresHTTPRequestSignatures, wantBase.RequiresHTTPRequestSignatures)
					}
				})
			}
		}
	}
}

func globalConfigWithField(field string, value *bool) config.PeerMappingConfig {
	var cfg config.PeerMappingConfig

	switch field {
	case "IncludesTokenExchangeRequirement":
		cfg.IncludesTokenExchangeRequirement = value
	case "RequiresTokenExchangeRequirement":
		cfg.RequiresTokenExchangeRequirement = value
	case "RequiresHTTPRequestSignatures":
		cfg.RequiresHTTPRequestSignatures = value
	}

	return cfg
}

func platformOverlayWithField(field string, value *bool) config.PeerPlatformOverlay {
	var overlay config.PeerPlatformOverlay

	switch field {
	case "IncludesTokenExchangeRequirement":
		overlay.IncludesTokenExchangeRequirement = value
	case "RequiresTokenExchangeRequirement":
		overlay.RequiresTokenExchangeRequirement = value
	}

	return overlay
}

func instanceOverlayWithField(field string, value *bool) config.PeerMappingInstanceOverlay {
	var overlay config.PeerMappingInstanceOverlay

	switch field {
	case "IncludesTokenExchangeRequirement":
		overlay.IncludesTokenExchangeRequirement = value
	case "RequiresTokenExchangeRequirement":
		overlay.RequiresTokenExchangeRequirement = value
	}

	return overlay
}

func factForField(field string, facts policy.Facts) bool {
	switch field {
	case "IncludesTokenExchangeRequirement":
		return facts.IncludesTokenExchangeRequirement
	case "RequiresTokenExchangeRequirement":
		return facts.RequiresTokenExchange
	case "RequiresHTTPRequestSignatures":
		return facts.RequiresHTTPRequestSignatures
	default:
		return false
	}
}
