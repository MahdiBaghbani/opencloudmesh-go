// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package policy_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/policy"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
)

// Naming guardrail: the peer mapping surface uses only the PeerMapping* and
// PeerPlatformOverlay identifier families. Legacy prefixes built from
// Peer+Compat and Peer+Profile are not allowed.
func TestPeerMapping_NamingGuardrail(t *testing.T) {
	policySrc := readPeerMappingSource(t, "peer_mapping.go")
	configSrc := readPeerMappingSource(t, filepath.Join("..", "..", "..", "platform", "config", "peer_mapping.go"))

	combined := policySrc + configSrc
	for _, banned := range []string{"Peer" + "Compat", "Peer" + "Profile"} {
		if strings.Contains(combined, banned) {
			t.Errorf("peer mapping surface contains banned identifier %q", banned)
		}
	}

	for _, required := range []string{"PeerMapping", "PeerPlatformOverlay"} {
		if !strings.Contains(combined, required) {
			t.Errorf("peer mapping surface missing required identifier %q", required)
		}
	}
}

func TestDefaultConfig_ResolveFactsEqualsEvaluate(t *testing.T) {
	cfg, err := config.Load(config.LoaderOptions{})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	resolver := policy.NewPeerMappingResolver(codeFlowFromConfig(cfg), &cfg.OCM.PeerMapping, config.CompatibilityScopeGlobal)
	facts := resolver.ResolveFacts("any-host.example")

	want := policy.NewCodeFlow().Evaluate()
	if facts != want {
		t.Fatalf("ResolveFacts(anyHost) = %+v, want %+v", facts, want)
	}
}

func TestPeerMapping_FailClosedMatrix(t *testing.T) {
	cfg, err := config.Load(config.LoaderOptions{})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	resolver := policy.NewPeerMappingResolver(codeFlowFromConfig(cfg), &cfg.OCM.PeerMapping, config.CompatibilityScopeGlobal)

	t.Run("empty config three facts true", func(t *testing.T) {
		facts := resolver.ResolveFacts("any-host.example")
		assertAllFactsTrue(t, facts)
	})
	t.Run("unknown host global strict", func(t *testing.T) {
		facts := resolver.ResolveFacts("unknown.example")
		assertAllFactsTrue(t, facts)
	})
}

func TestPeerMapping_InstanceOverridesPlatformOverridesGlobal(t *testing.T) {
	falseVal := false
	trueVal := true
	cfg := config.PeerMappingConfig{
		RequiresTokenExchangeRequirement: &trueVal,
		HostPlatform: map[string]string{
			"other.example": "platform-a",
		},
		Platform: map[string]config.PeerPlatformOverlay{
			"platform-a": {
				RequiresTokenExchangeRequirement: &falseVal,
				Instance: map[string]config.PeerMappingInstanceOverlay{
					"host.example": {
						RequiresTokenExchangeRequirement: &trueVal,
					},
				},
			},
		},
	}
	resolver := policy.NewPeerMappingResolver(policy.NewCodeFlow(), &cfg, config.CompatibilityScopeGlobal)

	facts := resolver.ResolveFacts("host.example")
	if !facts.RequiresTokenExchange {
		t.Error("instance true should enforce the token-exchange knob")
	}

	// host mapped to platform but without instance override should use platform value
	facts = resolver.ResolveFacts("other.example")
	if facts.RequiresTokenExchange {
		t.Error("platform false should relax the token-exchange knob for other host in platform")
	}
}

func TestPeerMapping_HostPlatformLookup(t *testing.T) {
	falseVal := false
	cfg := config.PeerMappingConfig{
		HostPlatform: map[string]string{
			"host.example": "platform-a",
		},
		Platform: map[string]config.PeerPlatformOverlay{
			"platform-a": {
				RequiresTokenExchangeRequirement: &falseVal,
			},
		},
	}
	resolver := policy.NewPeerMappingResolver(policy.NewCodeFlow(), &cfg, config.CompatibilityScopeGlobal)

	facts := resolver.ResolveFacts("host.example")
	if facts.RequiresTokenExchange {
		t.Error("host_platform lookup should apply platform overlay")
	}
}

func TestPeerMapping_TypedNilConfig_NoPanicFallsBackToGlobal(t *testing.T) {
	globalCodeFlow := policy.NewCodeFlow()

	var (
		typedNilCfg *config.PeerMappingConfig
		cfgSource   policy.PeerMappingConfigSource = typedNilCfg
	)

	resolver := policy.NewPeerMappingResolver(globalCodeFlow, cfgSource, config.CompatibilityScopeGlobal)
	facts := resolver.ResolveFacts("any-host.example")

	want := globalCodeFlow.Evaluate()
	if facts != want {
		t.Fatalf("typed-nil config should fall back to CodeFlow baseline: got %+v, want %+v", facts, want)
	}
}

func TestPeerMapping_NormalizedHostLookup(t *testing.T) {
	falseVal := false
	cfg := config.PeerMappingConfig{
		HostPlatform: map[string]string{
			"host.example": "platform-a",
		},
		Platform: map[string]config.PeerPlatformOverlay{
			"platform-a": {
				RequiresTokenExchangeRequirement: &falseVal,
			},
		},
	}
	resolver := policy.NewPeerMappingResolver(policy.NewCodeFlow(), &cfg, config.CompatibilityScopeGlobal)

	facts := resolver.ResolveFacts("host.example:443")
	if facts.RequiresTokenExchange {
		t.Error("raw host with default port should resolve to normalized key")
	}
}

func TestPeerMapping_GlobalNilInheritsCodeFlowBaseline(t *testing.T) {
	global := policy.NewCodeFlow()
	resolver := policy.NewPeerMappingResolver(global, &config.PeerMappingConfig{}, config.CompatibilityScopeGlobal)
	facts := resolver.ResolveFacts("any-host.example")

	want := global.Evaluate()
	if facts != want {
		t.Fatalf("global nil knobs should inherit CodeFlow baseline: got %+v, want %+v", facts, want)
	}
}

func TestPeerMapping_InstanceBindingPrecedenceOverHostPlatform(t *testing.T) {
	falseVal := false
	trueVal := true
	cfg := config.PeerMappingConfig{
		HostPlatform: map[string]string{
			"host.example": "platform-a",
		},
		Platform: map[string]config.PeerPlatformOverlay{
			"platform-a": {
				RequiresTokenExchangeRequirement: &falseVal,
			},
			"platform-b": {
				RequiresTokenExchangeRequirement: &trueVal,
				Instance: map[string]config.PeerMappingInstanceOverlay{
					"host.example": {},
				},
			},
		},
	}
	resolver := policy.NewPeerMappingResolver(policy.NewCodeFlow(), &cfg, config.CompatibilityScopeGlobal)

	facts := resolver.ResolveFacts("host.example")
	if !facts.RequiresTokenExchange {
		t.Error("instance binding should win over host_platform mapping")
	}
}

func TestPeerMapping_MappedHostAppliesPlatformOverlay(t *testing.T) {
	falseVal := false
	cfg := config.PeerMappingConfig{
		HostPlatform: map[string]string{
			"host.example": "platform-a",
		},
		Platform: map[string]config.PeerPlatformOverlay{
			"platform-a": {
				RequiresTokenExchangeRequirement: &falseVal,
			},
		},
	}
	resolver := policy.NewPeerMappingResolver(policy.NewCodeFlow(), &cfg, config.CompatibilityScopeGlobal)

	facts := resolver.ResolveFacts("host.example")
	if facts.RequiresTokenExchange {
		t.Error("mapped host should apply platform overlay")
	}
}

// TestPeerMapping_GlobalScope_KnobsApplyToUnmappedHost confirms that under the
// default global scope, global peer_compat knobs are merged for every host.
func TestPeerMapping_GlobalScope_KnobsApplyToUnmappedHost(t *testing.T) {
	falseVal := false
	cfg := config.PeerMappingConfig{
		RequiresTokenExchangeRequirement: &falseVal,
	}
	resolver := policy.NewPeerMappingResolver(policy.NewCodeFlow(), &cfg, config.CompatibilityScopeGlobal)

	facts := resolver.ResolveFacts("unmapped.example")
	if facts.RequiresTokenExchange {
		t.Error("global scope should apply global knobs to unmapped hosts")
	}
}

// TestPeerMapping_ScopedScope_KnobsApplyToMappedHost confirms that under scoped
// scope, peer_compat knobs still apply to explicitly mapped peers.
func TestPeerMapping_ScopedScope_KnobsApplyToMappedHost(t *testing.T) {
	falseVal := false
	cfg := config.PeerMappingConfig{
		RequiresTokenExchangeRequirement: &falseVal,
		HostPlatform: map[string]string{
			"mapped.example": "platform-a",
		},
	}
	resolver := policy.NewPeerMappingResolver(policy.NewCodeFlow(), &cfg, config.CompatibilityScopeScoped)

	facts := resolver.ResolveFacts("mapped.example")
	if facts.RequiresTokenExchange {
		t.Error("scoped scope should apply global knobs to mapped hosts")
	}
}

// TestPeerMapping_ScopedScope_KnobsDoNotApplyToUnmappedHost confirms that under
// scoped scope, global peer_compat knobs are not leaked to unknown peers.
func TestPeerMapping_ScopedScope_KnobsDoNotApplyToUnmappedHost(t *testing.T) {
	falseVal := false
	cfg := config.PeerMappingConfig{
		RequiresTokenExchangeRequirement: &falseVal,
	}
	resolver := policy.NewPeerMappingResolver(policy.NewCodeFlow(), &cfg, config.CompatibilityScopeScoped)

	facts := resolver.ResolveFacts("unmapped.example")
	if !facts.RequiresTokenExchange {
		t.Error("scoped scope must not leak global knobs to unmapped hosts")
	}
}

// TestPeerMapping_ScopedScope_UnmappedHostFallsBackToGlobalFacts confirms that
// scoped scope still leaves unmapped hosts with the global CodeFlow baseline.
func TestPeerMapping_ScopedScope_UnmappedHostFallsBackToGlobalFacts(t *testing.T) {
	cfg := config.PeerMappingConfig{}
	resolver := policy.NewPeerMappingResolver(policy.NewCodeFlow(), &cfg, config.CompatibilityScopeScoped)
	facts := resolver.ResolveFacts("unmapped.example")

	want := policy.NewCodeFlow().Evaluate()
	if facts != want {
		t.Fatalf("unmapped host under scoped scope should equal global CodeFlow facts: got %+v, want %+v", facts, want)
	}
}

// TestPeerMapping_PerPeerHTTPSigRemoved confirms that the peer_compat overlay
// no longer carries a per-peer HTTP signature knob. HTTP signature admission is
// governed by the must-use-http-sig criterion and Applicability rules, not by
// platform or instance compatibility overrides. The global peer_compat http-sig
// knob still applies (under the scope gate), but platform/instance cannot touch it.
func TestPeerMapping_PerPeerHTTPSigRemoved(t *testing.T) {
	trueVal := true
	cfg := config.PeerMappingConfig{
		RequiresHTTPRequestSignatures: &trueVal,
		HostPlatform: map[string]string{
			"mapped.example": "platform-a",
		},
		Platform: map[string]config.PeerPlatformOverlay{
			"platform-a": {
				// No RequiresHTTPRequestSignatures field on the platform overlay.
			},
		},
	}
	resolver := policy.NewPeerMappingResolver(policy.NewCodeFlow(), &cfg, config.CompatibilityScopeGlobal)

	facts := resolver.ResolveFacts("mapped.example")
	if !facts.RequiresHTTPRequestSignatures {
		t.Error("global peer_compat http-sig knob should still apply to mapped hosts under global scope")
	}

	// Per-peer http-sig removal: the platform and instance overlay types expose
	// no RequiresHTTPRequestSignatures field, so a mapped host cannot relax or
	// enforce http-sig independently of the global knob. With no global http-sig
	// knob set, the mapped host must inherit the CodeFlow baseline rather than
	// pick up a per-peer override.
	peerOnlyCfg := config.PeerMappingConfig{
		HostPlatform: map[string]string{
			"mapped.example": "platform-a",
		},
		Platform: map[string]config.PeerPlatformOverlay{
			"platform-a": {
				RequiresTokenExchangeRequirement: &trueVal,
			},
		},
	}
	peerOnlyResolver := policy.NewPeerMappingResolver(policy.NewCodeFlow(), &peerOnlyCfg, config.CompatibilityScopeGlobal)
	peerFacts := peerOnlyResolver.ResolveFacts("mapped.example")

	baseline := policy.NewCodeFlow().Evaluate()
	if peerFacts.RequiresHTTPRequestSignatures != baseline.RequiresHTTPRequestSignatures {
		t.Errorf("per-peer overlay must not touch http-sig: got %v, want baseline %v",
			peerFacts.RequiresHTTPRequestSignatures, baseline.RequiresHTTPRequestSignatures)
	}
}

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

func codeFlowFromConfig(cfg *config.Config) *policy.CodeFlow {
	return &policy.CodeFlow{
		IncludesTokenExchangeRequirement: cfg.OCM.CodeFlow.IncludesTokenExchangeRequirement,
		RequiresTokenExchangeRequirement: cfg.OCM.CodeFlow.RequiresTokenExchangeRequirement,
		RequiresHTTPRequestSignatures:    cfg.OCM.CodeFlow.RequiresHTTPRequestSignatures,
	}
}

func readPeerMappingSource(t *testing.T, rel string) string {
	t.Helper()

	data, err := os.ReadFile(rel)
	if err != nil {
		t.Fatalf("read source %q: %v", rel, err)
	}

	return string(data)
}
