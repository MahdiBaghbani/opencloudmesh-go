package policy_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/policy"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
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
	resolver := policy.NewPeerMappingResolver(codeFlowFromConfig(cfg), &cfg.OCM.PeerMapping)
	facts := resolver.ResolveFacts("any-host.example", nil)
	want := policy.NewCodeFlow().Evaluate()
	if facts != want {
		t.Fatalf("ResolveFacts(anyHost, nil) = %+v, want %+v", facts, want)
	}
}

func TestPeerMapping_FailClosedMatrix(t *testing.T) {
	cfg, err := config.Load(config.LoaderOptions{})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	resolver := policy.NewPeerMappingResolver(codeFlowFromConfig(cfg), &cfg.OCM.PeerMapping)

	t.Run("empty config four facts true", func(t *testing.T) {
		facts := resolver.ResolveFacts("any-host.example", &spec.Discovery{})
		assertAllFactsTrue(t, facts)
	})
	t.Run("nil discovery global facts", func(t *testing.T) {
		facts := resolver.ResolveFacts("any-host.example", nil)
		assertAllFactsTrue(t, facts)
	})
	t.Run("unknown host global strict", func(t *testing.T) {
		facts := resolver.ResolveFacts("unknown.example", &spec.Discovery{})
		assertAllFactsTrue(t, facts)
	})
	t.Run("token exchange capable invariant on mapped host", func(t *testing.T) {
		falseVal := false
		overlayCfg := config.PeerMappingConfig{
			HostPlatform: map[string]string{
				"any-host.example": "platform-a",
			},
			Platform: map[string]config.PeerPlatformOverlay{
				"platform-a": {
					RequiresHTTPRequestSignatures: &falseVal,
					Instance: map[string]config.PeerMappingInstanceOverlay{
						"any-host.example": {
							RequiresTokenExchangeRequirement: &falseVal,
						},
					},
				},
			},
		}
		overlayResolver := policy.NewPeerMappingResolver(codeFlowFromConfig(cfg), &overlayCfg)
		facts := overlayResolver.ResolveFacts("any-host.example", &spec.Discovery{})
		if !facts.TokenExchangeCapable {
			t.Error("TokenExchangeCapable must stay true from global Evaluate on mapped host")
		}
	})
}

func TestPeerMapping_InstanceOverridesPlatformOverridesGlobal(t *testing.T) {
	falseVal := false
	trueVal := true
	cfg := config.PeerMappingConfig{
		RequiresHTTPRequestSignatures: &trueVal,
		HostPlatform: map[string]string{
			"other.example": "platform-a",
		},
		Platform: map[string]config.PeerPlatformOverlay{
			"platform-a": {
				RequiresHTTPRequestSignatures: &falseVal,
				Instance: map[string]config.PeerMappingInstanceOverlay{
					"host.example": {
						RequiresHTTPRequestSignatures: &trueVal,
					},
				},
			},
		},
	}
	resolver := policy.NewPeerMappingResolver(policy.NewCodeFlow(), &cfg)
	facts := resolver.ResolveFacts("host.example", &spec.Discovery{})
	if !facts.RequiresHTTPRequestSignatures {
		t.Error("instance true should enforce the knob")
	}

	// host mapped to platform but without instance override should use platform value
	facts = resolver.ResolveFacts("other.example", &spec.Discovery{})
	if facts.RequiresHTTPRequestSignatures {
		t.Error("platform false should relax the knob for other host in platform")
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
				RequiresHTTPRequestSignatures: &falseVal,
			},
		},
	}
	resolver := policy.NewPeerMappingResolver(policy.NewCodeFlow(), &cfg)
	facts := resolver.ResolveFacts("host.example", &spec.Discovery{})
	if facts.RequiresHTTPRequestSignatures {
		t.Error("host_platform lookup should apply platform overlay")
	}
}

func TestPeerMapping_TypedNilDiscoveryFallback(t *testing.T) {
	resolver := policy.NewPeerMappingResolver(policy.NewCodeFlow(), &config.PeerMappingConfig{})
	var disc *spec.Discovery
	facts := resolver.ResolveFacts("unknown.example", disc)
	want := resolver.ResolveFacts("unknown.example", nil)
	if facts != want {
		t.Fatalf("typed-nil discovery should fall back to global facts: got %+v, want %+v", facts, want)
	}
}

func TestPeerMapping_TypedNilConfig_NoPanicFallsBackToGlobal(t *testing.T) {
	globalCodeFlow := policy.NewCodeFlow()
	var typedNilCfg *config.PeerMappingConfig
	var cfgSource policy.PeerMappingConfigSource = typedNilCfg
	resolver := policy.NewPeerMappingResolver(globalCodeFlow, cfgSource)
	facts := resolver.ResolveFacts("any-host.example", nil)
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
				RequiresHTTPRequestSignatures: &falseVal,
			},
		},
	}
	resolver := policy.NewPeerMappingResolver(policy.NewCodeFlow(), &cfg)
	facts := resolver.ResolveFacts("host.example:443", &spec.Discovery{})
	if facts.RequiresHTTPRequestSignatures {
		t.Error("raw host with default port should resolve to normalized key")
	}
}

func TestPeerMapping_GlobalNilInheritsCodeFlowBaseline(t *testing.T) {
	global := policy.NewCodeFlow()
	resolver := policy.NewPeerMappingResolver(global, &config.PeerMappingConfig{})
	facts := resolver.ResolveFacts("any-host.example", nil)
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
				RequiresHTTPRequestSignatures: &falseVal,
			},
			"platform-b": {
				RequiresHTTPRequestSignatures: &trueVal,
				Instance: map[string]config.PeerMappingInstanceOverlay{
					"host.example": {},
				},
			},
		},
	}
	resolver := policy.NewPeerMappingResolver(policy.NewCodeFlow(), &cfg)
	facts := resolver.ResolveFacts("host.example", &spec.Discovery{})
	if !facts.RequiresHTTPRequestSignatures {
		t.Error("instance binding should win over host_platform mapping")
	}
}

func TestPeerMapping_MappedHostNilDiscoveryAppliesOverlay(t *testing.T) {
	falseVal := false
	cfg := config.PeerMappingConfig{
		HostPlatform: map[string]string{
			"host.example": "platform-a",
		},
		Platform: map[string]config.PeerPlatformOverlay{
			"platform-a": {
				RequiresHTTPRequestSignatures: &falseVal,
			},
		},
	}
	resolver := policy.NewPeerMappingResolver(policy.NewCodeFlow(), &cfg)
	facts := resolver.ResolveFacts("host.example", nil)
	if facts.RequiresHTTPRequestSignatures {
		t.Error("mapped host with nil discovery should still apply platform overlay")
	}
}

// TestPeerMapping_OverlayTruthTable covers the three relaxable knobs at each
// ResolveFacts merge tier. Merge order is instance > platform > global config
// > CodeFlow baseline; nil inherits the parent value (default true).
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
	fields := []string{fieldIncludes, fieldRequires, fieldHTTP}
	tiers := []string{"global", "platform", "instance"}

	for _, field := range fields {
		for _, tier := range tiers {
			for _, st := range states {
				name := field + "/" + tier + "/" + st.name
				t.Run(name, func(t *testing.T) {
					var global *policy.CodeFlow
					var cfg config.PeerMappingConfig

					switch tier {
					case "global":
						// Global tier is [ocm.peer_compat] top-level knobs over the
						// CodeFlow baseline.
						global = policy.NewCodeFlow()
						cfg = globalConfigWithField(field, st.value)
					case "platform":
						global = policy.NewCodeFlow()
						cfg = config.PeerMappingConfig{
							HostPlatform: map[string]string{host: platformName},
							Platform: map[string]config.PeerPlatformOverlay{
								platformName: platformOverlayWithField(field, st.value),
							},
						}
					case "instance":
						global = policy.NewCodeFlow()
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
						t.Fatalf("unknown tier %q", tier)
					}

					resolver := policy.NewPeerMappingResolver(global, &cfg)
					facts := resolver.ResolveFacts(host, &spec.Discovery{})
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
	case "RequiresHTTPRequestSignatures":
		overlay.RequiresHTTPRequestSignatures = value
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
	case "RequiresHTTPRequestSignatures":
		overlay.RequiresHTTPRequestSignatures = value
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
