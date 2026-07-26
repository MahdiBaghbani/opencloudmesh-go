// Package policy resolves OCM code-flow facts for peers.
package policy

import (
	"reflect"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/hostport"
)

// DiscoveryView is a placeholder for the peer discovery surface the resolver
// will use once the outbound preflight phase adds peer-discovery accessors.
// The disc parameter is accepted and reserved for upcoming discovery-resolve
// wiring; it is not currently used by the scope-gated logic in ResolveFacts.
type DiscoveryView interface{}

// PeerMappingConfigSource abstracts the peer mapping data the resolver needs.
// It is implemented by config.PeerMappingConfig without importing policy.
type PeerMappingConfigSource interface {
	GlobalKnobs() (includes, requires, http *bool)
	Scheme() string
	HostPlatformFor(host string) (platform string, ok bool)
	PlatformInstanceBinding(host string) (platform string, ok bool)
	PlatformKnobs(platform string) (includes, requires *bool, ok bool)
	InstanceKnobs(platform, host string) (includes, requires *bool, ok bool)
}

// PeerMappingResolver resolves per-peer code-flow facts from the hierarchical
// [ocm.peer_compat] overlay. It is the sole owner of ResolveFacts.
type PeerMappingResolver struct {
	global *CodeFlow
	cfg    PeerMappingConfigSource
	scope  config.CompatibilityScope
}

// NewPeerMappingResolver constructs a resolver from the global code-flow policy,
// a peer mapping config source, and a compatibility scope. Both global and cfg may
// be nil; nil falls back to global facts. The constructor stores scope as given;
// scope validation and normalization happen at config load, not here.
func NewPeerMappingResolver(global *CodeFlow, cfg PeerMappingConfigSource, scope config.CompatibilityScope) *PeerMappingResolver {
	return &PeerMappingResolver{global: global, cfg: cfg, scope: scope}
}

// ResolveFacts is the public naming SSOT for host-facts resolution; keep this name (see architecture ban list).
// ResolveFacts returns the code-flow facts for host and optional discovery.
// Unknown or unmapped hosts skip platform and instance overlays: under global
// scope they get the global CodeFlow facts with global knobs; under scoped
// scope they get the global facts without peer-specific overrides.
// TokenExchangeCapable is always taken from the global policy and never
// modified by the peer overlay.
//
// Under global scope, global peer_compat knobs apply to every host.
// Under scoped scope, peer_compat knobs (global, platform, and instance) apply
// only to explicitly mapped peers. Unmapped peers receive the global CodeFlow
// facts without any peer_compat overlay.
//
// The disc parameter is accepted for signature stability and reserved for
// upcoming discovery-resolve wiring. It is not consulted by the current
// scope-gated logic; mapped hosts apply platform and instance overlays based
// solely on host-key resolution, and unmapped hosts fall back to the global
// CodeFlow facts (or global knobs under global scope).
func (r *PeerMappingResolver) ResolveFacts(host string, disc DiscoveryView) Facts {
	facts := Facts{}
	if r.global != nil {
		facts = r.global.Evaluate()
	}

	if isConfigNil(r.cfg) {
		return facts
	}

	norm, err := hostport.Normalize(host, r.cfg.Scheme())
	if err != nil {
		// Unnormalizable hosts are treated as unmapped.
		if r.scope == config.CompatibilityScopeScoped {
			return facts
		}
		return r.applyGlobalKnobs(facts)
	}

	if platform, mapped := r.resolvePlatform(norm); mapped {
		return r.applyMappedFacts(facts, platform, norm)
	}

	if r.scope == config.CompatibilityScopeScoped {
		return facts
	}
	return r.applyGlobalKnobs(facts)
}

func (r *PeerMappingResolver) applyGlobalKnobs(facts Facts) Facts {
	if isConfigNil(r.cfg) {
		return facts
	}
	includes, requires, http := r.cfg.GlobalKnobs()
	facts.IncludesTokenExchangeRequirement = mergeBool(facts.IncludesTokenExchangeRequirement, includes)
	facts.RequiresTokenExchange = mergeBool(facts.RequiresTokenExchange, requires)
	facts.RequiresHTTPRequestSignatures = mergeBool(facts.RequiresHTTPRequestSignatures, http)
	return facts
}

func (r *PeerMappingResolver) applyMappedFacts(facts Facts, platform, norm string) Facts {
	facts = r.applyGlobalKnobs(facts)

	if includes, requires, ok := r.cfg.PlatformKnobs(platform); ok {
		facts.IncludesTokenExchangeRequirement = mergeBool(facts.IncludesTokenExchangeRequirement, includes)
		facts.RequiresTokenExchange = mergeBool(facts.RequiresTokenExchange, requires)
	}
	if includes, requires, ok := r.cfg.InstanceKnobs(platform, norm); ok {
		facts.IncludesTokenExchangeRequirement = mergeBool(facts.IncludesTokenExchangeRequirement, includes)
		facts.RequiresTokenExchange = mergeBool(facts.RequiresTokenExchange, requires)
	}
	return facts
}

func (r *PeerMappingResolver) resolvePlatform(host string) (string, bool) {
	if isConfigNil(r.cfg) {
		return "", false
	}
	if platform, ok := r.cfg.PlatformInstanceBinding(host); ok {
		return platform, true
	}
	if platform, ok := r.cfg.HostPlatformFor(host); ok {
		return platform, true
	}
	return "", false
}

func mergeBool(base bool, overlay *bool) bool {
	if overlay == nil {
		return base
	}
	return *overlay
}

func isConfigNil(cfg PeerMappingConfigSource) bool {
	return isInterfaceValueNil(cfg)
}

func isInterfaceValueNil(v any) bool {
	if v == nil {
		return true
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Ptr, reflect.Interface, reflect.Slice, reflect.Map, reflect.Chan, reflect.Func:
		return rv.IsNil()
	default:
		return false
	}
}
