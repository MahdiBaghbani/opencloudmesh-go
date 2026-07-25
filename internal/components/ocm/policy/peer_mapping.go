// Package policy resolves OCM code-flow facts for peers.
package policy

import (
	"reflect"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/hostport"
)

// DiscoveryView is a placeholder for the peer discovery surface the resolver
// will use once the outbound preflight phase adds peer-discovery accessors.
// For now ResolveFacts only checks whether a discovery value is present.
type DiscoveryView interface{}

// PeerMappingConfigSource abstracts the peer mapping data the resolver needs.
// It is implemented by config.PeerMappingConfig without importing policy.
type PeerMappingConfigSource interface {
	GlobalKnobs() (includes, requires, http *bool)
	Scheme() string
	HostPlatformFor(host string) (platform string, ok bool)
	PlatformInstanceBinding(host string) (platform string, ok bool)
	PlatformKnobs(platform string) (includes, requires, http *bool, ok bool)
	InstanceKnobs(platform, host string) (includes, requires, http *bool, ok bool)
}

// PeerMappingResolver resolves per-peer code-flow facts from the hierarchical
// [ocm.peer_compat] overlay. It is the sole owner of ResolveFacts.
type PeerMappingResolver struct {
	global *CodeFlow
	cfg    PeerMappingConfigSource
}

// NewPeerMappingResolver constructs a resolver from the global code-flow policy
// and a peer mapping config source. Both may be nil; nil falls back to global
// facts.
func NewPeerMappingResolver(global *CodeFlow, cfg PeerMappingConfigSource) *PeerMappingResolver {
	return &PeerMappingResolver{global: global, cfg: cfg}
}

// ResolveFacts is the public naming SSOT for host-facts resolution; keep this name (see architecture ban list).
// ResolveFacts returns the code-flow facts for host and optional discovery.
// Nil discovery, unknown hosts, or empty overlay all fall back to the global
// CodeFlow Evaluate() facts. TokenExchangeCapable is always taken from the
// global policy and never modified by the peer overlay.
//
// Mapped hosts apply platform and instance overlays regardless of discovery
// state. Discovery is consulted only as a fallback for unmapped hosts.
func (r *PeerMappingResolver) ResolveFacts(host string, disc DiscoveryView) Facts {
	facts := Facts{}
	if r.global != nil {
		facts = r.global.Evaluate()
	}

	if !isConfigNil(r.cfg) {
		includes, requires, http := r.cfg.GlobalKnobs()
		facts.IncludesTokenExchangeRequirement = mergeBool(facts.IncludesTokenExchangeRequirement, includes)
		facts.RequiresTokenExchange = mergeBool(facts.RequiresTokenExchange, requires)
		facts.RequiresHTTPRequestSignatures = mergeBool(facts.RequiresHTTPRequestSignatures, http)

		norm, err := hostport.Normalize(host, r.cfg.Scheme())
		if err == nil {
			if platform, ok := r.resolvePlatform(norm); ok {
				if includes, requires, http, ok := r.cfg.PlatformKnobs(platform); ok {
					facts.IncludesTokenExchangeRequirement = mergeBool(facts.IncludesTokenExchangeRequirement, includes)
					facts.RequiresTokenExchange = mergeBool(facts.RequiresTokenExchange, requires)
					facts.RequiresHTTPRequestSignatures = mergeBool(facts.RequiresHTTPRequestSignatures, http)
				}
				if includes, requires, http, ok := r.cfg.InstanceKnobs(platform, norm); ok {
					facts.IncludesTokenExchangeRequirement = mergeBool(facts.IncludesTokenExchangeRequirement, includes)
					facts.RequiresTokenExchange = mergeBool(facts.RequiresTokenExchange, requires)
					facts.RequiresHTTPRequestSignatures = mergeBool(facts.RequiresHTTPRequestSignatures, http)
				}
				return facts
			}
		}
	}

	if isDiscoveryNil(disc) {
		return facts
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

func isDiscoveryNil(disc DiscoveryView) bool {
	return isInterfaceValueNil(disc)
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
