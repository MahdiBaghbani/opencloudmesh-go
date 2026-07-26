package policy

import (
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
)

// CompatCompiler is the SSOT for compiling code-flow facts and OCM wire
// emissions (discovery criteria and share requirements). It wraps the
// scope-gated peer mapping resolver.
type CompatCompiler struct {
	resolver *PeerMappingResolver
}

// NewCompatCompiler constructs a compiler from global code flow, peer mapping
// config, and compatibility scope.
func NewCompatCompiler(
	global *CodeFlow,
	cfg PeerMappingConfigSource,
	scope config.CompatibilityScope,
) *CompatCompiler {
	return &CompatCompiler{
		resolver: NewPeerMappingResolver(global, cfg, scope),
	}
}

// Resolver exposes the underlying peer mapping resolver for call sites that
// wire ResolveFacts directly.
func (c *CompatCompiler) Resolver() *PeerMappingResolver {
	if c == nil {
		return nil
	}
	return c.resolver
}

// LocalProfile returns code-flow facts for host via ResolveFacts(host, nil).
// Under scoped compatibility, overlays apply only to explicitly mapped peers;
// unmatched hosts keep the global CodeFlow baseline. Under global scope,
// global peer_compat knobs apply to every host. Discovery and middleware use
// this for the local provider domain.
func (c *CompatCompiler) LocalProfile(host string) Facts {
	if c == nil || c.resolver == nil {
		return Facts{}
	}
	return c.resolver.ResolveFacts(host, nil)
}

// FactsForHost is an alias of LocalProfile; both return identical facts for
// the same host.
func (c *CompatCompiler) FactsForHost(host string) Facts {
	return c.LocalProfile(host)
}

// EmitDiscoveryCriteriaInput carries discovery build context for criteria
// emission alongside resolved code-flow facts.
type EmitDiscoveryCriteriaInput struct {
	Facts            Facts
	AdvertiseHTTPSig bool
	TokenEndPoint    string
}

// EmitDiscoveryCriteria returns discovery criteria wire values from code-flow
// facts and build context. Values are spec-owned constants, not raw literals.
func (c *CompatCompiler) EmitDiscoveryCriteria(in EmitDiscoveryCriteriaInput) []string {
	_ = c
	var criteria []string
	if in.Facts.RequiresHTTPRequestSignatures && in.AdvertiseHTTPSig {
		criteria = append(criteria, spec.CriteriaMustUseHTTPSig)
	}
	if in.Facts.RequiresTokenExchange && in.Facts.TokenExchangeCapable && in.TokenEndPoint != "" {
		criteria = append(criteria, spec.CriteriaMustExchangeToken)
	}
	return criteria
}

// EmitShareRequirementsInput carries share-arm context for requirement
// emission. Shape mirrors EmitDiscoveryCriteriaInput (typed input struct).
type EmitShareRequirementsInput struct {
	IncludesTokenExchange bool
}

// EmitShareRequirements returns share protocol requirement wire values when
// token exchange must appear on the arm. Returns nil when no requirement is
// emitted.
func (c *CompatCompiler) EmitShareRequirements(in EmitShareRequirementsInput) []string {
	_ = c
	if !in.IncludesTokenExchange {
		return nil
	}
	return []string{spec.RequirementMustExchangeToken}
}

// RecognizedShareRequirements lists share requirement wire values the policy
// compiler recognizes. must-use-mfa is listed for GAP rejection only.
func (c *CompatCompiler) RecognizedShareRequirements() []string {
	_ = c
	return []string{
		spec.RequirementMustExchangeToken,
		spec.RequirementMustUseMFA,
	}
}
