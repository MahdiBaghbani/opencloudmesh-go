// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Mohammad Mahdi Baghbani Pourvahid <mahdi-baghbani@azadehafzar.io>
//
// OpenCloudMesh Go - a runnable Open Cloud Mesh peer in Go, focused on a strict, WebDAV-centered subset of the protocol.

package policy

import (
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
)

// CompatCompiler is the SSOT for compiling code-flow facts and OCM wire
// emissions (discovery criteria, capability-emit, protocol-emit, share
// requirements, and signature label). It wraps the scope-gated peer mapping
// resolver.
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

// LocalProfile returns code-flow facts for host via ResolveFacts(host).
// Under scoped compatibility, overlays apply only to explicitly mapped peers;
// unmatched hosts keep the global CodeFlow baseline. Under global scope,
// global peer_compat knobs apply to every host. Discovery and middleware use
// this for the local provider domain.
func (c *CompatCompiler) LocalProfile(host string) Facts {
	if c == nil || c.resolver == nil {
		return Facts{}
	}

	return c.resolver.ResolveFacts(host)
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

	if in.Facts.RequiresTokenExchange && in.TokenEndPoint != "" {
		criteria = append(criteria, spec.CriteriaMustExchangeToken)
	}

	return criteria
}

// EmitCapabilitiesInput carries discovery build context for capability-emit
// alongside route and key-manager flags.
type EmitCapabilitiesInput struct {
	AdvertiseHTTPSig     bool
	TokenExchangeCapable bool
	TokenEndPoint        string
	InvitesEnabled       bool
	WayfEnabled          bool
}

// EmitCapabilities returns discovery capability wire values from build
// context. Values are spec-owned constants, not raw literals.
func (c *CompatCompiler) EmitCapabilities(in EmitCapabilitiesInput) []string {
	_ = c

	var capabilities []string
	if in.AdvertiseHTTPSig {
		capabilities = append(capabilities, spec.CapabilityHTTPSig)
	}

	if in.TokenExchangeCapable && in.TokenEndPoint != "" {
		capabilities = append(capabilities, spec.CapabilityExchangeToken)
	}

	if in.InvitesEnabled {
		capabilities = append(capabilities, spec.CapabilityInvite)
	}

	if in.WayfEnabled {
		capabilities = append(capabilities, spec.CapabilityInviteWAYF)
	}

	return capabilities
}

// EmitProtocolsInput carries discovery build context for protocol-emit
// alongside route-projected WebDAV paths.
type EmitProtocolsInput struct {
	WebDAVRoot       string
	WebDAVReceiveURI spec.WebDAVReceiveURIKind
}

// EmitProtocols returns discovery protocol roles from build context. Role keys
// and webdav-receive uri kinds are spec-owned constants, not raw literals.
func (c *CompatCompiler) EmitProtocols(in EmitProtocolsInput) spec.Protocols {
	_ = c

	protocols := spec.Protocols{}
	if in.WebDAVRoot != "" {
		protocols[spec.ProtocolWebDAV] = spec.StringProtocolRole(in.WebDAVRoot)
	}

	if in.WebDAVReceiveURI != "" {
		protocols[spec.ProtocolWebDAVReceive] = spec.WebDAVReceiveRole(in.WebDAVReceiveURI)
	}

	return protocols
}

// SignatureLabel returns the RFC 9421 dictionary label for OCM HTTP signatures.
func (c *CompatCompiler) SignatureLabel() string {
	_ = c

	return spec.SignatureLabelOCM
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
// compiler recognizes. must-use-mfa is listed for hard-reject at admit only.
func (c *CompatCompiler) RecognizedShareRequirements() []string {
	_ = c

	return []string{
		spec.RequirementMustExchangeToken,
		spec.RequirementMustUseMFA,
	}
}
