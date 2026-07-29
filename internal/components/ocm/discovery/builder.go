package discovery

import (
	"log/slog"
	"net/url"
	"strings"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/logutil"
)

// BuildParams holds route-projected discovery inputs resolved by the caller.
// Path fields are final values; the builder does not join route segments.
type BuildParams struct {
	Provider           string
	EndPoint           string
	WebDAVRoot         string
	WebDAVReceiveURI   string
	TokenEndPoint      string
	InviteAcceptDialog string
	InvitesEnabled     bool
	WayfEnabled        bool

	// AdvertiseHTTPSig adds the http-sig capability when local signing keys are
	// published via the OCM /jwks route.
	AdvertiseHTTPSig bool

	// JwksURI is the advertised local jwksUri. Callers (resolve.Resolve) set
	// this to the configured signature.jwks_uri override when present,
	// otherwise to the route-inventory-derived default (<endPoint>/jwks). A
	// non-empty configured override is expected to already be
	// startup-validated (see discovery.ValidateLocalJwksURIOverride). When
	// JwksURI arrives empty (no override and no route projection available),
	// the builder falls back to deriving it directly from EndPoint.
	JwksURI string

	// Evaluation flags resolved by the caller from the canonical policies.
	TokenExchangeCapable   bool
	RequiresTokenExchange  bool
	RequiresHTTPSignatures bool
}

// BuildDiscovery constructs the static discovery document (Reva pattern:
// computed once, not at request time). An empty or non-absolute endPoint yields
// a disabled document.
func BuildDiscovery(p BuildParams, log *slog.Logger) *spec.Discovery {
	log = logutil.NoopIfNil(log)

	disc := &spec.Discovery{
		Enabled:    false,
		APIVersion: spec.APIVersionPin,
		Provider:   p.Provider,
		Criteria:   []string{}, // Always present, serializes as [] when empty
	}

	if p.EndPoint == "" || !isAbsoluteURL(p.EndPoint) {
		return disc
	}

	disc.Enabled = true
	disc.EndPoint = p.EndPoint

	protocols := buildDiscoveryProtocols(p)
	capabilities := buildDiscoveryCapabilities(p, disc, log)

	disc.ResourceTypes = buildDiscoveryResourceTypes(protocols)
	disc.Capabilities = capabilities
	buildDiscoveryCriteria(p, disc)

	return disc
}

func buildDiscoveryProtocols(p BuildParams) spec.Protocols {
	protocols := spec.Protocols{}
	if p.WebDAVRoot != "" {
		protocols[spec.ProtocolWebDAV] = spec.StringProtocolRole(p.WebDAVRoot)
	}

	if p.WebDAVReceiveURI != "" {
		protocols[spec.ProtocolWebDAVReceive] = spec.WebDAVReceiveRole(spec.WebDAVReceiveURIKind(p.WebDAVReceiveURI))
	}

	return protocols
}

func buildDiscoveryCapabilities(p BuildParams, disc *spec.Discovery, log *slog.Logger) []string {
	capabilities := []string{}

	if p.AdvertiseHTTPSig {
		capabilities = append(capabilities, spec.CapabilityHTTPSig)

		if p.JwksURI != "" {
			disc.JwksUri = p.JwksURI
		} else if jwksURI := endpointJwksURI(p.EndPoint); jwksURI != "" {
			disc.JwksUri = jwksURI
		} else {
			log.Warn("http-sig advertised but JWKS URL could not be derived from endPoint; omitting jwksUri")
		}
	}

	if p.TokenExchangeCapable && p.TokenEndPoint != "" {
		capabilities = append(capabilities, spec.CapabilityExchangeToken)
		disc.TokenEndPoint = p.TokenEndPoint
	} else if p.TokenExchangeCapable && p.TokenEndPoint == "" {
		log.Warn("token exchange enabled but token endpoint is empty; omitting " +
			spec.CapabilityExchangeToken + " capability")
	}

	if p.InviteAcceptDialog != "" {
		disc.InviteAcceptDialog = p.InviteAcceptDialog
	}

	if p.InvitesEnabled {
		capabilities = append(capabilities, spec.CapabilityInvite)
	}

	if p.WayfEnabled {
		capabilities = append(capabilities, spec.CapabilityInviteWAYF)
	}

	return capabilities
}

func buildDiscoveryResourceTypes(protocols spec.Protocols) []spec.ResourceType {
	resourceTypes := make([]spec.ResourceType, 0, len(spec.SupportedResourceTypes))
	for _, rtName := range spec.SupportedResourceTypes {
		resourceTypes = append(resourceTypes, spec.ResourceType{
			Name: rtName,
			// Core OCM share types are "user" and "group"; "federation" is registered by
			// OCM-MLS, not core OCM (https://github.com/cs3org/OCM-API/blob/a5b5da6/IETF-OCM.md#L1803-L1805).
			// ocmgo deliberately does not advertise "federation"; it advertises only "user"
			// because it does not implement group shares.
			ShareTypes: []string{"user"},
			Protocols:  protocols,
		})
	}

	return resourceTypes
}

func buildDiscoveryCriteria(p BuildParams, disc *spec.Discovery) {
	if p.RequiresHTTPSignatures && p.AdvertiseHTTPSig {
		disc.Criteria = append(disc.Criteria, spec.CriteriaMustUseHTTPSig)
	}

	if p.RequiresTokenExchange && p.TokenExchangeCapable && p.TokenEndPoint != "" {
		disc.Criteria = append(disc.Criteria, spec.CriteriaMustExchangeToken)
	}
}

// endpointJwksURI derives the server's own JWKS URL as <endPoint>/jwks, the
// same path the OCM service's route inventory mounts the local JWKS handler
// under. This is a fallback for direct BuildParams construction; callers
// wired through resolve.Resolve already populate JwksURI from the route
// inventory (spec.DeriveDiscoveryPaths) or a configured override.
func endpointJwksURI(endPoint string) string {
	u, err := url.Parse(endPoint)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}

	return strings.TrimSuffix(endPoint, "/") + "/jwks"
}
