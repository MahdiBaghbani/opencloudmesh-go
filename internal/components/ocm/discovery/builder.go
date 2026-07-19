package discovery

import (
	"log/slog"

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
	WayfEnabled        bool

	// AdvertiseHTTPSig adds the http-sig capability when local signing keys are
	// published via /.well-known/jwks.json.
	AdvertiseHTTPSig bool

	// Evaluation flags resolved by the caller from the canonical policies.
	TokenExchangeCapable   bool
	RequiresTokenExchange  bool
	RequiresHTTPSignatures bool
}

// BuildDiscovery constructs the static discovery document (Reva pattern:
// computed once, not at request time). An empty or non-absolute endPoint yields
// a disabled document, mirroring the prior service-layer behavior.
func BuildDiscovery(p BuildParams, log *slog.Logger) *Discovery {
	log = logutil.NoopIfNil(log)

	disc := &Discovery{
		Enabled:    false,
		APIVersion: "1.4.0",
		Provider:   p.Provider,
		Criteria:   []string{}, // Always present, serializes as [] when empty
	}

	if p.EndPoint == "" || !isAbsoluteURL(p.EndPoint) {
		return disc
	}

	disc.Enabled = true
	disc.EndPoint = p.EndPoint

	protocols := spec.Protocols{}
	if p.WebDAVRoot != "" {
		protocols["webdav"] = spec.StringProtocolRole(p.WebDAVRoot)
	}
	if p.WebDAVReceiveURI != "" {
		protocols["webdav-receive"] = spec.WebDAVReceiveRole(spec.WebDAVReceiveURIKind(p.WebDAVReceiveURI))
	}

	disc.ResourceTypes = make([]ResourceType, 0, len(spec.SupportedResourceTypes))
	for _, rtName := range spec.SupportedResourceTypes {
		disc.ResourceTypes = append(disc.ResourceTypes, ResourceType{
			Name:       rtName,
			ShareTypes: []string{"user"},
			Protocols:  protocols,
		})
	}

	capabilities := []string{}

	if p.AdvertiseHTTPSig {
		capabilities = append(capabilities, "http-sig")
	}

	if p.TokenExchangeCapable && p.TokenEndPoint != "" {
		capabilities = append(capabilities, "exchange-token")
		disc.TokenEndPoint = p.TokenEndPoint
	} else if p.TokenExchangeCapable && p.TokenEndPoint == "" {
		log.Warn("token exchange enabled but token endpoint is empty; omitting exchange-token capability")
	}

	if p.InviteAcceptDialog != "" {
		disc.InviteAcceptDialog = p.InviteAcceptDialog
	}
	if p.WayfEnabled {
		capabilities = append(capabilities, "invite-wayf")
	}

	disc.Capabilities = capabilities

	if p.RequiresHTTPSignatures {
		disc.Criteria = append(disc.Criteria, spec.CriteriaMustUseHTTPSig)
	}
	if p.RequiresTokenExchange && p.TokenExchangeCapable && p.TokenEndPoint != "" {
		disc.Criteria = append(disc.Criteria, spec.CriteriaMustExchangeToken)
	} else if p.RequiresTokenExchange && !p.TokenExchangeCapable {
		log.Warn("local evaluator requires token exchange but code flow is disabled; omitting token-exchange criteria")
	}

	return disc
}
