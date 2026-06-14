package discovery

import (
	"log/slog"
	"net/url"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/spec"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/logutil"
)

// BuildParams holds route-projected discovery inputs resolved by the caller.
// Path fields are final values; the builder does not join route segments.
type BuildParams struct {
	Provider            string
	EndPoint            string
	WebDAVRoot          string
	TokenEndPoint       string
	InviteAcceptDialog  string
	AdvertiseInviteWAYF bool

	// PublicKeys to advertise. When non-empty, the document also advertises
	// the http-sig capability.
	PublicKeys []PublicKey

	// Evaluation flags resolved by the caller from the canonical policies.
	TokenExchangeCapable   bool
	RequiresTokenExchange  bool
	RequiresHTTPSignatures bool
}

// BuildDiscovery constructs the static discovery document (Reva pattern:
// computed once, not at request time). An empty or unparseable endPoint yields
// a disabled document, mirroring the prior service-layer behavior.
func BuildDiscovery(p BuildParams, log *slog.Logger) *Discovery {
	log = logutil.NoopIfNil(log)

	disc := &Discovery{
		Enabled:    false,
		APIVersion: "1.2.2",
		Provider:   p.Provider,
		Criteria:   []string{}, // Always present, serializes as [] when empty
	}

	if p.EndPoint == "" {
		return disc
	}
	if _, err := url.Parse(p.EndPoint); err != nil {
		return disc
	}

	disc.Enabled = true
	disc.EndPoint = p.EndPoint

	disc.ResourceTypes = []ResourceType{{
		Name:       "file",
		ShareTypes: []string{"user"},
		Protocols:  map[string]string{"webdav": p.WebDAVRoot},
	}}

	capabilities := []string{}

	if len(p.PublicKeys) > 0 {
		disc.PublicKeys = p.PublicKeys
		capabilities = append(capabilities, "http-sig")
	}

	if p.TokenExchangeCapable && p.TokenEndPoint != "" {
		capabilities = append(capabilities, "exchange-token")
		disc.TokenEndPoint = p.TokenEndPoint
	} else if p.TokenExchangeCapable && p.TokenEndPoint == "" {
		log.Warn("token exchange enabled but token endpoint is empty; omitting exchange-token capability")
	}

	// Unconditional capabilities. See https://github.com/cs3org/OCM-API/blob/a2b8bacd4590ff201a06883330b67636e99c4f5b/IETF-RFC.md?plain=1#ocm-api-discovery
	capabilities = append(capabilities, "invites", "webdav-uri", "protocol-object", "notifications")

	if p.InviteAcceptDialog != "" {
		disc.InviteAcceptDialog = p.InviteAcceptDialog
	}
	if p.AdvertiseInviteWAYF {
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
