package discovery

import (
	"log/slog"
	"net/url"

	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/logutil"
)

// BuildParams holds the resolved inputs needed to construct a static OCM
// discovery document. The caller (the wellknown service) is responsible for
// config defaulting and for deriving cross-cutting values from shared deps
// (key manager, policy evaluators), then hands those resolved values here.
// This keeps the discovery component free of any dependency on the service or
// deps layers.
type BuildParams struct {
	Provider            string
	Endpoint            string
	OCMPrefix           string
	WebDAVRoot          string
	TokenExchangePath   string
	InviteAcceptDialog  string
	AdvertiseInviteWAYF bool

	// PublicKeys to advertise. When non-empty, the document also advertises
	// the http-sig capability.
	PublicKeys []PublicKey

	// Evaluation flags resolved by the caller from the canonical policies.
	// TokenExchangeCapable advertises exchange-token and a token endpoint.
	// RequiresTokenExchange emits the token-exchange criterion (only when
	// capable). RequiresHTTPSignatures emits the http-request-signatures
	// criterion.
	TokenExchangeCapable   bool
	RequiresTokenExchange  bool
	RequiresHTTPSignatures bool
}

// BuildDiscovery constructs the static discovery document (Reva pattern:
// computed once, not at request time). An empty or unparseable endpoint yields
// a disabled document, mirroring the prior service-layer behavior.
func BuildDiscovery(p BuildParams, log *slog.Logger) *Discovery {
	log = logutil.NoopIfNil(log)

	disc := &Discovery{
		Enabled:    false,
		APIVersion: "1.2.2",
		Provider:   p.Provider,
		Criteria:   []string{}, // Always present, serializes as [] when empty
	}

	if p.Endpoint == "" {
		return disc
	}
	if _, err := url.Parse(p.Endpoint); err != nil {
		return disc
	}

	disc.Enabled = true
	disc.EndPoint, _ = url.JoinPath(p.Endpoint, p.OCMPrefix)

	// Resource types with WebDAV protocol
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

	if p.TokenExchangeCapable {
		capabilities = append(capabilities, "exchange-token")
		tokenPath := p.TokenExchangePath
		if tokenPath == "" {
			tokenPath = "token"
		}
		disc.TokenEndPoint, _ = url.JoinPath(p.Endpoint, p.OCMPrefix, tokenPath)
	}

	// Unconditional capabilities. See https://github.com/cs3org/OCM-API/blob/a2b8bacd4590ff201a06883330b67636e99c4f5b/IETF-RFC.md?plain=1#ocm-api-discovery
	capabilities = append(capabilities, "invites", "webdav-uri", "protocol-object", "notifications")

	// Invite accept dialog (WAYF)
	if p.InviteAcceptDialog != "" {
		disc.InviteAcceptDialog = p.InviteAcceptDialog
		if p.AdvertiseInviteWAYF {
			capabilities = append(capabilities, "invite-wayf")
		}
	}

	disc.Capabilities = capabilities

	// Criteria (always present, serializes as [] when empty)
	if p.RequiresHTTPSignatures {
		disc.Criteria = append(disc.Criteria, "http-request-signatures")
	}
	if p.RequiresTokenExchange && p.TokenExchangeCapable {
		disc.Criteria = append(disc.Criteria, "token-exchange")
	} else if p.RequiresTokenExchange && !p.TokenExchangeCapable {
		log.Warn("local evaluator requires token exchange but code flow is disabled; omitting token-exchange criteria")
	}

	return disc
}
