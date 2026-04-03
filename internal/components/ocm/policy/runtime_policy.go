package policy

import "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"

// RuntimePolicy holds non-canonical runtime behavior that should not live on
// the canonical OCM policy object.
type RuntimePolicy struct {
	signatureInboundMode string
}

// NewRuntimePolicy creates the narrow runtime policy needed by incoming shares.
func NewRuntimePolicy(cfg *config.Config) *RuntimePolicy {
	return &RuntimePolicy{signatureInboundMode: cfg.Signature.InboundMode}
}

// StrictIncomingSharePayloadValidation reports whether incoming share payload
// validation should use the strict path for the current request.
func (p *RuntimePolicy) StrictIncomingSharePayloadValidation(authenticated bool) bool {
	switch p.signatureInboundMode {
	case "strict":
		return true
	case "lenient":
		return authenticated
	default:
		return false
	}
}
