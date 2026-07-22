package policy

// Facts are the OCM code-flow facts for this implementation. A non-nil
// *CodeFlow returns the fixed strict facts; a nil *CodeFlow returns
// all-false Facts (strict-off).
type Facts struct {
	TokenExchangeCapable             bool
	RequiresTokenExchange            bool
	IncludesTokenExchangeRequirement bool
	RequiresHTTPRequestSignatures    bool
}

// CodeFlow reports the fixed local code-flow facts. The code flow is not configurable.
type CodeFlow struct{}

// NewCodeFlow constructs the fixed local code-flow policy.
func NewCodeFlow() *CodeFlow {
	return &CodeFlow{}
}

// Evaluate returns the fixed local code-flow facts. Safe to call on a nil
// receiver: nil means strict-off (all Facts false).
func (c *CodeFlow) Evaluate() Facts {
	if c == nil {
		return Facts{}
	}
	return Facts{
		TokenExchangeCapable:             true,
		RequiresTokenExchange:            true,
		IncludesTokenExchangeRequirement: true,
		RequiresHTTPRequestSignatures:    true,
	}
}
