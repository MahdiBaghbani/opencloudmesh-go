package policy

// Facts are the fixed OCM code-flow facts for this implementation. There is
// exactly one supported code flow, so these facts hold as constants; that
// changes only in a later task.
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
// receiver.
func (c *CodeFlow) Evaluate() Facts {
	return Facts{
		TokenExchangeCapable:             true,
		RequiresTokenExchange:            true,
		IncludesTokenExchangeRequirement: true,
		RequiresHTTPRequestSignatures:    true,
	}
}
