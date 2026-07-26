package policy

// Facts are the OCM code-flow facts for this implementation. A non-nil
// *CodeFlow evaluates knobs with strict defaults; a nil *CodeFlow returns
// all-false Facts (strict-off).
type Facts struct {
	TokenExchangeCapable             bool
	RequiresTokenExchange            bool
	IncludesTokenExchangeRequirement bool
	RequiresHTTPRequestSignatures    bool
}

// CodeFlow reports local code-flow facts. Nil *bool knobs mean strict (true).
// false relaxes; true enforces. Knobs apply only to a non-nil CodeFlow.
type CodeFlow struct {
	IncludesTokenExchangeRequirement *bool
	RequiresTokenExchangeRequirement *bool
	RequiresHTTPRequestSignatures    *bool
}

// NewCodeFlow constructs a local code-flow policy with unset (strict) knobs.
func NewCodeFlow() *CodeFlow {
	return &CodeFlow{}
}

// Evaluate returns the local code-flow facts. Safe to call on a nil
// receiver: nil means strict-off (all Facts false). On a non-nil receiver,
// unset knobs default to true.
func (c *CodeFlow) Evaluate() Facts {
	if c == nil {
		return Facts{}
	}

	return Facts{
		TokenExchangeCapable:             true,
		RequiresTokenExchange:            boolOrDefaultTrue(c.RequiresTokenExchangeRequirement),
		IncludesTokenExchangeRequirement: boolOrDefaultTrue(c.IncludesTokenExchangeRequirement),
		RequiresHTTPRequestSignatures:    boolOrDefaultTrue(c.RequiresHTTPRequestSignatures),
	}
}

func boolOrDefaultTrue(v *bool) bool {
	if v == nil {
		return true
	}

	return *v
}
