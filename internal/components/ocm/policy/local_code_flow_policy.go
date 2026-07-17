package policy

import "github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"

// LocalCodeFlowFacts are the fixed OCM code-flow facts for this
// implementation. There is exactly one supported code flow, so these facts
// hold as constants; that changes only in a later task.
type LocalCodeFlowFacts struct {
	TokenExchangeCapable  bool
	RequiresTokenExchange bool
	IncludesRequirement   bool
}

// LocalCodeFlowPolicy reports the fixed local code-flow facts. It carries no
// relaxation or configuration fields on purpose: the current code flow is
// not configurable.
type LocalCodeFlowPolicy struct{}

// NewLocalCodeFlowPolicy constructs the fixed local code-flow policy. cfg is
// accepted for call-site symmetry with other local policies but does not
// influence the fixed facts below.
func NewLocalCodeFlowPolicy(cfg *config.Config) *LocalCodeFlowPolicy {
	_ = cfg
	return &LocalCodeFlowPolicy{}
}

// Evaluate returns the fixed local code-flow facts.
func (p *LocalCodeFlowPolicy) Evaluate() LocalCodeFlowFacts {
	return LocalCodeFlowFacts{
		TokenExchangeCapable:  true,
		RequiresTokenExchange: true,
		IncludesRequirement:   true,
	}
}
