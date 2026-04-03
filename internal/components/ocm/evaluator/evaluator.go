// Package evaluator is temporary compatibility glue during the policy rollout.
package evaluator

import (
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/components/ocm/policy"
	"github.com/MahdiBaghbani/opencloudmesh-go/internal/platform/config"
)

// LocalEvaluation preserves the pre-policy compatibility type name.
type LocalEvaluation = policy.Evaluation

// LocalEvaluator preserves the pre-policy compatibility wrapper.
type LocalEvaluator struct {
	policy *policy.OpenCloudMeshPolicy
}

// NewLocalEvaluator creates a LocalEvaluator from immutable config.
func NewLocalEvaluator(cfg *config.Config) *LocalEvaluator {
	return NewLocalEvaluatorFromPolicy(policy.NewOpenCloudMeshPolicy(cfg))
}

// NewLocalEvaluatorFromPolicy reuses an existing canonical policy object.
func NewLocalEvaluatorFromPolicy(p *policy.OpenCloudMeshPolicy) *LocalEvaluator {
	return &LocalEvaluator{policy: p}
}

// Evaluate returns the canonical local evaluation.
func (e *LocalEvaluator) Evaluate() LocalEvaluation {
	return e.policy.Evaluate()
}
